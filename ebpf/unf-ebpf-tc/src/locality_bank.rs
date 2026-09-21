#![no_std]
#![no_main]
#![allow(unsafe_code)]
//! Separately loaded immutable locality bank. Never attach this classifier
//! directly: its only production entry is the policy-first runtime tail call.
//! The seed program is private, non-transmitting and destroyed before publish.

use aya_ebpf::{
    EbpfContext,
    bindings::{TC_ACT_SHOT, bpf_fib_lookup as FibLookup},
    helpers::{
        bpf_fib_lookup, bpf_probe_read_kernel, bpf_probe_read_kernel_buf,
        bpf_probe_read_kernel_str_bytes, bpf_redirect_peer,
    },
    macros::{classifier, map},
    maps::{Array, DevMap, HashMap, PerCpuArray, ProgramArray},
    programs::TcContext,
};
use unf_ebpf_common::locality::{
    ALIAS_BYTES, AddressKey, AddressOwner, BankConfig, DeviceGeometry, Endpoint, MAX_ADDRESSES,
    MAX_ENDPOINTS, PACKET_DSR_PENDING, PacketInput, PlacementFence,
};

const READ_ONLY_PROGRAM: u32 = 1 << 7;

#[map]
static UL_CONFIG_V1: Array<BankConfig> = Array::with_max_entries(1, READ_ONLY_PROGRAM);
#[map]
static UL_ADDRESS_V1: HashMap<AddressKey, AddressOwner> =
    HashMap::with_max_entries(MAX_ADDRESSES, READ_ONLY_PROGRAM);
#[map]
static UL_ENDPOINT_V1: Array<Endpoint> = Array::with_max_entries(MAX_ENDPOINTS, READ_ONLY_PROGRAM);
#[map]
// Linux adds RDONLY_PROG itself; v5.14 rejects it in the create attributes.
static UL_DEVICE_V1: DevMap = DevMap::with_max_entries(MAX_ENDPOINTS * 2, 0);
// The seed is the only BPF writer. Freezing restricts userspace, so the loader
// MUST destroy the seed program capability as well; neither seed map is pinned.
#[map]
static UL_POINTER_V1: Array<u64> = Array::with_max_entries(MAX_ENDPOINTS, 0);
#[map]
static UL_SEEDED_V1: Array<u32> = Array::with_max_entries(MAX_ENDPOINTS, 0);
// These four maps bind to exact runtime FDs, not a fresh same-shaped replacement.
#[map]
static UL_LEASE_V1: HashMap<[u8; 32], u64> =
    HashMap::with_max_entries(MAX_ENDPOINTS, READ_ONLY_PROGRAM);
#[map]
static UL_INPUT_V1: PerCpuArray<PacketInput> = PerCpuArray::with_max_entries(1, 0);
#[map]
static UL_FENCE_V1: Array<PlacementFence> = Array::with_max_entries(1, READ_ONLY_PROGRAM);
#[map]
// Special FD arrays reject RDONLY_PROG on v5.14. BPF cannot mint program FDs.
static UL_RESUME_V1: ProgramArray = ProgramArray::with_max_entries(4, 0);
// Examined, misses/stale, rejected-local, requested-redirect, requested-NAT.
// A redirect request is NOT an observed application delivery.
#[map]
static UL_COUNTER_V1: PerCpuArray<[u64; 5]> = PerCpuArray::with_max_entries(1, 0);

#[classifier]
pub fn unf_locality_seed(ctx: TcContext) -> i32 {
    let Some(config) = UL_CONFIG_V1.get(0) else {
        return TC_ACT_SHOT;
    };
    if !config.valid()
        || ctx.load::<u16>(12).map(u16::from_be) != Ok(0x88b5)
        || ctx.load::<[u8; 8]>(14) != Ok(*b"UNFLOC01")
    {
        return TC_ACT_SHOT;
    }
    let Ok(index) = ctx.load::<u32>(22).map(u32::from_be) else {
        return TC_ACT_SHOT;
    };
    if index >= config.endpoints {
        return TC_ACT_SHOT;
    }
    let (Some(pointer), Some(seeded), Some(endpoint)) = (
        UL_POINTER_V1.get_ptr_mut(index),
        UL_SEEDED_V1.get_ptr_mut(index),
        UL_ENDPOINT_V1.get(index),
    ) else {
        return TC_ACT_SHOT;
    };
    // Fresh bank only. A rejected repeated seed cannot retain an old pointer.
    unsafe {
        *pointer = 0;
        *seeded = 0;
    }
    if endpoint.host_cookie != config.host_cookie
        || live_devices(index, endpoint).is_err()
        || ifindex(&ctx) != endpoint.host_index
    {
        return TC_ACT_SHOT;
    }
    if let Ok(device) = context_device(&ctx, config.geometry.skb_device / 8) {
        if live_endpoint(device, &config.geometry, endpoint).is_ok() {
            // The kernel TestRun context resolves/holds this actual host device.
            // Never expose the resulting pointer through userspace readback.
            unsafe {
                *pointer = device;
                *seeded = 1;
            }
        }
    }
    TC_ACT_SHOT
}

#[classifier]
pub fn unf_locality_bank(ctx: TcContext) -> i32 {
    count(0);
    match consume(&ctx) {
        Ok(action) => dispatch_continuation(&ctx, action),
        Err(()) => {
            count(2);
            TC_ACT_SHOT
        }
    }
}

#[inline(never)]
fn consume(ctx: &TcContext) -> Result<i32, ()> {
    let input = UL_INPUT_V1.get(0).ok_or(())?;
    let config = UL_CONFIG_V1.get(0).ok_or(())?;
    let fence = UL_FENCE_V1.get(0).ok_or(())?;
    if !input.matches(config) || !fence.matches(config) {
        return Ok(resume(ctx, input.family, false));
    }
    let source_key = AddressKey {
        address: input.source_address,
        family: input.family.into(),
    };
    let target_key = AddressKey {
        address: input.destination_address,
        family: input.family.into(),
    };
    // Frozen, program-read-only address values remain stable for this invocation.
    let (Some(source), Some(target)) = (unsafe { UL_ADDRESS_V1.get(&source_key) }, unsafe {
        UL_ADDRESS_V1.get(&target_key)
    }) else {
        return Ok(resume(ctx, input.family, false));
    };
    if !source.valid(config.endpoints)
        || !target.valid(config.endpoints)
        || source.identity != input.source_identity
        || target.identity != input.destination_identity
    {
        return Err(());
    }
    let source_endpoint = UL_ENDPOINT_V1.get(source.endpoint).ok_or(())?;
    let target_endpoint = UL_ENDPOINT_V1.get(target.endpoint).ok_or(())?;
    if source_endpoint.host_cookie != config.host_cookie
        || target_endpoint.host_cookie != config.host_cookie
        || input.ingress_index != ifindex(ctx)
        || input.ingress_index != source_endpoint.host_index
    {
        return Err(());
    }
    live_devices(source.endpoint, source_endpoint)?;
    live_devices(target.endpoint, target_endpoint)?;
    // Every packet compares the full nonce AND serial in the exact journal gate.
    if unsafe { UL_LEASE_V1.get(&source_endpoint.nonce).copied() } != Some(source_endpoint.serial)
        || unsafe { UL_LEASE_V1.get(&target_endpoint.nonce).copied() }
            != Some(target_endpoint.serial)
        || source_endpoint.serial == 0
        || target_endpoint.serial == 0
    {
        return Err(());
    }
    let source_device = context_device(ctx, config.geometry.skb_device / 8)?;
    if UL_POINTER_V1.get(source.endpoint).copied() != Some(source_device) {
        return Err(());
    }
    live_endpoint(source_device, &config.geometry, source_endpoint)?;
    let target_device = UL_POINTER_V1.get(target.endpoint).copied().ok_or(())?;
    live_endpoint(target_device, &config.geometry, target_endpoint)?;
    if input.flags & PACKET_DSR_PENDING != 0 {
        // The dedicated main-object continuation performs reversible NAT, then
        // re-enters a bank to repeat ALL checks before any redirect. No saved
        // pointer or admission boolean is a permission for that second call.
        return Ok(resume(ctx, input.family, true));
    }
    route_and_rewrite(ctx, input, target_endpoint)?;
    count(3);
    // Device unregister/namespace movement invalidates immutable references;
    // RCU protects this invocation. The loader never rearms a frozen devmap.
    Ok(unsafe { bpf_redirect_peer(target_endpoint.host_index, 0) } as i32)
}

#[inline(always)]
fn resume(ctx: &TcContext, family: u8, nat: bool) -> i32 {
    let _ = ctx;
    let index = match family {
        4 => 0,
        6 => 1,
        _ => return TC_ACT_SHOT,
    };
    // Return to the top-level classifier before any tail call. Keeping the
    // ownership/FIB subprogram stack out of tail dispatch avoids mixed-call
    // verifier stack restrictions; no authority is carried across a tail here.
    -100 - index - if nat { 2 } else { 0 }
}

#[inline(always)]
fn dispatch_continuation(ctx: &TcContext, action: i32) -> i32 {
    let index = match action {
        -100 => 0,
        -101 => 1,
        -102 => 2,
        -103 => 3,
        _ => return action,
    };
    if index >= 2 {
        count(4);
    } else {
        count(1);
    }
    // Missing, incompatible or exhausted continuation is a drop, never PIPE.
    unsafe {
        UL_RESUME_V1.tail_call(ctx, index);
    }
    TC_ACT_SHOT
}

#[inline(always)]
fn count(index: usize) {
    if let Some(counters) = UL_COUNTER_V1.get_ptr_mut(0) {
        // One current CPU, no userspace writes while the bank is published.
        unsafe {
            (*counters)[index] = (*counters)[index].saturating_add(1);
        }
    }
}

#[inline(always)]
fn live_devices(index: u32, endpoint: &Endpoint) -> Result<(), ()> {
    if index >= MAX_ENDPOINTS
        || UL_DEVICE_V1.get_ifindex(index * 2) != Some(endpoint.host_index)
        || UL_DEVICE_V1.get_ifindex(index * 2 + 1) != Some(endpoint.peer_index)
    {
        return Err(());
    }
    Ok(())
}

#[inline(never)]
fn live_endpoint(device: u64, geometry: &DeviceGeometry, endpoint: &Endpoint) -> Result<(), ()> {
    if read::<u32>(device, geometry.device_index)? != endpoint.host_index
        || read::<u32>(device, geometry.device_flags)? & 1 == 0
    {
        return Err(());
    }
    ownership(device, geometry, &endpoint.host_alias)?;
    let namespace = read::<u64>(device, geometry.device_net)?;
    if read::<u64>(namespace, geometry.net_cookie)? != endpoint.host_cookie {
        return Err(());
    }
    let peer = read::<u64>(device, geometry.device_peer)?;
    if read::<u32>(peer, geometry.device_index)? != endpoint.peer_index
        || read::<u32>(peer, geometry.device_flags)? & 1 == 0
        || read::<u64>(peer, geometry.device_peer)? != device
    {
        return Err(());
    }
    ownership(peer, geometry, &endpoint.peer_alias)?;
    let namespace = read::<u64>(peer, geometry.device_net)?;
    if read::<u64>(namespace, geometry.net_cookie)? != endpoint.peer_cookie {
        return Err(());
    }
    Ok(())
}

#[inline(never)]
fn ownership(
    device: u64,
    geometry: &DeviceGeometry,
    expected: &[u8; ALIAS_BYTES],
) -> Result<(), ()> {
    let alias = read::<u64>(device, geometry.device_alias)?;
    if alias == 0 || alias % 8 != 0 {
        return Err(());
    }
    let address = alias
        .checked_add(u64::from(geometry.alias_data))
        .ok_or(())?;
    let mut buffer = [0_u64; 14];
    let bytes = unsafe { core::slice::from_raw_parts_mut(buffer.as_mut_ptr().cast::<u8>(), 112) };
    // Kernel helper bounds/fault checks the RCU-owned alias read. Read beyond
    // the maximum valid alias length to reject truncated-prefix matches.
    let length = unsafe { bpf_probe_read_kernel_str_bytes(address as *const u8, bytes) }
        .map_err(|_| ())?
        .len();
    if length == 0 || length > 96 {
        return Err(());
    }
    for index in 0..13 {
        // Endpoint's field is at aligned offset 80/184 in an aligned map value;
        // unaligned read also keeps this helper correct for other byte borrows.
        let wanted =
            unsafe { core::ptr::read_unaligned(expected.as_ptr().add(index * 8).cast::<u64>()) };
        if buffer[index] != wanted {
            return Err(());
        }
    }
    Ok(())
}

// A distinct bounded WORD index keeps the verifier-visible stack address
// aligned. Folding byte_offset / 8 * 8 back to a checked byte offset loses its
// alignment fact on the qualified 5.14 verifier. Do not bypass alignment checks
// in BankConfig or guess an skb member offset.
#[inline(never)]
fn context_device(ctx: &TcContext, word: u32) -> Result<u64, ()> {
    if word > 7 {
        return Err(());
    }
    let mut prefix = [0_u64; 8];
    let bytes = unsafe { core::slice::from_raw_parts_mut(prefix.as_mut_ptr().cast::<u8>(), 64) };
    unsafe { bpf_probe_read_kernel_buf(ctx.as_ptr().cast(), bytes) }.map_err(|_| ())?;
    Ok(prefix[word as usize])
}

#[inline(always)]
fn read<T: Copy>(base: u64, offset: u32) -> Result<T, ()> {
    if base == 0 || base % 8 != 0 || offset > 65_536 {
        return Err(());
    }
    let address = base.checked_add(u64::from(offset)).ok_or(())?;
    unsafe { bpf_probe_read_kernel(address as *const T) }.map_err(|_| ())
}

#[inline(always)]
fn ifindex(ctx: &TcContext) -> u32 {
    unsafe { (*ctx.skb.skb).ifindex }
}

#[inline(never)]
fn route_and_rewrite(ctx: &TcContext, input: &PacketInput, target: &Endpoint) -> Result<(), ()> {
    // Linux 5.14's full FIB helper uses mark zero. Never erase a foreign mark
    // or claim its policy route agrees with a zero-mark lookup. A future
    // capability-gated marked lookup needs its own kernel qualification.
    if unsafe { (*ctx.skb.skb).mark } != 0 {
        return Err(());
    }
    let mut fib: FibLookup = unsafe { core::mem::zeroed() };
    fib.ifindex = input.ingress_index;
    fib.l4_protocol = input.protocol;
    let (offset, hop) = match input.family {
        4 => prepare_v4(ctx, input, &mut fib)?,
        6 => prepare_v6(ctx, input, &mut fib)?,
        _ => return Err(()),
    };
    // Use the actual post-NAT wire source for FIB routing; authenticated source
    // ownership above deliberately uses the original pre-Service-SNAT address.
    fib.sport = ctx.load::<u16>(offset).map_err(|_| ())?;
    fib.dport = ctx.load::<u16>(offset + 2).map_err(|_| ())?;
    if fib.dport.to_ne_bytes() != input.destination_port || hop <= 1 {
        return Err(());
    }
    let result = unsafe {
        bpf_fib_lookup(
            ctx.as_ptr(),
            &mut fib,
            core::mem::size_of::<FibLookup>() as i32,
            0,
        )
    };
    if result != 0
        || fib.ifindex != target.host_index
        || fib.smac != target.host_mac
        || fib.dmac != target.peer_mac
    {
        return Err(());
    }
    // The helper may replace destination with a gateway or even change family.
    // Require the direct final workload address, not just a matching ifindex.
    if input.family == 4 {
        if fib.family != 2
            || unsafe { fib.__bindgen_anon_4.ipv4_dst }.to_ne_bytes()
                != input.destination_address[..4]
        {
            return Err(());
        }
        let old = u64::from(u16::from_ne_bytes([hop, input.protocol]));
        let new = u64::from(u16::from_ne_bytes([hop - 1, input.protocol]));
        ctx.l3_csum_replace(24, old, new, 2).map_err(|_| ())?;
        ctx.store(22, &(hop - 1), 0).map_err(|_| ())?;
    } else {
        if fib.family != 10
            || unsafe { fib.__bindgen_anon_4.ipv6_dst } != words(input.destination_address)
        {
            return Err(());
        }
        ctx.store(21, &(hop - 1), 0).map_err(|_| ())?;
    }
    ctx.store(0, &target.peer_mac, 0).map_err(|_| ())?;
    ctx.store(6, &target.host_mac, 0).map_err(|_| ())?;
    Ok(())
}

#[inline(never)]
fn prepare_v4(
    ctx: &TcContext,
    input: &PacketInput,
    fib: &mut FibLookup,
) -> Result<(usize, u8), ()> {
    if ctx.load::<u16>(12).map(u16::from_be) != Ok(0x0800) {
        return Err(());
    }
    let version_ihl = ctx.load::<u8>(14).map_err(|_| ())?;
    let ihl = version_ihl & 15;
    if version_ihl >> 4 != 4
        // Options may alter route semantics (e.g. source routing). They need
        // explicit parser/forwarding qualification before this fast path.
        || ihl != 5
        || ctx.load::<u8>(23) != Ok(input.protocol)
        || u16::from_be(ctx.load::<u16>(20).map_err(|_| ())?) & 0x3fff != 0
        || ctx.load::<[u8; 4]>(30).map_err(|_| ())? != input.destination_address[..4]
    {
        return Err(());
    }
    let length = u16::from_be(ctx.load::<u16>(16).map_err(|_| ())?);
    let offset = 14 + usize::from(ihl) * 4;
    let minimum = transport_minimum(input.protocol)?;
    if usize::from(length) < usize::from(ihl) * 4 + minimum
        || unsafe { (*ctx.skb.skb).len } < u32::from(length) + 14
    {
        return Err(());
    }
    fib.family = 2;
    fib.__bindgen_anon_1.tot_len = length;
    fib.__bindgen_anon_2.tos = ctx.load::<u8>(15).map_err(|_| ())?;
    fib.__bindgen_anon_3.ipv4_src = ctx.load::<u32>(26).map_err(|_| ())?;
    fib.__bindgen_anon_4.ipv4_dst = ctx.load::<u32>(30).map_err(|_| ())?;
    Ok((offset, ctx.load::<u8>(22).map_err(|_| ())?))
}

#[inline(never)]
fn prepare_v6(
    ctx: &TcContext,
    input: &PacketInput,
    fib: &mut FibLookup,
) -> Result<(usize, u8), ()> {
    if ctx.load::<u16>(12).map(u16::from_be) != Ok(0x86dd)
        || ctx.load::<u8>(14).map(|value| value >> 4) != Ok(6)
        || !v6_destination_matches(ctx, input)?
    {
        return Err(());
    }
    let payload = u16::from_be(ctx.load::<u16>(18).map_err(|_| ())?);
    let total = payload.checked_add(40).ok_or(())?;
    if payload == 0 || unsafe { (*ctx.skb.skb).len } < u32::from(total) + 14 {
        return Err(());
    }
    let offset = v6_offset(ctx, input.protocol, 54 + usize::from(payload))?;
    fib.family = 10;
    fib.__bindgen_anon_1.tot_len = total;
    fib.__bindgen_anon_2.flowinfo = ctx.load::<u32>(14).map_err(|_| ())? & 0x0fff_ffff_u32.to_be();
    // Fixed word reads avoid aggregate Result<[u8;16]> copies on the small BPF
    // call stack. They preserve the exact original wire byte order.
    fib.__bindgen_anon_3.ipv6_src = [
        ctx.load::<u32>(22).map_err(|_| ())?,
        ctx.load::<u32>(26).map_err(|_| ())?,
        ctx.load::<u32>(30).map_err(|_| ())?,
        ctx.load::<u32>(34).map_err(|_| ())?,
    ];
    fib.__bindgen_anon_4.ipv6_dst = words(input.destination_address);
    Ok((offset, ctx.load::<u8>(21).map_err(|_| ())?))
}

#[inline(never)]
fn v6_destination_matches(ctx: &TcContext, input: &PacketInput) -> Result<bool, ()> {
    // ABI v1's destination is at offset 40 in an eight-byte-aligned map value.
    // Read aligned wire-order words without hoisting sixteen byte temporaries
    // across skb helper calls. No pointer is exported or used for kernel reads.
    let expected = unsafe { &*input.destination_address.as_ptr().cast::<[u32; 4]>() };
    Ok(ctx.load::<u32>(38).map_err(|_| ())? == expected[0]
        && ctx.load::<u32>(42).map_err(|_| ())? == expected[1]
        && ctx.load::<u32>(46).map_err(|_| ())? == expected[2]
        && ctx.load::<u32>(50).map_err(|_| ())? == expected[3])
}

#[inline(always)]
fn transport_minimum(protocol: u8) -> Result<usize, ()> {
    match protocol {
        6 => Ok(20),
        17 => Ok(8),
        132 => Ok(12),
        _ => Err(()),
    }
}

#[inline(never)]
fn v6_offset(ctx: &TcContext, protocol: u8, end: usize) -> Result<usize, ()> {
    use unf_ebpf_common::{
        IPV6_EXTENSION_BYTE_LIMIT, IPV6_EXTENSION_HEADER_LIMIT, IPV6_NEXT_HEADER_FRAGMENT,
        IPV6_NEXT_HEADER_HOP_BY_HOP, Ipv6ExtensionStep, ipv6_extension_step,
    };
    let mut next = ctx.load::<u8>(20).map_err(|_| ())?;
    let mut offset = 54;
    for depth in 0..=IPV6_EXTENSION_HEADER_LIMIT {
        if next == protocol {
            return if offset + transport_minimum(protocol)? <= end {
                Ok(offset)
            } else {
                Err(())
            };
        }
        if depth == IPV6_EXTENSION_HEADER_LIMIT
            || next == IPV6_NEXT_HEADER_FRAGMENT
            || (next == IPV6_NEXT_HEADER_HOP_BY_HOP && depth != 0)
            || offset + 8 > end
        {
            return Err(());
        }
        let header = ctx.load::<[u8; 8]>(offset).map_err(|_| ())?;
        let Ipv6ExtensionStep::Continue {
            next_header,
            length,
        } = ipv6_extension_step(next, header)
        else {
            return Err(());
        };
        offset += length;
        if offset > end || offset - 54 > IPV6_EXTENSION_BYTE_LIMIT {
            return Err(());
        }
        next = next_header;
    }
    Err(())
}

#[inline(always)]
fn words(address: [u8; 16]) -> [u32; 4] {
    [
        u32::from_ne_bytes([address[0], address[1], address[2], address[3]]),
        u32::from_ne_bytes([address[4], address[5], address[6], address[7]]),
        u32::from_ne_bytes([address[8], address[9], address[10], address[11]]),
        u32::from_ne_bytes([address[12], address[13], address[14], address[15]]),
    ]
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 4] = *b"GPL\0";

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
