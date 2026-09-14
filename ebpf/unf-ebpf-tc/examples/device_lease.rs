#![no_std]
#![no_main]
// Disposable lifetime/delivery experiment, not production locality authority.
#![allow(unsafe_code)]

use aya_ebpf::{
    EbpfContext,
    bindings::TC_ACT_SHOT,
    helpers::{bpf_probe_read_kernel, bpf_probe_read_kernel_str_bytes, bpf_redirect_peer},
    macros::{classifier, map},
    maps::{Array, DevMap},
    programs::TcContext,
};

// Schema, skb device word, index/net/cookie/peer offsets, source/target host
// indices, source/target peer indices, fabric/source/target cookies, reserved,
// target peer/host MACs; flags offset, alias pointer/data offsets, reserved.
// Schema 2 adds full alias matching and administrative-up checks.
#[map]
static P9LEASECFG: Array<[u64; 20]> = Array::with_max_entries(1, 0);
// Only a target-context seed may write this private pointer. Never export it
// in diagnostic results. Entries must not be implicitly rebound or reused.
#[map]
static P9LEASEPTR: Array<u64> = Array::with_max_entries(1, 0);
#[map]
static P9LEASEDEV: DevMap = DevMap::with_max_entries(2, 0);
// Exact NUL-terminated, zero-padded aliases: source host/peer, target host/peer.
// A production publisher must derive these from independently verified CNI
// ownership; matching caller-supplied strings alone is not authentication.
#[map]
static P9LEASEOWN: Array<[u64; 13]> = Array::with_max_entries(4, 0);
// Serial probes, requested redirects, rejected probes, last failure stage.
// Requested redirects are NOT observed application deliveries.
#[map]
static P9LEASERES: Array<[u64; 4]> = Array::with_max_entries(1, 0);

#[classifier]
pub fn device_lease_seed(ctx: TcContext) -> i32 {
    if !probe(&ctx, 17779) {
        return TC_ACT_SHOT;
    }
    let Some(config) = P9LEASECFG.get(0) else {
        return TC_ACT_SHOT;
    };
    let Some(slot) = P9LEASEPTR.get_ptr_mut(0) else {
        return TC_ACT_SHOT;
    };
    let Some(output) = P9LEASERES.get_ptr_mut(0) else {
        return TC_ACT_SHOT;
    };
    // A failed seed clears the old diagnostic pointer instead of retaining it.
    unsafe {
        *slot = 0;
        (*output)[3] = 101;
    };
    if valid_config(config)
        && P9LEASEDEV.get_ifindex(1).map(u64::from) == Some(config[7])
        && u64::from(ifindex(&ctx)) == config[7]
    {
        if let Ok(device) = context_device(&ctx, config) {
            if endpoint(device, config, 7, 9, 12, 2).is_ok() {
                // The fixture seeds once after binding the target devmap entry,
                // before it attaches the source classifier or sends traffic.
                unsafe {
                    *slot = device;
                    (*output)[3] = 100;
                };
            }
        }
    }
    TC_ACT_SHOT
}

#[classifier]
pub fn device_lease_redirect(ctx: TcContext) -> i32 {
    if !probe(&ctx, 17778) {
        return TC_ACT_SHOT;
    }
    let Some(output) = P9LEASERES.get_ptr_mut(0) else {
        return TC_ACT_SHOT;
    };
    // Serial isolated fixture only; no concurrent/lossless counter claim.
    unsafe { (*output)[0] = (*output)[0].saturating_add(1) };
    match redirect(&ctx) {
        Ok(action) => {
            unsafe {
                (*output)[1] = (*output)[1].saturating_add(1);
                (*output)[3] = 0;
            }
            action
        }
        Err(stage) => {
            unsafe {
                (*output)[2] = (*output)[2].saturating_add(1);
                (*output)[3] = stage;
            }
            TC_ACT_SHOT
        }
    }
}

#[inline(always)]
fn redirect(ctx: &TcContext) -> Result<i32, u64> {
    let config = P9LEASECFG.get(0).ok_or(1_u64)?;
    if !valid_config(config) || u64::from(ifindex(ctx)) != config[6] {
        return Err(1);
    }
    // Both immutable bindings must still exist before reading the seeded raw
    // target pointer. Unregister removes the entry; RCU delays dev_put/free.
    // This is an experimental lifetime construction, not a production proof.
    if P9LEASEDEV.get_ifindex(0).map(u64::from) != Some(config[6])
        || P9LEASEDEV.get_ifindex(1).map(u64::from) != Some(config[7])
    {
        return Err(2);
    }
    let source = context_device(ctx, config).map_err(|_| 3_u64)?;
    endpoint(source, config, 6, 8, 11, 0).map_err(|_| 4_u64)?;
    let target = P9LEASEPTR.get(0).copied().ok_or(5_u64)?;
    endpoint(target, config, 7, 9, 12, 2).map_err(|_| 6_u64)?;
    let destination = config[14].to_le_bytes();
    let source = config[15].to_le_bytes();
    ctx.store(
        0,
        &[
            destination[0],
            destination[1],
            destination[2],
            destination[3],
            destination[4],
            destination[5],
        ],
        0,
    )
    .map_err(|_| 7_u64)?;
    ctx.store(
        6,
        &[
            source[0], source[1], source[2], source[3], source[4], source[5],
        ],
        0,
    )
    .map_err(|_| 7_u64)?;
    // This helper issues a redirect request. The fixture must independently
    // prove reception and negative delivery, not infer either from this return.
    Ok(unsafe { bpf_redirect_peer(config[7] as u32, 0) } as i32)
}

#[inline(always)]
fn valid_config(c: &[u64; 20]) -> bool {
    c[0] == 2
        && c[1] <= 7
        && c[2] <= 8192
        && c[3] <= 8192
        && c[4] <= 65536
        && c[5] >= 64
        && c[5] <= 8192
        && c[5] % 8 == 0
        && c[6] > 0
        && c[6] <= u32::MAX as u64
        && c[7] > 0
        && c[7] <= u32::MAX as u64
        && c[6] != c[7]
        && c[8] > 0
        && c[8] <= u32::MAX as u64
        && c[9] > 0
        && c[9] <= u32::MAX as u64
        && c[10] != 0
        && c[11] != 0
        && c[12] != 0
        && c[10] != c[11]
        && c[10] != c[12]
        && c[11] != c[12]
        && c[13] == 0
        && c[14] > 0
        && c[15] > 0
        && c[14] >> 48 == 0
        && c[15] >> 48 == 0
        && c[16] <= 8192
        && c[16] % 4 == 0
        && c[17] <= 8192
        && c[17] % 8 == 0
        && c[18] >= 8
        && c[18] <= 256
        && c[19] == 0
}

#[inline(always)]
fn endpoint(
    device: u64,
    c: &[u64; 20],
    host: usize,
    peer: usize,
    cookie: usize,
    owner: u32,
) -> Result<(), ()> {
    if u64::from(read::<u32>(device, c[2])?) != c[host] || read::<u32>(device, c[16])? & 1 == 0 {
        return Err(());
    }
    ownership(device, c, owner)?;
    let namespace = read::<u64>(device, c[3])?;
    if read::<u64>(namespace, c[4])? != c[10] {
        return Err(());
    }
    let remote = read::<u64>(device, c[5])?;
    if u64::from(read::<u32>(remote, c[2])?) != c[peer] || read::<u32>(remote, c[16])? & 1 == 0 {
        return Err(());
    }
    ownership(remote, c, owner + 1)?;
    let namespace = read::<u64>(remote, c[3])?;
    if read::<u64>(namespace, c[4])? != c[cookie] {
        return Err(());
    }
    Ok(())
}

#[inline(always)]
fn ownership(device: u64, c: &[u64; 20], owner: u32) -> Result<(), ()> {
    let expected = P9LEASEOWN.get(owner).ok_or(())?;
    let alias = read::<u64>(device, c[17])?;
    if alias == 0 || alias % 8 != 0 {
        return Err(());
    }
    let address = alias.checked_add(c[18]).ok_or(())?;
    // CNI's longest v3 alias is 96 bytes. Read beyond that bound so a longer
    // string with the same prefix cannot pass through helper truncation.
    let mut buffer = [0_u64; 14];
    // The helper bounds/fault-checks the read. Linux replaces ifalias through
    // RCU and defers reclamation; no raw Rust dereference or pointer export.
    let length = {
        // SAFETY: this is exactly the initialized 112-byte backing array;
        // the temporary byte view does not outlive its exclusive borrow.
        let bytes =
            unsafe { core::slice::from_raw_parts_mut(buffer.as_mut_ptr().cast::<u8>(), 112) };
        unsafe { bpf_probe_read_kernel_str_bytes(address as *const u8, bytes) }
            .map_err(|_| ())?
            .len()
    };
    if length == 0 || length > 96 {
        return Err(());
    }
    // Compare complete bytes in thirteen aligned words, not a truncated hash
    // or prefix. This bounds comparison work; measured hot-path cost is open.
    for index in 0..13 {
        if buffer[index] != expected[index] {
            return Err(());
        }
    }
    Ok(())
}

#[inline(always)]
fn context_device(ctx: &TcContext, c: &[u64; 20]) -> Result<u64, ()> {
    if c[1] > 7 {
        return Err(());
    }
    let prefix =
        unsafe { bpf_probe_read_kernel::<[u64; 8]>(ctx.as_ptr().cast()) }.map_err(|_| ())?;
    Ok(prefix[c[1] as usize])
}

#[inline(always)]
fn read<T: Copy>(base: u64, offset: u64) -> Result<T, ()> {
    if base == 0 || base % 8 != 0 || offset > 65536 {
        return Err(());
    }
    let address = base.checked_add(offset).ok_or(())?;
    unsafe { bpf_probe_read_kernel(address as *const T) }.map_err(|_| ())
}

#[inline(always)]
fn ifindex(ctx: &TcContext) -> u32 {
    unsafe { (*ctx.skb.skb).ifindex }
}

#[inline(always)]
fn probe(ctx: &TcContext, port: u16) -> bool {
    match ctx.load::<u16>(12).map(u16::from_be) {
        Ok(0x0800) => {
            ctx.load::<u8>(14) == Ok(0x45)
                && ctx.load::<u8>(23) == Ok(17)
                && ctx.load::<u16>(36).map(u16::from_be) == Ok(port)
        }
        Ok(0x86dd) => {
            ctx.load::<u8>(20) == Ok(17) && ctx.load::<u16>(56).map(u16::from_be) == Ok(port)
        }
        _ => false,
    }
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 4] = *b"GPL\0";

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {
    loop {
        core::hint::spin_loop();
    }
}
