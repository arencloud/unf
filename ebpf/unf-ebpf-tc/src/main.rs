#![no_std]
#![no_main]

use aya_ebpf::bindings::TC_ACT_PIPE;
use aya_ebpf::helpers::bpf_ktime_get_ns;
use aya_ebpf::macros::{classifier, map};
use aya_ebpf::maps::{HashMap, PerCpuArray, RingBuf};
use aya_ebpf::programs::TcContext;
use unf_common::{IdentityId, PolicyId, RuleId, Verdict};
use unf_ebpf_common::{
    AddressFamily, Direction, FLOW_ABI_VERSION, FlowEvent, FlowKey, IDENTITY_MAP_ABI_VERSION,
    IdentityMapValue, Ipv4IdentityKey, ReasonCode,
};

const ETHERTYPE_IPV4: u16 = 0x0800;
const PROTOCOL_TCP: u8 = 6;
const PROTOCOL_UDP: u8 = 17;
const ETHERNET_HEADER_LEN: usize = 14;
const BPF_F_NO_PREALLOC: u32 = 1;

#[map]
static FLOW_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[map]
static FLOW_COUNTERS: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

#[map]
static IDENTITY_V4: HashMap<Ipv4IdentityKey, IdentityMapValue> =
    HashMap::with_max_entries(65_536, BPF_F_NO_PREALLOC);

#[classifier]
pub fn unf_observe_ingress(ctx: TcContext) -> i32 {
    observe(&ctx, Direction::Ingress);
    TC_ACT_PIPE
}

#[classifier]
pub fn unf_observe_egress(ctx: TcContext) -> i32 {
    observe(&ctx, Direction::Egress);
    TC_ACT_PIPE
}

#[inline(always)]
fn observe(ctx: &TcContext, direction: Direction) {
    let Ok(ether_type) = ctx.load::<u16>(12) else {
        return;
    };
    if u16::from_be(ether_type) != ETHERTYPE_IPV4 {
        return;
    }

    let Ok(version_ihl) = ctx.load::<u8>(ETHERNET_HEADER_LEN) else {
        return;
    };
    if version_ihl >> 4 != 4 {
        return;
    }
    let ihl_words = version_ihl & 0x0f;
    if !(5..=15).contains(&ihl_words) {
        return;
    }

    let Ok(fragment) = ctx.load::<u16>(ETHERNET_HEADER_LEN + 6) else {
        return;
    };
    if u16::from_be(fragment) & 0x1fff != 0 {
        // Non-initial fragments do not contain a reliable transport header.
        return;
    }

    let Ok(protocol) = ctx.load::<u8>(ETHERNET_HEADER_LEN + 9) else {
        return;
    };
    if protocol != PROTOCOL_TCP && protocol != PROTOCOL_UDP {
        return;
    }

    let Ok(source_ipv4) = ctx.load::<[u8; 4]>(ETHERNET_HEADER_LEN + 12) else {
        return;
    };
    let Ok(destination_ipv4) = ctx.load::<[u8; 4]>(ETHERNET_HEADER_LEN + 16) else {
        return;
    };
    let transport_offset = ETHERNET_HEADER_LEN + usize::from(ihl_words) * 4;
    let Ok(source_port) = ctx.load::<[u8; 2]>(transport_offset) else {
        return;
    };
    let Ok(destination_port) = ctx.load::<[u8; 2]>(transport_offset + 2) else {
        return;
    };

    if let Some(counter) = FLOW_COUNTERS.get_ptr_mut(0) {
        // SAFETY: get_ptr_mut returned a non-null pointer to the current CPU's
        // u64 slot at the valid, constant map index 0. No other CPU aliases it.
        #[allow(unsafe_code)]
        unsafe {
            *counter = (*counter).wrapping_add(1)
        };
    }

    let mut source_address = [0_u8; 16];
    source_address[..4].copy_from_slice(&source_ipv4);
    let mut destination_address = [0_u8; 16];
    destination_address[..4].copy_from_slice(&destination_ipv4);
    // SAFETY: this helper has no preconditions and returns monotonic kernel time.
    #[allow(unsafe_code)]
    let timestamp_ns = unsafe { bpf_ktime_get_ns() };
    let event = FlowEvent {
        timestamp_ns,
        flow: FlowKey {
            source_identity: lookup_identity(source_ipv4),
            destination_identity: lookup_identity(destination_ipv4),
            source_address,
            destination_address,
            source_port,
            destination_port,
            protocol,
            address_family: AddressFamily::Ipv4 as u8,
            reserved: [0; 2],
        },
        policy_id: PolicyId::new(0),
        rule_id: RuleId::new(0),
        interface_index: 0,
        version: FLOW_ABI_VERSION,
        size: core::mem::size_of::<FlowEvent>() as u16,
        verdict: Verdict::Allow,
        direction: direction as u8,
        reason: ReasonCode::Observed as u8,
        reserved: 0,
    };

    if let Some(mut entry) = FLOW_EVENTS.reserve::<FlowEvent>(0) {
        entry.write(event);
        entry.submit(0);
    }
}

#[inline(always)]
fn lookup_identity(address: [u8; 4]) -> IdentityId {
    let key = Ipv4IdentityKey::new(address);
    // SAFETY: IDENTITY_V4 uses BPF_F_NO_PREALLOC, values have a fixed Copy ABI,
    // and the reference is copied immediately without escaping this lookup.
    #[allow(unsafe_code)]
    let value = unsafe { IDENTITY_V4.get(&key).copied() };
    value.map_or(IdentityId::new(0), |value| {
        if value.schema_version == IDENTITY_MAP_ABI_VERSION {
            value.identity_id
        } else {
            IdentityId::new(0)
        }
    })
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {
    loop {
        core::hint::spin_loop();
    }
}
