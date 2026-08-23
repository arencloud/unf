#![no_std]
#![no_main]

use aya_ebpf::bindings::{TC_ACT_PIPE, TC_ACT_SHOT};
use aya_ebpf::helpers::bpf_ktime_get_ns;
use aya_ebpf::macros::{classifier, map};
use aya_ebpf::maps::{Array, HashMap, PerCpuArray, RingBuf};
use aya_ebpf::programs::TcContext;
use unf_common::{IdentityId, PolicyId, PolicyReason, RuleId, Verdict};
use unf_ebpf_common::{
    AddressFamily, Direction, FLOW_ABI_VERSION, FlowEvent, FlowKey, IDENTITY_MAP_ABI_VERSION,
    IdentityMapValue, Ipv4IdentityKey, POLICY_BANK_COUNT, POLICY_FLAG_HAS_POLICY,
    POLICY_FLAG_HAS_RULE, POLICY_FLAG_HAS_SHADOW, POLICY_FLAG_SHADOW_HAS_POLICY,
    POLICY_FLAG_SHADOW_HAS_RULE, POLICY_MAP_ABI_VERSION, PolicyMapConfig, PolicyMapKey,
    PolicyMapValue, ReasonCode,
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

/// Dual-bank policy state. Userspace stages the inactive bank and atomically
/// changes POLICY_CONFIG[0] only after validating the complete snapshot.
#[map]
static POLICY_RULES: HashMap<PolicyMapKey, PolicyMapValue> =
    HashMap::with_max_entries(262_144, BPF_F_NO_PREALLOC);

#[map]
static POLICY_CONFIG: Array<PolicyMapConfig> = Array::with_max_entries(1, 0);

#[classifier]
pub fn unf_observe_ingress(ctx: TcContext) -> i32 {
    observe(&ctx, Direction::Ingress)
}

#[classifier]
pub fn unf_observe_egress(ctx: TcContext) -> i32 {
    observe(&ctx, Direction::Egress)
}

#[inline(always)]
fn observe(ctx: &TcContext, direction: Direction) -> i32 {
    let Ok(ether_type) = ctx.load::<u16>(12) else {
        return TC_ACT_PIPE;
    };
    if u16::from_be(ether_type) != ETHERTYPE_IPV4 {
        return TC_ACT_PIPE;
    }

    let Ok(version_ihl) = ctx.load::<u8>(ETHERNET_HEADER_LEN) else {
        return TC_ACT_PIPE;
    };
    if version_ihl >> 4 != 4 {
        return TC_ACT_PIPE;
    }
    let ihl_words = version_ihl & 0x0f;
    if !(5..=15).contains(&ihl_words) {
        return TC_ACT_PIPE;
    }

    let Ok(fragment) = ctx.load::<u16>(ETHERNET_HEADER_LEN + 6) else {
        return TC_ACT_PIPE;
    };
    if u16::from_be(fragment) & 0x1fff != 0 {
        // Non-initial fragments do not contain a reliable transport header.
        return TC_ACT_PIPE;
    }

    let Ok(protocol) = ctx.load::<u8>(ETHERNET_HEADER_LEN + 9) else {
        return TC_ACT_PIPE;
    };
    if protocol != PROTOCOL_TCP && protocol != PROTOCOL_UDP {
        return TC_ACT_PIPE;
    }

    let Ok(source_ipv4) = ctx.load::<[u8; 4]>(ETHERNET_HEADER_LEN + 12) else {
        return TC_ACT_PIPE;
    };
    let Ok(destination_ipv4) = ctx.load::<[u8; 4]>(ETHERNET_HEADER_LEN + 16) else {
        return TC_ACT_PIPE;
    };
    let transport_offset = ETHERNET_HEADER_LEN + usize::from(ihl_words) * 4;
    let Ok(source_port) = ctx.load::<[u8; 2]>(transport_offset) else {
        return TC_ACT_PIPE;
    };
    let Ok(destination_port) = ctx.load::<[u8; 2]>(transport_offset + 2) else {
        return TC_ACT_PIPE;
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
    let source_identity = lookup_identity(source_ipv4);
    let destination_identity = lookup_identity(destination_ipv4);
    let decision = lookup_policy(
        source_identity,
        destination_identity,
        destination_port,
        protocol,
    );
    let event = FlowEvent {
        timestamp_ns,
        flow: FlowKey {
            source_identity,
            destination_identity,
            source_address,
            destination_address,
            source_port,
            destination_port,
            protocol,
            address_family: AddressFamily::Ipv4 as u8,
            reserved: [0; 2],
        },
        policy_revision: decision.policy_revision,
        policy_id: decision.policy_id,
        rule_id: decision.rule_id,
        shadow_policy_id: decision.shadow_policy_id,
        shadow_rule_id: decision.shadow_rule_id,
        interface_index: 0,
        version: FLOW_ABI_VERSION,
        size: core::mem::size_of::<FlowEvent>() as u16,
        verdict: decision.verdict,
        direction: direction as u8,
        reason: decision.reason,
        shadow_verdict: decision.shadow_verdict,
        shadow_reason: decision.shadow_reason,
        reserved: [0; 3],
    };

    if let Some(mut entry) = FLOW_EVENTS.reserve::<FlowEvent>(0) {
        entry.write(event);
        entry.submit(0);
    }

    if decision.verdict == Verdict::Deny {
        TC_ACT_SHOT
    } else {
        TC_ACT_PIPE
    }
}

#[derive(Clone, Copy)]
struct DataplaneDecision {
    policy_revision: u64,
    policy_id: PolicyId,
    rule_id: RuleId,
    shadow_policy_id: PolicyId,
    shadow_rule_id: RuleId,
    verdict: Verdict,
    reason: u8,
    shadow_verdict: u8,
    shadow_reason: u8,
}

impl DataplaneDecision {
    #[inline(always)]
    const fn observed(reason: ReasonCode) -> Self {
        Self {
            policy_revision: 0,
            policy_id: PolicyId::new(0),
            rule_id: RuleId::new(0),
            shadow_policy_id: PolicyId::new(0),
            shadow_rule_id: RuleId::new(0),
            verdict: Verdict::Allow,
            reason: reason as u8,
            shadow_verdict: Verdict::Unknown as u8,
            shadow_reason: ReasonCode::Observed as u8,
        }
    }
}

#[inline(always)]
fn lookup_policy(
    source_identity: IdentityId,
    destination_identity: IdentityId,
    destination_port: [u8; 2],
    protocol: u8,
) -> DataplaneDecision {
    if source_identity.get() == 0 || destination_identity.get() == 0 {
        return DataplaneDecision::observed(ReasonCode::IdentityUnknown);
    }
    let Some(config) = POLICY_CONFIG.get(0).copied() else {
        return DataplaneDecision::observed(ReasonCode::Observed);
    };
    if config.schema_version != POLICY_MAP_ABI_VERSION
        || config.active_bank >= POLICY_BANK_COUNT
        || config.revision == 0
    {
        return DataplaneDecision::observed(ReasonCode::Observed);
    }

    let exact = PolicyMapKey {
        source_identity,
        destination_identity,
        destination_port,
        protocol,
        bank: config.active_bank,
    };
    let fallback = PolicyMapKey {
        source_identity,
        destination_identity,
        destination_port: [0; 2],
        protocol: 0,
        bank: config.active_bank,
    };
    let value = lookup_policy_value(&exact, config.revision)
        .or_else(|| lookup_policy_value(&fallback, config.revision));
    let Some(value) = value else {
        return DataplaneDecision::observed(ReasonCode::Observed);
    };
    decode_policy_value(value, config.revision)
}

#[inline(always)]
fn lookup_policy_value(key: &PolicyMapKey, revision: u64) -> Option<PolicyMapValue> {
    // SAFETY: POLICY_RULES uses BPF_F_NO_PREALLOC, values have a fixed Copy ABI,
    // and the reference is copied immediately without escaping this lookup.
    #[allow(unsafe_code)]
    let value = unsafe { POLICY_RULES.get(key).copied() }?;
    if value.schema_version == POLICY_MAP_ABI_VERSION && value.revision == revision {
        Some(value)
    } else {
        None
    }
}

#[inline(always)]
fn decode_policy_value(value: PolicyMapValue, revision: u64) -> DataplaneDecision {
    let Some(verdict) = decode_verdict(value.verdict) else {
        return DataplaneDecision::observed(ReasonCode::Observed);
    };
    let Some(reason) = decode_reason(value.reason, verdict) else {
        return DataplaneDecision::observed(ReasonCode::Observed);
    };
    if !valid_provenance(value.flags, value.reason, false) {
        return DataplaneDecision::observed(ReasonCode::Observed);
    }

    let has_shadow = value.flags & POLICY_FLAG_HAS_SHADOW != 0;
    let (shadow_verdict, shadow_reason) = if has_shadow {
        let Some(shadow_verdict) = decode_verdict(value.shadow_verdict) else {
            return DataplaneDecision::observed(ReasonCode::Observed);
        };
        let Some(shadow_reason) = decode_reason(value.shadow_reason, shadow_verdict) else {
            return DataplaneDecision::observed(ReasonCode::Observed);
        };
        if !valid_provenance(value.flags, value.shadow_reason, true) {
            return DataplaneDecision::observed(ReasonCode::Observed);
        }
        (shadow_verdict as u8, shadow_reason)
    } else {
        (Verdict::Unknown as u8, ReasonCode::Observed as u8)
    };

    DataplaneDecision {
        policy_revision: revision,
        policy_id: if value.flags & POLICY_FLAG_HAS_POLICY != 0 {
            value.policy_id
        } else {
            PolicyId::new(0)
        },
        rule_id: if value.flags & POLICY_FLAG_HAS_RULE != 0 {
            value.rule_id
        } else {
            RuleId::new(0)
        },
        shadow_policy_id: if value.flags & POLICY_FLAG_SHADOW_HAS_POLICY != 0 {
            value.shadow_policy_id
        } else {
            PolicyId::new(0)
        },
        shadow_rule_id: if value.flags & POLICY_FLAG_SHADOW_HAS_RULE != 0 {
            value.shadow_rule_id
        } else {
            RuleId::new(0)
        },
        verdict,
        reason,
        shadow_verdict,
        shadow_reason,
    }
}

#[inline(always)]
const fn decode_verdict(value: u8) -> Option<Verdict> {
    match value {
        1 => Some(Verdict::Allow),
        2 => Some(Verdict::Deny),
        _ => None,
    }
}

#[inline(always)]
const fn decode_reason(value: u8, verdict: Verdict) -> Option<u8> {
    match (value, verdict) {
        (reason, Verdict::Allow) if reason == PolicyReason::NoApplicablePolicy as u8 => {
            Some(ReasonCode::Observed as u8)
        }
        (reason, Verdict::Allow) if reason == PolicyReason::ExplicitRule as u8 => {
            Some(ReasonCode::AllowExplicit as u8)
        }
        (reason, Verdict::Deny) if reason == PolicyReason::ExplicitRule as u8 => {
            Some(ReasonCode::DenyExplicit as u8)
        }
        (reason, Verdict::Allow) if reason == PolicyReason::DefaultAction as u8 => {
            Some(ReasonCode::AllowDefault as u8)
        }
        (reason, Verdict::Deny) if reason == PolicyReason::DefaultAction as u8 => {
            Some(ReasonCode::DenyDefault as u8)
        }
        _ => None,
    }
}

#[inline(always)]
const fn valid_provenance(flags: u16, reason: u8, shadow: bool) -> bool {
    let (has_policy, has_rule) = if shadow {
        (
            flags & POLICY_FLAG_SHADOW_HAS_POLICY != 0,
            flags & POLICY_FLAG_SHADOW_HAS_RULE != 0,
        )
    } else {
        (
            flags & POLICY_FLAG_HAS_POLICY != 0,
            flags & POLICY_FLAG_HAS_RULE != 0,
        )
    };
    if reason == PolicyReason::NoApplicablePolicy as u8 {
        !has_policy && !has_rule
    } else if reason == PolicyReason::ExplicitRule as u8 {
        has_policy && has_rule
    } else if reason == PolicyReason::DefaultAction as u8 {
        has_policy && !has_rule
    } else {
        false
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
