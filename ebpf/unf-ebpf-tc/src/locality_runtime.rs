//! Main-object bridge after policy and explicit egress ownership. A bank miss
//! resumes ordinary encryption without rerunning the policy/Service preamble.
use super::*;
use unf_ebpf_common::locality::{ABI_VERSION, PACKET_DSR_PENDING};

pub(super) const DISPATCH: i32 = -1_006;
pub(super) const TRANSPORT: i32 = -1_007;

#[inline(never)]
pub(super) fn prepare<const IPV6: bool>(ctx: &TcContext, observation: &FlowObservation) -> bool {
    if !observation.enforce
        || observation.source_identity.get() == 0
        || observation.destination_identity.get() == 0
        || !supported_transport(observation.protocol)
    {
        return false;
    }
    let (Some(config), Some(identity), Some(fence), Some(input)) = (
        ENCRYPTION_CONFIG.get(0),
        active_identity_config(),
        UL_FENCE_V1.get(0),
        UL_INPUT_V1.get_ptr_mut(0),
    ) else {
        return false;
    };
    // Local topology never replaces current policy/Service/egress authority.
    // Remote transport selection keeps its separate existing validation too.
    if !unf_ebpf_common::encryption_config_has_admitted_cut(config)
        || active_policy_revision() != config.policy_revision
        || active_service_config().map(|value| value.revision) != Some(config.service_revision)
        || fence.schema_version != ABI_VERSION
        || fence.reserved != [0; 6]
        || fence.identity_epoch != identity.source_epoch
        || fence.identity_revision != identity.revision
        || fence.routing_revision == 0
    {
        return false;
    }
    let offset = if IPV6 {
        let Some((protocol, offset, translatable)) = ipv6_transport(ctx) else {
            return false;
        };
        if !translatable || protocol != observation.protocol {
            return false;
        }
        offset
    } else {
        let Ok(version) = ctx.load::<u8>(ETHERNET_HEADER_LEN) else {
            return false;
        };
        if version >> 4 != 4 || !(5..=15).contains(&(version & 15)) {
            return false;
        }
        ETHERNET_HEADER_LEN + usize::from(version & 15) * 4
    };
    let (Ok(source_port), Ok(destination_port)) =
        (ctx.load::<[u8; 2]>(offset), ctx.load::<[u8; 2]>(offset + 2))
    else {
        return false;
    };
    // SAFETY: this invocation owns the per-CPU slot. Policy observation keeps
    // original workload source ownership; ports reflect actual post-NAT bytes.
    #[allow(unsafe_code)]
    let input = unsafe { &mut *input };
    input.identity_epoch = fence.identity_epoch;
    input.identity_revision = fence.identity_revision;
    input.routing_revision = fence.routing_revision;
    input.source_address = observation.source_address;
    input.destination_address = observation.destination_address;
    input.source_identity = observation.source_identity.get();
    input.destination_identity = observation.destination_identity.get();
    // SAFETY: the TC context contains the current skb interface, not a claimed
    // index from packet bytes. The bank independently checks the actual device.
    #[allow(unsafe_code)]
    {
        input.ingress_index = unsafe { (*ctx.skb.skb).ifindex };
    }
    input.schema_version = ABI_VERSION;
    input.family = if IPV6 { 6 } else { 4 };
    input.protocol = observation.protocol;
    input.source_port = source_port;
    input.destination_port = destination_port;
    input.flags = if SERVICE_POST_LOOKUP_SCRATCH.get(0).copied().unwrap_or(0)
        & SERVICE_POST_LOOKUP_TRANSLATED
        != 0
        && service_connection_is_dsr()
    {
        PACKET_DSR_PENDING
    } else {
        0
    };
    true
}

/// Inlined into each classifier so no BPF subprogram frame remains across a
/// tail call. Missing continuation/target drops; it never grants Native itself.
#[inline(always)]
pub(super) fn dispatch_transport<const IPV6: bool>(ctx: &TcContext, action: i32) -> i32 {
    if action == ENCRYPTION_SECURE_NAT_DISPATCH {
        #[allow(unsafe_code)]
        unsafe {
            SERVICE_DATAPLANE_TAIL_CALLS_V2.tail_call(
                ctx,
                if IPV6 {
                    ENCRYPTION_SECURE_NAT_TAIL_V6
                } else {
                    ENCRYPTION_SECURE_NAT_TAIL_V4
                },
            )
        };
        return TC_ACT_SHOT;
    }
    if action == ENCRYPTION_DSR_DISPATCH {
        #[allow(unsafe_code)]
        unsafe {
            SERVICE_DATAPLANE_TAIL_CALLS_V2.tail_call(
                ctx,
                if IPV6 {
                    SERVICE_DSR_TAIL_V6
                } else {
                    SERVICE_DSR_TAIL_V4
                },
            )
        };
        return dsr_route_failed();
    }
    action
}

#[classifier]
pub fn unf_locality_resume_v4(ctx: TcContext) -> i32 {
    let action = encryption_transport_finalizer::<false>(&ctx);
    dispatch_transport::<false>(&ctx, action)
}

#[classifier]
pub fn unf_locality_resume_v6(ctx: TcContext) -> i32 {
    let action = encryption_transport_finalizer::<true>(&ctx);
    dispatch_transport::<true>(&ctx, action)
}

#[inline(never)]
fn translate_local_dsr<const IPV6: bool>(ctx: &TcContext) -> bool {
    let Some(observation) = FLOW_OBSERVATION_SCRATCH.get_ptr(0) else {
        return false;
    };
    // SAFETY: the bank reached this continuation in the same invocation, with
    // the policy-authorized observation retained in the main runtime's slot.
    #[allow(unsafe_code)]
    let observation = unsafe { &*observation };
    secure_dsr_service_translation::<IPV6>(ctx, observation)
        && prepare::<IPV6>(ctx, observation)
        && UL_INPUT_V1.get(0).is_some_and(|input| input.flags == 0)
}

#[classifier]
pub fn unf_locality_nat_v4(ctx: TcContext) -> i32 {
    if translate_local_dsr::<false>(&ctx) {
        // All bank ownership/lease/tuple/FIB checks run again after NAT.
        #[allow(unsafe_code)]
        unsafe {
            UL_DISPATCH_V1.tail_call(&ctx, 0)
        };
    }
    TC_ACT_SHOT
}

#[classifier]
pub fn unf_locality_nat_v6(ctx: TcContext) -> i32 {
    if translate_local_dsr::<true>(&ctx) {
        #[allow(unsafe_code)]
        unsafe {
            UL_DISPATCH_V1.tail_call(&ctx, 0)
        };
    }
    TC_ACT_SHOT
}
