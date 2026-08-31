#![no_std]
#![no_main]

use aya_ebpf::bindings::{
    BPF_F_MARK_MANGLED_0, BPF_F_PSEUDO_HDR,
    BPF_FIB_LKUP_RET_NO_NEIGH, BPF_NOEXIST, TC_ACT_PIPE, TC_ACT_REDIRECT, TC_ACT_SHOT,
    bpf_fib_lookup as BpfFibLookup,
};
use aya_ebpf::helpers::{bpf_fib_lookup, bpf_ktime_get_ns, bpf_redirect, bpf_redirect_neigh};
use aya_ebpf::macros::{classifier, map};
use aya_ebpf::maps::lpm_trie::Key as LpmKey;
use aya_ebpf::maps::{Array, HashMap, LpmTrie, LruHashMap, PerCpuArray, RingBuf};
use aya_ebpf::programs::TcContext;
use unf_common::{BackendId, IdentityId, PolicyId, PolicyReason, RuleId, ServiceId, Verdict};
use unf_ebpf_common::{
    AddressFamily, ConnectionKey, ConnectionState, Direction, EgressIpv4PolicyMapKey,
    EgressIpv6PolicyMapData, FLOW_ABI_VERSION, FlowEvent, IDENTITY_BANK_COUNT,
    IDENTITY_MAP_ABI_VERSION, IPV6_EXTENSION_BYTE_LIMIT, IPV6_EXTENSION_HEADER_LIMIT,
    IPV6_NEXT_HEADER_HOP_BY_HOP, IdentityMapConfig, IdentityMapValue, Ipv4IdentityKey,
    Ipv4LoadBalancerFrontendKey, Ipv4NodePortFrontendKey, Ipv4PolicyMapKey,
    Ipv4ServiceBackendValue, Ipv4ServiceFrontendKey, Ipv6ExtensionStep, Ipv6IdentityKey,
    Ipv6LoadBalancerFrontendKey, Ipv6NodePortFrontendKey, Ipv6PolicyMapData,
    Ipv6ServiceBackendValue, Ipv6ServiceFrontendKey, LoadBalancerFrontendValue,
    LoadBalancerMapConfig, NodePortFrontendValue, NodePortMapConfig,
    NODE_PORT_BANK_COUNT, NODE_PORT_FRONTEND_FLAG_LOCAL, NODE_PORT_LOCAL_FRONTEND_INDEX_FLAG,
    NODE_PORT_MAP_ABI_VERSION, NODE_PORT_SNAT_PORT_PROBES,
    POLICY_BANK_COUNT, POLICY_FLAG_HAS_POLICY, POLICY_FLAG_HAS_RULE, POLICY_FLAG_HAS_SHADOW,
    POLICY_FLAG_SHADOW_HAS_POLICY, POLICY_FLAG_SHADOW_HAS_RULE, POLICY_MAP_ABI_VERSION,
    PolicyMapConfig, PolicyMapKey, PolicyMapValue, ReasonCode, SERVICE_BANK_COUNT,
    SERVICE_CONNECTION_FLAG_NODE_PORT_CLUSTER, SERVICE_CONNECTION_FLAG_NODE_PORT_LOCAL,
    SERVICE_CONNECTION_ROLE_FORWARD, SERVICE_CONNECTION_ROLE_REVERSE, SERVICE_EVENT_ABI_VERSION,
    SERVICE_EVENT_ACTION_DROP, SERVICE_EVENT_ACTION_EXPIRE, SERVICE_EVENT_ACTION_TRANSLATE,
    SERVICE_EVENT_FRONTEND_CLUSTER_IP, SERVICE_EVENT_FRONTEND_NODE_PORT_CLUSTER,
    SERVICE_EVENT_FRONTEND_NODE_PORT_LOCAL,
    SERVICE_EVENT_REASON_EXPIRED_OR_CORRUPT, SERVICE_EVENT_REASON_FORWARD_TRANSLATED,
    SERVICE_EVENT_REASON_INVALID_BACKEND, SERVICE_EVENT_REASON_INVALID_FRONTEND,
    SERVICE_EVENT_REASON_INVALID_SLOT, SERVICE_EVENT_REASON_MISSING_BACKEND,
    SERVICE_EVENT_REASON_MISSING_SLOT, SERVICE_EVENT_REASON_NO_BACKEND,
    SERVICE_EVENT_REASON_PAIR_INSERT_FAILED, SERVICE_EVENT_REASON_REVERSE_TRANSLATED,
    SERVICE_EVENT_REASON_REWRITE_FAILED, SERVICE_MAP_ABI_VERSION, ServiceBackendKey,
    ServiceBackendSlotKey, ServiceBackendSlotValue, ServiceConnectionKey, ServiceConnectionValue,
    ServiceEvent, ServiceFrontendValue, ServiceMapConfig, connection_is_active,
    ipv6_extension_step, packet_starts_connection, service_backend_is_eligible,
    node_port_snat_candidate, service_connection_is_active, service_flow_hash,
};

const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_IPV6: u16 = 0x86dd;
const PROTOCOL_TCP: u8 = 6;
const PROTOCOL_UDP: u8 = 17;
const PROTOCOL_SCTP: u8 = 132;
const ETHERNET_HEADER_LEN: usize = 14;
const BPF_F_NO_PREALLOC: u32 = 1;
const CONNECTION_CAPACITY: u32 = 65_536;
const SERVICE_FRONTEND_CAPACITY: u32 = 262_144;
const SERVICE_BACKEND_CAPACITY: u32 = 524_288;
const SERVICE_BACKEND_SLOT_CAPACITY: u32 = 1_048_576;
const SERVICE_CONNECTION_CAPACITY: u32 = 262_144;
const IPV4_HEADER_CHECKSUM_OFFSET: usize = ETHERNET_HEADER_LEN + 10;
const TCP_CHECKSUM_OFFSET: usize = 16;
const UDP_CHECKSUM_OFFSET: usize = 6;
const ADDRESS_FAMILY_INET: u8 = 2;
const ADDRESS_FAMILY_INET6: u8 = 10;

#[map]
static FLOW_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[map]
static FLOW_COUNTERS: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

#[map]
static FLOW_EVENT_SCRATCH: PerCpuArray<FlowEvent> = PerCpuArray::with_max_entries(1, 0);

#[map]
static SERVICE_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[map]
static SERVICE_EVENT_SCRATCH: PerCpuArray<ServiceEvent> = PerCpuArray::with_max_entries(1, 0);

#[map]
static POLICY_CONNECTION_SCRATCH: PerCpuArray<ConnectionKey> = PerCpuArray::with_max_entries(2, 0);

#[map]
static POLICY_DECISION_SCRATCH: PerCpuArray<DataplaneDecision> =
    PerCpuArray::with_max_entries(1, 0);

#[map]
static POLICY_DIRECTION_DECISION_SCRATCH: PerCpuArray<DataplaneDecision> =
    PerCpuArray::with_max_entries(2, 0);

/// Runtime-only, bounded flow state. Policy maps remain the complete persistent
/// recovery boundary; replacing the eBPF program intentionally resets flows.
#[map]
static CONNECTIONS: LruHashMap<ConnectionKey, ConnectionState> =
    LruHashMap::with_max_entries(CONNECTION_CAPACITY, 0);

#[map]
static IDENTITY_V4: HashMap<Ipv4IdentityKey, IdentityMapValue> =
    HashMap::with_max_entries(65_536, BPF_F_NO_PREALLOC);

#[map]
static IDENTITY_V4_B: HashMap<Ipv4IdentityKey, IdentityMapValue> =
    HashMap::with_max_entries(65_536, BPF_F_NO_PREALLOC);

#[map]
static IDENTITY_V6: HashMap<Ipv6IdentityKey, IdentityMapValue> =
    HashMap::with_max_entries(65_536, BPF_F_NO_PREALLOC);

#[map]
static IDENTITY_V6_B: HashMap<Ipv6IdentityKey, IdentityMapValue> =
    HashMap::with_max_entries(65_536, BPF_F_NO_PREALLOC);

#[map]
static IDENTITY_CONFIG: Array<IdentityMapConfig> = Array::with_max_entries(1, 0);

/// Dual-bank policy state. Userspace stages the inactive bank and atomically
/// changes POLICY_CONFIG[0] only after validating the complete snapshot.
#[map]
static POLICY_RULES: HashMap<PolicyMapKey, PolicyMapValue> =
    HashMap::with_max_entries(262_144, BPF_F_NO_PREALLOC);

/// Exact-source IPv4 compatibility decisions share the active policy bank and
/// revision with identity-keyed policy state.
#[map]
static POLICY_IPV4: HashMap<Ipv4PolicyMapKey, PolicyMapValue> =
    HashMap::with_max_entries(262_144, BPF_F_NO_PREALLOC);

/// Prefix-based IPv6 compatibility decisions share the dual-bank revision.
#[map]
static POLICY_IPV6: LpmTrie<Ipv6PolicyMapData, PolicyMapValue> =
    LpmTrie::with_max_entries(262_144, 0);

/// Exact-destination IPv4 egress decisions share the active policy bank.
#[map]
static EGRESS_IPV4: HashMap<EgressIpv4PolicyMapKey, PolicyMapValue> =
    HashMap::with_max_entries(262_144, BPF_F_NO_PREALLOC);

/// Destination-prefix IPv6 egress decisions share the active policy bank.
#[map]
static EGRESS_IPV6: LpmTrie<EgressIpv6PolicyMapData, PolicyMapValue> =
    LpmTrie::with_max_entries(262_144, 0);

#[map]
static POLICY_CONFIG: Array<PolicyMapConfig> = Array::with_max_entries(1, 0);

/// Service state is staged in the inactive logical bank and becomes visible
/// only through one SERVICE_CONFIG write. The packet path reads only the active
/// bank selected by that pointer.
#[map]
static SERVICE_FRONTENDS_V4: HashMap<Ipv4ServiceFrontendKey, ServiceFrontendValue> =
    HashMap::with_max_entries(SERVICE_FRONTEND_CAPACITY, BPF_F_NO_PREALLOC);

#[map]
static SERVICE_FRONTENDS_V6: HashMap<Ipv6ServiceFrontendKey, ServiceFrontendValue> =
    HashMap::with_max_entries(SERVICE_FRONTEND_CAPACITY, BPF_F_NO_PREALLOC);

#[map]
static SERVICE_BACKENDS_V4: HashMap<ServiceBackendKey, Ipv4ServiceBackendValue> =
    HashMap::with_max_entries(SERVICE_BACKEND_CAPACITY, BPF_F_NO_PREALLOC);

#[map]
static SERVICE_BACKENDS_V6: HashMap<ServiceBackendKey, Ipv6ServiceBackendValue> =
    HashMap::with_max_entries(SERVICE_BACKEND_CAPACITY, BPF_F_NO_PREALLOC);

#[map]
static SERVICE_BACKEND_SLOTS: HashMap<ServiceBackendSlotKey, ServiceBackendSlotValue> =
    HashMap::with_max_entries(SERVICE_BACKEND_SLOT_CAPACITY, BPF_F_NO_PREALLOC);

#[map]
static SERVICE_CONFIG: Array<ServiceMapConfig> = Array::with_max_entries(1, 0);

/// Host-facing state has an independent activation pointer. Values name the
/// exact service bank they reference; the ingress hook distinguishes validated
/// Cluster and node-local slot semantics without widening either policy.
#[map]
static NODE_PORT_FRONTENDS_V4: HashMap<Ipv4NodePortFrontendKey, NodePortFrontendValue> =
    HashMap::with_max_entries(SERVICE_FRONTEND_CAPACITY, BPF_F_NO_PREALLOC);

#[map]
static NODE_PORT_FRONTENDS_V6: HashMap<Ipv6NodePortFrontendKey, NodePortFrontendValue> =
    HashMap::with_max_entries(SERVICE_FRONTEND_CAPACITY, BPF_F_NO_PREALLOC);

#[map]
static NODE_PORT_CONFIG: Array<NodePortMapConfig> = Array::with_max_entries(1, 0);

/// Phase 6 host state is staged independently and remains unconsumed until the
/// following packet-path milestone explicitly admits its revision tuple.
#[map]
static LOAD_BALANCER_FRONTENDS_V4: HashMap<
    Ipv4LoadBalancerFrontendKey,
    LoadBalancerFrontendValue,
> = HashMap::with_max_entries(SERVICE_FRONTEND_CAPACITY, BPF_F_NO_PREALLOC);

#[map]
static LOAD_BALANCER_FRONTENDS_V6: HashMap<
    Ipv6LoadBalancerFrontendKey,
    LoadBalancerFrontendValue,
> = HashMap::with_max_entries(SERVICE_FRONTEND_CAPACITY, BPF_F_NO_PREALLOC);

#[map]
static LOAD_BALANCER_CONFIG: Array<LoadBalancerMapConfig> = Array::with_max_entries(1, 0);

/// Bounded persistent flow translations owned by the Phase 4.5 source-side
/// ClusterIP dataplane.
#[map]
static SERVICE_CONNECTIONS: LruHashMap<ServiceConnectionKey, ServiceConnectionValue> =
    LruHashMap::with_max_entries(SERVICE_CONNECTION_CAPACITY, 0);

/// Runtime-only per-CPU workspace keeps the connection value off the bounded
/// classifier stack. BPF execution is non-preemptible on one CPU.
#[map]
static SERVICE_CONNECTION_SCRATCH: PerCpuArray<ServiceConnectionValue> =
    PerCpuArray::with_max_entries(1, 0);

#[map]
static SERVICE_KEY_SCRATCH: PerCpuArray<ServiceConnectionKey> = PerCpuArray::with_max_entries(1, 0);

#[map]
static FLOW_OBSERVATION_SCRATCH: PerCpuArray<FlowObservation> = PerCpuArray::with_max_entries(1, 0);

#[classifier]
pub fn unf_observe_ingress(ctx: TcContext) -> i32 {
    observe(&ctx, Direction::Ingress, true)
}

#[classifier]
pub fn unf_observe_egress(ctx: TcContext) -> i32 {
    observe(&ctx, Direction::Egress, false)
}

#[inline(always)]
fn observe(ctx: &TcContext, direction: Direction, enforce: bool) -> i32 {
    let Ok(ether_type) = ctx.load::<u16>(12) else {
        return TC_ACT_PIPE;
    };
    match u16::from_be(ether_type) {
        ETHERTYPE_IPV4 => observe_ipv4(ctx, direction, enforce),
        ETHERTYPE_IPV6 => observe_ipv6(ctx, direction, enforce),
        _ => TC_ACT_PIPE,
    }
}

#[inline(never)]
fn observe_ipv4(ctx: &TcContext, direction: Direction, enforce: bool) -> i32 {
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
    let fragment = u16::from_be(fragment);
    if fragment & 0x1fff != 0 {
        // Non-initial fragments do not contain a reliable transport header.
        return TC_ACT_PIPE;
    }
    let service_translatable = fragment & 0x2000 == 0;

    let Ok(protocol) = ctx.load::<u8>(ETHERNET_HEADER_LEN + 9) else {
        return TC_ACT_PIPE;
    };
    if !supported_transport(protocol) {
        return TC_ACT_PIPE;
    }

    let Ok(source_ipv4) = ctx.load::<[u8; 4]>(ETHERNET_HEADER_LEN + 12) else {
        return TC_ACT_PIPE;
    };
    let Ok(mut destination_ipv4) = ctx.load::<[u8; 4]>(ETHERNET_HEADER_LEN + 16) else {
        return TC_ACT_PIPE;
    };
    let transport_offset = ETHERNET_HEADER_LEN + usize::from(ihl_words) * 4;
    let Ok(source_port) = ctx.load::<[u8; 2]>(transport_offset) else {
        return TC_ACT_PIPE;
    };
    let Ok(mut destination_port) = ctx.load::<[u8; 2]>(transport_offset + 2) else {
        return TC_ACT_PIPE;
    };
    let tcp_flags = if protocol == PROTOCOL_TCP {
        let Ok(flags) = ctx.load::<u8>(transport_offset + 13) else {
            return TC_ACT_PIPE;
        };
        flags
    } else {
        0
    };

    let service_protocol = protocol == PROTOCOL_TCP || protocol == PROTOCOL_UDP;
    let mut service_forward_translated = false;
    let mut reroute_host_cluster_ip = false;
    if service_protocol && service_translatable {
        // SAFETY: this helper has no preconditions and returns monotonic kernel time.
        #[allow(unsafe_code)]
        let now_ns = unsafe { bpf_ktime_get_ns() };
        if enforce {
            let Some(key_ptr) = SERVICE_KEY_SCRATCH.get_ptr_mut(0) else {
                return TC_ACT_SHOT;
            };
            // SAFETY: this CPU owns the per-CPU slot for the invocation.
            #[allow(unsafe_code)]
            let forward_key = unsafe { &mut *key_ptr };
            forward_key.source_address = ipv4_address(source_ipv4);
            forward_key.destination_address = ipv4_address(destination_ipv4);
            forward_key.source_port = source_port;
            forward_key.destination_port = destination_port;
            forward_key.protocol = protocol;
            forward_key.address_family = AddressFamily::Ipv4 as u8;
            forward_key.reserved = 0;
            // A Cluster NodePort reply from a remote backend returns to the
            // receiving Node's SNAT address on an ingress hook. Restore it
            // before treating the tuple as a possible new frontend flow.
            forward_key.role = SERVICE_CONNECTION_ROLE_REVERSE;
            if let Some(translation) = lookup_reverse_service(forward_key, now_ns) {
                if !rewrite_ipv4(ctx, transport_offset, protocol, &translation, true)
                    || service_connection_translation(false).is_some_and(
                        |destination_translation| {
                            !rewrite_ipv4(
                                ctx,
                                transport_offset,
                                protocol,
                                &destination_translation,
                                false,
                            )
                        },
                    )
                {
                    emit_service_connection_event(
                        SERVICE_EVENT_ACTION_DROP,
                        SERVICE_EVENT_REASON_REWRITE_FAILED,
                        now_ns,
                    );
                    return TC_ACT_SHOT;
                }
                emit_service_connection_event(
                    SERVICE_EVENT_ACTION_TRANSLATE,
                    SERVICE_EVENT_REASON_REVERSE_TRANSLATED,
                    now_ns,
                );
                return TC_ACT_PIPE;
            }
            forward_key.role = SERVICE_CONNECTION_ROLE_FORWARD;
            match lookup_forward_service_v4(forward_key, now_ns) {
                ServiceLookup::Miss => {}
                ServiceLookup::Drop => return TC_ACT_SHOT,
                ServiceLookup::Translation(translation, _) => {
                    service_forward_translated = true;
                    let backend_address = [
                        translation.address[0],
                        translation.address[1],
                        translation.address[2],
                        translation.address[3],
                    ];
                    if service_connection_translation(true).is_some_and(|source_translation| {
                        !rewrite_ipv4(
                            ctx,
                            transport_offset,
                            protocol,
                            &source_translation,
                            true,
                        )
                    }) || !rewrite_ipv4(ctx, transport_offset, protocol, &translation, false)
                    {
                        emit_service_connection_event(
                            SERVICE_EVENT_ACTION_DROP,
                            SERVICE_EVENT_REASON_REWRITE_FAILED,
                            now_ns,
                        );
                        return TC_ACT_SHOT;
                    }
                    emit_service_connection_event(
                        SERVICE_EVENT_ACTION_TRANSLATE,
                        SERVICE_EVENT_REASON_FORWARD_TRANSLATED,
                        now_ns,
                    );
                    destination_ipv4 = backend_address;
                    destination_port = translation.port;
                }
            }
        } else {
            let Some(key_ptr) = SERVICE_KEY_SCRATCH.get_ptr_mut(0) else {
                return TC_ACT_SHOT;
            };
            // SAFETY: this CPU owns the per-CPU slot for the invocation.
            #[allow(unsafe_code)]
            let service_key = unsafe { &mut *key_ptr };
            service_key.source_address = ipv4_address(source_ipv4);
            service_key.destination_address = ipv4_address(destination_ipv4);
            service_key.source_port = source_port;
            service_key.destination_port = destination_port;
            service_key.protocol = protocol;
            service_key.address_family = AddressFamily::Ipv4 as u8;
            service_key.role = SERVICE_CONNECTION_ROLE_REVERSE;
            service_key.reserved = 0;
            if let Some(translation) = lookup_reverse_service(service_key, now_ns) {
                if !rewrite_ipv4(ctx, transport_offset, protocol, &translation, true)
                    || service_connection_translation(false).is_some_and(
                        |destination_translation| {
                            !rewrite_ipv4(
                                ctx,
                                transport_offset,
                                protocol,
                                &destination_translation,
                                false,
                            )
                        },
                    )
                {
                    emit_service_connection_event(
                        SERVICE_EVENT_ACTION_DROP,
                        SERVICE_EVENT_REASON_REWRITE_FAILED,
                        now_ns,
                    );
                    return TC_ACT_SHOT;
                }
                emit_service_connection_event(
                    SERVICE_EVENT_ACTION_TRANSLATE,
                    SERVICE_EVENT_REASON_REVERSE_TRANSLATED,
                    now_ns,
                );
            } else {
                // Host-network and Node-origin traffic reaches the uplink's
                // egress hook without first traversing a workload-veth ingress
                // hook. Give an untranslated frontend the same bounded lookup
                // and connection-pair transaction used for workload traffic.
                service_key.role = SERVICE_CONNECTION_ROLE_FORWARD;
                match lookup_forward_service_v4(service_key, now_ns) {
                    ServiceLookup::Miss => {}
                    ServiceLookup::Drop => return TC_ACT_SHOT,
                    ServiceLookup::Translation(translation, cluster_ip) => {
                        service_forward_translated = true;
                        reroute_host_cluster_ip = cluster_ip;
                        let backend_address = [
                            translation.address[0],
                            translation.address[1],
                            translation.address[2],
                            translation.address[3],
                        ];
                        if service_connection_translation(true).is_some_and(
                            |source_translation| {
                                !rewrite_ipv4(
                                    ctx,
                                    transport_offset,
                                    protocol,
                                    &source_translation,
                                    true,
                                )
                            },
                        ) || !rewrite_ipv4(ctx, transport_offset, protocol, &translation, false)
                        {
                            emit_service_connection_event(
                                SERVICE_EVENT_ACTION_DROP,
                                SERVICE_EVENT_REASON_REWRITE_FAILED,
                                now_ns,
                            );
                            return TC_ACT_SHOT;
                        }
                        emit_service_connection_event(
                            SERVICE_EVENT_ACTION_TRANSLATE,
                            SERVICE_EVENT_REASON_FORWARD_TRANSLATED,
                            now_ns,
                        );
                        destination_ipv4 = backend_address;
                        destination_port = translation.port;
                    }
                }
            }
        }
    }

    let source_address = ipv4_address(source_ipv4);
    let destination_address = ipv4_address(destination_ipv4);
    let identity_config = active_identity_config();
    let Some(observation_ptr) = FLOW_OBSERVATION_SCRATCH.get_ptr_mut(0) else {
        return TC_ACT_SHOT;
    };
    // SAFETY: this CPU owns the per-CPU slot for the invocation.
    #[allow(unsafe_code)]
    let observation = unsafe { &mut *observation_ptr };
    observation.direction = direction;
    observation.source_address = source_address;
    observation.destination_address = destination_address;
    observation.source_port = source_port;
    observation.destination_port = destination_port;
    observation.protocol = protocol;
    observation.address_family = AddressFamily::Ipv4;
    observation.source_identity = lookup_identity_v4(source_ipv4, identity_config);
    observation.destination_identity = lookup_identity_v4(destination_ipv4, identity_config);
    observation.tcp_flags = tcp_flags;
    observation.enforce = enforce;
    let action = emit_flow(observation);
    if action == TC_ACT_SHOT {
        return action;
    }
    if service_forward_translated {
        seed_service_frontend_policy_connection(tcp_flags);
        if !enforce && reroute_host_cluster_ip {
            return reroute_host_service_v4(ctx, observation);
        }
    }
    action
}

#[inline(never)]
fn observe_ipv6(ctx: &TcContext, direction: Direction, enforce: bool) -> i32 {
    let Ok(version) = ctx.load::<u8>(ETHERNET_HEADER_LEN) else {
        return TC_ACT_PIPE;
    };
    if version >> 4 != 6 {
        return TC_ACT_PIPE;
    }
    let Some((protocol, transport_offset, service_translatable)) = ipv6_transport(ctx) else {
        return TC_ACT_PIPE;
    };
    let Some(observation_ptr) = FLOW_OBSERVATION_SCRATCH.get_ptr_mut(0) else {
        return TC_ACT_SHOT;
    };
    // SAFETY: this CPU owns the per-CPU slot for the invocation.
    #[allow(unsafe_code)]
    let observation = unsafe { &mut *observation_ptr };
    let Ok(address) = ctx.load::<[u8; 16]>(ETHERNET_HEADER_LEN + 8) else {
        return TC_ACT_PIPE;
    };
    observation.source_address = address;
    let Ok(address) = ctx.load::<[u8; 16]>(ETHERNET_HEADER_LEN + 24) else {
        return TC_ACT_PIPE;
    };
    observation.destination_address = address;
    let Ok(port) = ctx.load::<[u8; 2]>(transport_offset) else {
        return TC_ACT_PIPE;
    };
    observation.source_port = port;
    let Ok(port) = ctx.load::<[u8; 2]>(transport_offset + 2) else {
        return TC_ACT_PIPE;
    };
    observation.destination_port = port;
    observation.tcp_flags = if protocol == PROTOCOL_TCP {
        let Ok(flags) = ctx.load::<u8>(transport_offset + 13) else {
            return TC_ACT_PIPE;
        };
        flags
    } else {
        0
    };
    let service_protocol = protocol == PROTOCOL_TCP || protocol == PROTOCOL_UDP;
    let mut service_forward_translated = false;
    let mut reroute_host_cluster_ip = false;
    if service_protocol && service_translatable {
        // SAFETY: this helper has no preconditions and returns monotonic kernel time.
        #[allow(unsafe_code)]
        let now_ns = unsafe { bpf_ktime_get_ns() };
        if enforce {
            let Some(key_ptr) = SERVICE_KEY_SCRATCH.get_ptr_mut(0) else {
                return TC_ACT_SHOT;
            };
            // SAFETY: this CPU owns the per-CPU slot for the invocation.
            #[allow(unsafe_code)]
            let forward_key = unsafe { &mut *key_ptr };
            forward_key.source_address = observation.source_address;
            forward_key.destination_address = observation.destination_address;
            forward_key.source_port = observation.source_port;
            forward_key.destination_port = observation.destination_port;
            forward_key.protocol = protocol;
            forward_key.address_family = AddressFamily::Ipv6 as u8;
            forward_key.reserved = 0;
            forward_key.role = SERVICE_CONNECTION_ROLE_REVERSE;
            if let Some(translation) = lookup_reverse_service(forward_key, now_ns) {
                if !rewrite_ipv6(ctx, transport_offset, protocol, &translation, true)
                    || service_connection_translation(false).is_some_and(
                        |destination_translation| {
                            !rewrite_ipv6(
                                ctx,
                                transport_offset,
                                protocol,
                                &destination_translation,
                                false,
                            )
                        },
                    )
                {
                    emit_service_connection_event(
                        SERVICE_EVENT_ACTION_DROP,
                        SERVICE_EVENT_REASON_REWRITE_FAILED,
                        now_ns,
                    );
                    return TC_ACT_SHOT;
                }
                emit_service_connection_event(
                    SERVICE_EVENT_ACTION_TRANSLATE,
                    SERVICE_EVENT_REASON_REVERSE_TRANSLATED,
                    now_ns,
                );
                return TC_ACT_PIPE;
            }
            forward_key.role = SERVICE_CONNECTION_ROLE_FORWARD;
            match lookup_forward_service_v6(forward_key, now_ns) {
                ServiceLookup::Miss => {}
                ServiceLookup::Drop => return TC_ACT_SHOT,
                ServiceLookup::Translation(translation, _) => {
                    service_forward_translated = true;
                    if service_connection_translation(true).is_some_and(|source_translation| {
                        !rewrite_ipv6(
                            ctx,
                            transport_offset,
                            protocol,
                            &source_translation,
                            true,
                        )
                    }) || !rewrite_ipv6(ctx, transport_offset, protocol, &translation, false)
                    {
                        emit_service_connection_event(
                            SERVICE_EVENT_ACTION_DROP,
                            SERVICE_EVENT_REASON_REWRITE_FAILED,
                            now_ns,
                        );
                        return TC_ACT_SHOT;
                    }
                    emit_service_connection_event(
                        SERVICE_EVENT_ACTION_TRANSLATE,
                        SERVICE_EVENT_REASON_FORWARD_TRANSLATED,
                        now_ns,
                    );
                    observation.destination_address = translation.address;
                    observation.destination_port = translation.port;
                }
            }
        } else {
            let Some(key_ptr) = SERVICE_KEY_SCRATCH.get_ptr_mut(0) else {
                return TC_ACT_SHOT;
            };
            // SAFETY: this CPU owns the per-CPU slot for the invocation.
            #[allow(unsafe_code)]
            let service_key = unsafe { &mut *key_ptr };
            service_key.source_address = observation.source_address;
            service_key.destination_address = observation.destination_address;
            service_key.source_port = observation.source_port;
            service_key.destination_port = observation.destination_port;
            service_key.protocol = protocol;
            service_key.address_family = AddressFamily::Ipv6 as u8;
            service_key.role = SERVICE_CONNECTION_ROLE_REVERSE;
            service_key.reserved = 0;
            if let Some(translation) = lookup_reverse_service(service_key, now_ns) {
                if !rewrite_ipv6(ctx, transport_offset, protocol, &translation, true)
                    || service_connection_translation(false).is_some_and(
                        |destination_translation| {
                            !rewrite_ipv6(
                                ctx,
                                transport_offset,
                                protocol,
                                &destination_translation,
                                false,
                            )
                        },
                    )
                {
                    emit_service_connection_event(
                        SERVICE_EVENT_ACTION_DROP,
                        SERVICE_EVENT_REASON_REWRITE_FAILED,
                        now_ns,
                    );
                    return TC_ACT_SHOT;
                }
                emit_service_connection_event(
                    SERVICE_EVENT_ACTION_TRANSLATE,
                    SERVICE_EVENT_REASON_REVERSE_TRANSLATED,
                    now_ns,
                );
            } else {
                service_key.role = SERVICE_CONNECTION_ROLE_FORWARD;
                match lookup_forward_service_v6(service_key, now_ns) {
                    ServiceLookup::Miss => {}
                ServiceLookup::Drop => return TC_ACT_SHOT,
                ServiceLookup::Translation(translation, cluster_ip) => {
                    service_forward_translated = true;
                    reroute_host_cluster_ip = cluster_ip;
                    if service_connection_translation(true).is_some_and(
                            |source_translation| {
                                !rewrite_ipv6(
                                    ctx,
                                    transport_offset,
                                    protocol,
                                    &source_translation,
                                    true,
                                )
                            },
                        ) || !rewrite_ipv6(ctx, transport_offset, protocol, &translation, false)
                        {
                            emit_service_connection_event(
                                SERVICE_EVENT_ACTION_DROP,
                                SERVICE_EVENT_REASON_REWRITE_FAILED,
                                now_ns,
                            );
                            return TC_ACT_SHOT;
                        }
                        emit_service_connection_event(
                            SERVICE_EVENT_ACTION_TRANSLATE,
                            SERVICE_EVENT_REASON_FORWARD_TRANSLATED,
                            now_ns,
                        );
                        observation.destination_address = translation.address;
                        observation.destination_port = translation.port;
                    }
                }
            }
        }
    }

    let identity_config = active_identity_config();
    observation.direction = direction;
    observation.protocol = protocol;
    observation.address_family = AddressFamily::Ipv6;
    observation.source_identity = lookup_identity_v6(observation.source_address, identity_config);
    observation.destination_identity =
        lookup_identity_v6(observation.destination_address, identity_config);
    observation.enforce = enforce;
    let action = emit_flow(observation);
    if action == TC_ACT_SHOT {
        return action;
    }
    if service_forward_translated {
        seed_service_frontend_policy_connection(observation.tcp_flags);
        if !enforce && reroute_host_cluster_ip {
            return reroute_host_service_v6(ctx, observation);
        }
    }
    action
}

#[inline(always)]
fn ipv6_transport(ctx: &TcContext) -> Option<(u8, usize, bool)> {
    let payload_length = u16::from_be(ctx.load::<u16>(ETHERNET_HEADER_LEN + 4).ok()?);
    // Jumbograms require parsing the Hop-by-Hop Jumbo Payload option and remain
    // outside this bounded parser.
    if payload_length == 0 {
        return None;
    }
    let payload_start = ETHERNET_HEADER_LEN + 40;
    let payload_end = payload_start + payload_length as usize;
    let mut next_header = ctx.load::<u8>(ETHERNET_HEADER_LEN + 6).ok()?;
    let mut offset = payload_start;
    let mut extension_bytes = 0_usize;
    let mut service_translatable = true;

    for depth in 0..=IPV6_EXTENSION_HEADER_LIMIT {
        if supported_transport(next_header) {
            if offset + 4 > payload_end {
                return None;
            }
            return Some((next_header, offset, service_translatable));
        }
        if depth == IPV6_EXTENSION_HEADER_LIMIT
            || (next_header == IPV6_NEXT_HEADER_HOP_BY_HOP && depth != 0)
            || offset + 8 > payload_end
        {
            return None;
        }
        let header = ctx.load::<[u8; 8]>(offset).ok()?;
        if next_header == unf_ebpf_common::IPV6_NEXT_HEADER_FRAGMENT {
            service_translatable = false;
        }
        let Ipv6ExtensionStep::Continue {
            next_header: following,
            length,
        } = ipv6_extension_step(next_header, header)
        else {
            return None;
        };
        extension_bytes += length;
        if extension_bytes > IPV6_EXTENSION_BYTE_LIMIT || offset + length > payload_end {
            return None;
        }
        offset += length;
        next_header = following;
    }
    None
}

#[inline(always)]
const fn supported_transport(protocol: u8) -> bool {
    protocol == PROTOCOL_TCP || protocol == PROTOCOL_UDP || protocol == PROTOCOL_SCTP
}

#[derive(Clone, Copy)]
struct FlowObservation {
    source_address: [u8; 16],
    destination_address: [u8; 16],
    source_port: [u8; 2],
    destination_port: [u8; 2],
    source_identity: IdentityId,
    destination_identity: IdentityId,
    direction: Direction,
    address_family: AddressFamily,
    protocol: u8,
    tcp_flags: u8,
    enforce: bool,
}

#[derive(Clone, Copy)]
struct ServiceTranslation {
    address: [u8; 16],
    port: [u8; 2],
}

#[derive(Clone, Copy)]
enum ServiceLookup {
    Miss,
    Drop,
    Translation(ServiceTranslation, bool),
}

#[inline(always)]
const fn ipv4_address(address: [u8; 4]) -> [u8; 16] {
    let mut expanded = [0_u8; 16];
    expanded[0] = address[0];
    expanded[1] = address[1];
    expanded[2] = address[2];
    expanded[3] = address[3];
    expanded
}

#[inline(always)]
fn active_service_config() -> Option<ServiceMapConfig> {
    let config = SERVICE_CONFIG.get(0).copied()?;
    if config.schema_version != SERVICE_MAP_ABI_VERSION
        || config.active_bank >= SERVICE_BANK_COUNT
        || config.source_epoch == 0
        || config.revision == 0
        || config.flags != 0
    {
        return None;
    }
    Some(config)
}

#[inline(always)]
fn active_node_port_config(service: ServiceMapConfig) -> Option<NodePortMapConfig> {
    let config = NODE_PORT_CONFIG.get(0).copied()?;
    if config.schema_version != NODE_PORT_MAP_ABI_VERSION
        || config.active_bank >= NODE_PORT_BANK_COUNT
        || config.source_epoch == 0
        || config.service_revision == 0
        || config.node_revision == 0
        || config.source_epoch != service.source_epoch
        || config.service_revision != service.revision
        || config.ipv4_count > SERVICE_FRONTEND_CAPACITY / 2
        || config.ipv6_count > SERVICE_FRONTEND_CAPACITY / 2
        || config.flags != 0
        || config.reserved != 0
    {
        return None;
    }
    Some(config)
}

/// Returns the additional source translation for a Cluster NodePort forward
/// packet, or the destination restoration for its reverse packet.
#[inline(always)]
fn service_connection_translation(forward: bool) -> Option<ServiceTranslation> {
    let value_ptr = SERVICE_CONNECTION_SCRATCH.get_ptr_mut(0)?;
    // SAFETY: the active lookup initialized this CPU's unique scratch slot.
    #[allow(unsafe_code)]
    let value = unsafe { &*value_ptr };
    if value.flags & SERVICE_CONNECTION_FLAG_NODE_PORT_CLUSTER == 0 {
        return None;
    }
    if forward {
        Some(ServiceTranslation {
            address: value.frontend_address,
            port: node_port_snat_port(value),
        })
    } else {
        Some(ServiceTranslation {
            address: value.client_address,
            port: value.client_port,
        })
    }
}

#[inline(always)]
fn validate_node_port_frontend(
    forward_key: &ServiceConnectionKey,
    frontend: NodePortFrontendValue,
    config: NodePortMapConfig,
    service: ServiceMapConfig,
    now_ns: u64,
) -> Result<(ServiceFrontendValue, u16), ()> {
    if frontend.schema_version != NODE_PORT_MAP_ABI_VERSION
        || frontend.service_revision != config.service_revision
        || frontend.service_revision != service.revision
        || frontend.service_id.get() == 0
        || frontend.service_bank != service.active_bank
        || frontend.flags & !NODE_PORT_FRONTEND_FLAG_LOCAL != 0
        || (frontend.flags & NODE_PORT_FRONTEND_FLAG_LOCAL != 0
            && frontend.frontend_index & NODE_PORT_LOCAL_FRONTEND_INDEX_FLAG == 0)
        || (frontend.flags & NODE_PORT_FRONTEND_FLAG_LOCAL == 0
            && frontend.frontend_index & NODE_PORT_LOCAL_FRONTEND_INDEX_FLAG != 0)
        || frontend.reserved != [0; 7]
    {
        emit_service_lookup_failure(
            forward_key,
            frontend.service_id,
            frontend.service_revision,
            service_event_failure_metadata(
                SERVICE_EVENT_REASON_INVALID_FRONTEND,
                node_port_event_frontend_kind(frontend.flags),
            ),
            now_ns,
        );
        return Err(());
    }
    let connection_flags = if frontend.flags & NODE_PORT_FRONTEND_FLAG_LOCAL != 0 {
        SERVICE_CONNECTION_FLAG_NODE_PORT_LOCAL
    } else {
        SERVICE_CONNECTION_FLAG_NODE_PORT_CLUSTER
    };
    Ok((
        ServiceFrontendValue {
            service_id: frontend.service_id,
            frontend_index: frontend.frontend_index,
            backend_count: frontend.backend_count,
            schema_version: SERVICE_MAP_ABI_VERSION,
            flags: 0,
            revision: frontend.service_revision,
            reserved: [0; 8],
        },
        connection_flags,
    ))
}

#[inline(always)]
const fn node_port_event_frontend_kind(flags: u16) -> u8 {
    if flags & NODE_PORT_FRONTEND_FLAG_LOCAL != 0 {
        SERVICE_EVENT_FRONTEND_NODE_PORT_LOCAL
    } else {
        SERVICE_EVENT_FRONTEND_NODE_PORT_CLUSTER
    }
}

#[inline(always)]
const fn connection_event_frontend_kind(flags: u16) -> u8 {
    if flags & SERVICE_CONNECTION_FLAG_NODE_PORT_LOCAL != 0 {
        SERVICE_EVENT_FRONTEND_NODE_PORT_LOCAL
    } else if flags & SERVICE_CONNECTION_FLAG_NODE_PORT_CLUSTER != 0 {
        SERVICE_EVENT_FRONTEND_NODE_PORT_CLUSTER
    } else {
        SERVICE_EVENT_FRONTEND_CLUSTER_IP
    }
}

#[inline(always)]
const fn service_event_failure_metadata(reason: u8, frontend_kind: u8) -> u16 {
    reason as u16 | ((frontend_kind as u16) << 8)
}

#[inline(never)]
fn emit_service_connection_event(action: u8, reason: u8, timestamp_ns: u64) {
    let Some(value_ptr) = SERVICE_CONNECTION_SCRATCH.get_ptr_mut(0) else {
        return;
    };
    // SAFETY: this CPU owns the initialized connection scratch value.
    #[allow(unsafe_code)]
    let value = unsafe { &*value_ptr };
    let Some(event_ptr) = SERVICE_EVENT_SCRATCH.get_ptr_mut(0) else {
        return;
    };
    // SAFETY: this CPU owns the per-CPU event slot for this invocation.
    #[allow(unsafe_code)]
    let event = unsafe { &mut *event_ptr };
    event.timestamp_ns = timestamp_ns;
    event.service_revision = value.service_revision;
    event.client_address = value.client_address;
    event.frontend_address = value.frontend_address;
    event.backend_address = value.backend_address;
    event.service_id = value.service_id;
    event.backend_id = value.backend_id;
    event.client_port = value.client_port;
    event.frontend_port = value.frontend_port;
    event.backend_port = value.backend_port;
    event.version = SERVICE_EVENT_ABI_VERSION;
    event.size = core::mem::size_of::<ServiceEvent>() as u16;
    event.protocol = value.protocol;
    event.address_family = value.address_family;
    event.action = action;
    event.reason = reason;
    event.reserved = [0; 10];
    event.reserved[0] = connection_event_frontend_kind(value.flags);
    let _ = SERVICE_EVENTS.output::<ServiceEvent>(&*event, 0);
}

#[inline(never)]
fn emit_service_lookup_failure(
    key: &ServiceConnectionKey,
    service_id: ServiceId,
    service_revision: u64,
    failure_metadata: u16,
    timestamp_ns: u64,
) {
    let reason = failure_metadata as u8;
    let frontend_kind = (failure_metadata >> 8) as u8;
    let Some(event_ptr) = SERVICE_EVENT_SCRATCH.get_ptr_mut(0) else {
        return;
    };
    // SAFETY: this CPU owns the per-CPU event slot for this invocation.
    #[allow(unsafe_code)]
    let event = unsafe { &mut *event_ptr };
    event.timestamp_ns = timestamp_ns;
    event.service_revision = service_revision;
    event.client_address = key.source_address;
    event.frontend_address = key.destination_address;
    event.backend_address = [0; 16];
    event.service_id = service_id;
    event.backend_id = BackendId::new(0);
    event.client_port = key.source_port;
    event.frontend_port = key.destination_port;
    event.backend_port = [0; 2];
    event.version = SERVICE_EVENT_ABI_VERSION;
    event.size = core::mem::size_of::<ServiceEvent>() as u16;
    event.protocol = key.protocol;
    event.address_family = key.address_family;
    event.action = SERVICE_EVENT_ACTION_DROP;
    event.reason = reason;
    event.reserved = [0; 10];
    event.reserved[0] = frontend_kind;
    let _ = SERVICE_EVENTS.output::<ServiceEvent>(&*event, 0);
}

#[inline(always)]
fn service_forward_key(value: &ServiceConnectionValue) -> ServiceConnectionKey {
    ServiceConnectionKey {
        source_address: value.client_address,
        destination_address: value.frontend_address,
        source_port: value.client_port,
        destination_port: value.frontend_port,
        protocol: value.protocol,
        address_family: value.address_family,
        role: SERVICE_CONNECTION_ROLE_FORWARD,
        reserved: 0,
    }
}

#[inline(always)]
fn service_reverse_key(value: &ServiceConnectionValue) -> ServiceConnectionKey {
    let node_port_cluster =
        value.flags & SERVICE_CONNECTION_FLAG_NODE_PORT_CLUSTER != 0;
    ServiceConnectionKey {
        source_address: value.backend_address,
        destination_address: if node_port_cluster {
            value.frontend_address
        } else {
            value.client_address
        },
        source_port: value.backend_port,
        destination_port: if node_port_cluster {
            node_port_snat_port(value)
        } else {
            value.client_port
        },
        protocol: value.protocol,
        address_family: value.address_family,
        role: SERVICE_CONNECTION_ROLE_REVERSE,
        reserved: 0,
    }
}

#[inline(always)]
fn node_port_snat_port(value: &ServiceConnectionValue) -> [u8; 2] {
    [value.reserved[0], value.reserved[1]]
}

#[inline(always)]
fn remove_service_pair(value: &ServiceConnectionValue) {
    let _ = SERVICE_CONNECTIONS.remove(&service_forward_key(value));
    let _ = SERVICE_CONNECTIONS.remove(&service_reverse_key(value));
}

#[inline(always)]
fn store_service_pair(value: &ServiceConnectionValue) -> bool {
    let reverse = service_reverse_key(value);
    if SERVICE_CONNECTIONS.insert(&reverse, value, 0).is_err() {
        return false;
    }
    let forward = service_forward_key(value);
    if SERVICE_CONNECTIONS.insert(&forward, value, 0).is_err() {
        let _ = SERVICE_CONNECTIONS.remove(&reverse);
        return false;
    }
    true
}

#[inline(always)]
fn insert_new_service_pair(value: &ServiceConnectionValue) -> bool {
    let reverse = service_reverse_key(value);
    if SERVICE_CONNECTIONS
        .insert(&reverse, value, BPF_NOEXIST as u64)
        .is_err()
    {
        return false;
    }
    let forward = service_forward_key(value);
    if SERVICE_CONNECTIONS
        .insert(&forward, value, BPF_NOEXIST as u64)
        .is_err()
    {
        let _ = SERVICE_CONNECTIONS.remove(&reverse);
        return false;
    }
    true
}

#[inline(always)]
fn refresh_service_connection(
    key: &ServiceConnectionKey,
    now_ns: u64,
) -> Option<(ServiceTranslation, bool)> {
    // SAFETY: the fixed-layout value is copied before any update and no map
    // reference escapes this lookup.
    #[allow(unsafe_code)]
    let Some(stored) = (unsafe { SERVICE_CONNECTIONS.get(key) }) else {
        return None;
    };
    let Some(scratch) = SERVICE_CONNECTION_SCRATCH.get_ptr_mut(0) else {
        return None;
    };
    // SAFETY: `scratch` points at this CPU's unique map value. `stored` is a
    // valid fixed-layout map value and is copied before SERVICE_CONNECTIONS is
    // mutated.
    #[allow(unsafe_code)]
    unsafe {
        scratch.write(*stored);
    }
    // SAFETY: the pointer remains valid for this non-preemptible invocation.
    #[allow(unsafe_code)]
    let value = unsafe { &mut *scratch };
    let expected = if key.role == SERVICE_CONNECTION_ROLE_FORWARD {
        service_forward_key(value)
    } else if key.role == SERVICE_CONNECTION_ROLE_REVERSE {
        service_reverse_key(value)
    } else {
        let _ = SERVICE_CONNECTIONS.remove(key);
        return None;
    };
    if expected != *key || !service_connection_is_active(value, now_ns) {
        emit_service_connection_event(
            SERVICE_EVENT_ACTION_EXPIRE,
            SERVICE_EVENT_REASON_EXPIRED_OR_CORRUPT,
            now_ns,
        );
        remove_service_pair(value);
        return None;
    }
    let translation = if key.role == SERVICE_CONNECTION_ROLE_FORWARD {
        ServiceTranslation {
            address: value.backend_address,
            port: value.backend_port,
        }
    } else {
        ServiceTranslation {
            address: value.frontend_address,
            port: value.frontend_port,
        }
    };
    value.last_seen_ns = now_ns;
    if !store_service_pair(value) {
        remove_service_pair(value);
        return None;
    }
    let cluster_ip = value.flags
        & (SERVICE_CONNECTION_FLAG_NODE_PORT_CLUSTER | SERVICE_CONNECTION_FLAG_NODE_PORT_LOCAL)
        == 0;
    Some((translation, cluster_ip))
}

#[allow(clippy::too_many_arguments)]
#[inline(always)]
fn new_service_connection(
    client_address: [u8; 16],
    frontend_address: [u8; 16],
    backend_address: [u8; 16],
    client_port: [u8; 2],
    frontend_port: [u8; 2],
    backend_port: [u8; 2],
    protocol: u8,
    address_family: AddressFamily,
    frontend: ServiceFrontendValue,
    backend_id: unf_common::BackendId,
    flags: u16,
    now_ns: u64,
) -> Option<ServiceTranslation> {
    let scratch = SERVICE_CONNECTION_SCRATCH.get_ptr_mut(0)?;
    // SAFETY: the pointer addresses this CPU's unique, initialized array slot.
    #[allow(unsafe_code)]
    let value = unsafe { &mut *scratch };
    value.last_seen_ns = now_ns;
    value.service_revision = frontend.revision;
    value.client_address = client_address;
    value.frontend_address = frontend_address;
    value.backend_address = backend_address;
    value.service_id = frontend.service_id;
    value.backend_id = backend_id;
    value.client_port = client_port;
    value.frontend_port = frontend_port;
    value.backend_port = backend_port;
    value.schema_version = SERVICE_MAP_ABI_VERSION;
    value.protocol = protocol;
    value.address_family = address_family as u8;
    value.flags = flags;
    value.reserved = [0; 4];
    if flags & SERVICE_CONNECTION_FLAG_NODE_PORT_CLUSTER != 0 {
        let hash = service_flow_hash(&service_forward_key(value), frontend.service_id);
        let mut probe = 0_u32;
        while probe < NODE_PORT_SNAT_PORT_PROBES {
            let port = node_port_snat_candidate(hash, probe);
            value.reserved[0..2].copy_from_slice(&port.to_be_bytes());
            if insert_new_service_pair(value) {
                return Some(ServiceTranslation {
                    address: backend_address,
                    port: backend_port,
                });
            }
            probe += 1;
        }
        return None;
    }
    if !insert_new_service_pair(value) {
        return None;
    }
    Some(ServiceTranslation {
        address: backend_address,
        port: backend_port,
    })
}

#[allow(clippy::too_many_arguments)]
#[inline(never)]
fn lookup_forward_service_v4(forward_key: &ServiceConnectionKey, now_ns: u64) -> ServiceLookup {
    if let Some((translation, cluster_ip)) = refresh_service_connection(forward_key, now_ns) {
        return ServiceLookup::Translation(translation, cluster_ip);
    }

    let Some(config) = active_service_config() else {
        return ServiceLookup::Miss;
    };
    let frontend_key = Ipv4ServiceFrontendKey {
        address: [
            forward_key.destination_address[0],
            forward_key.destination_address[1],
            forward_key.destination_address[2],
            forward_key.destination_address[3],
        ],
        port: forward_key.destination_port,
        protocol: forward_key.protocol,
        bank: config.active_bank,
    };
    // SAFETY: the exact key and fixed-layout value match the declared map ABI;
    // the value is copied before any other map operation.
    #[allow(unsafe_code)]
    let cluster_frontend = unsafe { SERVICE_FRONTENDS_V4.get(&frontend_key).copied() };
    let (frontend, service_bank, connection_flags, frontend_kind) =
        if let Some(frontend) = cluster_frontend {
            (frontend, config.active_bank, 0, SERVICE_EVENT_FRONTEND_CLUSTER_IP)
    } else {
        let Some(node_port_config) = active_node_port_config(config) else {
            return ServiceLookup::Miss;
        };
        let node_port_key = Ipv4NodePortFrontendKey {
            address: [
                forward_key.destination_address[0],
                forward_key.destination_address[1],
                forward_key.destination_address[2],
                forward_key.destination_address[3],
            ],
            port: forward_key.destination_port,
            protocol: forward_key.protocol,
            bank: node_port_config.active_bank,
        };
        // SAFETY: the exact key and fixed-layout value match the declared map
        // ABI and the value is copied before any other map operation.
        #[allow(unsafe_code)]
        let Some(node_port_frontend) =
            (unsafe { NODE_PORT_FRONTENDS_V4.get(&node_port_key).copied() })
        else {
            return ServiceLookup::Miss;
        };
        let Ok((frontend, connection_flags)) = validate_node_port_frontend(
            forward_key,
            node_port_frontend,
            node_port_config,
            config,
            now_ns,
        ) else {
            return ServiceLookup::Drop;
        };
        (
            frontend,
            node_port_frontend.service_bank,
            connection_flags,
            node_port_event_frontend_kind(node_port_frontend.flags),
        )
    };
    if frontend.schema_version != SERVICE_MAP_ABI_VERSION
        || frontend.revision != config.revision
        || frontend.service_id.get() == 0
        || frontend.flags != 0
        || frontend.reserved != [0; 8]
    {
        emit_service_lookup_failure(
            forward_key,
            frontend.service_id,
            frontend.revision,
            service_event_failure_metadata(SERVICE_EVENT_REASON_INVALID_FRONTEND, frontend_kind),
            now_ns,
        );
        return ServiceLookup::Drop;
    }
    if frontend.backend_count == 0 {
        emit_service_lookup_failure(
            forward_key,
            frontend.service_id,
            frontend.revision,
            service_event_failure_metadata(SERVICE_EVENT_REASON_NO_BACKEND, frontend_kind),
            now_ns,
        );
        return ServiceLookup::Drop;
    }
    let slot_key = ServiceBackendSlotKey {
        service_id: frontend.service_id,
        frontend_index: frontend.frontend_index,
        slot: service_flow_hash(forward_key, frontend.service_id) % frontend.backend_count,
        bank: service_bank,
        reserved: [0; 3],
    };
    // SAFETY: the exact key and fixed-layout value match the declared map ABI.
    #[allow(unsafe_code)]
    let Some(slot) = (unsafe { SERVICE_BACKEND_SLOTS.get(&slot_key).copied() }) else {
        emit_service_lookup_failure(
            forward_key,
            frontend.service_id,
            frontend.revision,
            service_event_failure_metadata(SERVICE_EVENT_REASON_MISSING_SLOT, frontend_kind),
            now_ns,
        );
        return ServiceLookup::Drop;
    };
    if slot.schema_version != SERVICE_MAP_ABI_VERSION
        || slot.revision != config.revision
        || slot.backend_id.get() == 0
        || slot.flags != 0
    {
        emit_service_lookup_failure(
            forward_key,
            frontend.service_id,
            frontend.revision,
            service_event_failure_metadata(SERVICE_EVENT_REASON_INVALID_SLOT, frontend_kind),
            now_ns,
        );
        return ServiceLookup::Drop;
    }
    let backend_key = ServiceBackendKey {
        service_id: frontend.service_id,
        backend_id: slot.backend_id,
        bank: service_bank,
        reserved: [0; 3],
    };
    // SAFETY: the exact key and fixed-layout value match the declared map ABI.
    #[allow(unsafe_code)]
    let Some(backend) = (unsafe { SERVICE_BACKENDS_V4.get(&backend_key).copied() }) else {
        emit_service_lookup_failure(
            forward_key,
            frontend.service_id,
            frontend.revision,
            service_event_failure_metadata(SERVICE_EVENT_REASON_MISSING_BACKEND, frontend_kind),
            now_ns,
        );
        return ServiceLookup::Drop;
    };
    if backend.schema_version != SERVICE_MAP_ABI_VERSION
        || backend.revision != config.revision
        || backend.protocol != forward_key.protocol
        || backend.flags & !0b111 != 0
        || !service_backend_is_eligible(backend.flags)
    {
        emit_service_lookup_failure(
            forward_key,
            frontend.service_id,
            frontend.revision,
            service_event_failure_metadata(SERVICE_EVENT_REASON_INVALID_BACKEND, frontend_kind),
            now_ns,
        );
        return ServiceLookup::Drop;
    }
    let mut backend_address = [0_u8; 16];
    backend_address[0] = backend.address[0];
    backend_address[1] = backend.address[1];
    backend_address[2] = backend.address[2];
    backend_address[3] = backend.address[3];
    let Some(translation) = new_service_connection(
        forward_key.source_address,
        forward_key.destination_address,
        backend_address,
        forward_key.source_port,
        forward_key.destination_port,
        backend.port,
        forward_key.protocol,
        AddressFamily::Ipv4,
        frontend,
        slot.backend_id,
        connection_flags,
        now_ns,
    ) else {
        emit_service_connection_event(
            SERVICE_EVENT_ACTION_DROP,
            SERVICE_EVENT_REASON_PAIR_INSERT_FAILED,
            now_ns,
        );
        return ServiceLookup::Drop;
    };
    ServiceLookup::Translation(translation, connection_flags == 0)
}

#[allow(clippy::too_many_arguments)]
#[inline(never)]
fn lookup_forward_service_v6(forward_key: &ServiceConnectionKey, now_ns: u64) -> ServiceLookup {
    if let Some((translation, cluster_ip)) = refresh_service_connection(forward_key, now_ns) {
        return ServiceLookup::Translation(translation, cluster_ip);
    }

    let Some(config) = active_service_config() else {
        return ServiceLookup::Miss;
    };
    let frontend_key = Ipv6ServiceFrontendKey {
        address: forward_key.destination_address,
        port: forward_key.destination_port,
        protocol: forward_key.protocol,
        bank: config.active_bank,
    };
    // SAFETY: the exact key and fixed-layout value match the declared map ABI;
    // the value is copied before any other map operation.
    #[allow(unsafe_code)]
    let cluster_frontend = unsafe { SERVICE_FRONTENDS_V6.get(&frontend_key).copied() };
    let (frontend, service_bank, connection_flags, frontend_kind) =
        if let Some(frontend) = cluster_frontend {
            (frontend, config.active_bank, 0, SERVICE_EVENT_FRONTEND_CLUSTER_IP)
    } else {
        let Some(node_port_config) = active_node_port_config(config) else {
            return ServiceLookup::Miss;
        };
        let node_port_key = Ipv6NodePortFrontendKey {
            address: forward_key.destination_address,
            port: forward_key.destination_port,
            protocol: forward_key.protocol,
            bank: node_port_config.active_bank,
        };
        // SAFETY: the exact key and fixed-layout value match the declared map
        // ABI and the value is copied before any other map operation.
        #[allow(unsafe_code)]
        let Some(node_port_frontend) =
            (unsafe { NODE_PORT_FRONTENDS_V6.get(&node_port_key).copied() })
        else {
            return ServiceLookup::Miss;
        };
        let Ok((frontend, connection_flags)) = validate_node_port_frontend(
            forward_key,
            node_port_frontend,
            node_port_config,
            config,
            now_ns,
        ) else {
            return ServiceLookup::Drop;
        };
        (
            frontend,
            node_port_frontend.service_bank,
            connection_flags,
            node_port_event_frontend_kind(node_port_frontend.flags),
        )
    };
    if frontend.schema_version != SERVICE_MAP_ABI_VERSION
        || frontend.revision != config.revision
        || frontend.service_id.get() == 0
        || frontend.flags != 0
        || frontend.reserved != [0; 8]
    {
        emit_service_lookup_failure(
            forward_key,
            frontend.service_id,
            frontend.revision,
            service_event_failure_metadata(SERVICE_EVENT_REASON_INVALID_FRONTEND, frontend_kind),
            now_ns,
        );
        return ServiceLookup::Drop;
    }
    if frontend.backend_count == 0 {
        emit_service_lookup_failure(
            forward_key,
            frontend.service_id,
            frontend.revision,
            service_event_failure_metadata(SERVICE_EVENT_REASON_NO_BACKEND, frontend_kind),
            now_ns,
        );
        return ServiceLookup::Drop;
    }
    let slot_key = ServiceBackendSlotKey {
        service_id: frontend.service_id,
        frontend_index: frontend.frontend_index,
        slot: service_flow_hash(forward_key, frontend.service_id) % frontend.backend_count,
        bank: service_bank,
        reserved: [0; 3],
    };
    // SAFETY: the exact key and fixed-layout value match the declared map ABI.
    #[allow(unsafe_code)]
    let Some(slot) = (unsafe { SERVICE_BACKEND_SLOTS.get(&slot_key).copied() }) else {
        emit_service_lookup_failure(
            forward_key,
            frontend.service_id,
            frontend.revision,
            service_event_failure_metadata(SERVICE_EVENT_REASON_MISSING_SLOT, frontend_kind),
            now_ns,
        );
        return ServiceLookup::Drop;
    };
    if slot.schema_version != SERVICE_MAP_ABI_VERSION
        || slot.revision != config.revision
        || slot.backend_id.get() == 0
        || slot.flags != 0
    {
        emit_service_lookup_failure(
            forward_key,
            frontend.service_id,
            frontend.revision,
            service_event_failure_metadata(SERVICE_EVENT_REASON_INVALID_SLOT, frontend_kind),
            now_ns,
        );
        return ServiceLookup::Drop;
    }
    let backend_key = ServiceBackendKey {
        service_id: frontend.service_id,
        backend_id: slot.backend_id,
        bank: service_bank,
        reserved: [0; 3],
    };
    // SAFETY: the exact key and fixed-layout value match the declared map ABI.
    #[allow(unsafe_code)]
    let Some(backend) = (unsafe { SERVICE_BACKENDS_V6.get(&backend_key).copied() }) else {
        emit_service_lookup_failure(
            forward_key,
            frontend.service_id,
            frontend.revision,
            service_event_failure_metadata(SERVICE_EVENT_REASON_MISSING_BACKEND, frontend_kind),
            now_ns,
        );
        return ServiceLookup::Drop;
    };
    if backend.schema_version != SERVICE_MAP_ABI_VERSION
        || backend.revision != config.revision
        || backend.protocol != forward_key.protocol
        || backend.flags & !0b111 != 0
        || !service_backend_is_eligible(backend.flags)
    {
        emit_service_lookup_failure(
            forward_key,
            frontend.service_id,
            frontend.revision,
            service_event_failure_metadata(SERVICE_EVENT_REASON_INVALID_BACKEND, frontend_kind),
            now_ns,
        );
        return ServiceLookup::Drop;
    }
    let Some(translation) = new_service_connection(
        forward_key.source_address,
        forward_key.destination_address,
        backend.address,
        forward_key.source_port,
        forward_key.destination_port,
        backend.port,
        forward_key.protocol,
        AddressFamily::Ipv6,
        frontend,
        slot.backend_id,
        connection_flags,
        now_ns,
    ) else {
        emit_service_connection_event(
            SERVICE_EVENT_ACTION_DROP,
            SERVICE_EVENT_REASON_PAIR_INSERT_FAILED,
            now_ns,
        );
        return ServiceLookup::Drop;
    };
    ServiceLookup::Translation(translation, connection_flags == 0)
}

#[inline(never)]
fn lookup_reverse_service(
    reverse_key: &ServiceConnectionKey,
    now_ns: u64,
) -> Option<ServiceTranslation> {
    refresh_service_connection(reverse_key, now_ns).map(|(translation, _)| translation)
}

#[inline(always)]
const fn l4_checksum_offset(transport_offset: usize, protocol: u8) -> usize {
    if protocol == PROTOCOL_TCP {
        transport_offset + TCP_CHECKSUM_OFFSET
    } else {
        transport_offset + UDP_CHECKSUM_OFFSET
    }
}

#[inline(always)]
const fn l4_checksum_flags(protocol: u8, size: u64, pseudo_header: bool) -> u64 {
    let mut flags = size;
    if pseudo_header {
        flags |= BPF_F_PSEUDO_HDR as u64;
    }
    if protocol == PROTOCOL_UDP {
        flags |= BPF_F_MARK_MANGLED_0 as u64;
    }
    flags
}

/// Host-origin traffic reaches TC after the kernel selected a route for the
/// Service VIP. Once DNAT selects a Pod backend, repeat the bounded FIB lookup
/// and neighbor resolution so the packet uses the backend route rather than
/// the frontend route's stale L2 next hop.
#[inline(never)]
fn reroute_host_service_v4(ctx: &TcContext, observation: &FlowObservation) -> i32 {
    // SAFETY: the TC context owns a valid `__sk_buff` for this invocation.
    #[allow(unsafe_code)]
    let ifindex = unsafe { (*ctx.skb.skb).ifindex };
    // Kernel test-run uses the loopback index without a live route. UNF never
    // attaches this program to loopback, so retain the packet-only test
    // contract while every live managed egress has an index greater than one.
    if ifindex <= 1 {
        return TC_ACT_PIPE;
    }
    let Ok(total_length) = ctx.load::<u16>(ETHERNET_HEADER_LEN + 2) else {
        return service_reroute_failed();
    };
    // SAFETY: the kernel ABI structure is plain integer/byte storage and an
    // all-zero value is a valid starting point for the documented input fields.
    #[allow(unsafe_code)]
    let mut lookup = unsafe { core::mem::zeroed::<BpfFibLookup>() };
    lookup.family = ADDRESS_FAMILY_INET;
    lookup.l4_protocol = observation.protocol;
    lookup.sport = u16::from_ne_bytes(observation.source_port);
    lookup.dport = u16::from_ne_bytes(observation.destination_port);
    lookup.__bindgen_anon_1.tot_len = u16::from_be(total_length);
    lookup.ifindex = ifindex;
    lookup.__bindgen_anon_3.ipv4_src = u32::from_ne_bytes([
        observation.source_address[0],
        observation.source_address[1],
        observation.source_address[2],
        observation.source_address[3],
    ]);
    lookup.__bindgen_anon_4.ipv4_dst = u32::from_ne_bytes([
        observation.destination_address[0],
        observation.destination_address[1],
        observation.destination_address[2],
        observation.destination_address[3],
    ]);
    // SAFETY: pointers and length exactly match the TC helper ABI. This is a
    // forwarding lookup rather than BPF_FIB_LOOKUP_OUTPUT: the output flag
    // constrains flowi4_oif to the frontend route's interface and therefore
    // cannot discover a same-node backend veth after DNAT. A successful lookup
    // supplies the exact L2 addresses required by direct workload-veth routes;
    // unresolved physical neighbors use the helper fallback below.
    #[allow(unsafe_code)]
    let result = unsafe {
        bpf_fib_lookup(
            ctx.skb.skb.cast(),
            &mut lookup,
            core::mem::size_of::<BpfFibLookup>() as i32,
            0,
        )
    };
    redirect_service_route(ctx, &lookup, result)
}

#[inline(never)]
fn reroute_host_service_v6(ctx: &TcContext, observation: &FlowObservation) -> i32 {
    // SAFETY: the TC context owns a valid `__sk_buff` for this invocation.
    #[allow(unsafe_code)]
    let ifindex = unsafe { (*ctx.skb.skb).ifindex };
    if ifindex <= 1 {
        return TC_ACT_PIPE;
    }
    let Ok(payload_length) = ctx.load::<u16>(ETHERNET_HEADER_LEN + 4) else {
        return service_reroute_failed();
    };
    // SAFETY: see the IPv4 helper; all-zero is a valid ABI initialization.
    #[allow(unsafe_code)]
    let mut lookup = unsafe { core::mem::zeroed::<BpfFibLookup>() };
    lookup.family = ADDRESS_FAMILY_INET6;
    lookup.l4_protocol = observation.protocol;
    lookup.sport = u16::from_ne_bytes(observation.source_port);
    lookup.dport = u16::from_ne_bytes(observation.destination_port);
    lookup.__bindgen_anon_1.tot_len = u16::from_be(payload_length).saturating_add(40);
    lookup.ifindex = ifindex;
    lookup.__bindgen_anon_3.ipv6_src = ipv6_fib_words(observation.source_address);
    lookup.__bindgen_anon_4.ipv6_dst = ipv6_fib_words(observation.destination_address);
    // SAFETY: pointers and length exactly match the TC helper ABI. As for IPv4,
    // leaving the output flag clear permits the lookup to select a different
    // backend interface after translation.
    #[allow(unsafe_code)]
    let result = unsafe {
        bpf_fib_lookup(
            ctx.skb.skb.cast(),
            &mut lookup,
            core::mem::size_of::<BpfFibLookup>() as i32,
            0,
        )
    };
    redirect_service_route(ctx, &lookup, result)
}

#[inline(always)]
fn ipv6_fib_words(address: [u8; 16]) -> [u32; 4] {
    [
        u32::from_ne_bytes([address[0], address[1], address[2], address[3]]),
        u32::from_ne_bytes([address[4], address[5], address[6], address[7]]),
        u32::from_ne_bytes([address[8], address[9], address[10], address[11]]),
        u32::from_ne_bytes([address[12], address[13], address[14], address[15]]),
    ]
}

#[inline(always)]
fn redirect_service_route(ctx: &TcContext, lookup: &BpfFibLookup, result: i64) -> i32 {
    if lookup.ifindex == 0 {
        return service_reroute_failed();
    }
    if result == 0 {
        if ctx.store(0, &lookup.dmac, 0).is_err()
            || ctx.store(6, &lookup.smac, 0).is_err()
        {
            return service_reroute_failed();
        }
        // SAFETY: the successful FIB lookup returned a live output interface
        // and the Ethernet header now carries that route's exact addresses.
        #[allow(unsafe_code)]
        let action = unsafe { bpf_redirect(lookup.ifindex, 0) };
        return if action == i64::from(TC_ACT_REDIRECT) {
            TC_ACT_REDIRECT
        } else {
            service_reroute_failed()
        };
    }
    if result != i64::from(BPF_FIB_LKUP_RET_NO_NEIGH) {
        return service_reroute_failed();
    }
    // SAFETY: a null neighbor parameter requests the helper's documented FIB
    // resolution for a route whose first lookup reported only a missing
    // neighbor entry.
    #[allow(unsafe_code)]
    let action = unsafe { bpf_redirect_neigh(lookup.ifindex, core::ptr::null_mut(), 0, 0) };
    if action == i64::from(TC_ACT_REDIRECT) {
        TC_ACT_REDIRECT
    } else {
        service_reroute_failed()
    }
}

#[inline(always)]
fn service_reroute_failed() -> i32 {
    // SAFETY: this helper has no preconditions and returns monotonic kernel time.
    #[allow(unsafe_code)]
    let now_ns = unsafe { bpf_ktime_get_ns() };
    emit_service_connection_event(
        SERVICE_EVENT_ACTION_DROP,
        SERVICE_EVENT_REASON_REWRITE_FAILED,
        now_ns,
    );
    TC_ACT_SHOT
}

#[inline(never)]
fn rewrite_ipv4(
    ctx: &TcContext,
    transport_offset: usize,
    protocol: u8,
    translation: &ServiceTranslation,
    source: bool,
) -> bool {
    let address_offset = if source {
        ETHERNET_HEADER_LEN + 12
    } else {
        ETHERNET_HEADER_LEN + 16
    };
    let port_offset = if source {
        transport_offset
    } else {
        transport_offset + 2
    };
    let Ok(old_address) = ctx.load::<[u8; 4]>(address_offset) else {
        return false;
    };
    let Ok(old_port) = ctx.load::<[u8; 2]>(port_offset) else {
        return false;
    };
    let new_address = [
        translation.address[0],
        translation.address[1],
        translation.address[2],
        translation.address[3],
    ];
    let new_port = translation.port;
    let checksum_offset = l4_checksum_offset(transport_offset, protocol);
    if old_address != new_address {
        let old = u32::from_ne_bytes(old_address) as u64;
        let new = u32::from_ne_bytes(new_address) as u64;
        if ctx
            .l3_csum_replace(IPV4_HEADER_CHECKSUM_OFFSET, old, new, 4)
            .is_err()
            || ctx
                .l4_csum_replace(
                    checksum_offset,
                    old,
                    new,
                    l4_checksum_flags(protocol, 4, true),
                )
                .is_err()
            || ctx.store(address_offset, &new_address, 0).is_err()
        {
            return false;
        }
    }
    if old_port != new_port {
        if ctx
            .l4_csum_replace(
                checksum_offset,
                u16::from_ne_bytes(old_port) as u64,
                u16::from_ne_bytes(new_port) as u64,
                l4_checksum_flags(protocol, 2, false),
            )
            .is_err()
            || ctx.store(port_offset, &new_port, 0).is_err()
        {
            return false;
        }
    }
    true
}

#[inline(never)]
fn rewrite_ipv6(
    ctx: &TcContext,
    transport_offset: usize,
    protocol: u8,
    translation: &ServiceTranslation,
    source: bool,
) -> bool {
    let address_offset = if source {
        ETHERNET_HEADER_LEN + 8
    } else {
        ETHERNET_HEADER_LEN + 24
    };
    let port_offset = if source {
        transport_offset
    } else {
        transport_offset + 2
    };
    let Ok(old_address) = ctx.load::<[u8; 16]>(address_offset) else {
        return false;
    };
    let Ok(old_port) = ctx.load::<[u8; 2]>(port_offset) else {
        return false;
    };
    let new_address = translation.address;
    let new_port = translation.port;
    let checksum_offset = l4_checksum_offset(transport_offset, protocol);
    if old_address != new_address {
        let flags = l4_checksum_flags(protocol, 4, true);
        if ctx
            .l4_csum_replace(
                checksum_offset,
                u32::from_ne_bytes([
                    old_address[0],
                    old_address[1],
                    old_address[2],
                    old_address[3],
                ]) as u64,
                u32::from_ne_bytes([
                    new_address[0],
                    new_address[1],
                    new_address[2],
                    new_address[3],
                ]) as u64,
                flags,
            )
            .is_err()
            || ctx
                .l4_csum_replace(
                    checksum_offset,
                    u32::from_ne_bytes([
                        old_address[4],
                        old_address[5],
                        old_address[6],
                        old_address[7],
                    ]) as u64,
                    u32::from_ne_bytes([
                        new_address[4],
                        new_address[5],
                        new_address[6],
                        new_address[7],
                    ]) as u64,
                    flags,
                )
                .is_err()
            || ctx
                .l4_csum_replace(
                    checksum_offset,
                    u32::from_ne_bytes([
                        old_address[8],
                        old_address[9],
                        old_address[10],
                        old_address[11],
                    ]) as u64,
                    u32::from_ne_bytes([
                        new_address[8],
                        new_address[9],
                        new_address[10],
                        new_address[11],
                    ]) as u64,
                    flags,
                )
                .is_err()
            || ctx
                .l4_csum_replace(
                    checksum_offset,
                    u32::from_ne_bytes([
                        old_address[12],
                        old_address[13],
                        old_address[14],
                        old_address[15],
                    ]) as u64,
                    u32::from_ne_bytes([
                        new_address[12],
                        new_address[13],
                        new_address[14],
                        new_address[15],
                    ]) as u64,
                    flags,
                )
                .is_err()
            || ctx.store(address_offset, &new_address, 0).is_err()
        {
            return false;
        }
    }
    if old_port != new_port {
        if ctx
            .l4_csum_replace(
                checksum_offset,
                u16::from_ne_bytes(old_port) as u64,
                u16::from_ne_bytes(new_port) as u64,
                l4_checksum_flags(protocol, 2, false),
            )
            .is_err()
            || ctx.store(port_offset, &new_port, 0).is_err()
        {
            return false;
        }
    }
    true
}

#[inline(never)]
fn emit_flow(observation: &FlowObservation) -> i32 {
    if !observation.enforce {
        let (Some(connection_ptr), Some(reverse_ptr)) = (
            POLICY_CONNECTION_SCRATCH.get_ptr_mut(0),
            POLICY_CONNECTION_SCRATCH.get_ptr_mut(1),
        ) else {
            return TC_ACT_PIPE;
        };
        // SAFETY: each pointer names a distinct slot owned by this CPU.
        #[allow(unsafe_code)]
        let (connection_key, reverse_key) = unsafe { (&mut *connection_ptr, &mut *reverse_ptr) };
        populate_connection_keys(observation, connection_key, reverse_key);
        let policy_revision = active_policy_revision();
        // SAFETY: this helper has no preconditions and returns monotonic kernel time.
        #[allow(unsafe_code)]
        let timestamp_ns = unsafe { bpf_ktime_get_ns() };
        seed_forwarded_connection(
            connection_key,
            reverse_key,
            policy_revision,
            timestamp_ns,
            observation.tcp_flags,
        );
        return TC_ACT_PIPE;
    }
    if let Some(counter) = FLOW_COUNTERS.get_ptr_mut(0) {
        // SAFETY: get_ptr_mut returned a non-null pointer to the current CPU's
        // u64 slot at the valid, constant map index 0. No other CPU aliases it.
        #[allow(unsafe_code)]
        unsafe {
            *counter = (*counter).wrapping_add(1)
        };
    }

    let Some(decision_ptr) = POLICY_DECISION_SCRATCH.get_ptr_mut(0) else {
        return TC_ACT_SHOT;
    };
    // SAFETY: this CPU owns the initialized per-CPU decision slot.
    #[allow(unsafe_code)]
    let decision = unsafe { &mut *decision_ptr };
    lookup_observation_policy(observation, decision);
    let policy_revision = active_policy_revision();
    // SAFETY: this helper has no preconditions and returns monotonic kernel time.
    #[allow(unsafe_code)]
    let timestamp_ns = unsafe { bpf_ktime_get_ns() };
    let (Some(connection_ptr), Some(reverse_ptr)) = (
        POLICY_CONNECTION_SCRATCH.get_ptr_mut(0),
        POLICY_CONNECTION_SCRATCH.get_ptr_mut(1),
    ) else {
        return TC_ACT_SHOT;
    };
    // SAFETY: each pointer names a distinct slot owned by this CPU.
    #[allow(unsafe_code)]
    let (connection_key, reverse_key) = unsafe { (&mut *connection_ptr, &mut *reverse_ptr) };
    populate_connection_keys(observation, connection_key, reverse_key);
    if decision.verdict == Verdict::Deny {
        if refresh_connection(reverse_key, policy_revision, timestamp_ns) {
            *decision = DataplaneDecision::established(decision);
        }
    } else if !refresh_connection(connection_key, policy_revision, timestamp_ns)
        && packet_starts_connection(observation.protocol, observation.tcp_flags)
        && policy_revision != 0
    {
        let state = ConnectionState {
            last_seen_ns: timestamp_ns,
            policy_revision,
        };
        let _ = CONNECTIONS.insert(connection_key, &state, 0);
    }
    if let Some(event_ptr) = FLOW_EVENT_SCRATCH.get_ptr_mut(0) {
        // SAFETY: this CPU owns the initialized per-CPU event slot.
        #[allow(unsafe_code)]
        let event = unsafe { &mut *event_ptr };
        event.timestamp_ns = timestamp_ns;
        event.flow.source_identity = observation.source_identity;
        event.flow.destination_identity = observation.destination_identity;
        event.flow.source_address = observation.source_address;
        event.flow.destination_address = observation.destination_address;
        event.flow.source_port = observation.source_port;
        event.flow.destination_port = observation.destination_port;
        event.flow.protocol = observation.protocol;
        event.flow.address_family = observation.address_family as u8;
        event.flow.reserved = [0; 2];
        event.policy_revision = decision.policy_revision;
        event.policy_id = decision.policy_id;
        event.rule_id = decision.rule_id;
        event.shadow_policy_id = decision.shadow_policy_id;
        event.shadow_rule_id = decision.shadow_rule_id;
        event.interface_index = 0;
        event.version = FLOW_ABI_VERSION;
        event.size = core::mem::size_of::<FlowEvent>() as u16;
        event.verdict = decision.verdict;
        event.direction = decision.direction as u8;
        event.reason = decision.reason;
        event.shadow_verdict = decision.shadow_verdict;
        event.shadow_reason = decision.shadow_reason;
        event.reserved = [0; 3];
        let _ = FLOW_EVENTS.output::<FlowEvent>(&*event, 0);
    }

    if decision.verdict == Verdict::Deny {
        TC_ACT_SHOT
    } else {
        TC_ACT_PIPE
    }
}

#[inline(always)]
fn populate_connection_keys(
    observation: &FlowObservation,
    connection_key: &mut ConnectionKey,
    reverse_key: &mut ConnectionKey,
) {
    connection_key.source_address = observation.source_address;
    connection_key.destination_address = observation.destination_address;
    connection_key.source_port = observation.source_port;
    connection_key.destination_port = observation.destination_port;
    connection_key.protocol = observation.protocol;
    connection_key.address_family = observation.address_family as u8;
    connection_key.reserved = [0; 2];
    reverse_key.source_address = observation.destination_address;
    reverse_key.destination_address = observation.source_address;
    reverse_key.source_port = observation.destination_port;
    reverse_key.destination_port = observation.source_port;
    reverse_key.protocol = observation.protocol;
    reverse_key.address_family = observation.address_family as u8;
    reverse_key.reserved = [0; 2];
}

#[inline(always)]
fn lookup_observation_policy(observation: &FlowObservation, decision: &mut DataplaneDecision) {
    *decision = if observation.address_family == AddressFamily::Ipv4 {
        lookup_ipv4_observation_policy(observation)
    } else {
        lookup_ipv6_observation_policy(observation)
    };
}

#[inline(always)]
fn lookup_ipv4_observation_policy(observation: &FlowObservation) -> DataplaneDecision {
    let Some(config) = active_policy_config() else {
        return DataplaneDecision::observed(observation.direction, ReasonCode::Observed);
    };
    let (Some(ingress_ptr), Some(egress_ptr)) = (
        POLICY_DIRECTION_DECISION_SCRATCH.get_ptr_mut(0),
        POLICY_DIRECTION_DECISION_SCRATCH.get_ptr_mut(1),
    ) else {
        return DataplaneDecision::observed(observation.direction, ReasonCode::Observed);
    };
    // SAFETY: the pointers name distinct per-CPU slots.
    #[allow(unsafe_code)]
    let (ingress, egress) = unsafe { (&mut *ingress_ptr, &mut *egress_ptr) };
    *ingress = lookup_ipv4_ingress_policy(observation, config);
    *egress = lookup_ipv4_egress_policy(observation, config);
    observation_policy_decision(observation, ingress, egress)
}

#[inline(always)]
fn lookup_ipv6_observation_policy(observation: &FlowObservation) -> DataplaneDecision {
    let Some(config) = active_policy_config() else {
        return DataplaneDecision::observed(observation.direction, ReasonCode::Observed);
    };
    let (Some(ingress_ptr), Some(egress_ptr)) = (
        POLICY_DIRECTION_DECISION_SCRATCH.get_ptr_mut(0),
        POLICY_DIRECTION_DECISION_SCRATCH.get_ptr_mut(1),
    ) else {
        return DataplaneDecision::observed(observation.direction, ReasonCode::Observed);
    };
    // SAFETY: the pointers name distinct per-CPU slots.
    #[allow(unsafe_code)]
    let (ingress, egress) = unsafe { (&mut *ingress_ptr, &mut *egress_ptr) };
    *ingress = lookup_ipv6_ingress_policy(observation, config);
    *egress = lookup_ipv6_egress_policy(observation, config);
    observation_policy_decision(observation, ingress, egress)
}

#[inline(always)]
fn observation_policy_decision(
    observation: &FlowObservation,
    ingress: &DataplaneDecision,
    egress: &DataplaneDecision,
) -> DataplaneDecision {
    let reason =
        if observation.source_identity.get() == 0 || observation.destination_identity.get() == 0 {
            ReasonCode::IdentityUnknown
        } else {
            ReasonCode::Observed
        };
    decisive_directional_policy(
        ingress,
        egress,
        DataplaneDecision::observed(observation.direction, reason),
    )
}

#[inline(never)]
fn lookup_ipv4_ingress_policy(
    observation: &FlowObservation,
    config: PolicyMapConfig,
) -> DataplaneDecision {
    lookup_ingress_policy(
        Some([
            observation.source_address[0],
            observation.source_address[1],
            observation.source_address[2],
            observation.source_address[3],
        ]),
        None,
        observation.source_identity,
        observation.destination_identity,
        observation.destination_port,
        observation.protocol,
        config,
    )
}

#[inline(never)]
fn lookup_ipv4_egress_policy(
    observation: &FlowObservation,
    config: PolicyMapConfig,
) -> DataplaneDecision {
    lookup_egress_policy(
        Some([
            observation.destination_address[0],
            observation.destination_address[1],
            observation.destination_address[2],
            observation.destination_address[3],
        ]),
        None,
        observation.source_identity,
        observation.destination_port,
        observation.protocol,
        config,
    )
}

#[inline(never)]
fn lookup_ipv6_ingress_policy(
    observation: &FlowObservation,
    config: PolicyMapConfig,
) -> DataplaneDecision {
    lookup_ingress_policy(
        None,
        Some(observation.source_address),
        observation.source_identity,
        observation.destination_identity,
        observation.destination_port,
        observation.protocol,
        config,
    )
}

#[inline(never)]
fn lookup_ipv6_egress_policy(
    observation: &FlowObservation,
    config: PolicyMapConfig,
) -> DataplaneDecision {
    lookup_egress_policy(
        None,
        Some(observation.destination_address),
        observation.source_identity,
        observation.destination_port,
        observation.protocol,
        config,
    )
}

#[inline(always)]
fn seed_forwarded_connection(
    key: &ConnectionKey,
    reverse: &ConnectionKey,
    policy_revision: u64,
    now_ns: u64,
    tcp_flags: u8,
) {
    if policy_revision == 0
        || refresh_connection(key, policy_revision, now_ns)
        || refresh_connection(reverse, policy_revision, now_ns)
        || !packet_starts_connection(key.protocol, tcp_flags)
    {
        return;
    }
    let state = ConnectionState {
        last_seen_ns: now_ns,
        policy_revision,
    };
    let _ = CONNECTIONS.insert(key, &state, 0);
}

/// Preserve the client-to-frontend tuple as policy connection state after an
/// allowed Service flow has been evaluated against its selected backend. A
/// reverse Service translation can otherwise expose the frontend tuple to a
/// later enforcing hook, where an ingress-isolated client would reject the
/// legitimate reply because only the client-to-backend tuple was retained.
#[inline(always)]
fn seed_service_frontend_policy_connection(tcp_flags: u8) {
    let Some(value_ptr) = SERVICE_CONNECTION_SCRATCH.get_ptr_mut(0) else {
        return;
    };
    // SAFETY: the caller invokes this only after a successful forward Service
    // lookup initialized this CPU's service-connection scratch slot.
    #[allow(unsafe_code)]
    let value = unsafe { &*value_ptr };
    let (Some(connection_ptr), Some(reverse_ptr)) = (
        POLICY_CONNECTION_SCRATCH.get_ptr_mut(0),
        POLICY_CONNECTION_SCRATCH.get_ptr_mut(1),
    ) else {
        return;
    };
    // SAFETY: each pointer names a distinct slot owned by this CPU.
    #[allow(unsafe_code)]
    let (connection_key, reverse_key) = unsafe { (&mut *connection_ptr, &mut *reverse_ptr) };
    connection_key.source_address = value.client_address;
    connection_key.destination_address = value.frontend_address;
    connection_key.source_port = value.client_port;
    connection_key.destination_port = value.frontend_port;
    connection_key.protocol = value.protocol;
    connection_key.address_family = value.address_family;
    connection_key.reserved = [0; 2];
    reverse_key.source_address = value.frontend_address;
    reverse_key.destination_address = value.client_address;
    reverse_key.source_port = value.frontend_port;
    reverse_key.destination_port = value.client_port;
    reverse_key.protocol = value.protocol;
    reverse_key.address_family = value.address_family;
    reverse_key.reserved = [0; 2];
    let policy_revision = active_policy_revision();
    // SAFETY: this helper has no preconditions and returns monotonic kernel time.
    #[allow(unsafe_code)]
    let now_ns = unsafe { bpf_ktime_get_ns() };
    seed_forwarded_connection(
        connection_key,
        reverse_key,
        policy_revision,
        now_ns,
        tcp_flags,
    );
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
    direction: Direction,
}

impl DataplaneDecision {
    #[inline(always)]
    const fn observed(direction: Direction, reason: ReasonCode) -> Self {
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
            direction,
        }
    }

    #[inline(always)]
    const fn established(denied: &Self) -> Self {
        Self {
            policy_revision: denied.policy_revision,
            policy_id: PolicyId::new(0),
            rule_id: RuleId::new(0),
            shadow_policy_id: PolicyId::new(0),
            shadow_rule_id: RuleId::new(0),
            verdict: Verdict::Allow,
            reason: ReasonCode::AllowEstablished as u8,
            shadow_verdict: Verdict::Unknown as u8,
            shadow_reason: ReasonCode::Observed as u8,
            direction: denied.direction,
        }
    }
}

#[inline(always)]
fn active_policy_config() -> Option<PolicyMapConfig> {
    let config = POLICY_CONFIG.get(0).copied()?;
    if config.schema_version == POLICY_MAP_ABI_VERSION
        && config.active_bank < POLICY_BANK_COUNT
        && config.revision != 0
    {
        Some(config)
    } else {
        None
    }
}

#[inline(always)]
fn active_policy_revision() -> u64 {
    active_policy_config().map_or(0, |config| config.revision)
}

#[inline(always)]
fn refresh_connection(key: &ConnectionKey, policy_revision: u64, now_ns: u64) -> bool {
    // SAFETY: CONNECTIONS is a fixed-layout LRU map. The value is copied before
    // the subsequent update, so no map-backed reference escapes the lookup.
    #[allow(unsafe_code)]
    let Some(mut state) = (unsafe { CONNECTIONS.get(key).copied() }) else {
        return false;
    };
    if !connection_is_active(state, policy_revision, now_ns, key.protocol) {
        let _ = CONNECTIONS.remove(key);
        return false;
    }
    state.last_seen_ns = now_ns;
    let _ = CONNECTIONS.insert(key, &state, 0);
    true
}

#[inline(always)]
fn lookup_ingress_policy(
    source_ipv4: Option<[u8; 4]>,
    source_ipv6: Option<[u8; 16]>,
    source_identity: IdentityId,
    destination_identity: IdentityId,
    destination_port: [u8; 2],
    protocol: u8,
    config: PolicyMapConfig,
) -> DataplaneDecision {
    if destination_identity.get() == 0 {
        return DataplaneDecision::observed(Direction::Ingress, ReasonCode::IdentityUnknown);
    }

    if let Some(source_ipv4) = source_ipv4 {
        let ipv4_node_fallback = Ipv4PolicyMapKey {
            source_address: source_ipv4,
            destination_identity: IdentityId::new(0),
            destination_port: [0; 2],
            protocol: 0,
            bank: config.active_bank,
        };
        let ipv4_exact = Ipv4PolicyMapKey {
            source_address: source_ipv4,
            destination_identity,
            destination_port,
            protocol,
            bank: config.active_bank,
        };
        let ipv4_source_fallback = Ipv4PolicyMapKey {
            source_address: source_ipv4,
            destination_identity,
            destination_port: [0; 2],
            protocol: 0,
            bank: config.active_bank,
        };
        let ipv4_source_protocol_fallback = Ipv4PolicyMapKey {
            source_address: source_ipv4,
            destination_identity,
            destination_port: [0; 2],
            protocol,
            bank: config.active_bank,
        };
        let ipv4_external_exact = Ipv4PolicyMapKey {
            source_address: [0; 4],
            destination_identity,
            destination_port,
            protocol,
            bank: config.active_bank,
        };
        let ipv4_external_fallback = Ipv4PolicyMapKey {
            source_address: [0; 4],
            destination_identity,
            destination_port: [0; 2],
            protocol: 0,
            bank: config.active_bank,
        };
        let ipv4_external_protocol_fallback = Ipv4PolicyMapKey {
            source_address: [0; 4],
            destination_identity,
            destination_port: [0; 2],
            protocol,
            bank: config.active_bank,
        };
        if let Some(value) = lookup_ipv4_policy_value(&ipv4_node_fallback, config.revision)
            .or_else(|| lookup_ipv4_policy_value(&ipv4_exact, config.revision))
            .or_else(|| lookup_ipv4_policy_value(&ipv4_source_protocol_fallback, config.revision))
            .or_else(|| lookup_ipv4_policy_value(&ipv4_source_fallback, config.revision))
            .or_else(|| lookup_ipv4_policy_value(&ipv4_external_exact, config.revision))
            .or_else(|| lookup_ipv4_policy_value(&ipv4_external_protocol_fallback, config.revision))
            .or_else(|| lookup_ipv4_policy_value(&ipv4_external_fallback, config.revision))
        {
            return decode_policy_value(value, config.revision, Direction::Ingress);
        }
    }
    if let Some(source_ipv6) = source_ipv6 {
        let node_fallback = Ipv6PolicyMapData {
            destination_identity: IdentityId::new(0),
            destination_port: [0; 2],
            protocol: 0,
            bank: config.active_bank,
            source_address: source_ipv6,
        };
        let exact = Ipv6PolicyMapData {
            destination_identity,
            destination_port,
            protocol,
            bank: config.active_bank,
            source_address: source_ipv6,
        };
        let protocol_fallback = Ipv6PolicyMapData {
            destination_identity,
            destination_port: [0; 2],
            protocol,
            bank: config.active_bank,
            source_address: source_ipv6,
        };
        let global_fallback = Ipv6PolicyMapData {
            destination_identity,
            destination_port: [0; 2],
            protocol: 0,
            bank: config.active_bank,
            source_address: source_ipv6,
        };
        if let Some(value) = lookup_ipv6_policy_value(&node_fallback, config.revision)
            .or_else(|| lookup_ipv6_policy_value(&exact, config.revision))
            .or_else(|| lookup_ipv6_policy_value(&protocol_fallback, config.revision))
            .or_else(|| lookup_ipv6_policy_value(&global_fallback, config.revision))
        {
            return decode_policy_value(value, config.revision, Direction::Ingress);
        }
    }
    if source_identity.get() == 0 {
        return DataplaneDecision::observed(Direction::Ingress, ReasonCode::IdentityUnknown);
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
    let protocol_fallback = PolicyMapKey {
        source_identity,
        destination_identity,
        destination_port: [0; 2],
        protocol,
        bank: config.active_bank,
    };
    let value = lookup_policy_value(&exact, config.revision)
        .or_else(|| lookup_policy_value(&protocol_fallback, config.revision))
        .or_else(|| lookup_policy_value(&fallback, config.revision));
    let Some(value) = value else {
        return DataplaneDecision::observed(Direction::Ingress, ReasonCode::Observed);
    };
    decode_policy_value(value, config.revision, Direction::Ingress)
}

#[inline(always)]
fn lookup_egress_policy(
    destination_ipv4: Option<[u8; 4]>,
    destination_ipv6: Option<[u8; 16]>,
    source_identity: IdentityId,
    destination_port: [u8; 2],
    protocol: u8,
    config: PolicyMapConfig,
) -> DataplaneDecision {
    if source_identity.get() == 0 {
        return DataplaneDecision::observed(Direction::Egress, ReasonCode::IdentityUnknown);
    }
    if let Some(destination_ipv4) = destination_ipv4 {
        let node_fallback = EgressIpv4PolicyMapKey {
            destination_address: destination_ipv4,
            source_identity: IdentityId::new(0),
            destination_port: [0; 2],
            protocol: 0,
            bank: config.active_bank,
        };
        let exact = EgressIpv4PolicyMapKey {
            destination_address: destination_ipv4,
            source_identity,
            destination_port,
            protocol,
            bank: config.active_bank,
        };
        let protocol_fallback = EgressIpv4PolicyMapKey {
            destination_address: destination_ipv4,
            source_identity,
            destination_port: [0; 2],
            protocol,
            bank: config.active_bank,
        };
        let global_fallback = EgressIpv4PolicyMapKey {
            destination_address: destination_ipv4,
            source_identity,
            destination_port: [0; 2],
            protocol: 0,
            bank: config.active_bank,
        };
        let external_exact = EgressIpv4PolicyMapKey {
            destination_address: [0; 4],
            source_identity,
            destination_port,
            protocol,
            bank: config.active_bank,
        };
        let external_protocol_fallback = EgressIpv4PolicyMapKey {
            destination_address: [0; 4],
            source_identity,
            destination_port: [0; 2],
            protocol,
            bank: config.active_bank,
        };
        let external_global_fallback = EgressIpv4PolicyMapKey {
            destination_address: [0; 4],
            source_identity,
            destination_port: [0; 2],
            protocol: 0,
            bank: config.active_bank,
        };
        if let Some(value) = lookup_egress_ipv4_policy_value(&node_fallback, config.revision)
            .or_else(|| lookup_egress_ipv4_policy_value(&exact, config.revision))
            .or_else(|| lookup_egress_ipv4_policy_value(&protocol_fallback, config.revision))
            .or_else(|| lookup_egress_ipv4_policy_value(&global_fallback, config.revision))
            .or_else(|| lookup_egress_ipv4_policy_value(&external_exact, config.revision))
            .or_else(|| {
                lookup_egress_ipv4_policy_value(&external_protocol_fallback, config.revision)
            })
            .or_else(|| lookup_egress_ipv4_policy_value(&external_global_fallback, config.revision))
        {
            return decode_policy_value(value, config.revision, Direction::Egress);
        }
    }
    if let Some(destination_ipv6) = destination_ipv6 {
        let node_fallback = EgressIpv6PolicyMapData {
            source_identity: IdentityId::new(0),
            destination_port: [0; 2],
            protocol: 0,
            bank: config.active_bank,
            destination_address: destination_ipv6,
        };
        let exact = EgressIpv6PolicyMapData {
            source_identity,
            destination_port,
            protocol,
            bank: config.active_bank,
            destination_address: destination_ipv6,
        };
        let protocol_fallback = EgressIpv6PolicyMapData {
            source_identity,
            destination_port: [0; 2],
            protocol,
            bank: config.active_bank,
            destination_address: destination_ipv6,
        };
        let global_fallback = EgressIpv6PolicyMapData {
            source_identity,
            destination_port: [0; 2],
            protocol: 0,
            bank: config.active_bank,
            destination_address: destination_ipv6,
        };
        if let Some(value) = lookup_egress_ipv6_policy_value(&node_fallback, config.revision)
            .or_else(|| lookup_egress_ipv6_policy_value(&exact, config.revision))
            .or_else(|| lookup_egress_ipv6_policy_value(&protocol_fallback, config.revision))
            .or_else(|| lookup_egress_ipv6_policy_value(&global_fallback, config.revision))
        {
            return decode_policy_value(value, config.revision, Direction::Egress);
        }
    }
    DataplaneDecision::observed(Direction::Egress, ReasonCode::Observed)
}

#[inline(always)]
fn decisive_directional_policy(
    ingress: &DataplaneDecision,
    egress: &DataplaneDecision,
    observed: DataplaneDecision,
) -> DataplaneDecision {
    let has_ingress = ingress.policy_revision != 0;
    let has_egress = egress.policy_revision != 0;
    if has_ingress && ingress.verdict == Verdict::Deny {
        *ingress
    } else if has_egress && egress.verdict == Verdict::Deny {
        *egress
    } else if has_ingress {
        *ingress
    } else if has_egress {
        *egress
    } else {
        observed
    }
}

#[inline(always)]
fn lookup_ipv4_policy_value(key: &Ipv4PolicyMapKey, revision: u64) -> Option<PolicyMapValue> {
    // SAFETY: POLICY_IPV4 uses BPF_F_NO_PREALLOC, values have a fixed Copy ABI,
    // and the reference is copied immediately without escaping this lookup.
    #[allow(unsafe_code)]
    let value = unsafe { POLICY_IPV4.get(key).copied() }?;
    if value.schema_version == POLICY_MAP_ABI_VERSION && value.revision == revision {
        Some(value)
    } else {
        None
    }
}

#[inline(always)]
fn lookup_ipv6_policy_value(key: &Ipv6PolicyMapData, revision: u64) -> Option<PolicyMapValue> {
    let lookup = LpmKey::new(192, *key);
    let value = POLICY_IPV6.get(&lookup).copied()?;
    if value.schema_version == POLICY_MAP_ABI_VERSION && value.revision == revision {
        Some(value)
    } else {
        None
    }
}

#[inline(always)]
fn lookup_egress_ipv4_policy_value(
    key: &EgressIpv4PolicyMapKey,
    revision: u64,
) -> Option<PolicyMapValue> {
    // SAFETY: EGRESS_IPV4 uses BPF_F_NO_PREALLOC, values have a fixed Copy ABI,
    // and the reference is copied immediately without escaping this lookup.
    #[allow(unsafe_code)]
    let value = unsafe { EGRESS_IPV4.get(key).copied() }?;
    if value.schema_version == POLICY_MAP_ABI_VERSION && value.revision == revision {
        Some(value)
    } else {
        None
    }
}

#[inline(always)]
fn lookup_egress_ipv6_policy_value(
    key: &EgressIpv6PolicyMapData,
    revision: u64,
) -> Option<PolicyMapValue> {
    let lookup = LpmKey::new(192, *key);
    let value = EGRESS_IPV6.get(&lookup).copied()?;
    if value.schema_version == POLICY_MAP_ABI_VERSION && value.revision == revision {
        Some(value)
    } else {
        None
    }
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
fn decode_policy_value(
    value: PolicyMapValue,
    revision: u64,
    direction: Direction,
) -> DataplaneDecision {
    let Some(verdict) = decode_verdict(value.verdict) else {
        return DataplaneDecision::observed(direction, ReasonCode::Observed);
    };
    let Some(reason) = decode_reason(value.reason, verdict) else {
        return DataplaneDecision::observed(direction, ReasonCode::Observed);
    };
    if !valid_provenance(value.flags, value.reason, false) {
        return DataplaneDecision::observed(direction, ReasonCode::Observed);
    }

    let has_shadow = value.flags & POLICY_FLAG_HAS_SHADOW != 0;
    let (shadow_verdict, shadow_reason) = if has_shadow {
        let Some(shadow_verdict) = decode_verdict(value.shadow_verdict) else {
            return DataplaneDecision::observed(direction, ReasonCode::Observed);
        };
        let Some(shadow_reason) = decode_reason(value.shadow_reason, shadow_verdict) else {
            return DataplaneDecision::observed(direction, ReasonCode::Observed);
        };
        if !valid_provenance(value.flags, value.shadow_reason, true) {
            return DataplaneDecision::observed(direction, ReasonCode::Observed);
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
        direction,
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
fn active_identity_config() -> Option<IdentityMapConfig> {
    let config = IDENTITY_CONFIG.get(0).copied()?;
    if config.source_epoch == 0
        || config.schema_version != IDENTITY_MAP_ABI_VERSION
        || config.active_bank >= IDENTITY_BANK_COUNT
        || config.revision == 0
        || config.flags != 0
    {
        return None;
    }
    Some(config)
}

#[inline(always)]
fn lookup_identity_v4(address: [u8; 4], config: Option<IdentityMapConfig>) -> IdentityId {
    let Some(config) = config else {
        return IdentityId::new(0);
    };
    let key = Ipv4IdentityKey::new(address);
    // SAFETY: both identity maps use BPF_F_NO_PREALLOC, values have a fixed Copy
    // ABI, and the reference is copied immediately without escaping this lookup.
    #[allow(unsafe_code)]
    let value = unsafe {
        if config.active_bank == 0 {
            IDENTITY_V4.get(&key).copied()
        } else {
            IDENTITY_V4_B.get(&key).copied()
        }
    };
    value.map_or(IdentityId::new(0), |value| {
        if value.schema_version == IDENTITY_MAP_ABI_VERSION && value.revision == config.revision {
            value.identity_id
        } else {
            IdentityId::new(0)
        }
    })
}

#[inline(always)]
fn lookup_identity_v6(address: [u8; 16], config: Option<IdentityMapConfig>) -> IdentityId {
    let Some(config) = config else {
        return IdentityId::new(0);
    };
    let key = Ipv6IdentityKey::new(address);
    // SAFETY: both identity maps use BPF_F_NO_PREALLOC, values have a fixed Copy
    // ABI, and the reference is copied immediately without escaping this lookup.
    #[allow(unsafe_code)]
    let value = unsafe {
        if config.active_bank == 0 {
            IDENTITY_V6.get(&key).copied()
        } else {
            IDENTITY_V6_B.get(&key).copied()
        }
    };
    value.map_or(IdentityId::new(0), |value| {
        if value.schema_version == IDENTITY_MAP_ABI_VERSION && value.revision == config.revision {
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
