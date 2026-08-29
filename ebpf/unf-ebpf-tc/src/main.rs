#![no_std]
#![no_main]

use aya_ebpf::bindings::{TC_ACT_PIPE, TC_ACT_SHOT};
use aya_ebpf::helpers::bpf_ktime_get_ns;
use aya_ebpf::macros::{classifier, map};
use aya_ebpf::maps::lpm_trie::Key as LpmKey;
use aya_ebpf::maps::{Array, HashMap, LpmTrie, LruHashMap, PerCpuArray, RingBuf};
use aya_ebpf::programs::TcContext;
use unf_common::{IdentityId, PolicyId, PolicyReason, RuleId, Verdict};
use unf_ebpf_common::{
    AddressFamily, ConnectionKey, ConnectionState, Direction, EgressIpv4PolicyMapKey,
    EgressIpv6PolicyMapData, FLOW_ABI_VERSION, FlowEvent, FlowKey, IDENTITY_BANK_COUNT,
    IDENTITY_MAP_ABI_VERSION,
    IPV6_EXTENSION_BYTE_LIMIT, IPV6_EXTENSION_HEADER_LIMIT, IPV6_NEXT_HEADER_HOP_BY_HOP,
    IdentityMapConfig, IdentityMapValue, Ipv4IdentityKey, Ipv4PolicyMapKey, Ipv6ExtensionStep,
    Ipv4ServiceBackendValue, Ipv4ServiceFrontendKey, Ipv6IdentityKey, Ipv6PolicyMapData,
    Ipv6ServiceBackendValue, Ipv6ServiceFrontendKey, POLICY_BANK_COUNT, POLICY_FLAG_HAS_POLICY,
    POLICY_FLAG_HAS_RULE, POLICY_FLAG_HAS_SHADOW,
    POLICY_FLAG_SHADOW_HAS_POLICY, POLICY_FLAG_SHADOW_HAS_RULE, POLICY_MAP_ABI_VERSION,
    PolicyMapConfig, PolicyMapKey, PolicyMapValue, ReasonCode, ServiceBackendKey,
    ServiceBackendSlotKey, ServiceBackendSlotValue, ServiceFrontendValue, ServiceMapConfig,
    ServiceConnectionKey, ServiceConnectionValue, connection_is_active, ipv6_extension_step,
    packet_starts_connection,
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

#[map]
static FLOW_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[map]
static FLOW_COUNTERS: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

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
/// only through one SERVICE_CONFIG write. Phase 4.4 declares the verifier-safe
/// ABI; packet translation begins in Phase 4.5.
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

/// Bounded persistent flow translations reserved by the accepted Phase 4
/// connection-state contract. Phase 4.5 adds packet-path reads and writes.
#[map]
static SERVICE_CONNECTIONS: LruHashMap<ServiceConnectionKey, ServiceConnectionValue> =
    LruHashMap::with_max_entries(SERVICE_CONNECTION_CAPACITY, 0);

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

#[inline(always)]
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
    if u16::from_be(fragment) & 0x1fff != 0 {
        // Non-initial fragments do not contain a reliable transport header.
        return TC_ACT_PIPE;
    }

    let Ok(protocol) = ctx.load::<u8>(ETHERNET_HEADER_LEN + 9) else {
        return TC_ACT_PIPE;
    };
    if !supported_transport(protocol) {
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
    let tcp_flags = if protocol == PROTOCOL_TCP {
        let Ok(flags) = ctx.load::<u8>(transport_offset + 13) else {
            return TC_ACT_PIPE;
        };
        flags
    } else {
        0
    };

    let mut source_address = [0_u8; 16];
    source_address[..4].copy_from_slice(&source_ipv4);
    let mut destination_address = [0_u8; 16];
    destination_address[..4].copy_from_slice(&destination_ipv4);
    let identity_config = active_identity_config();
    emit_flow(
        direction,
        source_address,
        destination_address,
        source_port,
        destination_port,
        protocol,
        AddressFamily::Ipv4,
        lookup_identity_v4(source_ipv4, identity_config),
        lookup_identity_v4(destination_ipv4, identity_config),
        Some(source_ipv4),
        Some(destination_ipv4),
        None,
        None,
        tcp_flags,
        enforce,
    )
}

#[inline(always)]
fn observe_ipv6(ctx: &TcContext, direction: Direction, enforce: bool) -> i32 {
    let Ok(version) = ctx.load::<u8>(ETHERNET_HEADER_LEN) else {
        return TC_ACT_PIPE;
    };
    if version >> 4 != 6 {
        return TC_ACT_PIPE;
    }
    let Some((protocol, transport_offset)) = ipv6_transport(ctx) else {
        return TC_ACT_PIPE;
    };
    let Ok(source_address) = ctx.load::<[u8; 16]>(ETHERNET_HEADER_LEN + 8) else {
        return TC_ACT_PIPE;
    };
    let Ok(destination_address) = ctx.load::<[u8; 16]>(ETHERNET_HEADER_LEN + 24) else {
        return TC_ACT_PIPE;
    };
    let Ok(source_port) = ctx.load::<[u8; 2]>(transport_offset) else {
        return TC_ACT_PIPE;
    };
    let Ok(destination_port) = ctx.load::<[u8; 2]>(transport_offset + 2) else {
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
    let identity_config = active_identity_config();
    emit_flow(
        direction,
        source_address,
        destination_address,
        source_port,
        destination_port,
        protocol,
        AddressFamily::Ipv6,
        lookup_identity_v6(source_address, identity_config),
        lookup_identity_v6(destination_address, identity_config),
        None,
        None,
        Some(source_address),
        Some(destination_address),
        tcp_flags,
        enforce,
    )
}

#[inline(always)]
fn ipv6_transport(ctx: &TcContext) -> Option<(u8, usize)> {
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

    for depth in 0..=IPV6_EXTENSION_HEADER_LIMIT {
        if supported_transport(next_header) {
            if offset + 4 > payload_end {
                return None;
            }
            return Some((next_header, offset));
        }
        if depth == IPV6_EXTENSION_HEADER_LIMIT
            || (next_header == IPV6_NEXT_HEADER_HOP_BY_HOP && depth != 0)
            || offset + 8 > payload_end
        {
            return None;
        }
        let header = ctx.load::<[u8; 8]>(offset).ok()?;
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

#[allow(clippy::too_many_arguments)]
#[inline(always)]
fn emit_flow(
    direction: Direction,
    source_address: [u8; 16],
    destination_address: [u8; 16],
    source_port: [u8; 2],
    destination_port: [u8; 2],
    protocol: u8,
    address_family: AddressFamily,
    source_identity: IdentityId,
    destination_identity: IdentityId,
    source_ipv4: Option<[u8; 4]>,
    destination_ipv4: Option<[u8; 4]>,
    source_ipv6: Option<[u8; 16]>,
    destination_ipv6: Option<[u8; 16]>,
    tcp_flags: u8,
    enforce: bool,
) -> i32 {
    let connection_key = ConnectionKey {
        source_address,
        destination_address,
        source_port,
        destination_port,
        protocol,
        address_family: address_family as u8,
        reserved: [0; 2],
    };
    let policy_revision = active_policy_revision();
    // SAFETY: this helper has no preconditions and returns monotonic kernel time.
    #[allow(unsafe_code)]
    let timestamp_ns = unsafe { bpf_ktime_get_ns() };
    if !enforce {
        seed_forwarded_connection(connection_key, policy_revision, timestamp_ns, tcp_flags);
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

    let mut decision = lookup_policy(
        direction,
        source_ipv4,
        destination_ipv4,
        source_ipv6,
        destination_ipv6,
        source_identity,
        destination_identity,
        destination_port,
        protocol,
    );
    if decision.verdict == Verdict::Deny {
        if refresh_connection(connection_key.reverse(), policy_revision, timestamp_ns) {
            decision = DataplaneDecision::established(decision);
        }
    } else if !refresh_connection(connection_key, policy_revision, timestamp_ns)
        && packet_starts_connection(protocol, tcp_flags)
        && policy_revision != 0
    {
        let state = ConnectionState {
            last_seen_ns: timestamp_ns,
            policy_revision,
        };
        let _ = CONNECTIONS.insert(&connection_key, &state, 0);
    }
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
            address_family: address_family as u8,
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
        direction: decision.direction as u8,
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

#[inline(always)]
fn seed_forwarded_connection(
    key: ConnectionKey,
    policy_revision: u64,
    now_ns: u64,
    tcp_flags: u8,
) {
    if policy_revision == 0
        || refresh_connection(key, policy_revision, now_ns)
        || refresh_connection(key.reverse(), policy_revision, now_ns)
        || !packet_starts_connection(key.protocol, tcp_flags)
    {
        return;
    }
    let state = ConnectionState {
        last_seen_ns: now_ns,
        policy_revision,
    };
    let _ = CONNECTIONS.insert(&key, &state, 0);
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
    const fn established(denied: Self) -> Self {
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
fn active_policy_revision() -> u64 {
    let Some(config) = POLICY_CONFIG.get(0).copied() else {
        return 0;
    };
    if config.schema_version == POLICY_MAP_ABI_VERSION
        && config.active_bank < POLICY_BANK_COUNT
        && config.revision != 0
    {
        config.revision
    } else {
        0
    }
}

#[inline(always)]
fn refresh_connection(key: ConnectionKey, policy_revision: u64, now_ns: u64) -> bool {
    // SAFETY: CONNECTIONS is a fixed-layout LRU map. The value is copied before
    // the subsequent update, so no map-backed reference escapes the lookup.
    #[allow(unsafe_code)]
    let Some(mut state) = (unsafe { CONNECTIONS.get(&key).copied() }) else {
        return false;
    };
    if !connection_is_active(state, policy_revision, now_ns, key.protocol) {
        let _ = CONNECTIONS.remove(&key);
        return false;
    }
    state.last_seen_ns = now_ns;
    let _ = CONNECTIONS.insert(&key, &state, 0);
    true
}

#[inline(always)]
fn lookup_policy(
    observed_direction: Direction,
    source_ipv4: Option<[u8; 4]>,
    destination_ipv4: Option<[u8; 4]>,
    source_ipv6: Option<[u8; 16]>,
    destination_ipv6: Option<[u8; 16]>,
    source_identity: IdentityId,
    destination_identity: IdentityId,
    destination_port: [u8; 2],
    protocol: u8,
) -> DataplaneDecision {
    let Some(config) = POLICY_CONFIG.get(0).copied() else {
        return DataplaneDecision::observed(observed_direction, ReasonCode::Observed);
    };
    if config.schema_version != POLICY_MAP_ABI_VERSION
        || config.active_bank >= POLICY_BANK_COUNT
        || config.revision == 0
    {
        return DataplaneDecision::observed(observed_direction, ReasonCode::Observed);
    }

    let ingress = lookup_ingress_policy(
        source_ipv4,
        source_ipv6,
        source_identity,
        destination_identity,
        destination_port,
        protocol,
        config,
    );
    let egress = lookup_egress_policy(
        destination_ipv4,
        destination_ipv6,
        source_identity,
        destination_port,
        protocol,
        config,
    );
    let reason = if source_identity.get() == 0 || destination_identity.get() == 0 {
        ReasonCode::IdentityUnknown
    } else {
        ReasonCode::Observed
    };
    decisive_directional_policy(
        ingress,
        egress,
        DataplaneDecision::observed(observed_direction, reason),
    )
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
            .or_else(|| {
                lookup_ipv4_policy_value(&ipv4_external_protocol_fallback, config.revision)
            })
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
            .or_else(|| {
                lookup_egress_ipv4_policy_value(&external_global_fallback, config.revision)
            })
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
    ingress: DataplaneDecision,
    egress: DataplaneDecision,
    observed: DataplaneDecision,
) -> DataplaneDecision {
    let has_ingress = ingress.policy_revision != 0;
    let has_egress = egress.policy_revision != 0;
    if has_ingress && ingress.verdict == Verdict::Deny {
        ingress
    } else if has_egress && egress.verdict == Verdict::Deny {
        egress
    } else if has_ingress {
        ingress
    } else if has_egress {
        egress
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
fn lookup_identity_v4(
    address: [u8; 4],
    config: Option<IdentityMapConfig>,
) -> IdentityId {
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
fn lookup_identity_v6(
    address: [u8; 16],
    config: Option<IdentityMapConfig>,
) -> IdentityId {
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
