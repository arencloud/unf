#![no_std]

//! Versioned, fixed-layout data shared by eBPF programs and userspace.

use unf_common::{BackendId, IdentityId, PolicyId, RuleId, ServiceId, Verdict};

pub use unf_common::PolicyDirection as Direction;

pub const FLOW_ABI_VERSION: u16 = 2;
pub const SERVICE_EVENT_ABI_VERSION: u16 = 2;
pub const SERVICE_EVENT_FRONTEND_CLUSTER_IP: u8 = 1;
pub const SERVICE_EVENT_FRONTEND_NODE_PORT_CLUSTER: u8 = 2;
pub const SERVICE_EVENT_FRONTEND_NODE_PORT_LOCAL: u8 = 3;
pub const SERVICE_EVENT_FRONTEND_LOAD_BALANCER_CLUSTER: u8 = 4;
pub const SERVICE_EVENT_FRONTEND_LOAD_BALANCER_LOCAL: u8 = 5;
pub const IDENTITY_MAP_ABI_VERSION: u16 = 2;
pub const IDENTITY_BANK_COUNT: u8 = 2;
pub const POLICY_MAP_ABI_VERSION: u16 = 3;
pub const POLICY_BANK_COUNT: u8 = 2;
pub const SERVICE_MAP_ABI_VERSION: u16 = 2;
pub const SERVICE_BANK_COUNT: u8 = 2;
pub const NODE_PORT_MAP_ABI_VERSION: u16 = 1;
pub const NODE_PORT_BANK_COUNT: u8 = 2;
pub const NODE_PORT_FRONTEND_FLAG_LOCAL: u16 = 1;
pub const LOAD_BALANCER_MAP_ABI_VERSION: u16 = 1;
pub const LOAD_BALANCER_NODE_SOURCE_SCHEMA_VERSION: u16 = 1;
pub const LOAD_BALANCER_NODE_SOURCE_FLAG_IPV4: u8 = 1;
pub const LOAD_BALANCER_NODE_SOURCE_FLAG_IPV6: u8 = 1 << 1;
pub const LOAD_BALANCER_BANK_COUNT: u8 = 2;
pub const LOAD_BALANCER_FRONTEND_FLAG_LOCAL: u16 = 1;
pub const LOAD_BALANCER_FRONTEND_FLAG_SOURCE_RANGES: u16 = 1 << 1;
pub const NODE_PORT_LOCAL_FRONTEND_INDEX_FLAG: u32 = 1 << 31;
pub const LOAD_BALANCER_LOCAL_FRONTEND_INDEX_BASE: u32 = 3 << 30;
pub const NODE_PORT_SNAT_PORT_BASE: u16 = 32_768;
pub const NODE_PORT_SNAT_PORT_MASK: u32 = 32_767;
pub const NODE_PORT_SNAT_PORT_PROBES: u32 = 16;
pub const SERVICE_BACKEND_FLAG_READY: u8 = 1 << 0;
pub const SERVICE_BACKEND_FLAG_SERVING: u8 = 1 << 1;
pub const SERVICE_BACKEND_FLAG_TERMINATING: u8 = 1 << 2;
pub const SERVICE_CONNECTION_ROLE_FORWARD: u8 = 1;
pub const SERVICE_CONNECTION_ROLE_REVERSE: u8 = 2;
pub const SERVICE_CONNECTION_FLAG_NODE_PORT_CLUSTER: u16 = 1 << 0;
pub const SERVICE_CONNECTION_FLAG_NODE_PORT_LOCAL: u16 = 1 << 1;
pub const SERVICE_EVENT_ACTION_TRANSLATE: u8 = 1;
pub const SERVICE_EVENT_ACTION_DROP: u8 = 2;
pub const SERVICE_EVENT_ACTION_EXPIRE: u8 = 3;
pub const SERVICE_EVENT_REASON_FORWARD_TRANSLATED: u8 = 1;
pub const SERVICE_EVENT_REASON_REVERSE_TRANSLATED: u8 = 2;
pub const SERVICE_EVENT_REASON_NO_BACKEND: u8 = 3;
pub const SERVICE_EVENT_REASON_INVALID_FRONTEND: u8 = 4;
pub const SERVICE_EVENT_REASON_MISSING_SLOT: u8 = 5;
pub const SERVICE_EVENT_REASON_INVALID_SLOT: u8 = 6;
pub const SERVICE_EVENT_REASON_MISSING_BACKEND: u8 = 7;
pub const SERVICE_EVENT_REASON_INVALID_BACKEND: u8 = 8;
pub const SERVICE_EVENT_REASON_PAIR_INSERT_FAILED: u8 = 9;
pub const SERVICE_EVENT_REASON_REWRITE_FAILED: u8 = 10;
pub const SERVICE_EVENT_REASON_EXPIRED_OR_CORRUPT: u8 = 11;
pub const SERVICE_EVENT_REASON_SOURCE_RANGE_DENIED: u8 = 12;
pub const POLICY_FLAG_HAS_POLICY: u16 = 1 << 0;
pub const POLICY_FLAG_HAS_RULE: u16 = 1 << 1;
pub const POLICY_FLAG_HAS_SHADOW: u16 = 1 << 2;
pub const POLICY_FLAG_SHADOW_HAS_POLICY: u16 = 1 << 3;
pub const POLICY_FLAG_SHADOW_HAS_RULE: u16 = 1 << 4;
pub const IPV6_EXTENSION_HEADER_LIMIT: u8 = 6;
pub const IPV6_EXTENSION_BYTE_LIMIT: usize = 256;
pub const CONNECTION_TCP_TIMEOUT_NS: u64 = 300_000_000_000;
pub const CONNECTION_UDP_TIMEOUT_NS: u64 = 30_000_000_000;
pub const CONNECTION_SCTP_TIMEOUT_NS: u64 = 60_000_000_000;
pub const TCP_FLAG_SYN: u8 = 0x02;
pub const TCP_FLAG_ACK: u8 = 0x10;

pub const IPV6_NEXT_HEADER_HOP_BY_HOP: u8 = 0;
pub const IPV6_NEXT_HEADER_ROUTING: u8 = 43;
pub const IPV6_NEXT_HEADER_FRAGMENT: u8 = 44;
pub const IPV6_NEXT_HEADER_ESP: u8 = 50;
pub const IPV6_NEXT_HEADER_AUTHENTICATION: u8 = 51;
pub const IPV6_NEXT_HEADER_NONE: u8 = 59;
pub const IPV6_NEXT_HEADER_DESTINATION_OPTIONS: u8 = 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ipv6ExtensionStep {
    Transport,
    Continue { next_header: u8, length: usize },
    Unsupported,
}

/// Decodes one IPv6 extension-header boundary from its first eight bytes.
///
/// Transport protocols are returned without inspecting `header`. Opaque,
/// terminal, malformed, and non-initial-fragment headers are unsupported.
#[must_use]
pub const fn ipv6_extension_step(next_header: u8, header: [u8; 8]) -> Ipv6ExtensionStep {
    match next_header {
        6 | 17 | 132 => Ipv6ExtensionStep::Transport,
        IPV6_NEXT_HEADER_HOP_BY_HOP
        | IPV6_NEXT_HEADER_ROUTING
        | IPV6_NEXT_HEADER_DESTINATION_OPTIONS => Ipv6ExtensionStep::Continue {
            next_header: header[0],
            length: (header[1] as usize + 1) * 8,
        },
        IPV6_NEXT_HEADER_FRAGMENT => {
            let fragment = u16::from_be_bytes([header[2], header[3]]);
            if fragment & 0xfff8 == 0 {
                Ipv6ExtensionStep::Continue {
                    next_header: header[0],
                    length: 8,
                }
            } else {
                Ipv6ExtensionStep::Unsupported
            }
        }
        IPV6_NEXT_HEADER_AUTHENTICATION if header[1] >= 1 => Ipv6ExtensionStep::Continue {
            next_header: header[0],
            length: (header[1] as usize + 2) * 4,
        },
        IPV6_NEXT_HEADER_ESP | IPV6_NEXT_HEADER_NONE | IPV6_NEXT_HEADER_AUTHENTICATION => {
            Ipv6ExtensionStep::Unsupported
        }
        _ => Ipv6ExtensionStep::Unsupported,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AddressFamily {
    Ipv4 = 4,
    Ipv6 = 6,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ReasonCode {
    Observed = 0,
    AllowExplicit = 1,
    DenyExplicit = 2,
    DenyDefault = 3,
    IdentityUnknown = 4,
    AllowDefault = 5,
    AllowEstablished = 6,
}

/// Address/transport tuple used by the bounded runtime connection tracker.
/// IPv4 addresses occupy the first four bytes, matching [`FlowKey`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct ConnectionKey {
    pub source_address: [u8; 16],
    pub destination_address: [u8; 16],
    pub source_port: [u8; 2],
    pub destination_port: [u8; 2],
    pub protocol: u8,
    pub address_family: u8,
    pub reserved: [u8; 2],
}

impl ConnectionKey {
    #[must_use]
    pub const fn reverse(self) -> Self {
        Self {
            source_address: self.destination_address,
            destination_address: self.source_address,
            source_port: self.destination_port,
            destination_port: self.source_port,
            protocol: self.protocol,
            address_family: self.address_family,
            reserved: [0; 2],
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct ConnectionState {
    pub last_seen_ns: u64,
    pub policy_revision: u64,
}

#[must_use]
pub const fn connection_timeout_ns(protocol: u8) -> Option<u64> {
    match protocol {
        6 => Some(CONNECTION_TCP_TIMEOUT_NS),
        17 => Some(CONNECTION_UDP_TIMEOUT_NS),
        132 => Some(CONNECTION_SCTP_TIMEOUT_NS),
        _ => None,
    }
}

/// New service flows may select only a ready endpoint that is not draining.
/// `serving` remains provenance for graceful termination: an already selected
/// flow keeps its persisted tuple until timeout even after the endpoint leaves
/// the active slot set.
#[must_use]
pub const fn service_backend_is_eligible(flags: u8) -> bool {
    flags & SERVICE_BACKEND_FLAG_READY != 0 && flags & SERVICE_BACKEND_FLAG_TERMINATING == 0
}

/// A service translation survives desired-state revision changes and expires
/// only by protocol lifetime or an incompatible fixed-layout value.
#[must_use]
pub const fn service_connection_is_active(state: &ServiceConnectionValue, now_ns: u64) -> bool {
    let Some(timeout_ns) = connection_timeout_ns(state.protocol) else {
        return false;
    };
    state.schema_version == SERVICE_MAP_ABI_VERSION
        && matches!(state.address_family, 4 | 6)
        && state.service_revision != 0
        && state.service_id.get() != 0
        && state.backend_id.get() != 0
        && matches!(
            state.flags,
            0 | SERVICE_CONNECTION_FLAG_NODE_PORT_CLUSTER | SERVICE_CONNECTION_FLAG_NODE_PORT_LOCAL
        )
        && if state.flags & SERVICE_CONNECTION_FLAG_NODE_PORT_CLUSTER != 0 {
            !address_is_zero(state.translated_source_address)
                && u16::from_be_bytes([state.reserved[0], state.reserved[1]]) >= 32_768
                && matches!(
                    state.reserved[2],
                    0 | SERVICE_EVENT_FRONTEND_LOAD_BALANCER_CLUSTER
                )
                && state.reserved[3] == 0
        } else {
            address_is_zero(state.translated_source_address)
                && state.reserved[0] == 0
                && state.reserved[1] == 0
                && matches!(
                    state.reserved[2],
                    0 | SERVICE_EVENT_FRONTEND_LOAD_BALANCER_LOCAL
                )
                && state.reserved[3] == 0
        }
        && now_ns.saturating_sub(state.last_seen_ns) <= timeout_ns
}

const fn address_is_zero(address: [u8; 16]) -> bool {
    let mut index = 0;
    while index < address.len() {
        if address[index] != 0 {
            return false;
        }
        index += 1;
    }
    true
}

#[must_use]
pub const fn service_event_action_reason_is_valid(action: u8, reason: u8) -> bool {
    matches!(
        (action, reason),
        (
            SERVICE_EVENT_ACTION_TRANSLATE,
            SERVICE_EVENT_REASON_FORWARD_TRANSLATED | SERVICE_EVENT_REASON_REVERSE_TRANSLATED
        ) | (
            SERVICE_EVENT_ACTION_DROP,
            SERVICE_EVENT_REASON_NO_BACKEND
                | SERVICE_EVENT_REASON_INVALID_FRONTEND
                | SERVICE_EVENT_REASON_MISSING_SLOT
                | SERVICE_EVENT_REASON_INVALID_SLOT
                | SERVICE_EVENT_REASON_MISSING_BACKEND
                | SERVICE_EVENT_REASON_INVALID_BACKEND
                | SERVICE_EVENT_REASON_PAIR_INSERT_FAILED
                | SERVICE_EVENT_REASON_REWRITE_FAILED
                | SERVICE_EVENT_REASON_SOURCE_RANGE_DENIED
        ) | (
            SERVICE_EVENT_ACTION_EXPIRE,
            SERVICE_EVENT_REASON_EXPIRED_OR_CORRUPT
        )
    )
}

#[must_use]
pub const fn service_event_frontend_kind_is_valid(kind: u8) -> bool {
    matches!(
        kind,
        SERVICE_EVENT_FRONTEND_CLUSTER_IP
            | SERVICE_EVENT_FRONTEND_NODE_PORT_CLUSTER
            | SERVICE_EVENT_FRONTEND_NODE_PORT_LOCAL
            | SERVICE_EVENT_FRONTEND_LOAD_BALANCER_CLUSTER
            | SERVICE_EVENT_FRONTEND_LOAD_BALANCER_LOCAL
    )
}

/// Deterministic flow hash used only for selecting a new revision-local slot.
/// Persistence is provided by `SERVICE_CONNECTIONS`, not by relying on this
/// hash after membership changes.
#[must_use]
pub const fn service_flow_hash(key: &ServiceConnectionKey, service_id: ServiceId) -> u32 {
    const OFFSET: u32 = 2_166_136_261;
    const PRIME: u32 = 16_777_619;

    const fn mix(hash: u32, value: u32) -> u32 {
        (hash ^ value).wrapping_mul(PRIME)
    }

    let mut hash = mix(OFFSET, service_id.get());
    hash = mix(
        hash,
        u32::from_be_bytes([
            key.source_address[0],
            key.source_address[1],
            key.source_address[2],
            key.source_address[3],
        ]),
    );
    hash = mix(
        hash,
        u32::from_be_bytes([
            key.source_address[4],
            key.source_address[5],
            key.source_address[6],
            key.source_address[7],
        ]),
    );
    hash = mix(
        hash,
        u32::from_be_bytes([
            key.source_address[8],
            key.source_address[9],
            key.source_address[10],
            key.source_address[11],
        ]),
    );
    hash = mix(
        hash,
        u32::from_be_bytes([
            key.source_address[12],
            key.source_address[13],
            key.source_address[14],
            key.source_address[15],
        ]),
    );
    hash = mix(
        hash,
        u32::from_be_bytes([
            key.destination_address[0],
            key.destination_address[1],
            key.destination_address[2],
            key.destination_address[3],
        ]),
    );
    hash = mix(
        hash,
        u32::from_be_bytes([
            key.destination_address[4],
            key.destination_address[5],
            key.destination_address[6],
            key.destination_address[7],
        ]),
    );
    hash = mix(
        hash,
        u32::from_be_bytes([
            key.destination_address[8],
            key.destination_address[9],
            key.destination_address[10],
            key.destination_address[11],
        ]),
    );
    hash = mix(
        hash,
        u32::from_be_bytes([
            key.destination_address[12],
            key.destination_address[13],
            key.destination_address[14],
            key.destination_address[15],
        ]),
    );
    hash = mix(
        hash,
        u32::from_be_bytes([
            key.source_port[0],
            key.source_port[1],
            key.destination_port[0],
            key.destination_port[1],
        ]),
    );
    mix(
        hash,
        u32::from_be_bytes([key.protocol, key.address_family, 0, 0]),
    )
}

/// Returns one bounded `NodePort` SNAT candidate from a full-cycle permutation
/// of the dynamic/private half of the port space.
#[must_use]
pub const fn node_port_snat_candidate(hash: u32, probe: u32) -> u16 {
    let stride = ((hash >> 16) & NODE_PORT_SNAT_PORT_MASK) | 1;
    NODE_PORT_SNAT_PORT_BASE.wrapping_add(
        (hash.wrapping_add(probe.wrapping_mul(stride)) & NODE_PORT_SNAT_PORT_MASK) as u16,
    )
}

#[must_use]
pub const fn packet_starts_connection(protocol: u8, tcp_flags: u8) -> bool {
    match protocol {
        6 => tcp_flags & TCP_FLAG_SYN != 0 && tcp_flags & TCP_FLAG_ACK == 0,
        17 | 132 => true,
        _ => false,
    }
}

#[must_use]
pub const fn connection_is_active(
    state: ConnectionState,
    active_policy_revision: u64,
    now_ns: u64,
    protocol: u8,
) -> bool {
    let Some(timeout_ns) = connection_timeout_ns(protocol) else {
        return false;
    };
    state.policy_revision != 0
        && active_policy_revision != 0
        && now_ns.saturating_sub(state.last_seen_ns) <= timeout_ns
}

/// Network-byte-order flow tuple. IPv4 addresses occupy the first four bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct FlowKey {
    pub source_identity: IdentityId,
    pub destination_identity: IdentityId,
    pub source_address: [u8; 16],
    pub destination_address: [u8; 16],
    pub source_port: [u8; 2],
    pub destination_port: [u8; 2],
    pub protocol: u8,
    pub address_family: u8,
    pub reserved: [u8; 2],
}

/// A compact event emitted from a ring buffer and enriched in userspace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct FlowEvent {
    pub timestamp_ns: u64,
    pub flow: FlowKey,
    pub policy_revision: u64,
    pub policy_id: PolicyId,
    pub rule_id: RuleId,
    pub shadow_policy_id: PolicyId,
    pub shadow_rule_id: RuleId,
    pub interface_index: u32,
    pub version: u16,
    pub size: u16,
    pub verdict: Verdict,
    pub direction: u8,
    pub reason: u8,
    pub shadow_verdict: u8,
    pub shadow_reason: u8,
    pub reserved: [u8; 3],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct Ipv4IdentityKey {
    /// IPv4 address in network byte order.
    pub address: [u8; 4],
}

impl Ipv4IdentityKey {
    #[must_use]
    pub const fn new(address: [u8; 4]) -> Self {
        Self { address }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct Ipv6IdentityKey {
    /// IPv6 address in network byte order.
    pub address: [u8; 16],
}

impl Ipv6IdentityKey {
    #[must_use]
    pub const fn new(address: [u8; 16]) -> Self {
        Self { address }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct IdentityMapValue {
    pub identity_id: IdentityId,
    pub schema_version: u16,
    pub flags: u16,
    pub revision: u64,
}

impl IdentityMapValue {
    #[must_use]
    pub const fn new(identity_id: IdentityId, revision: u64) -> Self {
        Self {
            identity_id,
            schema_version: IDENTITY_MAP_ABI_VERSION,
            flags: 0,
            revision,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct IdentityMapConfig {
    pub source_epoch: u64,
    pub revision: u64,
    pub entry_count: u32,
    pub schema_version: u16,
    pub active_bank: u8,
    pub flags: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct PolicyMapKey {
    pub source_identity: IdentityId,
    pub destination_identity: IdentityId,
    /// Destination port in network byte order; zero means protocol/global wildcard.
    pub destination_port: [u8; 2],
    /// IP protocol number; zero means global wildcard fallback.
    pub protocol: u8,
    pub bank: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct Ipv4PolicyMapKey {
    /// Exact source IPv4 address in network byte order; zero is a fallback.
    pub source_address: [u8; 4],
    pub destination_identity: IdentityId,
    /// Destination port in network byte order; zero means protocol/global wildcard.
    pub destination_port: [u8; 2],
    /// IP protocol number; zero means global wildcard fallback.
    pub protocol: u8,
    pub bank: u8,
}

/// The first 64 bits are exact policy dimensions; the final 128 bits are the
/// source address matched by an LPM trie.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct Ipv6PolicyMapData {
    pub destination_identity: IdentityId,
    pub destination_port: [u8; 2],
    pub protocol: u8,
    pub bank: u8,
    pub source_address: [u8; 16],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct EgressIpv4PolicyMapKey {
    /// Exact destination IPv4 address in network byte order; zero is a fallback.
    pub destination_address: [u8; 4],
    pub source_identity: IdentityId,
    /// Destination port in network byte order; zero means protocol/global wildcard.
    pub destination_port: [u8; 2],
    /// IP protocol number; zero means global wildcard fallback.
    pub protocol: u8,
    pub bank: u8,
}

/// The first 64 bits are exact egress dimensions; the final 128 bits are the
/// destination address matched by an LPM trie.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct EgressIpv6PolicyMapData {
    pub source_identity: IdentityId,
    pub destination_port: [u8; 2],
    pub protocol: u8,
    pub bank: u8,
    pub destination_address: [u8; 16],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct PolicyMapValue {
    pub policy_id: PolicyId,
    pub rule_id: RuleId,
    pub shadow_policy_id: PolicyId,
    pub shadow_rule_id: RuleId,
    pub revision: u64,
    pub schema_version: u16,
    pub flags: u16,
    pub verdict: u8,
    pub reason: u8,
    pub shadow_verdict: u8,
    pub shadow_reason: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct PolicyMapConfig {
    pub source_epoch: u64,
    pub revision: u64,
    pub entry_count: u32,
    pub schema_version: u16,
    pub active_bank: u8,
    pub flags: u8,
}

/// Exact IPv4 `ClusterIP` frontend. Ports are stored in network byte order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct Ipv4ServiceFrontendKey {
    pub address: [u8; 4],
    pub port: [u8; 2],
    pub protocol: u8,
    pub bank: u8,
}

/// Exact IPv6 `ClusterIP` frontend. Ports are stored in network byte order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct Ipv6ServiceFrontendKey {
    pub address: [u8; 16],
    pub port: [u8; 2],
    pub protocol: u8,
    pub bank: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct ServiceFrontendValue {
    pub service_id: ServiceId,
    pub frontend_index: u32,
    pub backend_count: u32,
    pub schema_version: u16,
    pub flags: u16,
    pub revision: u64,
    pub reserved: [u8; 8],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct ServiceBackendKey {
    pub service_id: ServiceId,
    pub backend_id: BackendId,
    pub bank: u8,
    pub reserved: [u8; 3],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct Ipv4ServiceBackendValue {
    pub revision: u64,
    pub address: [u8; 4],
    pub port: [u8; 2],
    pub schema_version: u16,
    pub protocol: u8,
    pub flags: u8,
    pub reserved: [u8; 6],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct Ipv6ServiceBackendValue {
    pub revision: u64,
    pub address: [u8; 16],
    pub port: [u8; 2],
    pub schema_version: u16,
    pub protocol: u8,
    pub flags: u8,
    pub reserved: [u8; 2],
}

/// Ordered backend membership for one frontend. The index is deterministic
/// only within a revision; connection state persists the stable `BackendId`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct ServiceBackendSlotKey {
    pub service_id: ServiceId,
    pub frontend_index: u32,
    pub slot: u32,
    pub bank: u8,
    pub reserved: [u8; 3],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct ServiceBackendSlotValue {
    pub backend_id: BackendId,
    pub schema_version: u16,
    pub flags: u16,
    pub revision: u64,
}

/// The sole activation pointer for the complete service map family.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct ServiceMapConfig {
    pub source_epoch: u64,
    pub revision: u64,
    pub frontend_count: u32,
    pub backend_count: u32,
    pub backend_slot_count: u32,
    pub schema_version: u16,
    pub active_bank: u8,
    pub flags: u8,
}

/// A host-facing `NodePort` key. The bank belongs to `NODE_PORT_CONFIG`, not to
/// the `ClusterIP` service map family.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct Ipv4NodePortFrontendKey {
    pub address: [u8; 4],
    pub port: [u8; 2],
    pub protocol: u8,
    pub bank: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct Ipv6NodePortFrontendKey {
    pub address: [u8; 16],
    pub port: [u8; 2],
    pub protocol: u8,
    pub bank: u8,
}

/// `NodePort` frontend metadata points to the independently active `ClusterIP`
/// service bank so Node-address-only updates never churn backend state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct NodePortFrontendValue {
    pub service_id: ServiceId,
    pub frontend_index: u32,
    pub backend_count: u32,
    pub schema_version: u16,
    pub flags: u16,
    pub service_revision: u64,
    pub service_bank: u8,
    pub reserved: [u8; 7],
}

/// Independent atomic pointer for the complete local `NodePort` frontend family.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct NodePortMapConfig {
    pub source_epoch: u64,
    pub service_revision: u64,
    pub node_revision: u64,
    pub ipv4_count: u32,
    pub ipv6_count: u32,
    pub schema_version: u16,
    pub active_bank: u8,
    pub flags: u8,
    pub reserved: u32,
}

/// A VIP frontend key. Its independent bank is selected by
/// `LOAD_BALANCER_CONFIG`; the value binds it to one active service bank.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct Ipv4LoadBalancerFrontendKey {
    pub address: [u8; 4],
    pub port: [u8; 2],
    pub protocol: u8,
    pub bank: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct Ipv6LoadBalancerFrontendKey {
    pub address: [u8; 16],
    pub port: [u8; 2],
    pub protocol: u8,
    pub bank: u8,
}

/// VIP metadata references exact service slots and all three independently
/// advancing control-plane revisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct LoadBalancerFrontendValue {
    pub service_id: ServiceId,
    pub frontend_index: u32,
    pub backend_count: u32,
    pub schema_version: u16,
    pub flags: u16,
    pub service_revision: u64,
    pub reachability_revision: u64,
    pub allocation_revision: u64,
    pub service_bank: u8,
    pub reserved: [u8; 7],
}

/// The first 64 bits are exact `LoadBalancer` dimensions; the final 32 bits are
/// the external source address matched by an LPM trie.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct Ipv4LoadBalancerSourceRangeData {
    pub service_id: ServiceId,
    pub bank: u8,
    pub reserved: [u8; 3],
    pub source_address: [u8; 4],
}

/// The first 64 bits are exact `LoadBalancer` dimensions; the final 128 bits are
/// the external source address matched by an LPM trie.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct Ipv6LoadBalancerSourceRangeData {
    pub service_id: ServiceId,
    pub bank: u8,
    pub reserved: [u8; 3],
    pub source_address: [u8; 16],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct LoadBalancerSourceRangeValue {
    pub service_revision: u64,
    pub reachability_revision: u64,
    pub allocation_revision: u64,
    pub schema_version: u16,
    pub reserved: [u8; 6],
}

/// Atomic pointer for the complete local VIP frontend family.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct LoadBalancerMapConfig {
    pub source_epoch: u64,
    pub service_revision: u64,
    pub reachability_revision: u64,
    pub allocation_revision: u64,
    pub ipv4_count: u32,
    pub ipv6_count: u32,
    pub schema_version: u16,
    pub active_bank: u8,
    pub service_bank: u8,
    pub flags: u8,
    pub reserved: [u8; 3],
}

/// Runtime-only local Node addresses used for Cluster `LoadBalancer` SNAT.
/// Userspace rebuilds this map from the authenticated Node snapshot on every
/// agent start, so it is deliberately independent from the persistent map ABI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct LoadBalancerNodeSourceConfig {
    pub node_revision: u64,
    pub ipv4_address: [u8; 4],
    pub ipv6_address: [u8; 16],
    pub schema_version: u16,
    pub flags: u8,
    pub reserved: [u8; 9],
}

/// Forward or reverse service-flow key. The role disambiguates identical
/// tuples admitted in opposite translation directions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct ServiceConnectionKey {
    pub source_address: [u8; 16],
    pub destination_address: [u8; 16],
    pub source_port: [u8; 2],
    pub destination_port: [u8; 2],
    pub protocol: u8,
    pub address_family: u8,
    pub role: u8,
    pub reserved: u8,
}

/// Stable translation selected for one service flow. Both forward and reverse
/// keys point at the same semantic value so backend selection survives service
/// revision churn.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct ServiceConnectionValue {
    pub last_seen_ns: u64,
    pub service_revision: u64,
    pub client_address: [u8; 16],
    pub frontend_address: [u8; 16],
    pub backend_address: [u8; 16],
    pub translated_source_address: [u8; 16],
    pub service_id: ServiceId,
    pub backend_id: BackendId,
    pub client_port: [u8; 2],
    pub frontend_port: [u8; 2],
    pub backend_port: [u8; 2],
    pub schema_version: u16,
    pub protocol: u8,
    pub address_family: u8,
    pub flags: u16,
    pub reserved: [u8; 4],
}

/// Fixed machine-readable service dataplane outcome. Kubernetes strings remain
/// in userspace; stable IDs and exact tuples are sufficient for enrichment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct ServiceEvent {
    pub timestamp_ns: u64,
    pub service_revision: u64,
    pub client_address: [u8; 16],
    pub frontend_address: [u8; 16],
    pub backend_address: [u8; 16],
    pub service_id: ServiceId,
    pub backend_id: BackendId,
    pub client_port: [u8; 2],
    pub frontend_port: [u8; 2],
    pub backend_port: [u8; 2],
    pub version: u16,
    pub size: u16,
    pub protocol: u8,
    pub address_family: u8,
    pub action: u8,
    pub reason: u8,
    pub reserved: [u8; 10],
}

const _: () = assert!(core::mem::size_of::<FlowKey>() == 48);
const _: () = assert!(core::mem::size_of::<FlowEvent>() == 96);
const _: () = assert!(core::mem::size_of::<ConnectionKey>() == 40);
const _: () = assert!(core::mem::size_of::<ConnectionState>() == 16);
const _: () = assert!(core::mem::size_of::<Ipv4IdentityKey>() == 4);
const _: () = assert!(core::mem::size_of::<Ipv6IdentityKey>() == 16);
const _: () = assert!(core::mem::size_of::<IdentityMapValue>() == 16);
const _: () = assert!(core::mem::size_of::<IdentityMapConfig>() == 24);
const _: () = assert!(core::mem::size_of::<PolicyMapKey>() == 12);
const _: () = assert!(core::mem::size_of::<Ipv4PolicyMapKey>() == 12);
const _: () = assert!(core::mem::size_of::<Ipv6PolicyMapData>() == 24);
const _: () = assert!(core::mem::size_of::<EgressIpv4PolicyMapKey>() == 12);
const _: () = assert!(core::mem::size_of::<EgressIpv6PolicyMapData>() == 24);
const _: () = assert!(core::mem::size_of::<PolicyMapValue>() == 32);
const _: () = assert!(core::mem::size_of::<PolicyMapConfig>() == 24);
const _: () = assert!(core::mem::size_of::<Ipv4ServiceFrontendKey>() == 8);
const _: () = assert!(core::mem::size_of::<Ipv6ServiceFrontendKey>() == 20);
const _: () = assert!(core::mem::size_of::<ServiceFrontendValue>() == 32);
const _: () = assert!(core::mem::size_of::<ServiceBackendKey>() == 12);
const _: () = assert!(core::mem::size_of::<Ipv4ServiceBackendValue>() == 24);
const _: () = assert!(core::mem::size_of::<Ipv6ServiceBackendValue>() == 32);
const _: () = assert!(core::mem::size_of::<ServiceBackendSlotKey>() == 16);
const _: () = assert!(core::mem::size_of::<ServiceBackendSlotValue>() == 16);
const _: () = assert!(core::mem::size_of::<ServiceMapConfig>() == 32);
const _: () = assert!(core::mem::size_of::<Ipv4NodePortFrontendKey>() == 8);
const _: () = assert!(core::mem::size_of::<Ipv6NodePortFrontendKey>() == 20);
const _: () = assert!(core::mem::size_of::<NodePortFrontendValue>() == 32);
const _: () = assert!(core::mem::size_of::<Ipv4LoadBalancerFrontendKey>() == 8);
const _: () = assert!(core::mem::size_of::<Ipv6LoadBalancerFrontendKey>() == 20);
const _: () = assert!(core::mem::size_of::<LoadBalancerFrontendValue>() == 48);
const _: () = assert!(core::mem::size_of::<Ipv4LoadBalancerSourceRangeData>() == 12);
const _: () = assert!(core::mem::size_of::<Ipv6LoadBalancerSourceRangeData>() == 24);
const _: () = assert!(core::mem::size_of::<LoadBalancerSourceRangeValue>() == 32);
const _: () = assert!(core::mem::size_of::<LoadBalancerMapConfig>() == 48);
const _: () = assert!(core::mem::size_of::<LoadBalancerNodeSourceConfig>() == 40);
const _: () = assert!(core::mem::size_of::<NodePortMapConfig>() == 40);
const _: () = assert!(core::mem::size_of::<ServiceConnectionKey>() == 40);
const _: () = assert!(core::mem::size_of::<ServiceConnectionValue>() == 104);
const _: () = assert!(core::mem::size_of::<ServiceEvent>() == 96);

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    #[test]
    fn abi_layout_is_stable() {
        assert_eq!(core::mem::align_of::<FlowKey>(), 4);
        assert_eq!(core::mem::align_of::<FlowEvent>(), 8);
        assert_eq!(core::mem::size_of::<FlowEvent>(), 96);
        assert_eq!(core::mem::align_of::<ConnectionKey>(), 1);
        assert_eq!(core::mem::size_of::<ConnectionKey>(), 40);
        assert_eq!(core::mem::align_of::<ConnectionState>(), 8);
        assert_eq!(core::mem::size_of::<ConnectionState>(), 16);
        assert_eq!(core::mem::align_of::<IdentityMapValue>(), 8);
        assert_eq!(core::mem::size_of::<IdentityMapValue>(), 16);
        assert_eq!(core::mem::align_of::<IdentityMapConfig>(), 8);
        assert_eq!(core::mem::size_of::<IdentityMapConfig>(), 24);
        assert_eq!(core::mem::align_of::<Ipv6IdentityKey>(), 1);
        assert_eq!(core::mem::size_of::<Ipv6IdentityKey>(), 16);
        assert_eq!(core::mem::align_of::<PolicyMapKey>(), 4);
        assert_eq!(core::mem::size_of::<PolicyMapKey>(), 12);
        assert_eq!(core::mem::align_of::<Ipv4PolicyMapKey>(), 4);
        assert_eq!(core::mem::size_of::<Ipv4PolicyMapKey>(), 12);
        assert_eq!(core::mem::align_of::<Ipv6PolicyMapData>(), 4);
        assert_eq!(core::mem::size_of::<Ipv6PolicyMapData>(), 24);
        assert_eq!(core::mem::align_of::<EgressIpv4PolicyMapKey>(), 4);
        assert_eq!(core::mem::size_of::<EgressIpv4PolicyMapKey>(), 12);
        assert_eq!(core::mem::align_of::<EgressIpv6PolicyMapData>(), 4);
        assert_eq!(core::mem::size_of::<EgressIpv6PolicyMapData>(), 24);
        assert_eq!(core::mem::align_of::<PolicyMapValue>(), 8);
        assert_eq!(core::mem::size_of::<PolicyMapValue>(), 32);
        assert_eq!(core::mem::align_of::<PolicyMapConfig>(), 8);
        assert_eq!(core::mem::size_of::<PolicyMapConfig>(), 24);
        assert_eq!(core::mem::align_of::<Ipv4ServiceFrontendKey>(), 1);
        assert_eq!(core::mem::size_of::<Ipv4ServiceFrontendKey>(), 8);
        assert_eq!(core::mem::align_of::<Ipv6ServiceFrontendKey>(), 1);
        assert_eq!(core::mem::size_of::<Ipv6ServiceFrontendKey>(), 20);
        assert_eq!(core::mem::align_of::<ServiceFrontendValue>(), 8);
        assert_eq!(core::mem::size_of::<ServiceFrontendValue>(), 32);
        assert_eq!(core::mem::align_of::<ServiceBackendKey>(), 4);
        assert_eq!(core::mem::size_of::<ServiceBackendKey>(), 12);
        assert_eq!(core::mem::align_of::<Ipv4ServiceBackendValue>(), 8);
        assert_eq!(core::mem::size_of::<Ipv4ServiceBackendValue>(), 24);
        assert_eq!(core::mem::align_of::<Ipv6ServiceBackendValue>(), 8);
        assert_eq!(core::mem::size_of::<Ipv6ServiceBackendValue>(), 32);
        assert_eq!(core::mem::align_of::<ServiceBackendSlotKey>(), 4);
        assert_eq!(core::mem::size_of::<ServiceBackendSlotKey>(), 16);
        assert_eq!(core::mem::align_of::<ServiceBackendSlotValue>(), 8);
        assert_eq!(core::mem::size_of::<ServiceBackendSlotValue>(), 16);
        assert_eq!(core::mem::align_of::<ServiceMapConfig>(), 8);
        assert_eq!(core::mem::size_of::<ServiceMapConfig>(), 32);
        assert_eq!(core::mem::size_of::<Ipv4NodePortFrontendKey>(), 8);
        assert_eq!(core::mem::size_of::<Ipv6NodePortFrontendKey>(), 20);
        assert_eq!(core::mem::align_of::<NodePortFrontendValue>(), 8);
        assert_eq!(core::mem::size_of::<NodePortFrontendValue>(), 32);
        assert_eq!(core::mem::align_of::<NodePortMapConfig>(), 8);
        assert_eq!(core::mem::size_of::<NodePortMapConfig>(), 40);
        assert_eq!(core::mem::size_of::<Ipv4LoadBalancerSourceRangeData>(), 12);
        assert_eq!(core::mem::size_of::<Ipv6LoadBalancerSourceRangeData>(), 24);
        assert_eq!(core::mem::size_of::<LoadBalancerSourceRangeValue>(), 32);
        assert_eq!(core::mem::align_of::<LoadBalancerNodeSourceConfig>(), 8);
        assert_eq!(core::mem::size_of::<LoadBalancerNodeSourceConfig>(), 40);
        assert_eq!(core::mem::align_of::<ServiceConnectionKey>(), 1);
        assert_eq!(core::mem::size_of::<ServiceConnectionKey>(), 40);
        assert_eq!(core::mem::align_of::<ServiceConnectionValue>(), 8);
        assert_eq!(core::mem::size_of::<ServiceConnectionValue>(), 104);
    }

    #[test]
    fn connection_keys_reverse_every_address_and_transport_field() {
        let key = ConnectionKey {
            source_address: [1; 16],
            destination_address: [2; 16],
            source_port: 32_000_u16.to_be_bytes(),
            destination_port: 8080_u16.to_be_bytes(),
            protocol: 6,
            address_family: AddressFamily::Ipv6 as u8,
            reserved: [9; 2],
        };
        let reverse = key.reverse();
        assert_eq!(reverse.source_address, key.destination_address);
        assert_eq!(reverse.destination_address, key.source_address);
        assert_eq!(reverse.source_port, key.destination_port);
        assert_eq!(reverse.destination_port, key.source_port);
        assert_eq!(
            reverse.reverse(),
            ConnectionKey {
                reserved: [0; 2],
                ..key
            }
        );
    }

    #[test]
    fn connection_state_is_protocol_bounded_and_survives_policy_churn() {
        let state = ConnectionState {
            last_seen_ns: 10,
            policy_revision: 7,
        };
        assert!(connection_is_active(
            state,
            7,
            10 + CONNECTION_TCP_TIMEOUT_NS,
            6
        ));
        assert!(!connection_is_active(
            state,
            7,
            11 + CONNECTION_TCP_TIMEOUT_NS,
            6
        ));
        assert!(connection_is_active(state, 8, 11, 6));
        assert!(!connection_is_active(state, 0, 11, 6));
        assert!(!connection_is_active(state, 7, 11, 1));
    }

    #[test]
    fn only_an_initial_tcp_syn_starts_tcp_state() {
        assert!(packet_starts_connection(6, TCP_FLAG_SYN));
        assert!(!packet_starts_connection(6, TCP_FLAG_SYN | TCP_FLAG_ACK));
        assert!(!packet_starts_connection(6, TCP_FLAG_ACK));
        assert!(packet_starts_connection(17, 0));
        assert!(packet_starts_connection(132, 0));
        assert!(!packet_starts_connection(1, 0));
    }

    fn service_connection(protocol: u8) -> ServiceConnectionValue {
        ServiceConnectionValue {
            last_seen_ns: 10,
            service_revision: 3,
            client_address: [1; 16],
            frontend_address: [2; 16],
            backend_address: [3; 16],
            translated_source_address: [0; 16],
            service_id: ServiceId::new(4),
            backend_id: BackendId::new(5),
            client_port: 32_000_u16.to_be_bytes(),
            frontend_port: 80_u16.to_be_bytes(),
            backend_port: 8080_u16.to_be_bytes(),
            schema_version: SERVICE_MAP_ABI_VERSION,
            protocol,
            address_family: AddressFamily::Ipv6 as u8,
            flags: 0,
            reserved: [0; 4],
        }
    }

    #[test]
    fn service_backend_eligibility_excludes_draining_and_unready_endpoints() {
        assert!(service_backend_is_eligible(
            SERVICE_BACKEND_FLAG_READY | SERVICE_BACKEND_FLAG_SERVING
        ));
        assert!(!service_backend_is_eligible(SERVICE_BACKEND_FLAG_SERVING));
        assert!(!service_backend_is_eligible(
            SERVICE_BACKEND_FLAG_READY | SERVICE_BACKEND_FLAG_TERMINATING
        ));
    }

    #[test]
    fn service_event_actions_accept_only_their_bounded_reasons() {
        assert!(service_event_action_reason_is_valid(
            SERVICE_EVENT_ACTION_TRANSLATE,
            SERVICE_EVENT_REASON_FORWARD_TRANSLATED
        ));
        assert!(service_event_action_reason_is_valid(
            SERVICE_EVENT_ACTION_DROP,
            SERVICE_EVENT_REASON_NO_BACKEND
        ));
        assert!(service_event_action_reason_is_valid(
            SERVICE_EVENT_ACTION_EXPIRE,
            SERVICE_EVENT_REASON_EXPIRED_OR_CORRUPT
        ));
        assert!(!service_event_action_reason_is_valid(
            SERVICE_EVENT_ACTION_TRANSLATE,
            SERVICE_EVENT_REASON_NO_BACKEND
        ));
        assert!(!service_event_action_reason_is_valid(0, 0));
        assert!(service_event_frontend_kind_is_valid(
            SERVICE_EVENT_FRONTEND_CLUSTER_IP
        ));
        assert!(service_event_frontend_kind_is_valid(
            SERVICE_EVENT_FRONTEND_NODE_PORT_CLUSTER
        ));
        assert!(service_event_frontend_kind_is_valid(
            SERVICE_EVENT_FRONTEND_NODE_PORT_LOCAL
        ));
        assert!(service_event_frontend_kind_is_valid(
            SERVICE_EVENT_FRONTEND_LOAD_BALANCER_CLUSTER
        ));
        assert!(service_event_frontend_kind_is_valid(
            SERVICE_EVENT_FRONTEND_LOAD_BALANCER_LOCAL
        ));
        assert!(!service_event_frontend_kind_is_valid(0));
        assert!(!service_event_frontend_kind_is_valid(6));
    }

    #[test]
    fn service_connections_expire_without_following_desired_state_revisions() {
        let tcp = service_connection(6);
        assert!(service_connection_is_active(
            &tcp,
            10 + CONNECTION_TCP_TIMEOUT_NS
        ));
        assert!(!service_connection_is_active(
            &tcp,
            11 + CONNECTION_TCP_TIMEOUT_NS
        ));

        let mut invalid = tcp;
        invalid.schema_version = SERVICE_MAP_ABI_VERSION + 1;
        assert!(!service_connection_is_active(&invalid, 11));
        invalid = tcp;
        invalid.address_family = 5;
        assert!(!service_connection_is_active(&invalid, 11));
        invalid = tcp;
        invalid.backend_id = BackendId::new(0);
        assert!(!service_connection_is_active(&invalid, 11));
        invalid = tcp;
        invalid.flags = SERVICE_CONNECTION_FLAG_NODE_PORT_CLUSTER << 3;
        assert!(!service_connection_is_active(&invalid, 11));
        invalid = tcp;
        invalid.flags = SERVICE_CONNECTION_FLAG_NODE_PORT_CLUSTER;
        assert!(!service_connection_is_active(&invalid, 11));
        invalid.translated_source_address = invalid.frontend_address;
        invalid.reserved[0..2].copy_from_slice(&32_768_u16.to_be_bytes());
        assert!(service_connection_is_active(&invalid, 11));
        invalid = tcp;
        invalid.flags = SERVICE_CONNECTION_FLAG_NODE_PORT_LOCAL;
        assert!(service_connection_is_active(&invalid, 11));
        invalid.flags |= SERVICE_CONNECTION_FLAG_NODE_PORT_CLUSTER;
        assert!(!service_connection_is_active(&invalid, 11));
        invalid = tcp;
        invalid.flags = SERVICE_CONNECTION_FLAG_NODE_PORT_CLUSTER;
        invalid.translated_source_address = invalid.frontend_address;
        invalid.reserved[0..2].copy_from_slice(&32_768_u16.to_be_bytes());
        invalid.reserved[2] = SERVICE_EVENT_FRONTEND_LOAD_BALANCER_CLUSTER;
        assert!(service_connection_is_active(&invalid, 11));
        invalid = tcp;
        invalid.flags = SERVICE_CONNECTION_FLAG_NODE_PORT_LOCAL;
        invalid.reserved[2] = SERVICE_EVENT_FRONTEND_LOAD_BALANCER_LOCAL;
        assert!(service_connection_is_active(&invalid, 11));
    }

    #[test]
    fn service_flow_hash_is_stable_and_covers_both_families_and_ports() {
        let key = ServiceConnectionKey {
            source_address: [1; 16],
            destination_address: [2; 16],
            source_port: 32_000_u16.to_be_bytes(),
            destination_port: 443_u16.to_be_bytes(),
            protocol: 6,
            address_family: AddressFamily::Ipv6 as u8,
            role: SERVICE_CONNECTION_ROLE_FORWARD,
            reserved: 0,
        };
        let expected = service_flow_hash(&key, ServiceId::new(7));
        assert_eq!(service_flow_hash(&key, ServiceId::new(7)), expected);

        let mut changed = key;
        changed.destination_address[15] ^= 1;
        assert_ne!(service_flow_hash(&changed, ServiceId::new(7)), expected);
        changed = key;
        changed.destination_port = 8443_u16.to_be_bytes();
        assert_ne!(service_flow_hash(&changed, ServiceId::new(7)), expected);
        assert_ne!(service_flow_hash(&key, ServiceId::new(8)), expected);
    }

    #[test]
    fn node_port_snat_candidates_are_bounded_dispersed_and_churn_safe() {
        let mut candidates = std::collections::HashSet::new();
        for probe in 0..NODE_PORT_SNAT_PORT_PROBES {
            let candidate = node_port_snat_candidate(7, probe);
            assert!(candidate >= NODE_PORT_SNAT_PORT_BASE);
            assert!(candidates.insert(candidate));
        }
        assert_eq!(candidates.len(), NODE_PORT_SNAT_PORT_PROBES as usize);

        let mut allocated = std::collections::HashSet::new();
        let mut key = ServiceConnectionKey {
            source_address: [1; 16],
            destination_address: [2; 16],
            source_port: 10_000_u16.to_be_bytes(),
            destination_port: 30_080_u16.to_be_bytes(),
            protocol: 6,
            address_family: AddressFamily::Ipv4 as u8,
            role: SERVICE_CONNECTION_ROLE_FORWARD,
            reserved: 0,
        };
        for source_port in 10_000_u16..14_096_u16 {
            key.source_port = source_port.to_be_bytes();
            let hash = service_flow_hash(&key, ServiceId::new(7));
            let candidate = (0..NODE_PORT_SNAT_PORT_PROBES)
                .map(|probe| node_port_snat_candidate(hash, probe))
                .find(|candidate| allocated.insert(*candidate));
            assert!(
                candidate.is_some(),
                "bounded allocation failed at source port {source_port}"
            );
        }
    }

    #[test]
    fn ipv6_extension_steps_validate_lengths_and_fragments() {
        assert_eq!(ipv6_extension_step(6, [0; 8]), Ipv6ExtensionStep::Transport);
        assert_eq!(
            ipv6_extension_step(IPV6_NEXT_HEADER_HOP_BY_HOP, [17, 1, 0, 0, 0, 0, 0, 0]),
            Ipv6ExtensionStep::Continue {
                next_header: 17,
                length: 16,
            }
        );
        assert_eq!(
            ipv6_extension_step(IPV6_NEXT_HEADER_ROUTING, [6, 2, 0, 0, 0, 0, 0, 0]),
            Ipv6ExtensionStep::Continue {
                next_header: 6,
                length: 24,
            }
        );
        assert_eq!(
            ipv6_extension_step(
                IPV6_NEXT_HEADER_DESTINATION_OPTIONS,
                [17, 0, 0, 0, 0, 0, 0, 0]
            ),
            Ipv6ExtensionStep::Continue {
                next_header: 17,
                length: 8,
            }
        );
        assert_eq!(
            ipv6_extension_step(IPV6_NEXT_HEADER_FRAGMENT, [132, 0, 0, 1, 0, 0, 0, 0]),
            Ipv6ExtensionStep::Continue {
                next_header: 132,
                length: 8,
            }
        );
        assert_eq!(
            ipv6_extension_step(IPV6_NEXT_HEADER_FRAGMENT, [6, 0, 0, 8, 0, 0, 0, 0]),
            Ipv6ExtensionStep::Unsupported
        );
        assert_eq!(
            ipv6_extension_step(IPV6_NEXT_HEADER_AUTHENTICATION, [6, 1, 0, 0, 0, 0, 0, 0]),
            Ipv6ExtensionStep::Continue {
                next_header: 6,
                length: 12,
            }
        );
        assert_eq!(
            ipv6_extension_step(IPV6_NEXT_HEADER_AUTHENTICATION, [6, 0, 0, 0, 0, 0, 0, 0]),
            Ipv6ExtensionStep::Unsupported
        );
        assert_eq!(
            ipv6_extension_step(IPV6_NEXT_HEADER_ESP, [0; 8]),
            Ipv6ExtensionStep::Unsupported
        );
        assert_eq!(
            ipv6_extension_step(IPV6_NEXT_HEADER_NONE, [0; 8]),
            Ipv6ExtensionStep::Unsupported
        );
    }
}
