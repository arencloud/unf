//! Kubernetes-independent service load-balancing intent.
//!
//! This crate deliberately stops before selecting a dataplane algorithm or map
//! ABI. It defines the validated, deterministic boundary that Kubernetes and
//! future native APIs must cross before service state can reach an agent.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use unf_common::{BackendId, Protocol, Revision, ServiceId};
use unf_ebpf_common::{
    LOAD_BALANCER_LOCAL_FRONTEND_INDEX_BASE, NODE_PORT_BANK_COUNT, NODE_PORT_FRONTEND_FLAG_LOCAL,
    NODE_PORT_LOCAL_FRONTEND_INDEX_FLAG, NODE_PORT_MAP_ABI_VERSION, SERVICE_BACKEND_FLAG_READY,
    SERVICE_BACKEND_FLAG_SERVING, SERVICE_BACKEND_FLAG_TERMINATING, SERVICE_BANK_COUNT,
    SERVICE_MAP_ABI_VERSION,
};

pub use unf_common::SERVICE_SNAPSHOT_SCHEMA_VERSION;

pub const LEGACY_SERVICE_SNAPSHOT_SCHEMA_VERSION: u16 = 1;
pub const NODE_PORT_SERVICE_SNAPSHOT_SCHEMA_VERSION: u16 = 2;
pub const LOAD_BALANCER_SERVICE_SNAPSHOT_SCHEMA_VERSION: u16 = 3;
pub const NODE_PORT_NODE_SNAPSHOT_SCHEMA_VERSION: u16 = 1;
pub const UNF_LOAD_BALANCER_CLASS: &str = "network.unf.io/load-balancer";
pub const MAX_NODE_PORT_NODE_ADDRESSES: usize = 64;
pub const MAX_SERVICES: usize = 65_536;
pub const MAX_SERVICE_FRONTENDS: usize = 131_072;
pub const MAX_SERVICE_NODE_PORTS: usize = 131_072;
pub const MAX_SERVICE_LOAD_BALANCER_FRONTENDS: usize = 131_072;
pub const MAX_SERVICE_BACKENDS: usize = 262_144;
pub const MAX_SERVICE_BACKEND_REFERENCES: usize = 524_288;
pub const MAX_BACKENDS_PER_SERVICE: usize = 4_096;
pub const MAX_LOAD_BALANCER_SOURCE_RANGES_PER_SERVICE: usize = 64;
pub const MAX_PROVENANCE_COMPONENT_BYTES: usize = 253;
pub const MAX_ENDPOINT_SLICE_PROVENANCE: usize = 128;
pub const SERVICE_FRONTEND_BANK_CAPACITY: usize = MAX_SERVICE_FRONTENDS;
pub const SERVICE_BACKEND_BANK_CAPACITY: usize = MAX_SERVICE_BACKENDS;
pub const SERVICE_BACKEND_SLOT_BANK_CAPACITY: usize = MAX_SERVICE_BACKEND_REFERENCES;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ServiceFrontend {
    pub address: IpAddr,
    pub port: u16,
    pub protocol: Protocol,
    pub name: Option<String>,
    pub app_protocol: Option<String>,
    pub backend_ids: Vec<BackendId>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ServiceBackend {
    pub id: BackendId,
    pub address: IpAddr,
    pub port: u16,
    pub protocol: Protocol,
    pub port_name: Option<String>,
    pub app_protocol: Option<String>,
    pub endpoint_slices: Vec<String>,
    pub target_workload: Option<String>,
    pub node_name: Option<String>,
    pub zone: Option<String>,
    pub ready: bool,
    pub serving: bool,
    pub terminating: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum AddressFamily {
    Ipv4,
    Ipv6,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ServiceTrafficPolicy {
    #[default]
    Cluster,
    Local,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ServiceTrafficDistribution {
    #[default]
    Any,
    PreferSameZone,
    PreferSameNode,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(
    tag = "mode",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum ServiceSessionAffinity {
    #[default]
    None,
    ClientIp {
        timeout_seconds: u32,
    },
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ServiceSelectionAlgorithm {
    #[default]
    StableHash,
    Maglev,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ServiceForwardingMode {
    #[default]
    Nat,
    Dsr,
}

#[allow(clippy::trivially_copy_pass_by_ref)]
const fn is_cluster_policy(value: &ServiceTrafficPolicy) -> bool {
    matches!(value, ServiceTrafficPolicy::Cluster)
}

#[allow(clippy::trivially_copy_pass_by_ref)]
const fn is_any_distribution(value: &ServiceTrafficDistribution) -> bool {
    matches!(value, ServiceTrafficDistribution::Any)
}

#[allow(clippy::trivially_copy_pass_by_ref)]
const fn is_no_affinity(value: &ServiceSessionAffinity) -> bool {
    matches!(value, ServiceSessionAffinity::None)
}

#[allow(clippy::trivially_copy_pass_by_ref)]
const fn is_stable_hash(value: &ServiceSelectionAlgorithm) -> bool {
    matches!(value, ServiceSelectionAlgorithm::StableHash)
}

#[allow(clippy::trivially_copy_pass_by_ref)]
const fn is_nat(value: &ServiceForwardingMode) -> bool {
    matches!(value, ServiceForwardingMode::Nat)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ServiceIpFamilyPolicy {
    SingleStack,
    PreferDualStack,
    RequireDualStack,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ServiceIpPrefix {
    pub address: IpAddr,
    pub prefix_length: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ServiceIpPrefixParseError {
    #[error("IP prefix must use address/prefix-length syntax")]
    MissingPrefixLength,
    #[error("invalid IP address in prefix")]
    InvalidAddress,
    #[error("invalid IP prefix length")]
    InvalidPrefixLength,
    #[error("IP prefix address has host bits set")]
    NonCanonical,
}

impl FromStr for ServiceIpPrefix {
    type Err = ServiceIpPrefixParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (address, prefix_length) = value
            .split_once('/')
            .ok_or(ServiceIpPrefixParseError::MissingPrefixLength)?;
        let address = address
            .parse()
            .map_err(|_| ServiceIpPrefixParseError::InvalidAddress)?;
        let prefix_length = prefix_length
            .parse()
            .map_err(|_| ServiceIpPrefixParseError::InvalidPrefixLength)?;
        let prefix = Self {
            address,
            prefix_length,
        };
        if !prefix.is_canonical() {
            return Err(ServiceIpPrefixParseError::NonCanonical);
        }
        Ok(prefix)
    }
}

impl ServiceIpPrefix {
    #[must_use]
    pub const fn family(self) -> AddressFamily {
        match self.address {
            IpAddr::V4(_) => AddressFamily::Ipv4,
            IpAddr::V6(_) => AddressFamily::Ipv6,
        }
    }

    #[must_use]
    pub fn is_canonical(self) -> bool {
        match self.address {
            IpAddr::V4(address) if self.prefix_length <= 32 => {
                let mask = if self.prefix_length == 0 {
                    0
                } else {
                    u32::MAX << (32 - self.prefix_length)
                };
                u32::from(address) & mask == u32::from(address)
            }
            IpAddr::V6(address) if self.prefix_length <= 128 => {
                let mask = if self.prefix_length == 0 {
                    0
                } else {
                    u128::MAX << (128 - self.prefix_length)
                };
                u128::from(address) & mask == u128::from(address)
            }
            IpAddr::V4(_) | IpAddr::V6(_) => false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum NodeAddressKind {
    Internal,
    External,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ServiceNodeAddress {
    pub address: IpAddr,
    pub kind: NodeAddressKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct NodePortNodeSnapshot {
    pub schema_version: u16,
    pub source_epoch: u64,
    pub revision: Revision,
    pub node_name: String,
    pub node_uid: String,
    pub addresses: Vec<ServiceNodeAddress>,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum NodePortNodeError {
    #[error("unsupported NodePort Node snapshot schema {actual}; expected {expected}")]
    UnsupportedSchema { actual: u16, expected: u16 },
    #[error("NodePort Node snapshot source epoch and revision must be nonzero")]
    ZeroRevision,
    #[error("NodePort Node snapshot has invalid {field}")]
    InvalidIdentity { field: &'static str },
    #[error("NodePort Node snapshot has no eligible addresses")]
    MissingAddress,
    #[error("NodePort Node snapshot has {actual} addresses; limit is {limit}")]
    TooManyAddresses { actual: usize, limit: usize },
    #[error("NodePort Node snapshot repeats address {0:?}")]
    DuplicateAddress(ServiceNodeAddress),
    #[error("NodePort Node snapshot contains unusable address {0:?}")]
    UnusableAddress(ServiceNodeAddress),
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ServiceNodePort {
    pub family: AddressFamily,
    pub port: u16,
    pub service_port: u16,
    pub protocol: Protocol,
    pub name: Option<String>,
    pub app_protocol: Option<String>,
    pub traffic_policy: ServiceTrafficPolicy,
    pub backend_ids: Vec<BackendId>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ServiceLoadBalancerFrontend {
    pub family: AddressFamily,
    pub service_port: u16,
    pub protocol: Protocol,
    pub name: Option<String>,
    pub app_protocol: Option<String>,
    pub backend_ids: Vec<BackendId>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ServiceLoadBalancer {
    pub class: String,
    pub ip_families: Vec<AddressFamily>,
    pub ip_family_policy: ServiceIpFamilyPolicy,
    pub requested_ips: Vec<IpAddr>,
    pub traffic_policy: ServiceTrafficPolicy,
    pub source_ranges: Vec<ServiceIpPrefix>,
    pub allocate_node_ports: bool,
    pub health_check_node_port: Option<u16>,
    pub frontends: Vec<ServiceLoadBalancerFrontend>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ServiceLoadBalancerSource {
    pub class: String,
    pub ip_families: Vec<AddressFamily>,
    pub ip_family_policy: ServiceIpFamilyPolicy,
    pub requested_ips: Vec<IpAddr>,
    pub source_ranges: Vec<ServiceIpPrefix>,
    pub allocate_node_ports: bool,
    pub health_check_node_port: Option<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ServiceSourcePort {
    pub name: Option<String>,
    pub protocol: Protocol,
    pub port: u16,
    pub app_protocol: Option<String>,
    pub node_port: Option<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ServiceSource {
    pub namespace: String,
    pub name: String,
    pub cluster_ips: Vec<IpAddr>,
    pub external_traffic_policy: ServiceTrafficPolicy,
    pub internal_traffic_policy: ServiceTrafficPolicy,
    pub session_affinity: ServiceSessionAffinity,
    pub traffic_distribution: ServiceTrafficDistribution,
    pub selection_algorithm: ServiceSelectionAlgorithm,
    pub forwarding_mode: ServiceForwardingMode,
    pub load_balancer: Option<ServiceLoadBalancerSource>,
    pub ports: Vec<ServiceSourcePort>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct EndpointPortSource {
    pub name: Option<String>,
    pub protocol: Protocol,
    pub port: Option<u16>,
    pub app_protocol: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct EndpointSource {
    pub addresses: Vec<IpAddr>,
    pub target_workload: Option<String>,
    pub node_name: Option<String>,
    pub zone: Option<String>,
    pub ready: bool,
    pub serving: bool,
    pub terminating: bool,
    pub ports: Vec<EndpointPortSource>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct EndpointSliceSource {
    pub namespace: String,
    pub name: String,
    pub service_name: String,
    pub address_family: AddressFamily,
    pub endpoints: Vec<EndpointSource>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ServiceIr {
    pub id: ServiceId,
    pub namespace: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "is_cluster_policy")]
    pub internal_traffic_policy: ServiceTrafficPolicy,
    #[serde(default, skip_serializing_if = "is_no_affinity")]
    pub session_affinity: ServiceSessionAffinity,
    #[serde(default, skip_serializing_if = "is_any_distribution")]
    pub traffic_distribution: ServiceTrafficDistribution,
    #[serde(default, skip_serializing_if = "is_stable_hash")]
    pub selection_algorithm: ServiceSelectionAlgorithm,
    #[serde(default, skip_serializing_if = "is_nat")]
    pub forwarding_mode: ServiceForwardingMode,
    pub frontends: Vec<ServiceFrontend>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub node_ports: Vec<ServiceNodePort>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub load_balancer: Option<ServiceLoadBalancer>,
    pub backends: Vec<ServiceBackend>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ServiceSnapshot {
    pub schema_version: u16,
    pub source_epoch: u64,
    pub revision: Revision,
    pub services: Vec<ServiceIr>,
}

impl NodePortNodeSnapshot {
    /// Validates local Node ownership and returns canonical address ordering.
    ///
    /// # Errors
    ///
    /// Rejects unsupported schemas, missing provenance, unusable or duplicate
    /// addresses, and snapshots outside the explicit per-Node bound.
    pub fn validate_and_normalize(mut self) -> Result<Self, NodePortNodeError> {
        if self.schema_version != NODE_PORT_NODE_SNAPSHOT_SCHEMA_VERSION {
            return Err(NodePortNodeError::UnsupportedSchema {
                actual: self.schema_version,
                expected: NODE_PORT_NODE_SNAPSHOT_SCHEMA_VERSION,
            });
        }
        if self.source_epoch == 0 || self.revision == Revision::INITIAL {
            return Err(NodePortNodeError::ZeroRevision);
        }
        if self.node_name.is_empty() || self.node_name.len() > 253 {
            return Err(NodePortNodeError::InvalidIdentity { field: "node name" });
        }
        if self.node_uid.is_empty() || self.node_uid.len() > 128 {
            return Err(NodePortNodeError::InvalidIdentity { field: "node UID" });
        }
        if self.addresses.is_empty() {
            return Err(NodePortNodeError::MissingAddress);
        }
        if self.addresses.len() > MAX_NODE_PORT_NODE_ADDRESSES {
            return Err(NodePortNodeError::TooManyAddresses {
                actual: self.addresses.len(),
                limit: MAX_NODE_PORT_NODE_ADDRESSES,
            });
        }
        self.addresses.sort();
        for pair in self.addresses.windows(2) {
            if pair[0].address == pair[1].address {
                return Err(NodePortNodeError::DuplicateAddress(pair[1]));
            }
        }
        if let Some(address) = self
            .addresses
            .iter()
            .find(|address| !usable_node_port_address(address.address))
        {
            return Err(NodePortNodeError::UnusableAddress(*address));
        }
        Ok(self)
    }
}

const fn usable_node_port_address(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            !address.is_unspecified()
                && !address.is_loopback()
                && !address.is_multicast()
                && !address.is_broadcast()
                && !address.is_link_local()
        }
        IpAddr::V6(address) => {
            !address.is_unspecified()
                && !address.is_loopback()
                && !address.is_multicast()
                && !address.is_unicast_link_local()
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ServiceIrError {
    #[error("unsupported service snapshot schema {actual}; expected {expected}")]
    UnsupportedSchema { actual: u16, expected: u16 },
    #[error("legacy service snapshot schema v1 cannot contain NodePort intent")]
    LegacyNodePortIntent,
    #[error("service snapshot schema v{schema} cannot contain LoadBalancer intent")]
    LegacyLoadBalancerIntent { schema: u16 },
    #[error("service snapshot schema v{schema} cannot contain advanced selection intent")]
    LegacyAdvancedSelectionIntent { schema: u16 },
    #[error("service snapshot source epoch must be nonzero")]
    ZeroSourceEpoch,
    #[error("service snapshot revision must be nonzero")]
    ZeroRevision,
    #[error("service snapshot has {actual} services; limit is {limit}")]
    TooManyServices { actual: usize, limit: usize },
    #[error("service snapshot has {actual} frontends; limit is {limit}")]
    TooManyFrontends { actual: usize, limit: usize },
    #[error("service snapshot has {actual} NodePort frontends; limit is {limit}")]
    TooManyNodePorts { actual: usize, limit: usize },
    #[error("service snapshot has {actual} LoadBalancer frontends; limit is {limit}")]
    TooManyLoadBalancerFrontends { actual: usize, limit: usize },
    #[error("service snapshot has {actual} backends; limit is {limit}")]
    TooManyBackends { actual: usize, limit: usize },
    #[error("service snapshot has {actual} frontend/backend references; limit is {limit}")]
    TooManyBackendReferences { actual: usize, limit: usize },
    #[error("service {service:?} has {actual} backends; per-service limit is {limit}")]
    TooManyServiceBackends {
        service: ServiceId,
        actual: usize,
        limit: usize,
    },
    #[error("service ID zero is reserved")]
    ZeroServiceId,
    #[error("backend ID zero is reserved for service {service:?}")]
    ZeroBackendId { service: ServiceId },
    #[error("duplicate service ID {0:?}")]
    DuplicateServiceId(ServiceId),
    #[error("duplicate service provenance {namespace}/{name}")]
    DuplicateServiceName { namespace: String, name: String },
    #[error("service {service:?} has invalid {field}: {reason}")]
    InvalidServiceField {
        service: ServiceId,
        field: &'static str,
        reason: &'static str,
    },
    #[error("service {service:?} must have at least one frontend")]
    MissingFrontend { service: ServiceId },
    #[error("service {service:?} has invalid frontend {frontend:?}: {reason}")]
    InvalidFrontend {
        service: ServiceId,
        frontend: ServiceFrontend,
        reason: &'static str,
    },
    #[error("frontend {0:?} is owned by more than one service")]
    DuplicateFrontend(ServiceFrontend),
    #[error("NodePort {port}/{protocol:?} is owned by services {existing:?} and {candidate:?}")]
    DuplicateNodePort {
        port: u16,
        protocol: Protocol,
        existing: ServiceId,
        candidate: ServiceId,
    },
    #[error("service {service:?} has duplicate NodePort frontend {node_port:?}")]
    DuplicateNodePortFrontend {
        service: ServiceId,
        node_port: ServiceNodePort,
    },
    #[error("service {service:?} has invalid NodePort frontend {node_port:?}: {reason}")]
    InvalidNodePort {
        service: ServiceId,
        node_port: ServiceNodePort,
        reason: &'static str,
    },
    #[error("service {service:?} has invalid LoadBalancer intent: {reason}")]
    InvalidLoadBalancer {
        service: ServiceId,
        reason: &'static str,
    },
    #[error("service {service:?} has invalid LoadBalancer frontend {frontend:?}: {reason}")]
    InvalidLoadBalancerFrontend {
        service: ServiceId,
        frontend: ServiceLoadBalancerFrontend,
        reason: &'static str,
    },
    #[error(
        "LoadBalancer requested IP {address} is owned by services {existing:?} and {candidate:?}"
    )]
    DuplicateLoadBalancerAddress {
        address: IpAddr,
        existing: ServiceId,
        candidate: ServiceId,
    },
    #[error("LoadBalancer requested IP {address} collides with a ClusterIP")]
    LoadBalancerClusterIpCollision { address: IpAddr },
    #[error("frontend {frontend:?} repeats backend reference {backend:?}")]
    DuplicateFrontendBackend {
        frontend: ServiceFrontend,
        backend: BackendId,
    },
    #[error("frontend {frontend:?} references unknown backend {backend:?}")]
    UnknownFrontendBackend {
        frontend: ServiceFrontend,
        backend: BackendId,
    },
    #[error("frontend {frontend:?} and backend {backend:?} use different address families")]
    BackendFamilyMismatch {
        frontend: ServiceFrontend,
        backend: BackendId,
    },
    #[error("service {service:?} has duplicate backend ID {backend:?}")]
    DuplicateBackendId {
        service: ServiceId,
        backend: BackendId,
    },
    #[error("service {service:?} has duplicate backend endpoint {address}:{port}/{protocol:?}")]
    DuplicateBackendEndpoint {
        service: ServiceId,
        address: IpAddr,
        port: u16,
        protocol: Protocol,
    },
    #[error("service {service:?} backend {backend:?} is invalid: {reason}")]
    InvalidBackend {
        service: ServiceId,
        backend: BackendId,
        reason: &'static str,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ServiceCompileError {
    #[error("duplicate Service source {namespace}/{name}")]
    DuplicateService { namespace: String, name: String },
    #[error("duplicate EndpointSlice source {namespace}/{name}")]
    DuplicateEndpointSlice { namespace: String, name: String },
    #[error("{kind} provisional ID collision {id} between {existing:?} and {candidate:?}")]
    IdCollision {
        kind: &'static str,
        id: u32,
        existing: String,
        candidate: String,
    },
    #[error("EndpointSlice {endpoint_slice} declares {declared:?} but contains address {address}")]
    AddressFamilyMismatch {
        endpoint_slice: String,
        declared: AddressFamily,
        address: IpAddr,
    },
    #[error(
        "EndpointSlice {endpoint_slice} has no resolved port for Service {service} port {port_name:?}/{protocol:?}"
    )]
    UnresolvedEndpointPort {
        endpoint_slice: String,
        service: String,
        port_name: Option<String>,
        protocol: Protocol,
    },
    #[error(
        "backend {address}:{port}/{protocol:?} for Service {service} has conflicting endpoint provenance"
    )]
    ConflictingBackendProvenance {
        service: String,
        address: IpAddr,
        port: u16,
        protocol: Protocol,
    },
    #[error(transparent)]
    InvalidIr(#[from] ServiceIrError),
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ServiceDataplaneError {
    #[error(transparent)]
    InvalidIr(#[from] ServiceIrError),
    #[error("invalid service map bank {0}; expected 0 or 1")]
    InvalidBank(u8),
    #[error(
        "NodePort intent contains {actual} frontends but host-facing lowering is not implemented"
    )]
    UnsupportedNodePort { actual: usize },
    #[error("LoadBalancer intent contains {actual} frontends but VIP lowering is not implemented")]
    UnsupportedLoadBalancer { actual: usize },
    #[error("advanced Service selection intent requires the Phase 7 transactional lowerer")]
    UnsupportedAdvancedSelection,
    #[error("Local LoadBalancer slot index overflow for service {service:?} on Node {node}")]
    LocalLoadBalancerIndex { service: ServiceId, node: String },
    #[error("Local LoadBalancer slot key collided with another service slot")]
    LocalLoadBalancerSlotCollision,
    #[error("service map {map} requires {actual} entries; per-bank limit is {limit}")]
    Capacity {
        map: &'static str,
        actual: usize,
        limit: usize,
    },
}

/// Canonical fixed-width bytes written to one logical service bank.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceDataplaneState {
    pub source_epoch: u64,
    pub revision: u64,
    pub bank: u8,
    pub ipv4_frontends: BTreeMap<[u8; 8], [u8; 32]>,
    pub ipv6_frontends: BTreeMap<[u8; 20], [u8; 32]>,
    pub ipv4_backends: BTreeMap<[u8; 12], [u8; 24]>,
    pub ipv6_backends: BTreeMap<[u8; 12], [u8; 32]>,
    pub backend_slots: BTreeMap<[u8; 16], [u8; 16]>,
    pub config: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum NodePortDataplaneError {
    #[error(transparent)]
    InvalidService(#[from] ServiceIrError),
    #[error(transparent)]
    InvalidNode(#[from] NodePortNodeError),
    #[error("service and NodePort Node snapshots have different source epochs")]
    SourceEpochMismatch,
    #[error("invalid service bank {0}; expected 0 or 1")]
    InvalidServiceBank(u8),
    #[error("invalid NodePort bank {0}; expected 0 or 1")]
    InvalidNodePortBank(u8),
    #[error("NodePort {node_port} for service {service_id:?} has no exact ClusterIP frontend")]
    MissingFrontendLink {
        service_id: ServiceId,
        node_port: u16,
    },
    #[error("NodePort dataplane does not support protocol {0:?}")]
    UnsupportedProtocol(Protocol),
    #[error("advanced Service selection intent requires the Phase 7 transactional lowerer")]
    UnsupportedAdvancedSelection,
    #[error("NodePort map {map} requires {actual} entries; per-bank limit is {limit}")]
    Capacity {
        map: &'static str,
        actual: usize,
        limit: usize,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum NodePortFabricDataplaneError {
    #[error(transparent)]
    Service(#[from] ServiceDataplaneError),
    #[error(transparent)]
    NodePort(#[from] NodePortDataplaneError),
    #[error("node-local NodePort slot key collided with a ClusterIP slot")]
    LocalSlotCollision,
}

/// Canonical fixed-width local `NodePort` state. Values reference one already
/// staged `ClusterIP` service bank and become visible through a separate pointer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodePortDataplaneState {
    pub source_epoch: u64,
    pub service_revision: u64,
    pub node_revision: u64,
    pub service_bank: u8,
    pub bank: u8,
    pub ipv4_frontends: BTreeMap<[u8; 8], [u8; 32]>,
    pub ipv6_frontends: BTreeMap<[u8; 20], [u8; 32]>,
    /// Node-local slot entries merged into the referenced service bank by the
    /// complete fabric compiler. Cluster-policy frontends leave this empty.
    pub service_backend_slots: BTreeMap<[u8; 16], [u8; 16]>,
    pub config: [u8; 40],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodePortFabricDataplaneState {
    pub service: ServiceDataplaneState,
    pub node_port: NodePortDataplaneState,
}

/// Returns the disjoint service-slot index for one Local `LoadBalancer` frontend
/// on one Node. The fixed per-Service backend bound plus one no-local sentinel
/// is the Node ordinal stride.
#[must_use]
pub fn load_balancer_local_frontend_index(
    service: &ServiceIr,
    frontend_index: usize,
    node_name: &str,
) -> Option<u32> {
    let node_ordinal = service
        .backends
        .iter()
        .filter_map(|backend| backend.node_name.as_deref())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .position(|candidate| candidate == node_name)
        .unwrap_or(MAX_BACKENDS_PER_SERVICE);
    let offset = frontend_index
        .checked_mul(MAX_BACKENDS_PER_SERVICE + 1)?
        .checked_add(node_ordinal)?;
    LOAD_BALANCER_LOCAL_FRONTEND_INDEX_BASE.checked_add(u32::try_from(offset).ok()?)
}

struct CompiledNodePortFrontends {
    ipv4: BTreeMap<[u8; 8], [u8; 32]>,
    ipv6: BTreeMap<[u8; 20], [u8; 32]>,
    service_backend_slots: BTreeMap<[u8; 16], [u8; 16]>,
}

#[derive(Default)]
struct ProvisionalIdRegistry {
    service_keys: BTreeMap<u32, String>,
    backend_keys: BTreeMap<u32, String>,
}

impl ProvisionalIdRegistry {
    fn service_id(&mut self, key: &str) -> Result<ServiceId, ServiceCompileError> {
        let id = provisional_id(key);
        admit_id(&mut self.service_keys, "service", id, key)?;
        Ok(ServiceId::new(id))
    }

    fn backend_id(&mut self, key: &str) -> Result<BackendId, ServiceCompileError> {
        let id = provisional_id(key);
        admit_id(&mut self.backend_keys, "backend", id, key)?;
        Ok(BackendId::new(id))
    }
}

/// Compiles platform-neutral Service and `EndpointSlice` observations into the
/// shared, deterministic service intent boundary.
///
/// Cluster-IP Services without selected endpoints remain valid with an empty
/// backend set. Headless Services are omitted because they have no load-balancer
/// frontend. Endpoint eligibility is deliberately preserved, not interpreted.
///
/// # Errors
///
/// Rejects duplicate source ownership, address-family lies, unresolved matching
/// endpoint ports, conflicting duplicate backend provenance, provisional ID
/// collisions, and any invalid or over-capacity output IR.
#[allow(clippy::too_many_lines)]
pub fn compile_service_snapshot(
    source_epoch: u64,
    revision: Revision,
    mut services: Vec<ServiceSource>,
    mut endpoint_slices: Vec<EndpointSliceSource>,
) -> Result<ServiceSnapshot, ServiceCompileError> {
    services.sort();
    endpoint_slices.sort();
    reject_duplicate_services(&services)?;
    reject_duplicate_endpoint_slices(&endpoint_slices)?;

    let mut ids = ProvisionalIdRegistry::default();
    let mut compiled = Vec::new();
    for service in services {
        if service.cluster_ips.is_empty() {
            continue;
        }
        let service_reference = format!("{}/{}", service.namespace, service.name);
        let service_key = canonical_key(
            "service-v1",
            [service.namespace.as_str(), service.name.as_str()].into_iter(),
        );
        let service_id = ids.service_id(&service_key)?;
        let matching_slices: Vec<&EndpointSliceSource> = endpoint_slices
            .iter()
            .filter(|slice| {
                slice.namespace == service.namespace && slice.service_name == service.name
            })
            .collect();
        validate_slice_families(&matching_slices)?;

        let mut backends = BTreeMap::<(IpAddr, u16, Protocol), ServiceBackend>::new();
        let mut frontends = Vec::new();
        let mut node_ports = Vec::new();
        for cluster_ip in service.cluster_ips.iter().copied() {
            for service_port in &service.ports {
                let mut backend_ids = BTreeSet::new();
                for slice in &matching_slices {
                    let slice_reference = format!("{}/{}", slice.namespace, slice.name);
                    for endpoint in &slice.endpoints {
                        for endpoint_port in endpoint.ports.iter().filter(|candidate| {
                            candidate.name == service_port.name
                                && candidate.protocol == service_port.protocol
                        }) {
                            let port = endpoint_port.port.ok_or_else(|| {
                                ServiceCompileError::UnresolvedEndpointPort {
                                    endpoint_slice: slice_reference.clone(),
                                    service: service_reference.clone(),
                                    port_name: service_port.name.clone(),
                                    protocol: service_port.protocol,
                                }
                            })?;
                            for address in endpoint
                                .addresses
                                .iter()
                                .copied()
                                .filter(|address| address.is_ipv4() == cluster_ip.is_ipv4())
                            {
                                let backend_key = canonical_key(
                                    "backend-v1",
                                    [
                                        service_key.as_str(),
                                        &address.to_string(),
                                        &port.to_string(),
                                        &(endpoint_port.protocol as u8).to_string(),
                                    ]
                                    .into_iter(),
                                );
                                let backend_id = ids.backend_id(&backend_key)?;
                                let candidate = ServiceBackend {
                                    id: backend_id,
                                    address,
                                    port,
                                    protocol: endpoint_port.protocol,
                                    port_name: endpoint_port.name.clone(),
                                    app_protocol: endpoint_port.app_protocol.clone(),
                                    endpoint_slices: vec![slice_reference.clone()],
                                    target_workload: endpoint.target_workload.clone(),
                                    node_name: endpoint.node_name.clone(),
                                    zone: endpoint.zone.clone(),
                                    ready: endpoint.ready,
                                    serving: endpoint.serving,
                                    terminating: endpoint.terminating,
                                };
                                merge_backend(&service_reference, &mut backends, candidate)?;
                                backend_ids.insert(backend_id);
                            }
                        }
                    }
                }
                let backend_ids = backend_ids.into_iter().collect::<Vec<_>>();
                frontends.push(ServiceFrontend {
                    address: cluster_ip,
                    port: service_port.port,
                    protocol: service_port.protocol,
                    name: service_port.name.clone(),
                    app_protocol: service_port.app_protocol.clone(),
                    backend_ids: backend_ids.clone(),
                });
                if let Some(node_port) = service_port.node_port {
                    node_ports.push(ServiceNodePort {
                        family: if cluster_ip.is_ipv4() {
                            AddressFamily::Ipv4
                        } else {
                            AddressFamily::Ipv6
                        },
                        port: node_port,
                        service_port: service_port.port,
                        protocol: service_port.protocol,
                        name: service_port.name.clone(),
                        app_protocol: service_port.app_protocol.clone(),
                        traffic_policy: service.external_traffic_policy,
                        backend_ids,
                    });
                }
            }
        }
        let load_balancer = service.load_balancer.map(|source| {
            let mut load_balancer_frontends = Vec::new();
            for family in &source.ip_families {
                for service_port in &service.ports {
                    let backend_ids = frontends
                        .iter()
                        .find(|frontend| {
                            frontend.address.is_ipv4() == (*family == AddressFamily::Ipv4)
                                && frontend.port == service_port.port
                                && frontend.protocol == service_port.protocol
                                && frontend.name == service_port.name
                                && frontend.app_protocol == service_port.app_protocol
                        })
                        .map_or_else(Vec::new, |frontend| frontend.backend_ids.clone());
                    load_balancer_frontends.push(ServiceLoadBalancerFrontend {
                        family: *family,
                        service_port: service_port.port,
                        protocol: service_port.protocol,
                        name: service_port.name.clone(),
                        app_protocol: service_port.app_protocol.clone(),
                        backend_ids,
                    });
                }
            }
            ServiceLoadBalancer {
                class: source.class,
                ip_families: source.ip_families,
                ip_family_policy: source.ip_family_policy,
                requested_ips: source.requested_ips,
                traffic_policy: service.external_traffic_policy,
                source_ranges: source.source_ranges,
                allocate_node_ports: source.allocate_node_ports,
                health_check_node_port: source.health_check_node_port,
                frontends: load_balancer_frontends,
            }
        });
        compiled.push(ServiceIr {
            id: service_id,
            namespace: service.namespace,
            name: service.name,
            internal_traffic_policy: service.internal_traffic_policy,
            session_affinity: service.session_affinity,
            traffic_distribution: service.traffic_distribution,
            selection_algorithm: service.selection_algorithm,
            forwarding_mode: service.forwarding_mode,
            frontends,
            node_ports,
            load_balancer,
            backends: backends.into_values().collect(),
        });
    }
    Ok(ServiceSnapshot {
        schema_version: SERVICE_SNAPSHOT_SCHEMA_VERSION,
        source_epoch,
        revision,
        services: compiled,
    }
    .validate_and_normalize()?)
}

fn reject_duplicate_services(services: &[ServiceSource]) -> Result<(), ServiceCompileError> {
    for pair in services.windows(2) {
        if pair[0].namespace == pair[1].namespace && pair[0].name == pair[1].name {
            return Err(ServiceCompileError::DuplicateService {
                namespace: pair[1].namespace.clone(),
                name: pair[1].name.clone(),
            });
        }
    }
    Ok(())
}

fn reject_duplicate_endpoint_slices(
    slices: &[EndpointSliceSource],
) -> Result<(), ServiceCompileError> {
    for pair in slices.windows(2) {
        if pair[0].namespace == pair[1].namespace && pair[0].name == pair[1].name {
            return Err(ServiceCompileError::DuplicateEndpointSlice {
                namespace: pair[1].namespace.clone(),
                name: pair[1].name.clone(),
            });
        }
    }
    Ok(())
}

fn validate_slice_families(slices: &[&EndpointSliceSource]) -> Result<(), ServiceCompileError> {
    for slice in slices {
        for address in slice
            .endpoints
            .iter()
            .flat_map(|endpoint| endpoint.addresses.iter().copied())
        {
            let matches = match slice.address_family {
                AddressFamily::Ipv4 => address.is_ipv4(),
                AddressFamily::Ipv6 => address.is_ipv6(),
            };
            if !matches {
                return Err(ServiceCompileError::AddressFamilyMismatch {
                    endpoint_slice: format!("{}/{}", slice.namespace, slice.name),
                    declared: slice.address_family,
                    address,
                });
            }
        }
    }
    Ok(())
}

fn merge_backend(
    service: &str,
    backends: &mut BTreeMap<(IpAddr, u16, Protocol), ServiceBackend>,
    candidate: ServiceBackend,
) -> Result<(), ServiceCompileError> {
    let key = (candidate.address, candidate.port, candidate.protocol);
    let Some(existing) = backends.get_mut(&key) else {
        backends.insert(key, candidate);
        return Ok(());
    };
    let candidate_slice = candidate.endpoint_slices[0].clone();
    let same_provenance = existing.id == candidate.id
        && existing.target_workload == candidate.target_workload
        && existing.node_name == candidate.node_name
        && existing.zone == candidate.zone
        && existing.ready == candidate.ready
        && existing.serving == candidate.serving
        && existing.terminating == candidate.terminating;
    if !same_provenance {
        return Err(ServiceCompileError::ConflictingBackendProvenance {
            service: service.to_owned(),
            address: candidate.address,
            port: candidate.port,
            protocol: candidate.protocol,
        });
    }
    // Kubernetes permits multiple named Service ports to resolve to the same
    // address/port/protocol backend tuple. A backend has one dataplane identity,
    // so retain a singular port/appProtocol value only when every reference
    // agrees; otherwise the optional provenance is intentionally unspecific.
    if existing.port_name != candidate.port_name {
        existing.port_name = None;
    }
    if existing.app_protocol != candidate.app_protocol {
        existing.app_protocol = None;
    }
    if !existing.endpoint_slices.contains(&candidate_slice) {
        existing.endpoint_slices.push(candidate_slice);
        existing.endpoint_slices.sort();
    }
    Ok(())
}

fn canonical_key<'a>(namespace: &str, components: impl Iterator<Item = &'a str>) -> String {
    let mut key = namespace.to_owned();
    for component in components {
        key.push('|');
        key.push_str(&component.len().to_string());
        key.push(':');
        key.push_str(component);
    }
    key
}

fn provisional_id(key: &str) -> u32 {
    let mut hash = 0x811c_9dc5_u32;
    for byte in key.as_bytes() {
        hash ^= u32::from(*byte);
        hash = hash.wrapping_mul(0x0100_0193);
    }
    if hash == 0 { 1 } else { hash }
}

fn admit_id(
    registry: &mut BTreeMap<u32, String>,
    kind: &'static str,
    id: u32,
    key: &str,
) -> Result<(), ServiceCompileError> {
    if let Some(existing) = registry.get(&id) {
        if existing != key {
            return Err(ServiceCompileError::IdCollision {
                kind,
                id,
                existing: existing.clone(),
                candidate: key.to_owned(),
            });
        }
    } else {
        registry.insert(id, key.to_owned());
    }
    Ok(())
}

impl ServiceSnapshot {
    /// Validates bounded service intent and returns one canonical ordering.
    ///
    /// Backend readiness is retained rather than interpreted here. Selection,
    /// draining, session affinity, and connection persistence belong to the
    /// later load-balancer compiler and dataplane contract.
    ///
    /// # Errors
    ///
    /// Rejects incompatible schemas, unversioned state, invalid or duplicate
    /// identities/endpoints, unusable addresses/ports, and bounded-capacity
    /// violations.
    #[allow(clippy::too_many_lines)]
    pub fn validate_and_normalize(mut self) -> Result<Self, ServiceIrError> {
        migrate_service_snapshot_schema(&mut self)?;
        if self.source_epoch == 0 {
            return Err(ServiceIrError::ZeroSourceEpoch);
        }
        if self.revision == Revision::INITIAL {
            return Err(ServiceIrError::ZeroRevision);
        }
        if self.services.len() > MAX_SERVICES {
            return Err(ServiceIrError::TooManyServices {
                actual: self.services.len(),
                limit: MAX_SERVICES,
            });
        }

        let mut service_ids = BTreeSet::new();
        let mut service_names = BTreeSet::new();
        let mut frontend_owners = BTreeMap::new();
        let mut node_port_owners = BTreeMap::new();
        let mut load_balancer_address_owners = BTreeMap::new();
        let cluster_ip_addresses = self
            .services
            .iter()
            .flat_map(|service| service.frontends.iter().map(|frontend| frontend.address))
            .collect::<BTreeSet<_>>();
        let mut total_frontends = 0_usize;
        let mut total_node_ports = 0_usize;
        let mut total_load_balancer_frontends = 0_usize;
        let mut total_backends = 0_usize;
        let mut total_backend_references = 0_usize;

        for service in &mut self.services {
            validate_service_identity(service, &mut service_ids, &mut service_names)?;
            if let ServiceSessionAffinity::ClientIp { timeout_seconds } = service.session_affinity
                && !(1..=86_400).contains(&timeout_seconds)
            {
                return Err(ServiceIrError::InvalidServiceField {
                    service: service.id,
                    field: "session affinity timeout",
                    reason: "must be between 1 and 86400 seconds",
                });
            }
            if service.frontends.is_empty() {
                return Err(ServiceIrError::MissingFrontend {
                    service: service.id,
                });
            }
            if service.backends.len() > MAX_BACKENDS_PER_SERVICE {
                return Err(ServiceIrError::TooManyServiceBackends {
                    service: service.id,
                    actual: service.backends.len(),
                    limit: MAX_BACKENDS_PER_SERVICE,
                });
            }
            total_frontends = total_frontends.saturating_add(service.frontends.len());
            let (service_node_port_count, service_node_port_references) =
                validate_and_normalize_node_ports(service, &mut node_port_owners)?;
            total_node_ports = total_node_ports.saturating_add(service_node_port_count);
            total_backends = total_backends.saturating_add(service.backends.len());
            total_backend_references = service
                .frontends
                .iter()
                .fold(total_backend_references, |count, frontend| {
                    count.saturating_add(frontend.backend_ids.len())
                });
            total_backend_references =
                total_backend_references.saturating_add(service_node_port_references);

            for frontend in &mut service.frontends {
                validate_frontend(service.id, frontend)?;
                let key = (frontend.address, frontend.port, frontend.protocol);
                if frontend_owners.insert(key, service.id).is_some() {
                    return Err(ServiceIrError::DuplicateFrontend(frontend.clone()));
                }
                frontend.backend_ids.sort();
            }
            for backend in &mut service.backends {
                backend.endpoint_slices.sort();
                backend.endpoint_slices.dedup();
            }
            validate_backends(service)?;
            validate_frontend_backends(service)?;
            validate_node_port_backends(service)?;
            let (load_balancer_frontends, load_balancer_references) =
                validate_and_normalize_load_balancer(
                    service,
                    &cluster_ip_addresses,
                    &mut load_balancer_address_owners,
                )?;
            total_load_balancer_frontends =
                total_load_balancer_frontends.saturating_add(load_balancer_frontends);
            total_backend_references =
                total_backend_references.saturating_add(load_balancer_references);
            service.frontends.sort();
            service.backends.sort();
        }

        validate_snapshot_capacities(
            total_frontends,
            total_node_ports,
            total_load_balancer_frontends,
            total_backends,
            total_backend_references,
        )?;
        self.services.sort_by(|left, right| {
            left.id
                .cmp(&right.id)
                .then_with(|| left.namespace.cmp(&right.namespace))
                .then_with(|| left.name.cmp(&right.name))
        });
        Ok(self)
    }

    /// Produces the exact additive-schema-v1 view used only for old agents.
    ///
    /// # Errors
    ///
    /// Returns the same validation error as [`Self::validate_and_normalize`]
    /// when the source snapshot is not valid current or migratable state.
    pub fn legacy_v1_projection(&self) -> Result<Self, ServiceIrError> {
        let mut projected = self.clone().validate_and_normalize()?;
        reject_legacy_advanced_selection_intent(
            &projected,
            LEGACY_SERVICE_SNAPSHOT_SCHEMA_VERSION,
        )?;
        for service in &mut projected.services {
            service.node_ports.clear();
            service.load_balancer = None;
        }
        projected.schema_version = LEGACY_SERVICE_SNAPSHOT_SCHEMA_VERSION;
        Ok(projected)
    }

    /// Produces the exact schema-v2 `NodePort` view for consumers that do not
    /// understand `LoadBalancer` intent.
    ///
    /// # Errors
    ///
    /// Returns the same validation error as [`Self::validate_and_normalize`]
    /// when the source snapshot is not valid current or migratable state.
    pub fn node_port_v2_projection(&self) -> Result<Self, ServiceIrError> {
        let mut projected = self.clone().validate_and_normalize()?;
        reject_legacy_advanced_selection_intent(
            &projected,
            NODE_PORT_SERVICE_SNAPSHOT_SCHEMA_VERSION,
        )?;
        for service in &mut projected.services {
            service.load_balancer = None;
        }
        projected.schema_version = NODE_PORT_SERVICE_SNAPSHOT_SCHEMA_VERSION;
        Ok(projected)
    }

    /// Produces the exact schema-v3 `LoadBalancer` view when advanced selection
    /// intent is absent.
    ///
    /// # Errors
    ///
    /// Rejects invalid current state or any advanced selection intent that a
    /// schema-v3 consumer would ignore.
    pub fn load_balancer_v3_projection(&self) -> Result<Self, ServiceIrError> {
        let mut projected = self.clone().validate_and_normalize()?;
        reject_legacy_advanced_selection_intent(
            &projected,
            LOAD_BALANCER_SERVICE_SNAPSHOT_SCHEMA_VERSION,
        )?;
        projected.schema_version = LOAD_BALANCER_SERVICE_SNAPSHOT_SCHEMA_VERSION;
        Ok(projected)
    }
}

fn migrate_service_snapshot_schema(snapshot: &mut ServiceSnapshot) -> Result<(), ServiceIrError> {
    match snapshot.schema_version {
        LEGACY_SERVICE_SNAPSHOT_SCHEMA_VERSION => {
            if snapshot
                .services
                .iter()
                .any(|service| !service.node_ports.is_empty())
            {
                return Err(ServiceIrError::LegacyNodePortIntent);
            }
            reject_legacy_load_balancer_intent(snapshot, LEGACY_SERVICE_SNAPSHOT_SCHEMA_VERSION)?;
            snapshot.schema_version = SERVICE_SNAPSHOT_SCHEMA_VERSION;
        }
        NODE_PORT_SERVICE_SNAPSHOT_SCHEMA_VERSION => {
            reject_legacy_load_balancer_intent(
                snapshot,
                NODE_PORT_SERVICE_SNAPSHOT_SCHEMA_VERSION,
            )?;
            snapshot.schema_version = SERVICE_SNAPSHOT_SCHEMA_VERSION;
        }
        LOAD_BALANCER_SERVICE_SNAPSHOT_SCHEMA_VERSION => {
            reject_legacy_advanced_selection_intent(
                snapshot,
                LOAD_BALANCER_SERVICE_SNAPSHOT_SCHEMA_VERSION,
            )?;
            snapshot.schema_version = SERVICE_SNAPSHOT_SCHEMA_VERSION;
        }
        SERVICE_SNAPSHOT_SCHEMA_VERSION => {}
        actual => {
            return Err(ServiceIrError::UnsupportedSchema {
                actual,
                expected: SERVICE_SNAPSHOT_SCHEMA_VERSION,
            });
        }
    }
    Ok(())
}

fn reject_legacy_advanced_selection_intent(
    snapshot: &ServiceSnapshot,
    schema: u16,
) -> Result<(), ServiceIrError> {
    if has_advanced_selection_intent(snapshot) {
        return Err(ServiceIrError::LegacyAdvancedSelectionIntent { schema });
    }
    Ok(())
}

fn has_advanced_selection_intent(snapshot: &ServiceSnapshot) -> bool {
    snapshot.services.iter().any(|service| {
        service.internal_traffic_policy != ServiceTrafficPolicy::Cluster
            || service.session_affinity != ServiceSessionAffinity::None
            || service.traffic_distribution != ServiceTrafficDistribution::Any
            || service.selection_algorithm != ServiceSelectionAlgorithm::StableHash
            || service.forwarding_mode != ServiceForwardingMode::Nat
    })
}

fn reject_legacy_load_balancer_intent(
    snapshot: &ServiceSnapshot,
    schema: u16,
) -> Result<(), ServiceIrError> {
    if snapshot
        .services
        .iter()
        .any(|service| service.load_balancer.is_some())
    {
        return Err(ServiceIrError::LegacyLoadBalancerIntent { schema });
    }
    Ok(())
}

fn validate_snapshot_capacities(
    frontends: usize,
    node_ports: usize,
    load_balancer_frontends: usize,
    backends: usize,
    backend_references: usize,
) -> Result<(), ServiceIrError> {
    if frontends > MAX_SERVICE_FRONTENDS {
        return Err(ServiceIrError::TooManyFrontends {
            actual: frontends,
            limit: MAX_SERVICE_FRONTENDS,
        });
    }
    if node_ports > MAX_SERVICE_NODE_PORTS {
        return Err(ServiceIrError::TooManyNodePorts {
            actual: node_ports,
            limit: MAX_SERVICE_NODE_PORTS,
        });
    }
    if load_balancer_frontends > MAX_SERVICE_LOAD_BALANCER_FRONTENDS {
        return Err(ServiceIrError::TooManyLoadBalancerFrontends {
            actual: load_balancer_frontends,
            limit: MAX_SERVICE_LOAD_BALANCER_FRONTENDS,
        });
    }
    if backends > MAX_SERVICE_BACKENDS {
        return Err(ServiceIrError::TooManyBackends {
            actual: backends,
            limit: MAX_SERVICE_BACKENDS,
        });
    }
    if backend_references > MAX_SERVICE_BACKEND_REFERENCES {
        return Err(ServiceIrError::TooManyBackendReferences {
            actual: backend_references,
            limit: MAX_SERVICE_BACKEND_REFERENCES,
        });
    }
    Ok(())
}

fn validate_service_identity(
    service: &ServiceIr,
    ids: &mut BTreeSet<ServiceId>,
    names: &mut BTreeSet<(String, String)>,
) -> Result<(), ServiceIrError> {
    if service.id.get() == 0 {
        return Err(ServiceIrError::ZeroServiceId);
    }
    validate_provenance_component(service.id, "namespace", &service.namespace)?;
    validate_provenance_component(service.id, "name", &service.name)?;
    if !ids.insert(service.id) {
        return Err(ServiceIrError::DuplicateServiceId(service.id));
    }
    if !names.insert((service.namespace.clone(), service.name.clone())) {
        return Err(ServiceIrError::DuplicateServiceName {
            namespace: service.namespace.clone(),
            name: service.name.clone(),
        });
    }
    Ok(())
}

fn validate_provenance_component(
    service: ServiceId,
    field: &'static str,
    value: &str,
) -> Result<(), ServiceIrError> {
    if value.is_empty() {
        return Err(ServiceIrError::InvalidServiceField {
            service,
            field,
            reason: "must not be empty",
        });
    }
    if value.len() > MAX_PROVENANCE_COMPONENT_BYTES {
        return Err(ServiceIrError::InvalidServiceField {
            service,
            field,
            reason: "exceeds the bounded provenance length",
        });
    }
    Ok(())
}

fn validate_frontend(service: ServiceId, frontend: &ServiceFrontend) -> Result<(), ServiceIrError> {
    if frontend.address.is_unspecified() || frontend.address.is_multicast() {
        return Err(ServiceIrError::InvalidFrontend {
            service,
            frontend: frontend.clone(),
            reason: "address must be unicast and specified",
        });
    }
    if frontend.port == 0 {
        return Err(ServiceIrError::InvalidFrontend {
            service,
            frontend: frontend.clone(),
            reason: "port zero is not a service frontend",
        });
    }
    if !is_service_protocol(frontend.protocol) {
        return Err(ServiceIrError::InvalidFrontend {
            service,
            frontend: frontend.clone(),
            reason: "only TCP, UDP, and SCTP frontends are supported",
        });
    }
    if !valid_optional_provenance(frontend.name.as_deref())
        || !valid_optional_provenance(frontend.app_protocol.as_deref())
    {
        return Err(ServiceIrError::InvalidFrontend {
            service,
            frontend: frontend.clone(),
            reason: "port name and app protocol must be nonempty and bounded when present",
        });
    }
    Ok(())
}

fn validate_node_port(
    service: ServiceId,
    node_port: &ServiceNodePort,
) -> Result<(), ServiceIrError> {
    if node_port.port == 0 || node_port.service_port == 0 {
        return Err(ServiceIrError::InvalidNodePort {
            service,
            node_port: node_port.clone(),
            reason: "NodePort and linked Service port must be nonzero",
        });
    }
    if !is_service_protocol(node_port.protocol) {
        return Err(ServiceIrError::InvalidNodePort {
            service,
            node_port: node_port.clone(),
            reason: "only TCP, UDP, and SCTP NodePorts are supported in intent",
        });
    }
    if !valid_optional_provenance(node_port.name.as_deref())
        || !valid_optional_provenance(node_port.app_protocol.as_deref())
    {
        return Err(ServiceIrError::InvalidNodePort {
            service,
            node_port: node_port.clone(),
            reason: "port name and app protocol must be nonempty and bounded when present",
        });
    }
    Ok(())
}

fn validate_and_normalize_node_ports(
    service: &mut ServiceIr,
    owners: &mut BTreeMap<(u16, Protocol), ServiceId>,
) -> Result<(usize, usize), ServiceIrError> {
    let mut exact_frontends = BTreeSet::new();
    let mut backend_references = 0_usize;
    for node_port in &mut service.node_ports {
        validate_node_port(service.id, node_port)?;
        if !exact_frontends.insert((node_port.family, node_port.port, node_port.protocol)) {
            return Err(ServiceIrError::DuplicateNodePortFrontend {
                service: service.id,
                node_port: node_port.clone(),
            });
        }
        let key = (node_port.port, node_port.protocol);
        if let Some(existing) = owners.insert(key, service.id)
            && existing != service.id
        {
            return Err(ServiceIrError::DuplicateNodePort {
                port: node_port.port,
                protocol: node_port.protocol,
                existing,
                candidate: service.id,
            });
        }
        backend_references = backend_references.saturating_add(node_port.backend_ids.len());
        node_port.backend_ids.sort();
    }
    service.node_ports.sort();
    Ok((service.node_ports.len(), backend_references))
}

fn validate_and_normalize_load_balancer(
    service: &mut ServiceIr,
    cluster_ip_addresses: &BTreeSet<IpAddr>,
    address_owners: &mut BTreeMap<IpAddr, ServiceId>,
) -> Result<(usize, usize), ServiceIrError> {
    let Some(mut load_balancer) = service.load_balancer.take() else {
        return Ok((0, 0));
    };
    validate_load_balancer_ownership(service.id, &mut load_balancer)?;
    validate_load_balancer_requested_ips(
        service.id,
        &mut load_balancer,
        cluster_ip_addresses,
        address_owners,
    )?;
    validate_load_balancer_source_controls(service.id, &mut load_balancer)?;
    let backend_references =
        validate_load_balancer_frontends(service.id, &service.frontends, &mut load_balancer)?;
    let frontend_count = load_balancer.frontends.len();
    service.load_balancer = Some(load_balancer);
    Ok((frontend_count, backend_references))
}

fn invalid_load_balancer(service: ServiceId, reason: &'static str) -> ServiceIrError {
    ServiceIrError::InvalidLoadBalancer { service, reason }
}

fn validate_load_balancer_ownership(
    service: ServiceId,
    load_balancer: &mut ServiceLoadBalancer,
) -> Result<(), ServiceIrError> {
    if load_balancer.class != UNF_LOAD_BALANCER_CLASS {
        return Err(invalid_load_balancer(service, "class is not owned by UNF"));
    }
    if load_balancer.ip_families.is_empty() || load_balancer.ip_families.len() > 2 {
        return Err(invalid_load_balancer(
            service,
            "must request one or two address families",
        ));
    }
    load_balancer.ip_families.sort();
    if load_balancer
        .ip_families
        .windows(2)
        .any(|pair| pair[0] == pair[1])
    {
        return Err(invalid_load_balancer(service, "repeats an address family"));
    }
    match load_balancer.ip_family_policy {
        ServiceIpFamilyPolicy::SingleStack if load_balancer.ip_families.len() != 1 => {
            return Err(invalid_load_balancer(
                service,
                "SingleStack requires exactly one address family",
            ));
        }
        ServiceIpFamilyPolicy::RequireDualStack if load_balancer.ip_families.len() != 2 => {
            return Err(invalid_load_balancer(
                service,
                "RequireDualStack requires both address families",
            ));
        }
        ServiceIpFamilyPolicy::SingleStack
        | ServiceIpFamilyPolicy::PreferDualStack
        | ServiceIpFamilyPolicy::RequireDualStack => {}
    }
    Ok(())
}

fn validate_load_balancer_requested_ips(
    service: ServiceId,
    load_balancer: &mut ServiceLoadBalancer,
    cluster_ip_addresses: &BTreeSet<IpAddr>,
    address_owners: &mut BTreeMap<IpAddr, ServiceId>,
) -> Result<(), ServiceIrError> {
    if load_balancer.requested_ips.len() > load_balancer.ip_families.len() {
        return Err(invalid_load_balancer(
            service,
            "requested IP count exceeds the requested address-family count",
        ));
    }
    load_balancer.requested_ips.sort();
    for pair in load_balancer.requested_ips.windows(2) {
        if pair[0] == pair[1] {
            return Err(invalid_load_balancer(service, "repeats a requested IP"));
        }
    }
    let mut requested_families = BTreeSet::new();
    for address in &load_balancer.requested_ips {
        let family = address_family(*address);
        if !load_balancer.ip_families.contains(&family) {
            return Err(invalid_load_balancer(
                service,
                "requested IP family is not admitted",
            ));
        }
        if !requested_families.insert(family) {
            return Err(invalid_load_balancer(
                service,
                "requests more than one IP in one address family",
            ));
        }
        if !usable_node_port_address(*address) {
            return Err(invalid_load_balancer(
                service,
                "requested IP must be a usable unicast address",
            ));
        }
        if cluster_ip_addresses.contains(address) {
            return Err(ServiceIrError::LoadBalancerClusterIpCollision { address: *address });
        }
        if let Some(existing) = address_owners.insert(*address, service)
            && existing != service
        {
            return Err(ServiceIrError::DuplicateLoadBalancerAddress {
                address: *address,
                existing,
                candidate: service,
            });
        }
    }
    Ok(())
}

fn validate_load_balancer_source_controls(
    service: ServiceId,
    load_balancer: &mut ServiceLoadBalancer,
) -> Result<(), ServiceIrError> {
    if load_balancer.source_ranges.len() > MAX_LOAD_BALANCER_SOURCE_RANGES_PER_SERVICE {
        return Err(invalid_load_balancer(
            service,
            "source-range count exceeds the per-Service bound",
        ));
    }
    load_balancer.source_ranges.sort();
    for pair in load_balancer.source_ranges.windows(2) {
        if pair[0] == pair[1] {
            return Err(invalid_load_balancer(service, "repeats a source range"));
        }
    }
    for prefix in &load_balancer.source_ranges {
        if !prefix.is_canonical() {
            return Err(invalid_load_balancer(
                service,
                "source ranges must be canonical IP prefixes",
            ));
        }
        if !load_balancer.ip_families.contains(&prefix.family()) {
            return Err(invalid_load_balancer(
                service,
                "source-range family is not admitted",
            ));
        }
        if prefix.address.is_multicast() {
            return Err(invalid_load_balancer(
                service,
                "source ranges cannot be multicast",
            ));
        }
    }
    if load_balancer.health_check_node_port == Some(0) {
        return Err(invalid_load_balancer(
            service,
            "health-check NodePort must be nonzero",
        ));
    }
    if load_balancer.health_check_node_port.is_some()
        && load_balancer.traffic_policy != ServiceTrafficPolicy::Local
    {
        return Err(invalid_load_balancer(
            service,
            "health-check NodePort requires Local external traffic policy",
        ));
    }
    Ok(())
}

type LoadBalancerFrontendIdentity = (AddressFamily, u16, Protocol, Option<String>, Option<String>);

fn validate_load_balancer_frontends(
    service: ServiceId,
    cluster_ip_frontends: &[ServiceFrontend],
    load_balancer: &mut ServiceLoadBalancer,
) -> Result<usize, ServiceIrError> {
    let expected_frontends = cluster_ip_frontends
        .iter()
        .filter_map(|frontend| {
            let family = address_family(frontend.address);
            load_balancer.ip_families.contains(&family).then(|| {
                (
                    family,
                    frontend.port,
                    frontend.protocol,
                    frontend.name.clone(),
                    frontend.app_protocol.clone(),
                )
            })
        })
        .collect::<BTreeSet<LoadBalancerFrontendIdentity>>();
    let mut actual_frontends = BTreeSet::<LoadBalancerFrontendIdentity>::new();
    let mut backend_references = 0_usize;
    for frontend in &mut load_balancer.frontends {
        if frontend.service_port == 0 {
            return Err(ServiceIrError::InvalidLoadBalancerFrontend {
                service,
                frontend: frontend.clone(),
                reason: "linked Service port must be nonzero",
            });
        }
        if !matches!(frontend.protocol, Protocol::Tcp | Protocol::Udp) {
            return Err(ServiceIrError::InvalidLoadBalancerFrontend {
                service,
                frontend: frontend.clone(),
                reason: "only TCP and UDP LoadBalancer frontends are admitted",
            });
        }
        if !load_balancer.ip_families.contains(&frontend.family) {
            return Err(ServiceIrError::InvalidLoadBalancerFrontend {
                service,
                frontend: frontend.clone(),
                reason: "address family is not admitted",
            });
        }
        if !valid_optional_provenance(frontend.name.as_deref())
            || !valid_optional_provenance(frontend.app_protocol.as_deref())
        {
            return Err(ServiceIrError::InvalidLoadBalancerFrontend {
                service,
                frontend: frontend.clone(),
                reason: "port name and app protocol must be nonempty and bounded when present",
            });
        }
        let key = (
            frontend.family,
            frontend.service_port,
            frontend.protocol,
            frontend.name.clone(),
            frontend.app_protocol.clone(),
        );
        if !actual_frontends.insert(key) {
            return Err(ServiceIrError::InvalidLoadBalancerFrontend {
                service,
                frontend: frontend.clone(),
                reason: "repeats an exact frontend",
            });
        }
        frontend.backend_ids.sort();
        let linked = cluster_ip_frontends.iter().find(|candidate| {
            address_family(candidate.address) == frontend.family
                && candidate.port == frontend.service_port
                && candidate.protocol == frontend.protocol
                && candidate.name == frontend.name
                && candidate.app_protocol == frontend.app_protocol
        });
        let Some(linked) = linked else {
            return Err(ServiceIrError::InvalidLoadBalancerFrontend {
                service,
                frontend: frontend.clone(),
                reason: "does not link to an exact same-family ClusterIP frontend",
            });
        };
        if frontend.backend_ids != linked.backend_ids {
            return Err(ServiceIrError::InvalidLoadBalancerFrontend {
                service,
                frontend: frontend.clone(),
                reason: "backend linkage differs from the exact ClusterIP frontend",
            });
        }
        backend_references = backend_references.saturating_add(frontend.backend_ids.len());
    }
    if actual_frontends != expected_frontends {
        return Err(invalid_load_balancer(
            service,
            "frontends do not exactly cover every admitted family and Service port",
        ));
    }
    load_balancer.frontends.sort();
    Ok(backend_references)
}

const fn address_family(address: IpAddr) -> AddressFamily {
    match address {
        IpAddr::V4(_) => AddressFamily::Ipv4,
        IpAddr::V6(_) => AddressFamily::Ipv6,
    }
}

fn validate_backends(service: &ServiceIr) -> Result<(), ServiceIrError> {
    let mut ids = BTreeSet::new();
    let mut endpoints = BTreeSet::new();
    for backend in &service.backends {
        if backend.id.get() == 0 {
            return Err(ServiceIrError::ZeroBackendId {
                service: service.id,
            });
        }
        if !ids.insert(backend.id) {
            return Err(ServiceIrError::DuplicateBackendId {
                service: service.id,
                backend: backend.id,
            });
        }
        if !endpoints.insert((backend.address, backend.port, backend.protocol)) {
            return Err(ServiceIrError::DuplicateBackendEndpoint {
                service: service.id,
                address: backend.address,
                port: backend.port,
                protocol: backend.protocol,
            });
        }
        if backend.address.is_unspecified() || backend.address.is_multicast() {
            return Err(ServiceIrError::InvalidBackend {
                service: service.id,
                backend: backend.id,
                reason: "address must be unicast and specified",
            });
        }
        if backend.port == 0 {
            return Err(ServiceIrError::InvalidBackend {
                service: service.id,
                backend: backend.id,
                reason: "port must be nonzero",
            });
        }
        if !is_service_protocol(backend.protocol) {
            return Err(ServiceIrError::InvalidBackend {
                service: service.id,
                backend: backend.id,
                reason: "only TCP, UDP, and SCTP backends are supported",
            });
        }
        if backend.endpoint_slices.is_empty()
            || backend.endpoint_slices.len() > MAX_ENDPOINT_SLICE_PROVENANCE
            || backend.endpoint_slices.iter().any(|value| {
                value.is_empty() || value.len() > MAX_PROVENANCE_COMPONENT_BYTES * 2 + 1
            })
        {
            return Err(ServiceIrError::InvalidBackend {
                service: service.id,
                backend: backend.id,
                reason: "EndpointSlice provenance must be present and bounded",
            });
        }
        if !valid_optional_provenance(backend.port_name.as_deref())
            || !valid_optional_provenance(backend.app_protocol.as_deref())
            || !valid_optional_reference(backend.target_workload.as_deref())
            || !valid_optional_provenance(backend.node_name.as_deref())
            || !valid_optional_provenance(backend.zone.as_deref())
        {
            return Err(ServiceIrError::InvalidBackend {
                service: service.id,
                backend: backend.id,
                reason: "optional backend provenance must be nonempty and bounded when present",
            });
        }
    }
    Ok(())
}

fn validate_frontend_backends(service: &ServiceIr) -> Result<(), ServiceIrError> {
    let backends: BTreeMap<BackendId, &ServiceBackend> = service
        .backends
        .iter()
        .map(|backend| (backend.id, backend))
        .collect();
    for frontend in &service.frontends {
        let mut references = BTreeSet::new();
        for backend_id in &frontend.backend_ids {
            if !references.insert(*backend_id) {
                return Err(ServiceIrError::DuplicateFrontendBackend {
                    frontend: frontend.clone(),
                    backend: *backend_id,
                });
            }
            let Some(backend) = backends.get(backend_id) else {
                return Err(ServiceIrError::UnknownFrontendBackend {
                    frontend: frontend.clone(),
                    backend: *backend_id,
                });
            };
            if frontend.address.is_ipv4() != backend.address.is_ipv4() {
                return Err(ServiceIrError::BackendFamilyMismatch {
                    frontend: frontend.clone(),
                    backend: *backend_id,
                });
            }
            if frontend.protocol != backend.protocol {
                return Err(ServiceIrError::InvalidBackend {
                    service: service.id,
                    backend: *backend_id,
                    reason: "frontend and backend protocols differ",
                });
            }
        }
    }
    Ok(())
}

fn validate_node_port_backends(service: &ServiceIr) -> Result<(), ServiceIrError> {
    let backends: BTreeMap<BackendId, &ServiceBackend> = service
        .backends
        .iter()
        .map(|backend| (backend.id, backend))
        .collect();
    for node_port in &service.node_ports {
        let linked_frontend = service.frontends.iter().any(|frontend| {
            let family_matches = match node_port.family {
                AddressFamily::Ipv4 => frontend.address.is_ipv4(),
                AddressFamily::Ipv6 => frontend.address.is_ipv6(),
            };
            family_matches
                && frontend.port == node_port.service_port
                && frontend.protocol == node_port.protocol
                && frontend.name == node_port.name
                && frontend.app_protocol == node_port.app_protocol
        });
        if !linked_frontend {
            return Err(ServiceIrError::InvalidNodePort {
                service: service.id,
                node_port: node_port.clone(),
                reason: "does not link to an exact same-family ClusterIP frontend",
            });
        }
        let mut references = BTreeSet::new();
        for backend_id in &node_port.backend_ids {
            if !references.insert(*backend_id) {
                return Err(ServiceIrError::InvalidNodePort {
                    service: service.id,
                    node_port: node_port.clone(),
                    reason: "repeats a backend reference",
                });
            }
            let Some(backend) = backends.get(backend_id) else {
                return Err(ServiceIrError::InvalidNodePort {
                    service: service.id,
                    node_port: node_port.clone(),
                    reason: "references an unknown backend",
                });
            };
            let family_matches = match node_port.family {
                AddressFamily::Ipv4 => backend.address.is_ipv4(),
                AddressFamily::Ipv6 => backend.address.is_ipv6(),
            };
            if !family_matches || node_port.protocol != backend.protocol {
                return Err(ServiceIrError::InvalidNodePort {
                    service: service.id,
                    node_port: node_port.clone(),
                    reason: "backend family or protocol differs from the NodePort frontend",
                });
            }
        }
    }
    Ok(())
}

fn valid_optional_provenance(value: Option<&str>) -> bool {
    value.is_none_or(|value| !value.is_empty() && value.len() <= MAX_PROVENANCE_COMPONENT_BYTES)
}

fn valid_optional_reference(value: Option<&str>) -> bool {
    value.is_none_or(|value| {
        !value.is_empty() && value.len() <= MAX_PROVENANCE_COMPONENT_BYTES * 2 + 1
    })
}

const fn is_service_protocol(protocol: Protocol) -> bool {
    matches!(protocol, Protocol::Tcp | Protocol::Udp | Protocol::Sctp)
}

/// Lowers one validated service snapshot into the exact bytes for an inactive
/// logical BPF bank. This function has no map side effects.
///
/// # Errors
///
/// Rejects invalid IR, a bank outside the two-bank ABI, or any per-map capacity
/// violation before a kernel map can be mutated.
#[allow(clippy::too_many_lines)]
pub fn compile_service_dataplane(
    snapshot: &ServiceSnapshot,
    bank: u8,
) -> Result<ServiceDataplaneState, ServiceDataplaneError> {
    if bank >= SERVICE_BANK_COUNT {
        return Err(ServiceDataplaneError::InvalidBank(bank));
    }
    let snapshot = snapshot.clone().validate_and_normalize()?;
    if has_advanced_selection_intent(&snapshot) {
        return Err(ServiceDataplaneError::UnsupportedAdvancedSelection);
    }
    let node_port_count = snapshot
        .services
        .iter()
        .map(|service| service.node_ports.len())
        .sum();
    if node_port_count != 0 {
        return Err(ServiceDataplaneError::UnsupportedNodePort {
            actual: node_port_count,
        });
    }
    let load_balancer_count = snapshot
        .services
        .iter()
        .filter_map(|service| service.load_balancer.as_ref())
        .map(|load_balancer| load_balancer.frontends.len())
        .sum();
    if load_balancer_count != 0 {
        return Err(ServiceDataplaneError::UnsupportedLoadBalancer {
            actual: load_balancer_count,
        });
    }
    let mut ipv4_frontends = BTreeMap::new();
    let mut ipv6_frontends = BTreeMap::new();
    let mut ipv4_backends = BTreeMap::new();
    let mut ipv6_backends = BTreeMap::new();
    let mut backend_slots = BTreeMap::new();

    for service in &snapshot.services {
        let eligible_backends = service
            .backends
            .iter()
            .filter(|backend| backend.ready && !backend.terminating)
            .map(|backend| backend.id)
            .collect::<BTreeSet<_>>();
        for backend in &service.backends {
            let key = encode_service_backend_key(service.id, backend.id, bank);
            let flags = encode_backend_flags(backend);
            match backend.address {
                IpAddr::V4(address) => {
                    ipv4_backends.insert(
                        key,
                        encode_ipv4_service_backend(
                            address.octets(),
                            backend.port,
                            backend.protocol,
                            flags,
                            snapshot.revision.get(),
                        ),
                    );
                }
                IpAddr::V6(address) => {
                    ipv6_backends.insert(
                        key,
                        encode_ipv6_service_backend(
                            address.octets(),
                            backend.port,
                            backend.protocol,
                            flags,
                            snapshot.revision.get(),
                        ),
                    );
                }
            }
        }
        for (frontend_index, frontend) in service.frontends.iter().enumerate() {
            let frontend_index = bounded_u32(frontend_index);
            let eligible_frontend_backends = frontend
                .backend_ids
                .iter()
                .filter(|backend_id| eligible_backends.contains(backend_id))
                .copied()
                .collect::<Vec<_>>();
            let value = encode_service_frontend_value(
                service.id,
                frontend_index,
                eligible_frontend_backends.len(),
                snapshot.revision.get(),
            );
            match frontend.address {
                IpAddr::V4(address) => {
                    ipv4_frontends.insert(
                        encode_ipv4_service_frontend_key(
                            address.octets(),
                            frontend.port,
                            frontend.protocol,
                            bank,
                        ),
                        value,
                    );
                }
                IpAddr::V6(address) => {
                    ipv6_frontends.insert(
                        encode_ipv6_service_frontend_key(
                            address.octets(),
                            frontend.port,
                            frontend.protocol,
                            bank,
                        ),
                        value,
                    );
                }
            }
            for (slot, backend_id) in eligible_frontend_backends.iter().enumerate() {
                let slot = bounded_u32(slot);
                backend_slots.insert(
                    encode_service_backend_slot_key(service.id, frontend_index, slot, bank),
                    encode_service_backend_slot_value(*backend_id, snapshot.revision.get()),
                );
            }
        }
    }

    validate_dataplane_capacity(
        "SERVICE_FRONTENDS_V4",
        ipv4_frontends.len(),
        SERVICE_FRONTEND_BANK_CAPACITY,
    )?;
    validate_dataplane_capacity(
        "SERVICE_FRONTENDS_V6",
        ipv6_frontends.len(),
        SERVICE_FRONTEND_BANK_CAPACITY,
    )?;
    validate_dataplane_capacity(
        "SERVICE_BACKENDS_V4",
        ipv4_backends.len(),
        SERVICE_BACKEND_BANK_CAPACITY,
    )?;
    validate_dataplane_capacity(
        "SERVICE_BACKENDS_V6",
        ipv6_backends.len(),
        SERVICE_BACKEND_BANK_CAPACITY,
    )?;
    validate_dataplane_capacity(
        "SERVICE_BACKEND_SLOTS",
        backend_slots.len(),
        SERVICE_BACKEND_SLOT_BANK_CAPACITY,
    )?;
    let frontend_count = ipv4_frontends.len() + ipv6_frontends.len();
    let backend_count = ipv4_backends.len() + ipv6_backends.len();
    let config = encode_service_config(
        snapshot.source_epoch,
        snapshot.revision.get(),
        frontend_count,
        backend_count,
        backend_slots.len(),
        bank,
    );
    Ok(ServiceDataplaneState {
        source_epoch: snapshot.source_epoch,
        revision: snapshot.revision.get(),
        bank,
        ipv4_frontends,
        ipv6_frontends,
        ipv4_backends,
        ipv6_backends,
        backend_slots,
        config,
    })
}

/// Lowers `ClusterIP` state plus deterministic per-Node slots needed by Local
/// `LoadBalancer` frontends into one transactional service bank.
///
/// # Errors
///
/// Rejects invalid intent, slot-index/capacity overflow, or any collision with
/// the ordinary `ClusterIP` slot namespace.
pub fn compile_service_load_balancer_fabric_dataplane(
    snapshot: &ServiceSnapshot,
    bank: u8,
) -> Result<ServiceDataplaneState, ServiceDataplaneError> {
    let snapshot = snapshot.clone().validate_and_normalize()?;
    if has_advanced_selection_intent(&snapshot) {
        return Err(ServiceDataplaneError::UnsupportedAdvancedSelection);
    }
    let mut cluster_ip = snapshot.clone();
    for service in &mut cluster_ip.services {
        service.node_ports.clear();
        service.load_balancer = None;
    }
    let mut service = compile_service_dataplane(&cluster_ip, bank)?;
    merge_load_balancer_local_slots(&snapshot, &mut service)?;
    Ok(service)
}

fn merge_load_balancer_local_slots(
    snapshot: &ServiceSnapshot,
    state: &mut ServiceDataplaneState,
) -> Result<(), ServiceDataplaneError> {
    for service in &snapshot.services {
        let Some(load_balancer) = service
            .load_balancer
            .as_ref()
            .filter(|load_balancer| load_balancer.traffic_policy == ServiceTrafficPolicy::Local)
        else {
            continue;
        };
        let node_names = service
            .backends
            .iter()
            .filter_map(|backend| backend.node_name.as_deref())
            .collect::<BTreeSet<_>>();
        for frontend in &load_balancer.frontends {
            let frontend_index = service
                .frontends
                .iter()
                .position(|candidate| {
                    address_family(candidate.address) == frontend.family
                        && candidate.port == frontend.service_port
                        && candidate.protocol == frontend.protocol
                        && candidate.name == frontend.name
                        && candidate.app_protocol == frontend.app_protocol
                        && candidate.backend_ids == frontend.backend_ids
                })
                .expect("validated LoadBalancer frontend has one ClusterIP link");
            for node_name in &node_names {
                let local_index =
                    load_balancer_local_frontend_index(service, frontend_index, node_name)
                        .ok_or_else(|| ServiceDataplaneError::LocalLoadBalancerIndex {
                            service: service.id,
                            node: (*node_name).to_owned(),
                        })?;
                let eligible = frontend.backend_ids.iter().filter(|backend_id| {
                    service.backends.iter().any(|backend| {
                        backend.id == **backend_id
                            && backend.ready
                            && !backend.terminating
                            && backend.node_name.as_deref() == Some(*node_name)
                    })
                });
                for (slot, backend_id) in eligible.enumerate() {
                    let key = encode_service_backend_slot_key(
                        service.id,
                        local_index,
                        bounded_u32(slot),
                        state.bank,
                    );
                    if state
                        .backend_slots
                        .insert(
                            key,
                            encode_service_backend_slot_value(*backend_id, snapshot.revision.get()),
                        )
                        .is_some()
                    {
                        return Err(ServiceDataplaneError::LocalLoadBalancerSlotCollision);
                    }
                }
            }
        }
    }
    validate_dataplane_capacity(
        "SERVICE_BACKEND_SLOTS",
        state.backend_slots.len(),
        SERVICE_BACKEND_SLOT_BANK_CAPACITY,
    )?;
    state.config = encode_service_config(
        state.source_epoch,
        state.revision,
        state.ipv4_frontends.len() + state.ipv6_frontends.len(),
        state.ipv4_backends.len() + state.ipv6_backends.len(),
        state.backend_slots.len(),
        state.bank,
    );
    Ok(())
}

/// Lowers validated `NodePort` intent for one authenticated local Node. The
/// resulting values reference an already staged `ClusterIP` service bank.
///
/// # Errors
///
/// Rejects invalid snapshots, epoch skew, invalid banks, missing exact
/// frontend linkage, and per-family map capacity overflow.
pub fn compile_node_port_dataplane(
    snapshot: &ServiceSnapshot,
    node: &NodePortNodeSnapshot,
    service_bank: u8,
    bank: u8,
) -> Result<NodePortDataplaneState, NodePortDataplaneError> {
    if service_bank >= SERVICE_BANK_COUNT {
        return Err(NodePortDataplaneError::InvalidServiceBank(service_bank));
    }
    if bank >= NODE_PORT_BANK_COUNT {
        return Err(NodePortDataplaneError::InvalidNodePortBank(bank));
    }
    let snapshot = snapshot.clone().validate_and_normalize()?;
    if has_advanced_selection_intent(&snapshot) {
        return Err(NodePortDataplaneError::UnsupportedAdvancedSelection);
    }
    let node = node.clone().validate_and_normalize()?;
    if snapshot.source_epoch != node.source_epoch {
        return Err(NodePortDataplaneError::SourceEpochMismatch);
    }
    preflight_node_port_capacity(&snapshot, &node)?;
    let frontends = compile_node_port_frontends(&snapshot, &node, service_bank, bank)?;
    validate_node_port_capacity("NODE_PORT_FRONTENDS_V4", frontends.ipv4.len())?;
    validate_node_port_capacity("NODE_PORT_FRONTENDS_V6", frontends.ipv6.len())?;
    let config = encode_node_port_config(
        snapshot.source_epoch,
        snapshot.revision.get(),
        node.revision.get(),
        frontends.ipv4.len(),
        frontends.ipv6.len(),
        bank,
    );
    Ok(NodePortDataplaneState {
        source_epoch: snapshot.source_epoch,
        service_revision: snapshot.revision.get(),
        node_revision: node.revision.get(),
        service_bank,
        bank,
        ipv4_frontends: frontends.ipv4,
        ipv6_frontends: frontends.ipv6,
        service_backend_slots: frontends.service_backend_slots,
        config,
    })
}

/// Explicitly lowers one complete service snapshot into coherent `ClusterIP`
/// and local `NodePort` staging banks.
///
/// # Errors
///
/// Rejects either side of the complete service/Node contract before returning
/// any state suitable for map mutation.
pub fn compile_node_port_fabric_dataplane(
    snapshot: &ServiceSnapshot,
    node: &NodePortNodeSnapshot,
    service_bank: u8,
    node_port_bank: u8,
) -> Result<NodePortFabricDataplaneState, NodePortFabricDataplaneError> {
    let node_port = compile_node_port_dataplane(snapshot, node, service_bank, node_port_bank)?;
    let mut cluster_ip = snapshot
        .clone()
        .validate_and_normalize()
        .map_err(ServiceDataplaneError::from)?;
    for service in &mut cluster_ip.services {
        service.node_ports.clear();
        service.load_balancer = None;
    }
    let mut service = compile_service_dataplane(&cluster_ip, service_bank)?;
    for (key, value) in &node_port.service_backend_slots {
        if service.backend_slots.insert(*key, *value).is_some() {
            return Err(NodePortFabricDataplaneError::LocalSlotCollision);
        }
    }
    merge_load_balancer_local_slots(snapshot, &mut service)?;
    validate_dataplane_capacity(
        "SERVICE_BACKEND_SLOTS",
        service.backend_slots.len(),
        SERVICE_BACKEND_SLOT_BANK_CAPACITY,
    )?;
    service.config = encode_service_config(
        service.source_epoch,
        service.revision,
        service.ipv4_frontends.len() + service.ipv6_frontends.len(),
        service.ipv4_backends.len() + service.ipv6_backends.len(),
        service.backend_slots.len(),
        service.bank,
    );
    Ok(NodePortFabricDataplaneState { service, node_port })
}

fn preflight_node_port_capacity(
    snapshot: &ServiceSnapshot,
    node: &NodePortNodeSnapshot,
) -> Result<(), NodePortDataplaneError> {
    let ipv4_address_count = node
        .addresses
        .iter()
        .filter(|address| address.address.is_ipv4())
        .count();
    let ipv6_address_count = node.addresses.len() - ipv4_address_count;
    let ipv4_node_port_count = snapshot
        .services
        .iter()
        .flat_map(|service| &service.node_ports)
        .filter(|node_port| node_port.family == AddressFamily::Ipv4)
        .count();
    let ipv6_node_port_count = snapshot
        .services
        .iter()
        .flat_map(|service| &service.node_ports)
        .filter(|node_port| node_port.family == AddressFamily::Ipv6)
        .count();
    preflight_node_port_family_capacity(
        "NODE_PORT_FRONTENDS_V4",
        ipv4_address_count,
        ipv4_node_port_count,
    )?;
    preflight_node_port_family_capacity(
        "NODE_PORT_FRONTENDS_V6",
        ipv6_address_count,
        ipv6_node_port_count,
    )
}

fn preflight_node_port_family_capacity(
    map: &'static str,
    address_count: usize,
    node_port_count: usize,
) -> Result<(), NodePortDataplaneError> {
    let actual = address_count.saturating_mul(node_port_count);
    validate_node_port_capacity(map, actual)
}

fn compile_node_port_frontends(
    snapshot: &ServiceSnapshot,
    node: &NodePortNodeSnapshot,
    service_bank: u8,
    bank: u8,
) -> Result<CompiledNodePortFrontends, NodePortDataplaneError> {
    let mut ipv4_frontends = BTreeMap::new();
    let mut ipv6_frontends = BTreeMap::new();
    let mut service_backend_slots = BTreeMap::new();
    for service in &snapshot.services {
        for (node_port_index, node_port) in service.node_ports.iter().enumerate() {
            if !matches!(node_port.protocol, Protocol::Tcp | Protocol::Udp) {
                return Err(NodePortDataplaneError::UnsupportedProtocol(
                    node_port.protocol,
                ));
            }
            let frontend_index = service
                .frontends
                .iter()
                .position(|frontend| {
                    frontend.address.is_ipv4() == matches!(node_port.family, AddressFamily::Ipv4)
                        && frontend.port == node_port.service_port
                        && frontend.protocol == node_port.protocol
                        && frontend.name == node_port.name
                        && frontend.app_protocol == node_port.app_protocol
                })
                .ok_or(NodePortDataplaneError::MissingFrontendLink {
                    service_id: service.id,
                    node_port: node_port.port,
                })?;
            let eligible_backend_ids = eligible_node_port_backend_ids(service, node_port, node);
            let (frontend_index, flags) = match node_port.traffic_policy {
                ServiceTrafficPolicy::Cluster => (bounded_u32(frontend_index), 0),
                ServiceTrafficPolicy::Local => {
                    let local_frontend_index =
                        NODE_PORT_LOCAL_FRONTEND_INDEX_FLAG + bounded_u32(node_port_index);
                    for (slot, backend_id) in eligible_backend_ids.iter().enumerate() {
                        service_backend_slots.insert(
                            encode_service_backend_slot_key(
                                service.id,
                                local_frontend_index,
                                bounded_u32(slot),
                                service_bank,
                            ),
                            encode_service_backend_slot_value(*backend_id, snapshot.revision.get()),
                        );
                    }
                    (local_frontend_index, NODE_PORT_FRONTEND_FLAG_LOCAL)
                }
            };
            let value = encode_node_port_frontend_value(
                service.id,
                frontend_index,
                eligible_backend_ids.len(),
                flags,
                snapshot.revision.get(),
                service_bank,
            );
            for address in node.addresses.iter().filter(|address| {
                address.address.is_ipv4() == matches!(node_port.family, AddressFamily::Ipv4)
            }) {
                match address.address {
                    IpAddr::V4(address) => {
                        ipv4_frontends.insert(
                            encode_ipv4_service_frontend_key(
                                address.octets(),
                                node_port.port,
                                node_port.protocol,
                                bank,
                            ),
                            value,
                        );
                    }
                    IpAddr::V6(address) => {
                        ipv6_frontends.insert(
                            encode_ipv6_service_frontend_key(
                                address.octets(),
                                node_port.port,
                                node_port.protocol,
                                bank,
                            ),
                            value,
                        );
                    }
                }
            }
        }
    }
    Ok(CompiledNodePortFrontends {
        ipv4: ipv4_frontends,
        ipv6: ipv6_frontends,
        service_backend_slots,
    })
}

fn eligible_node_port_backend_ids(
    service: &ServiceIr,
    node_port: &ServiceNodePort,
    node: &NodePortNodeSnapshot,
) -> Vec<BackendId> {
    node_port
        .backend_ids
        .iter()
        .filter(|backend_id| {
            service.backends.iter().any(|backend| {
                backend.id == **backend_id
                    && backend.ready
                    && !backend.terminating
                    && (node_port.traffic_policy == ServiceTrafficPolicy::Cluster
                        || backend.node_name.as_deref() == Some(node.node_name.as_str()))
            })
        })
        .copied()
        .collect()
}

fn validate_node_port_capacity(
    map: &'static str,
    actual: usize,
) -> Result<(), NodePortDataplaneError> {
    if actual > SERVICE_FRONTEND_BANK_CAPACITY {
        return Err(NodePortDataplaneError::Capacity {
            map,
            actual,
            limit: SERVICE_FRONTEND_BANK_CAPACITY,
        });
    }
    Ok(())
}

fn validate_dataplane_capacity(
    map: &'static str,
    actual: usize,
    limit: usize,
) -> Result<(), ServiceDataplaneError> {
    if actual > limit {
        return Err(ServiceDataplaneError::Capacity { map, actual, limit });
    }
    Ok(())
}

fn encode_ipv4_service_frontend_key(
    address: [u8; 4],
    port: u16,
    protocol: Protocol,
    bank: u8,
) -> [u8; 8] {
    let mut key = [0_u8; 8];
    key[0..4].copy_from_slice(&address);
    key[4..6].copy_from_slice(&port.to_be_bytes());
    key[6] = protocol as u8;
    key[7] = bank;
    key
}

fn encode_ipv6_service_frontend_key(
    address: [u8; 16],
    port: u16,
    protocol: Protocol,
    bank: u8,
) -> [u8; 20] {
    let mut key = [0_u8; 20];
    key[0..16].copy_from_slice(&address);
    key[16..18].copy_from_slice(&port.to_be_bytes());
    key[18] = protocol as u8;
    key[19] = bank;
    key
}

fn encode_service_frontend_value(
    service_id: ServiceId,
    frontend_index: u32,
    backend_count: usize,
    revision: u64,
) -> [u8; 32] {
    let mut value = [0_u8; 32];
    value[0..4].copy_from_slice(&service_id.get().to_ne_bytes());
    value[4..8].copy_from_slice(&frontend_index.to_ne_bytes());
    value[8..12].copy_from_slice(&bounded_u32(backend_count).to_ne_bytes());
    value[12..14].copy_from_slice(&SERVICE_MAP_ABI_VERSION.to_ne_bytes());
    value[16..24].copy_from_slice(&revision.to_ne_bytes());
    value
}

fn encode_node_port_frontend_value(
    service_id: ServiceId,
    frontend_index: u32,
    backend_count: usize,
    flags: u16,
    service_revision: u64,
    service_bank: u8,
) -> [u8; 32] {
    let mut value = [0_u8; 32];
    value[0..4].copy_from_slice(&service_id.get().to_ne_bytes());
    value[4..8].copy_from_slice(&frontend_index.to_ne_bytes());
    value[8..12].copy_from_slice(&bounded_u32(backend_count).to_ne_bytes());
    value[12..14].copy_from_slice(&NODE_PORT_MAP_ABI_VERSION.to_ne_bytes());
    value[14..16].copy_from_slice(&flags.to_ne_bytes());
    value[16..24].copy_from_slice(&service_revision.to_ne_bytes());
    value[24] = service_bank;
    value
}

fn encode_service_backend_key(service_id: ServiceId, backend_id: BackendId, bank: u8) -> [u8; 12] {
    let mut key = [0_u8; 12];
    key[0..4].copy_from_slice(&service_id.get().to_ne_bytes());
    key[4..8].copy_from_slice(&backend_id.get().to_ne_bytes());
    key[8] = bank;
    key
}

fn encode_ipv4_service_backend(
    address: [u8; 4],
    port: u16,
    protocol: Protocol,
    flags: u8,
    revision: u64,
) -> [u8; 24] {
    let mut value = [0_u8; 24];
    value[0..8].copy_from_slice(&revision.to_ne_bytes());
    value[8..12].copy_from_slice(&address);
    value[12..14].copy_from_slice(&port.to_be_bytes());
    value[14..16].copy_from_slice(&SERVICE_MAP_ABI_VERSION.to_ne_bytes());
    value[16] = protocol as u8;
    value[17] = flags;
    value
}

fn encode_ipv6_service_backend(
    address: [u8; 16],
    port: u16,
    protocol: Protocol,
    flags: u8,
    revision: u64,
) -> [u8; 32] {
    let mut value = [0_u8; 32];
    value[0..8].copy_from_slice(&revision.to_ne_bytes());
    value[8..24].copy_from_slice(&address);
    value[24..26].copy_from_slice(&port.to_be_bytes());
    value[26..28].copy_from_slice(&SERVICE_MAP_ABI_VERSION.to_ne_bytes());
    value[28] = protocol as u8;
    value[29] = flags;
    value
}

fn encode_backend_flags(backend: &ServiceBackend) -> u8 {
    (u8::from(backend.ready) * SERVICE_BACKEND_FLAG_READY)
        | (u8::from(backend.serving) * SERVICE_BACKEND_FLAG_SERVING)
        | (u8::from(backend.terminating) * SERVICE_BACKEND_FLAG_TERMINATING)
}

fn encode_service_backend_slot_key(
    service_id: ServiceId,
    frontend_index: u32,
    slot: u32,
    bank: u8,
) -> [u8; 16] {
    let mut key = [0_u8; 16];
    key[0..4].copy_from_slice(&service_id.get().to_ne_bytes());
    key[4..8].copy_from_slice(&frontend_index.to_ne_bytes());
    key[8..12].copy_from_slice(&slot.to_ne_bytes());
    key[12] = bank;
    key
}

fn encode_service_backend_slot_value(backend_id: BackendId, revision: u64) -> [u8; 16] {
    let mut value = [0_u8; 16];
    value[0..4].copy_from_slice(&backend_id.get().to_ne_bytes());
    value[4..6].copy_from_slice(&SERVICE_MAP_ABI_VERSION.to_ne_bytes());
    value[8..16].copy_from_slice(&revision.to_ne_bytes());
    value
}

fn encode_service_config(
    source_epoch: u64,
    revision: u64,
    frontend_count: usize,
    backend_count: usize,
    backend_slot_count: usize,
    bank: u8,
) -> [u8; 32] {
    let mut config = [0_u8; 32];
    config[0..8].copy_from_slice(&source_epoch.to_ne_bytes());
    config[8..16].copy_from_slice(&revision.to_ne_bytes());
    config[16..20].copy_from_slice(&bounded_u32(frontend_count).to_ne_bytes());
    config[20..24].copy_from_slice(&bounded_u32(backend_count).to_ne_bytes());
    config[24..28].copy_from_slice(&bounded_u32(backend_slot_count).to_ne_bytes());
    config[28..30].copy_from_slice(&SERVICE_MAP_ABI_VERSION.to_ne_bytes());
    config[30] = bank;
    config
}

fn encode_node_port_config(
    source_epoch: u64,
    service_revision: u64,
    node_revision: u64,
    ipv4_count: usize,
    ipv6_count: usize,
    bank: u8,
) -> [u8; 40] {
    let mut config = [0_u8; 40];
    config[0..8].copy_from_slice(&source_epoch.to_ne_bytes());
    config[8..16].copy_from_slice(&service_revision.to_ne_bytes());
    config[16..24].copy_from_slice(&node_revision.to_ne_bytes());
    config[24..28].copy_from_slice(&bounded_u32(ipv4_count).to_ne_bytes());
    config[28..32].copy_from_slice(&bounded_u32(ipv6_count).to_ne_bytes());
    config[32..34].copy_from_slice(&NODE_PORT_MAP_ABI_VERSION.to_ne_bytes());
    config[34] = bank;
    config
}

fn bounded_u32(value: usize) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frontend(address: &str, protocol: Protocol, port: u16) -> ServiceFrontend {
        ServiceFrontend {
            address: address.parse().expect("valid test address"),
            port,
            protocol,
            name: Some("https".to_owned()),
            app_protocol: Some("kubernetes.io/h2c".to_owned()),
            backend_ids: Vec::new(),
        }
    }

    fn backend(id: u32, address: &str, port: u16) -> ServiceBackend {
        ServiceBackend {
            id: BackendId::new(id),
            address: address.parse().expect("valid test address"),
            port,
            protocol: Protocol::Tcp,
            port_name: Some("https".to_owned()),
            app_protocol: Some("kubernetes.io/h2c".to_owned()),
            endpoint_slices: vec![format!("default/example-{id}")],
            target_workload: Some(format!("default/pod-{id}")),
            node_name: Some(format!("worker-{id}")),
            zone: Some("zone-a".to_owned()),
            ready: true,
            serving: true,
            terminating: false,
        }
    }

    fn service(id: u32, name: &str) -> ServiceIr {
        ServiceIr {
            id: ServiceId::new(id),
            namespace: "default".to_owned(),
            name: name.to_owned(),
            internal_traffic_policy: ServiceTrafficPolicy::Cluster,
            session_affinity: ServiceSessionAffinity::None,
            traffic_distribution: ServiceTrafficDistribution::Any,
            selection_algorithm: ServiceSelectionAlgorithm::StableHash,
            forwarding_mode: ServiceForwardingMode::Nat,
            frontends: vec![ServiceFrontend {
                backend_ids: vec![BackendId::new(id)],
                ..frontend(
                    if id == 1 { "fd02::10" } else { "10.96.0.10" },
                    Protocol::Tcp,
                    443,
                )
            }],
            node_ports: Vec::new(),
            load_balancer: None,
            backends: vec![backend(
                id,
                if id == 1 { "fd01::10" } else { "10.244.0.10" },
                8443,
            )],
        }
    }

    fn snapshot(services: Vec<ServiceIr>) -> ServiceSnapshot {
        ServiceSnapshot {
            schema_version: SERVICE_SNAPSHOT_SCHEMA_VERSION,
            source_epoch: 7,
            revision: Revision::new(11),
            services,
        }
    }

    #[test]
    fn normalization_is_deterministic_and_retains_endpoint_state() {
        let mut first = service(1, "ipv6");
        first.frontends.push(ServiceFrontend {
            backend_ids: vec![BackendId::new(3)],
            ..frontend("fd02::11", Protocol::Udp, 53)
        });
        first.backends.push(ServiceBackend {
            protocol: Protocol::Udp,
            ready: false,
            serving: true,
            terminating: true,
            ..backend(3, "fd01::11", 8053)
        });
        first.frontends.reverse();
        first.backends.reverse();

        let left = snapshot(vec![service(2, "ipv4"), first.clone()])
            .validate_and_normalize()
            .expect("valid service state");
        first.frontends.sort();
        first.backends.sort();
        let right = snapshot(vec![first, service(2, "ipv4")])
            .validate_and_normalize()
            .expect("valid service state");

        assert_eq!(left, right);
        assert!(!left.services[0].backends[1].ready);
        assert!(left.services[0].backends[1].terminating);
    }

    #[test]
    fn service_dataplane_encoding_is_fixed_width_network_order_and_banked() {
        let state = compile_service_dataplane(&snapshot(vec![service(2, "ipv4")]), 1)
            .expect("valid service dataplane state");
        assert_eq!(state.source_epoch, 7);
        assert_eq!(state.revision, 11);
        assert_eq!(state.bank, 1);
        assert_eq!(state.ipv4_frontends.len(), 1);
        assert_eq!(state.ipv4_backends.len(), 1);
        assert_eq!(state.backend_slots.len(), 1);
        let (frontend_key, frontend_value) = state.ipv4_frontends.first_key_value().unwrap();
        assert_eq!(&frontend_key[0..4], &[10, 96, 0, 10]);
        assert_eq!(&frontend_key[4..6], &443_u16.to_be_bytes());
        assert_eq!(frontend_key[6], Protocol::Tcp as u8);
        assert_eq!(frontend_key[7], 1);
        assert_eq!(
            u32::from_ne_bytes(frontend_value[0..4].try_into().unwrap()),
            2
        );
        assert_eq!(
            u32::from_ne_bytes(frontend_value[8..12].try_into().unwrap()),
            1
        );
        assert_eq!(
            u64::from_ne_bytes(frontend_value[16..24].try_into().unwrap()),
            11
        );
        let (backend_key, backend_value) = state.ipv4_backends.first_key_value().unwrap();
        assert_eq!(backend_key[8], 1);
        assert_eq!(&backend_value[8..12], &[10, 244, 0, 10]);
        assert_eq!(&backend_value[12..14], &8443_u16.to_be_bytes());
        assert_eq!(
            backend_value[17],
            SERVICE_BACKEND_FLAG_READY | SERVICE_BACKEND_FLAG_SERVING
        );
        let slot_key = state.backend_slots.first_key_value().unwrap().0;
        assert_eq!(slot_key[12], 1);
        assert_eq!(state.config[30], 1);
    }

    #[test]
    fn service_dataplane_rejects_unknown_bank_before_encoding() {
        assert_eq!(
            compile_service_dataplane(&snapshot(vec![service(1, "ipv6")]), 2),
            Err(ServiceDataplaneError::InvalidBank(2))
        );
    }

    #[test]
    fn service_dataplane_capacity_fault_is_rejected_before_map_mutation() {
        assert_eq!(
            validate_dataplane_capacity(
                "SERVICE_BACKEND_SLOTS",
                SERVICE_BACKEND_SLOT_BANK_CAPACITY + 1,
                SERVICE_BACKEND_SLOT_BANK_CAPACITY,
            ),
            Err(ServiceDataplaneError::Capacity {
                map: "SERVICE_BACKEND_SLOTS",
                actual: SERVICE_BACKEND_SLOT_BANK_CAPACITY + 1,
                limit: SERVICE_BACKEND_SLOT_BANK_CAPACITY,
            })
        );
    }

    #[test]
    fn backendless_service_is_valid_for_explicit_no_backend_behavior() {
        let mut service = service(1, "empty");
        service.backends.clear();
        service.frontends[0].backend_ids.clear();
        assert!(snapshot(vec![service]).validate_and_normalize().is_ok());
    }

    #[test]
    fn dataplane_slots_admit_only_ready_non_terminating_backends() {
        let mut service = service(2, "lifecycle");
        let mut draining = backend(3, "10.244.0.11", 8443);
        draining.ready = true;
        draining.serving = true;
        draining.terminating = true;
        let mut unready = backend(4, "10.244.0.12", 8443);
        unready.ready = false;
        unready.serving = false;
        service.backends.extend([draining, unready]);
        service.frontends[0].backend_ids =
            vec![BackendId::new(2), BackendId::new(3), BackendId::new(4)];

        let state = compile_service_dataplane(&snapshot(vec![service]), 0)
            .expect("valid lifecycle-aware service state");
        assert_eq!(state.ipv4_backends.len(), 3);
        assert_eq!(state.backend_slots.len(), 1);
        let frontend = state.ipv4_frontends.first_key_value().unwrap().1;
        assert_eq!(u32::from_ne_bytes(frontend[8..12].try_into().unwrap()), 1);
        let slot = state.backend_slots.first_key_value().unwrap().1;
        assert_eq!(u32::from_ne_bytes(slot[0..4].try_into().unwrap()), 2);
    }

    #[test]
    fn duplicate_frontend_across_services_is_rejected() {
        let first = service(1, "one");
        let mut second = service(2, "two");
        second.frontends = first.frontends.clone();
        assert!(matches!(
            snapshot(vec![first, second]).validate_and_normalize(),
            Err(ServiceIrError::DuplicateFrontend(_))
        ));
    }

    #[test]
    fn invalid_protocol_and_backend_identity_are_rejected() {
        let mut invalid_protocol = service(1, "icmp");
        invalid_protocol.frontends[0].protocol = Protocol::Icmp;
        assert!(matches!(
            snapshot(vec![invalid_protocol]).validate_and_normalize(),
            Err(ServiceIrError::InvalidFrontend { .. })
        ));

        let mut invalid_backend = service(1, "zero-backend");
        invalid_backend.backends[0].id = BackendId::new(0);
        assert!(matches!(
            snapshot(vec![invalid_backend]).validate_and_normalize(),
            Err(ServiceIrError::ZeroBackendId { .. })
        ));
    }

    #[test]
    fn frontend_backend_references_are_exact_and_family_safe() {
        let mut unknown = service(1, "unknown");
        unknown.frontends[0].backend_ids = vec![BackendId::new(99)];
        assert!(matches!(
            snapshot(vec![unknown]).validate_and_normalize(),
            Err(ServiceIrError::UnknownFrontendBackend { .. })
        ));

        let mut duplicate = service(1, "duplicate");
        duplicate.frontends[0].backend_ids = vec![BackendId::new(1), BackendId::new(1)];
        assert!(matches!(
            snapshot(vec![duplicate]).validate_and_normalize(),
            Err(ServiceIrError::DuplicateFrontendBackend { .. })
        ));

        let mut wrong_family = service(1, "wrong-family");
        wrong_family.backends[0].address = "10.244.0.10".parse().expect("valid test address");
        assert!(matches!(
            snapshot(vec![wrong_family]).validate_and_normalize(),
            Err(ServiceIrError::BackendFamilyMismatch { .. })
        ));

        let mut wrong_protocol = service(1, "wrong-protocol");
        wrong_protocol.backends[0].protocol = Protocol::Udp;
        assert!(matches!(
            snapshot(vec![wrong_protocol]).validate_and_normalize(),
            Err(ServiceIrError::InvalidBackend { .. })
        ));
    }

    #[test]
    fn unversioned_and_unknown_wire_state_is_rejected() {
        let mut unversioned = snapshot(vec![service(1, "one")]);
        unversioned.revision = Revision::INITIAL;
        assert_eq!(
            unversioned.validate_and_normalize(),
            Err(ServiceIrError::ZeroRevision)
        );

        let value = serde_json::json!({
            "schemaVersion": SERVICE_SNAPSHOT_SCHEMA_VERSION,
            "sourceEpoch": 7,
            "revision": 1,
            "services": [],
            "futureField": true
        });
        assert!(serde_json::from_value::<ServiceSnapshot>(value).is_err());
    }

    #[test]
    fn service_schema_transition_migrates_v1_v2_v3_and_projects_newer_intent() {
        let current = snapshot(vec![service(1, "one")])
            .validate_and_normalize()
            .expect("current snapshot is valid");
        let node_port_v2 = current
            .node_port_v2_projection()
            .expect("current snapshot has a schema-v2 projection");
        let node_port_v2_value =
            serde_json::to_value(&node_port_v2).expect("schema-v2 snapshot encodes");
        assert_eq!(node_port_v2_value["schemaVersion"], 2);
        assert!(
            node_port_v2_value["services"][0]
                .get("loadBalancer")
                .is_none()
        );
        assert_eq!(
            serde_json::from_value::<ServiceSnapshot>(node_port_v2_value)
                .expect("schema-v2 snapshot decodes")
                .validate_and_normalize()
                .expect("schema-v2 snapshot migrates"),
            current
        );
        let legacy = current
            .legacy_v1_projection()
            .expect("current snapshot has a legacy projection");
        let legacy_value = serde_json::to_value(&legacy).expect("legacy snapshot encodes");
        assert_eq!(legacy_value["schemaVersion"], 1);
        assert!(legacy_value["services"][0].get("nodePorts").is_none());
        assert_eq!(
            serde_json::from_value::<ServiceSnapshot>(legacy_value)
                .expect("legacy snapshot decodes")
                .validate_and_normalize()
                .expect("legacy snapshot migrates"),
            current
        );

        let mut node_port_source = source_service();
        node_port_source.ports[0].node_port = Some(30_080);
        let node_port_snapshot = compile_service_snapshot(
            9,
            Revision::new(3),
            vec![node_port_source],
            vec![source_slice(AddressFamily::Ipv4, "api-v4", "10.244.0.20")],
        )
        .expect("valid NodePort snapshot");
        let mut disguised_legacy =
            serde_json::to_value(node_port_snapshot).expect("NodePort snapshot encodes");
        disguised_legacy["schemaVersion"] = serde_json::json!(1);
        assert_eq!(
            serde_json::from_value::<ServiceSnapshot>(disguised_legacy)
                .expect("additive field decodes")
                .validate_and_normalize(),
            Err(ServiceIrError::LegacyNodePortIntent)
        );

        let mut lb_service = source_service();
        lb_service.external_traffic_policy = ServiceTrafficPolicy::Local;
        lb_service.load_balancer = Some(load_balancer_source());
        let load_balancer_snapshot =
            compile_service_snapshot(9, Revision::new(4), vec![lb_service], Vec::new())
                .expect("valid LoadBalancer snapshot");
        let projected_v2 = load_balancer_snapshot
            .node_port_v2_projection()
            .expect("LoadBalancer intent has a safe schema-v2 projection");
        assert_eq!(
            projected_v2.schema_version,
            NODE_PORT_SERVICE_SNAPSHOT_SCHEMA_VERSION
        );
        assert!(projected_v2.services[0].load_balancer.is_none());
        let mut disguised_v2 =
            serde_json::to_value(&load_balancer_snapshot).expect("LoadBalancer snapshot encodes");
        disguised_v2["schemaVersion"] = serde_json::json!(2);
        assert_eq!(
            serde_json::from_value::<ServiceSnapshot>(disguised_v2)
                .expect("additive LoadBalancer field decodes")
                .validate_and_normalize(),
            Err(ServiceIrError::LegacyLoadBalancerIntent { schema: 2 })
        );

        let projected_v3 = load_balancer_snapshot
            .load_balancer_v3_projection()
            .expect("default selection intent has a safe schema-v3 projection");
        assert_eq!(
            projected_v3.schema_version,
            LOAD_BALANCER_SERVICE_SNAPSHOT_SCHEMA_VERSION
        );
        assert_eq!(
            projected_v3
                .validate_and_normalize()
                .expect("schema-v3 snapshot migrates"),
            load_balancer_snapshot
        );
    }

    #[test]
    fn compiler_preserves_advanced_selection_and_fences_legacy_projection() {
        let mut source = source_service();
        source.internal_traffic_policy = ServiceTrafficPolicy::Local;
        source.session_affinity = ServiceSessionAffinity::ClientIp {
            timeout_seconds: 900,
        };
        source.traffic_distribution = ServiceTrafficDistribution::PreferSameNode;
        source.selection_algorithm = ServiceSelectionAlgorithm::Maglev;
        source.forwarding_mode = ServiceForwardingMode::Dsr;
        let snapshot = compile_service_snapshot(11, Revision::new(7), vec![source], Vec::new())
            .expect("advanced selection intent compiles");
        let service = &snapshot.services[0];
        assert_eq!(service.internal_traffic_policy, ServiceTrafficPolicy::Local);
        assert_eq!(
            service.session_affinity,
            ServiceSessionAffinity::ClientIp {
                timeout_seconds: 900
            }
        );
        assert_eq!(
            service.traffic_distribution,
            ServiceTrafficDistribution::PreferSameNode
        );
        assert_eq!(
            service.selection_algorithm,
            ServiceSelectionAlgorithm::Maglev
        );
        assert_eq!(service.forwarding_mode, ServiceForwardingMode::Dsr);
        assert_eq!(
            compile_service_dataplane(&snapshot, 0),
            Err(ServiceDataplaneError::UnsupportedAdvancedSelection)
        );
        assert_eq!(
            snapshot.load_balancer_v3_projection(),
            Err(ServiceIrError::LegacyAdvancedSelectionIntent { schema: 3 })
        );

        let mut invalid = snapshot;
        invalid.services[0].session_affinity =
            ServiceSessionAffinity::ClientIp { timeout_seconds: 0 };
        assert!(matches!(
            invalid.validate_and_normalize(),
            Err(ServiceIrError::InvalidServiceField {
                field: "session affinity timeout",
                ..
            })
        ));
    }

    #[test]
    fn node_port_node_snapshot_is_bounded_owned_and_canonical() {
        let snapshot = NodePortNodeSnapshot {
            schema_version: NODE_PORT_NODE_SNAPSHOT_SCHEMA_VERSION,
            source_epoch: 9,
            revision: Revision::new(4),
            node_name: "worker-a".to_owned(),
            node_uid: "worker-a-uid".to_owned(),
            addresses: vec![
                ServiceNodeAddress {
                    address: "fdff::10".parse().unwrap(),
                    kind: NodeAddressKind::External,
                },
                ServiceNodeAddress {
                    address: "192.0.2.10".parse().unwrap(),
                    kind: NodeAddressKind::Internal,
                },
            ],
        }
        .validate_and_normalize()
        .expect("valid dual-stack Node addresses");
        assert!(snapshot.addresses[0].address.is_ipv4());
        assert_eq!(snapshot.addresses[1].kind, NodeAddressKind::External);

        let mut duplicate = snapshot.clone();
        duplicate.addresses.push(ServiceNodeAddress {
            address: "192.0.2.10".parse().unwrap(),
            kind: NodeAddressKind::External,
        });
        assert!(matches!(
            duplicate.validate_and_normalize(),
            Err(NodePortNodeError::DuplicateAddress(_))
        ));
        let mut unusable = snapshot;
        unusable.addresses[0].address = "127.0.0.1".parse().unwrap();
        assert!(matches!(
            unusable.validate_and_normalize(),
            Err(NodePortNodeError::UnusableAddress(_))
        ));
    }

    fn source_service() -> ServiceSource {
        ServiceSource {
            namespace: "demo".to_owned(),
            name: "api".to_owned(),
            cluster_ips: vec![
                "fd02::10".parse().expect("valid IPv6 address"),
                "10.96.0.10".parse().expect("valid IPv4 address"),
            ],
            external_traffic_policy: ServiceTrafficPolicy::Cluster,
            internal_traffic_policy: ServiceTrafficPolicy::Cluster,
            session_affinity: ServiceSessionAffinity::None,
            traffic_distribution: ServiceTrafficDistribution::Any,
            selection_algorithm: ServiceSelectionAlgorithm::StableHash,
            forwarding_mode: ServiceForwardingMode::Nat,
            load_balancer: None,
            ports: vec![
                ServiceSourcePort {
                    name: Some("dns".to_owned()),
                    protocol: Protocol::Udp,
                    port: 53,
                    app_protocol: None,
                    node_port: None,
                },
                ServiceSourcePort {
                    name: Some("http".to_owned()),
                    protocol: Protocol::Tcp,
                    port: 80,
                    app_protocol: Some("kubernetes.io/h2c".to_owned()),
                    node_port: None,
                },
            ],
        }
    }

    fn load_balancer_source() -> ServiceLoadBalancerSource {
        ServiceLoadBalancerSource {
            class: UNF_LOAD_BALANCER_CLASS.to_owned(),
            ip_families: vec![AddressFamily::Ipv6, AddressFamily::Ipv4],
            ip_family_policy: ServiceIpFamilyPolicy::RequireDualStack,
            requested_ips: vec![
                "2001:db8::60".parse().unwrap(),
                "192.0.2.60".parse().unwrap(),
            ],
            source_ranges: vec![
                "2001:db8:100::/56".parse().unwrap(),
                "198.51.100.0/24".parse().unwrap(),
            ],
            allocate_node_ports: false,
            health_check_node_port: Some(32_000),
        }
    }

    fn source_slice(family: AddressFamily, name: &str, address: &str) -> EndpointSliceSource {
        EndpointSliceSource {
            namespace: "demo".to_owned(),
            name: name.to_owned(),
            service_name: "api".to_owned(),
            address_family: family,
            endpoints: vec![EndpointSource {
                addresses: vec![address.parse().expect("valid endpoint address")],
                target_workload: Some(format!("demo/{name}-pod")),
                node_name: Some(format!("{name}-node")),
                zone: Some("zone-a".to_owned()),
                ready: false,
                serving: true,
                terminating: true,
                ports: vec![
                    EndpointPortSource {
                        name: Some("http".to_owned()),
                        protocol: Protocol::Tcp,
                        port: Some(8080),
                        app_protocol: Some("kubernetes.io/h2c".to_owned()),
                    },
                    EndpointPortSource {
                        name: Some("dns".to_owned()),
                        protocol: Protocol::Udp,
                        port: Some(8053),
                        app_protocol: None,
                    },
                ],
            }],
        }
    }

    #[test]
    fn compiler_is_order_independent_and_family_port_exact() {
        let service = source_service();
        let ipv4 = source_slice(AddressFamily::Ipv4, "api-v4", "10.244.0.20");
        let ipv6 = source_slice(AddressFamily::Ipv6, "api-v6", "fd01::20");
        let left = compile_service_snapshot(
            9,
            Revision::new(3),
            vec![service.clone()],
            vec![ipv6.clone(), ipv4.clone()],
        )
        .expect("valid dual-stack sources");
        let right = compile_service_snapshot(9, Revision::new(3), vec![service], vec![ipv4, ipv6])
            .expect("same sources in another order");
        assert_eq!(left, right);
        assert_eq!(left.services.len(), 1);
        let compiled = &left.services[0];
        assert_eq!(compiled.frontends.len(), 4);
        assert_eq!(compiled.backends.len(), 4);
        for frontend in &compiled.frontends {
            assert_eq!(frontend.backend_ids.len(), 1);
            let backend = compiled
                .backends
                .iter()
                .find(|backend| backend.id == frontend.backend_ids[0])
                .expect("referenced backend");
            assert_eq!(frontend.address.is_ipv4(), backend.address.is_ipv4());
            assert_eq!(frontend.protocol, backend.protocol);
            assert!(!backend.ready);
            assert!(backend.serving);
            assert!(backend.terminating);
            assert!(backend.target_workload.is_some());
            assert!(backend.node_name.is_some());
            assert!(backend.zone.is_some());
        }
    }

    #[test]
    fn compiler_preserves_dual_stack_node_ports_and_external_traffic_policy() {
        let mut service = source_service();
        service.external_traffic_policy = ServiceTrafficPolicy::Local;
        service.ports[0].node_port = Some(30_053);
        service.ports[1].node_port = Some(30_080);
        let compiled = compile_service_snapshot(
            9,
            Revision::new(3),
            vec![service],
            vec![
                source_slice(AddressFamily::Ipv4, "api-v4", "10.244.0.20"),
                source_slice(AddressFamily::Ipv6, "api-v6", "fd01::20"),
            ],
        )
        .expect("valid dual-stack NodePort sources");
        let service = &compiled.services[0];
        assert_eq!(compiled.schema_version, SERVICE_SNAPSHOT_SCHEMA_VERSION);
        assert_eq!(service.node_ports.len(), 4);
        assert!(service.node_ports.iter().all(|node_port| {
            node_port.traffic_policy == ServiceTrafficPolicy::Local
                && node_port.backend_ids.len() == 1
                && service.frontends.iter().any(|frontend| {
                    frontend.address.is_ipv4() == matches!(node_port.family, AddressFamily::Ipv4)
                        && frontend.port == node_port.service_port
                        && frontend.protocol == node_port.protocol
                        && frontend.name == node_port.name
                })
        }));
        assert!(service.node_ports.iter().any(|node_port| {
            node_port.family == AddressFamily::Ipv4 && node_port.port == 30_080
        }));
        assert!(service.node_ports.iter().any(|node_port| {
            node_port.family == AddressFamily::Ipv6 && node_port.port == 30_053
        }));
        assert_eq!(
            compile_service_dataplane(&compiled, 0),
            Err(ServiceDataplaneError::UnsupportedNodePort { actual: 4 })
        );
    }

    #[test]
    fn compiler_preserves_bounded_dual_stack_load_balancer_intent() {
        let mut source = source_service();
        source.external_traffic_policy = ServiceTrafficPolicy::Local;
        source.load_balancer = Some(load_balancer_source());
        let compiled = compile_service_snapshot(
            9,
            Revision::new(3),
            vec![source],
            vec![
                source_slice(AddressFamily::Ipv4, "api-v4", "10.244.0.20"),
                source_slice(AddressFamily::Ipv6, "api-v6", "fd01::20"),
            ],
        )
        .expect("valid dual-stack LoadBalancer source");

        assert_eq!(compiled.schema_version, SERVICE_SNAPSHOT_SCHEMA_VERSION);
        let service = &compiled.services[0];
        let load_balancer = service
            .load_balancer
            .as_ref()
            .expect("explicit UNF LoadBalancer intent");
        assert_eq!(load_balancer.class, UNF_LOAD_BALANCER_CLASS);
        assert_eq!(
            load_balancer.ip_families,
            [AddressFamily::Ipv4, AddressFamily::Ipv6]
        );
        assert_eq!(
            load_balancer.ip_family_policy,
            ServiceIpFamilyPolicy::RequireDualStack
        );
        assert!(!load_balancer.allocate_node_ports);
        assert_eq!(load_balancer.health_check_node_port, Some(32_000));
        assert_eq!(load_balancer.traffic_policy, ServiceTrafficPolicy::Local);
        assert_eq!(load_balancer.requested_ips.len(), 2);
        assert_eq!(load_balancer.source_ranges.len(), 2);
        assert_eq!(load_balancer.frontends.len(), 4);
        assert!(load_balancer.frontends.iter().all(|frontend| {
            frontend.backend_ids.len() == 1
                && service.frontends.iter().any(|cluster_ip| {
                    address_family(cluster_ip.address) == frontend.family
                        && cluster_ip.port == frontend.service_port
                        && cluster_ip.protocol == frontend.protocol
                        && cluster_ip.name == frontend.name
                        && cluster_ip.backend_ids == frontend.backend_ids
                })
        }));
        assert_eq!(
            compile_service_dataplane(&compiled, 0),
            Err(ServiceDataplaneError::UnsupportedLoadBalancer { actual: 4 })
        );
    }

    #[test]
    fn load_balancer_validation_rejects_foreign_ambiguous_and_broadening_intent() {
        assert!("198.51.100.1/24".parse::<ServiceIpPrefix>().is_err());
        assert!("2001:db8::/129".parse::<ServiceIpPrefix>().is_err());

        let mut foreign = source_service();
        let mut foreign_intent = load_balancer_source();
        foreign_intent.class = "example.com/foreign".to_owned();
        foreign.load_balancer = Some(foreign_intent);
        assert!(matches!(
            compile_service_snapshot(9, Revision::new(3), vec![foreign], Vec::new()),
            Err(ServiceCompileError::InvalidIr(
                ServiceIrError::InvalidLoadBalancer { .. }
            ))
        ));

        let mut first = source_service();
        first.name = "first".to_owned();
        first.external_traffic_policy = ServiceTrafficPolicy::Local;
        first.load_balancer = Some(load_balancer_source());
        let mut second = source_service();
        second.name = "second".to_owned();
        second.external_traffic_policy = ServiceTrafficPolicy::Local;
        second.cluster_ips = vec!["10.97.0.10".parse().unwrap(), "fd03::10".parse().unwrap()];
        second.load_balancer = Some(load_balancer_source());
        assert!(matches!(
            compile_service_snapshot(9, Revision::new(3), vec![first, second], Vec::new()),
            Err(ServiceCompileError::InvalidIr(
                ServiceIrError::DuplicateLoadBalancerAddress { .. }
            ))
        ));

        let mut unsupported_protocol = source_service();
        unsupported_protocol.external_traffic_policy = ServiceTrafficPolicy::Local;
        unsupported_protocol.ports[0].protocol = Protocol::Sctp;
        unsupported_protocol.load_balancer = Some(load_balancer_source());
        assert!(matches!(
            compile_service_snapshot(9, Revision::new(3), vec![unsupported_protocol], Vec::new()),
            Err(ServiceCompileError::InvalidIr(
                ServiceIrError::InvalidLoadBalancerFrontend { .. }
            ))
        ));

        let mut mismatched_range = source_service();
        let mut intent = load_balancer_source();
        intent.ip_families = vec![AddressFamily::Ipv4];
        intent.ip_family_policy = ServiceIpFamilyPolicy::SingleStack;
        intent.requested_ips = vec!["192.0.2.60".parse().unwrap()];
        intent.source_ranges = vec!["2001:db8:100::/56".parse().unwrap()];
        mismatched_range.cluster_ips = vec!["10.96.0.10".parse().unwrap()];
        mismatched_range.load_balancer = Some(intent);
        assert!(matches!(
            compile_service_snapshot(9, Revision::new(3), vec![mismatched_range], Vec::new()),
            Err(ServiceCompileError::InvalidIr(
                ServiceIrError::InvalidLoadBalancer { .. }
            ))
        ));
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn node_port_dataplane_is_node_scoped_banked_and_policy_typed() {
        let mut source = source_service();
        source.external_traffic_policy = ServiceTrafficPolicy::Local;
        source.ports[1].node_port = Some(30_080);
        let snapshot = compile_service_snapshot(
            9,
            Revision::new(3),
            vec![source],
            vec![
                source_slice(AddressFamily::Ipv4, "api-v4", "10.244.0.20"),
                source_slice(AddressFamily::Ipv6, "api-v6", "fd01::20"),
            ],
        )
        .expect("valid NodePort service intent");
        let node = NodePortNodeSnapshot {
            schema_version: NODE_PORT_NODE_SNAPSHOT_SCHEMA_VERSION,
            source_epoch: 9,
            revision: Revision::new(7),
            node_name: "worker-a".to_owned(),
            node_uid: "worker-a-uid".to_owned(),
            addresses: vec![
                ServiceNodeAddress {
                    address: "192.0.2.10".parse().unwrap(),
                    kind: NodeAddressKind::Internal,
                },
                ServiceNodeAddress {
                    address: "198.51.100.10".parse().unwrap(),
                    kind: NodeAddressKind::External,
                },
                ServiceNodeAddress {
                    address: "fdff::10".parse().unwrap(),
                    kind: NodeAddressKind::Internal,
                },
            ],
        };
        let state =
            compile_node_port_dataplane(&snapshot, &node, 1, 0).expect("valid local NodePort maps");
        assert_eq!(state.ipv4_frontends.len(), 2);
        assert_eq!(state.ipv6_frontends.len(), 1);
        for value in state
            .ipv4_frontends
            .values()
            .chain(state.ipv6_frontends.values())
        {
            assert_eq!(
                u16::from_ne_bytes(value[14..16].try_into().unwrap()),
                NODE_PORT_FRONTEND_FLAG_LOCAL
            );
            assert_eq!(value[24], 1);
        }
        assert_eq!(
            u64::from_ne_bytes(state.config[8..16].try_into().unwrap()),
            3
        );
        assert_eq!(
            u64::from_ne_bytes(state.config[16..24].try_into().unwrap()),
            7
        );
        assert_eq!(state.config[34], 0);

        let mut local_snapshot = snapshot.clone();
        for backend in &mut local_snapshot.services[0].backends {
            backend.ready = true;
            backend.terminating = false;
        }
        let mut local_node = node.clone();
        local_node.node_name = "api-v4-node".to_owned();
        let local = compile_node_port_dataplane(&local_snapshot, &local_node, 1, 0)
            .expect("Local NodePort slots compile for only the receiving Node");
        assert_eq!(local.service_backend_slots.len(), 1);
        assert!(local.ipv4_frontends.values().all(|value| {
            u32::from_ne_bytes(value[4..8].try_into().unwrap())
                >= NODE_PORT_LOCAL_FRONTEND_INDEX_FLAG
                && u32::from_ne_bytes(value[8..12].try_into().unwrap()) == 1
        }));
        assert!(local.ipv6_frontends.values().all(|value| {
            u32::from_ne_bytes(value[4..8].try_into().unwrap())
                >= NODE_PORT_LOCAL_FRONTEND_INDEX_FLAG
                && u32::from_ne_bytes(value[8..12].try_into().unwrap()) == 0
        }));
        let fabric = compile_node_port_fabric_dataplane(&local_snapshot, &local_node, 1, 0)
            .expect("node-local slots merge into the same service transaction");
        assert_eq!(fabric.service.backend_slots.len(), 5);
        assert_eq!(
            u32::from_ne_bytes(fabric.service.config[24..28].try_into().unwrap()),
            5
        );

        let mut skewed = node;
        skewed.source_epoch = 10;
        assert_eq!(
            compile_node_port_dataplane(&snapshot, &skewed, 1, 0),
            Err(NodePortDataplaneError::SourceEpochMismatch)
        );
        assert_eq!(
            preflight_node_port_family_capacity(
                "NODE_PORT_FRONTENDS_V4",
                2,
                (SERVICE_FRONTEND_BANK_CAPACITY / 2) + 1,
            ),
            Err(NodePortDataplaneError::Capacity {
                map: "NODE_PORT_FRONTENDS_V4",
                actual: SERVICE_FRONTEND_BANK_CAPACITY + 2,
                limit: SERVICE_FRONTEND_BANK_CAPACITY,
            })
        );
    }

    #[test]
    fn node_port_validation_rejects_collisions_and_inexact_links() {
        let mut first = service(2, "one");
        first.node_ports.push(ServiceNodePort {
            family: AddressFamily::Ipv4,
            port: 30_080,
            service_port: 443,
            protocol: Protocol::Tcp,
            name: Some("https".to_owned()),
            app_protocol: Some("kubernetes.io/h2c".to_owned()),
            traffic_policy: ServiceTrafficPolicy::Cluster,
            backend_ids: vec![BackendId::new(2)],
        });
        let mut second = service(3, "two");
        second.frontends[0].address = "10.96.0.11".parse().unwrap();
        second.backends[0].address = "10.244.0.11".parse().unwrap();
        second.node_ports.push(ServiceNodePort {
            family: AddressFamily::Ipv4,
            port: 30_080,
            service_port: 443,
            protocol: Protocol::Tcp,
            name: Some("https".to_owned()),
            app_protocol: Some("kubernetes.io/h2c".to_owned()),
            traffic_policy: ServiceTrafficPolicy::Cluster,
            backend_ids: vec![BackendId::new(3)],
        });
        assert!(matches!(
            snapshot(vec![first.clone(), second]).validate_and_normalize(),
            Err(ServiceIrError::DuplicateNodePort { .. })
        ));

        first.node_ports[0].service_port = 444;
        assert!(matches!(
            snapshot(vec![first]).validate_and_normalize(),
            Err(ServiceIrError::InvalidNodePort { .. })
        ));
    }

    #[test]
    fn compiler_omits_headless_and_keeps_backendless_frontends() {
        let mut headless = source_service();
        headless.name = "headless".to_owned();
        headless.cluster_ips.clear();
        let compiled = compile_service_snapshot(
            9,
            Revision::new(3),
            vec![headless, source_service()],
            Vec::new(),
        )
        .expect("valid source state");
        assert_eq!(compiled.services.len(), 1);
        assert_eq!(compiled.services[0].frontends.len(), 4);
        assert!(compiled.services[0].backends.is_empty());
        assert!(
            compiled.services[0]
                .frontends
                .iter()
                .all(|frontend| frontend.backend_ids.is_empty())
        );
    }

    #[test]
    fn compiler_rejects_unresolved_ports_and_family_lies() {
        let mut unresolved = source_slice(AddressFamily::Ipv4, "api-v4", "10.244.0.20");
        unresolved.endpoints[0].ports[0].port = None;
        assert!(matches!(
            compile_service_snapshot(
                9,
                Revision::new(3),
                vec![source_service()],
                vec![unresolved]
            ),
            Err(ServiceCompileError::UnresolvedEndpointPort { .. })
        ));

        let family_lie = source_slice(AddressFamily::Ipv6, "api-v6", "10.244.0.20");
        assert!(matches!(
            compile_service_snapshot(
                9,
                Revision::new(3),
                vec![source_service()],
                vec![family_lie]
            ),
            Err(ServiceCompileError::AddressFamilyMismatch { .. })
        ));
    }

    #[test]
    fn compiler_merges_equivalent_slices_and_rejects_conflicting_lifecycle() {
        let first = source_slice(AddressFamily::Ipv4, "api-v4-a", "10.244.0.20");
        let mut second = first.clone();
        second.name = "api-v4-b".to_owned();
        let compiled = compile_service_snapshot(
            9,
            Revision::new(3),
            vec![source_service()],
            vec![second.clone(), first],
        )
        .expect("equivalent duplicate endpoint provenance");
        assert!(
            compiled.services[0]
                .backends
                .iter()
                .all(|backend| backend.endpoint_slices.len() == 2)
        );

        second.endpoints[0].ready = true;
        let first = source_slice(AddressFamily::Ipv4, "api-v4-a", "10.244.0.20");
        assert!(matches!(
            compile_service_snapshot(
                9,
                Revision::new(3),
                vec![source_service()],
                vec![first, second]
            ),
            Err(ServiceCompileError::ConflictingBackendProvenance { .. })
        ));
    }

    #[test]
    fn compiler_merges_named_service_ports_that_share_one_backend_tuple() {
        let mut service = source_service();
        service.cluster_ips = vec!["10.96.0.10".parse().expect("valid IPv4 address")];
        service.ports = vec![
            ServiceSourcePort {
                name: Some("ironic".to_owned()),
                protocol: Protocol::Tcp,
                port: 6388,
                app_protocol: None,
                node_port: None,
            },
            ServiceSourcePort {
                name: Some("ironic-api".to_owned()),
                protocol: Protocol::Tcp,
                port: 6385,
                app_protocol: Some("example.io/api".to_owned()),
                node_port: None,
            },
        ];
        let mut slice = source_slice(AddressFamily::Ipv4, "metal3", "10.244.0.20");
        slice.endpoints[0].ready = true;
        slice.endpoints[0].terminating = false;
        slice.endpoints[0].ports = vec![
            EndpointPortSource {
                name: Some("ironic".to_owned()),
                protocol: Protocol::Tcp,
                port: Some(6388),
                app_protocol: None,
            },
            EndpointPortSource {
                name: Some("ironic-api".to_owned()),
                protocol: Protocol::Tcp,
                port: Some(6388),
                app_protocol: Some("example.io/api".to_owned()),
            },
        ];

        let expected = compile_service_snapshot(
            9,
            Revision::new(3),
            vec![service.clone()],
            vec![slice.clone()],
        )
        .expect("valid shared target port");
        service.ports.reverse();
        slice.endpoints[0].ports.reverse();
        let reordered = compile_service_snapshot(9, Revision::new(3), vec![service], vec![slice])
            .expect("source ordering does not alter shared target lowering");

        assert_eq!(expected, reordered);
        let compiled = &expected.services[0];
        assert_eq!(compiled.frontends.len(), 2);
        assert_eq!(compiled.backends.len(), 1);
        assert_eq!(
            compiled.frontends[0].backend_ids,
            compiled.frontends[1].backend_ids
        );
        assert_eq!(compiled.backends[0].port, 6388);
        assert_eq!(compiled.backends[0].port_name, None);
        assert_eq!(compiled.backends[0].app_protocol, None);
    }

    #[test]
    fn provisional_id_admission_detects_collisions() {
        let mut registry = BTreeMap::new();
        admit_id(&mut registry, "service", 42, "first").expect("first owner");
        admit_id(&mut registry, "service", 42, "first").expect("same owner replay");
        assert!(matches!(
            admit_id(&mut registry, "service", 42, "second"),
            Err(ServiceCompileError::IdCollision { .. })
        ));
    }
}
