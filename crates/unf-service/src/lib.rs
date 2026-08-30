//! Kubernetes-independent service load-balancing intent.
//!
//! This crate deliberately stops before selecting a dataplane algorithm or map
//! ABI. It defines the validated, deterministic boundary that Kubernetes and
//! future native APIs must cross before service state can reach an agent.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use unf_common::{BackendId, Protocol, Revision, ServiceId};
use unf_ebpf_common::{
    SERVICE_BACKEND_FLAG_READY, SERVICE_BACKEND_FLAG_SERVING, SERVICE_BACKEND_FLAG_TERMINATING,
    SERVICE_BANK_COUNT, SERVICE_MAP_ABI_VERSION,
};

pub use unf_common::SERVICE_SNAPSHOT_SCHEMA_VERSION;

pub const LEGACY_SERVICE_SNAPSHOT_SCHEMA_VERSION: u16 = 1;
pub const MAX_SERVICES: usize = 65_536;
pub const MAX_SERVICE_FRONTENDS: usize = 131_072;
pub const MAX_SERVICE_NODE_PORTS: usize = 131_072;
pub const MAX_SERVICE_BACKENDS: usize = 262_144;
pub const MAX_SERVICE_BACKEND_REFERENCES: usize = 524_288;
pub const MAX_BACKENDS_PER_SERVICE: usize = 4_096;
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
    pub frontends: Vec<ServiceFrontend>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub node_ports: Vec<ServiceNodePort>,
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

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ServiceIrError {
    #[error("unsupported service snapshot schema {actual}; expected {expected}")]
    UnsupportedSchema { actual: u16, expected: u16 },
    #[error("legacy service snapshot schema v1 cannot contain NodePort intent")]
    LegacyNodePortIntent,
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
        for cluster_ip in service.cluster_ips {
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
        compiled.push(ServiceIr {
            id: service_id,
            namespace: service.namespace,
            name: service.name,
            frontends,
            node_ports,
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
    pub fn validate_and_normalize(mut self) -> Result<Self, ServiceIrError> {
        if self.schema_version == LEGACY_SERVICE_SNAPSHOT_SCHEMA_VERSION {
            if self
                .services
                .iter()
                .any(|service| !service.node_ports.is_empty())
            {
                return Err(ServiceIrError::LegacyNodePortIntent);
            }
            self.schema_version = SERVICE_SNAPSHOT_SCHEMA_VERSION;
        } else if self.schema_version != SERVICE_SNAPSHOT_SCHEMA_VERSION {
            return Err(ServiceIrError::UnsupportedSchema {
                actual: self.schema_version,
                expected: SERVICE_SNAPSHOT_SCHEMA_VERSION,
            });
        }
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
        let mut total_frontends = 0_usize;
        let mut total_node_ports = 0_usize;
        let mut total_backends = 0_usize;
        let mut total_backend_references = 0_usize;

        for service in &mut self.services {
            validate_service_identity(service, &mut service_ids, &mut service_names)?;
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
            service.frontends.sort();
            service.backends.sort();
        }

        validate_snapshot_capacities(
            total_frontends,
            total_node_ports,
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

    /// Produces the exact additive-schema-v1 view used only for old agents
    /// during the bounded controller-first v1-to-v2 transition.
    ///
    /// # Errors
    ///
    /// Returns the same validation error as [`Self::validate_and_normalize`]
    /// when the source snapshot is not valid current or migratable state.
    pub fn legacy_v1_projection(&self) -> Result<Self, ServiceIrError> {
        let mut projected = self.clone().validate_and_normalize()?;
        for service in &mut projected.services {
            service.node_ports.clear();
        }
        projected.schema_version = LEGACY_SERVICE_SNAPSHOT_SCHEMA_VERSION;
        Ok(projected)
    }
}

fn validate_snapshot_capacities(
    frontends: usize,
    node_ports: usize,
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
            frontends: vec![ServiceFrontend {
                backend_ids: vec![BackendId::new(id)],
                ..frontend(
                    if id == 1 { "fd02::10" } else { "10.96.0.10" },
                    Protocol::Tcp,
                    443,
                )
            }],
            node_ports: Vec::new(),
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
    fn service_schema_transition_migrates_v1_and_projects_without_node_port_intent() {
        let current = snapshot(vec![service(1, "one")])
            .validate_and_normalize()
            .expect("current snapshot is valid");
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
        assert_eq!(compiled.schema_version, 2);
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
