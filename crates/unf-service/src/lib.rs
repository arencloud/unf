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

pub const SERVICE_SNAPSHOT_SCHEMA_VERSION: u16 = 1;
pub const MAX_SERVICES: usize = 65_536;
pub const MAX_SERVICE_FRONTENDS: usize = 131_072;
pub const MAX_SERVICE_BACKENDS: usize = 262_144;
pub const MAX_BACKENDS_PER_SERVICE: usize = 4_096;
pub const MAX_PROVENANCE_COMPONENT_BYTES: usize = 253;
pub const MAX_ENDPOINT_SLICE_PROVENANCE: usize = 128;

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AddressFamily {
    Ipv4,
    Ipv6,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ServiceSourcePort {
    pub name: Option<String>,
    pub protocol: Protocol,
    pub port: u16,
    pub app_protocol: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ServiceSource {
    pub namespace: String,
    pub name: String,
    pub cluster_ips: Vec<IpAddr>,
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
    #[error("service snapshot source epoch must be nonzero")]
    ZeroSourceEpoch,
    #[error("service snapshot revision must be nonzero")]
    ZeroRevision,
    #[error("service snapshot has {actual} services; limit is {limit}")]
    TooManyServices { actual: usize, limit: usize },
    #[error("service snapshot has {actual} frontends; limit is {limit}")]
    TooManyFrontends { actual: usize, limit: usize },
    #[error("service snapshot has {actual} backends; limit is {limit}")]
    TooManyBackends { actual: usize, limit: usize },
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
                frontends.push(ServiceFrontend {
                    address: cluster_ip,
                    port: service_port.port,
                    protocol: service_port.protocol,
                    name: service_port.name.clone(),
                    app_protocol: service_port.app_protocol.clone(),
                    backend_ids: backend_ids.into_iter().collect(),
                });
            }
        }
        compiled.push(ServiceIr {
            id: service_id,
            namespace: service.namespace,
            name: service.name,
            frontends,
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
        && existing.port_name == candidate.port_name
        && existing.app_protocol == candidate.app_protocol
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
        if self.schema_version != SERVICE_SNAPSHOT_SCHEMA_VERSION {
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
        let mut total_frontends = 0_usize;
        let mut total_backends = 0_usize;

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
            total_backends = total_backends.saturating_add(service.backends.len());

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
            service.frontends.sort();
            service.backends.sort();
        }

        if total_frontends > MAX_SERVICE_FRONTENDS {
            return Err(ServiceIrError::TooManyFrontends {
                actual: total_frontends,
                limit: MAX_SERVICE_FRONTENDS,
            });
        }
        if total_backends > MAX_SERVICE_BACKENDS {
            return Err(ServiceIrError::TooManyBackends {
                actual: total_backends,
                limit: MAX_SERVICE_BACKENDS,
            });
        }
        self.services.sort_by(|left, right| {
            left.id
                .cmp(&right.id)
                .then_with(|| left.namespace.cmp(&right.namespace))
                .then_with(|| left.name.cmp(&right.name))
        });
        Ok(self)
    }
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
    fn backendless_service_is_valid_for_explicit_no_backend_behavior() {
        let mut service = service(1, "empty");
        service.backends.clear();
        service.frontends[0].backend_ids.clear();
        assert!(snapshot(vec![service]).validate_and_normalize().is_ok());
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

    fn source_service() -> ServiceSource {
        ServiceSource {
            namespace: "demo".to_owned(),
            name: "api".to_owned(),
            cluster_ips: vec![
                "fd02::10".parse().expect("valid IPv6 address"),
                "10.96.0.10".parse().expect("valid IPv4 address"),
            ],
            ports: vec![
                ServiceSourcePort {
                    name: Some("dns".to_owned()),
                    protocol: Protocol::Udp,
                    port: 53,
                    app_protocol: None,
                },
                ServiceSourcePort {
                    name: Some("http".to_owned()),
                    protocol: Protocol::Tcp,
                    port: 80,
                    app_protocol: Some("kubernetes.io/h2c".to_owned()),
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
