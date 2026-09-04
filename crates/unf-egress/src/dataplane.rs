//! Fixed-width Phase 8 egress lowering and pre-certified source paths.
//!
//! The compiler accepts only an admitted host bank plus the admission guard.
//! Active identities additionally require an exact source-local path
//! certificate for every address family and ready gateway candidate.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use unf_common::{IdentityId, Revision};
use unf_ebpf_common::{
    AddressFamily as BpfAddressFamily, EGRESS_ADMISSION_ACTIVE, EGRESS_ADMISSION_FENCED,
    EGRESS_BANK_COUNT, EGRESS_CONFIG_FLAG_GATEWAY_NAT, EGRESS_DESTINATION_DENY_DEADLINE,
    EGRESS_DESTINATION_STATIC_DEADLINE, EGRESS_MAP_ABI_VERSION, EGRESS_PATH_DIRECT_NEIGHBOR,
    EGRESS_PATH_LOCAL_GATEWAY, EGRESS_PATH_TUNNEL, EGRESS_SELECTION_FLAG_STANDBY,
    EGRESS_SELECTION_TABLE_SIZE, EGRESS_SOURCE_FLAG_GATEWAY_NAT, EGRESS_SOURCE_FLAG_IPV4,
    EGRESS_SOURCE_FLAG_IPV6, EGRESS_SOURCE_FLAG_PRECERTIFIED_STANDBY, EgressAddressValue,
    EgressCandidateKey, EgressDestinationValue, EgressGatewayValue, EgressIpv4DestinationData,
    EgressIpv6DestinationData, EgressMapConfig, EgressSelectionKey, EgressSelectionValue,
    EgressSourceKey, EgressSourceValue,
};

use crate::{
    AddressFamily, AdmittedEgressGatewayProjection, EgressAdmissionDecision, EgressAdmissionGuard,
    EgressBehaviorPlan, EgressDestinations, EgressGatewayHostBank, EgressHaPlan, EgressNode,
    MAX_EGRESS_CONTRACT_PLANS, MAX_EGRESS_GATEWAYS_PER_PLAN, MAX_EGRESS_INTENTS,
    select_bucket_with_ha,
};

pub const EGRESS_PATH_CERTIFICATE_SCHEMA_VERSION: u16 = 1;
pub const MAX_EGRESS_DATAPLANE_PATHS: usize = MAX_EGRESS_INTENTS * MAX_EGRESS_GATEWAYS_PER_PLAN * 2;
pub const MAX_EGRESS_DATAPLANE_SELECTIONS: usize =
    MAX_EGRESS_INTENTS * EGRESS_SELECTION_TABLE_SIZE as usize * 2;
/// One logical bank receives at most half of each physical 262,144-entry LPM
/// map so the active and staging banks can coexist during replacement.
pub const MAX_EGRESS_DATAPLANE_DESTINATIONS_PER_FAMILY: usize = 131_072;
pub const MAX_EGRESS_DATAPLANE_DESTINATIONS: usize =
    MAX_EGRESS_DATAPLANE_DESTINATIONS_PER_FAMILY * 2;

/// Stable wall/monotonic anchor captured by the agent immediately before a
/// bank is compiled. DNS leases are converted once; eBPF never trusts wall
/// clock time or userspace refresh for expiry enforcement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EgressDataplaneClock {
    pub unix_seconds: u64,
    pub monotonic_seconds: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum EgressPathMode {
    DirectNeighbor,
    Tunnel,
    LocalGateway,
}

impl EgressPathMode {
    const fn abi(self) -> u8 {
        match self {
            Self::DirectNeighbor => EGRESS_PATH_DIRECT_NEIGHBOR,
            Self::Tunnel => EGRESS_PATH_TUNNEL,
            Self::LocalGateway => EGRESS_PATH_LOCAL_GATEWAY,
        }
    }
}

/// Source-local route/neighbor or tunnel evidence. The agent creates this only
/// after readback confirms the exact output interface, next hop, transport,
/// MTU, gateway UID, and lease epoch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EgressPathCertificate {
    pub schema_version: u16,
    pub source: EgressNode,
    pub gateway: EgressNode,
    pub address_family: AddressFamily,
    pub transport_address: IpAddr,
    pub next_hop_address: IpAddr,
    pub output_interface: u32,
    pub mtu: u32,
    pub mode: EgressPathMode,
    pub path_revision: Revision,
    pub lease_epoch: u64,
    pub certificate_digest: EgressPathCertificateDigest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EgressPathCertificateDigest(pub [u8; 32]);

impl EgressPathCertificate {
    /// Seals exact source-local path readback into a mutation-detecting
    /// certificate. Authentication remains the agent transport boundary.
    ///
    /// # Errors
    ///
    /// Rejects malformed identity, addresses, interface, MTU, revision, or
    /// lease state.
    #[allow(clippy::too_many_arguments)]
    pub fn issue(
        source: EgressNode,
        gateway: EgressNode,
        address_family: AddressFamily,
        transport_address: IpAddr,
        next_hop_address: IpAddr,
        output_interface: u32,
        mtu: u32,
        mode: EgressPathMode,
        path_revision: Revision,
        lease_epoch: u64,
    ) -> Result<Self, EgressDataplaneError> {
        let mut certificate = Self {
            schema_version: EGRESS_PATH_CERTIFICATE_SCHEMA_VERSION,
            source,
            gateway,
            address_family,
            transport_address,
            next_hop_address,
            output_interface,
            mtu,
            mode,
            path_revision,
            lease_epoch,
            certificate_digest: EgressPathCertificateDigest([0; 32]),
        };
        certificate.validate_fields()?;
        certificate.certificate_digest = certificate.digest()?;
        Ok(certificate)
    }

    /// Checks the physical bounds and exact content commitment.
    ///
    /// # Errors
    ///
    /// Rejects malformed or mutated path evidence.
    pub fn verify_integrity(&self) -> Result<(), EgressDataplaneError> {
        self.validate_fields()?;
        if self.certificate_digest != self.digest()? {
            return Err(EgressDataplaneError::InvalidPath);
        }
        Ok(())
    }

    fn validate_fields(&self) -> Result<(), EgressDataplaneError> {
        if self.schema_version != EGRESS_PATH_CERTIFICATE_SCHEMA_VERSION
            || self.source.name.is_empty()
            || self.source.uid.is_empty()
            || self.gateway.name.is_empty()
            || self.gateway.uid.is_empty()
            || (self.source == self.gateway) != (self.mode == EgressPathMode::LocalGateway)
            || self.path_revision == Revision::INITIAL
            || self.lease_epoch == 0
            || self.output_interface == 0
            || !(1280..=65_535).contains(&self.mtu)
            || family(self.transport_address) != self.address_family
            || family(self.next_hop_address) != self.address_family
            || unusable(self.transport_address)
            || unusable(self.next_hop_address)
            || (self.mode == EgressPathMode::LocalGateway
                && self.transport_address != self.next_hop_address)
        {
            return Err(EgressDataplaneError::InvalidPath);
        }
        Ok(())
    }

    fn digest(&self) -> Result<EgressPathCertificateDigest, EgressDataplaneError> {
        let material = serde_json::to_vec(&(
            self.schema_version,
            &self.source,
            &self.gateway,
            self.address_family,
            self.transport_address,
            self.next_hop_address,
            self.output_interface,
            self.mtu,
            self.mode,
            self.path_revision,
            self.lease_epoch,
        ))
        .map_err(|_| EgressDataplaneError::InvalidPath)?;
        let mut hasher = Sha256::new();
        hasher.update(b"unf.egress-path-certificate.v1\0");
        hasher.update(material);
        Ok(EgressPathCertificateDigest(hasher.finalize().into()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EgressDataplaneState {
    pub config: EgressMapConfig,
    pub sources: Vec<(EgressSourceKey, EgressSourceValue)>,
    pub ipv4_destinations: Vec<(u32, EgressIpv4DestinationData, EgressDestinationValue)>,
    pub ipv6_destinations: Vec<(u32, EgressIpv6DestinationData, EgressDestinationValue)>,
    pub addresses: Vec<(EgressCandidateKey, EgressAddressValue)>,
    pub gateways: Vec<(EgressCandidateKey, EgressGatewayValue)>,
    pub selections: Vec<(EgressSelectionKey, EgressSelectionValue)>,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum EgressDataplaneError {
    #[error("invalid egress dataplane bank {0}")]
    InvalidBank(u8),
    #[error("invalid admitted egress host bank")]
    InvalidHostBank,
    #[error("egress source identity {0:?} has no matching admission fence")]
    AdmissionMissing(IdentityId),
    #[error("egress source identity {0:?} admission does not match its host bank")]
    AdmissionMismatch(IdentityId),
    #[error("egress dataplane contains too many distinct intents")]
    TooManyIntents,
    #[error("plans for egress intent {0} disagree on allocation or gateways")]
    InconsistentIntent(String),
    #[error("egress path certificate is invalid")]
    InvalidPath,
    #[error("egress path certificate is duplicated")]
    DuplicatePath,
    #[error(
        "active egress path is missing for identity {identity:?}, gateway {gateway}, family {family:?}"
    )]
    MissingPath {
        identity: IdentityId,
        gateway: String,
        family: AddressFamily,
    },
    #[error("egress path snapshot contains unused or foreign certificates")]
    UnusedPath,
    #[error("active egress path revisions are not one coherent snapshot")]
    PathRevisionMismatch,
    #[error("egress dataplane capacity exceeded for {kind}")]
    Capacity { kind: &'static str },
    #[error("egress candidate index cannot be represented in the ABI")]
    CandidateIndex,
    #[error("egress rendezvous selection failed")]
    Selection,
    #[error("FQDN egress destinations require a valid wall/monotonic clock anchor")]
    MissingClock,
    #[error("FQDN egress deadline cannot be represented safely in the dataplane")]
    Deadline,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct PathKey {
    source_uid: String,
    gateway_uid: String,
    family: AddressFamily,
    lease_epoch: u64,
}

/// Lowers admission and certified path state into an inactive fixed-width
/// bank. It performs no host or BPF mutation.
///
/// # Errors
///
/// Rejects invalid banks, missing/mismatched admission, inconsistent shared
/// intent state, invalid/unused paths, incoherent revisions, or any ABI bound.
#[allow(clippy::too_many_lines)]
pub fn compile_egress_dataplane(
    host: &EgressGatewayHostBank,
    guard: &EgressAdmissionGuard,
    paths: &[EgressPathCertificate],
    bank: u8,
) -> Result<EgressDataplaneState, EgressDataplaneError> {
    compile_egress_dataplane_inner(host, guard, paths, bank, None)
}

/// Clock-anchored variant required for temporal FQDN destinations.
///
/// # Errors
///
/// Returns an error when the admitted host state, bank, paths, destinations,
/// or temporal deadline cannot be lowered exactly.
pub fn compile_egress_dataplane_at(
    host: &EgressGatewayHostBank,
    guard: &EgressAdmissionGuard,
    paths: &[EgressPathCertificate],
    bank: u8,
    clock: EgressDataplaneClock,
) -> Result<EgressDataplaneState, EgressDataplaneError> {
    compile_egress_dataplane_inner(host, guard, paths, bank, Some(clock))
}

#[allow(clippy::too_many_lines)]
fn compile_egress_dataplane_inner(
    host: &EgressGatewayHostBank,
    guard: &EgressAdmissionGuard,
    paths: &[EgressPathCertificate],
    bank: u8,
    clock: Option<EgressDataplaneClock>,
) -> Result<EgressDataplaneState, EgressDataplaneError> {
    if bank >= EGRESS_BANK_COUNT {
        return Err(EgressDataplaneError::InvalidBank(bank));
    }
    host.verify_integrity()
        .map_err(|_| EgressDataplaneError::InvalidHostBank)?;
    if host.contract.plans.len() > MAX_EGRESS_CONTRACT_PLANS
        || paths.len() > MAX_EGRESS_DATAPLANE_PATHS
    {
        return Err(EgressDataplaneError::Capacity { kind: "input" });
    }

    let path_map = validate_paths(paths)?;
    let mut used_paths = BTreeSet::new();
    let mut intents: BTreeMap<&str, Vec<&EgressBehaviorPlan>> = BTreeMap::new();
    for plan in &host.contract.plans {
        intents.entry(&plan.intent.uid).or_default().push(plan);
    }
    if intents.len() > MAX_EGRESS_INTENTS {
        return Err(EgressDataplaneError::TooManyIntents);
    }

    let mut state = EgressDataplaneState {
        config: EgressMapConfig {
            controller_epoch: host.controller_epoch,
            projection_revision: host.projection_revision.get(),
            contract_revision: host.contract.contract_revision.get(),
            path_revision: 0,
            source_count: 0,
            address_count: 0,
            gateway_count: 0,
            selection_count: 0,
            schema_version: EGRESS_MAP_ABI_VERSION,
            active_bank: bank,
            flags: 0,
            destination_count: 0,
        },
        sources: Vec::with_capacity(host.contract.plans.len()),
        ipv4_destinations: Vec::new(),
        ipv6_destinations: Vec::new(),
        addresses: Vec::new(),
        gateways: Vec::new(),
        selections: Vec::new(),
    };
    let mut coherent_path_revision = None;

    for (intent_index, (intent_uid, plans)) in intents.into_iter().enumerate() {
        let intent_index =
            u32::try_from(intent_index).map_err(|_| EgressDataplaneError::CandidateIndex)?;
        let template = plans[0];
        if plans.iter().skip(1).any(|plan| {
            plan.allocation != template.allocation
                || plan.gateways != template.gateways
                || plan.destinations != template.destinations
                || plan.revisions.allocation != template.revisions.allocation
                || plan.revisions.gateway != template.revisions.gateway
                || plan.revisions.reachability != template.revisions.reachability
        }) {
            return Err(EgressDataplaneError::InconsistentIntent(
                intent_uid.to_owned(),
            ));
        }

        let mut active = Vec::new();
        for plan in &plans {
            let (mut admission, mut active_state) = match guard.decision(plan.source.identity) {
                EgressAdmissionDecision::Native => {
                    return Err(EgressDataplaneError::AdmissionMissing(plan.source.identity));
                }
                EgressAdmissionDecision::Fenced(fence)
                    if fence.owner == plan.intent
                        && fence.intent_revision == plan.revisions.intent =>
                {
                    (EGRESS_ADMISSION_FENCED, None)
                }
                EgressAdmissionDecision::Active(value)
                    if value.owner == plan.intent
                        && value.intent_revision == plan.revisions.intent
                        && value.controller_epoch == host.controller_epoch
                        && value.projection_revision == host.projection_revision
                        && value.contract_revision == host.contract.contract_revision
                        && value.contract_digest == host.contract.contract_digest
                        && value.lease_epoch == plan.allocation.lease_epoch =>
                {
                    (EGRESS_ADMISSION_ACTIVE, Some(value))
                }
                _ => {
                    return Err(EgressDataplaneError::AdmissionMismatch(
                        plan.source.identity,
                    ));
                }
            };
            if matches!(template.destinations, EgressDestinations::DenyAll) {
                admission = EGRESS_ADMISSION_FENCED;
                active_state = None;
            } else if active_state.is_some() {
                active.push(plan.source.identity);
            }
            let flags = family_flags(template, active_state.is_some() && has_standby(template));
            state.sources.push((
                EgressSourceKey {
                    source_identity: plan.source.identity,
                    bank,
                    reserved: [0; 3],
                },
                EgressSourceValue {
                    lease_epoch: plan.allocation.lease_epoch,
                    contract_revision: host.contract.contract_revision.get(),
                    intent_revision: plan.revisions.intent.get(),
                    identity_revision: plan.revisions.identity.get(),
                    policy_revision: plan.revisions.policy.get(),
                    allocation_revision: plan.revisions.allocation.get(),
                    gateway_revision: plan.revisions.gateway.get(),
                    reachability_revision: plan.revisions.reachability.get(),
                    contract_digest: host.contract.contract_digest.0,
                    intent_digest: digest16(b"unf.egress-intent.v1\0", intent_uid.as_bytes()),
                    intent_index,
                    address_count: u16::try_from(plan.allocation.addresses.len())
                        .map_err(|_| EgressDataplaneError::CandidateIndex)?,
                    gateway_count: u16::try_from(plan.gateways.len())
                        .map_err(|_| EgressDataplaneError::CandidateIndex)?,
                    schema_version: EGRESS_MAP_ABI_VERSION,
                    admission,
                    flags,
                    reserved: [0; 4],
                },
            ));
        }

        compile_intent_destinations(
            &mut state,
            host,
            template,
            intent_index,
            bank,
            intent_uid,
            clock,
        )?;
        if active.is_empty() {
            continue;
        }
        compile_intent_candidates(
            &mut state,
            host,
            template,
            intent_index,
            bank,
            &path_map,
            &mut used_paths,
            &mut coherent_path_revision,
            active[0],
            host.ha_plans
                .iter()
                .find(|ha_plan| ha_plan.owner == template.intent),
        )?;
    }

    if used_paths.len() != path_map.len() {
        return Err(EgressDataplaneError::UnusedPath);
    }
    state.config.path_revision = coherent_path_revision.map_or(0, Revision::get);
    state.config.source_count = count("sources", state.sources.len())?;
    state.config.address_count = count("addresses", state.addresses.len())?;
    state.config.gateway_count = count("gateways", state.gateways.len())?;
    state.config.selection_count = count("selections", state.selections.len())?;
    state.config.destination_count = count(
        "destinations",
        state.ipv4_destinations.len() + state.ipv6_destinations.len(),
    )?;
    if state.selections.len() > MAX_EGRESS_DATAPLANE_SELECTIONS {
        return Err(EgressDataplaneError::Capacity { kind: "selections" });
    }
    if state.ipv4_destinations.len() > MAX_EGRESS_DATAPLANE_DESTINATIONS_PER_FAMILY
        || state.ipv6_destinations.len() > MAX_EGRESS_DATAPLANE_DESTINATIONS_PER_FAMILY
        || usize::try_from(state.config.destination_count).unwrap_or(usize::MAX)
            > MAX_EGRESS_DATAPLANE_DESTINATIONS
    {
        return Err(EgressDataplaneError::Capacity {
            kind: "destinations",
        });
    }
    Ok(state)
}

/// Lowers one admitted selected-gateway projection into a heterogeneous,
/// identity-keyed NAT bank. Unlike a source bank, every source may carry a
/// different contract revision; the source identity is therefore also the
/// candidate/selection namespace and no contract can alias another.
///
/// # Errors
///
/// Rejects an invalid bank, duplicate or zero identity, missing local gateway,
/// malformed allocation, or a capacity/index overflow.
#[allow(clippy::too_many_lines)]
pub fn compile_egress_gateway_dataplane(
    admitted: &AdmittedEgressGatewayProjection,
    bank: u8,
) -> Result<EgressDataplaneState, EgressDataplaneError> {
    compile_egress_gateway_dataplane_inner(admitted, bank, None)
}

/// Clock-anchored gateway compiler for temporal FQDN destinations.
///
/// # Errors
///
/// Returns an error when the admitted aggregate, bank, destination evidence,
/// or temporal deadline cannot be lowered exactly.
pub fn compile_egress_gateway_dataplane_at(
    admitted: &AdmittedEgressGatewayProjection,
    bank: u8,
    clock: EgressDataplaneClock,
) -> Result<EgressDataplaneState, EgressDataplaneError> {
    compile_egress_gateway_dataplane_inner(admitted, bank, Some(clock))
}

#[allow(clippy::too_many_lines)]
fn compile_egress_gateway_dataplane_inner(
    admitted: &AdmittedEgressGatewayProjection,
    bank: u8,
    clock: Option<EgressDataplaneClock>,
) -> Result<EgressDataplaneState, EgressDataplaneError> {
    if bank >= EGRESS_BANK_COUNT {
        return Err(EgressDataplaneError::InvalidBank(bank));
    }
    let projection = admitted.projection();
    let mut state = EgressDataplaneState {
        config: EgressMapConfig {
            controller_epoch: projection.controller_epoch,
            projection_revision: projection.revision.get(),
            contract_revision: 0,
            path_revision: 0,
            source_count: 0,
            address_count: 0,
            gateway_count: 0,
            selection_count: 0,
            schema_version: EGRESS_MAP_ABI_VERSION,
            active_bank: bank,
            flags: EGRESS_CONFIG_FLAG_GATEWAY_NAT,
            destination_count: 0,
        },
        sources: Vec::new(),
        ipv4_destinations: Vec::new(),
        ipv6_destinations: Vec::new(),
        addresses: Vec::new(),
        gateways: Vec::new(),
        selections: Vec::new(),
    };
    let mut identities = BTreeSet::new();
    for contract in &projection.source_contracts {
        for plan in &contract.plans {
            let Some((local_index, _)) = plan.gateways.iter().enumerate().find(|(_, candidate)| {
                candidate.node == projection.gateway
                    && candidate.ready
                    && candidate.reachable
                    && candidate.lease_epoch == plan.allocation.lease_epoch
            }) else {
                continue;
            };
            let identity = plan.source.identity;
            if identity.get() == 0 || !identities.insert(identity) {
                return Err(EgressDataplaneError::InvalidHostBank);
            }
            let local_index =
                u16::try_from(local_index).map_err(|_| EgressDataplaneError::CandidateIndex)?;
            let namespace = identity.get();
            let intent_digest = digest16(b"unf.egress-intent.v1\0", plan.intent.uid.as_bytes());
            let mut reserved = [0; 4];
            reserved[..2].copy_from_slice(&local_index.to_ne_bytes());
            state.sources.push((
                EgressSourceKey {
                    source_identity: identity,
                    bank,
                    reserved: [0; 3],
                },
                EgressSourceValue {
                    lease_epoch: plan.allocation.lease_epoch,
                    contract_revision: contract.contract_revision.get(),
                    intent_revision: plan.revisions.intent.get(),
                    identity_revision: plan.revisions.identity.get(),
                    policy_revision: plan.revisions.policy.get(),
                    allocation_revision: plan.revisions.allocation.get(),
                    gateway_revision: plan.revisions.gateway.get(),
                    reachability_revision: plan.revisions.reachability.get(),
                    contract_digest: contract.contract_digest.0,
                    intent_digest,
                    intent_index: namespace,
                    address_count: u16::try_from(plan.allocation.addresses.len())
                        .map_err(|_| EgressDataplaneError::CandidateIndex)?,
                    gateway_count: u16::try_from(plan.gateways.len())
                        .map_err(|_| EgressDataplaneError::CandidateIndex)?,
                    schema_version: EGRESS_MAP_ABI_VERSION,
                    admission: if matches!(plan.destinations, EgressDestinations::DenyAll) {
                        EGRESS_ADMISSION_FENCED
                    } else {
                        EGRESS_ADMISSION_ACTIVE
                    },
                    flags: family_flags(plan, has_standby(plan)) | EGRESS_SOURCE_FLAG_GATEWAY_NAT,
                    reserved,
                },
            ));
            compile_gateway_destinations(
                &mut state,
                plan,
                namespace,
                bank,
                contract.contract_revision.get(),
                intent_digest,
                clock,
            )?;
            for (index, address) in plan.allocation.addresses.iter().enumerate() {
                let index =
                    u16::try_from(index).map_err(|_| EgressDataplaneError::CandidateIndex)?;
                state.addresses.push((
                    candidate_key(namespace, index, family(*address), bank),
                    EgressAddressValue {
                        lease_epoch: plan.allocation.lease_epoch,
                        contract_revision: contract.contract_revision.get(),
                        address: address_bytes(*address),
                        candidate_witness: candidate_witness(
                            b"unf.egress-address-candidate.v1\0",
                            &contract.contract_digest.0,
                            plan.intent.uid.as_bytes(),
                            index,
                            &address_bytes(*address),
                        ),
                        schema_version: EGRESS_MAP_ABI_VERSION,
                        flags: 0,
                        reserved: [0; 4],
                    },
                ));
            }
            for address_family in present_families(plan) {
                let ha_plan = projection
                    .ha_plans
                    .iter()
                    .find(|ha_plan| ha_plan.owner == plan.intent);
                for (gateway_index, gateway) in plan.gateways.iter().enumerate() {
                    let gateway_index = u16::try_from(gateway_index)
                        .map_err(|_| EgressDataplaneError::CandidateIndex)?;
                    state.gateways.push((
                        candidate_key(namespace, gateway_index, address_family, bank),
                        EgressGatewayValue {
                            lease_epoch: plan.allocation.lease_epoch,
                            contract_revision: contract.contract_revision.get(),
                            path_revision: plan.revisions.reachability.get(),
                            transport_address: [0; 16],
                            next_hop_address: [0; 16],
                            gateway_digest: digest16(
                                b"unf.egress-gateway.v1\0",
                                gateway.node.uid.as_bytes(),
                            ),
                            output_interface: 0,
                            mtu: 0,
                            schema_version: EGRESS_MAP_ABI_VERSION,
                            path_mode: 0,
                            flags: 0,
                            reserved: [0; 4],
                        },
                    ));
                }
                for bucket in 0..EGRESS_SELECTION_TABLE_SIZE {
                    let selected = select_bucket_with_ha(plan, address_family, bucket, ha_plan)
                        .map_err(|_| EgressDataplaneError::Selection)?;
                    let address_index = u16::try_from(selected.address_index)
                        .map_err(|_| EgressDataplaneError::CandidateIndex)?;
                    let primary_gateway_index = u16::try_from(selected.primary_gateway_index)
                        .map_err(|_| EgressDataplaneError::CandidateIndex)?;
                    let standby_gateway_index = selected
                        .standby_gateway_index
                        .map(u16::try_from)
                        .transpose()
                        .map_err(|_| EgressDataplaneError::CandidateIndex)?;
                    let flags = if standby_gateway_index.is_some() {
                        EGRESS_SELECTION_FLAG_STANDBY
                    } else {
                        0
                    };
                    let standby = standby_gateway_index.unwrap_or(primary_gateway_index);
                    state.selections.push((
                        EgressSelectionKey {
                            intent_index: namespace,
                            bucket,
                            address_family: family_abi(address_family),
                            bank,
                        },
                        EgressSelectionValue {
                            selection_witness: selection_witness(
                                &contract.contract_digest.0,
                                &plan.intent.uid,
                                address_family,
                                bucket,
                                address_index,
                                primary_gateway_index,
                                standby,
                            ),
                            address_index,
                            primary_gateway_index,
                            standby_gateway_index: standby,
                            schema_version: EGRESS_MAP_ABI_VERSION,
                            flags,
                            reserved: [0; 6],
                        },
                    ));
                }
            }
        }
    }
    state.config.source_count = count("gateway sources", state.sources.len())?;
    state.config.address_count = count("gateway addresses", state.addresses.len())?;
    state.config.gateway_count = count("local gateways", state.gateways.len())?;
    state.config.selection_count = count("gateway selections", state.selections.len())?;
    state.config.destination_count = count(
        "gateway destinations",
        state.ipv4_destinations.len() + state.ipv6_destinations.len(),
    )?;
    if state.selections.len() > MAX_EGRESS_DATAPLANE_SELECTIONS {
        return Err(EgressDataplaneError::Capacity { kind: "selections" });
    }
    Ok(state)
}

fn compile_gateway_destinations(
    state: &mut EgressDataplaneState,
    plan: &EgressBehaviorPlan,
    namespace: u32,
    bank: u8,
    contract_revision: u64,
    intent_digest: [u8; 16],
    clock: Option<EgressDataplaneClock>,
) -> Result<(), EgressDataplaneError> {
    let static_value = static_destination_value(contract_revision, intent_digest);
    let networks = match &plan.destinations {
        EgressDestinations::DenyAll => {
            push_catch_all_destinations(
                state,
                namespace,
                bank,
                deny_destination_value(contract_revision, intent_digest),
            );
            return Ok(());
        }
        EgressDestinations::Any => {
            state.ipv4_destinations.push((
                0,
                EgressIpv4DestinationData {
                    intent_index: namespace,
                    bank,
                    reserved: [0; 3],
                    destination_address: [0; 4],
                },
                static_value,
            ));
            state.ipv6_destinations.push((
                0,
                EgressIpv6DestinationData {
                    intent_index: namespace,
                    bank,
                    reserved: [0; 3],
                    destination_address: [0; 16],
                },
                static_value,
            ));
            return Ok(());
        }
        EgressDestinations::Networks(networks) => networks,
        EgressDestinations::Fqdn(snapshot) => {
            compile_fqdn_destinations(
                state,
                namespace,
                bank,
                contract_revision,
                intent_digest,
                snapshot,
                clock.ok_or(EgressDataplaneError::MissingClock)?,
            )?;
            return Ok(());
        }
    };
    for prefix in networks {
        if !prefix.is_canonical() {
            return Err(EgressDataplaneError::InvalidHostBank);
        }
        match prefix.address {
            IpAddr::V4(address) => state.ipv4_destinations.push((
                u32::from(prefix.prefix_len),
                EgressIpv4DestinationData {
                    intent_index: namespace,
                    bank,
                    reserved: [0; 3],
                    destination_address: address.octets(),
                },
                static_value,
            )),
            IpAddr::V6(address) => state.ipv6_destinations.push((
                u32::from(prefix.prefix_len),
                EgressIpv6DestinationData {
                    intent_index: namespace,
                    bank,
                    reserved: [0; 3],
                    destination_address: address.octets(),
                },
                static_value,
            )),
        }
    }
    Ok(())
}

fn compile_intent_destinations(
    state: &mut EgressDataplaneState,
    host: &EgressGatewayHostBank,
    plan: &EgressBehaviorPlan,
    intent_index: u32,
    bank: u8,
    intent_uid: &str,
    clock: Option<EgressDataplaneClock>,
) -> Result<(), EgressDataplaneError> {
    let contract_revision = host.contract.contract_revision.get();
    let intent_digest = digest16(b"unf.egress-intent.v1\0", intent_uid.as_bytes());
    let value = static_destination_value(contract_revision, intent_digest);
    match &plan.destinations {
        EgressDestinations::DenyAll => {
            push_catch_all_destinations(
                state,
                intent_index,
                bank,
                deny_destination_value(contract_revision, intent_digest),
            );
        }
        EgressDestinations::Any => {
            state.ipv4_destinations.push((
                0,
                EgressIpv4DestinationData {
                    intent_index,
                    bank,
                    reserved: [0; 3],
                    destination_address: [0; 4],
                },
                value,
            ));
            state.ipv6_destinations.push((
                0,
                EgressIpv6DestinationData {
                    intent_index,
                    bank,
                    reserved: [0; 3],
                    destination_address: [0; 16],
                },
                value,
            ));
        }
        EgressDestinations::Networks(networks) => {
            for prefix in networks {
                if !prefix.is_canonical() {
                    return Err(EgressDataplaneError::InvalidHostBank);
                }
                match prefix.address {
                    std::net::IpAddr::V4(address) => state.ipv4_destinations.push((
                        u32::from(prefix.prefix_len),
                        EgressIpv4DestinationData {
                            intent_index,
                            bank,
                            reserved: [0; 3],
                            destination_address: address.octets(),
                        },
                        value,
                    )),
                    std::net::IpAddr::V6(address) => state.ipv6_destinations.push((
                        u32::from(prefix.prefix_len),
                        EgressIpv6DestinationData {
                            intent_index,
                            bank,
                            reserved: [0; 3],
                            destination_address: address.octets(),
                        },
                        value,
                    )),
                }
            }
        }
        EgressDestinations::Fqdn(snapshot) => compile_fqdn_destinations(
            state,
            intent_index,
            bank,
            contract_revision,
            intent_digest,
            snapshot,
            clock.ok_or(EgressDataplaneError::MissingClock)?,
        )?,
    }
    Ok(())
}

const fn static_destination_value(
    contract_revision: u64,
    intent_digest: [u8; 16],
) -> EgressDestinationValue {
    EgressDestinationValue {
        contract_revision,
        intent_digest,
        new_flows_until_monotonic_seconds: EGRESS_DESTINATION_STATIC_DEADLINE,
        established_flows_until_monotonic_seconds: EGRESS_DESTINATION_STATIC_DEADLINE,
    }
}

const fn deny_destination_value(
    contract_revision: u64,
    intent_digest: [u8; 16],
) -> EgressDestinationValue {
    EgressDestinationValue {
        contract_revision,
        intent_digest,
        new_flows_until_monotonic_seconds: EGRESS_DESTINATION_DENY_DEADLINE,
        established_flows_until_monotonic_seconds: EGRESS_DESTINATION_DENY_DEADLINE,
    }
}

fn compile_fqdn_destinations(
    state: &mut EgressDataplaneState,
    intent_index: u32,
    bank: u8,
    contract_revision: u64,
    intent_digest: [u8; 16],
    snapshot: &crate::EgressFqdnSnapshot,
    clock: EgressDataplaneClock,
) -> Result<(), EgressDataplaneError> {
    crate::verify_egress_fqdn_snapshot(snapshot.clone())
        .map_err(|_| EgressDataplaneError::InvalidHostBank)?;
    push_catch_all_destinations(
        state,
        intent_index,
        bank,
        deny_destination_value(contract_revision, intent_digest),
    );
    let mut leases = BTreeMap::<IpAddr, (u64, u64)>::new();
    for lease in &snapshot.leases {
        leases
            .entry(lease.address)
            .and_modify(|current| {
                *current = (*current).max((
                    lease.new_flows_until_unix_seconds,
                    lease.established_flows_until_unix_seconds,
                ));
            })
            .or_insert((
                lease.new_flows_until_unix_seconds,
                lease.established_flows_until_unix_seconds,
            ));
    }
    for (address, (new_until, established_until)) in leases {
        let value = EgressDestinationValue {
            contract_revision,
            intent_digest,
            new_flows_until_monotonic_seconds: monotonic_deadline(new_until, clock)?,
            established_flows_until_monotonic_seconds: monotonic_deadline(
                established_until,
                clock,
            )?,
        };
        match address {
            IpAddr::V4(address) => state.ipv4_destinations.push((
                32,
                EgressIpv4DestinationData {
                    intent_index,
                    bank,
                    reserved: [0; 3],
                    destination_address: address.octets(),
                },
                value,
            )),
            IpAddr::V6(address) => state.ipv6_destinations.push((
                128,
                EgressIpv6DestinationData {
                    intent_index,
                    bank,
                    reserved: [0; 3],
                    destination_address: address.octets(),
                },
                value,
            )),
        }
    }
    Ok(())
}

fn monotonic_deadline(
    unix_deadline: u64,
    clock: EgressDataplaneClock,
) -> Result<u32, EgressDataplaneError> {
    let delta = unix_deadline.saturating_sub(clock.unix_seconds);
    let delta = u32::try_from(delta).map_err(|_| EgressDataplaneError::Deadline)?;
    let deadline = clock
        .monotonic_seconds
        .checked_add(delta)
        .map(|deadline| {
            // Both clocks are supplied with whole-second precision. Close one
            // second early so sampling phase can never extend DNS authority.
            if delta == 0 {
                deadline
            } else {
                deadline.saturating_sub(1)
            }
        })
        .ok_or(EgressDataplaneError::Deadline)?;
    if deadline == EGRESS_DESTINATION_STATIC_DEADLINE {
        return Err(EgressDataplaneError::Deadline);
    }
    Ok(deadline)
}

fn push_catch_all_destinations(
    state: &mut EgressDataplaneState,
    intent_index: u32,
    bank: u8,
    value: EgressDestinationValue,
) {
    state.ipv4_destinations.push((
        0,
        EgressIpv4DestinationData {
            intent_index,
            bank,
            reserved: [0; 3],
            destination_address: [0; 4],
        },
        value,
    ));
    state.ipv6_destinations.push((
        0,
        EgressIpv6DestinationData {
            intent_index,
            bank,
            reserved: [0; 3],
            destination_address: [0; 16],
        },
        value,
    ));
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn compile_intent_candidates(
    state: &mut EgressDataplaneState,
    host: &EgressGatewayHostBank,
    plan: &EgressBehaviorPlan,
    intent_index: u32,
    bank: u8,
    paths: &BTreeMap<PathKey, &EgressPathCertificate>,
    used_paths: &mut BTreeSet<PathKey>,
    coherent_path_revision: &mut Option<Revision>,
    identity: IdentityId,
    ha_plan: Option<&EgressHaPlan>,
) -> Result<(), EgressDataplaneError> {
    for (index, address) in plan.allocation.addresses.iter().enumerate() {
        let index = u16::try_from(index).map_err(|_| EgressDataplaneError::CandidateIndex)?;
        let family = family(*address);
        state.addresses.push((
            candidate_key(intent_index, index, family, bank),
            EgressAddressValue {
                lease_epoch: plan.allocation.lease_epoch,
                contract_revision: host.contract.contract_revision.get(),
                address: address_bytes(*address),
                candidate_witness: candidate_witness(
                    b"unf.egress-address-candidate.v1\0",
                    &host.contract.contract_digest.0,
                    plan.intent.uid.as_bytes(),
                    index,
                    &address_bytes(*address),
                ),
                schema_version: EGRESS_MAP_ABI_VERSION,
                flags: 0,
                reserved: [0; 4],
            },
        ));
    }

    for (index, gateway) in plan.gateways.iter().enumerate() {
        let index = u16::try_from(index).map_err(|_| EgressDataplaneError::CandidateIndex)?;
        for address_family in present_families(plan) {
            let key = PathKey {
                source_uid: host.contract.node.uid.clone(),
                gateway_uid: gateway.node.uid.clone(),
                family: address_family,
                lease_epoch: plan.allocation.lease_epoch,
            };
            let path = paths
                .get(&key)
                .ok_or_else(|| EgressDataplaneError::MissingPath {
                    identity,
                    gateway: gateway.node.uid.clone(),
                    family: address_family,
                })?;
            if path.source != host.contract.node || path.gateway != gateway.node {
                return Err(EgressDataplaneError::InvalidPath);
            }
            match coherent_path_revision {
                Some(revision) if *revision != path.path_revision => {
                    return Err(EgressDataplaneError::PathRevisionMismatch);
                }
                None => *coherent_path_revision = Some(path.path_revision),
                Some(_) => {}
            }
            used_paths.insert(key);
            state.gateways.push((
                candidate_key(intent_index, index, address_family, bank),
                EgressGatewayValue {
                    lease_epoch: plan.allocation.lease_epoch,
                    contract_revision: host.contract.contract_revision.get(),
                    path_revision: path.path_revision.get(),
                    transport_address: address_bytes(path.transport_address),
                    next_hop_address: address_bytes(path.next_hop_address),
                    gateway_digest: digest16(
                        b"unf.egress-gateway.v1\0",
                        gateway.node.uid.as_bytes(),
                    ),
                    output_interface: path.output_interface,
                    mtu: path.mtu,
                    schema_version: EGRESS_MAP_ABI_VERSION,
                    path_mode: path.mode.abi(),
                    flags: 0,
                    reserved: [0; 4],
                },
            ));
        }
    }

    for address_family in present_families(plan) {
        for bucket in 0..EGRESS_SELECTION_TABLE_SIZE {
            let selected = select_bucket_with_ha(plan, address_family, bucket, ha_plan)
                .map_err(|_| EgressDataplaneError::Selection)?;
            let address_index = u16::try_from(selected.address_index)
                .map_err(|_| EgressDataplaneError::CandidateIndex)?;
            let primary_gateway_index = u16::try_from(selected.primary_gateway_index)
                .map_err(|_| EgressDataplaneError::CandidateIndex)?;
            let standby_gateway_index = selected
                .standby_gateway_index
                .map(u16::try_from)
                .transpose()
                .map_err(|_| EgressDataplaneError::CandidateIndex)?;
            let flags = if standby_gateway_index.is_some() {
                EGRESS_SELECTION_FLAG_STANDBY
            } else {
                0
            };
            let standby = standby_gateway_index.unwrap_or(primary_gateway_index);
            let witness = selection_witness(
                &host.contract.contract_digest.0,
                &plan.intent.uid,
                address_family,
                bucket,
                address_index,
                primary_gateway_index,
                standby,
            );
            state.selections.push((
                EgressSelectionKey {
                    intent_index,
                    bucket,
                    address_family: family_abi(address_family),
                    bank,
                },
                EgressSelectionValue {
                    selection_witness: witness,
                    address_index,
                    primary_gateway_index,
                    standby_gateway_index: standby,
                    schema_version: EGRESS_MAP_ABI_VERSION,
                    flags,
                    reserved: [0; 6],
                },
            ));
        }
    }
    Ok(())
}

fn validate_paths(
    paths: &[EgressPathCertificate],
) -> Result<BTreeMap<PathKey, &EgressPathCertificate>, EgressDataplaneError> {
    let mut result = BTreeMap::new();
    for path in paths {
        path.verify_integrity()?;
        let key = PathKey {
            source_uid: path.source.uid.clone(),
            gateway_uid: path.gateway.uid.clone(),
            family: path.address_family,
            lease_epoch: path.lease_epoch,
        };
        if result.insert(key, path).is_some() {
            return Err(EgressDataplaneError::DuplicatePath);
        }
    }
    Ok(result)
}

fn family_flags(plan: &EgressBehaviorPlan, standby: bool) -> u8 {
    let mut flags = 0;
    for address in &plan.allocation.addresses {
        match address {
            IpAddr::V4(_) => flags |= EGRESS_SOURCE_FLAG_IPV4,
            IpAddr::V6(_) => flags |= EGRESS_SOURCE_FLAG_IPV6,
        }
    }
    if standby {
        flags |= EGRESS_SOURCE_FLAG_PRECERTIFIED_STANDBY;
    }
    flags
}

fn has_standby(plan: &EgressBehaviorPlan) -> bool {
    plan.gateways
        .iter()
        .filter(|gateway| gateway.ready && gateway.reachable)
        .count()
        >= 2
}

fn present_families(plan: &EgressBehaviorPlan) -> Vec<AddressFamily> {
    let mut families = BTreeSet::new();
    for address in &plan.allocation.addresses {
        families.insert(family(*address));
    }
    families.into_iter().collect()
}

fn candidate_key(
    intent_index: u32,
    candidate_index: u16,
    address_family: AddressFamily,
    bank: u8,
) -> EgressCandidateKey {
    EgressCandidateKey {
        intent_index,
        candidate_index,
        address_family: family_abi(address_family),
        bank,
    }
}

fn family(address: IpAddr) -> AddressFamily {
    match address {
        IpAddr::V4(_) => AddressFamily::Ipv4,
        IpAddr::V6(_) => AddressFamily::Ipv6,
    }
}

const fn family_abi(address_family: AddressFamily) -> u8 {
    match address_family {
        AddressFamily::Ipv4 => BpfAddressFamily::Ipv4 as u8,
        AddressFamily::Ipv6 => BpfAddressFamily::Ipv6 as u8,
    }
}

fn address_bytes(address: IpAddr) -> [u8; 16] {
    match address {
        IpAddr::V4(address) => {
            let mut bytes = [0; 16];
            bytes[..4].copy_from_slice(&address.octets());
            bytes
        }
        IpAddr::V6(address) => address.octets(),
    }
}

fn unusable(address: IpAddr) -> bool {
    address.is_unspecified() || address.is_loopback() || address.is_multicast()
}

fn digest16(domain: &[u8], material: &[u8]) -> [u8; 16] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(material);
    let digest = hasher.finalize();
    let mut value = [0; 16];
    value.copy_from_slice(&digest[..16]);
    value
}

fn candidate_witness(
    domain: &[u8],
    contract_digest: &[u8; 32],
    intent_uid: &[u8],
    index: u16,
    candidate: &[u8],
) -> [u8; 16] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(contract_digest);
    hasher.update(intent_uid);
    hasher.update(index.to_be_bytes());
    hasher.update(candidate);
    let digest = hasher.finalize();
    let mut value = [0; 16];
    value.copy_from_slice(&digest[..16]);
    value
}

#[allow(clippy::too_many_arguments)]
fn selection_witness(
    contract_digest: &[u8; 32],
    intent_uid: &str,
    address_family: AddressFamily,
    bucket: u16,
    address_index: u16,
    primary_gateway_index: u16,
    standby_gateway_index: u16,
) -> [u8; 16] {
    let mut hasher = Sha256::new();
    hasher.update(b"unf.egress-selection-bucket.v1\0");
    hasher.update(contract_digest);
    hasher.update(intent_uid.as_bytes());
    hasher.update([family_abi(address_family)]);
    hasher.update(bucket.to_be_bytes());
    hasher.update(address_index.to_be_bytes());
    hasher.update(primary_gateway_index.to_be_bytes());
    hasher.update(standby_gateway_index.to_be_bytes());
    let digest = hasher.finalize();
    let mut value = [0; 16];
    value.copy_from_slice(&digest[..16]);
    value
}

fn count(kind: &'static str, value: usize) -> Result<u32, EgressDataplaneError> {
    u32::try_from(value).map_err(|_| EgressDataplaneError::Capacity { kind })
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use unf_ebpf_common::{
        AddressFamily as BpfAddressFamily, EGRESS_ADMISSION_ACTIVE, EGRESS_ADMISSION_FENCED,
        EGRESS_SELECTION_FLAG_STANDBY, EGRESS_SELECTION_TABLE_SIZE,
        EGRESS_SOURCE_FLAG_PRECERTIFIED_STANDBY,
    };

    use super::*;
    use crate::distribution::test_support::{advertisement, fixture, node, principal};
    use crate::{
        AdmittedEgressProjection, EGRESS_PROTOCOL_TCP, EgressAddressLease, EgressBehaviorContract,
        EgressDnsAnswer, EgressDnsObservation, EgressDnsObservationSource, EgressFlowProof,
        EgressFqdnDestinationSpec, EgressFqdnPattern, EgressFqdnPolicy, EgressGatewayFact,
        EgressGatewayProjection, EgressHaCandidate, EgressNodeProjection, EgressOriginalFlow,
        EgressProviderRef, compile_egress_fqdn_snapshot, compile_egress_ha_plan,
    };

    fn ip(value: &str) -> IpAddr {
        value.parse().expect("valid address")
    }

    fn ha_plan(model: &crate::EgressModel, facts: &crate::EgressContractFacts) -> EgressHaPlan {
        let intent = model.intents[0].clone();
        let allocation = &facts.allocations[0];
        let lease = EgressAddressLease {
            intent,
            pool: None,
            provider: EgressProviderRef {
                name: "static".to_owned(),
                instance: "lab".to_owned(),
            },
            addresses: allocation.addresses.clone(),
            lease_epoch: allocation.lease_epoch,
            intent_epoch: 1,
            intent_revision: facts.revisions.intent,
            allocation_revision: facts.revisions.allocation,
        };
        let candidates = facts
            .gateways
            .iter()
            .map(|gateway| EgressHaCandidate {
                node: gateway.node.clone(),
                capacity_units: 1,
                failure_domains: BTreeMap::new(),
            })
            .collect();
        compile_egress_ha_plan(&lease, candidates, None, facts.revisions.gateway).expect("HA plan")
    }

    fn source_projection() -> AdmittedEgressProjection {
        let (model, mut facts, _) = fixture();
        facts.gateways.push(EgressGatewayFact {
            intent_uid: "intent-uid".to_owned(),
            rank: 1,
            node: node("gateway-b"),
            lease_epoch: 7,
            ready: true,
            reachable: true,
        });
        let contract =
            EgressBehaviorContract::issue(&model, &facts, node("worker-a"), Revision::new(20))
                .expect("two-gateway contract");
        let ha_plan = ha_plan(&model, &facts);
        EgressNodeProjection::issue_with_ha(
            &principal("worker-a"),
            &advertisement(),
            10,
            Revision::new(4),
            contract,
            vec![ha_plan],
        )
        .expect("source projection")
        .admit(&principal("worker-a"), &advertisement(), &model, &facts)
        .expect("admitted source")
    }

    fn unresolved_fqdn_projection() -> AdmittedEgressProjection {
        let (mut model, mut facts, _) = fixture();
        model.intents[0].destinations = EgressDestinations::DenyAll;
        model.intents[0].fqdn = Some(EgressFqdnDestinationSpec {
            patterns: vec![EgressFqdnPattern::Exact("api.example.test".to_owned())],
            view: crate::DEFAULT_EGRESS_FQDN_VIEW.to_owned(),
            required_observers: crate::DEFAULT_EGRESS_FQDN_REQUIRED_OBSERVERS,
            max_addresses: crate::DEFAULT_EGRESS_FQDN_MAX_ADDRESSES,
            max_ttl_seconds: crate::DEFAULT_EGRESS_FQDN_MAX_TTL_SECONDS,
            established_flow_grace_seconds: crate::DEFAULT_EGRESS_FQDN_ESTABLISHED_GRACE_SECONDS,
        });
        facts.gateways.push(EgressGatewayFact {
            intent_uid: "intent-uid".to_owned(),
            rank: 1,
            node: node("gateway-b"),
            lease_epoch: 7,
            ready: true,
            reachable: true,
        });
        let contract =
            EgressBehaviorContract::issue(&model, &facts, node("worker-a"), Revision::new(20))
                .expect("unresolved FQDN contract");
        let ha_plan = ha_plan(&model, &facts);
        EgressNodeProjection::issue_with_ha(
            &principal("worker-a"),
            &advertisement(),
            10,
            Revision::new(4),
            contract,
            vec![ha_plan],
        )
        .expect("unresolved FQDN projection")
        .admit(&principal("worker-a"), &advertisement(), &model, &facts)
        .expect("admitted unresolved FQDN source")
    }

    fn two_source_projection() -> AdmittedEgressProjection {
        let (model, mut facts, _) = fixture();
        facts.gateways.push(EgressGatewayFact {
            intent_uid: "intent-uid".to_owned(),
            rank: 1,
            node: node("gateway-b"),
            lease_epoch: 7,
            ready: true,
            reachable: true,
        });
        let mut second_source = facts.sources[0].clone();
        second_source.identity = IdentityId::new(43);
        second_source.workload = "ledger-1".to_owned();
        second_source.workload_uid = "ledger-uid-2".to_owned();
        facts.sources.push(second_source);
        let mut second_policy = facts.policies[0].clone();
        second_policy.identity = IdentityId::new(43);
        facts.policies.push(second_policy);
        let contract =
            EgressBehaviorContract::issue(&model, &facts, node("worker-a"), Revision::new(20))
                .expect("two-source contract");
        let ha_plan = ha_plan(&model, &facts);
        EgressNodeProjection::issue_with_ha(
            &principal("worker-a"),
            &advertisement(),
            10,
            Revision::new(4),
            contract,
            vec![ha_plan],
        )
        .expect("source projection")
        .admit(&principal("worker-a"), &advertisement(), &model, &facts)
        .expect("admitted source")
    }

    #[test]
    fn gateway_nat_bank_is_identity_namespaced_and_heterogeneous() {
        let source = two_source_projection();
        let gateway_principal = principal("gateway-a");
        let admitted = EgressGatewayProjection::issue(
            &gateway_principal,
            &advertisement(),
            10,
            Revision::new(9),
            &[source],
        )
        .expect("gateway projection")
        .admit(&gateway_principal, &advertisement())
        .expect("admitted gateway projection");
        let state = compile_egress_gateway_dataplane(&admitted, 1).expect("gateway NAT bank");
        assert_eq!(
            state.config.flags,
            unf_ebpf_common::EGRESS_CONFIG_FLAG_GATEWAY_NAT
        );
        assert_eq!(state.config.contract_revision, 0);
        assert_eq!(state.config.path_revision, 0);
        assert_eq!(state.sources.len(), 2);
        assert_eq!(state.ipv4_destinations.len(), 2);
        assert_eq!(state.ipv6_destinations.len(), 2);
        for (key, value) in &state.sources {
            assert_eq!(value.intent_index, key.source_identity.get());
            assert_ne!(
                value.flags & unf_ebpf_common::EGRESS_SOURCE_FLAG_GATEWAY_NAT,
                0
            );
            assert_eq!(key.bank, 1);
        }
        let namespaces = state
            .selections
            .iter()
            .map(|(key, _)| key.intent_index)
            .collect::<BTreeSet<_>>();
        assert_eq!(namespaces, BTreeSet::from([42, 43]));
    }

    fn guard(projection: &AdmittedEgressProjection, active: bool) -> EgressAdmissionGuard {
        let plan = &projection.projection().contract.plans[0];
        let mut guard = EgressAdmissionGuard::default();
        guard
            .fence(
                plan.source.identity,
                plan.intent.clone(),
                plan.revisions.intent,
            )
            .expect("fence");
        if active {
            guard
                .activate(plan.source.identity, projection)
                .expect("activate");
        }
        guard
    }

    fn path(
        source: &EgressNode,
        gateway: &EgressNode,
        family: AddressFamily,
        transport: &str,
        output_interface: u32,
    ) -> EgressPathCertificate {
        EgressPathCertificate::issue(
            source.clone(),
            gateway.clone(),
            family,
            ip(transport),
            ip(transport),
            output_interface,
            1_500,
            EgressPathMode::DirectNeighbor,
            Revision::new(30),
            7,
        )
        .expect("valid path")
    }

    fn paths(projection: &AdmittedEgressProjection) -> Vec<EgressPathCertificate> {
        let contract = &projection.projection().contract;
        let gateways = &contract.plans[0].gateways;
        vec![
            path(
                &contract.node,
                &gateways[0].node,
                AddressFamily::Ipv4,
                "10.0.0.2",
                2,
            ),
            path(
                &contract.node,
                &gateways[0].node,
                AddressFamily::Ipv6,
                "fd00::2",
                2,
            ),
            path(
                &contract.node,
                &gateways[1].node,
                AddressFamily::Ipv4,
                "10.0.0.3",
                3,
            ),
            path(
                &contract.node,
                &gateways[1].node,
                AddressFamily::Ipv6,
                "fd00::3",
                3,
            ),
        ]
    }

    fn flow(identity: IdentityId) -> EgressOriginalFlow {
        EgressOriginalFlow {
            identity,
            source_address: ip("10.244.0.20"),
            destination_address: ip("198.51.100.30"),
            source_port: 30_000,
            destination_port: 443,
            protocol: EGRESS_PROTOCOL_TCP,
            fragmented: false,
        }
    }

    #[test]
    fn fenced_identity_lowers_to_drop_without_candidates_or_paths() {
        let projection = source_projection();
        let host = EgressGatewayHostBank::compile(&projection).expect("host bank");
        let state = compile_egress_dataplane(&host, &guard(&projection, false), &[], 1)
            .expect("fenced state");
        assert_eq!(state.sources.len(), 1);
        assert_eq!(state.sources[0].1.admission, EGRESS_ADMISSION_FENCED);
        assert!(state.addresses.is_empty());
        assert!(state.gateways.is_empty());
        assert!(state.selections.is_empty());
        assert_eq!(state.ipv4_destinations.len(), 1);
        assert_eq!(state.ipv6_destinations.len(), 1);
        assert_eq!(state.config.destination_count, 2);
        assert_eq!(state.config.path_revision, 0);
    }

    #[test]
    fn unresolved_fqdn_owns_both_families_and_fences_even_an_active_guard() {
        let projection = unresolved_fqdn_projection();
        let host = EgressGatewayHostBank::compile(&projection).expect("host bank");
        let state = compile_egress_dataplane(&host, &guard(&projection, true), &[], 1)
            .expect("fail-closed unresolved FQDN state");
        assert_eq!(state.sources.len(), 1);
        assert_eq!(state.sources[0].1.admission, EGRESS_ADMISSION_FENCED);
        assert!(state.addresses.is_empty());
        assert!(state.gateways.is_empty());
        assert!(state.selections.is_empty());
        assert_eq!(state.ipv4_destinations[0].0, 0);
        assert_eq!(state.ipv6_destinations[0].0, 0);
        assert_eq!(state.config.destination_count, 2);
        assert_eq!(state.config.path_revision, 0);

        let gateway_principal = principal("gateway-a");
        let gateway = EgressGatewayProjection::issue(
            &gateway_principal,
            &advertisement(),
            10,
            Revision::new(9),
            &[projection],
        )
        .expect("gateway projection")
        .admit(&gateway_principal, &advertisement())
        .expect("admitted gateway projection");
        let gateway_state =
            compile_egress_gateway_dataplane(&gateway, 1).expect("gateway fail-closed bank");
        assert_eq!(gateway_state.sources.len(), 1);
        assert_eq!(
            gateway_state.sources[0].1.admission,
            EGRESS_ADMISSION_FENCED
        );
        assert_eq!(gateway_state.ipv4_destinations[0].0, 0);
        assert_eq!(gateway_state.ipv6_destinations[0].0, 0);
        assert_eq!(gateway_state.config.destination_count, 2);
    }

    #[test]
    fn plr_snapshot_lowers_to_exact_temporal_authority_plus_dual_stack_deny() {
        const NOW: u64 = 1_000_000;
        let (mut model, mut facts, _) = fixture();
        let spec = EgressFqdnDestinationSpec {
            patterns: vec![EgressFqdnPattern::Exact("api.example.test".to_owned())],
            view: crate::DEFAULT_EGRESS_FQDN_VIEW.to_owned(),
            required_observers: 1,
            max_addresses: 8,
            max_ttl_seconds: 300,
            established_flow_grace_seconds: 30,
        };
        let address: IpAddr = "203.0.113.77".parse().unwrap();
        let snapshot = compile_egress_fqdn_snapshot(
            EgressFqdnPolicy {
                revision: Revision::new(9),
                owner: model.intents[0].owner.clone(),
                patterns: spec.patterns.clone(),
                view: spec.view.clone(),
                required_observers: spec.required_observers,
                max_addresses: spec.max_addresses,
                max_ttl_seconds: spec.max_ttl_seconds,
                established_flow_grace_seconds: spec.established_flow_grace_seconds,
            },
            vec![EgressDnsObservation {
                source: EgressDnsObservationSource {
                    observer_uid: "worker-a-uid".to_owned(),
                    resolver: "10.96.0.10".parse().unwrap(),
                    view: spec.view.clone(),
                    source_epoch: 1,
                },
                observation_revision: Revision::new(1),
                query_name: "api.example.test".to_owned(),
                canonical_chain: vec!["api.example.test".to_owned()],
                answers: vec![EgressDnsAnswer {
                    address,
                    ttl_seconds: 60,
                }],
                observed_at_unix_seconds: NOW,
            }],
            NOW,
        )
        .unwrap()
        .snapshot;
        model.intents[0].fqdn = Some(spec);
        model.intents[0].destinations = EgressDestinations::Fqdn(snapshot);
        facts.gateways.push(EgressGatewayFact {
            intent_uid: "intent-uid".to_owned(),
            rank: 1,
            node: node("gateway-b"),
            lease_epoch: 7,
            ready: true,
            reachable: true,
        });
        let contract =
            EgressBehaviorContract::issue(&model, &facts, node("worker-a"), Revision::new(20))
                .unwrap();
        let projection = EgressNodeProjection::issue_with_ha(
            &principal("worker-a"),
            &advertisement(),
            10,
            Revision::new(4),
            contract,
            vec![ha_plan(&model, &facts)],
        )
        .unwrap()
        .admit(&principal("worker-a"), &advertisement(), &model, &facts)
        .unwrap();
        let host = EgressGatewayHostBank::compile(&projection).unwrap();
        let state = compile_egress_dataplane_at(
            &host,
            &guard(&projection, true),
            &paths(&projection),
            1,
            EgressDataplaneClock {
                unix_seconds: NOW,
                monotonic_seconds: 10_000,
            },
        )
        .unwrap();
        assert_eq!(state.sources[0].1.admission, EGRESS_ADMISSION_ACTIVE);
        assert_eq!(state.ipv4_destinations.len(), 2);
        assert_eq!(state.ipv6_destinations.len(), 1);
        let (_, data, value) = state
            .ipv4_destinations
            .iter()
            .find(|(prefix, _, _)| *prefix == 32)
            .unwrap();
        assert_eq!(data.destination_address, [203, 0, 113, 77]);
        assert_eq!(value.new_flows_until_monotonic_seconds, 10_059);
        assert_eq!(value.established_flows_until_monotonic_seconds, 10_089);
        assert!(state.ipv4_destinations.iter().any(|(prefix, _, value)| {
            *prefix == 0 && value.new_flows_until_monotonic_seconds == 0
        }));
        assert!(
            compile_egress_dataplane(&host, &guard(&projection, true), &paths(&projection), 0)
                .is_err()
        );
    }

    #[test]
    fn destination_prefixes_are_exact_banked_and_contract_bound() {
        let (mut model, facts, _) = fixture();
        model.intents[0].destinations = EgressDestinations::Networks(vec![
            crate::IpPrefix {
                address: ip("198.51.100.0"),
                prefix_len: 24,
            },
            crate::IpPrefix {
                address: ip("2001:db8:42::"),
                prefix_len: 64,
            },
        ]);
        let contract =
            EgressBehaviorContract::issue(&model, &facts, node("worker-a"), Revision::new(20))
                .expect("destination-scoped contract");
        let projection = EgressNodeProjection::issue(
            &principal("worker-a"),
            &advertisement(),
            10,
            Revision::new(4),
            contract,
        )
        .expect("source projection")
        .admit(&principal("worker-a"), &advertisement(), &model, &facts)
        .expect("admitted source");
        let host = EgressGatewayHostBank::compile(&projection).expect("host bank");
        let state = compile_egress_dataplane(&host, &guard(&projection, false), &[], 1)
            .expect("fenced destination state");
        assert_eq!(state.config.destination_count, 2);
        let (prefix, data, value) = state.ipv4_destinations[0];
        assert_eq!(prefix, 24);
        assert_eq!(data.intent_index, 0);
        assert_eq!(data.bank, 1);
        assert_eq!(data.destination_address, [198, 51, 100, 0]);
        assert_eq!(
            value.contract_revision,
            host.contract.contract_revision.get()
        );
        assert_eq!(value.intent_digest, state.sources[0].1.intent_digest);
        let (prefix, data, value) = state.ipv6_destinations[0];
        assert_eq!(prefix, 64);
        assert_eq!(data.intent_index, 0);
        assert_eq!(data.bank, 1);
        assert_eq!(
            data.destination_address,
            "2001:db8:42::"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
                .octets()
        );
        assert_eq!(value.intent_digest, state.sources[0].1.intent_digest);
    }

    #[test]
    fn active_dual_stack_state_precertifies_primary_and_standby_buckets() {
        let projection = source_projection();
        let host = EgressGatewayHostBank::compile(&projection).expect("host bank");
        let guard = guard(&projection, true);
        let state =
            compile_egress_dataplane(&host, &guard, &paths(&projection), 1).expect("active state");
        assert_eq!(state.sources.len(), 1);
        assert_eq!(state.sources[0].1.admission, EGRESS_ADMISSION_ACTIVE);
        assert_ne!(
            state.sources[0].1.flags & EGRESS_SOURCE_FLAG_PRECERTIFIED_STANDBY,
            0
        );
        assert_eq!(state.addresses.len(), 2);
        assert_eq!(state.gateways.len(), 4);
        assert_eq!(state.config.destination_count, 2);
        assert_eq!(
            state.selections.len(),
            usize::from(EGRESS_SELECTION_TABLE_SIZE) * 2
        );
        assert_eq!(state.config.path_revision, 30);
        assert!(state.selections.iter().all(|(_, value)| {
            value.flags & EGRESS_SELECTION_FLAG_STANDBY != 0
                && value.primary_gateway_index != value.standby_gateway_index
                && value.selection_witness != [0; 16]
        }));
        let ha = &projection.projection().ha_plans[0];
        let owner = &ha.assignments[0].gateway;
        let owner_index = u16::try_from(
            projection.projection().contract.plans[0]
                .gateways
                .iter()
                .position(|gateway| gateway.node == *owner)
                .unwrap(),
        )
        .unwrap();
        assert!(
            state
                .selections
                .iter()
                .all(|(_, value)| value.primary_gateway_index == owner_index),
            "every family of the dual-stack shard selects its exclusive CCR owner"
        );
    }

    #[test]
    fn identities_sharing_intent_share_candidates_and_rendezvous_tables() {
        let projection = two_source_projection();
        let host = EgressGatewayHostBank::compile(&projection).expect("host bank");
        let mut guard = EgressAdmissionGuard::default();
        for plan in &projection.projection().contract.plans {
            guard
                .fence(
                    plan.source.identity,
                    plan.intent.clone(),
                    plan.revisions.intent,
                )
                .expect("fence");
            guard
                .activate(plan.source.identity, &projection)
                .expect("activate");
        }
        let state = compile_egress_dataplane(&host, &guard, &paths(&projection), 1)
            .expect("shared intent state");
        assert_eq!(state.sources.len(), 2);
        assert_eq!(state.sources[0].1.intent_index, 0);
        assert_eq!(state.sources[1].1.intent_index, 0);
        assert_eq!(state.addresses.len(), 2);
        assert_eq!(state.gateways.len(), 4);
        assert_eq!(
            state.selections.len(),
            usize::from(EGRESS_SELECTION_TABLE_SIZE) * 2
        );
    }

    #[test]
    fn proof_and_compiled_bucket_choose_the_exact_same_path() {
        let projection = source_projection();
        let plan = &projection.projection().contract.plans[0];
        let guard = guard(&projection, true);
        let host = EgressGatewayHostBank::compile(&projection).expect("host bank");
        let state = compile_egress_dataplane(&host, &guard, &paths(&projection), 0)
            .expect("compiled state");
        let original = flow(plan.source.identity);
        let proof = EgressFlowProof::issue(&projection, &guard, original).expect("proof");
        let bucket = crate::flow_bucket(original);
        let (_, selected) = state
            .selections
            .iter()
            .find(|(key, _)| {
                key.bucket == bucket
                    && key.address_family == BpfAddressFamily::Ipv4 as u8
                    && key.bank == 0
            })
            .expect("compiled bucket");
        assert_eq!(
            plan.allocation.addresses[usize::from(selected.address_index)],
            proof.egress_address
        );
        assert_eq!(
            plan.gateways[usize::from(selected.primary_gateway_index)]
                .node
                .uid,
            proof.gateway.uid
        );
    }

    #[test]
    fn missing_duplicate_foreign_and_revision_skewed_paths_fail_closed() {
        let projection = source_projection();
        let host = EgressGatewayHostBank::compile(&projection).expect("host bank");
        let guard = guard(&projection, true);
        let mut certificates = paths(&projection);
        certificates.pop();
        assert!(matches!(
            compile_egress_dataplane(&host, &guard, &certificates, 0),
            Err(EgressDataplaneError::MissingPath { .. })
        ));

        let mut duplicate = paths(&projection);
        duplicate.push(duplicate[0].clone());
        assert_eq!(
            compile_egress_dataplane(&host, &guard, &duplicate, 0),
            Err(EgressDataplaneError::DuplicatePath)
        );

        let mut skewed = paths(&projection);
        skewed[0].path_revision = Revision::new(31);
        skewed[0].certificate_digest = skewed[0].digest().expect("reseal skewed path");
        assert_eq!(
            compile_egress_dataplane(&host, &guard, &skewed, 0),
            Err(EgressDataplaneError::PathRevisionMismatch)
        );

        let mut foreign = paths(&projection);
        foreign.push(path(
            &host.contract.node,
            &node("gateway-foreign"),
            AddressFamily::Ipv4,
            "10.0.0.4",
            4,
        ));
        assert_eq!(
            compile_egress_dataplane(&host, &guard, &foreign, 0),
            Err(EgressDataplaneError::UnusedPath)
        );
    }

    #[test]
    fn path_wire_shape_and_physical_bounds_are_strict() {
        let projection = source_projection();
        let host = EgressGatewayHostBank::compile(&projection).expect("host bank");
        let guard = guard(&projection, true);
        let mut invalid = paths(&projection);
        invalid[0].mtu = 1_279;
        assert_eq!(
            compile_egress_dataplane(&host, &guard, &invalid, 0),
            Err(EgressDataplaneError::InvalidPath)
        );
        let mut value = serde_json::to_value(&paths(&projection)[0]).expect("encode path");
        value
            .as_object_mut()
            .expect("object")
            .insert("trusted".to_owned(), serde_json::json!(true));
        assert!(serde_json::from_value::<EgressPathCertificate>(value).is_err());

        let source = host.contract.node.clone();
        let local = EgressPathCertificate::issue(
            source.clone(),
            source.clone(),
            AddressFamily::Ipv4,
            ip("10.0.0.1"),
            ip("10.0.0.1"),
            2,
            1_500,
            EgressPathMode::LocalGateway,
            Revision::new(30),
            7,
        )
        .expect("same-Node fast path is explicit and sealed");
        assert!(local.verify_integrity().is_ok());
        assert!(
            EgressPathCertificate::issue(
                source.clone(),
                source,
                AddressFamily::Ipv4,
                ip("10.0.0.1"),
                ip("10.0.0.1"),
                2,
                1_500,
                EgressPathMode::DirectNeighbor,
                Revision::new(30),
                7,
            )
            .is_err()
        );
    }
}
