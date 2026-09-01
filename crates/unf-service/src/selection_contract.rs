//! Machine-verifiable contracts for per-Node Service selection plans.
//!
//! The contract is deliberately a userspace boundary. It binds one canonical
//! selection plan to authoritative Service and topology revisions, checks the
//! plan independently against normalized Service intent, records a bounded
//! single-failure envelope, and derives compact decision witnesses. It does not
//! select a backend per packet or claim formal verification of the compiler.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::net::IpAddr;

use serde::de::Visitor;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use unf_common::{BackendId, Protocol, Revision, ServiceId};

pub use unf_common::SELECTION_CONTRACT_SCHEMA_VERSION;

use crate::{
    AddressFamily, ServiceForwardingMode, ServiceIr, ServiceIrError, ServiceSelectionAlgorithm,
    ServiceSessionAffinity, ServiceSnapshot, ServiceTrafficDistribution, ServiceTrafficPolicy,
};

/// Maximum number of exact frontend plans carried by one per-Node contract.
pub const MAX_SELECTION_CONTRACT_PLANS: usize = 131_072;
/// Maximum number of explicit observations retained in a failure envelope.
pub const MAX_FAILURE_ENVELOPE_OBSERVATIONS: usize = 4_096;

/// A SHA-256 commitment rendered as 64 lowercase hexadecimal characters.
#[derive(Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SelectionDigest([u8; 32]);

impl SelectionDigest {
    /// Returns the fixed-width digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for SelectionDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl fmt::Display for SelectionDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_hex(formatter, &self.0)
    }
}

impl Serialize for SelectionDigest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for SelectionDigest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer
            .deserialize_str(HexVisitor::<32>(std::marker::PhantomData))
            .map(Self)
    }
}

/// Compact identifier emitted with a decision and resolved against its exact
/// retained contract. It is provenance, not an authorization token.
#[derive(Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SelectionDecisionWitness([u8; 16]);

impl SelectionDecisionWitness {
    /// Returns the fixed-width witness bytes intended for bounded event state.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl fmt::Debug for SelectionDecisionWitness {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl fmt::Display for SelectionDecisionWitness {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_hex(formatter, &self.0)
    }
}

impl Serialize for SelectionDecisionWitness {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for SelectionDecisionWitness {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer
            .deserialize_str(HexVisitor::<16>(std::marker::PhantomData))
            .map(Self)
    }
}

struct HexVisitor<const N: usize>(std::marker::PhantomData<[u8; N]>);

impl<const N: usize> Visitor<'_> for HexVisitor<N> {
    type Value = [u8; N];

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "exactly {} lowercase hexadecimal characters",
            N * 2
        )
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        if value.len() != N * 2 {
            return Err(E::invalid_length(value.len(), &self));
        }
        let mut decoded = [0_u8; N];
        for (index, output) in decoded.iter_mut().enumerate() {
            let offset = index * 2;
            let high = decode_nibble(value.as_bytes()[offset]).ok_or_else(|| {
                E::custom("digest must contain only lowercase hexadecimal characters")
            })?;
            let low = decode_nibble(value.as_bytes()[offset + 1]).ok_or_else(|| {
                E::custom("digest must contain only lowercase hexadecimal characters")
            })?;
            *output = (high << 4) | low;
        }
        Ok(decoded)
    }
}

fn decode_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

fn write_hex(formatter: &mut fmt::Formatter<'_>, bytes: &[u8]) -> fmt::Result {
    for byte in bytes {
        write!(formatter, "{byte:02x}")?;
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SelectionCapability {
    StableHash,
    Maglev,
    Nat,
    DsrIpv4,
    DsrIpv6,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SelectionNode {
    pub name: String,
    pub uid: String,
    pub zone: Option<String>,
    pub capabilities: BTreeSet<SelectionCapability>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum SelectionFrontend {
    ClusterIp {
        address: IpAddr,
        port: u16,
        protocol: Protocol,
    },
    NodePort {
        family: AddressFamily,
        node_port: u16,
        service_port: u16,
        protocol: Protocol,
    },
    LoadBalancer {
        family: AddressFamily,
        service_port: u16,
        protocol: Protocol,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SelectionPlanKey {
    pub service_id: ServiceId,
    pub frontend: SelectionFrontend,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SelectionTier {
    SameNode,
    SameZone,
    Cluster,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SelectionEligibilityTier {
    pub tier: SelectionTier,
    pub backend_ids: Vec<BackendId>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ServiceSelectionPlan {
    pub key: SelectionPlanKey,
    pub traffic_policy: ServiceTrafficPolicy,
    pub traffic_distribution: ServiceTrafficDistribution,
    pub session_affinity: ServiceSessionAffinity,
    pub selection_algorithm: ServiceSelectionAlgorithm,
    pub forwarding_mode: ServiceForwardingMode,
    pub tiers: Vec<SelectionEligibilityTier>,
}

impl ServiceSelectionPlan {
    /// Resolves the first non-empty eligibility tier. When every tier is empty,
    /// the final tier is retained so a strict-local or exhausted fallback drop
    /// still has exact provenance.
    #[must_use]
    pub fn selected_tier(&self) -> Option<&SelectionEligibilityTier> {
        self.tiers
            .iter()
            .find(|tier| !tier.backend_ids.is_empty())
            .or_else(|| self.tiers.last())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SelectionInvariant {
    SourceRevisionBound,
    NodeOwnershipBound,
    PlanKeysUnique,
    FrontendsExact,
    IntentExact,
    StrictPolicyFirst,
    TopologyOrderExact,
    BackendsEligible,
    FamilyProtocolExact,
    CapabilitiesAdmitted,
    StateBounded,
    FailureEnvelopeBounded,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SelectionInvariantReport {
    pub verified: Vec<SelectionInvariant>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum SelectionFailure {
    CurrentState,
    EndpointLoss {
        service_id: ServiceId,
        backend_id: BackendId,
    },
    NodeLoss {
        node_name: String,
    },
    ZoneLoss {
        zone: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(
    tag = "outcome",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum SelectionFailureOutcome {
    Available {
        selected_tier: SelectionTier,
        remaining_backends: u32,
    },
    ExpectedPolicyDrop,
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SelectionFailureObservation {
    pub plan: SelectionPlanKey,
    pub failure: SelectionFailure,
    pub outcome: SelectionFailureOutcome,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SelectionFailureEnvelope {
    pub observations: Vec<SelectionFailureObservation>,
    pub total_observations: u64,
    pub truncated: bool,
}

/// Hash-addressed, independently reproducible selection contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct NetworkBehaviorContract {
    pub schema_version: u16,
    pub source_epoch: u64,
    pub service_revision: Revision,
    pub topology_revision: Revision,
    pub contract_revision: Revision,
    pub node: SelectionNode,
    pub plans: Vec<ServiceSelectionPlan>,
    pub invariant_report: SelectionInvariantReport,
    pub failure_envelope: SelectionFailureEnvelope,
    pub plan_digest: SelectionDigest,
    pub contract_digest: SelectionDigest,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SelectionContractError {
    #[error(transparent)]
    InvalidServiceSnapshot(#[from] ServiceIrError),
    #[error("unsupported selection contract schema {actual}; expected {expected}")]
    UnsupportedSchema { actual: u16, expected: u16 },
    #[error("selection contract revisions and source epoch must be nonzero")]
    ZeroRevision,
    #[error("selection contract source tuple differs from the Service snapshot")]
    SourceTupleMismatch,
    #[error("selection contract Node identity, zone, or capabilities differ from local facts")]
    NodeTupleMismatch,
    #[error("selection contract has invalid {field}")]
    InvalidNodeIdentity { field: &'static str },
    #[error("selection contract has {actual} plans; limit is {limit}")]
    TooManyPlans { actual: usize, limit: usize },
    #[error("selection contract repeats plan key {0:?}")]
    DuplicatePlan(SelectionPlanKey),
    #[error("selection plan references unknown service {0:?}")]
    UnknownService(ServiceId),
    #[error("selection plan references a frontend not owned by service {0:?}")]
    UnknownFrontend(ServiceId),
    #[error("selection plan {plan:?} differs from source intent field {field}")]
    IntentMismatch {
        plan: SelectionPlanKey,
        field: &'static str,
    },
    #[error("selection plan {plan:?} has invalid tier order")]
    TierOrderMismatch { plan: SelectionPlanKey },
    #[error("selection plan {plan:?} has a duplicate backend in tier {tier:?}")]
    DuplicateTierBackend {
        plan: SelectionPlanKey,
        tier: SelectionTier,
    },
    #[error("selection plan {plan:?} has an incorrect backend set for tier {tier:?}")]
    TierBackendMismatch {
        plan: SelectionPlanKey,
        tier: SelectionTier,
    },
    #[error("selection plan {plan:?} requires unavailable capability {capability:?}")]
    MissingCapability {
        plan: SelectionPlanKey,
        capability: SelectionCapability,
    },
    #[error("selection contract encoding failed: {0}")]
    CanonicalEncoding(String),
    #[error("selection contract is not canonically ordered")]
    NonCanonical,
    #[error("selection plan digest does not match its canonical state")]
    PlanDigestMismatch,
    #[error("selection invariant report does not match independent validation")]
    InvariantReportMismatch,
    #[error("selection failure envelope does not match independent simulation")]
    FailureEnvelopeMismatch,
    #[error("selection contract digest does not match its canonical state")]
    ContractDigestMismatch,
    #[error("selection decision witness references an unknown plan")]
    UnknownWitnessPlan,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PlanDigestMaterial<'a> {
    schema_version: u16,
    source_epoch: u64,
    service_revision: Revision,
    topology_revision: Revision,
    contract_revision: Revision,
    node: &'a SelectionNode,
    plans: &'a [ServiceSelectionPlan],
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ContractDigestMaterial<'a> {
    plan: PlanDigestMaterial<'a>,
    invariant_report: &'a SelectionInvariantReport,
    failure_envelope: &'a SelectionFailureEnvelope,
    plan_digest: SelectionDigest,
}

struct ResolvedFrontend<'a> {
    service: &'a ServiceIr,
    traffic_policy: ServiceTrafficPolicy,
    family: AddressFamily,
    protocol: Protocol,
    backend_ids: &'a [BackendId],
}

impl NetworkBehaviorContract {
    /// Returns the exact canonical plan for one frontend.
    #[must_use]
    pub fn plan(&self, key: &SelectionPlanKey) -> Option<&ServiceSelectionPlan> {
        self.plans
            .binary_search_by(|plan| plan.key.cmp(key))
            .ok()
            .map(|index| &self.plans[index])
    }

    /// Compiles every exact frontend in a normalized Service snapshot into one
    /// canonical per-Node contract.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::issue`] when source intent, Node
    /// capabilities, or derived eligibility state cannot be admitted.
    pub fn compile(
        snapshot: &ServiceSnapshot,
        topology_revision: Revision,
        contract_revision: Revision,
        node: SelectionNode,
    ) -> Result<Self, SelectionContractError> {
        let snapshot = snapshot.clone().validate_and_normalize()?;
        let mut plans = Vec::new();
        for service in &snapshot.services {
            plans.extend(service.frontends.iter().map(|frontend| SelectionPlanKey {
                service_id: service.id,
                frontend: SelectionFrontend::ClusterIp {
                    address: frontend.address,
                    port: frontend.port,
                    protocol: frontend.protocol,
                },
            }));
            plans.extend(service.node_ports.iter().map(|frontend| SelectionPlanKey {
                service_id: service.id,
                frontend: SelectionFrontend::NodePort {
                    family: frontend.family,
                    node_port: frontend.port,
                    service_port: frontend.service_port,
                    protocol: frontend.protocol,
                },
            }));
            if let Some(load_balancer) = &service.load_balancer {
                plans.extend(
                    load_balancer
                        .frontends
                        .iter()
                        .map(|frontend| SelectionPlanKey {
                            service_id: service.id,
                            frontend: SelectionFrontend::LoadBalancer {
                                family: frontend.family,
                                service_port: frontend.service_port,
                                protocol: frontend.protocol,
                            },
                        }),
                );
            }
        }
        if plans.len() > MAX_SELECTION_CONTRACT_PLANS {
            return Err(SelectionContractError::TooManyPlans {
                actual: plans.len(),
                limit: MAX_SELECTION_CONTRACT_PLANS,
            });
        }
        let plans = plans
            .into_iter()
            .map(|key| {
                let resolved = resolve_frontend(&snapshot, &key)?;
                Ok(ServiceSelectionPlan {
                    forwarding_mode: frontend_forwarding_mode(resolved.service, &key.frontend),
                    key,
                    traffic_policy: resolved.traffic_policy,
                    traffic_distribution: resolved.service.traffic_distribution,
                    session_affinity: resolved.service.session_affinity,
                    selection_algorithm: resolved.service.selection_algorithm,
                    tiers: expected_tiers(&resolved, &node),
                })
            })
            .collect::<Result<Vec<_>, SelectionContractError>>()?;
        Self::issue(&snapshot, topology_revision, contract_revision, node, plans)
    }

    /// Issues a canonical contract after independently validating every plan.
    ///
    /// The failure envelope covers current state and deterministic single
    /// endpoint, Node, and zone loss observations. Truncation at the public
    /// bound is explicit and included in the digest.
    ///
    /// # Errors
    ///
    /// Rejects invalid source state, identities, frontends, intent, eligibility
    /// tiers, capabilities, bounds, or canonical encoding failures.
    pub fn issue(
        snapshot: &ServiceSnapshot,
        topology_revision: Revision,
        contract_revision: Revision,
        node: SelectionNode,
        mut plans: Vec<ServiceSelectionPlan>,
    ) -> Result<Self, SelectionContractError> {
        let snapshot = snapshot.clone().validate_and_normalize()?;
        validate_header(
            snapshot.source_epoch,
            snapshot.revision,
            topology_revision,
            contract_revision,
            &node,
            plans.len(),
        )?;
        normalize_plans(&mut plans);
        validate_plans(&snapshot, &node, &plans)?;
        let invariant_report = expected_invariant_report();
        let failure_envelope = build_failure_envelope(&snapshot, &plans)?;
        let plan_material = PlanDigestMaterial {
            schema_version: SELECTION_CONTRACT_SCHEMA_VERSION,
            source_epoch: snapshot.source_epoch,
            service_revision: snapshot.revision,
            topology_revision,
            contract_revision,
            node: &node,
            plans: &plans,
        };
        let plan_digest = canonical_digest(b"unf.selection-plan.v1", &plan_material)?;
        let contract_digest = canonical_digest(
            b"unf.network-behavior-contract.v1",
            &ContractDigestMaterial {
                plan: plan_material,
                invariant_report: &invariant_report,
                failure_envelope: &failure_envelope,
                plan_digest,
            },
        )?;
        Ok(Self {
            schema_version: SELECTION_CONTRACT_SCHEMA_VERSION,
            source_epoch: snapshot.source_epoch,
            service_revision: snapshot.revision,
            topology_revision,
            contract_revision,
            node,
            plans,
            invariant_report,
            failure_envelope,
            plan_digest,
            contract_digest,
        })
    }

    /// Recomputes source binding, invariants, failure observations, and both
    /// digests as an agent-side admission check.
    ///
    /// # Errors
    ///
    /// Rejects any unsupported, noncanonical, stale, mutated, or unsafe plan.
    pub fn verify(
        &self,
        snapshot: &ServiceSnapshot,
        local_node: &SelectionNode,
    ) -> Result<(), SelectionContractError> {
        if self.schema_version != SELECTION_CONTRACT_SCHEMA_VERSION {
            return Err(SelectionContractError::UnsupportedSchema {
                actual: self.schema_version,
                expected: SELECTION_CONTRACT_SCHEMA_VERSION,
            });
        }
        let snapshot = snapshot.clone().validate_and_normalize()?;
        if self.source_epoch != snapshot.source_epoch || self.service_revision != snapshot.revision
        {
            return Err(SelectionContractError::SourceTupleMismatch);
        }
        if self.node != *local_node {
            return Err(SelectionContractError::NodeTupleMismatch);
        }
        validate_header(
            self.source_epoch,
            self.service_revision,
            self.topology_revision,
            self.contract_revision,
            &self.node,
            self.plans.len(),
        )?;
        let mut normalized_plans = self.plans.clone();
        normalize_plans(&mut normalized_plans);
        if normalized_plans != self.plans {
            return Err(SelectionContractError::NonCanonical);
        }
        validate_plans(&snapshot, &self.node, &self.plans)?;
        let expected_report = expected_invariant_report();
        if self.invariant_report != expected_report {
            return Err(SelectionContractError::InvariantReportMismatch);
        }
        let expected_failure_envelope = build_failure_envelope(&snapshot, &self.plans)?;
        if self.failure_envelope != expected_failure_envelope {
            return Err(SelectionContractError::FailureEnvelopeMismatch);
        }
        let plan_material = PlanDigestMaterial {
            schema_version: self.schema_version,
            source_epoch: self.source_epoch,
            service_revision: self.service_revision,
            topology_revision: self.topology_revision,
            contract_revision: self.contract_revision,
            node: &self.node,
            plans: &self.plans,
        };
        let expected_plan_digest = canonical_digest(b"unf.selection-plan.v1", &plan_material)?;
        if self.plan_digest != expected_plan_digest {
            return Err(SelectionContractError::PlanDigestMismatch);
        }
        let expected_contract_digest = canonical_digest(
            b"unf.network-behavior-contract.v1",
            &ContractDigestMaterial {
                plan: plan_material,
                invariant_report: &self.invariant_report,
                failure_envelope: &self.failure_envelope,
                plan_digest: self.plan_digest,
            },
        )?;
        if self.contract_digest != expected_contract_digest {
            return Err(SelectionContractError::ContractDigestMismatch);
        }
        Ok(())
    }

    /// Derives a fixed-width provenance witness for one exact admitted plan.
    ///
    /// # Errors
    ///
    /// Returns [`SelectionContractError::UnknownWitnessPlan`] when the key is
    /// not part of this contract.
    pub fn decision_witness(
        &self,
        key: &SelectionPlanKey,
    ) -> Result<SelectionDecisionWitness, SelectionContractError> {
        if !self.plans.iter().any(|plan| plan.key == *key) {
            return Err(SelectionContractError::UnknownWitnessPlan);
        }
        let key_bytes = serde_json::to_vec(key)
            .map_err(|error| SelectionContractError::CanonicalEncoding(error.to_string()))?;
        let mut hasher = Sha256::new();
        hasher.update(b"unf.selection-decision-witness.v1\0");
        hasher.update(self.contract_digest.as_bytes());
        hasher.update(key_bytes);
        let digest = hasher.finalize();
        let mut witness = [0_u8; 16];
        witness.copy_from_slice(&digest[..16]);
        Ok(SelectionDecisionWitness(witness))
    }
}

fn validate_header(
    source_epoch: u64,
    service_revision: Revision,
    topology_revision: Revision,
    contract_revision: Revision,
    node: &SelectionNode,
    plan_count: usize,
) -> Result<(), SelectionContractError> {
    if source_epoch == 0
        || service_revision == Revision::INITIAL
        || topology_revision == Revision::INITIAL
        || contract_revision == Revision::INITIAL
    {
        return Err(SelectionContractError::ZeroRevision);
    }
    if node.name.is_empty() || node.name.len() > 253 {
        return Err(SelectionContractError::InvalidNodeIdentity { field: "node name" });
    }
    if node.uid.is_empty() || node.uid.len() > 128 {
        return Err(SelectionContractError::InvalidNodeIdentity { field: "node UID" });
    }
    if node
        .zone
        .as_ref()
        .is_some_and(|zone| zone.is_empty() || zone.len() > 253)
    {
        return Err(SelectionContractError::InvalidNodeIdentity { field: "node zone" });
    }
    if plan_count > MAX_SELECTION_CONTRACT_PLANS {
        return Err(SelectionContractError::TooManyPlans {
            actual: plan_count,
            limit: MAX_SELECTION_CONTRACT_PLANS,
        });
    }
    Ok(())
}

fn normalize_plans(plans: &mut [ServiceSelectionPlan]) {
    for plan in plans.iter_mut() {
        for tier in &mut plan.tiers {
            tier.backend_ids.sort();
        }
    }
    plans.sort_by(|left, right| left.key.cmp(&right.key));
}

fn validate_plans(
    snapshot: &ServiceSnapshot,
    node: &SelectionNode,
    plans: &[ServiceSelectionPlan],
) -> Result<(), SelectionContractError> {
    for pair in plans.windows(2) {
        if pair[0].key == pair[1].key {
            return Err(SelectionContractError::DuplicatePlan(pair[1].key.clone()));
        }
    }
    for plan in plans {
        let resolved = resolve_frontend(snapshot, &plan.key)?;
        validate_intent(plan, &resolved)?;
        validate_capabilities(plan, node, resolved.family)?;
        let expected = expected_tiers(&resolved, node);
        if plan.tiers.iter().map(|tier| tier.tier).collect::<Vec<_>>()
            != expected.iter().map(|tier| tier.tier).collect::<Vec<_>>()
        {
            return Err(SelectionContractError::TierOrderMismatch {
                plan: plan.key.clone(),
            });
        }
        for tier in &plan.tiers {
            if tier.backend_ids.windows(2).any(|pair| pair[0] == pair[1]) {
                return Err(SelectionContractError::DuplicateTierBackend {
                    plan: plan.key.clone(),
                    tier: tier.tier,
                });
            }
            let expected_tier = expected
                .iter()
                .find(|candidate| candidate.tier == tier.tier)
                .expect("tier order equality guarantees an expected tier");
            if tier.backend_ids != expected_tier.backend_ids {
                return Err(SelectionContractError::TierBackendMismatch {
                    plan: plan.key.clone(),
                    tier: tier.tier,
                });
            }
        }
    }
    Ok(())
}

fn resolve_frontend<'a>(
    snapshot: &'a ServiceSnapshot,
    key: &SelectionPlanKey,
) -> Result<ResolvedFrontend<'a>, SelectionContractError> {
    let service = snapshot
        .services
        .iter()
        .find(|service| service.id == key.service_id)
        .ok_or(SelectionContractError::UnknownService(key.service_id))?;
    match key.frontend {
        SelectionFrontend::ClusterIp {
            address,
            port,
            protocol,
        } => service
            .frontends
            .iter()
            .find(|frontend| {
                frontend.address == address
                    && frontend.port == port
                    && frontend.protocol == protocol
            })
            .map(|frontend| ResolvedFrontend {
                service,
                traffic_policy: service.internal_traffic_policy,
                family: family(address),
                protocol,
                backend_ids: &frontend.backend_ids,
            }),
        SelectionFrontend::NodePort {
            family,
            node_port,
            service_port,
            protocol,
        } => service
            .node_ports
            .iter()
            .find(|frontend| {
                frontend.family == family
                    && frontend.port == node_port
                    && frontend.service_port == service_port
                    && frontend.protocol == protocol
            })
            .map(|frontend| ResolvedFrontend {
                service,
                traffic_policy: frontend.traffic_policy,
                family,
                protocol,
                backend_ids: &frontend.backend_ids,
            }),
        SelectionFrontend::LoadBalancer {
            family,
            service_port,
            protocol,
        } => service.load_balancer.as_ref().and_then(|load_balancer| {
            load_balancer
                .frontends
                .iter()
                .find(|frontend| {
                    frontend.family == family
                        && frontend.service_port == service_port
                        && frontend.protocol == protocol
                })
                .map(|frontend| ResolvedFrontend {
                    service,
                    traffic_policy: load_balancer.traffic_policy,
                    family,
                    protocol,
                    backend_ids: &frontend.backend_ids,
                })
        }),
    }
    .ok_or(SelectionContractError::UnknownFrontend(key.service_id))
}

fn validate_intent(
    plan: &ServiceSelectionPlan,
    resolved: &ResolvedFrontend<'_>,
) -> Result<(), SelectionContractError> {
    let service = resolved.service;
    let fields = [
        (
            plan.traffic_policy == resolved.traffic_policy,
            "traffic policy",
        ),
        (
            plan.traffic_distribution == service.traffic_distribution,
            "traffic distribution",
        ),
        (
            plan.session_affinity == service.session_affinity,
            "session affinity",
        ),
        (
            plan.selection_algorithm == service.selection_algorithm,
            "selection algorithm",
        ),
        (
            plan.forwarding_mode == frontend_forwarding_mode(service, &plan.key.frontend),
            "forwarding mode",
        ),
    ];
    if let Some((_, field)) = fields.into_iter().find(|(matches, _)| !matches) {
        return Err(SelectionContractError::IntentMismatch {
            plan: plan.key.clone(),
            field,
        });
    }
    Ok(())
}

/// DSR is meaningful only for a stable `LoadBalancer` VIP. `ClusterIP` and
/// `NodePort` retain the qualified NAT contract even when the same Service opts
/// its `LoadBalancer` frontend into direct return.
const fn frontend_forwarding_mode(
    service: &ServiceIr,
    frontend: &SelectionFrontend,
) -> ServiceForwardingMode {
    if matches!(frontend, SelectionFrontend::LoadBalancer { .. }) {
        service.forwarding_mode
    } else {
        ServiceForwardingMode::Nat
    }
}

fn validate_capabilities(
    plan: &ServiceSelectionPlan,
    node: &SelectionNode,
    family: AddressFamily,
) -> Result<(), SelectionContractError> {
    let algorithm = match plan.selection_algorithm {
        ServiceSelectionAlgorithm::StableHash => SelectionCapability::StableHash,
        ServiceSelectionAlgorithm::Maglev => SelectionCapability::Maglev,
    };
    require_capability(plan, node, algorithm)?;
    let forwarding = match (plan.forwarding_mode, family) {
        (ServiceForwardingMode::Nat, _) => SelectionCapability::Nat,
        (ServiceForwardingMode::Dsr, AddressFamily::Ipv4) => SelectionCapability::DsrIpv4,
        (ServiceForwardingMode::Dsr, AddressFamily::Ipv6) => SelectionCapability::DsrIpv6,
    };
    require_capability(plan, node, forwarding)
}

fn require_capability(
    plan: &ServiceSelectionPlan,
    node: &SelectionNode,
    capability: SelectionCapability,
) -> Result<(), SelectionContractError> {
    if node.capabilities.contains(&capability) {
        Ok(())
    } else {
        Err(SelectionContractError::MissingCapability {
            plan: plan.key.clone(),
            capability,
        })
    }
}

fn expected_tiers(
    resolved: &ResolvedFrontend<'_>,
    node: &SelectionNode,
) -> Vec<SelectionEligibilityTier> {
    let expected_order = match (
        resolved.traffic_policy,
        resolved.service.traffic_distribution,
    ) {
        (ServiceTrafficPolicy::Local, _) => vec![SelectionTier::SameNode],
        (ServiceTrafficPolicy::Cluster, ServiceTrafficDistribution::Any) => {
            vec![SelectionTier::Cluster]
        }
        (ServiceTrafficPolicy::Cluster, ServiceTrafficDistribution::PreferSameZone) => {
            vec![SelectionTier::SameZone, SelectionTier::Cluster]
        }
        (ServiceTrafficPolicy::Cluster, ServiceTrafficDistribution::PreferSameNode) => vec![
            SelectionTier::SameNode,
            SelectionTier::SameZone,
            SelectionTier::Cluster,
        ],
    };
    let referenced = resolved
        .backend_ids
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    expected_order
        .into_iter()
        .map(|tier| {
            let backend_ids = resolved
                .service
                .backends
                .iter()
                .filter(|backend| {
                    referenced.contains(&backend.id)
                        && backend.ready
                        && !backend.terminating
                        && family(backend.address) == resolved.family
                        && backend.protocol == resolved.protocol
                        && match tier {
                            SelectionTier::SameNode => {
                                backend.node_name.as_deref() == Some(node.name.as_str())
                            }
                            SelectionTier::SameZone => node
                                .zone
                                .as_ref()
                                .is_some_and(|zone| backend.zone.as_deref() == Some(zone.as_str())),
                            SelectionTier::Cluster => true,
                        }
                })
                .map(|backend| backend.id)
                .collect();
            SelectionEligibilityTier { tier, backend_ids }
        })
        .collect()
}

fn build_failure_envelope(
    snapshot: &ServiceSnapshot,
    plans: &[ServiceSelectionPlan],
) -> Result<SelectionFailureEnvelope, SelectionContractError> {
    let mut failures_by_plan = Vec::with_capacity(plans.len());
    let mut total_observations = 0_u64;
    for plan in plans {
        let resolved = resolve_frontend(snapshot, &plan.key)?;
        let backend_ids = plan
            .tiers
            .iter()
            .flat_map(|tier| tier.backend_ids.iter().copied())
            .collect::<BTreeSet<_>>();
        let backends = resolved
            .service
            .backends
            .iter()
            .filter(|backend| backend_ids.contains(&backend.id))
            .map(|backend| (backend.id, backend))
            .collect::<BTreeMap<_, _>>();
        let mut failures = BTreeSet::from([SelectionFailure::CurrentState]);
        for backend in backends.values() {
            failures.insert(SelectionFailure::EndpointLoss {
                service_id: plan.key.service_id,
                backend_id: backend.id,
            });
            if let Some(node_name) = &backend.node_name {
                failures.insert(SelectionFailure::NodeLoss {
                    node_name: node_name.clone(),
                });
            }
            if let Some(zone) = &backend.zone {
                failures.insert(SelectionFailure::ZoneLoss { zone: zone.clone() });
            }
        }
        total_observations =
            total_observations.saturating_add(u64::try_from(failures.len()).unwrap_or(u64::MAX));
        failures_by_plan.push((plan, backends, failures));
    }

    let mut observations = Vec::with_capacity(
        usize::try_from(total_observations)
            .unwrap_or(usize::MAX)
            .min(MAX_FAILURE_ENVELOPE_OBSERVATIONS),
    );
    for (plan, backends, failures) in failures_by_plan {
        for failure in failures {
            if observations.len() == MAX_FAILURE_ENVELOPE_OBSERVATIONS {
                break;
            }
            observations.push(SelectionFailureObservation {
                plan: plan.key.clone(),
                outcome: failure_outcome(plan, &backends, &failure),
                failure,
            });
        }
    }
    Ok(SelectionFailureEnvelope {
        truncated: total_observations
            > u64::try_from(MAX_FAILURE_ENVELOPE_OBSERVATIONS).unwrap_or(u64::MAX),
        total_observations,
        observations,
    })
}

fn failure_outcome(
    plan: &ServiceSelectionPlan,
    backends: &BTreeMap<BackendId, &crate::ServiceBackend>,
    failure: &SelectionFailure,
) -> SelectionFailureOutcome {
    for tier in &plan.tiers {
        let remaining = tier
            .backend_ids
            .iter()
            .filter(|backend_id| {
                let Some(backend) = backends.get(backend_id) else {
                    return false;
                };
                match failure {
                    SelectionFailure::CurrentState => true,
                    SelectionFailure::EndpointLoss {
                        service_id,
                        backend_id: failed_backend,
                    } => *service_id != plan.key.service_id || **backend_id != *failed_backend,
                    SelectionFailure::NodeLoss { node_name } => {
                        backend.node_name.as_deref() != Some(node_name.as_str())
                    }
                    SelectionFailure::ZoneLoss { zone } => {
                        backend.zone.as_deref() != Some(zone.as_str())
                    }
                }
            })
            .count();
        if remaining != 0 {
            return SelectionFailureOutcome::Available {
                selected_tier: tier.tier,
                remaining_backends: u32::try_from(remaining).unwrap_or(u32::MAX),
            };
        }
    }
    if plan.traffic_policy == ServiceTrafficPolicy::Local {
        SelectionFailureOutcome::ExpectedPolicyDrop
    } else {
        SelectionFailureOutcome::Unavailable
    }
}

fn expected_invariant_report() -> SelectionInvariantReport {
    SelectionInvariantReport {
        verified: vec![
            SelectionInvariant::SourceRevisionBound,
            SelectionInvariant::NodeOwnershipBound,
            SelectionInvariant::PlanKeysUnique,
            SelectionInvariant::FrontendsExact,
            SelectionInvariant::IntentExact,
            SelectionInvariant::StrictPolicyFirst,
            SelectionInvariant::TopologyOrderExact,
            SelectionInvariant::BackendsEligible,
            SelectionInvariant::FamilyProtocolExact,
            SelectionInvariant::CapabilitiesAdmitted,
            SelectionInvariant::StateBounded,
            SelectionInvariant::FailureEnvelopeBounded,
        ],
    }
}

fn canonical_digest(
    domain: &[u8],
    material: &impl Serialize,
) -> Result<SelectionDigest, SelectionContractError> {
    let encoded = serde_json::to_vec(material)
        .map_err(|error| SelectionContractError::CanonicalEncoding(error.to_string()))?;
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(b"\0");
    hasher.update(encoded);
    Ok(SelectionDigest(hasher.finalize().into()))
}

const fn family(address: IpAddr) -> AddressFamily {
    match address {
        IpAddr::V4(_) => AddressFamily::Ipv4,
        IpAddr::V6(_) => AddressFamily::Ipv6,
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;
    use crate::{
        SERVICE_SNAPSHOT_SCHEMA_VERSION, ServiceBackend, ServiceFrontend, ServiceIpFamilyPolicy,
        ServiceLoadBalancer, ServiceLoadBalancerFrontend, ServiceNodePort, UNF_LOAD_BALANCER_CLASS,
    };

    fn backend(id: u32, address: &str, node: &str, zone: &str) -> ServiceBackend {
        ServiceBackend {
            id: BackendId::new(id),
            address: address.parse().unwrap(),
            port: 8080,
            protocol: Protocol::Tcp,
            port_name: Some("http".to_owned()),
            app_protocol: None,
            endpoint_slices: vec![format!("default/api-{id}")],
            target_workload: Some(format!("default/api-{id}")),
            node_name: Some(node.to_owned()),
            zone: Some(zone.to_owned()),
            ready: true,
            serving: true,
            terminating: false,
        }
    }

    fn snapshot(policy: ServiceTrafficPolicy) -> ServiceSnapshot {
        ServiceSnapshot {
            schema_version: SERVICE_SNAPSHOT_SCHEMA_VERSION,
            source_epoch: 17,
            revision: Revision::new(23),
            services: vec![ServiceIr {
                id: ServiceId::new(7),
                namespace: "default".to_owned(),
                name: "api".to_owned(),
                internal_traffic_policy: policy,
                session_affinity: ServiceSessionAffinity::ClientIp {
                    timeout_seconds: 10_800,
                },
                traffic_distribution: ServiceTrafficDistribution::PreferSameNode,
                selection_algorithm: ServiceSelectionAlgorithm::StableHash,
                forwarding_mode: ServiceForwardingMode::Nat,
                frontends: vec![ServiceFrontend {
                    address: "10.96.0.7".parse().unwrap(),
                    port: 80,
                    protocol: Protocol::Tcp,
                    name: Some("http".to_owned()),
                    app_protocol: None,
                    backend_ids: vec![BackendId::new(1), BackendId::new(2), BackendId::new(3)],
                }],
                node_ports: Vec::new(),
                load_balancer: None,
                backends: vec![
                    backend(1, "10.244.0.11", "worker-a", "zone-a"),
                    backend(2, "10.244.1.12", "worker-b", "zone-a"),
                    backend(3, "10.244.2.13", "worker-c", "zone-b"),
                ],
            }],
        }
        .validate_and_normalize()
        .unwrap()
    }

    fn node() -> SelectionNode {
        SelectionNode {
            name: "worker-a".to_owned(),
            uid: "worker-a-uid".to_owned(),
            zone: Some("zone-a".to_owned()),
            capabilities: BTreeSet::from([
                SelectionCapability::StableHash,
                SelectionCapability::Nat,
            ]),
        }
    }

    fn plan(policy: ServiceTrafficPolicy) -> ServiceSelectionPlan {
        let tiers = if policy == ServiceTrafficPolicy::Local {
            vec![SelectionEligibilityTier {
                tier: SelectionTier::SameNode,
                backend_ids: vec![BackendId::new(1)],
            }]
        } else {
            vec![
                SelectionEligibilityTier {
                    tier: SelectionTier::SameNode,
                    backend_ids: vec![BackendId::new(1)],
                },
                SelectionEligibilityTier {
                    tier: SelectionTier::SameZone,
                    backend_ids: vec![BackendId::new(1), BackendId::new(2)],
                },
                SelectionEligibilityTier {
                    tier: SelectionTier::Cluster,
                    backend_ids: vec![BackendId::new(1), BackendId::new(2), BackendId::new(3)],
                },
            ]
        };
        ServiceSelectionPlan {
            key: SelectionPlanKey {
                service_id: ServiceId::new(7),
                frontend: SelectionFrontend::ClusterIp {
                    address: "10.96.0.7".parse().unwrap(),
                    port: 80,
                    protocol: Protocol::Tcp,
                },
            },
            traffic_policy: policy,
            traffic_distribution: ServiceTrafficDistribution::PreferSameNode,
            session_affinity: ServiceSessionAffinity::ClientIp {
                timeout_seconds: 10_800,
            },
            selection_algorithm: ServiceSelectionAlgorithm::StableHash,
            forwarding_mode: ServiceForwardingMode::Nat,
            tiers,
        }
    }

    fn issue(policy: ServiceTrafficPolicy) -> NetworkBehaviorContract {
        NetworkBehaviorContract::issue(
            &snapshot(policy),
            Revision::new(29),
            Revision::new(31),
            node(),
            vec![plan(policy)],
        )
        .unwrap()
    }

    #[test]
    fn contract_binds_exact_intent_and_has_stable_human_readable_digests() {
        let contract = issue(ServiceTrafficPolicy::Cluster);
        contract
            .verify(&snapshot(ServiceTrafficPolicy::Cluster), &node())
            .unwrap();
        assert_eq!(contract.invariant_report, expected_invariant_report());
        assert_eq!(
            contract.plan_digest.to_string(),
            "f53fd7191f63ac4973b7e185c88ef8e06beda09f2483a8409858990890bd3467"
        );
        assert_eq!(
            contract.contract_digest.to_string(),
            "52751d2ea0582d102c3656a66e1404430ffcfa8a655f4764ea0597b7ad8b9219"
        );
        let encoded = serde_json::to_string(&contract).unwrap();
        assert!(encoded.contains(&format!("\"planDigest\":\"{}\"", contract.plan_digest)));
        let decoded: NetworkBehaviorContract = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, contract);
        decoded
            .verify(&snapshot(ServiceTrafficPolicy::Cluster), &node())
            .unwrap();
    }

    #[test]
    fn contract_rejects_remote_local_backend_and_missing_capability() {
        let mut invalid = plan(ServiceTrafficPolicy::Local);
        invalid.tiers[0].backend_ids.push(BackendId::new(2));
        assert!(matches!(
            NetworkBehaviorContract::issue(
                &snapshot(ServiceTrafficPolicy::Local),
                Revision::new(29),
                Revision::new(31),
                node(),
                vec![invalid]
            ),
            Err(SelectionContractError::TierBackendMismatch { .. })
        ));

        let mut unsupported_node = node();
        unsupported_node
            .capabilities
            .remove(&SelectionCapability::StableHash);
        assert!(matches!(
            NetworkBehaviorContract::issue(
                &snapshot(ServiceTrafficPolicy::Cluster),
                Revision::new(29),
                Revision::new(31),
                unsupported_node,
                vec![plan(ServiceTrafficPolicy::Cluster)]
            ),
            Err(SelectionContractError::MissingCapability {
                capability: SelectionCapability::StableHash,
                ..
            })
        ));
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn node_port_and_load_balancer_plans_bind_exact_external_frontends() {
        let mut source = snapshot(ServiceTrafficPolicy::Cluster);
        let service = &mut source.services[0];
        let backend_ids = service.frontends[0].backend_ids.clone();
        service.node_ports = vec![ServiceNodePort {
            family: AddressFamily::Ipv4,
            port: 30_080,
            service_port: 80,
            protocol: Protocol::Tcp,
            name: Some("http".to_owned()),
            app_protocol: None,
            traffic_policy: ServiceTrafficPolicy::Local,
            backend_ids: backend_ids.clone(),
        }];
        service.load_balancer = Some(ServiceLoadBalancer {
            class: UNF_LOAD_BALANCER_CLASS.to_owned(),
            ip_families: vec![AddressFamily::Ipv4],
            ip_family_policy: ServiceIpFamilyPolicy::SingleStack,
            requested_ips: vec!["192.0.2.80".parse().unwrap()],
            traffic_policy: ServiceTrafficPolicy::Cluster,
            source_ranges: Vec::new(),
            allocate_node_ports: false,
            health_check_node_port: None,
            frontends: vec![ServiceLoadBalancerFrontend {
                family: AddressFamily::Ipv4,
                service_port: 80,
                protocol: Protocol::Tcp,
                name: Some("http".to_owned()),
                app_protocol: None,
                backend_ids,
            }],
        });
        source = source.validate_and_normalize().unwrap();

        let base = plan(ServiceTrafficPolicy::Cluster);
        let node_port = ServiceSelectionPlan {
            key: SelectionPlanKey {
                service_id: ServiceId::new(7),
                frontend: SelectionFrontend::NodePort {
                    family: AddressFamily::Ipv4,
                    node_port: 30_080,
                    service_port: 80,
                    protocol: Protocol::Tcp,
                },
            },
            traffic_policy: ServiceTrafficPolicy::Local,
            tiers: vec![SelectionEligibilityTier {
                tier: SelectionTier::SameNode,
                backend_ids: vec![BackendId::new(1)],
            }],
            ..base.clone()
        };
        let load_balancer = ServiceSelectionPlan {
            key: SelectionPlanKey {
                service_id: ServiceId::new(7),
                frontend: SelectionFrontend::LoadBalancer {
                    family: AddressFamily::Ipv4,
                    service_port: 80,
                    protocol: Protocol::Tcp,
                },
            },
            ..base
        };
        let contract = NetworkBehaviorContract::issue(
            &source,
            Revision::new(29),
            Revision::new(31),
            node(),
            vec![load_balancer, node_port],
        )
        .unwrap();
        contract.verify(&source, &node()).unwrap();

        let mut wrong_family = contract.plans[0].clone();
        wrong_family.key.frontend = SelectionFrontend::LoadBalancer {
            family: AddressFamily::Ipv6,
            service_port: 80,
            protocol: Protocol::Tcp,
        };
        assert_eq!(
            NetworkBehaviorContract::issue(
                &source,
                Revision::new(29),
                Revision::new(31),
                node(),
                vec![wrong_family]
            ),
            Err(SelectionContractError::UnknownFrontend(ServiceId::new(7)))
        );

        let compiled =
            NetworkBehaviorContract::compile(&source, Revision::new(29), Revision::new(31), node())
                .unwrap();
        assert_eq!(compiled.plans.len(), 3);
        assert_eq!(
            compiled,
            NetworkBehaviorContract::issue(
                &source,
                Revision::new(29),
                Revision::new(31),
                node(),
                vec![
                    plan(ServiceTrafficPolicy::Cluster),
                    contract.plans[0].clone(),
                    contract.plans[1].clone(),
                ],
            )
            .unwrap()
        );
    }

    #[test]
    fn independent_verification_rejects_every_mutated_contract_domain() {
        let source = snapshot(ServiceTrafficPolicy::Cluster);

        let mut stale_source = source.clone();
        stale_source.revision = Revision::new(24);
        assert_eq!(
            issue(ServiceTrafficPolicy::Cluster).verify(&stale_source, &node()),
            Err(SelectionContractError::SourceTupleMismatch)
        );

        let contract = issue(ServiceTrafficPolicy::Cluster);
        let mut foreign_node = node();
        foreign_node.uid = "foreign-node-uid".to_owned();
        assert_eq!(
            contract.verify(&source, &foreign_node),
            Err(SelectionContractError::NodeTupleMismatch)
        );

        let mut noncanonical = issue(ServiceTrafficPolicy::Cluster);
        noncanonical.plans[0].tiers[2].backend_ids.reverse();
        assert_eq!(
            noncanonical.verify(&source, &node()),
            Err(SelectionContractError::NonCanonical)
        );

        let mut plan_mutation = issue(ServiceTrafficPolicy::Cluster);
        plan_mutation.plans[0].tiers[2].backend_ids.pop();
        assert!(matches!(
            plan_mutation.verify(&source, &node()),
            Err(SelectionContractError::TierBackendMismatch { .. })
        ));

        let mut report_mutation = issue(ServiceTrafficPolicy::Cluster);
        report_mutation.invariant_report.verified.pop();
        assert_eq!(
            report_mutation.verify(&source, &node()),
            Err(SelectionContractError::InvariantReportMismatch)
        );

        let mut envelope_mutation = issue(ServiceTrafficPolicy::Cluster);
        envelope_mutation.failure_envelope.observations.pop();
        assert_eq!(
            envelope_mutation.verify(&source, &node()),
            Err(SelectionContractError::FailureEnvelopeMismatch)
        );

        let mut digest_mutation = issue(ServiceTrafficPolicy::Cluster);
        digest_mutation.plan_digest.0[0] ^= 1;
        assert_eq!(
            digest_mutation.verify(&source, &node()),
            Err(SelectionContractError::PlanDigestMismatch)
        );

        let mut envelope_revision_mutation = issue(ServiceTrafficPolicy::Cluster);
        envelope_revision_mutation.contract_revision = Revision::new(32);
        assert_eq!(
            envelope_revision_mutation.verify(&source, &node()),
            Err(SelectionContractError::PlanDigestMismatch)
        );

        let mut contract_digest_mutation = issue(ServiceTrafficPolicy::Cluster);
        contract_digest_mutation.contract_digest.0[0] ^= 1;
        assert_eq!(
            contract_digest_mutation.verify(&source, &node()),
            Err(SelectionContractError::ContractDigestMismatch)
        );
    }

    #[test]
    fn failure_envelope_distinguishes_fallback_unavailability_and_policy_drop() {
        let cluster = issue(ServiceTrafficPolicy::Cluster);
        assert!(
            cluster
                .failure_envelope
                .observations
                .iter()
                .any(|observation| {
                    observation.failure
                        == SelectionFailure::NodeLoss {
                            node_name: "worker-a".to_owned(),
                        }
                        && observation.outcome
                            == SelectionFailureOutcome::Available {
                                selected_tier: SelectionTier::SameZone,
                                remaining_backends: 1,
                            }
                })
        );
        assert!(
            cluster
                .failure_envelope
                .observations
                .iter()
                .any(|observation| {
                    observation.failure
                        == SelectionFailure::ZoneLoss {
                            zone: "zone-a".to_owned(),
                        }
                        && observation.outcome
                            == SelectionFailureOutcome::Available {
                                selected_tier: SelectionTier::Cluster,
                                remaining_backends: 1,
                            }
                })
        );

        let local = issue(ServiceTrafficPolicy::Local);
        assert!(
            local
                .failure_envelope
                .observations
                .iter()
                .any(|observation| {
                    observation.failure
                        == SelectionFailure::EndpointLoss {
                            service_id: ServiceId::new(7),
                            backend_id: BackendId::new(1),
                        }
                        && observation.outcome == SelectionFailureOutcome::ExpectedPolicyDrop
                })
        );
    }

    #[test]
    fn failure_envelope_is_bounded_and_never_hides_truncation() {
        let mut source = snapshot(ServiceTrafficPolicy::Cluster);
        let service = &mut source.services[0];
        service.traffic_distribution = ServiceTrafficDistribution::Any;
        service.backends.clear();
        service.frontends[0].backend_ids.clear();
        for id in 1..=4_096_u32 {
            let address = format!("10.200.{}.{}", (id - 1) / 256, (id - 1) % 256);
            service
                .backends
                .push(backend(id, &address, &format!("worker-{id}"), "zone-a"));
            service.frontends[0].backend_ids.push(BackendId::new(id));
        }
        source = source.validate_and_normalize().unwrap();
        let candidate = ServiceSelectionPlan {
            traffic_distribution: ServiceTrafficDistribution::Any,
            tiers: vec![SelectionEligibilityTier {
                tier: SelectionTier::Cluster,
                backend_ids: (1..=4_096_u32).map(BackendId::new).collect(),
            }],
            ..plan(ServiceTrafficPolicy::Cluster)
        };
        let contract = NetworkBehaviorContract::issue(
            &source,
            Revision::new(29),
            Revision::new(31),
            node(),
            vec![candidate],
        )
        .unwrap();
        assert_eq!(
            contract.failure_envelope.observations.len(),
            MAX_FAILURE_ENVELOPE_OBSERVATIONS
        );
        assert_eq!(contract.failure_envelope.total_observations, 8_194);
        assert!(contract.failure_envelope.truncated);
        contract.verify(&source, &node()).unwrap();
    }

    #[test]
    fn witness_is_exact_revisioned_provenance_and_not_an_authority() {
        let first = issue(ServiceTrafficPolicy::Cluster);
        let witness = first.decision_witness(&first.plans[0].key).unwrap();
        assert_eq!(witness.to_string().len(), 32);
        assert_eq!(
            first.decision_witness(&first.plans[0].key).unwrap(),
            witness
        );

        let second = NetworkBehaviorContract::issue(
            &snapshot(ServiceTrafficPolicy::Cluster),
            Revision::new(29),
            Revision::new(32),
            node(),
            vec![plan(ServiceTrafficPolicy::Cluster)],
        )
        .unwrap();
        assert_ne!(
            second.decision_witness(&second.plans[0].key).unwrap(),
            witness
        );

        let missing = SelectionPlanKey {
            service_id: ServiceId::new(99),
            frontend: first.plans[0].key.frontend.clone(),
        };
        assert_eq!(
            first.decision_witness(&missing),
            Err(SelectionContractError::UnknownWitnessPlan)
        );
    }

    #[test]
    fn schema_and_json_shape_fail_closed() {
        let source = snapshot(ServiceTrafficPolicy::Cluster);
        let mut contract = issue(ServiceTrafficPolicy::Cluster);
        contract.schema_version = 2;
        assert_eq!(
            contract.verify(&source, &node()),
            Err(SelectionContractError::UnsupportedSchema {
                actual: 2,
                expected: 1,
            })
        );

        let mut encoded = serde_json::to_value(issue(ServiceTrafficPolicy::Cluster)).unwrap();
        encoded["unexpectedAuthority"] = serde_json::json!(true);
        assert!(serde_json::from_value::<NetworkBehaviorContract>(encoded).is_err());
    }

    proptest! {
        #[test]
        fn issuance_canonicalizes_backend_order(
            reverse_same_zone in any::<bool>(),
            reverse_cluster in any::<bool>(),
        ) {
            let source = snapshot(ServiceTrafficPolicy::Cluster);
            let mut candidate = plan(ServiceTrafficPolicy::Cluster);
            if reverse_same_zone {
                candidate.tiers[1].backend_ids.reverse();
            }
            if reverse_cluster {
                candidate.tiers[2].backend_ids.reverse();
            }
            let contract = NetworkBehaviorContract::issue(
                &source,
                Revision::new(29),
                Revision::new(31),
                node(),
                vec![candidate],
            ).unwrap();
            prop_assert_eq!(contract, issue(ServiceTrafficPolicy::Cluster));
        }
    }
}
