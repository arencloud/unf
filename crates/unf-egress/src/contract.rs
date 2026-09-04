//! Canonical per-source/per-Node Egress Behavior Contracts.
//!
//! Contracts are userspace authority boundaries. They bind independently
//! supplied intent, identity, policy, allocation, gateway, capability, and
//! revision facts before later distribution or dataplane activation.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use unf_common::{IdentityId, PolicyId, Revision};

use crate::{
    AddressFamily, EgressAddressPool, EgressAddressRequest, EgressDestinations, EgressIntent,
    EgressIntentOwner, EgressModel, EgressModelError, EgressProviderRef, MAX_EGRESS_INTENTS,
    normalize_model,
};

pub const EGRESS_BEHAVIOR_CONTRACT_SCHEMA_VERSION: u16 = 1;
pub const MAX_EGRESS_CONTRACT_PLANS: usize = 65_536;
pub const MAX_EGRESS_GATEWAYS_PER_PLAN: usize = 16;
pub const MAX_EGRESS_GATEWAY_FACTS: usize = MAX_EGRESS_INTENTS * MAX_EGRESS_GATEWAYS_PER_PLAN;
pub const MAX_EGRESS_FAILURE_OBSERVATIONS: usize = 4_096;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum EgressCapability {
    IdentitySourceSteering,
    LeaseEpochFencing,
    OriginalTupleWitness,
    Ipv4TcpUdpNat,
    Ipv6TcpUdpNat,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EgressNode {
    pub name: String,
    pub uid: String,
    pub capabilities: BTreeSet<EgressCapability>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EgressSourceFact {
    pub identity: IdentityId,
    pub namespace: String,
    pub workload: String,
    pub workload_uid: String,
    pub service_account: String,
    pub namespace_labels: BTreeMap<String, String>,
    pub workload_labels: BTreeMap<String, String>,
    pub node: EgressNode,
    pub intent_uid: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EgressPolicyFact {
    pub identity: IdentityId,
    pub intent_uid: String,
    pub allowed: bool,
    pub policy_ids: Vec<PolicyId>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EgressAllocationFact {
    pub intent_uid: String,
    pub pool_name: Option<String>,
    pub pool_uid: Option<String>,
    pub addresses: Vec<IpAddr>,
    pub lease_epoch: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EgressGatewayFact {
    pub intent_uid: String,
    pub rank: u16,
    pub node: EgressNode,
    pub lease_epoch: u64,
    pub ready: bool,
    pub reachable: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EgressContractRevisions {
    pub intent: Revision,
    pub identity: Revision,
    pub policy: Revision,
    pub allocation: Revision,
    pub gateway: Revision,
    pub reachability: Revision,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EgressContractFacts {
    pub revisions: EgressContractRevisions,
    pub sources: Vec<EgressSourceFact>,
    pub policies: Vec<EgressPolicyFact>,
    pub allocations: Vec<EgressAllocationFact>,
    pub gateways: Vec<EgressGatewayFact>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EgressPoolBinding {
    pub name: String,
    pub uid: String,
    pub provider: EgressProviderRef,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EgressAllocationBinding {
    pub pool: Option<EgressPoolBinding>,
    pub addresses: Vec<IpAddr>,
    pub lease_epoch: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EgressPolicyBinding {
    pub policy_ids: Vec<PolicyId>,
    pub revision: Revision,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EgressBehaviorPlan {
    pub source: EgressSourceFact,
    pub intent: EgressIntentOwner,
    pub destinations: EgressDestinations,
    pub policy: EgressPolicyBinding,
    pub allocation: EgressAllocationBinding,
    pub gateways: Vec<EgressGatewayFact>,
    pub required_capabilities: BTreeSet<EgressCapability>,
    pub revisions: EgressContractRevisions,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum EgressInvariant {
    ModelNormalized,
    ExactNodeOwnership,
    SourceIdentitySelected,
    PolicyAllowBeforeSteering,
    AllocationIntentExact,
    GatewayLeaseFenced,
    GatewayReadinessAcknowledged,
    CapabilitiesAdmitted,
    RevisionsBound,
    StateBounded,
    FailureEnvelopeBounded,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "outcome", content = "gateway")]
pub enum EgressFailureOutcome {
    Failover(EgressNode),
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EgressFailureObservation {
    pub identity: IdentityId,
    pub failed_gateway: EgressNode,
    pub outcome: EgressFailureOutcome,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EgressFailureEnvelope {
    pub observations: Vec<EgressFailureObservation>,
    pub total_observations: u64,
    pub truncated: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EgressContractDigest(pub [u8; 32]);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EgressDecisionWitness(pub [u8; 16]);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EgressBehaviorContract {
    pub schema_version: u16,
    pub contract_revision: Revision,
    pub node: EgressNode,
    pub plans: Vec<EgressBehaviorPlan>,
    pub verified_invariants: Vec<EgressInvariant>,
    pub failure_envelope: EgressFailureEnvelope,
    pub contract_digest: EgressContractDigest,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum EgressContractError {
    #[error(transparent)]
    InvalidModel(#[from] EgressModelError),
    #[error("unsupported egress contract schema {actual}; expected {expected}")]
    UnsupportedSchema { actual: u16, expected: u16 },
    #[error("egress contract revisions must all be nonzero")]
    ZeroRevision,
    #[error("invalid egress contract Node: {0}")]
    InvalidNode(&'static str),
    #[error("egress contract has {actual} plans; limit is {limit}")]
    TooManyPlans { actual: usize, limit: usize },
    #[error("egress contract has {actual} {kind} facts; limit is {limit}")]
    TooManyFacts {
        kind: &'static str,
        actual: usize,
        limit: usize,
    },
    #[error("egress source identity {0:?} is invalid or duplicated")]
    InvalidSource(IdentityId),
    #[error("egress source identity {0:?} references an unknown or nonmatching intent")]
    IntentMismatch(IdentityId),
    #[error("egress source identity {0:?} is not allowed by source-side policy")]
    PolicyNotAllowed(IdentityId),
    #[error("egress source identity {0:?} has missing, duplicate, or invalid allocation")]
    AllocationMismatch(IdentityId),
    #[error("egress source identity {0:?} has invalid gateway candidates")]
    GatewayMismatch(IdentityId),
    #[error("egress source identity {identity:?} requires unavailable capability {capability:?}")]
    MissingCapability {
        identity: IdentityId,
        capability: EgressCapability,
    },
    #[error("egress contract differs from independent replay")]
    ReplayMismatch,
    #[error("egress contract canonical encoding failed: {0}")]
    CanonicalEncoding(String),
    #[error("egress decision witness references an unknown plan/address/gateway")]
    UnknownWitnessSelection,
}

impl EgressBehaviorContract {
    /// Issues a canonical exact-Node contract from independently supplied facts.
    ///
    /// # Errors
    ///
    /// Rejects invalid model, revisions, identity selection, policy, allocation,
    /// gateway readiness, capabilities, bounds, or canonical encoding.
    pub fn issue(
        model: &EgressModel,
        facts: &EgressContractFacts,
        node: EgressNode,
        contract_revision: Revision,
    ) -> Result<Self, EgressContractError> {
        compile_contract(model, facts, node, contract_revision)
    }

    /// Independently replays the complete contract and compares every field.
    ///
    /// # Errors
    ///
    /// Rejects unsupported schema, wrong local Node, stale or mutated content,
    /// or any source fact that no longer validates.
    pub fn verify(
        &self,
        model: &EgressModel,
        facts: &EgressContractFacts,
        local_node: &EgressNode,
    ) -> Result<(), EgressContractError> {
        if self.schema_version != EGRESS_BEHAVIOR_CONTRACT_SCHEMA_VERSION {
            return Err(EgressContractError::UnsupportedSchema {
                actual: self.schema_version,
                expected: EGRESS_BEHAVIOR_CONTRACT_SCHEMA_VERSION,
            });
        }
        if self.node != *local_node {
            return Err(EgressContractError::InvalidNode("local identity mismatch"));
        }
        let expected = compile_contract(model, facts, local_node.clone(), self.contract_revision)?;
        if *self != expected {
            return Err(EgressContractError::ReplayMismatch);
        }
        Ok(())
    }

    /// Verifies the self-contained contract commitment without requiring live
    /// controller facts. This is used only to reject corrupted durable state;
    /// fresh activation still requires [`Self::verify`] against every source
    /// domain.
    ///
    /// # Errors
    ///
    /// Rejects an unsupported schema or any mutation covered by the canonical
    /// contract digest.
    pub fn verify_integrity(&self) -> Result<(), EgressContractError> {
        if self.schema_version != EGRESS_BEHAVIOR_CONTRACT_SCHEMA_VERSION {
            return Err(EgressContractError::UnsupportedSchema {
                actual: self.schema_version,
                expected: EGRESS_BEHAVIOR_CONTRACT_SCHEMA_VERSION,
            });
        }
        if self.contract_digest
            != contract_digest(
                self.contract_revision,
                &self.node,
                &self.plans,
                &self.verified_invariants,
                &self.failure_envelope,
            )?
        {
            return Err(EgressContractError::ReplayMismatch);
        }
        Ok(())
    }

    /// Derives a fixed-width provenance witness for one selected path.
    ///
    /// The witness is not authority; it resolves only against the retained
    /// contract digest and exact plan/address/gateway indexes.
    ///
    /// # Errors
    ///
    /// Rejects indexes outside canonical contract state.
    pub fn decision_witness(
        &self,
        plan_index: usize,
        address_index: usize,
        gateway_index: usize,
    ) -> Result<EgressDecisionWitness, EgressContractError> {
        let plan = self
            .plans
            .get(plan_index)
            .ok_or(EgressContractError::UnknownWitnessSelection)?;
        let address = plan
            .allocation
            .addresses
            .get(address_index)
            .ok_or(EgressContractError::UnknownWitnessSelection)?;
        let gateway = plan
            .gateways
            .get(gateway_index)
            .ok_or(EgressContractError::UnknownWitnessSelection)?;
        let material = serde_json::to_vec(&(
            plan.source.identity,
            plan.intent.uid.as_str(),
            address,
            gateway.node.uid.as_str(),
            gateway.lease_epoch,
            plan.revisions,
        ))
        .map_err(|error| EgressContractError::CanonicalEncoding(error.to_string()))?;
        let mut hasher = Sha256::new();
        hasher.update(b"unf.egress-decision-witness.v1\0");
        hasher.update(self.contract_digest.0);
        hasher.update(material);
        let digest = hasher.finalize();
        let mut witness = [0_u8; 16];
        witness.copy_from_slice(&digest[..16]);
        Ok(EgressDecisionWitness(witness))
    }
}

fn compile_contract(
    model: &EgressModel,
    facts: &EgressContractFacts,
    node: EgressNode,
    contract_revision: Revision,
) -> Result<EgressBehaviorContract, EgressContractError> {
    validate_revisions(facts.revisions, contract_revision)?;
    validate_node(&node)?;
    validate_facts(facts)?;
    let model = normalize_model(model.pools.clone(), model.intents.clone())?;
    let mut plans = Vec::new();
    let mut identities = BTreeSet::new();
    for source in facts.sources.iter().filter(|source| source.node == node) {
        if source.identity.get() == 0 || !identities.insert(source.identity) {
            return Err(EgressContractError::InvalidSource(source.identity));
        }
        plans.push(compile_plan(&model, facts, source)?);
    }
    if plans.len() > MAX_EGRESS_CONTRACT_PLANS {
        return Err(EgressContractError::TooManyPlans {
            actual: plans.len(),
            limit: MAX_EGRESS_CONTRACT_PLANS,
        });
    }
    plans.sort_by_key(|plan| plan.source.identity);
    let verified_invariants = vec![
        EgressInvariant::ModelNormalized,
        EgressInvariant::ExactNodeOwnership,
        EgressInvariant::SourceIdentitySelected,
        EgressInvariant::PolicyAllowBeforeSteering,
        EgressInvariant::AllocationIntentExact,
        EgressInvariant::GatewayLeaseFenced,
        EgressInvariant::GatewayReadinessAcknowledged,
        EgressInvariant::CapabilitiesAdmitted,
        EgressInvariant::RevisionsBound,
        EgressInvariant::StateBounded,
        EgressInvariant::FailureEnvelopeBounded,
    ];
    let failure_envelope = failure_envelope(&plans);
    let contract_digest = contract_digest(
        contract_revision,
        &node,
        &plans,
        &verified_invariants,
        &failure_envelope,
    )?;
    Ok(EgressBehaviorContract {
        schema_version: EGRESS_BEHAVIOR_CONTRACT_SCHEMA_VERSION,
        contract_revision,
        node,
        plans,
        verified_invariants,
        failure_envelope,
        contract_digest,
    })
}

fn contract_digest(
    contract_revision: Revision,
    node: &EgressNode,
    plans: &[EgressBehaviorPlan],
    verified_invariants: &[EgressInvariant],
    failure_envelope: &EgressFailureEnvelope,
) -> Result<EgressContractDigest, EgressContractError> {
    let digest_material = serde_json::to_vec(&(
        EGRESS_BEHAVIOR_CONTRACT_SCHEMA_VERSION,
        contract_revision,
        node,
        plans,
        verified_invariants,
        failure_envelope,
    ))
    .map_err(|error| EgressContractError::CanonicalEncoding(error.to_string()))?;
    let mut hasher = Sha256::new();
    hasher.update(b"unf.egress-behavior-contract.v1\0");
    hasher.update(digest_material);
    Ok(EgressContractDigest(hasher.finalize().into()))
}

fn compile_plan(
    model: &EgressModel,
    facts: &EgressContractFacts,
    source: &EgressSourceFact,
) -> Result<EgressBehaviorPlan, EgressContractError> {
    validate_source(source)?;
    let intent = model
        .intents
        .iter()
        .find(|intent| intent.owner.uid == source.intent_uid)
        .ok_or(EgressContractError::IntentMismatch(source.identity))?;
    if !intent.source.matches(
        &source.namespace_labels,
        &source.workload_labels,
        &source.service_account,
    ) {
        return Err(EgressContractError::IntentMismatch(source.identity));
    }
    let policy =
        unique_fact(facts.policies.iter().filter(|fact| {
            fact.identity == source.identity && fact.intent_uid == source.intent_uid
        }))
        .ok_or(EgressContractError::PolicyNotAllowed(source.identity))?;
    if !policy.allowed
        || policy.policy_ids.is_empty()
        || policy.policy_ids.iter().any(|id| id.get() == 0)
    {
        return Err(EgressContractError::PolicyNotAllowed(source.identity));
    }
    let mut policy_ids = policy.policy_ids.clone();
    policy_ids.sort_unstable();
    if policy_ids.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(EgressContractError::PolicyNotAllowed(source.identity));
    }
    let allocation = unique_fact(
        facts
            .allocations
            .iter()
            .filter(|fact| fact.intent_uid == source.intent_uid),
    )
    .ok_or(EgressContractError::AllocationMismatch(source.identity))?;
    let allocation = compile_allocation(model, intent, allocation, source.identity)?;
    let required_capabilities = required_capabilities(&allocation.addresses);
    for capability in [
        EgressCapability::IdentitySourceSteering,
        EgressCapability::LeaseEpochFencing,
        EgressCapability::OriginalTupleWitness,
    ] {
        if !source.node.capabilities.contains(&capability) {
            return Err(EgressContractError::MissingCapability {
                identity: source.identity,
                capability,
            });
        }
    }
    let mut gateways = facts
        .gateways
        .iter()
        .filter(|gateway| gateway.intent_uid == source.intent_uid)
        .cloned()
        .collect::<Vec<_>>();
    gateways.sort_unstable();
    validate_gateways(
        source.identity,
        allocation.lease_epoch,
        &required_capabilities,
        &gateways,
    )?;
    Ok(EgressBehaviorPlan {
        source: source.clone(),
        intent: intent.owner.clone(),
        destinations: intent.destinations.clone(),
        policy: EgressPolicyBinding {
            policy_ids,
            revision: facts.revisions.policy,
        },
        allocation,
        gateways,
        required_capabilities,
        revisions: facts.revisions,
    })
}

fn compile_allocation(
    model: &EgressModel,
    intent: &EgressIntent,
    fact: &EgressAllocationFact,
    identity: IdentityId,
) -> Result<EgressAllocationBinding, EgressContractError> {
    if fact.lease_epoch == 0 || fact.addresses.is_empty() {
        return Err(EgressContractError::AllocationMismatch(identity));
    }
    let mut addresses = fact.addresses.clone();
    addresses.sort_unstable();
    if addresses.windows(2).any(|pair| pair[0] == pair[1])
        || addresses.iter().any(IpAddr::is_unspecified)
    {
        return Err(EgressContractError::AllocationMismatch(identity));
    }
    let pool = match &intent.addresses {
        EgressAddressRequest::Explicit {
            addresses: expected,
        } => {
            if fact.pool_name.is_some() || fact.pool_uid.is_some() || addresses != *expected {
                return Err(EgressContractError::AllocationMismatch(identity));
            }
            None
        }
        EgressAddressRequest::Pool {
            name,
            families,
            addresses_per_family,
        } => {
            let pool = model
                .pools
                .iter()
                .find(|pool| pool.name == *name)
                .ok_or(EgressContractError::AllocationMismatch(identity))?;
            if fact.pool_name.as_ref() != Some(name) || fact.pool_uid.as_ref() != Some(&pool.uid) {
                return Err(EgressContractError::AllocationMismatch(identity));
            }
            for family in families {
                let count = addresses
                    .iter()
                    .filter(|address| family_of(**address) == *family)
                    .count();
                if count != usize::from(*addresses_per_family) {
                    return Err(EgressContractError::AllocationMismatch(identity));
                }
            }
            if addresses.len() != families.len() * usize::from(*addresses_per_family)
                || addresses
                    .iter()
                    .any(|address| !pool.prefixes.iter().any(|prefix| prefix.contains(*address)))
            {
                return Err(EgressContractError::AllocationMismatch(identity));
            }
            Some(pool_binding(pool))
        }
    };
    Ok(EgressAllocationBinding {
        pool,
        addresses,
        lease_epoch: fact.lease_epoch,
    })
}

fn validate_gateways(
    identity: IdentityId,
    lease_epoch: u64,
    required: &BTreeSet<EgressCapability>,
    gateways: &[EgressGatewayFact],
) -> Result<(), EgressContractError> {
    if gateways.is_empty() || gateways.len() > MAX_EGRESS_GATEWAYS_PER_PLAN {
        return Err(EgressContractError::GatewayMismatch(identity));
    }
    let mut nodes = BTreeSet::new();
    for (rank, gateway) in gateways.iter().enumerate() {
        validate_node(&gateway.node)?;
        if usize::from(gateway.rank) != rank
            || gateway.lease_epoch != lease_epoch
            || !gateway.ready
            || !gateway.reachable
            || !nodes.insert(gateway.node.uid.clone())
            || !required.is_subset(&gateway.node.capabilities)
        {
            return Err(EgressContractError::GatewayMismatch(identity));
        }
    }
    Ok(())
}

fn required_capabilities(addresses: &[IpAddr]) -> BTreeSet<EgressCapability> {
    let mut required = BTreeSet::from([
        EgressCapability::LeaseEpochFencing,
        EgressCapability::OriginalTupleWitness,
    ]);
    for address in addresses {
        required.insert(match address {
            IpAddr::V4(_) => EgressCapability::Ipv4TcpUdpNat,
            IpAddr::V6(_) => EgressCapability::Ipv6TcpUdpNat,
        });
    }
    required
}

fn failure_envelope(plans: &[EgressBehaviorPlan]) -> EgressFailureEnvelope {
    let total = plans
        .iter()
        .map(|plan| plan.gateways.len() as u64)
        .sum::<u64>();
    let mut observations = Vec::new();
    for plan in plans {
        for failed in &plan.gateways {
            if observations.len() == MAX_EGRESS_FAILURE_OBSERVATIONS {
                break;
            }
            let outcome = plan
                .gateways
                .iter()
                .find(|candidate| candidate.node.uid != failed.node.uid)
                .map_or(EgressFailureOutcome::Unavailable, |candidate| {
                    EgressFailureOutcome::Failover(candidate.node.clone())
                });
            observations.push(EgressFailureObservation {
                identity: plan.source.identity,
                failed_gateway: failed.node.clone(),
                outcome,
            });
        }
    }
    EgressFailureEnvelope {
        observations,
        total_observations: total,
        truncated: total > MAX_EGRESS_FAILURE_OBSERVATIONS as u64,
    }
}

fn validate_revisions(
    revisions: EgressContractRevisions,
    contract: Revision,
) -> Result<(), EgressContractError> {
    if contract == Revision::INITIAL
        || [
            revisions.intent,
            revisions.identity,
            revisions.policy,
            revisions.allocation,
            revisions.gateway,
            revisions.reachability,
        ]
        .contains(&Revision::INITIAL)
    {
        return Err(EgressContractError::ZeroRevision);
    }
    Ok(())
}

fn validate_facts(facts: &EgressContractFacts) -> Result<(), EgressContractError> {
    for (kind, actual, limit) in [
        ("source", facts.sources.len(), MAX_EGRESS_CONTRACT_PLANS),
        ("policy", facts.policies.len(), MAX_EGRESS_CONTRACT_PLANS),
        ("allocation", facts.allocations.len(), MAX_EGRESS_INTENTS),
        ("gateway", facts.gateways.len(), MAX_EGRESS_GATEWAY_FACTS),
    ] {
        if actual > limit {
            return Err(EgressContractError::TooManyFacts {
                kind,
                actual,
                limit,
            });
        }
    }
    let mut identities = BTreeSet::new();
    for source in &facts.sources {
        validate_source(source)?;
        if !identities.insert((source.identity, source.node.uid.as_str())) {
            return Err(EgressContractError::InvalidSource(source.identity));
        }
    }
    let mut policy_keys = BTreeSet::new();
    for policy in &facts.policies {
        if !policy_keys.insert((policy.identity, policy.intent_uid.as_str())) {
            return Err(EgressContractError::PolicyNotAllowed(policy.identity));
        }
    }
    let mut allocation_uids = BTreeSet::new();
    for allocation in &facts.allocations {
        if allocation.intent_uid.is_empty()
            || allocation.lease_epoch == 0
            || !allocation_uids.insert(allocation.intent_uid.as_str())
        {
            let identity = facts
                .sources
                .iter()
                .find(|source| source.intent_uid == allocation.intent_uid)
                .map_or(IdentityId::new(0), |source| source.identity);
            return Err(EgressContractError::AllocationMismatch(identity));
        }
    }
    let mut gateway_ranks = BTreeSet::new();
    let mut gateway_counts = BTreeMap::new();
    for gateway in &facts.gateways {
        validate_node(&gateway.node)?;
        if gateway.intent_uid.is_empty()
            || !gateway_ranks.insert((gateway.intent_uid.as_str(), gateway.rank))
        {
            return Err(EgressContractError::GatewayMismatch(IdentityId::new(0)));
        }
        let count = gateway_counts
            .entry(gateway.intent_uid.as_str())
            .or_insert(0_usize);
        *count += 1;
        if *count > MAX_EGRESS_GATEWAYS_PER_PLAN {
            return Err(EgressContractError::GatewayMismatch(IdentityId::new(0)));
        }
    }
    Ok(())
}

fn validate_node(node: &EgressNode) -> Result<(), EgressContractError> {
    if node.name.is_empty() || node.name.len() > 253 || node.uid.is_empty() || node.uid.len() > 128
    {
        return Err(EgressContractError::InvalidNode("name or UID is invalid"));
    }
    Ok(())
}

fn validate_source(source: &EgressSourceFact) -> Result<(), EgressContractError> {
    if source.identity.get() == 0
        || source.namespace.is_empty()
        || source.workload.is_empty()
        || source.workload_uid.is_empty()
        || source.service_account.is_empty()
        || source.intent_uid.is_empty()
    {
        return Err(EgressContractError::InvalidSource(source.identity));
    }
    validate_node(&source.node)
}

fn unique_fact<'a, T>(mut facts: impl Iterator<Item = &'a T>) -> Option<&'a T> {
    let first = facts.next()?;
    facts.next().is_none().then_some(first)
}

fn pool_binding(pool: &EgressAddressPool) -> EgressPoolBinding {
    EgressPoolBinding {
        name: pool.name.clone(),
        uid: pool.uid.clone(),
        provider: pool.provider.clone(),
    }
}

const fn family_of(address: IpAddr) -> AddressFamily {
    match address {
        IpAddr::V4(_) => AddressFamily::Ipv4,
        IpAddr::V6(_) => AddressFamily::Ipv6,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        DEFAULT_EGRESS_INTENT_PRIORITY, EgressAddressPool, EgressIntentScope, EgressProviderRef,
        EgressSourceSelector, IpPrefix,
    };

    fn ip(value: &str) -> IpAddr {
        value.parse().expect("valid test IP")
    }

    fn capabilities(ipv6: bool) -> BTreeSet<EgressCapability> {
        let mut capabilities = BTreeSet::from([
            EgressCapability::IdentitySourceSteering,
            EgressCapability::LeaseEpochFencing,
            EgressCapability::OriginalTupleWitness,
            EgressCapability::Ipv4TcpUdpNat,
        ]);
        if ipv6 {
            capabilities.insert(EgressCapability::Ipv6TcpUdpNat);
        }
        capabilities
    }

    fn node(name: &str) -> EgressNode {
        EgressNode {
            name: name.to_owned(),
            uid: format!("uid-{name}"),
            capabilities: capabilities(true),
        }
    }

    fn fixture() -> (EgressModel, EgressContractFacts, EgressNode) {
        let source_node = node("worker-a");
        let model = normalize_model(
            vec![EgressAddressPool {
                name: "finance".to_owned(),
                uid: "uid-pool".to_owned(),
                provider: EgressProviderRef {
                    name: "static".to_owned(),
                    instance: "lab".to_owned(),
                },
                prefixes: vec![
                    IpPrefix {
                        address: ip("192.0.2.0"),
                        prefix_len: 24,
                    },
                    IpPrefix {
                        address: ip("2001:db8::"),
                        prefix_len: 64,
                    },
                ],
            }],
            vec![EgressIntent {
                owner: EgressIntentOwner {
                    scope: EgressIntentScope::Namespace("finance".to_owned()),
                    name: "payments".to_owned(),
                    uid: "uid-intent".to_owned(),
                },
                priority: DEFAULT_EGRESS_INTENT_PRIORITY,
                source: EgressSourceSelector::default(),
                destinations: EgressDestinations::Any,
                fqdn: None,
                internet: None,
                addresses: EgressAddressRequest::Pool {
                    name: "finance".to_owned(),
                    families: vec![AddressFamily::Ipv4, AddressFamily::Ipv6],
                    addresses_per_family: 1,
                },
            }],
        )
        .expect("valid model");
        let revisions = EgressContractRevisions {
            intent: Revision::new(11),
            identity: Revision::new(12),
            policy: Revision::new(13),
            allocation: Revision::new(14),
            gateway: Revision::new(15),
            reachability: Revision::new(16),
        };
        let facts = EgressContractFacts {
            revisions,
            sources: vec![EgressSourceFact {
                identity: IdentityId::new(42),
                namespace: "finance".to_owned(),
                workload: "ledger-0".to_owned(),
                workload_uid: "uid-ledger".to_owned(),
                service_account: "settlement".to_owned(),
                namespace_labels: BTreeMap::new(),
                workload_labels: BTreeMap::new(),
                node: source_node.clone(),
                intent_uid: "uid-intent".to_owned(),
            }],
            policies: vec![EgressPolicyFact {
                identity: IdentityId::new(42),
                intent_uid: "uid-intent".to_owned(),
                allowed: true,
                policy_ids: vec![PolicyId::new(9), PolicyId::new(3)],
            }],
            allocations: vec![EgressAllocationFact {
                intent_uid: "uid-intent".to_owned(),
                pool_name: Some("finance".to_owned()),
                pool_uid: Some("uid-pool".to_owned()),
                addresses: vec![ip("2001:db8::20"), ip("192.0.2.20")],
                lease_epoch: 7,
            }],
            gateways: vec![
                EgressGatewayFact {
                    intent_uid: "uid-intent".to_owned(),
                    rank: 1,
                    node: node("gateway-b"),
                    lease_epoch: 7,
                    ready: true,
                    reachable: true,
                },
                EgressGatewayFact {
                    intent_uid: "uid-intent".to_owned(),
                    rank: 0,
                    node: node("gateway-a"),
                    lease_epoch: 7,
                    ready: true,
                    reachable: true,
                },
            ],
        };
        (model, facts, source_node)
    }

    #[test]
    fn contract_binds_every_domain_and_replays_independently() {
        let (model, facts, source_node) = fixture();
        let contract =
            EgressBehaviorContract::issue(&model, &facts, source_node.clone(), Revision::new(20))
                .expect("valid contract");
        contract
            .verify(&model, &facts, &source_node)
            .expect("independent replay");
        assert_eq!(contract.plans.len(), 1);
        let plan = &contract.plans[0];
        assert_eq!(
            plan.policy.policy_ids,
            vec![PolicyId::new(3), PolicyId::new(9)]
        );
        assert_eq!(
            plan.allocation.addresses,
            vec![ip("192.0.2.20"), ip("2001:db8::20")]
        );
        assert_eq!(plan.gateways[0].node.name, "gateway-a");
        assert_eq!(plan.revisions, facts.revisions);
        assert_eq!(contract.verified_invariants.len(), 11);
    }

    #[test]
    fn shared_workload_identity_can_be_projected_once_per_source_node() {
        let (model, mut facts, source_node) = fixture();
        let second_node = node("worker-b");
        let mut second_source = facts.sources[0].clone();
        second_source.node = second_node.clone();
        second_source.workload_uid = "uid-ledger-replica".to_owned();
        facts.sources.push(second_source);

        let first = EgressBehaviorContract::issue(&model, &facts, source_node, Revision::new(20))
            .expect("shared identity is valid on the first exact source Node");
        let second = EgressBehaviorContract::issue(&model, &facts, second_node, Revision::new(20))
            .expect("shared identity is valid on the second exact source Node");
        assert_eq!(first.plans.len(), 1);
        assert_eq!(second.plans.len(), 1);
        assert_eq!(
            first.plans[0].source.identity,
            second.plans[0].source.identity
        );
        assert_ne!(first.plans[0].source.node, second.plans[0].source.node);

        facts.sources[1].node = facts.sources[0].node.clone();
        assert!(matches!(
            EgressBehaviorContract::issue(
                &model,
                &facts,
                facts.sources[0].node.clone(),
                Revision::new(21)
            ),
            Err(EgressContractError::InvalidSource(IdentityId(42)))
        ));
    }

    #[test]
    fn digest_and_witness_are_deterministic_and_selection_exact() {
        let (model, mut facts, source_node) = fixture();
        let first =
            EgressBehaviorContract::issue(&model, &facts, source_node.clone(), Revision::new(20))
                .expect("valid contract");
        facts.gateways.reverse();
        let second = EgressBehaviorContract::issue(&model, &facts, source_node, Revision::new(20))
            .expect("order-independent contract");
        assert_eq!(first, second);
        assert_eq!(
            first.decision_witness(0, 0, 0).expect("valid witness"),
            second.decision_witness(0, 0, 0).expect("valid witness")
        );
        assert!(first.decision_witness(0, 2, 0).is_err());
    }

    #[test]
    fn independent_replay_rejects_mutated_policy_allocation_gateway_and_revision() {
        let (model, facts, source_node) = fixture();
        let contract =
            EgressBehaviorContract::issue(&model, &facts, source_node.clone(), Revision::new(20))
                .expect("valid contract");
        let mutations = [
            {
                let mut value = contract.clone();
                value.plans[0].policy.policy_ids.clear();
                value
            },
            {
                let mut value = contract.clone();
                value.plans[0].allocation.addresses[0] = ip("192.0.2.99");
                value
            },
            {
                let mut value = contract.clone();
                value.plans[0].gateways[0].lease_epoch += 1;
                value
            },
            {
                let mut value = contract.clone();
                value.plans[0].revisions.policy = Revision::new(99);
                value
            },
        ];
        for mutation in mutations {
            assert!(matches!(
                mutation.verify(&model, &facts, &source_node),
                Err(EgressContractError::ReplayMismatch)
            ));
        }
    }

    #[test]
    fn policy_allocation_readiness_and_capability_fail_closed() {
        let (model, facts, source_node) = fixture();
        let assert_rejected = |facts: &EgressContractFacts| {
            assert!(
                EgressBehaviorContract::issue(
                    &model,
                    facts,
                    source_node.clone(),
                    Revision::new(20)
                )
                .is_err()
            );
        };
        let mut denied = facts.clone();
        denied.policies[0].allowed = false;
        assert_rejected(&denied);
        let mut foreign = facts.clone();
        foreign.allocations[0].addresses[0] = ip("2001:db9::20");
        assert_rejected(&foreign);
        let mut unready = facts.clone();
        unready.gateways[0].ready = false;
        assert_rejected(&unready);
        let mut incapable = facts;
        incapable.gateways[0]
            .node
            .capabilities
            .remove(&EgressCapability::Ipv6TcpUdpNat);
        assert_rejected(&incapable);
    }

    #[test]
    fn failure_envelope_distinguishes_failover_from_unavailability() {
        let (model, mut facts, source_node) = fixture();
        let redundant =
            EgressBehaviorContract::issue(&model, &facts, source_node.clone(), Revision::new(20))
                .expect("valid contract");
        assert!(
            redundant
                .failure_envelope
                .observations
                .iter()
                .all(|item| matches!(item.outcome, EgressFailureOutcome::Failover(_)))
        );
        facts.gateways.truncate(1);
        facts.gateways[0].rank = 0;
        let single = EgressBehaviorContract::issue(&model, &facts, source_node, Revision::new(20))
            .expect("valid single gateway");
        assert_eq!(
            single.failure_envelope.observations[0].outcome,
            EgressFailureOutcome::Unavailable
        );
    }

    #[test]
    fn wire_shape_rejects_unknown_fields() {
        let (model, facts, source_node) = fixture();
        let contract =
            EgressBehaviorContract::issue(&model, &facts, source_node, Revision::new(20))
                .expect("valid contract");
        let mut json = serde_json::to_value(contract).expect("serializes");
        json.as_object_mut()
            .expect("object")
            .insert("futureAuthority".to_owned(), serde_json::json!(true));
        assert!(serde_json::from_value::<EgressBehaviorContract>(json).is_err());
    }
}
