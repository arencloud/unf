//! UNF Egress Proof Chain: zero-leak admission and bilateral flow decisions.
//!
//! A proof is not a bearer credential and is never trusted by itself. It is a
//! deterministic commitment that the source and selected gateway independently
//! reproduce from the same authenticated behavior contract and original tuple.

use std::collections::BTreeMap;
use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use unf_common::{IdentityId, Revision};
use unf_ebpf_common::{
    AddressFamily as BpfAddressFamily, EGRESS_CONNECTION_ROLE_FORWARD, EgressConnectionKey,
    egress_selection_bucket,
};

use crate::{
    AddressFamily, AdmittedEgressProjection, EgressBehaviorContract, EgressBehaviorPlan,
    EgressContractDigest, EgressContractError, EgressContractRevisions, EgressDecisionWitness,
    EgressDestinations, EgressHaDigest, EgressHaPlan, EgressIntentOwner, EgressNode,
    MAX_EGRESS_CONTRACT_PLANS,
};

pub const EGRESS_FLOW_PROOF_SCHEMA_VERSION: u16 = 2;
pub const EGRESS_SELECTION_ALGORITHM_COMPILED_RENDEZVOUS_SHA256_V2: u16 = 2;
pub const EGRESS_SELECTION_ALGORITHM_CCR_SHARD_V3: u16 = 3;
pub const EGRESS_PROTOCOL_TCP: u8 = 6;
pub const EGRESS_PROTOCOL_UDP: u8 = 17;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum EgressAdmissionDisposition {
    Native,
    Fenced,
    Active,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EgressFencedAdmission {
    pub owner: EgressIntentOwner,
    pub intent_revision: Revision,
    pub admission_revision: Revision,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EgressActiveAdmission {
    pub owner: EgressIntentOwner,
    pub intent_revision: Revision,
    pub admission_revision: Revision,
    pub controller_epoch: u64,
    pub projection_revision: Revision,
    pub contract_revision: Revision,
    pub contract_digest: EgressContractDigest,
    pub ha_plan_digest: Option<EgressHaDigest>,
    pub lease_epoch: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EgressAdmissionState {
    Fenced(EgressFencedAdmission),
    Active(EgressActiveAdmission),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EgressAdmissionDecision {
    Native,
    Fenced(EgressFencedAdmission),
    Active(EgressActiveAdmission),
}

impl EgressAdmissionDecision {
    #[must_use]
    pub const fn disposition(&self) -> EgressAdmissionDisposition {
        match self {
            Self::Native => EgressAdmissionDisposition::Native,
            Self::Fenced(_) => EgressAdmissionDisposition::Fenced,
            Self::Active(_) => EgressAdmissionDisposition::Active,
        }
    }
}

/// Identity-indexed admission guard. The controller distributes a fence before
/// any explicit egress intent can become active; absence alone means native.
#[derive(Debug, Clone, Default)]
pub struct EgressAdmissionGuard {
    revision: Revision,
    identities: BTreeMap<IdentityId, EgressAdmissionState>,
}

impl EgressAdmissionGuard {
    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    #[must_use]
    pub fn decision(&self, identity: IdentityId) -> EgressAdmissionDecision {
        match self.identities.get(&identity) {
            None => EgressAdmissionDecision::Native,
            Some(EgressAdmissionState::Fenced(fence)) => {
                EgressAdmissionDecision::Fenced(fence.clone())
            }
            Some(EgressAdmissionState::Active(active)) => {
                EgressAdmissionDecision::Active(active.clone())
            }
        }
    }

    /// Installs the fail-closed state before allocation or contract activation.
    ///
    /// # Errors
    ///
    /// Rejects invalid identity/ownership, intent regression, foreign owner
    /// replacement, capacity exhaustion, or revision exhaustion.
    pub fn fence(
        &mut self,
        identity: IdentityId,
        owner: EgressIntentOwner,
        intent_revision: Revision,
    ) -> Result<EgressAdmissionDecision, EgressProofError> {
        validate_identity_owner(identity, &owner, intent_revision)?;
        if !self.identities.contains_key(&identity)
            && self.identities.len() >= MAX_EGRESS_CONTRACT_PLANS
        {
            return Err(EgressProofError::AdmissionCapacity);
        }
        if let Some(existing) = self.identities.get(&identity) {
            let (existing_owner, existing_revision) = match existing {
                EgressAdmissionState::Fenced(state) => (&state.owner, state.intent_revision),
                EgressAdmissionState::Active(state) => (&state.owner, state.intent_revision),
            };
            if *existing_owner != owner {
                return Err(EgressProofError::ForeignOwner);
            }
            if intent_revision < existing_revision {
                return Err(EgressProofError::RevisionRegression);
            }
            if let EgressAdmissionState::Fenced(state) = existing
                && intent_revision == existing_revision
            {
                return Ok(EgressAdmissionDecision::Fenced(state.clone()));
            }
        }
        let admission_revision = self.advance()?;
        let fence = EgressFencedAdmission {
            owner,
            intent_revision,
            admission_revision,
        };
        self.identities
            .insert(identity, EgressAdmissionState::Fenced(fence.clone()));
        Ok(EgressAdmissionDecision::Fenced(fence))
    }

    /// Activates exactly one identity from an independently admitted contract.
    /// A prior matching fence is mandatory.
    ///
    /// # Errors
    ///
    /// Rejects missing/mismatched fences, absent plans, or invalid lease state.
    pub fn activate(
        &mut self,
        identity: IdentityId,
        projection: &AdmittedEgressProjection,
    ) -> Result<EgressActiveAdmission, EgressProofError> {
        let projection = projection.projection();
        let plan = unique_plan(&projection.contract, identity)?;
        let Some(EgressAdmissionState::Fenced(fence)) = self.identities.get(&identity) else {
            return Err(EgressProofError::FenceRequired);
        };
        if fence.owner != plan.intent || fence.intent_revision != plan.revisions.intent {
            return Err(EgressProofError::FenceMismatch);
        }
        if plan.allocation.lease_epoch == 0 {
            return Err(EgressProofError::InvalidFlow("zero lease epoch"));
        }
        let admission_revision = self.advance()?;
        let active = EgressActiveAdmission {
            owner: plan.intent.clone(),
            intent_revision: plan.revisions.intent,
            admission_revision,
            controller_epoch: projection.controller_epoch,
            projection_revision: projection.revision,
            contract_revision: projection.contract.contract_revision,
            contract_digest: projection.contract.contract_digest,
            ha_plan_digest: projection
                .ha_plans
                .iter()
                .find(|ha_plan| ha_plan.owner == plan.intent)
                .map(|ha_plan| ha_plan.plan_digest),
            lease_epoch: plan.allocation.lease_epoch,
        };
        self.identities
            .insert(identity, EgressAdmissionState::Active(active.clone()));
        Ok(active)
    }

    /// Returns active intent to a fail-closed fence before withdrawal.
    ///
    /// # Errors
    ///
    /// Rejects an unknown identity or foreign owner.
    pub fn retire(
        &mut self,
        identity: IdentityId,
        owner: &EgressIntentOwner,
    ) -> Result<EgressFencedAdmission, EgressProofError> {
        let Some(existing) = self.identities.get(&identity) else {
            return Err(EgressProofError::UnknownAdmission);
        };
        let intent_revision = match existing {
            EgressAdmissionState::Fenced(state) if &state.owner == owner => {
                return Ok(state.clone());
            }
            EgressAdmissionState::Active(state) if &state.owner == owner => state.intent_revision,
            _ => return Err(EgressProofError::ForeignOwner),
        };
        let admission_revision = self.advance()?;
        let fence = EgressFencedAdmission {
            owner: owner.clone(),
            intent_revision,
            admission_revision,
        };
        self.identities
            .insert(identity, EgressAdmissionState::Fenced(fence.clone()));
        Ok(fence)
    }

    /// Releases an identity to native routing only after external orchestration
    /// has completed safe gateway/address withdrawal.
    ///
    /// # Errors
    ///
    /// Rejects an active, unknown, or foreign-owned identity.
    pub fn release_native(
        &mut self,
        identity: IdentityId,
        owner: &EgressIntentOwner,
    ) -> Result<Revision, EgressProofError> {
        match self.identities.get(&identity) {
            Some(EgressAdmissionState::Fenced(state)) if &state.owner == owner => {}
            Some(EgressAdmissionState::Active(state)) if &state.owner == owner => {
                return Err(EgressProofError::AdmissionStillActive);
            }
            Some(_) => return Err(EgressProofError::ForeignOwner),
            None => return Err(EgressProofError::UnknownAdmission),
        }
        let revision = self.advance()?;
        self.identities.remove(&identity);
        Ok(revision)
    }

    fn advance(&mut self) -> Result<Revision, EgressProofError> {
        let next = self
            .revision
            .get()
            .checked_add(1)
            .ok_or(EgressProofError::CounterExhausted)?;
        self.revision = Revision::new(next);
        Ok(self.revision)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EgressOriginalFlow {
    pub identity: IdentityId,
    pub source_address: IpAddr,
    pub destination_address: IpAddr,
    pub source_port: u16,
    pub destination_port: u16,
    pub protocol: u8,
    pub fragmented: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EgressOriginalTupleDigest(pub [u8; 16]);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EgressFlowProofDigest(pub [u8; 32]);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EgressFlowProof {
    pub schema_version: u16,
    pub selection_algorithm: u16,
    pub identity: IdentityId,
    pub intent_uid: String,
    pub contract_revision: Revision,
    pub contract_digest: EgressContractDigest,
    pub ha_plan_digest: Option<EgressHaDigest>,
    pub revisions: EgressContractRevisions,
    pub lease_epoch: u64,
    pub egress_address: IpAddr,
    pub gateway_rank: u16,
    pub gateway: EgressNode,
    pub decision_witness: EgressDecisionWitness,
    pub original_tuple_digest: EgressOriginalTupleDigest,
    pub proof_digest: EgressFlowProofDigest,
}

impl EgressFlowProof {
    /// Produces a proof only for an active, exact admitted identity.
    ///
    /// # Errors
    ///
    /// Rejects native/fenced identities, contract drift, unsupported tuples,
    /// destination mismatch, or missing family/gateway choices.
    pub fn issue(
        projection: &AdmittedEgressProjection,
        guard: &EgressAdmissionGuard,
        flow: EgressOriginalFlow,
    ) -> Result<Self, EgressProofError> {
        let active = match guard.decision(flow.identity) {
            EgressAdmissionDecision::Native => return Err(EgressProofError::NativeFlow),
            EgressAdmissionDecision::Fenced(_) => return Err(EgressProofError::IntentFenced),
            EgressAdmissionDecision::Active(active) => active,
        };
        let projection = projection.projection();
        let plan = unique_plan(&projection.contract, flow.identity)?;
        if active.owner != plan.intent
            || active.controller_epoch != projection.controller_epoch
            || active.projection_revision != projection.revision
            || active.contract_revision != projection.contract.contract_revision
            || active.contract_digest != projection.contract.contract_digest
            || active.lease_epoch != plan.allocation.lease_epoch
        {
            return Err(EgressProofError::AdmissionMismatch);
        }
        let ha_plan = projection
            .ha_plans
            .iter()
            .find(|ha_plan| ha_plan.owner == plan.intent);
        if active.ha_plan_digest != ha_plan.map(|plan| plan.plan_digest) {
            return Err(EgressProofError::AdmissionMismatch);
        }
        derive(&projection.contract, plan, flow, ha_plan)
    }

    /// Independently reproduces the source decision on the selected gateway.
    /// The caller supplies `flow.identity` from the gateway's authoritative
    /// identity lookup; proof bytes never establish identity.
    ///
    /// # Errors
    ///
    /// Rejects wrong gateway ownership, tuple/contract/proof mutation, or any
    /// decision the gateway cannot reproduce exactly.
    pub fn verify_at_gateway(
        &self,
        contract: &EgressBehaviorContract,
        gateway: &EgressNode,
        flow: EgressOriginalFlow,
    ) -> Result<(), EgressProofError> {
        contract.verify_integrity()?;
        self.verify_at_gateway_with_ha(contract, gateway, flow, None)
    }

    /// Reproduces a decision with the exact distributed CCR plan.
    ///
    /// # Errors
    ///
    /// Rejects plan, gateway, tuple, contract, or proof mismatch.
    pub fn verify_at_gateway_with_ha(
        &self,
        contract: &EgressBehaviorContract,
        gateway: &EgressNode,
        flow: EgressOriginalFlow,
        ha_plan: Option<&EgressHaPlan>,
    ) -> Result<(), EgressProofError> {
        contract.verify_integrity()?;
        let expected_algorithm = if ha_plan.is_some() {
            EGRESS_SELECTION_ALGORITHM_CCR_SHARD_V3
        } else {
            EGRESS_SELECTION_ALGORITHM_COMPILED_RENDEZVOUS_SHA256_V2
        };
        if self.schema_version != EGRESS_FLOW_PROOF_SCHEMA_VERSION
            || self.selection_algorithm != expected_algorithm
            || self.gateway != *gateway
        {
            return Err(EgressProofError::GatewayMismatch);
        }
        let plan = unique_plan(contract, flow.identity)?;
        let expected = derive(contract, plan, flow, ha_plan)?;
        if *self != expected {
            return Err(EgressProofError::ProofMismatch);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum EgressProofError {
    #[error("egress admission identity or owner is invalid")]
    InvalidAdmission,
    #[error("egress admission capacity is exhausted")]
    AdmissionCapacity,
    #[error("egress admission is owned by a different intent")]
    ForeignOwner,
    #[error("egress admission revision regressed")]
    RevisionRegression,
    #[error("egress admission counter is exhausted")]
    CounterExhausted,
    #[error("egress identity must be fenced before activation")]
    FenceRequired,
    #[error("egress fence does not match the admitted contract")]
    FenceMismatch,
    #[error("egress admission does not match the admitted contract")]
    AdmissionMismatch,
    #[error("egress admission is unknown")]
    UnknownAdmission,
    #[error("active egress admission must retire to a fence before native release")]
    AdmissionStillActive,
    #[error("flow has no explicit egress intent and remains native")]
    NativeFlow,
    #[error("explicit egress intent is fenced and must drop new flows")]
    IntentFenced,
    #[error("egress contract has no unique plan for identity {0:?}")]
    UnknownPlan(IdentityId),
    #[error("invalid egress flow: {0}")]
    InvalidFlow(&'static str),
    #[error("egress flow destination is outside the admitted intent")]
    DestinationMismatch,
    #[error("egress flow has no allocated address for its family")]
    AddressFamilyUnavailable,
    #[error("egress flow has no ready gateway")]
    GatewayUnavailable,
    #[error("egress flow arrived at a gateway not selected by its proof")]
    GatewayMismatch,
    #[error("egress flow proof does not reproduce from trusted state")]
    ProofMismatch,
    #[error("egress flow proof encoding failed: {0}")]
    Encoding(String),
    #[error(transparent)]
    Contract(#[from] EgressContractError),
}

fn derive(
    contract: &EgressBehaviorContract,
    plan: &EgressBehaviorPlan,
    flow: EgressOriginalFlow,
    ha_plan: Option<&EgressHaPlan>,
) -> Result<EgressFlowProof, EgressProofError> {
    validate_flow(plan, flow)?;
    let address_family = family(flow.source_address);
    let selection = select_bucket_with_ha(plan, address_family, flow_bucket(flow), ha_plan)?;
    let address_index = selection.address_index;
    let egress_address = selection.address;
    let gateway_index = selection.primary_gateway_index;
    let gateway = selection.primary_gateway;
    let decision_witness = contract.decision_witness(
        address_plan_index(contract, flow.identity)?,
        address_index,
        gateway_index,
    )?;
    let original_tuple_digest = tuple_digest(flow);
    let mut proof = EgressFlowProof {
        schema_version: EGRESS_FLOW_PROOF_SCHEMA_VERSION,
        selection_algorithm: if ha_plan.is_some() {
            EGRESS_SELECTION_ALGORITHM_CCR_SHARD_V3
        } else {
            EGRESS_SELECTION_ALGORITHM_COMPILED_RENDEZVOUS_SHA256_V2
        },
        identity: flow.identity,
        intent_uid: plan.intent.uid.clone(),
        contract_revision: contract.contract_revision,
        contract_digest: contract.contract_digest,
        ha_plan_digest: ha_plan.map(|plan| plan.plan_digest),
        revisions: plan.revisions,
        lease_epoch: plan.allocation.lease_epoch,
        egress_address,
        gateway_rank: gateway.rank,
        gateway: gateway.node.clone(),
        decision_witness,
        original_tuple_digest,
        proof_digest: EgressFlowProofDigest([0; 32]),
    };
    proof.proof_digest = proof_digest(&proof)?;
    Ok(proof)
}

fn validate_flow(
    plan: &EgressBehaviorPlan,
    flow: EgressOriginalFlow,
) -> Result<(), EgressProofError> {
    if flow.identity.get() == 0
        || flow.source_address.is_unspecified()
        || flow.destination_address.is_unspecified()
        || family(flow.source_address) != family(flow.destination_address)
        || flow.source_port == 0
        || flow.destination_port == 0
    {
        return Err(EgressProofError::InvalidFlow("invalid original tuple"));
    }
    if flow.fragmented {
        return Err(EgressProofError::InvalidFlow("fragments are unsupported"));
    }
    if !matches!(flow.protocol, EGRESS_PROTOCOL_TCP | EGRESS_PROTOCOL_UDP) {
        return Err(EgressProofError::InvalidFlow("protocol is unsupported"));
    }
    if flow.identity != plan.source.identity {
        return Err(EgressProofError::UnknownPlan(flow.identity));
    }
    let allowed = match &plan.destinations {
        EgressDestinations::Any => true,
        EgressDestinations::Networks(networks) => networks
            .iter()
            .any(|network| network.contains(flow.destination_address)),
    };
    if !allowed {
        return Err(EgressProofError::DestinationMismatch);
    }
    Ok(())
}

pub(crate) struct EgressBucketSelection<'a> {
    pub address_index: usize,
    pub address: IpAddr,
    pub primary_gateway_index: usize,
    pub primary_gateway: &'a crate::EgressGatewayFact,
    pub standby_gateway_index: Option<usize>,
}

pub(crate) fn select_bucket(
    plan: &EgressBehaviorPlan,
    address_family: AddressFamily,
    bucket: u16,
) -> Result<EgressBucketSelection<'_>, EgressProofError> {
    let mut addresses = plan
        .allocation
        .addresses
        .iter()
        .enumerate()
        .filter(|(_, address)| family(**address) == address_family)
        .map(|(index, address)| {
            (
                rendezvous_score(
                    b"unf.egress-address-bucket-rendezvous.v2\0",
                    plan,
                    bucket,
                    &address_bytes(*address),
                ),
                index,
                *address,
            )
        })
        .collect::<Vec<_>>();
    addresses.sort_by(|left, right| right.0.cmp(&left.0).then_with(|| left.1.cmp(&right.1)));
    let Some((_, address_index, address)) = addresses.first().copied() else {
        return Err(EgressProofError::AddressFamilyUnavailable);
    };

    let mut gateways = plan
        .gateways
        .iter()
        .enumerate()
        .filter(|(_, gateway)| gateway.ready && gateway.reachable)
        .map(|(index, gateway)| {
            (
                rendezvous_score(
                    b"unf.egress-gateway-bucket-rendezvous.v2\0",
                    plan,
                    bucket,
                    gateway.node.uid.as_bytes(),
                ),
                index,
                gateway,
            )
        })
        .collect::<Vec<_>>();
    gateways.sort_by(|left, right| right.0.cmp(&left.0).then_with(|| left.1.cmp(&right.1)));
    let Some((_, primary_gateway_index, primary_gateway)) = gateways.first().copied() else {
        return Err(EgressProofError::GatewayUnavailable);
    };
    let standby_gateway_index = gateways.get(1).map(|(_, index, _)| *index);
    Ok(EgressBucketSelection {
        address_index,
        address,
        primary_gateway_index,
        primary_gateway,
        standby_gateway_index,
    })
}

pub(crate) fn select_bucket_with_ha<'a>(
    plan: &'a EgressBehaviorPlan,
    address_family: AddressFamily,
    bucket: u16,
    ha_plan: Option<&EgressHaPlan>,
) -> Result<EgressBucketSelection<'a>, EgressProofError> {
    let mut selected = select_bucket(plan, address_family, bucket)?;
    let Some(ha_plan) = ha_plan else {
        return Ok(selected);
    };
    ha_plan
        .verify_integrity()
        .map_err(|_| EgressProofError::ProofMismatch)?;
    let shard = ha_plan
        .shards
        .iter()
        .find(|shard| shard.addresses.contains(&selected.address))
        .ok_or(EgressProofError::ProofMismatch)?;
    let assignment = ha_plan
        .assignments
        .iter()
        .find(|assignment| assignment.shard_index == shard.index)
        .ok_or(EgressProofError::ProofMismatch)?;
    let primary_gateway_index = plan
        .gateways
        .iter()
        .position(|gateway| gateway.node == assignment.gateway)
        .ok_or(EgressProofError::ProofMismatch)?;
    let contingency = ha_plan
        .contingencies
        .iter()
        .find(|contingency| contingency.failed_gateway == assignment.gateway)
        .ok_or(EgressProofError::ProofMismatch)?;
    let standby = contingency
        .assignments
        .iter()
        .find(|candidate| candidate.shard_index == shard.index)
        .ok_or(EgressProofError::ProofMismatch)?;
    let standby_gateway_index = plan
        .gateways
        .iter()
        .position(|gateway| gateway.node == standby.gateway)
        .ok_or(EgressProofError::ProofMismatch)?;
    if primary_gateway_index == standby_gateway_index {
        return Err(EgressProofError::ProofMismatch);
    }
    selected.primary_gateway_index = primary_gateway_index;
    selected.primary_gateway = &plan.gateways[primary_gateway_index];
    selected.standby_gateway_index = Some(standby_gateway_index);
    Ok(selected)
}

fn rendezvous_score(
    domain: &[u8],
    plan: &EgressBehaviorPlan,
    bucket: u16,
    candidate: &[u8],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(plan.intent.uid.as_bytes());
    hasher.update(plan.allocation.lease_epoch.to_be_bytes());
    hasher.update(bucket.to_be_bytes());
    hasher.update(candidate);
    hasher.finalize().into()
}

pub(crate) fn flow_bucket(flow: EgressOriginalFlow) -> u16 {
    let key = EgressConnectionKey {
        source_address: address_bytes(flow.source_address),
        destination_address: address_bytes(flow.destination_address),
        source_port: flow.source_port.to_be_bytes(),
        destination_port: flow.destination_port.to_be_bytes(),
        source_identity: flow.identity,
        protocol: flow.protocol,
        address_family: match family(flow.source_address) {
            AddressFamily::Ipv4 => BpfAddressFamily::Ipv4 as u8,
            AddressFamily::Ipv6 => BpfAddressFamily::Ipv6 as u8,
        },
        role: EGRESS_CONNECTION_ROLE_FORWARD,
        reserved: 0,
    };
    egress_selection_bucket(&key)
}

fn tuple_digest(flow: EgressOriginalFlow) -> EgressOriginalTupleDigest {
    let mut hasher = Sha256::new();
    hasher.update(b"unf.egress-original-tuple.v1\0");
    hasher.update(flow_bytes(flow));
    let digest = hasher.finalize();
    let mut truncated = [0; 16];
    truncated.copy_from_slice(&digest[..16]);
    EgressOriginalTupleDigest(truncated)
}

fn proof_digest(proof: &EgressFlowProof) -> Result<EgressFlowProofDigest, EgressProofError> {
    let material = serde_json::to_vec(&(
        proof.schema_version,
        proof.selection_algorithm,
        proof.identity,
        proof.intent_uid.as_str(),
        proof.contract_revision,
        proof.contract_digest,
        proof.ha_plan_digest,
        proof.revisions,
        proof.lease_epoch,
        proof.egress_address,
        proof.gateway_rank,
        &proof.gateway,
        proof.decision_witness,
        proof.original_tuple_digest,
    ))
    .map_err(|error| EgressProofError::Encoding(error.to_string()))?;
    let mut hasher = Sha256::new();
    hasher.update(b"unf.egress-flow-proof.v2\0");
    hasher.update(material);
    Ok(EgressFlowProofDigest(hasher.finalize().into()))
}

fn flow_bytes(flow: EgressOriginalFlow) -> [u8; 44] {
    let mut bytes = [0; 44];
    bytes[..4].copy_from_slice(&flow.identity.get().to_be_bytes());
    bytes[4] = match family(flow.source_address) {
        AddressFamily::Ipv4 => 4,
        AddressFamily::Ipv6 => 6,
    };
    bytes[5] = flow.protocol;
    bytes[6] = u8::from(flow.fragmented);
    bytes[8..24].copy_from_slice(&address_bytes(flow.source_address));
    bytes[24..40].copy_from_slice(&address_bytes(flow.destination_address));
    bytes[40..42].copy_from_slice(&flow.source_port.to_be_bytes());
    bytes[42..44].copy_from_slice(&flow.destination_port.to_be_bytes());
    bytes
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

fn family(address: IpAddr) -> AddressFamily {
    match address {
        IpAddr::V4(_) => AddressFamily::Ipv4,
        IpAddr::V6(_) => AddressFamily::Ipv6,
    }
}

fn address_plan_index(
    contract: &EgressBehaviorContract,
    identity: IdentityId,
) -> Result<usize, EgressProofError> {
    contract
        .plans
        .iter()
        .position(|plan| plan.source.identity == identity)
        .ok_or(EgressProofError::UnknownPlan(identity))
}

fn unique_plan(
    contract: &EgressBehaviorContract,
    identity: IdentityId,
) -> Result<&EgressBehaviorPlan, EgressProofError> {
    let mut plans = contract
        .plans
        .iter()
        .filter(|plan| plan.source.identity == identity);
    let plan = plans
        .next()
        .ok_or(EgressProofError::UnknownPlan(identity))?;
    if plans.next().is_some() {
        return Err(EgressProofError::UnknownPlan(identity));
    }
    Ok(plan)
}

fn validate_identity_owner(
    identity: IdentityId,
    owner: &EgressIntentOwner,
    intent_revision: Revision,
) -> Result<(), EgressProofError> {
    if identity.get() == 0
        || owner.name.is_empty()
        || owner.uid.is_empty()
        || intent_revision == Revision::INITIAL
    {
        return Err(EgressProofError::InvalidAdmission);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;
    use crate::distribution::test_support::{advertisement, fixture, node, principal};
    use crate::{EgressAddressRequest, EgressGatewayFact, EgressNodeProjection, IpPrefix};

    fn ip(value: &str) -> IpAddr {
        value.parse().expect("valid test address")
    }

    fn multi_projection() -> AdmittedEgressProjection {
        let (mut model, mut facts, _) = fixture();
        model.intents[0].addresses = EgressAddressRequest::Pool {
            name: "finance".to_owned(),
            families: vec![AddressFamily::Ipv4, AddressFamily::Ipv6],
            addresses_per_family: 2,
        };
        facts.allocations[0].addresses = vec![
            ip("192.0.2.20"),
            ip("192.0.2.21"),
            ip("2001:db8::20"),
            ip("2001:db8::21"),
        ];
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
                .expect("valid multiple-choice contract");
        EgressNodeProjection::issue(
            &principal("worker-a"),
            &advertisement(),
            10,
            Revision::new(4),
            contract,
        )
        .expect("issue projection")
        .admit(&principal("worker-a"), &advertisement(), &model, &facts)
        .expect("admit projection")
    }

    fn guarded(projection: &AdmittedEgressProjection) -> (EgressAdmissionGuard, IdentityId) {
        let plan = &projection.projection().contract.plans[0];
        let identity = plan.source.identity;
        let mut guard = EgressAdmissionGuard::default();
        guard
            .fence(identity, plan.intent.clone(), plan.revisions.intent)
            .expect("install fence");
        guard
            .activate(identity, projection)
            .expect("activate admission");
        (guard, identity)
    }

    fn flow(identity: IdentityId, source_port: u16) -> EgressOriginalFlow {
        EgressOriginalFlow {
            identity,
            source_address: ip("10.244.1.20"),
            destination_address: ip("198.51.100.30"),
            source_port,
            destination_port: 443,
            protocol: EGRESS_PROTOCOL_TCP,
            fragmented: false,
        }
    }

    #[test]
    fn explicit_intent_is_fenced_before_it_can_become_active() {
        let projection = multi_projection();
        let plan = &projection.projection().contract.plans[0];
        let identity = plan.source.identity;
        let mut guard = EgressAdmissionGuard::default();
        assert_eq!(
            guard.decision(identity).disposition(),
            EgressAdmissionDisposition::Native
        );
        guard
            .fence(identity, plan.intent.clone(), plan.revisions.intent)
            .expect("install fence");
        assert_eq!(
            guard.decision(identity).disposition(),
            EgressAdmissionDisposition::Fenced
        );
        assert_eq!(
            EgressFlowProof::issue(&projection, &guard, flow(identity, 30_000)),
            Err(EgressProofError::IntentFenced)
        );
    }

    #[test]
    fn activation_requires_exact_fence_and_safe_retirement_before_native() {
        let projection = multi_projection();
        let plan = &projection.projection().contract.plans[0];
        let identity = plan.source.identity;
        let mut guard = EgressAdmissionGuard::default();
        assert_eq!(
            guard.activate(identity, &projection),
            Err(EgressProofError::FenceRequired)
        );
        guard
            .fence(identity, plan.intent.clone(), plan.revisions.intent)
            .expect("install fence");
        guard
            .activate(identity, &projection)
            .expect("activate exact intent");
        assert_eq!(
            guard.release_native(identity, &plan.intent),
            Err(EgressProofError::AdmissionStillActive)
        );
        guard.retire(identity, &plan.intent).expect("retire active");
        guard
            .release_native(identity, &plan.intent)
            .expect("release after withdrawal boundary");
        assert_eq!(
            guard.decision(identity).disposition(),
            EgressAdmissionDisposition::Native
        );
    }

    #[test]
    fn deterministic_selection_uses_all_multiple_addresses_and_gateways() {
        let projection = multi_projection();
        let (guard, identity) = guarded(&projection);
        let mut addresses = BTreeSet::new();
        let mut gateways = BTreeSet::new();
        for source_port in 30_000..30_512 {
            let proof = EgressFlowProof::issue(&projection, &guard, flow(identity, source_port))
                .expect("issue proof");
            let replay = EgressFlowProof::issue(&projection, &guard, flow(identity, source_port))
                .expect("replay proof");
            assert_eq!(proof, replay);
            addresses.insert(proof.egress_address);
            gateways.insert(proof.gateway.uid);
        }
        assert_eq!(
            addresses,
            BTreeSet::from([ip("192.0.2.20"), ip("192.0.2.21")])
        );
        assert_eq!(gateways.len(), 2);
    }

    #[test]
    fn dual_stack_flow_selects_only_same_family_address() {
        let projection = multi_projection();
        let (guard, identity) = guarded(&projection);
        let ipv4 = EgressFlowProof::issue(&projection, &guard, flow(identity, 30_000))
            .expect("IPv4 proof");
        assert!(ipv4.egress_address.is_ipv4());
        let ipv6_flow = EgressOriginalFlow {
            source_address: ip("fd00::20"),
            destination_address: ip("2001:db8:ffff::30"),
            ..flow(identity, 30_001)
        };
        let ipv6 = EgressFlowProof::issue(&projection, &guard, ipv6_flow).expect("IPv6 proof");
        assert!(ipv6.egress_address.is_ipv6());
    }

    #[test]
    fn original_destination_constraint_is_checked_before_selection() {
        let (mut model, facts, _) = fixture();
        model.intents[0].destinations = EgressDestinations::Networks(vec![IpPrefix {
            address: ip("203.0.113.0"),
            prefix_len: 24,
        }]);
        let contract =
            EgressBehaviorContract::issue(&model, &facts, node("worker-a"), Revision::new(20))
                .expect("destination contract");
        let projection = EgressNodeProjection::issue(
            &principal("worker-a"),
            &advertisement(),
            10,
            Revision::new(4),
            contract,
        )
        .expect("issue")
        .admit(&principal("worker-a"), &advertisement(), &model, &facts)
        .expect("admit");
        let (guard, identity) = guarded(&projection);
        assert_eq!(
            EgressFlowProof::issue(&projection, &guard, flow(identity, 30_000)),
            Err(EgressProofError::DestinationMismatch)
        );
        let allowed = EgressOriginalFlow {
            destination_address: ip("203.0.113.9"),
            ..flow(identity, 30_000)
        };
        EgressFlowProof::issue(&projection, &guard, allowed).expect("allowed destination");
    }

    #[test]
    fn fragments_sctp_and_mixed_families_fail_closed() {
        let projection = multi_projection();
        let (guard, identity) = guarded(&projection);
        let fragmented = EgressOriginalFlow {
            fragmented: true,
            ..flow(identity, 30_000)
        };
        assert!(matches!(
            EgressFlowProof::issue(&projection, &guard, fragmented),
            Err(EgressProofError::InvalidFlow("fragments are unsupported"))
        ));
        let sctp = EgressOriginalFlow {
            protocol: 132,
            ..flow(identity, 30_001)
        };
        assert!(matches!(
            EgressFlowProof::issue(&projection, &guard, sctp),
            Err(EgressProofError::InvalidFlow("protocol is unsupported"))
        ));
        let mixed = EgressOriginalFlow {
            destination_address: ip("2001:db8::30"),
            ..flow(identity, 30_002)
        };
        assert!(matches!(
            EgressFlowProof::issue(&projection, &guard, mixed),
            Err(EgressProofError::InvalidFlow("invalid original tuple"))
        ));
    }

    #[test]
    fn selected_gateway_independently_replays_proof_and_rejects_mutation() {
        let projection = multi_projection();
        let (guard, identity) = guarded(&projection);
        let original = flow(identity, 30_000);
        let proof = EgressFlowProof::issue(&projection, &guard, original).expect("proof");
        proof
            .verify_at_gateway(&projection.projection().contract, &proof.gateway, original)
            .expect("bilateral replay");
        assert_eq!(
            proof.verify_at_gateway(
                &projection.projection().contract,
                &node("foreign-gateway"),
                original,
            ),
            Err(EgressProofError::GatewayMismatch)
        );
        assert_eq!(
            proof.verify_at_gateway(
                &projection.projection().contract,
                &proof.gateway,
                flow(identity, 30_001),
            ),
            Err(EgressProofError::ProofMismatch)
        );
        let mut mutation = proof.clone();
        mutation.proof_digest.0[0] ^= 0xff;
        assert_eq!(
            mutation.verify_at_gateway(
                &projection.projection().contract,
                &mutation.gateway,
                original,
            ),
            Err(EgressProofError::ProofMismatch)
        );
    }

    #[test]
    fn rendezvous_removal_moves_only_flows_using_removed_gateway() {
        let projection = multi_projection();
        let plan = &projection.projection().contract.plans[0];
        let identity = plan.source.identity;
        for source_port in 30_000..30_128 {
            let original = flow(identity, source_port);
            let selected = select_bucket(plan, AddressFamily::Ipv4, flow_bucket(original))
                .expect("select gateway")
                .primary_gateway;
            let mut remaining = plan.clone();
            let removed_uid = remaining
                .gateways
                .iter()
                .find(|gateway| gateway.node.uid != selected.node.uid)
                .expect("other gateway")
                .node
                .uid
                .clone();
            remaining
                .gateways
                .retain(|gateway| gateway.node.uid != removed_uid);
            let after = select_bucket(&remaining, AddressFamily::Ipv4, flow_bucket(original))
                .expect("select remaining")
                .primary_gateway;
            assert_eq!(after.node.uid, selected.node.uid);
        }
    }

    #[test]
    fn proof_wire_shape_is_strict_and_digest_bound() {
        let projection = multi_projection();
        let (guard, identity) = guarded(&projection);
        let proof =
            EgressFlowProof::issue(&projection, &guard, flow(identity, 30_000)).expect("proof");
        assert_eq!(
            proof.selection_algorithm,
            EGRESS_SELECTION_ALGORITHM_COMPILED_RENDEZVOUS_SHA256_V2
        );
        let mut value = serde_json::to_value(&proof).expect("encode proof");
        value
            .as_object_mut()
            .expect("object")
            .insert("trusted".to_owned(), serde_json::json!(true));
        assert!(serde_json::from_value::<EgressFlowProof>(value).is_err());
        assert_ne!(proof.proof_digest.0, [0; 32]);
        assert_ne!(proof.original_tuple_digest.0, [0; 16]);
    }

    #[test]
    fn fence_rejects_foreign_owner_and_revision_regression() {
        let projection = multi_projection();
        let plan = &projection.projection().contract.plans[0];
        let identity = plan.source.identity;
        let mut guard = EgressAdmissionGuard::default();
        guard
            .fence(identity, plan.intent.clone(), Revision::new(20))
            .expect("fence");
        assert_eq!(
            guard.fence(identity, plan.intent.clone(), Revision::new(19)),
            Err(EgressProofError::RevisionRegression)
        );
        let mut foreign = plan.intent.clone();
        foreign.uid.push_str("-foreign");
        assert_eq!(
            guard.fence(identity, foreign, Revision::new(21)),
            Err(EgressProofError::ForeignOwner)
        );
    }
}
