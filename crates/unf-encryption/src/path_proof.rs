//! Two-ended, nonce-bound proof of a live encrypted path.
//!
//! Configuration readback, peer counters, authenticated Node identity, and an
//! encrypted challenge are independent evidence planes. No single plane—and
//! especially no handshake timestamp—can activate Required traffic.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use unf_common::{IdentityId, Revision};

use crate::{
    AttestedEncryptionContractDigest, AttestedEncryptionPathContract, AuthenticatedNodeIdentity,
    EncryptionDecisionWitness, EncryptionDisposition, EncryptionFastPathDigest,
    EncryptionFastPathState, EncryptionGenerationRecipient, EncryptionPathChallengeDelivery,
    FastPathError, IpPrefix, WireGuardKernelConfigurationDigest, WireGuardKernelObservationDigest,
    WireGuardKernelSnapshot, WireGuardPublicKey, derive_wireguard_proof_addresses,
};

pub const ENCRYPTION_PATH_PROOF_SCHEMA_VERSION: u16 = 2;
pub const ENCRYPTION_PATH_PROOF_ASSIGNMENT_BATCH_SCHEMA_VERSION: u16 = 1;
pub const ENCRYPTION_ENDPOINT_PATH_PROOF_BATCH_SCHEMA_VERSION: u16 = 1;
pub const MAX_ENCRYPTION_ENDPOINT_PATH_PROOF_BATCH: usize = 64;
pub const MAX_ENCRYPTION_PATH_PROOF_LIFETIME_MS: u64 = 60_000;
pub const PATH_FAMILY_IPV4: u8 = 1;
pub const PATH_FAMILY_IPV6: u8 = 2;
const ROUND_DOMAIN: &[u8] = b"unf.encryption-path-proof-round.v2\0";
const CHALLENGE_REQUEST_DOMAIN: &[u8] = b"unf.encryption-path-challenge-request.v2\0";
const CHALLENGE_RESPONSE_DOMAIN: &[u8] = b"unf.encryption-path-challenge-response.v2\0";
const ENDPOINT_PROOF_DOMAIN: &[u8] = b"unf.encryption-path-endpoint-proof.v2\0";
const ACTIVATION_DOMAIN: &[u8] = b"unf.encryption-path-activation.v2\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum EncryptionPathEndpointRole {
    Source,
    Destination,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EncryptionPathProofRoundDigest(pub [u8; 32]);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EncryptionPathChallengeDigest(pub [u8; 32]);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EncryptionEndpointPathProofDigest(pub [u8; 32]);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EncryptionPathActivationDigest(pub [u8; 32]);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncryptionGenerationPathProofWitness(pub [u8; 32]);

/// Controller-issued immutable challenge for one canonical Required plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EncryptionPathProofRound {
    pub schema_version: u16,
    pub contract_digest: AttestedEncryptionContractDigest,
    pub contract_revision: Revision,
    pub decision_witness: EncryptionDecisionWitness,
    pub source: EncryptionGenerationRecipient,
    pub destination: EncryptionGenerationRecipient,
    pub epoch: u64,
    pub family_mask: u8,
    pub nonce: [u8; 32],
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub round_digest: EncryptionPathProofRoundDigest,
}

/// Exact peer counters surrounding a delivered encrypted challenge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EncryptionPeerCounterDelta {
    pub received_before: u64,
    pub received_after: u64,
    pub transmitted_before: u64,
    pub transmitted_after: u64,
}

/// One authenticated endpoint's independently derived proof.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EncryptionEndpointPathProof {
    pub schema_version: u16,
    pub round_digest: EncryptionPathProofRoundDigest,
    pub role: EncryptionPathEndpointRole,
    pub recipient: EncryptionGenerationRecipient,
    pub peer: EncryptionGenerationRecipient,
    pub contract_digest: AttestedEncryptionContractDigest,
    pub decision_witness: EncryptionDecisionWitness,
    pub epoch: u64,
    pub interface_name: String,
    pub interface_index: u32,
    pub mtu: u32,
    pub local_public_key: WireGuardPublicKey,
    pub peer_public_key: WireGuardPublicKey,
    pub kernel_configuration_digest: WireGuardKernelConfigurationDigest,
    pub kernel_before_observation_digest: WireGuardKernelObservationDigest,
    pub kernel_after_observation_digest: WireGuardKernelObservationDigest,
    pub counters: EncryptionPeerCounterDelta,
    pub family_mask: u8,
    pub challenge_delivery_digest: [u8; 32],
    pub challenge_request_digest: EncryptionPathChallengeDigest,
    pub challenge_response_digest: EncryptionPathChallengeDigest,
    pub observed_at_unix_ms: u64,
    pub proof_digest: EncryptionEndpointPathProofDigest,
}

/// Non-authoritative durable evidence that both endpoints proved one path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EncryptionPathActivationReceipt {
    pub schema_version: u16,
    pub round: EncryptionPathProofRound,
    pub source_proof_digest: EncryptionEndpointPathProofDigest,
    pub destination_proof_digest: EncryptionEndpointPathProofDigest,
    pub source_kernel_configuration_digest: WireGuardKernelConfigurationDigest,
    pub destination_kernel_configuration_digest: WireGuardKernelConfigurationDigest,
    pub admitted_at_unix_ms: u64,
    pub valid_until_unix_ms: u64,
    pub activation_digest: EncryptionPathActivationDigest,
}

/// Self-contained work item delivered only to one of the two path endpoints.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EncryptionPathProofAssignment {
    pub schema_version: u16,
    pub generation: unf_common::Revision,
    pub round: EncryptionPathProofRound,
    pub contract: AttestedEncryptionPathContract,
    pub plan_index: usize,
}

/// Compact reference to one plan inside a contract carried once by an
/// [`EncryptionPathProofAssignmentBatch`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EncryptionPathProofAssignmentIndex {
    pub schema_version: u16,
    pub generation: unf_common::Revision,
    pub round: EncryptionPathProofRound,
    pub contract_digest: AttestedEncryptionContractDigest,
    pub plan_index: usize,
}

/// One endpoint's path-proof work with each immutable contract represented
/// exactly once, independent of the number of selected plans.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EncryptionPathProofAssignmentBatch {
    pub schema_version: u16,
    pub generation: unf_common::Revision,
    pub contracts: Vec<AttestedEncryptionPathContract>,
    pub assignments: Vec<EncryptionPathProofAssignmentIndex>,
}

/// A fully replayed compact batch. Its private selection index makes contract
/// access both fail-closed and logarithmic without rehashing a full contract
/// for every selected plan.
pub struct AdmittedEncryptionPathProofAssignmentBatch {
    batch: EncryptionPathProofAssignmentBatch,
    selections: BTreeSet<(
        AttestedEncryptionContractDigest,
        usize,
        EncryptionPathProofRoundDigest,
    )>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncryptionPathProofAdmission {
    AcceptedPendingPeer,
    AcceptedComplete,
    Idempotent,
}

#[derive(Debug, Clone)]
pub struct EncryptionPathProofLedger {
    round: EncryptionPathProofRound,
    proofs: BTreeMap<EncryptionPathEndpointRole, EncryptionEndpointPathProof>,
}

/// Bounded, generation-fenced endpoint publication. It contains no new
/// authority: each proof retains its independent nonce and duplex evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EncryptionEndpointPathProofBatch {
    pub schema_version: u16,
    pub generation: Revision,
    pub proofs: Vec<EncryptionEndpointPathProof>,
}

#[derive(Debug)]
struct CoordinatedPathProof {
    assignment: EncryptionPathProofAssignmentIndex,
    ledger: EncryptionPathProofLedger,
}

/// Generation-fenced controller exchange. A plan cut publishes every challenge
/// atomically; later endpoint evidence cannot leak into its successor.
#[derive(Debug, Default)]
pub struct EncryptionPathProofCoordinator {
    generation: unf_common::Revision,
    source_digest: [u8; 32],
    contracts: BTreeMap<AttestedEncryptionContractDigest, AttestedEncryptionPathContract>,
    paths: BTreeMap<EncryptionPathProofRoundDigest, CoordinatedPathProof>,
}

/// Consuming, non-serializable authority proving that every Required decision
/// in one exact local generation has a current two-ended receipt.
pub struct EncryptionGenerationPathProofPermit {
    recipient: EncryptionGenerationRecipient,
    state_digest: EncryptionFastPathDigest,
    receipts: Vec<EncryptionPathActivationReceipt>,
    plan_identities: Option<Vec<(IdentityId, IdentityId)>>,
    valid_until_unix_ms: u64,
    witness: EncryptionGenerationPathProofWitness,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum EncryptionPathProofError {
    #[error("invalid or expired path-proof round")]
    InvalidRound,
    #[error("path proof does not resolve one Required contract plan")]
    InvalidContractPlan,
    #[error("path proof belongs to another authenticated Node")]
    ForeignNode,
    #[error("kernel configuration differs from the exact contract path")]
    KernelConfigurationDrift,
    #[error("encrypted challenge transcript is absent or mutated")]
    ChallengeMismatch,
    #[error("peer counters did not advance in both directions")]
    CounterProofMissing,
    #[error("endpoint proof replay or equivocation was rejected")]
    ReplayOrEquivocation,
    #[error("both endpoint proofs are not available")]
    IncompleteQuorum,
    #[error("canonical path-proof encoding failed: {0}")]
    CanonicalEncoding(String),
    #[error("path-proof generation regressed or equivocated")]
    GenerationConflict,
    #[error("invalid kernel snapshot: {0}")]
    InvalidKernelSnapshot(String),
    #[error("invalid contract: {0}")]
    InvalidContract(String),
    #[error("path receipts do not cover the exact Required generation")]
    InvalidGenerationProof,
    #[error("invalid encryption fast-path generation: {0}")]
    InvalidFastPath(FastPathError),
}

impl EncryptionPathProofRound {
    /// Issues a fresh bounded round for one exact Required plan.
    ///
    /// # Errors
    ///
    /// Rejects invalid contract authority, plan selection, lifetime, or OS
    /// randomness failure.
    pub fn fresh(
        contract: &AttestedEncryptionPathContract,
        plan_index: usize,
        issued_at_unix_ms: u64,
        expires_at_unix_ms: u64,
    ) -> Result<Self, EncryptionPathProofError> {
        let mut nonce = [0_u8; 32];
        getrandom::fill(&mut nonce)
            .map_err(|error| EncryptionPathProofError::CanonicalEncoding(error.to_string()))?;
        Self::issue(
            contract,
            plan_index,
            nonce,
            issued_at_unix_ms,
            expires_at_unix_ms,
        )
    }

    fn fresh_for_verified_contract(
        contract: &AttestedEncryptionPathContract,
        plan_index: usize,
        issued_at_unix_ms: u64,
        expires_at_unix_ms: u64,
    ) -> Result<Self, EncryptionPathProofError> {
        let mut nonce = [0_u8; 32];
        getrandom::fill(&mut nonce)
            .map_err(|error| EncryptionPathProofError::CanonicalEncoding(error.to_string()))?;
        Self::issue_for_verified_contract(
            contract,
            plan_index,
            nonce,
            issued_at_unix_ms,
            expires_at_unix_ms,
        )
    }

    /// Deterministic constructor for replay and constrained runtimes.
    ///
    /// # Errors
    ///
    /// Rejects invalid contract authority, plan selection, nonce, family
    /// coverage, or lifetime.
    pub fn issue(
        contract: &AttestedEncryptionPathContract,
        plan_index: usize,
        nonce: [u8; 32],
        issued_at_unix_ms: u64,
        expires_at_unix_ms: u64,
    ) -> Result<Self, EncryptionPathProofError> {
        contract
            .verify_integrity()
            .map_err(|error| EncryptionPathProofError::InvalidContract(error.to_string()))?;
        Self::issue_for_verified_contract(
            contract,
            plan_index,
            nonce,
            issued_at_unix_ms,
            expires_at_unix_ms,
        )
    }

    fn issue_for_verified_contract(
        contract: &AttestedEncryptionPathContract,
        plan_index: usize,
        nonce: [u8; 32],
        issued_at_unix_ms: u64,
        expires_at_unix_ms: u64,
    ) -> Result<Self, EncryptionPathProofError> {
        let plan = contract
            .plans
            .get(plan_index)
            .ok_or(EncryptionPathProofError::InvalidContractPlan)?;
        if plan.disposition != EncryptionDisposition::Required
            || plan.source.node.uid == plan.destination.node.uid
            || plan.source_key.epoch == 0
            || plan.source_key.epoch != plan.destination_key.epoch
            || nonce == [0; 32]
            || issued_at_unix_ms == 0
            || expires_at_unix_ms <= issued_at_unix_ms
            || expires_at_unix_ms - issued_at_unix_ms > MAX_ENCRYPTION_PATH_PROOF_LIFETIME_MS
            || issued_at_unix_ms < contract.valid_from_unix_ms
            || expires_at_unix_ms > contract.valid_until_unix_ms
        {
            return Err(EncryptionPathProofError::InvalidRound);
        }
        let family_mask = family_mask(&plan.transport.forward.allowed_ips)
            & family_mask(&plan.transport.reverse.allowed_ips);
        if family_mask == 0 {
            return Err(EncryptionPathProofError::InvalidContractPlan);
        }
        let mut round = Self {
            schema_version: ENCRYPTION_PATH_PROOF_SCHEMA_VERSION,
            contract_digest: contract.contract_digest,
            contract_revision: contract.contract_revision,
            decision_witness: contract
                .decision_witness(plan_index)
                .map_err(|error| EncryptionPathProofError::InvalidContract(error.to_string()))?,
            source: recipient(&plan.source.node.name, &plan.source.node.uid),
            destination: recipient(&plan.destination.node.name, &plan.destination.node.uid),
            epoch: plan.source_key.epoch,
            family_mask,
            nonce,
            issued_at_unix_ms,
            expires_at_unix_ms,
            round_digest: EncryptionPathProofRoundDigest([0; 32]),
        };
        round.round_digest = round.calculate_digest()?;
        round.verify()?;
        Ok(round)
    }

    /// Replays the round's bounded shape and commitment.
    ///
    /// # Errors
    ///
    /// Rejects malformed, expired-shape, or digest-mutated rounds.
    pub fn verify(&self) -> Result<(), EncryptionPathProofError> {
        if self.schema_version != ENCRYPTION_PATH_PROOF_SCHEMA_VERSION
            || self.source == self.destination
            || self.contract_revision == Revision::INITIAL
            || self.source.node_name.is_empty()
            || self.source.node_uid.is_empty()
            || self.destination.node_name.is_empty()
            || self.destination.node_uid.is_empty()
            || self.epoch == 0
            || self.family_mask == 0
            || self.family_mask & !(PATH_FAMILY_IPV4 | PATH_FAMILY_IPV6) != 0
            || self.nonce == [0; 32]
            || self.issued_at_unix_ms == 0
            || self.expires_at_unix_ms <= self.issued_at_unix_ms
            || self.expires_at_unix_ms - self.issued_at_unix_ms
                > MAX_ENCRYPTION_PATH_PROOF_LIFETIME_MS
            || self.round_digest != self.calculate_digest()?
        {
            return Err(EncryptionPathProofError::InvalidRound);
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Result<EncryptionPathProofRoundDigest, EncryptionPathProofError> {
        let mut canonical = self.clone();
        canonical.round_digest = EncryptionPathProofRoundDigest([0; 32]);
        hash(ROUND_DOMAIN, &canonical).map(EncryptionPathProofRoundDigest)
    }

    fn request_digest(&self) -> Result<EncryptionPathChallengeDigest, EncryptionPathProofError> {
        hash(
            CHALLENGE_REQUEST_DOMAIN,
            &(self.round_digest, self.nonce, self.family_mask),
        )
        .map(EncryptionPathChallengeDigest)
    }

    fn response_digest(&self) -> Result<EncryptionPathChallengeDigest, EncryptionPathProofError> {
        hash(
            CHALLENGE_RESPONSE_DOMAIN,
            &(
                self.request_digest()?,
                self.destination.clone(),
                self.source.clone(),
            ),
        )
        .map(EncryptionPathChallengeDigest)
    }
}

impl EncryptionEndpointPathProof {
    /// Joins exact before/after kernel readback with a delivered challenge.
    ///
    /// # Errors
    ///
    /// Rejects foreign identity, contract/kernel drift, missing counter
    /// movement, incomplete family delivery, expiry, or transcript mutation.
    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    pub fn issue(
        round: &EncryptionPathProofRound,
        contract: &AttestedEncryptionPathContract,
        plan_index: usize,
        role: EncryptionPathEndpointRole,
        authenticated: &AuthenticatedNodeIdentity,
        before: &WireGuardKernelSnapshot,
        after: &WireGuardKernelSnapshot,
        delivery: &EncryptionPathChallengeDelivery,
        observed_at_unix_ms: u64,
    ) -> Result<Self, EncryptionPathProofError> {
        round.verify()?;
        contract
            .verify_integrity()
            .map_err(|error| EncryptionPathProofError::InvalidContract(error.to_string()))?;
        Self::issue_for_verified_contract(
            round,
            contract,
            plan_index,
            role,
            authenticated,
            before,
            after,
            delivery,
            observed_at_unix_ms,
        )
    }

    /// Issues a proof from a contract selection admitted once with its compact
    /// batch, avoiding repeated whole-contract hashing per path.
    ///
    /// # Errors
    ///
    /// Rejects foreign work and every malformed kernel or delivery fact
    /// rejected by [`Self::issue`].
    #[allow(clippy::too_many_arguments)]
    pub fn issue_from_assignment_batch(
        batch: &AdmittedEncryptionPathProofAssignmentBatch,
        assignment: &EncryptionPathProofAssignmentIndex,
        role: EncryptionPathEndpointRole,
        authenticated: &AuthenticatedNodeIdentity,
        before: &WireGuardKernelSnapshot,
        after: &WireGuardKernelSnapshot,
        delivery: &EncryptionPathChallengeDelivery,
        observed_at_unix_ms: u64,
    ) -> Result<Self, EncryptionPathProofError> {
        let contract = batch.contract_for(assignment)?;
        Self::issue_for_verified_contract(
            &assignment.round,
            contract,
            assignment.plan_index,
            role,
            authenticated,
            before,
            after,
            delivery,
            observed_at_unix_ms,
        )
    }

    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    fn issue_for_verified_contract(
        round: &EncryptionPathProofRound,
        contract: &AttestedEncryptionPathContract,
        plan_index: usize,
        role: EncryptionPathEndpointRole,
        authenticated: &AuthenticatedNodeIdentity,
        before: &WireGuardKernelSnapshot,
        after: &WireGuardKernelSnapshot,
        delivery: &EncryptionPathChallengeDelivery,
        observed_at_unix_ms: u64,
    ) -> Result<Self, EncryptionPathProofError> {
        let plan = contract
            .plans
            .get(plan_index)
            .ok_or(EncryptionPathProofError::InvalidContractPlan)?;
        delivery.verify_for(round)?;
        let delivered_family_mask = delivery.family_mask();
        if round.contract_digest != contract.contract_digest
            || round.decision_witness
                != contract
                    .decision_witness(plan_index)
                    .map_err(|error| EncryptionPathProofError::InvalidContract(error.to_string()))?
            || observed_at_unix_ms < round.issued_at_unix_ms
            || observed_at_unix_ms >= round.expires_at_unix_ms
            || delivered_family_mask != round.family_mask
        {
            return Err(EncryptionPathProofError::ChallengeMismatch);
        }
        before
            .verify_integrity()
            .map_err(|error| EncryptionPathProofError::InvalidKernelSnapshot(error.to_string()))?;
        after
            .verify_integrity()
            .map_err(|error| EncryptionPathProofError::InvalidKernelSnapshot(error.to_string()))?;

        let (local, peer, local_key, peer_key, path) = match role {
            EncryptionPathEndpointRole::Source => (
                &round.source,
                &round.destination,
                plan.source_key.public_key,
                plan.destination_key.public_key,
                &plan.transport.forward,
            ),
            EncryptionPathEndpointRole::Destination => (
                &round.destination,
                &round.source,
                plan.destination_key.public_key,
                plan.source_key.public_key,
                &plan.transport.reverse,
            ),
        };
        if authenticated.cluster_id != plan.source.node.cluster_id
            || authenticated.node_name != local.node_name
            || authenticated.node_uid != local.node_uid
        {
            return Err(EncryptionPathProofError::ForeignNode);
        }
        let before_peer = exact_peer(before, peer_key)?;
        let after_peer = exact_peer(after, peer_key)?;
        let expected_proof_addresses = derive_wireguard_proof_addresses(match role {
            EncryptionPathEndpointRole::Source => &plan.source.node.pod_cidrs,
            EncryptionPathEndpointRole::Destination => &plan.destination.node.pod_cidrs,
        })
        .map_err(|error| EncryptionPathProofError::InvalidContract(error.to_string()))?;
        let routes_exact = |snapshot: &WireGuardKernelSnapshot| {
            path.allowed_ips.iter().all(|prefix| {
                let mut matching = snapshot
                    .routes
                    .iter()
                    .filter(|route| route.prefix == *prefix);
                matching.next().is_some_and(|route| {
                    route.table == path.route_table
                        && route.interface_index == snapshot.interface_index
                }) && matching.next().is_none()
            })
        };
        if before.configuration_digest != after.configuration_digest
            || before.public_key != local_key
            || after.public_key != local_key
            || before.interface_name != path.interface_name
            || after.interface_name != path.interface_name
            || before.mtu != path.mtu
            || after.mtu != path.mtu
            || before.fwmark != path.fwmark
            || after.fwmark != path.fwmark
            || before.proof_addresses != expected_proof_addresses
            || after.proof_addresses != expected_proof_addresses
            || before_peer.endpoint != path.peer_endpoint
            || after_peer.endpoint != path.peer_endpoint
            || before_peer.allowed_ips != path.allowed_ips
            || after_peer.allowed_ips != path.allowed_ips
            || !routes_exact(before)
            || !routes_exact(after)
        {
            return Err(EncryptionPathProofError::KernelConfigurationDrift);
        }
        let counters = EncryptionPeerCounterDelta {
            received_before: before_peer.received_bytes,
            received_after: after_peer.received_bytes,
            transmitted_before: before_peer.transmitted_bytes,
            transmitted_after: after_peer.transmitted_bytes,
        };
        if counters.received_after <= counters.received_before
            || counters.transmitted_after <= counters.transmitted_before
        {
            return Err(EncryptionPathProofError::CounterProofMissing);
        }
        let mut proof = Self {
            schema_version: ENCRYPTION_PATH_PROOF_SCHEMA_VERSION,
            round_digest: round.round_digest,
            role,
            recipient: local.clone(),
            peer: peer.clone(),
            contract_digest: round.contract_digest,
            decision_witness: round.decision_witness,
            epoch: round.epoch,
            interface_name: after.interface_name.clone(),
            interface_index: after.interface_index,
            mtu: after.mtu,
            local_public_key: local_key,
            peer_public_key: peer_key,
            kernel_configuration_digest: after.configuration_digest,
            kernel_before_observation_digest: before.observation_digest,
            kernel_after_observation_digest: after.observation_digest,
            counters,
            family_mask: delivered_family_mask,
            challenge_delivery_digest: delivery.transcript_digest(),
            challenge_request_digest: round.request_digest()?,
            challenge_response_digest: round.response_digest()?,
            observed_at_unix_ms,
            proof_digest: EncryptionEndpointPathProofDigest([0; 32]),
        };
        proof.proof_digest = proof.calculate_digest()?;
        proof.verify(round, observed_at_unix_ms)?;
        Ok(proof)
    }

    /// Replays the endpoint proof against the immutable round.
    ///
    /// # Errors
    ///
    /// Rejects expired, foreign, incomplete, or digest-mutated evidence.
    pub fn verify(
        &self,
        round: &EncryptionPathProofRound,
        now_unix_ms: u64,
    ) -> Result<(), EncryptionPathProofError> {
        round.verify()?;
        let (recipient, peer) = match self.role {
            EncryptionPathEndpointRole::Source => (&round.source, &round.destination),
            EncryptionPathEndpointRole::Destination => (&round.destination, &round.source),
        };
        if self.schema_version != ENCRYPTION_PATH_PROOF_SCHEMA_VERSION
            || self.round_digest != round.round_digest
            || &self.recipient != recipient
            || &self.peer != peer
            || self.contract_digest != round.contract_digest
            || self.decision_witness != round.decision_witness
            || self.epoch != round.epoch
            || self.family_mask != round.family_mask
            || self.challenge_delivery_digest == [0; 32]
            || self.challenge_request_digest != round.request_digest()?
            || self.challenge_response_digest != round.response_digest()?
            || self.observed_at_unix_ms < round.issued_at_unix_ms
            || self.observed_at_unix_ms >= round.expires_at_unix_ms
            || now_unix_ms >= round.expires_at_unix_ms
            || self.interface_name.is_empty()
            || self.interface_index == 0
            || self.mtu < 1_280
            || self.local_public_key.0 == [0; 32]
            || self.peer_public_key.0 == [0; 32]
            || self.counters.received_after <= self.counters.received_before
            || self.counters.transmitted_after <= self.counters.transmitted_before
            || self.proof_digest != self.calculate_digest()?
        {
            return Err(EncryptionPathProofError::ChallengeMismatch);
        }
        Ok(())
    }

    fn calculate_digest(
        &self,
    ) -> Result<EncryptionEndpointPathProofDigest, EncryptionPathProofError> {
        let mut canonical = self.clone();
        canonical.proof_digest = EncryptionEndpointPathProofDigest([0; 32]);
        hash(ENDPOINT_PROOF_DOMAIN, &canonical).map(EncryptionEndpointPathProofDigest)
    }
}

impl EncryptionPathProofLedger {
    /// Starts a ledger for one independently verified round.
    ///
    /// # Errors
    ///
    /// Rejects an invalid round.
    pub fn new(round: EncryptionPathProofRound) -> Result<Self, EncryptionPathProofError> {
        round.verify()?;
        Ok(Self {
            round,
            proofs: BTreeMap::new(),
        })
    }

    /// Admits one authenticated endpoint proof without replacing prior truth.
    ///
    /// # Errors
    ///
    /// Rejects foreign identity, invalid evidence, expiry, replay, or
    /// same-role equivocation.
    pub fn observe(
        &mut self,
        authenticated: &AuthenticatedNodeIdentity,
        proof: EncryptionEndpointPathProof,
        now_unix_ms: u64,
    ) -> Result<EncryptionPathProofAdmission, EncryptionPathProofError> {
        proof.verify(&self.round, now_unix_ms)?;
        if authenticated.cluster_id.is_empty()
            || authenticated.node_name != proof.recipient.node_name
            || authenticated.node_uid != proof.recipient.node_uid
        {
            return Err(EncryptionPathProofError::ForeignNode);
        }
        if let Some(previous) = self.proofs.get(&proof.role) {
            return if previous == &proof {
                Ok(EncryptionPathProofAdmission::Idempotent)
            } else {
                Err(EncryptionPathProofError::ReplayOrEquivocation)
            };
        }
        self.proofs.insert(proof.role, proof);
        if self.proofs.len() == 2 {
            Ok(EncryptionPathProofAdmission::AcceptedComplete)
        } else {
            Ok(EncryptionPathProofAdmission::AcceptedPendingPeer)
        }
    }

    /// Seals the two-ended quorum into a bounded non-authoritative receipt.
    ///
    /// # Errors
    ///
    /// Rejects incomplete or expired endpoint evidence.
    pub fn activation_receipt(
        &self,
        now_unix_ms: u64,
    ) -> Result<EncryptionPathActivationReceipt, EncryptionPathProofError> {
        let source = self
            .proofs
            .get(&EncryptionPathEndpointRole::Source)
            .ok_or(EncryptionPathProofError::IncompleteQuorum)?;
        let destination = self
            .proofs
            .get(&EncryptionPathEndpointRole::Destination)
            .ok_or(EncryptionPathProofError::IncompleteQuorum)?;
        source.verify(&self.round, now_unix_ms)?;
        destination.verify(&self.round, now_unix_ms)?;
        let mut receipt = EncryptionPathActivationReceipt {
            schema_version: ENCRYPTION_PATH_PROOF_SCHEMA_VERSION,
            round: self.round.clone(),
            source_proof_digest: source.proof_digest,
            destination_proof_digest: destination.proof_digest,
            source_kernel_configuration_digest: source.kernel_configuration_digest,
            destination_kernel_configuration_digest: destination.kernel_configuration_digest,
            admitted_at_unix_ms: now_unix_ms,
            valid_until_unix_ms: self.round.expires_at_unix_ms,
            activation_digest: EncryptionPathActivationDigest([0; 32]),
        };
        receipt.activation_digest = receipt.calculate_digest()?;
        receipt.verify(now_unix_ms)?;
        Ok(receipt)
    }
}

impl EncryptionPathProofAssignment {
    /// Replays the contract, selection, round, and generation binding.
    ///
    /// # Errors
    ///
    /// Rejects malformed, cross-contract, or digest-mutated assignments.
    pub fn verify(&self) -> Result<(), EncryptionPathProofError> {
        self.contract
            .verify_integrity()
            .map_err(|error| EncryptionPathProofError::InvalidContract(error.to_string()))?;
        self.round.verify()?;
        let expected_round = EncryptionPathProofRound::issue_for_verified_contract(
            &self.contract,
            self.plan_index,
            self.round.nonce,
            self.round.issued_at_unix_ms,
            self.round.expires_at_unix_ms,
        )?;
        if self.schema_version != ENCRYPTION_PATH_PROOF_SCHEMA_VERSION
            || self.generation == unf_common::Revision::INITIAL
            || self.round != expected_round
            || self.round.contract_digest != self.contract.contract_digest
            || self.round.decision_witness
                != self
                    .contract
                    .decision_witness(self.plan_index)
                    .map_err(|error| EncryptionPathProofError::InvalidContract(error.to_string()))?
        {
            return Err(EncryptionPathProofError::InvalidContractPlan);
        }
        Ok(())
    }

    #[must_use]
    pub fn includes(&self, recipient: &EncryptionGenerationRecipient) -> bool {
        &self.round.source == recipient || &self.round.destination == recipient
    }
}

impl EncryptionPathProofAssignmentIndex {
    /// Verifies this lightweight selection against its batch-owned contract.
    ///
    /// # Errors
    ///
    /// Rejects a digest mismatch, malformed contract, invalid plan index, or
    /// a round that is not the exact deterministic replay of the selection.
    pub fn verify_with(
        &self,
        contract: &AttestedEncryptionPathContract,
    ) -> Result<(), EncryptionPathProofError> {
        contract
            .verify_integrity()
            .map_err(|error| EncryptionPathProofError::InvalidContract(error.to_string()))?;
        self.verify_with_verified_contract(contract)
    }

    fn verify_with_verified_contract(
        &self,
        contract: &AttestedEncryptionPathContract,
    ) -> Result<(), EncryptionPathProofError> {
        self.round.verify()?;
        let expected_round = EncryptionPathProofRound::issue_for_verified_contract(
            contract,
            self.plan_index,
            self.round.nonce,
            self.round.issued_at_unix_ms,
            self.round.expires_at_unix_ms,
        )?;
        if self.schema_version != ENCRYPTION_PATH_PROOF_SCHEMA_VERSION
            || self.generation == unf_common::Revision::INITIAL
            || self.contract_digest != contract.contract_digest
            || self.round != expected_round
            || self.round.contract_digest != self.contract_digest
        {
            return Err(EncryptionPathProofError::InvalidContractPlan);
        }
        Ok(())
    }

    #[must_use]
    pub fn includes(&self, recipient: &EncryptionGenerationRecipient) -> bool {
        &self.round.source == recipient || &self.round.destination == recipient
    }
}

impl EncryptionPathProofAssignmentBatch {
    /// Resolves one lightweight selection to the unique immutable contract in
    /// this batch.
    ///
    /// # Errors
    ///
    /// Rejects an absent or duplicate contract digest.
    pub fn contract_for(
        &self,
        assignment: &EncryptionPathProofAssignmentIndex,
    ) -> Result<&AttestedEncryptionPathContract, EncryptionPathProofError> {
        self.contracts
            .binary_search_by_key(&assignment.contract_digest, |contract| {
                contract.contract_digest
            })
            .ok()
            .and_then(|index| self.contracts.get(index))
            .ok_or(EncryptionPathProofError::InvalidContractPlan)
    }

    /// Independently replays the compact contract table and every selection.
    ///
    /// # Errors
    ///
    /// Rejects malformed, duplicate, unreferenced, cross-generation, or
    /// digest-mutated state.
    pub fn verify(&self) -> Result<(), EncryptionPathProofError> {
        if self.schema_version != ENCRYPTION_PATH_PROOF_ASSIGNMENT_BATCH_SCHEMA_VERSION
            || self.generation == unf_common::Revision::INITIAL
        {
            return Err(EncryptionPathProofError::InvalidContractPlan);
        }
        if self
            .contracts
            .windows(2)
            .any(|contracts| contracts[0].contract_digest >= contracts[1].contract_digest)
        {
            return Err(EncryptionPathProofError::InvalidContractPlan);
        }
        for contract in &self.contracts {
            contract
                .verify_integrity()
                .map_err(|error| EncryptionPathProofError::InvalidContract(error.to_string()))?;
        }
        let contract_digests = self
            .contracts
            .iter()
            .map(|contract| contract.contract_digest)
            .collect::<BTreeSet<_>>();
        let mut selections = BTreeSet::new();
        let mut referenced = BTreeSet::new();
        for assignment in &self.assignments {
            if assignment.generation != self.generation
                || !selections.insert((assignment.contract_digest, assignment.plan_index))
            {
                return Err(EncryptionPathProofError::InvalidContractPlan);
            }
            let contract = self.contract_for(assignment)?;
            assignment.verify_with_verified_contract(contract)?;
            referenced.insert(assignment.contract_digest);
        }
        if referenced != contract_digests {
            return Err(EncryptionPathProofError::InvalidContractPlan);
        }
        Ok(())
    }

    /// Consumes this untrusted wire batch after one complete integrity replay.
    ///
    /// # Errors
    ///
    /// Rejects every condition rejected by [`Self::verify`].
    pub fn admit(
        self,
    ) -> Result<AdmittedEncryptionPathProofAssignmentBatch, EncryptionPathProofError> {
        self.verify()?;
        let selections = self
            .assignments
            .iter()
            .map(|assignment| {
                (
                    assignment.contract_digest,
                    assignment.plan_index,
                    assignment.round.round_digest,
                )
            })
            .collect();
        Ok(AdmittedEncryptionPathProofAssignmentBatch {
            batch: self,
            selections,
        })
    }
}

impl AdmittedEncryptionPathProofAssignmentBatch {
    #[must_use]
    pub fn assignments(&self) -> &[EncryptionPathProofAssignmentIndex] {
        &self.batch.assignments
    }

    /// Resolves only an exact selection admitted by this batch.
    ///
    /// # Errors
    ///
    /// Rejects foreign work and any selection-to-contract mismatch.
    pub fn contract_for(
        &self,
        assignment: &EncryptionPathProofAssignmentIndex,
    ) -> Result<&AttestedEncryptionPathContract, EncryptionPathProofError> {
        if assignment.generation != self.batch.generation
            || !self.selections.contains(&(
                assignment.contract_digest,
                assignment.plan_index,
                assignment.round.round_digest,
            ))
        {
            return Err(EncryptionPathProofError::InvalidContractPlan);
        }
        let contract = self.batch.contract_for(assignment)?;
        assignment.verify_with_verified_contract(contract)?;
        Ok(contract)
    }
}

impl EncryptionPathProofCoordinator {
    /// Atomically replaces the full challenge set for one fleet generation.
    ///
    /// # Errors
    ///
    /// Rejects regression, same-generation equivocation, malformed contracts,
    /// duplicate paths, invalid lifetime, or randomness failure. Existing
    /// rounds remain unchanged on every error.
    pub fn replace_contracts(
        &mut self,
        generation: unf_common::Revision,
        contracts: Vec<(AttestedEncryptionPathContract, usize)>,
        issued_at_unix_ms: u64,
        lifetime_ms: u64,
    ) -> Result<bool, EncryptionPathProofError> {
        let mut unique = BTreeMap::new();
        let mut selections = Vec::with_capacity(contracts.len());
        for (contract, plan_index) in contracts {
            selections.push((contract.contract_digest, plan_index));
            if unique
                .insert(contract.contract_digest, contract.clone())
                .is_some_and(|previous| previous != contract)
            {
                return Err(EncryptionPathProofError::InvalidContractPlan);
            }
        }
        self.replace_contract_selection(
            generation,
            unique.into_values().collect(),
            selections,
            issued_at_unix_ms,
            lifetime_ms,
        )
    }

    /// Atomically replaces a generation while expanding only lightweight plan
    /// indexes. Every full contract remains represented exactly once.
    ///
    /// # Errors
    ///
    /// Rejects the same invalid authority as [`Self::replace_contracts`].
    pub fn replace_contract_batches(
        &mut self,
        generation: unf_common::Revision,
        contracts: Vec<AttestedEncryptionPathContract>,
        issued_at_unix_ms: u64,
        lifetime_ms: u64,
    ) -> Result<bool, EncryptionPathProofError> {
        let selections = contracts
            .iter()
            .flat_map(|contract| {
                (0..contract.plans.len()).map(|index| (contract.contract_digest, index))
            })
            .collect();
        self.replace_contract_selection(
            generation,
            contracts,
            selections,
            issued_at_unix_ms,
            lifetime_ms,
        )
    }

    fn replace_contract_selection(
        &mut self,
        generation: unf_common::Revision,
        contracts: Vec<AttestedEncryptionPathContract>,
        mut selections: Vec<(AttestedEncryptionContractDigest, usize)>,
        issued_at_unix_ms: u64,
        lifetime_ms: u64,
    ) -> Result<bool, EncryptionPathProofError> {
        if generation == unf_common::Revision::INITIAL
            || lifetime_ms == 0
            || lifetime_ms > MAX_ENCRYPTION_PATH_PROOF_LIFETIME_MS
        {
            return Err(EncryptionPathProofError::InvalidRound);
        }
        let mut contract_table = BTreeMap::new();
        for contract in contracts {
            contract
                .verify_integrity()
                .map_err(|error| EncryptionPathProofError::InvalidContract(error.to_string()))?;
            if contract_table
                .insert(contract.contract_digest, contract)
                .is_some()
            {
                return Err(EncryptionPathProofError::InvalidContractPlan);
            }
        }
        selections.sort_unstable();
        if selections.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(EncryptionPathProofError::InvalidContractPlan);
        }
        for (contract_digest, plan_index) in &selections {
            contract_table
                .get(contract_digest)
                .ok_or(EncryptionPathProofError::InvalidContractPlan)?
                .plans
                .get(*plan_index)
                .ok_or(EncryptionPathProofError::InvalidContractPlan)?;
        }
        let source_digest = hash(
            b"unf.encryption-path-proof-source.v1\0",
            &(generation, &selections),
        )?;
        if generation < self.generation
            || generation == self.generation
                && self.source_digest != [0; 32]
                && self.source_digest != source_digest
        {
            return Err(EncryptionPathProofError::GenerationConflict);
        }
        if generation == self.generation
            && self.source_digest == source_digest
            && (self.paths.is_empty()
                || self
                    .paths
                    .values()
                    .all(|path| path.assignment.round.expires_at_unix_ms > issued_at_unix_ms))
        {
            return Ok(false);
        }
        let expires_at_unix_ms = issued_at_unix_ms
            .checked_add(lifetime_ms)
            .ok_or(EncryptionPathProofError::InvalidRound)?;
        let mut paths = BTreeMap::new();
        for (contract_digest, plan_index) in selections {
            let contract = contract_table
                .get(&contract_digest)
                .ok_or(EncryptionPathProofError::InvalidContractPlan)?;
            let round = EncryptionPathProofRound::fresh_for_verified_contract(
                contract,
                plan_index,
                issued_at_unix_ms,
                expires_at_unix_ms,
            )?;
            let assignment = EncryptionPathProofAssignmentIndex {
                schema_version: ENCRYPTION_PATH_PROOF_SCHEMA_VERSION,
                generation,
                round: round.clone(),
                contract_digest,
                plan_index,
            };
            assignment.verify_with_verified_contract(contract)?;
            let ledger = EncryptionPathProofLedger::new(round.clone())?;
            if paths
                .insert(
                    round.round_digest,
                    CoordinatedPathProof { assignment, ledger },
                )
                .is_some()
            {
                return Err(EncryptionPathProofError::ReplayOrEquivocation);
            }
        }
        self.generation = generation;
        self.source_digest = source_digest;
        self.contracts = contract_table;
        self.paths = paths;
        Ok(true)
    }

    /// Returns compact endpoint work with each referenced contract carried
    /// exactly once.
    #[must_use]
    pub fn assignment_batch_for(
        &self,
        recipient: &EncryptionGenerationRecipient,
    ) -> EncryptionPathProofAssignmentBatch {
        let assignments = self
            .paths
            .values()
            .filter(|path| path.assignment.includes(recipient))
            .map(|path| path.assignment.clone())
            .collect::<Vec<_>>();
        let referenced = assignments
            .iter()
            .map(|assignment| assignment.contract_digest)
            .collect::<BTreeSet<_>>();
        let contracts = referenced
            .into_iter()
            .filter_map(|digest| self.contracts.get(&digest).cloned())
            .collect();
        EncryptionPathProofAssignmentBatch {
            schema_version: ENCRYPTION_PATH_PROOF_ASSIGNMENT_BATCH_SCHEMA_VERSION,
            generation: self.generation,
            contracts,
            assignments,
        }
    }

    /// Returns only immutable work assigned to the authenticated endpoint.
    #[must_use]
    pub fn assignments_for(
        &self,
        recipient: &EncryptionGenerationRecipient,
    ) -> Vec<EncryptionPathProofAssignment> {
        self.paths
            .values()
            .filter(|path| path.assignment.includes(recipient))
            .filter_map(|path| {
                self.contracts
                    .get(&path.assignment.contract_digest)
                    .cloned()
                    .map(|contract| EncryptionPathProofAssignment {
                        schema_version: path.assignment.schema_version,
                        generation: path.assignment.generation,
                        round: path.assignment.round.clone(),
                        contract,
                        plan_index: path.assignment.plan_index,
                    })
            })
            .collect()
    }

    /// Admits one proof into its exact generation/round ledger.
    ///
    /// # Errors
    ///
    /// Rejects an unknown round, foreign Node, expired evidence, replay, or
    /// equivocation.
    pub fn observe(
        &mut self,
        authenticated: &AuthenticatedNodeIdentity,
        proof: EncryptionEndpointPathProof,
        now_unix_ms: u64,
    ) -> Result<EncryptionPathProofAdmission, EncryptionPathProofError> {
        self.paths
            .get_mut(&proof.round_digest)
            .ok_or(EncryptionPathProofError::ReplayOrEquivocation)?
            .ledger
            .observe(authenticated, proof, now_unix_ms)
    }

    /// Admits a bounded batch atomically, cloning only touched ledgers, never
    /// contracts or the fleet catalog. Retrying an accepted batch is idempotent.
    ///
    /// # Errors
    /// Rejects invalid schema/size/generation, duplicate rounds, and any proof
    /// rejected by standalone admission without retaining a valid prefix.
    ///
    /// # Panics
    /// Panics if an exclusively borrowed, already-staged round disappears,
    /// which indicates an internal coordinator invariant violation.
    pub fn observe_batch(
        &mut self,
        authenticated: &AuthenticatedNodeIdentity,
        batch: &EncryptionEndpointPathProofBatch,
        now_unix_ms: u64,
    ) -> Result<Vec<EncryptionPathProofAdmission>, EncryptionPathProofError> {
        if batch.schema_version != ENCRYPTION_ENDPOINT_PATH_PROOF_BATCH_SCHEMA_VERSION
            || batch.generation != self.generation
            || batch.proofs.is_empty()
            || batch.proofs.len() > MAX_ENCRYPTION_ENDPOINT_PATH_PROOF_BATCH
        {
            return Err(EncryptionPathProofError::InvalidGenerationProof);
        }
        let mut seen = BTreeSet::new();
        let mut staged = Vec::with_capacity(batch.proofs.len());
        for proof in &batch.proofs {
            if !seen.insert(proof.round_digest) {
                return Err(EncryptionPathProofError::ReplayOrEquivocation);
            }
            let mut ledger = self
                .paths
                .get(&proof.round_digest)
                .ok_or(EncryptionPathProofError::ReplayOrEquivocation)?
                .ledger
                .clone();
            let admission = ledger.observe(authenticated, proof.clone(), now_unix_ms)?;
            staged.push((proof.round_digest, ledger, admission));
        }
        Ok(staged
            .into_iter()
            .map(|(round, ledger, admission)| {
                self.paths
                    .get_mut(&round)
                    .expect("exclusively staged round exists")
                    .ledger = ledger;
                admission
            })
            .collect())
    }

    /// Returns current completed receipts owned by one source endpoint.
    ///
    /// Destination participation proves duplex reachability, but only the
    /// source-side receipt can authorize that Node's outbound fast-path
    /// decision. Keeping destination receipts out of this projection avoids
    /// weakening exact generation coverage when several workload decisions
    /// share one pair of Nodes.
    #[must_use]
    pub fn receipts_for(
        &self,
        recipient: &EncryptionGenerationRecipient,
        now_unix_ms: u64,
    ) -> Vec<EncryptionPathActivationReceipt> {
        self.paths
            .values()
            .filter(|path| path.assignment.round.source == *recipient)
            .filter_map(|path| path.ledger.activation_receipt(now_unix_ms).ok())
            .collect()
    }

    #[must_use]
    pub const fn generation(&self) -> unf_common::Revision {
        self.generation
    }
}

impl EncryptionPathActivationReceipt {
    /// Replays receipt integrity and current lifetime.
    ///
    /// # Errors
    ///
    /// Rejects malformed, expired, or digest-mutated receipts.
    pub fn verify(&self, now_unix_ms: u64) -> Result<(), EncryptionPathProofError> {
        self.round.verify()?;
        if self.schema_version != ENCRYPTION_PATH_PROOF_SCHEMA_VERSION
            || self.source_proof_digest.0 == [0; 32]
            || self.destination_proof_digest.0 == [0; 32]
            || self.source_proof_digest == self.destination_proof_digest
            || self.source_kernel_configuration_digest.0 == [0; 32]
            || self.destination_kernel_configuration_digest.0 == [0; 32]
            || self.admitted_at_unix_ms < self.round.issued_at_unix_ms
            || self.valid_until_unix_ms != self.round.expires_at_unix_ms
            || now_unix_ms >= self.valid_until_unix_ms
            || self.activation_digest != self.calculate_digest()?
        {
            return Err(EncryptionPathProofError::InvalidRound);
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Result<EncryptionPathActivationDigest, EncryptionPathProofError> {
        let mut canonical = self.clone();
        canonical.activation_digest = EncryptionPathActivationDigest([0; 32]);
        hash(ACTIVATION_DOMAIN, &canonical).map(EncryptionPathActivationDigest)
    }
}

impl EncryptionGenerationPathProofPermit {
    /// Joins all current receipts to one exact local fast-path generation.
    ///
    /// # Errors
    ///
    /// Rejects incomplete, extra, expired, foreign, duplicate, or kernel-
    /// divergent receipt coverage.
    pub fn issue(
        state: &EncryptionFastPathState,
        recipient: EncryptionGenerationRecipient,
        receipts: Vec<EncryptionPathActivationReceipt>,
        now_unix_ms: u64,
    ) -> Result<Self, EncryptionPathProofError> {
        Self::issue_with_batch(state, recipient, receipts, None, now_unix_ms)
    }

    /// Joins direct and replicated decisions through exact admitted plan
    /// identities. Only compact private bindings survive construction; the
    /// full assignment batch is consumed and released before map publication.
    ///
    /// # Errors
    /// Rejects foreign generations/rounds and incomplete or divergent coverage.
    pub fn issue_from_assignment_batch(
        state: &EncryptionFastPathState,
        recipient: EncryptionGenerationRecipient,
        receipts: Vec<EncryptionPathActivationReceipt>,
        batch: AdmittedEncryptionPathProofAssignmentBatch,
        now_unix_ms: u64,
    ) -> Result<Self, EncryptionPathProofError> {
        Self::issue_with_batch(state, recipient, receipts, Some(batch), now_unix_ms)
    }

    fn issue_with_batch(
        state: &EncryptionFastPathState,
        recipient: EncryptionGenerationRecipient,
        mut receipts: Vec<EncryptionPathActivationReceipt>,
        batch: Option<AdmittedEncryptionPathProofAssignmentBatch>,
        now_unix_ms: u64,
    ) -> Result<Self, EncryptionPathProofError> {
        state
            .verify_integrity()
            .map_err(EncryptionPathProofError::InvalidFastPath)?;
        receipts.sort_by_key(|receipt| receipt.activation_digest.0);
        if receipts
            .windows(2)
            .any(|pair| pair[0].activation_digest == pair[1].activation_digest)
        {
            return Err(EncryptionPathProofError::InvalidGenerationProof);
        }
        let plan_identities = batch
            .as_ref()
            .map(|batch| receipt_plan_identities(state, batch, &receipts))
            .transpose()?;
        drop(batch);
        let valid_until_unix_ms = match &plan_identities {
            Some(identities) => validate_replica_aware_generation_coverage(
                state,
                &recipient,
                &receipts,
                identities,
                now_unix_ms,
            )?,
            None => validate_generation_coverage(state, &recipient, &receipts, now_unix_ms)?,
        };
        let witness = generation_path_witness(
            state.state_digest,
            &recipient,
            &receipts,
            valid_until_unix_ms,
        )?;
        Ok(Self {
            recipient,
            state_digest: state.state_digest,
            receipts,
            plan_identities,
            valid_until_unix_ms,
            witness,
        })
    }

    /// Revalidates the consuming permit immediately before map staging.
    ///
    /// # Errors
    ///
    /// Rejects generation/Node substitution, expiry, or receipt drift.
    pub fn verify_for(
        &self,
        state: &EncryptionFastPathState,
        recipient: &EncryptionGenerationRecipient,
        now_unix_ms: u64,
    ) -> Result<(), EncryptionPathProofError> {
        state
            .verify_integrity()
            .map_err(EncryptionPathProofError::InvalidFastPath)?;
        let valid_until = match &self.plan_identities {
            Some(identities) => validate_replica_aware_generation_coverage(
                state,
                recipient,
                &self.receipts,
                identities,
                now_unix_ms,
            )?,
            None => validate_generation_coverage(state, recipient, &self.receipts, now_unix_ms)?,
        };
        if &self.recipient != recipient
            || self.state_digest != state.state_digest
            || self.valid_until_unix_ms != valid_until
            || self.witness
                != generation_path_witness(
                    state.state_digest,
                    recipient,
                    &self.receipts,
                    valid_until,
                )?
        {
            return Err(EncryptionPathProofError::InvalidGenerationProof);
        }
        Ok(())
    }

    #[must_use]
    pub const fn witness(&self) -> EncryptionGenerationPathProofWitness {
        self.witness
    }
}

/// Coverage-only fixture; endpoint transcript/counter admission is exercised
/// separately by the ledger and live `WireGuard` tests.
#[cfg(test)]
pub(crate) fn test_activation_receipt(
    round: EncryptionPathProofRound,
    kernel: [u8; 32],
) -> EncryptionPathActivationReceipt {
    let mut receipt = EncryptionPathActivationReceipt {
        schema_version: ENCRYPTION_PATH_PROOF_SCHEMA_VERSION,
        source_proof_digest: EncryptionEndpointPathProofDigest([1; 32]),
        destination_proof_digest: EncryptionEndpointPathProofDigest([2; 32]),
        source_kernel_configuration_digest: WireGuardKernelConfigurationDigest(kernel),
        destination_kernel_configuration_digest: WireGuardKernelConfigurationDigest([3; 32]),
        admitted_at_unix_ms: round.issued_at_unix_ms + 1,
        valid_until_unix_ms: round.expires_at_unix_ms,
        activation_digest: EncryptionPathActivationDigest([0; 32]),
        round,
    };
    receipt.activation_digest = receipt.calculate_digest().unwrap();
    receipt.verify(receipt.admitted_at_unix_ms).unwrap();
    receipt
}

/// Checks whether current duplex receipts cover one exact local generation
/// without creating a consuming activation capability.
///
/// This is used by an already-active Node when a replacement controller asks
/// it to reconstruct lost activation history. Successful validation permits a
/// testimony report only; it cannot be supplied to map publication.
///
/// # Errors
///
/// Rejects an invalid fast-path state or incomplete, duplicate, expired,
/// foreign, or kernel-divergent receipt coverage.
pub fn validate_encryption_generation_path_receipts(
    state: &EncryptionFastPathState,
    recipient: &EncryptionGenerationRecipient,
    receipts: &[EncryptionPathActivationReceipt],
    now_unix_ms: u64,
) -> Result<(), EncryptionPathProofError> {
    state
        .verify_integrity()
        .map_err(EncryptionPathProofError::InvalidFastPath)?;
    let unique = receipts
        .iter()
        .map(|receipt| receipt.activation_digest.0)
        .collect::<BTreeSet<_>>();
    if unique.len() != receipts.len() {
        return Err(EncryptionPathProofError::InvalidGenerationProof);
    }
    validate_generation_coverage(state, recipient, receipts, now_unix_ms).map(|_| ())
}

/// Validates complete direct/replica coverage without issuing a map capability.
///
/// # Errors
/// Rejects unbound rounds, foreign generations and any incomplete, extra,
/// expired or kernel-divergent plan evidence.
pub fn validate_encryption_generation_path_receipts_from_assignment_batch(
    state: &EncryptionFastPathState,
    recipient: &EncryptionGenerationRecipient,
    receipts: &[EncryptionPathActivationReceipt],
    batch: &AdmittedEncryptionPathProofAssignmentBatch,
    now_unix_ms: u64,
) -> Result<(), EncryptionPathProofError> {
    state
        .verify_integrity()
        .map_err(EncryptionPathProofError::InvalidFastPath)?;
    let identities = receipt_plan_identities(state, batch, receipts)?;
    validate_replica_aware_generation_coverage(state, recipient, receipts, &identities, now_unix_ms)
        .map(|_| ())
}

fn receipt_plan_identities(
    state: &EncryptionFastPathState,
    batch: &AdmittedEncryptionPathProofAssignmentBatch,
    receipts: &[EncryptionPathActivationReceipt],
) -> Result<Vec<(IdentityId, IdentityId)>, EncryptionPathProofError> {
    if batch.batch.generation != Revision::new(state.config.generation) {
        return Err(EncryptionPathProofError::InvalidGenerationProof);
    }
    let assignments = batch
        .assignments()
        .iter()
        .map(|assignment| (assignment.round.round_digest, assignment))
        .collect::<BTreeMap<_, _>>();
    if assignments.len() != batch.assignments().len() {
        return Err(EncryptionPathProofError::InvalidGenerationProof);
    }
    receipts
        .iter()
        .map(|receipt| {
            let assignment = assignments
                .get(&receipt.round.round_digest)
                .ok_or(EncryptionPathProofError::InvalidGenerationProof)?;
            if assignment.round != receipt.round {
                return Err(EncryptionPathProofError::InvalidGenerationProof);
            }
            let plan = batch
                .contract_for(assignment)?
                .plans
                .get(assignment.plan_index)
                .ok_or(EncryptionPathProofError::InvalidGenerationProof)?;
            Ok((plan.source.identity, plan.destination.identity))
        })
        .collect()
}

fn validate_replica_aware_generation_coverage(
    state: &EncryptionFastPathState,
    recipient: &EncryptionGenerationRecipient,
    receipts: &[EncryptionPathActivationReceipt],
    identities: &[(IdentityId, IdentityId)],
    now_unix_ms: u64,
) -> Result<u64, EncryptionPathProofError> {
    if receipts.len() != identities.len() {
        return Err(EncryptionPathProofError::InvalidGenerationProof);
    }
    let mut groups = BTreeMap::<_, Vec<_>>::new();
    let mut unique = BTreeSet::new();
    let mut valid_until = u64::MAX;
    for (receipt, identity) in receipts.iter().zip(identities) {
        receipt
            .verify(now_unix_ms)
            .map_err(|_| EncryptionPathProofError::InvalidGenerationProof)?;
        if receipt.round.source != *recipient || !unique.insert(receipt.activation_digest.0) {
            return Err(EncryptionPathProofError::InvalidGenerationProof);
        }
        groups.entry(*identity).or_default().push(receipt);
        valid_until = valid_until.min(receipt.valid_until_unix_ms);
    }
    let transports = state
        .transport_authority
        .iter()
        .map(|transport| (transport.transport_id, transport))
        .collect::<BTreeMap<_, _>>();
    let replica_transports = state
        .transport_authority
        .iter()
        .map(|transport| {
            (
                transport.destination_node_uid.as_str(),
                transport.key_epoch,
                transport.kernel_configuration_digest,
            )
        })
        .collect::<BTreeSet<_>>();
    for decision in state
        .decision_authority
        .iter()
        .filter(|decision| decision.disposition == EncryptionDisposition::Required)
    {
        let group = groups
            .remove(&(decision.source_identity, decision.destination_identity))
            .ok_or(EncryptionPathProofError::InvalidGenerationProof)?;
        let mut witnesses = Vec::with_capacity(group.len());
        for receipt in &group {
            if Some(receipt.round.contract_revision) != decision.contract_revision
                || Some(receipt.round.epoch) != decision.key_epoch
            {
                return Err(EncryptionPathProofError::InvalidGenerationProof);
            }
            let transport_matches = match decision.transport_id {
                Some(id) => transports.get(&id).is_some_and(|transport| {
                    transport.destination_node_uid == receipt.round.destination.node_uid
                        && transport.key_epoch == receipt.round.epoch
                        && transport.kernel_configuration_digest
                            == receipt.source_kernel_configuration_digest.0
                }),
                None => replica_transports.contains(&(
                    receipt.round.destination.node_uid.as_str(),
                    receipt.round.epoch,
                    receipt.source_kernel_configuration_digest.0,
                )),
            };
            if !transport_matches {
                return Err(EncryptionPathProofError::InvalidGenerationProof);
            }
            witnesses.push(receipt.round.decision_witness.0);
        }
        witnesses.sort_unstable();
        let matches = if decision.transport_id.is_some() {
            witnesses.len() == 1 && witnesses[0] == decision.decision_witness
        } else {
            witnesses.len() > 1
                && !witnesses.windows(2).any(|pair| pair[0] == pair[1])
                && crate::fast_path::aggregate_decision_witness(
                    Revision::new(state.config.generation),
                    decision.source_identity,
                    decision.destination_identity,
                    &witnesses,
                ) == decision.decision_witness
        };
        if !matches {
            return Err(EncryptionPathProofError::InvalidGenerationProof);
        }
    }
    if !groups.is_empty() || now_unix_ms >= valid_until {
        return Err(EncryptionPathProofError::InvalidGenerationProof);
    }
    Ok(valid_until)
}

fn validate_generation_coverage(
    state: &EncryptionFastPathState,
    recipient: &EncryptionGenerationRecipient,
    receipts: &[EncryptionPathActivationReceipt],
    now_unix_ms: u64,
) -> Result<u64, EncryptionPathProofError> {
    let required = state
        .decision_authority
        .iter()
        .filter(|decision| decision.disposition == EncryptionDisposition::Required)
        .collect::<Vec<_>>();
    if required.is_empty() {
        return receipts
            .is_empty()
            .then_some(u64::MAX)
            .ok_or(EncryptionPathProofError::InvalidGenerationProof);
    }
    if receipts.len() != required.len() {
        return Err(EncryptionPathProofError::InvalidGenerationProof);
    }
    let mut used = vec![false; receipts.len()];
    let mut valid_until = u64::MAX;
    for decision in required {
        let transport_id = decision
            .transport_id
            .ok_or(EncryptionPathProofError::InvalidGenerationProof)?;
        let transport = state
            .transport_authority
            .iter()
            .find(|transport| transport.transport_id == transport_id)
            .ok_or(EncryptionPathProofError::InvalidGenerationProof)?;
        let position = receipts
            .iter()
            .enumerate()
            .find(|(position, receipt)| {
                !used[*position]
                    && receipt.round.source == *recipient
                    && receipt.round.destination.node_uid == transport.destination_node_uid
                    && receipt.round.epoch == transport.key_epoch
                    && Some(receipt.round.contract_revision) == decision.contract_revision
                    && receipt.round.decision_witness.0 == decision.decision_witness
                    && receipt.source_kernel_configuration_digest.0
                        == transport.kernel_configuration_digest
                    && receipt.verify(now_unix_ms).is_ok()
            })
            .map(|(position, _)| position)
            .ok_or(EncryptionPathProofError::InvalidGenerationProof)?;
        used[position] = true;
        valid_until = valid_until.min(receipts[position].valid_until_unix_ms);
    }
    if used.iter().any(|used| !used) || now_unix_ms >= valid_until {
        return Err(EncryptionPathProofError::InvalidGenerationProof);
    }
    Ok(valid_until)
}

fn generation_path_witness(
    state_digest: EncryptionFastPathDigest,
    recipient: &EncryptionGenerationRecipient,
    receipts: &[EncryptionPathActivationReceipt],
    valid_until_unix_ms: u64,
) -> Result<EncryptionGenerationPathProofWitness, EncryptionPathProofError> {
    hash(
        b"unf.encryption-generation-path-proof.v1\0",
        &(
            state_digest.0,
            recipient,
            receipts
                .iter()
                .map(|receipt| receipt.activation_digest)
                .collect::<Vec<_>>(),
            valid_until_unix_ms,
        ),
    )
    .map(EncryptionGenerationPathProofWitness)
}

fn exact_peer(
    snapshot: &WireGuardKernelSnapshot,
    public_key: WireGuardPublicKey,
) -> Result<&crate::WireGuardPeerReadback, EncryptionPathProofError> {
    let mut peers = snapshot
        .peers
        .iter()
        .filter(|peer| peer.public_key == public_key);
    let peer = peers
        .next()
        .ok_or(EncryptionPathProofError::KernelConfigurationDrift)?;
    if peers.next().is_some() {
        return Err(EncryptionPathProofError::KernelConfigurationDrift);
    }
    Ok(peer)
}

fn recipient(name: &str, uid: &str) -> EncryptionGenerationRecipient {
    EncryptionGenerationRecipient {
        node_name: name.to_owned(),
        node_uid: uid.to_owned(),
    }
}

fn family_mask(prefixes: &[IpPrefix]) -> u8 {
    prefixes.iter().fold(0, |mask, prefix| {
        mask | match prefix.address {
            IpAddr::V4(_) => PATH_FAMILY_IPV4,
            IpAddr::V6(_) => PATH_FAMILY_IPV6,
        }
    })
}

fn hash<T: Serialize>(domain: &[u8], value: &T) -> Result<[u8; 32], EncryptionPathProofError> {
    let encoded = serde_json::to_vec(value)
        .map_err(|error| EncryptionPathProofError::CanonicalEncoding(error.to_string()))?;
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(encoded);
    Ok(hasher.finalize().into())
}

#[cfg(test)]
pub(crate) mod tests {
    use std::collections::BTreeSet;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

    use unf_common::{IdentityId, PolicyReason, Revision};

    use super::*;
    use crate::kernel_provider::WireGuardKernelSnapshotInput;
    use crate::{
        ATTESTED_ENCRYPTION_PATH_CONTRACT_SCHEMA_VERSION, AttestedEncryptionPathPlan,
        EncryptionCapability, EncryptionContractRevisions, EncryptionEndpointFact,
        EncryptionFailureEnvelope, EncryptionKeyBinding, EncryptionKeyPhase, EncryptionNode,
        EncryptionPathChallengeDelivery, EncryptionPathClass, EncryptionPathFact,
        EncryptionPathProbeExchange, EncryptionPathProbeFrame, EncryptionPolicyBinding,
        EncryptionPublicKeyDigest, EncryptionTransportBinding, UNF_WIREGUARD_ROUTE_PROTOCOL,
        WireGuardPeerReadback, WireGuardRouteReadback, WireGuardRouteScope,
    };

    fn prefix(address: IpAddr, prefix_len: u8) -> IpPrefix {
        IpPrefix {
            address,
            prefix_len,
        }
    }

    fn node(name: &str, uid: &str, pod: IpAddr, underlay: IpAddr) -> EncryptionNode {
        let ipv6 = if uid == "uid-a" {
            "fd00:1::".parse().unwrap()
        } else {
            "fd00:2::".parse().unwrap()
        };
        EncryptionNode {
            cluster_id: "cluster-a".into(),
            name: name.into(),
            uid: uid.into(),
            pod_cidrs: vec![
                prefix(pod, if pod.is_ipv4() { 24 } else { 64 }),
                prefix(IpAddr::V6(ipv6), 64),
            ],
            underlay_addresses: vec![underlay],
            capabilities: BTreeSet::from([
                EncryptionCapability::KernelWireGuard,
                EncryptionCapability::PolicyRouting,
                EncryptionCapability::EncryptedPathChallenge,
            ]),
        }
    }

    #[allow(clippy::too_many_lines)]
    fn fixture_contract() -> AttestedEncryptionPathContract {
        let source_node = node(
            "node-a",
            "uid-a",
            IpAddr::V4(Ipv4Addr::new(10, 10, 1, 0)),
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
        );
        let destination_node = node(
            "node-b",
            "uid-b",
            IpAddr::V4(Ipv4Addr::new(10, 10, 2, 0)),
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)),
        );
        let forward_prefixes = vec![
            prefix(IpAddr::V4(Ipv4Addr::new(10, 10, 2, 0)), 24),
            prefix(IpAddr::V6("fd00:2::".parse::<Ipv6Addr>().unwrap()), 64),
        ];
        let reverse_prefixes = vec![
            prefix(IpAddr::V4(Ipv4Addr::new(10, 10, 1, 0)), 24),
            prefix(IpAddr::V6("fd00:1::".parse::<Ipv6Addr>().unwrap()), 64),
        ];
        let revisions = EncryptionContractRevisions {
            intent: Revision::new(1),
            identity: Revision::new(2),
            policy: Revision::new(3),
            routing: Revision::new(4),
            key: Revision::new(5),
        };
        let plan = AttestedEncryptionPathPlan {
            source: EncryptionEndpointFact {
                identity: IdentityId::new(11),
                workload_uid: "pod-a".into(),
                node: source_node.clone(),
            },
            destination: EncryptionEndpointFact {
                identity: IdentityId::new(22),
                workload_uid: "pod-b".into(),
                node: destination_node,
            },
            disposition: EncryptionDisposition::Required,
            intent_uids: vec!["encrypt-a-b".into()],
            policy: EncryptionPolicyBinding {
                policy_ids: vec![],
                reason: PolicyReason::NoApplicablePolicy,
                revision: revisions.policy,
            },
            source_key: EncryptionKeyBinding {
                node_uid: "uid-a".into(),
                epoch: 7,
                public_key: WireGuardPublicKey([1; 32]),
                public_key_digest: EncryptionPublicKeyDigest([3; 32]),
                phase: EncryptionKeyPhase::Active,
            },
            destination_key: EncryptionKeyBinding {
                node_uid: "uid-b".into(),
                epoch: 7,
                public_key: WireGuardPublicKey([2; 32]),
                public_key_digest: EncryptionPublicKeyDigest([4; 32]),
                phase: EncryptionKeyPhase::Active,
            },
            transport: EncryptionTransportBinding {
                forward: EncryptionPathFact {
                    source_node_uid: "uid-a".into(),
                    destination_node_uid: "uid-b".into(),
                    epoch: 7,
                    path_class: EncryptionPathClass::ManagedPod,
                    peer_endpoint: SocketAddr::from(([192, 0, 2, 2], 51821)),
                    allowed_ips: forward_prefixes,
                    interface_name: "unfwg7a".into(),
                    route_table: 10_007,
                    fwmark: 20_007,
                    mtu: 1_380,
                },
                reverse: EncryptionPathFact {
                    source_node_uid: "uid-b".into(),
                    destination_node_uid: "uid-a".into(),
                    epoch: 7,
                    path_class: EncryptionPathClass::ManagedPod,
                    peer_endpoint: SocketAddr::from(([192, 0, 2, 1], 51820)),
                    allowed_ips: reverse_prefixes,
                    interface_name: "unfwg7b".into(),
                    route_table: 10_008,
                    fwmark: 20_008,
                    mtu: 1_380,
                },
            },
            revisions,
        };
        let mut contract = AttestedEncryptionPathContract {
            schema_version: ATTESTED_ENCRYPTION_PATH_CONTRACT_SCHEMA_VERSION,
            contract_revision: Revision::new(9),
            local_node: source_node,
            valid_from_unix_ms: 1_000,
            valid_until_unix_ms: 100_000,
            plans: vec![plan],
            verified_invariants: vec![],
            failure_envelope: EncryptionFailureEnvelope {
                observations: vec![],
                total_observations: 0,
                truncated: false,
            },
            contract_digest: AttestedEncryptionContractDigest([0; 32]),
        };
        contract.contract_digest = crate::contract_digest(
            contract.contract_revision,
            &contract.local_node,
            contract.valid_from_unix_ms,
            contract.valid_until_unix_ms,
            &contract.plans,
            &contract.verified_invariants,
            &contract.failure_envelope,
        )
        .unwrap();
        contract
    }

    fn fixture_contract_with_plans(plan_count: usize) -> AttestedEncryptionPathContract {
        let mut contract = fixture_contract();
        let template = contract.plans[0].clone();
        contract.plans = (0..plan_count)
            .map(|index| {
                let mut plan = template.clone();
                let identity_offset = u32::try_from(index).unwrap();
                plan.source.identity = IdentityId::new(100 + identity_offset);
                plan.source.workload_uid = format!("pod-a-{index}");
                plan.destination.identity = IdentityId::new(10_000 + identity_offset);
                plan.destination.workload_uid = format!("pod-b-{index}");
                plan
            })
            .collect();
        contract.contract_digest = crate::contract_digest(
            contract.contract_revision,
            &contract.local_node,
            contract.valid_from_unix_ms,
            contract.valid_until_unix_ms,
            &contract.plans,
            &contract.verified_invariants,
            &contract.failure_envelope,
        )
        .unwrap();
        contract
    }

    pub(crate) fn assignment_fixture() -> EncryptionPathProofAssignment {
        let contract = fixture_contract();
        let round = EncryptionPathProofRound::issue(&contract, 0, [9; 32], 1_500, 10_000).unwrap();
        EncryptionPathProofAssignment {
            schema_version: ENCRYPTION_PATH_PROOF_SCHEMA_VERSION,
            generation: Revision::new(10),
            round,
            contract,
            plan_index: 0,
        }
    }

    fn snapshot(
        contract: &AttestedEncryptionPathContract,
        role: EncryptionPathEndpointRole,
        rx: u64,
        tx: u64,
    ) -> WireGuardKernelSnapshot {
        let plan = &contract.plans[0];
        let (path, local_key, peer_key, local_node, index, port) = match role {
            EncryptionPathEndpointRole::Source => (
                &plan.transport.forward,
                plan.source_key.public_key,
                plan.destination_key.public_key,
                &plan.source.node,
                71,
                51820,
            ),
            EncryptionPathEndpointRole::Destination => (
                &plan.transport.reverse,
                plan.destination_key.public_key,
                plan.source_key.public_key,
                &plan.destination.node,
                72,
                51821,
            ),
        };
        WireGuardKernelSnapshot::issue(WireGuardKernelSnapshotInput {
            interface_name: path.interface_name.clone(),
            interface_index: index,
            owner_alias: format!("unf:encryption:v2:{}:7", plan.source.node.cluster_id),
            is_up: true,
            mtu: path.mtu,
            public_key: local_key,
            listen_port: port,
            fwmark: path.fwmark,
            proof_addresses: crate::derive_wireguard_proof_addresses(&local_node.pod_cidrs)
                .unwrap(),
            peers: vec![
                WireGuardPeerReadback {
                    public_key: peer_key,
                    endpoint: path.peer_endpoint,
                    persistent_keepalive_seconds: 5,
                    allowed_ips: path.allowed_ips.clone(),
                    last_handshake_unix_seconds: 2,
                    received_bytes: rx,
                    transmitted_bytes: tx,
                },
                WireGuardPeerReadback {
                    public_key: WireGuardPublicKey([9; 32]),
                    endpoint: SocketAddr::from(([192, 0, 2, 99], 51_899)),
                    persistent_keepalive_seconds: 5,
                    allowed_ips: vec![prefix(IpAddr::V4(Ipv4Addr::new(10, 250, 0, 0)), 24)],
                    last_handshake_unix_seconds: 2,
                    received_bytes: rx,
                    transmitted_bytes: tx,
                },
            ],
            routes: path
                .allowed_ips
                .iter()
                .copied()
                .chain([prefix(IpAddr::V4(Ipv4Addr::new(10, 250, 0, 0)), 24)])
                .map(|prefix| WireGuardRouteReadback {
                    prefix,
                    interface_index: index,
                    table: path.route_table,
                    protocol: UNF_WIREGUARD_ROUTE_PROTOCOL,
                    scope: WireGuardRouteScope::for_prefix(prefix),
                })
                .collect(),
        })
        .unwrap()
    }

    fn auth(role: EncryptionPathEndpointRole) -> AuthenticatedNodeIdentity {
        let (name, uid) = match role {
            EncryptionPathEndpointRole::Source => ("node-a", "uid-a"),
            EncryptionPathEndpointRole::Destination => ("node-b", "uid-b"),
        };
        AuthenticatedNodeIdentity {
            cluster_id: "cluster-a".into(),
            node_name: name.into(),
            node_uid: uid.into(),
        }
    }

    fn delivery(
        round: &EncryptionPathProofRound,
        contract: &AttestedEncryptionPathContract,
        role: EncryptionPathEndpointRole,
    ) -> EncryptionPathChallengeDelivery {
        let assignment = EncryptionPathProofAssignment {
            schema_version: ENCRYPTION_PATH_PROOF_SCHEMA_VERSION,
            generation: Revision::new(10),
            round: round.clone(),
            contract: contract.clone(),
            plan_index: 0,
        };
        let recipient = match role {
            EncryptionPathEndpointRole::Source => round.source.clone(),
            EncryptionPathEndpointRole::Destination => round.destination.clone(),
        };
        let plan = &contract.plans[0];
        let (local_node, peer_node) = match role {
            EncryptionPathEndpointRole::Source => (&plan.source.node, &plan.destination.node),
            EncryptionPathEndpointRole::Destination => (&plan.destination.node, &plan.source.node),
        };
        let local = crate::derive_wireguard_proof_addresses(&local_node.pod_cidrs).unwrap();
        let peer = crate::derive_wireguard_proof_addresses(&peer_node.pod_cidrs).unwrap();
        let exchanges = [PATH_FAMILY_IPV4, PATH_FAMILY_IPV6]
            .into_iter()
            .filter(|family| round.family_mask & family != 0)
            .map(|family| {
                let request = EncryptionPathProbeFrame::request(round, family).unwrap();
                let response = EncryptionPathProbeFrame::response(round, request).unwrap();
                EncryptionPathProbeExchange::from_wire(
                    round,
                    local
                        .iter()
                        .find(|prefix| prefix.address.is_ipv4() == (family == PATH_FAMILY_IPV4))
                        .unwrap()
                        .address,
                    peer.iter()
                        .find(|prefix| prefix.address.is_ipv4() == (family == PATH_FAMILY_IPV4))
                        .unwrap()
                        .address,
                    &request.encode(),
                    &response.encode(),
                )
                .unwrap()
            })
            .collect();
        EncryptionPathChallengeDelivery::issue(&assignment, &recipient, exchanges).unwrap()
    }

    fn proof(
        round: &EncryptionPathProofRound,
        contract: &AttestedEncryptionPathContract,
        role: EncryptionPathEndpointRole,
    ) -> EncryptionEndpointPathProof {
        let delivery = delivery(round, contract, role);
        EncryptionEndpointPathProof::issue(
            round,
            contract,
            0,
            role,
            &auth(role),
            &snapshot(contract, role, 10, 20),
            &snapshot(contract, role, 110, 120),
            &delivery,
            2_000,
        )
        .unwrap()
    }

    #[test]
    fn causal_duplex_quorum_requires_both_authenticated_counter_backed_transcripts() {
        let contract = fixture_contract();
        let round = EncryptionPathProofRound::issue(&contract, 0, [9; 32], 1_500, 10_000).unwrap();
        let indexed = EncryptionPathProofAssignmentIndex {
            schema_version: ENCRYPTION_PATH_PROOF_SCHEMA_VERSION,
            generation: Revision::new(10),
            round: round.clone(),
            contract_digest: contract.contract_digest,
            plan_index: 0,
        };
        let batch = EncryptionPathProofAssignmentBatch {
            schema_version: ENCRYPTION_PATH_PROOF_ASSIGNMENT_BATCH_SCHEMA_VERSION,
            generation: Revision::new(10),
            contracts: vec![contract.clone()],
            assignments: vec![indexed.clone()],
        }
        .admit()
        .unwrap();
        let role = EncryptionPathEndpointRole::Source;
        let admitted_proof = EncryptionEndpointPathProof::issue_from_assignment_batch(
            &batch,
            &indexed,
            role,
            &auth(role),
            &snapshot(&contract, role, 10, 20),
            &snapshot(&contract, role, 110, 120),
            &delivery(&round, &contract, role),
            2_000,
        )
        .unwrap();
        assert_eq!(admitted_proof, proof(&round, &contract, role));
        let mut ledger = EncryptionPathProofLedger::new(round.clone()).unwrap();
        let source = proof(&round, &contract, EncryptionPathEndpointRole::Source);
        assert_eq!(
            ledger.observe(&auth(EncryptionPathEndpointRole::Source), source, 2_100),
            Ok(EncryptionPathProofAdmission::AcceptedPendingPeer)
        );
        assert_eq!(
            ledger.activation_receipt(2_100),
            Err(EncryptionPathProofError::IncompleteQuorum)
        );
        let destination = proof(&round, &contract, EncryptionPathEndpointRole::Destination);
        assert_eq!(
            ledger.observe(
                &auth(EncryptionPathEndpointRole::Destination),
                destination,
                2_100
            ),
            Ok(EncryptionPathProofAdmission::AcceptedComplete)
        );
        let receipt = ledger.activation_receipt(2_100).unwrap();
        receipt.verify(9_999).unwrap();
        assert!(receipt.verify(10_000).is_err());
    }

    #[test]
    fn roaming_replay_counter_stall_and_mutation_deny_closed() {
        let contract = fixture_contract();
        let round = EncryptionPathProofRound::issue(&contract, 0, [7; 32], 1_500, 10_000).unwrap();
        let role = EncryptionPathEndpointRole::Source;
        let before = snapshot(&contract, role, 10, 20);

        let stalled = EncryptionEndpointPathProof::issue(
            &round,
            &contract,
            0,
            role,
            &auth(role),
            &before,
            &before,
            &delivery(&round, &contract, role),
            2_000,
        );
        assert_eq!(stalled, Err(EncryptionPathProofError::CounterProofMissing));

        let mut roamed = snapshot(&contract, role, 110, 120);
        roamed.peers[0].endpoint = SocketAddr::from(([192, 0, 2, 99], 51821));
        assert!(
            EncryptionEndpointPathProof::issue(
                &round,
                &contract,
                0,
                role,
                &auth(role),
                &before,
                &roamed,
                &delivery(&round, &contract, role),
                2_000,
            )
            .is_err()
        );

        let mut valid = proof(&round, &contract, role);
        valid.challenge_response_digest.0[0] ^= 1;
        assert!(valid.verify(&round, 2_100).is_err());
        let other_round =
            EncryptionPathProofRound::issue(&contract, 0, [8; 32], 1_500, 10_000).unwrap();
        assert!(
            proof(&round, &contract, role)
                .verify(&other_round, 2_100)
                .is_err()
        );
    }

    #[test]
    fn path_proof_wire_shape_rejects_unknown_authority() {
        let contract = fixture_contract();
        let round = EncryptionPathProofRound::issue(&contract, 0, [6; 32], 1_500, 10_000).unwrap();
        let mut value = serde_json::to_value(&round).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("handshakeIsEnough".into(), serde_json::json!(true));
        assert!(serde_json::from_value::<EncryptionPathProofRound>(value).is_err());
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn endpoint_proof_batches_are_bounded_atomic_generation_fenced_and_idempotent() {
        let contract = fixture_contract();
        let mut coordinator = EncryptionPathProofCoordinator::default();
        coordinator
            .replace_contract_batches(Revision::new(10), vec![contract.clone()], 1_500, 8_500)
            .unwrap();
        let round = coordinator
            .paths
            .values()
            .next()
            .unwrap()
            .assignment
            .round
            .clone();
        let source = EncryptionPathEndpointRole::Source;
        let batch = EncryptionEndpointPathProofBatch {
            schema_version: ENCRYPTION_ENDPOINT_PATH_PROOF_BATCH_SCHEMA_VERSION,
            generation: Revision::new(10),
            proofs: vec![proof(&round, &contract, source)],
        };
        let mut invalid = batch.clone();
        let mut unknown = batch.proofs[0].clone();
        unknown.round_digest.0[0] ^= 1;
        invalid.proofs.push(unknown);
        assert!(
            coordinator
                .observe_batch(&auth(source), &invalid, 2_100)
                .is_err()
        );
        assert!(
            coordinator
                .paths
                .values()
                .all(|path| path.ledger.proofs.is_empty()),
            "a rejected tail must not retain the valid prefix"
        );
        invalid = batch.clone();
        invalid.proofs.push(batch.proofs[0].clone());
        assert!(
            coordinator
                .observe_batch(&auth(source), &invalid, 2_100)
                .is_err()
        );
        invalid = batch.clone();
        invalid.generation = Revision::new(11);
        assert!(
            coordinator
                .observe_batch(&auth(source), &invalid, 2_100)
                .is_err()
        );
        invalid = batch.clone();
        invalid.schema_version += 1;
        assert!(
            coordinator
                .observe_batch(&auth(source), &invalid, 2_100)
                .is_err()
        );
        invalid = batch.clone();
        invalid.proofs.clear();
        assert!(
            coordinator
                .observe_batch(&auth(source), &invalid, 2_100)
                .is_err()
        );
        invalid.proofs =
            vec![batch.proofs[0].clone(); MAX_ENCRYPTION_ENDPOINT_PATH_PROOF_BATCH + 1];
        assert!(
            coordinator
                .observe_batch(&auth(source), &invalid, 2_100)
                .is_err()
        );
        let destination = EncryptionPathEndpointRole::Destination;
        assert!(
            coordinator
                .observe_batch(&auth(destination), &batch, 2_100)
                .is_err()
        );
        assert!(
            coordinator
                .observe_batch(&auth(source), &batch, 10_000)
                .is_err()
        );
        assert!(
            coordinator
                .paths
                .values()
                .all(|path| path.ledger.proofs.is_empty())
        );
        assert_eq!(
            coordinator
                .observe_batch(&auth(source), &batch, 2_100)
                .unwrap(),
            vec![EncryptionPathProofAdmission::AcceptedPendingPeer]
        );
        assert_eq!(
            coordinator
                .observe_batch(&auth(source), &batch, 2_100)
                .unwrap(),
            vec![EncryptionPathProofAdmission::Idempotent]
        );
        let destination_batch = EncryptionEndpointPathProofBatch {
            proofs: vec![proof(&round, &contract, destination)],
            ..batch.clone()
        };
        assert_eq!(
            coordinator
                .observe_batch(&auth(destination), &destination_batch, 2_100)
                .unwrap(),
            vec![EncryptionPathProofAdmission::AcceptedComplete]
        );
        let encoded = serde_json::to_value(&batch).unwrap();
        assert_eq!(
            serde_json::from_value::<EncryptionEndpointPathProofBatch>(encoded.clone()).unwrap(),
            batch
        );
        let mut unknown_field = encoded;
        unknown_field["trustBatchWithoutProofs"] = serde_json::json!(true);
        assert!(serde_json::from_value::<EncryptionEndpointPathProofBatch>(unknown_field).is_err());
    }

    #[test]
    fn generation_fenced_coordinator_scopes_assignments_and_clears_old_evidence() {
        let contract = fixture_contract();
        let mut coordinator = EncryptionPathProofCoordinator::default();
        assert_eq!(
            coordinator.replace_contracts(
                Revision::new(12),
                vec![(contract.clone(), 0)],
                1_500,
                8_000,
            ),
            Ok(true)
        );
        assert_eq!(
            coordinator.replace_contracts(
                Revision::new(12),
                vec![(contract.clone(), 0)],
                1_500,
                8_000,
            ),
            Ok(false)
        );
        let source_recipient = recipient("node-a", "uid-a");
        let destination_recipient = recipient("node-b", "uid-b");
        let foreign_recipient = recipient("node-c", "uid-c");
        assert_eq!(coordinator.assignments_for(&source_recipient).len(), 1);
        assert_eq!(coordinator.assignments_for(&destination_recipient).len(), 1);
        assert!(coordinator.assignments_for(&foreign_recipient).is_empty());

        let assignment = coordinator.assignments_for(&source_recipient).remove(0);
        coordinator
            .observe(
                &auth(EncryptionPathEndpointRole::Source),
                proof(
                    &assignment.round,
                    &assignment.contract,
                    EncryptionPathEndpointRole::Source,
                ),
                2_100,
            )
            .unwrap();
        assert!(
            coordinator
                .receipts_for(&source_recipient, 2_100)
                .is_empty()
        );
        coordinator
            .observe(
                &auth(EncryptionPathEndpointRole::Destination),
                proof(
                    &assignment.round,
                    &assignment.contract,
                    EncryptionPathEndpointRole::Destination,
                ),
                2_100,
            )
            .unwrap();
        assert_eq!(coordinator.receipts_for(&source_recipient, 2_100).len(), 1);
        assert!(
            coordinator
                .receipts_for(&destination_recipient, 2_100)
                .is_empty()
        );

        assert_eq!(
            coordinator.replace_contracts(Revision::new(13), vec![], 3_000, 8_000),
            Ok(true)
        );
        assert!(coordinator.assignments_for(&source_recipient).is_empty());
        assert!(
            coordinator
                .receipts_for(&source_recipient, 3_100)
                .is_empty()
        );
        assert!(matches!(
            coordinator.replace_contracts(Revision::new(12), vec![(contract, 0)], 3_000, 8_000,),
            Err(EncryptionPathProofError::GenerationConflict)
        ));
    }

    #[test]
    fn compact_assignment_replays_contract_once_per_boundary() {
        for plan_count in [1, 64, 256] {
            let contract = fixture_contract_with_plans(plan_count);
            let mut coordinator = EncryptionPathProofCoordinator::default();
            crate::CONTRACT_INTEGRITY_REPLAYS.with(|count| count.set(0));
            coordinator
                .replace_contract_batches(Revision::new(14), vec![contract], 1_500, 8_000)
                .unwrap();
            assert_eq!(
                crate::CONTRACT_INTEGRITY_REPLAYS.with(std::cell::Cell::get),
                1
            );
            let batch = coordinator.assignment_batch_for(&recipient("node-a", "uid-a"));
            crate::CONTRACT_INTEGRITY_REPLAYS.with(|count| count.set(0));
            let admitted = batch.admit().unwrap();
            assert_eq!(
                crate::CONTRACT_INTEGRITY_REPLAYS.with(std::cell::Cell::get),
                1
            );
            for assignment in admitted.assignments() {
                admitted.contract_for(assignment).unwrap();
                assignment
                    .probe_targets_from_assignment_batch(&admitted, &recipient("node-a", "uid-a"))
                    .unwrap();
            }
            assert_eq!(
                crate::CONTRACT_INTEGRITY_REPLAYS.with(std::cell::Cell::get),
                1
            );
        }
    }

    #[test]
    fn contract_deduplicated_assignment_batch_is_linear_and_fails_closed() {
        let contract = fixture_contract_with_plans(64);
        let mut coordinator = EncryptionPathProofCoordinator::default();
        assert_eq!(
            coordinator.replace_contract_batches(
                Revision::new(14),
                vec![contract.clone()],
                1_500,
                8_000,
            ),
            Ok(true)
        );
        let source = recipient("node-a", "uid-a");
        let batch = coordinator.assignment_batch_for(&source);
        assert_eq!(batch.contracts, vec![contract]);
        assert_eq!(batch.assignments.len(), 64);
        batch.verify().unwrap();

        let encoded = serde_json::to_vec(&batch).unwrap();
        let legacy = serde_json::to_vec(&coordinator.assignments_for(&source)).unwrap();
        assert!(encoded.len() * 16 < legacy.len());
        serde_json::from_slice::<EncryptionPathProofAssignmentBatch>(&encoded)
            .unwrap()
            .verify()
            .unwrap();

        let admitted = batch.clone().admit().unwrap();
        let mut selection = admitted.assignments()[0].clone();
        admitted.contract_for(&selection).unwrap();
        selection.generation = Revision::new(15);
        assert!(admitted.contract_for(&selection).is_err());
        selection.generation = Revision::new(14);
        selection.round.source.node_uid.push_str("-foreign");
        assert!(admitted.contract_for(&selection).is_err());

        let mut digest_mutated = batch.clone();
        digest_mutated.assignments[0].contract_digest.0[0] ^= 1;
        assert_eq!(
            digest_mutated.verify(),
            Err(EncryptionPathProofError::InvalidContractPlan)
        );
        let mut duplicate_contract = batch;
        duplicate_contract
            .contracts
            .push(duplicate_contract.contracts[0].clone());
        assert_eq!(
            duplicate_contract.verify(),
            Err(EncryptionPathProofError::InvalidContractPlan)
        );
    }
}
