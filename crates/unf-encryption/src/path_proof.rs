//! Two-ended, nonce-bound proof of a live encrypted path.
//!
//! Configuration readback, peer counters, authenticated Node identity, and an
//! encrypted challenge are independent evidence planes. No single plane—and
//! especially no handshake timestamp—can activate Required traffic.

use std::collections::BTreeMap;
use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::{
    AttestedEncryptionContractDigest, AttestedEncryptionPathContract, AuthenticatedNodeIdentity,
    EncryptionDecisionWitness, EncryptionDisposition, EncryptionGenerationRecipient, IpPrefix,
    WireGuardKernelConfigurationDigest, WireGuardKernelObservationDigest, WireGuardKernelSnapshot,
    WireGuardPublicKey,
};

pub const ENCRYPTION_PATH_PROOF_SCHEMA_VERSION: u16 = 1;
pub const MAX_ENCRYPTION_PATH_PROOF_LIFETIME_MS: u64 = 60_000;
pub const PATH_FAMILY_IPV4: u8 = 1;
pub const PATH_FAMILY_IPV6: u8 = 2;
const ROUND_DOMAIN: &[u8] = b"unf.encryption-path-proof-round.v1\0";
const CHALLENGE_REQUEST_DOMAIN: &[u8] = b"unf.encryption-path-challenge-request.v1\0";
const CHALLENGE_RESPONSE_DOMAIN: &[u8] = b"unf.encryption-path-challenge-response.v1\0";
const ENDPOINT_PROOF_DOMAIN: &[u8] = b"unf.encryption-path-endpoint-proof.v1\0";
const ACTIVATION_DOMAIN: &[u8] = b"unf.encryption-path-activation.v1\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum EncryptionPathEndpointRole {
    Source,
    Destination,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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

/// Controller-issued immutable challenge for one canonical Required plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EncryptionPathProofRound {
    pub schema_version: u16,
    pub contract_digest: AttestedEncryptionContractDigest,
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
    pub admitted_at_unix_ms: u64,
    pub valid_until_unix_ms: u64,
    pub activation_digest: EncryptionPathActivationDigest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncryptionPathProofAdmission {
    AcceptedPendingPeer,
    AcceptedComplete,
    Idempotent,
}

#[derive(Debug)]
pub struct EncryptionPathProofLedger {
    round: EncryptionPathProofRound,
    proofs: BTreeMap<EncryptionPathEndpointRole, EncryptionEndpointPathProof>,
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
    #[error("invalid kernel snapshot: {0}")]
    InvalidKernelSnapshot(String),
    #[error("invalid contract: {0}")]
    InvalidContract(String),
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
        delivered_family_mask: u8,
        observed_at_unix_ms: u64,
    ) -> Result<Self, EncryptionPathProofError> {
        round.verify()?;
        contract
            .verify_integrity()
            .map_err(|error| EncryptionPathProofError::InvalidContract(error.to_string()))?;
        let plan = contract
            .plans
            .get(plan_index)
            .ok_or(EncryptionPathProofError::InvalidContractPlan)?;
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
        let routes_exact = |snapshot: &WireGuardKernelSnapshot| {
            snapshot.routes.len() == path.allowed_ips.len()
                && snapshot
                    .routes
                    .iter()
                    .zip(&path.allowed_ips)
                    .all(|(route, prefix)| {
                        route.prefix == *prefix
                            && route.table == path.route_table
                            && route.interface_index == snapshot.interface_index
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
            admitted_at_unix_ms: now_unix_ms,
            valid_until_unix_ms: self.round.expires_at_unix_ms,
            activation_digest: EncryptionPathActivationDigest([0; 32]),
        };
        receipt.activation_digest = receipt.calculate_digest()?;
        receipt.verify(now_unix_ms)?;
        Ok(receipt)
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
mod tests {
    use std::collections::BTreeSet;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

    use unf_common::{IdentityId, PolicyReason, Revision};

    use super::*;
    use crate::kernel_provider::WireGuardKernelSnapshotInput;
    use crate::{
        ATTESTED_ENCRYPTION_PATH_CONTRACT_SCHEMA_VERSION, AttestedEncryptionPathPlan,
        EncryptionCapability, EncryptionContractRevisions, EncryptionEndpointFact,
        EncryptionFailureEnvelope, EncryptionKeyBinding, EncryptionKeyPhase, EncryptionNode,
        EncryptionPathClass, EncryptionPathFact, EncryptionPolicyBinding,
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
        EncryptionNode {
            cluster_id: "cluster-a".into(),
            name: name.into(),
            uid: uid.into(),
            pod_cidrs: vec![prefix(pod, if pod.is_ipv4() { 24 } else { 64 })],
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

    fn snapshot(
        contract: &AttestedEncryptionPathContract,
        role: EncryptionPathEndpointRole,
        rx: u64,
        tx: u64,
    ) -> WireGuardKernelSnapshot {
        let plan = &contract.plans[0];
        let (path, local_key, peer_key, index, port) = match role {
            EncryptionPathEndpointRole::Source => (
                &plan.transport.forward,
                plan.source_key.public_key,
                plan.destination_key.public_key,
                71,
                51820,
            ),
            EncryptionPathEndpointRole::Destination => (
                &plan.transport.reverse,
                plan.destination_key.public_key,
                plan.source_key.public_key,
                72,
                51821,
            ),
        };
        WireGuardKernelSnapshot::issue(WireGuardKernelSnapshotInput {
            interface_name: path.interface_name.clone(),
            interface_index: index,
            owner_alias: format!("unf:encryption:v1:{}:7", plan.source.node.cluster_id),
            is_up: true,
            mtu: path.mtu,
            public_key: local_key,
            listen_port: port,
            fwmark: path.fwmark,
            peers: vec![WireGuardPeerReadback {
                public_key: peer_key,
                endpoint: path.peer_endpoint,
                persistent_keepalive_seconds: 5,
                allowed_ips: path.allowed_ips.clone(),
                last_handshake_unix_seconds: 2,
                received_bytes: rx,
                transmitted_bytes: tx,
            }],
            routes: path
                .allowed_ips
                .iter()
                .map(|prefix| WireGuardRouteReadback {
                    prefix: *prefix,
                    interface_index: index,
                    table: path.route_table,
                    protocol: UNF_WIREGUARD_ROUTE_PROTOCOL,
                    scope: WireGuardRouteScope::for_prefix(*prefix),
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

    fn proof(
        round: &EncryptionPathProofRound,
        contract: &AttestedEncryptionPathContract,
        role: EncryptionPathEndpointRole,
    ) -> EncryptionEndpointPathProof {
        EncryptionEndpointPathProof::issue(
            round,
            contract,
            0,
            role,
            &auth(role),
            &snapshot(contract, role, 10, 20),
            &snapshot(contract, role, 110, 120),
            PATH_FAMILY_IPV4 | PATH_FAMILY_IPV6,
            2_000,
        )
        .unwrap()
    }

    #[test]
    fn causal_duplex_quorum_requires_both_authenticated_counter_backed_transcripts() {
        let contract = fixture_contract();
        let round = EncryptionPathProofRound::issue(&contract, 0, [9; 32], 1_500, 10_000).unwrap();
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
            round.family_mask,
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
                round.family_mask,
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
}
