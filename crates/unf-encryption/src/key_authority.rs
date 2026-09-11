//! Node-local `WireGuard` key authority and durable epoch rotation.
//!
//! Secret material is deliberately absent from every serializable public type.
//! Only the private, mode-0600 Node-local checkpoint format can encode it.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write as _};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use unf_common::Revision;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::{WireGuardPublicKey, public_key_digest};

pub const NODE_KEY_AUTHORITY_SCHEMA_VERSION: u16 = 1;
pub const NODE_KEY_PUBLICATION_SCHEMA_VERSION: u16 = 1;
pub const CAUSAL_EPOCH_BARRIER_SCHEMA_VERSION: u16 = 1;
pub const MAX_ROTATION_PEERS: usize = 4_096;
pub const MAX_KEY_AUTHORITY_TEXT_BYTES: usize = 253;
pub const MAX_KEY_LIFETIME_MS: u64 = 31 * 24 * 60 * 60 * 1_000;
pub const MAX_EPOCH_DRAIN_MS: u64 = 24 * 60 * 60 * 1_000;

const KEY_FILE_MODE: u32 = 0o600;
const KEY_DIRECTORY_MODE: u32 = 0o700;
const CHECKPOINT_DIGEST_DOMAIN: &[u8] = b"unf.node-key-checkpoint.v1\0";
const BARRIER_DIGEST_DOMAIN: &[u8] = b"unf.causal-epoch-barrier.v1\0";
const READINESS_DIGEST_DOMAIN: &[u8] = b"unf.epoch-readiness-certificate.v1\0";
const PUBLICATION_DIGEST_DOMAIN: &[u8] = b"unf.node-key-publication.v1\0";
const DRAIN_PROOF_DIGEST_DOMAIN: &[u8] = b"unf.epoch-drain-proof.v1\0";
const REVOCATION_DIGEST_DOMAIN: &[u8] = b"unf.epoch-revocation.v1\0";

/// A secret whose debug representation can never reveal key bytes.
pub struct WireGuardPrivateKey(Zeroizing<[u8; 32]>);

impl WireGuardPrivateKey {
    fn from_zeroizing(bytes: Zeroizing<[u8; 32]>) -> Result<Self, KeyAuthorityError> {
        if *bytes == [0; 32] {
            return Err(KeyAuthorityError::InvalidPrivateKey);
        }
        Ok(Self(bytes))
    }

    /// Returns the bytes solely for programming the local kernel provider.
    ///
    /// Callers must not log, serialize, publish, or checkpoint this slice
    /// outside [`FileNodeKeyStateStore`].
    #[must_use]
    pub fn expose_for_kernel(&self) -> &[u8; 32] {
        &self.0
    }

    pub(crate) fn public_key(&self) -> WireGuardPublicKey {
        let secret = StaticSecret::from(*self.0);
        WireGuardPublicKey(PublicKey::from(&secret).to_bytes())
    }

    fn clone_bytes(&self) -> Zeroizing<[u8; 32]> {
        self.0.clone()
    }
}

impl Clone for WireGuardPrivateKey {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl fmt::Debug for WireGuardPrivateKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WireGuardPrivateKey(<redacted>)")
    }
}

pub trait WireGuardKeyGenerator {
    /// Generates a fresh private key from a cryptographically secure source.
    ///
    /// # Errors
    ///
    /// Returns an error when the entropy source fails.
    fn generate(&mut self) -> Result<WireGuardPrivateKey, KeyAuthorityError>;
}

#[derive(Debug, Default)]
pub struct OsWireGuardKeyGenerator;

impl WireGuardKeyGenerator for OsWireGuardKeyGenerator {
    fn generate(&mut self) -> Result<WireGuardPrivateKey, KeyAuthorityError> {
        let mut bytes = Zeroizing::new([0_u8; 32]);
        getrandom::fill(&mut bytes[..])
            .map_err(|error| KeyAuthorityError::EntropyUnavailable(error.to_string()))?;
        WireGuardPrivateKey::from_zeroizing(bytes)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum KeyEpochPhase {
    Prepared,
    MutuallyAttested,
    Active,
    Draining,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CausalEpochBarrierDigest(pub [u8; 32]);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EpochReadinessDigest(pub [u8; 32]);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct NodeKeyPublicationDigest(pub [u8; 32]);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EpochDrainProofDigest(pub [u8; 32]);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EpochRevocationDigest(pub [u8; 32]);

/// Exact affected-peer frontier that must acknowledge a prepared epoch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CausalEpochBarrier {
    pub schema_version: u16,
    pub target_node_uid: String,
    pub epoch: u64,
    pub public_key_digest: crate::EncryptionPublicKeyDigest,
    pub topology_revision: Revision,
    pub required_peer_uids: BTreeSet<String>,
    pub valid_until_unix_ms: u64,
    pub barrier_digest: CausalEpochBarrierDigest,
}

impl CausalEpochBarrier {
    fn issue(
        target_node_uid: String,
        epoch: u64,
        public_key: WireGuardPublicKey,
        topology_revision: Revision,
        required_peer_uids: BTreeSet<String>,
        valid_until_unix_ms: u64,
    ) -> Result<Self, KeyAuthorityError> {
        validate_peer_frontier(&target_node_uid, &required_peer_uids)?;
        if epoch == 0 || topology_revision == Revision::INITIAL || valid_until_unix_ms == 0 {
            return Err(KeyAuthorityError::InvalidBarrier);
        }
        let mut barrier = Self {
            schema_version: CAUSAL_EPOCH_BARRIER_SCHEMA_VERSION,
            target_node_uid,
            epoch,
            public_key_digest: public_key_digest(public_key),
            topology_revision,
            required_peer_uids,
            valid_until_unix_ms,
            barrier_digest: CausalEpochBarrierDigest([0; 32]),
        };
        barrier.barrier_digest = barrier.calculate_digest()?;
        Ok(barrier)
    }

    /// Independently verifies the canonical peer frontier and digest.
    ///
    /// # Errors
    ///
    /// Rejects malformed, oversized, or digest-mismatched barriers.
    pub fn verify(&self) -> Result<(), KeyAuthorityError> {
        if self.schema_version != CAUSAL_EPOCH_BARRIER_SCHEMA_VERSION
            || self.epoch == 0
            || self.topology_revision == Revision::INITIAL
            || self.valid_until_unix_ms == 0
        {
            return Err(KeyAuthorityError::InvalidBarrier);
        }
        validate_peer_frontier(&self.target_node_uid, &self.required_peer_uids)?;
        if self.barrier_digest != self.calculate_digest()? {
            return Err(KeyAuthorityError::BarrierDigestMismatch);
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Result<CausalEpochBarrierDigest, KeyAuthorityError> {
        let mut canonical = self.clone();
        canonical.barrier_digest = CausalEpochBarrierDigest([0; 32]);
        hash_canonical(BARRIER_DIGEST_DOMAIN, &canonical).map(CausalEpochBarrierDigest)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PeerEpochAcknowledgement {
    pub peer_node_uid: String,
    pub target_node_uid: String,
    pub epoch: u64,
    pub barrier_digest: CausalEpochBarrierDigest,
    pub peer_public_epoch: u64,
    pub observed_at_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EpochReadinessCertificate {
    pub barrier_digest: CausalEpochBarrierDigest,
    pub acknowledged_peer_uids: Vec<String>,
    pub readiness_digest: EpochReadinessDigest,
}

pub struct LocalKeyEpoch {
    epoch: u64,
    public_key: WireGuardPublicKey,
    private_key: WireGuardPrivateKey,
    valid_from_unix_ms: u64,
    valid_until_unix_ms: u64,
    phase: KeyEpochPhase,
    barrier: CausalEpochBarrier,
    acknowledgements: BTreeMap<String, PeerEpochAcknowledgement>,
    readiness: Option<EpochReadinessCertificate>,
    drain_deadline_unix_ms: Option<u64>,
}

impl Clone for LocalKeyEpoch {
    fn clone(&self) -> Self {
        Self {
            epoch: self.epoch,
            public_key: self.public_key,
            private_key: self.private_key.clone(),
            valid_from_unix_ms: self.valid_from_unix_ms,
            valid_until_unix_ms: self.valid_until_unix_ms,
            phase: self.phase,
            barrier: self.barrier.clone(),
            acknowledgements: self.acknowledgements.clone(),
            readiness: self.readiness.clone(),
            drain_deadline_unix_ms: self.drain_deadline_unix_ms,
        }
    }
}

impl fmt::Debug for LocalKeyEpoch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LocalKeyEpoch")
            .field("epoch", &self.epoch)
            .field("public_key", &self.public_key)
            .field("private_key", &"<redacted>")
            .field("valid_from_unix_ms", &self.valid_from_unix_ms)
            .field("valid_until_unix_ms", &self.valid_until_unix_ms)
            .field("phase", &self.phase)
            .field("barrier", &self.barrier)
            .field("acknowledgement_count", &self.acknowledgements.len())
            .field("readiness", &self.readiness)
            .field("drain_deadline_unix_ms", &self.drain_deadline_unix_ms)
            .finish()
    }
}

impl LocalKeyEpoch {
    #[must_use]
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    #[must_use]
    pub const fn public_key(&self) -> WireGuardPublicKey {
        self.public_key
    }

    #[must_use]
    pub const fn phase(&self) -> KeyEpochPhase {
        self.phase
    }

    #[must_use]
    pub const fn valid_until_unix_ms(&self) -> u64 {
        self.valid_until_unix_ms
    }

    #[must_use]
    pub const fn barrier(&self) -> &CausalEpochBarrier {
        &self.barrier
    }

    #[must_use]
    pub fn private_key_for_kernel(&self) -> &[u8; 32] {
        self.private_key.expose_for_kernel()
    }
}

/// Node-local state. This type intentionally does not implement Serialize.
#[derive(Clone)]
pub struct NodeKeyAuthority {
    schema_version: u16,
    cluster_id: String,
    node_name: String,
    node_uid: String,
    key_revision: Revision,
    next_epoch: u64,
    retired_through_epoch: u64,
    revoked_through_epoch: u64,
    epochs: Vec<LocalKeyEpoch>,
}

impl fmt::Debug for NodeKeyAuthority {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NodeKeyAuthority")
            .field("schema_version", &self.schema_version)
            .field("cluster_id", &self.cluster_id)
            .field("node_name", &self.node_name)
            .field("node_uid", &self.node_uid)
            .field("key_revision", &self.key_revision)
            .field("next_epoch", &self.next_epoch)
            .field("retired_through_epoch", &self.retired_through_epoch)
            .field("revoked_through_epoch", &self.revoked_through_epoch)
            .field("epochs", &self.epochs)
            .finish()
    }
}

impl NodeKeyAuthority {
    /// Creates an empty authority bound to one immutable Node identity.
    ///
    /// # Errors
    ///
    /// Rejects empty, control-containing, or oversized identity fields.
    pub fn new(
        cluster_id: String,
        node_name: String,
        node_uid: String,
    ) -> Result<Self, KeyAuthorityError> {
        validate_identity(&cluster_id, &node_name, &node_uid)?;
        Ok(Self {
            schema_version: NODE_KEY_AUTHORITY_SCHEMA_VERSION,
            cluster_id,
            node_name,
            node_uid,
            key_revision: Revision::INITIAL,
            next_epoch: 1,
            retired_through_epoch: 0,
            revoked_through_epoch: 0,
            epochs: Vec::new(),
        })
    }

    #[must_use]
    pub fn cluster_id(&self) -> &str {
        &self.cluster_id
    }

    #[must_use]
    pub fn node_name(&self) -> &str {
        &self.node_name
    }

    #[must_use]
    pub fn node_uid(&self) -> &str {
        &self.node_uid
    }

    #[must_use]
    pub const fn key_revision(&self) -> Revision {
        self.key_revision
    }

    #[must_use]
    pub fn epochs(&self) -> &[LocalKeyEpoch] {
        &self.epochs
    }

    /// Returns the draining epoch whose bounded drain window has elapsed.
    ///
    /// This is deliberately only a lifecycle query. The caller must still
    /// prove that packet, route, and kernel ownership are empty before issuing
    /// an [`EpochDrainProof`]. An idle Node can have a draining key with no
    /// transport plan, so retirement cannot depend solely on a WireGuard-plan
    /// journal entry.
    ///
    /// # Errors
    ///
    /// Rejects corrupt authority state or the zero wall-clock instant.
    pub fn drained_epoch_ready_for_retirement(
        &self,
        now_unix_ms: u64,
    ) -> Result<Option<u64>, KeyAuthorityError> {
        self.validate()?;
        if now_unix_ms == 0 {
            return Err(KeyAuthorityError::InvalidDrainProof);
        }
        Ok(self.epochs.iter().find_map(|epoch| {
            (epoch.phase == KeyEpochPhase::Draining
                && epoch
                    .drain_deadline_unix_ms
                    .is_some_and(|deadline| now_unix_ms >= deadline))
            .then_some(epoch.epoch)
        }))
    }

    /// Returns secret authority only to the in-crate Linux convergence
    /// orchestrator after the complete plan identity and public key match a
    /// locally ready epoch.
    pub(crate) fn private_key_for_kernel_plan(
        &self,
        plan: &crate::WireGuardKernelPlan,
    ) -> Result<&WireGuardPrivateKey, KeyAuthorityError> {
        self.validate()?;
        plan.verify()
            .map_err(|_| KeyAuthorityError::KernelPlanMismatch)?;
        let epoch = self
            .epochs
            .iter()
            .find(|candidate| candidate.epoch == plan.epoch)
            .ok_or(KeyAuthorityError::UnknownEpoch(plan.epoch))?;
        if self.cluster_id != plan.cluster_id
            || self.node_uid != plan.local_node_uid
            || epoch.public_key != plan.local_public_key
            || epoch.phase == KeyEpochPhase::Prepared
        {
            return Err(KeyAuthorityError::KernelPlanMismatch);
        }
        Ok(&epoch.private_key)
    }

    /// Generates and stages one epoch behind an exact causal peer barrier.
    ///
    /// # Errors
    ///
    /// Rejects invalid lifetimes/frontiers, capacity conflicts, entropy
    /// failure, duplicate keys, or invalid recovered state.
    pub fn prepare_epoch<G: WireGuardKeyGenerator>(
        &mut self,
        topology_revision: Revision,
        required_peer_uids: BTreeSet<String>,
        valid_from_unix_ms: u64,
        valid_until_unix_ms: u64,
        generator: &mut G,
    ) -> Result<u64, KeyAuthorityError> {
        self.validate()?;
        if self.epochs.len() >= 2
            || self.epochs.iter().any(|epoch| {
                matches!(
                    epoch.phase,
                    KeyEpochPhase::Prepared | KeyEpochPhase::MutuallyAttested
                )
            })
        {
            return Err(KeyAuthorityError::EpochCapacityOrTransition);
        }
        validate_lifetime(valid_from_unix_ms, valid_until_unix_ms)?;
        let private_key = generator.generate()?;
        let public_key = private_key.public_key();
        if self
            .epochs
            .iter()
            .any(|epoch| epoch.public_key == public_key)
        {
            return Err(KeyAuthorityError::DuplicatePublicKey);
        }
        let epoch = self.next_epoch;
        let barrier = CausalEpochBarrier::issue(
            self.node_uid.clone(),
            epoch,
            public_key,
            topology_revision,
            required_peer_uids,
            valid_until_unix_ms,
        )?;
        let immediately_ready = barrier.required_peer_uids.is_empty();
        let mut local = LocalKeyEpoch {
            epoch,
            public_key,
            private_key,
            valid_from_unix_ms,
            valid_until_unix_ms,
            phase: KeyEpochPhase::Prepared,
            barrier,
            acknowledgements: BTreeMap::new(),
            readiness: None,
            drain_deadline_unix_ms: None,
        };
        if immediately_ready {
            local.readiness = Some(issue_readiness_certificate(&local)?);
            local.phase = KeyEpochPhase::MutuallyAttested;
        }
        self.epochs.push(local);
        self.epochs.sort_by_key(|candidate| candidate.epoch);
        self.next_epoch = epoch
            .checked_add(1)
            .ok_or(KeyAuthorityError::EpochOverflow)?;
        self.bump_revision()?;
        self.validate()?;
        Ok(epoch)
    }

    /// Records an acknowledgement authenticated as the exact peer Node UID.
    ///
    /// Returns `false` for an exact idempotent replay.
    ///
    /// # Errors
    ///
    /// Rejects identity mismatch, mutation, expiry, unknown peers/epochs, or
    /// acknowledgements outside the sealed barrier.
    pub fn acknowledge_epoch(
        &mut self,
        authenticated_peer_node_uid: &str,
        acknowledgement: PeerEpochAcknowledgement,
        now_unix_ms: u64,
    ) -> Result<bool, KeyAuthorityError> {
        self.validate()?;
        if authenticated_peer_node_uid != acknowledgement.peer_node_uid {
            return Err(KeyAuthorityError::UnauthenticatedPeer);
        }
        let local = self
            .epochs
            .iter_mut()
            .find(|candidate| candidate.epoch == acknowledgement.epoch)
            .ok_or(KeyAuthorityError::UnknownEpoch(acknowledgement.epoch))?;
        if local.phase != KeyEpochPhase::Prepared {
            return Err(KeyAuthorityError::EpochCapacityOrTransition);
        }
        if acknowledgement.target_node_uid != self.node_uid
            || acknowledgement.barrier_digest != local.barrier.barrier_digest
            || acknowledgement.peer_public_epoch == 0
            || acknowledgement.observed_at_unix_ms == 0
            || acknowledgement.observed_at_unix_ms > now_unix_ms
            || now_unix_ms > local.barrier.valid_until_unix_ms
            || !local
                .barrier
                .required_peer_uids
                .contains(authenticated_peer_node_uid)
        {
            return Err(KeyAuthorityError::InvalidAcknowledgement);
        }
        if let Some(previous) = local.acknowledgements.get(authenticated_peer_node_uid) {
            if previous == &acknowledgement {
                return Ok(false);
            }
            return Err(KeyAuthorityError::AcknowledgementMutation);
        }
        local
            .acknowledgements
            .insert(authenticated_peer_node_uid.to_owned(), acknowledgement);
        if local.acknowledgements.len() == local.barrier.required_peer_uids.len() {
            local.readiness = Some(issue_readiness_certificate(local)?);
            local.phase = KeyEpochPhase::MutuallyAttested;
        }
        self.bump_revision()?;
        self.validate()?;
        Ok(true)
    }

    /// Activates a mutually attested epoch and places the prior epoch in drain.
    ///
    /// # Errors
    ///
    /// Rejects incomplete/stale barriers, invalid time, topology drift,
    /// excessive drain windows, or invalid recovered state.
    pub fn activate_epoch(
        &mut self,
        epoch: u64,
        current_topology_revision: Revision,
        now_unix_ms: u64,
        drain_window_ms: u64,
    ) -> Result<(), KeyAuthorityError> {
        self.validate()?;
        if drain_window_ms == 0 || drain_window_ms > MAX_EPOCH_DRAIN_MS {
            return Err(KeyAuthorityError::InvalidDrainWindow);
        }
        let position = self
            .epochs
            .iter()
            .position(|candidate| candidate.epoch == epoch)
            .ok_or(KeyAuthorityError::UnknownEpoch(epoch))?;
        let prepared = &self.epochs[position];
        if prepared.phase != KeyEpochPhase::MutuallyAttested
            || prepared.barrier.topology_revision != current_topology_revision
            || now_unix_ms < prepared.valid_from_unix_ms
            || now_unix_ms >= prepared.valid_until_unix_ms
            || prepared.readiness.is_none()
        {
            return Err(KeyAuthorityError::ActivationBarrierNotSatisfied);
        }
        let drain_deadline = now_unix_ms
            .checked_add(drain_window_ms)
            .ok_or(KeyAuthorityError::InvalidDrainWindow)?;
        for (index, candidate) in self.epochs.iter_mut().enumerate() {
            if candidate.phase == KeyEpochPhase::Active {
                if index == position || drain_deadline > candidate.valid_until_unix_ms {
                    return Err(KeyAuthorityError::InvalidDrainWindow);
                }
                candidate.phase = KeyEpochPhase::Draining;
                candidate.drain_deadline_unix_ms = Some(drain_deadline);
            }
        }
        self.epochs[position].phase = KeyEpochPhase::Active;
        self.bump_revision()?;
        self.validate()?;
        Ok(())
    }

    /// Retires and zeroizes a draining epoch after positive zero-state proof.
    ///
    /// # Errors
    ///
    /// Rejects forged, stale, nonempty, wrong-Node, or wrong-phase proof.
    pub fn retire_drained_epoch(
        &mut self,
        proof: &EpochDrainProof,
        now_unix_ms: u64,
    ) -> Result<(), KeyAuthorityError> {
        self.validate()?;
        proof.verify()?;
        if proof.node_uid != self.node_uid
            || proof.observed_at_unix_ms > now_unix_ms
            || proof.established_flow_count != 0
            || proof.owned_route_count != 0
        {
            return Err(KeyAuthorityError::InvalidDrainProof);
        }
        let position = self
            .epochs
            .iter()
            .position(|candidate| candidate.epoch == proof.epoch)
            .ok_or(KeyAuthorityError::UnknownEpoch(proof.epoch))?;
        if self.epochs[position].phase != KeyEpochPhase::Draining
            || self
                .epochs
                .iter()
                .all(|candidate| candidate.phase != KeyEpochPhase::Active)
        {
            return Err(KeyAuthorityError::EpochCapacityOrTransition);
        }
        self.epochs.remove(position);
        self.retired_through_epoch = self.retired_through_epoch.max(proof.epoch);
        self.bump_revision()?;
        self.validate()?;
        Ok(())
    }

    /// Emergency-fences all key material through an issued epoch.
    ///
    /// # Errors
    ///
    /// Rejects unknown/future epochs, invalid time, or corrupted state.
    pub fn revoke_through(
        &mut self,
        epoch: u64,
        reason: EpochRevocationReason,
        now_unix_ms: u64,
    ) -> Result<EpochRevocationReceipt, KeyAuthorityError> {
        self.validate()?;
        if epoch == 0 || epoch >= self.next_epoch || now_unix_ms == 0 {
            return Err(KeyAuthorityError::UnknownEpoch(epoch));
        }
        self.epochs.retain(|candidate| candidate.epoch > epoch);
        self.revoked_through_epoch = self.revoked_through_epoch.max(epoch);
        self.bump_revision()?;
        self.validate()?;
        EpochRevocationReceipt::issue(
            self.node_uid.clone(),
            epoch,
            reason,
            now_unix_ms,
            self.key_revision,
        )
    }

    /// Builds the public-only authenticated publication payload.
    ///
    /// # Errors
    ///
    /// Rejects invalid local state or canonical encoding failure.
    pub fn publication(&self) -> Result<NodeKeyPublication, KeyAuthorityError> {
        self.validate()?;
        let epochs = self
            .epochs
            .iter()
            .map(|epoch| {
                Ok(KeyEpochPublication {
                    epoch: epoch.epoch,
                    public_key: epoch.public_key,
                    phase: epoch.phase,
                    valid_from_unix_ms: epoch.valid_from_unix_ms,
                    valid_until_unix_ms: epoch.valid_until_unix_ms,
                    topology_revision: epoch.barrier.topology_revision,
                    barrier_digest: epoch.barrier.barrier_digest,
                    required_peer_count: u32::try_from(epoch.barrier.required_peer_uids.len())
                        .map_err(|_| KeyAuthorityError::InvalidDurableState)?,
                    acknowledged_peer_count: u32::try_from(epoch.acknowledgements.len())
                        .map_err(|_| KeyAuthorityError::InvalidDurableState)?,
                    readiness_digest: epoch
                        .readiness
                        .as_ref()
                        .map(|readiness| readiness.readiness_digest),
                    drain_deadline_unix_ms: epoch.drain_deadline_unix_ms,
                })
            })
            .collect::<Result<Vec<_>, KeyAuthorityError>>()?;
        NodeKeyPublication::issue(NodeKeyPublicationFields {
            cluster_id: self.cluster_id.clone(),
            node_name: self.node_name.clone(),
            node_uid: self.node_uid.clone(),
            key_revision: self.key_revision,
            next_epoch: self.next_epoch,
            retired_through_epoch: self.retired_through_epoch,
            revoked_through_epoch: self.revoked_through_epoch,
            epochs,
        })
    }

    fn bump_revision(&mut self) -> Result<(), KeyAuthorityError> {
        let next = self.key_revision.next();
        if next == self.key_revision {
            return Err(KeyAuthorityError::RevisionOverflow);
        }
        self.key_revision = next;
        Ok(())
    }

    fn validate(&self) -> Result<(), KeyAuthorityError> {
        if self.schema_version != NODE_KEY_AUTHORITY_SCHEMA_VERSION {
            return Err(KeyAuthorityError::UnsupportedSchema(self.schema_version));
        }
        validate_identity(&self.cluster_id, &self.node_name, &self.node_uid)?;
        if self.next_epoch == 0
            || self.epochs.len() > 2
            || self.retired_through_epoch >= self.next_epoch
            || self.revoked_through_epoch >= self.next_epoch
        {
            return Err(KeyAuthorityError::InvalidDurableState);
        }
        let mut phases = BTreeMap::<KeyEpochPhase, usize>::new();
        let mut prior_epoch = 0;
        let mut public_keys = BTreeSet::new();
        for epoch in &self.epochs {
            if epoch.epoch <= prior_epoch
                || epoch.epoch >= self.next_epoch
                || epoch.epoch <= self.retired_through_epoch
                || epoch.epoch <= self.revoked_through_epoch
                || !public_keys.insert(epoch.public_key)
                || epoch.private_key.public_key() != epoch.public_key
            {
                return Err(KeyAuthorityError::InvalidDurableState);
            }
            validate_lifetime(epoch.valid_from_unix_ms, epoch.valid_until_unix_ms)?;
            epoch.barrier.verify()?;
            if epoch.barrier.target_node_uid != self.node_uid
                || epoch.barrier.epoch != epoch.epoch
                || epoch.barrier.public_key_digest != public_key_digest(epoch.public_key)
                || epoch.barrier.valid_until_unix_ms != epoch.valid_until_unix_ms
                || epoch
                    .acknowledgements
                    .iter()
                    .any(|(peer, acknowledgement)| {
                        !epoch.barrier.required_peer_uids.contains(peer)
                            || acknowledgement.peer_node_uid != *peer
                            || acknowledgement.target_node_uid != self.node_uid
                            || acknowledgement.epoch != epoch.epoch
                            || acknowledgement.barrier_digest != epoch.barrier.barrier_digest
                            || acknowledgement.peer_public_epoch == 0
                            || acknowledgement.observed_at_unix_ms == 0
                            || acknowledgement.observed_at_unix_ms
                                > epoch.barrier.valid_until_unix_ms
                    })
            {
                return Err(KeyAuthorityError::InvalidDurableState);
            }
            let acknowledgement_complete =
                epoch.acknowledgements.len() == epoch.barrier.required_peer_uids.len();
            match epoch.phase {
                KeyEpochPhase::Prepared => {
                    if acknowledgement_complete || epoch.readiness.is_some() {
                        return Err(KeyAuthorityError::InvalidDurableState);
                    }
                }
                KeyEpochPhase::MutuallyAttested
                | KeyEpochPhase::Active
                | KeyEpochPhase::Draining => {
                    if !acknowledgement_complete
                        || epoch.readiness.as_ref() != Some(&issue_readiness_certificate(epoch)?)
                    {
                        return Err(KeyAuthorityError::InvalidDurableState);
                    }
                }
            }
            if (epoch.phase == KeyEpochPhase::Draining) != epoch.drain_deadline_unix_ms.is_some() {
                return Err(KeyAuthorityError::InvalidDurableState);
            }
            *phases.entry(epoch.phase).or_default() += 1;
            prior_epoch = epoch.epoch;
        }
        if phases.values().any(|count| *count > 1)
            || phases
                .get(&KeyEpochPhase::Prepared)
                .copied()
                .unwrap_or_default()
                + phases
                    .get(&KeyEpochPhase::MutuallyAttested)
                    .copied()
                    .unwrap_or_default()
                > 1
            || phases
                .get(&KeyEpochPhase::Draining)
                .copied()
                .unwrap_or_default()
                > 0
                && phases
                    .get(&KeyEpochPhase::Active)
                    .copied()
                    .unwrap_or_default()
                    != 1
        {
            return Err(KeyAuthorityError::InvalidDurableState);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct KeyEpochPublication {
    pub epoch: u64,
    pub public_key: WireGuardPublicKey,
    pub phase: KeyEpochPhase,
    pub valid_from_unix_ms: u64,
    pub valid_until_unix_ms: u64,
    pub topology_revision: Revision,
    pub barrier_digest: CausalEpochBarrierDigest,
    pub required_peer_count: u32,
    pub acknowledged_peer_count: u32,
    pub readiness_digest: Option<EpochReadinessDigest>,
    pub drain_deadline_unix_ms: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct NodeKeyPublication {
    pub schema_version: u16,
    pub cluster_id: String,
    pub node_name: String,
    pub node_uid: String,
    pub key_revision: Revision,
    pub next_epoch: u64,
    pub retired_through_epoch: u64,
    pub revoked_through_epoch: u64,
    pub epochs: Vec<KeyEpochPublication>,
    pub publication_digest: NodeKeyPublicationDigest,
}

struct NodeKeyPublicationFields {
    cluster_id: String,
    node_name: String,
    node_uid: String,
    key_revision: Revision,
    next_epoch: u64,
    retired_through_epoch: u64,
    revoked_through_epoch: u64,
    epochs: Vec<KeyEpochPublication>,
}

impl NodeKeyPublication {
    fn issue(fields: NodeKeyPublicationFields) -> Result<Self, KeyAuthorityError> {
        let mut publication = Self {
            schema_version: NODE_KEY_PUBLICATION_SCHEMA_VERSION,
            cluster_id: fields.cluster_id,
            node_name: fields.node_name,
            node_uid: fields.node_uid,
            key_revision: fields.key_revision,
            next_epoch: fields.next_epoch,
            retired_through_epoch: fields.retired_through_epoch,
            revoked_through_epoch: fields.revoked_through_epoch,
            epochs: fields.epochs,
            publication_digest: NodeKeyPublicationDigest([0; 32]),
        };
        publication.publication_digest = publication.calculate_digest()?;
        Ok(publication)
    }

    /// Verifies public-only schema, monotonic shape, and digest integrity.
    ///
    /// # Errors
    ///
    /// Rejects malformed, noncanonical, or digest-mismatched publications.
    pub fn verify(&self) -> Result<(), KeyAuthorityError> {
        validate_identity(&self.cluster_id, &self.node_name, &self.node_uid)?;
        let public_keys = self
            .epochs
            .iter()
            .map(|epoch| epoch.public_key)
            .collect::<BTreeSet<_>>();
        let mut phases = BTreeMap::<KeyEpochPhase, usize>::new();
        for epoch in &self.epochs {
            *phases.entry(epoch.phase).or_default() += 1;
        }
        if self.schema_version != NODE_KEY_PUBLICATION_SCHEMA_VERSION
            || self.next_epoch == 0
            || self.epochs.len() > 2
            || public_keys.len() != self.epochs.len()
            || self.retired_through_epoch >= self.next_epoch
            || self.revoked_through_epoch >= self.next_epoch
            || self
                .epochs
                .windows(2)
                .any(|pair| pair[0].epoch >= pair[1].epoch)
            || self.epochs.iter().any(|epoch| {
                epoch.epoch == 0
                    || epoch.epoch >= self.next_epoch
                    || epoch.epoch <= self.retired_through_epoch
                    || epoch.epoch <= self.revoked_through_epoch
                    || epoch.public_key.0 == [0; 32]
                    || epoch.valid_from_unix_ms >= epoch.valid_until_unix_ms
                    || epoch
                        .valid_until_unix_ms
                        .saturating_sub(epoch.valid_from_unix_ms)
                        > MAX_KEY_LIFETIME_MS
                    || epoch.required_peer_count as usize > MAX_ROTATION_PEERS
                    || epoch.required_peer_count < epoch.acknowledged_peer_count
                    || epoch.phase == KeyEpochPhase::Prepared
                        && (epoch.required_peer_count == epoch.acknowledged_peer_count
                            || epoch.readiness_digest.is_some())
                    || matches!(
                        epoch.phase,
                        KeyEpochPhase::MutuallyAttested
                            | KeyEpochPhase::Active
                            | KeyEpochPhase::Draining
                    ) && (epoch.required_peer_count != epoch.acknowledged_peer_count
                        || epoch.readiness_digest.is_none())
                    || (epoch.phase == KeyEpochPhase::Draining)
                        != epoch.drain_deadline_unix_ms.is_some()
            })
            || phases.values().any(|count| *count > 1)
            || phases
                .get(&KeyEpochPhase::Prepared)
                .copied()
                .unwrap_or_default()
                + phases
                    .get(&KeyEpochPhase::MutuallyAttested)
                    .copied()
                    .unwrap_or_default()
                > 1
            || phases
                .get(&KeyEpochPhase::Draining)
                .copied()
                .unwrap_or_default()
                > 0
                && phases
                    .get(&KeyEpochPhase::Active)
                    .copied()
                    .unwrap_or_default()
                    != 1
            || self.publication_digest != self.calculate_digest()?
        {
            return Err(KeyAuthorityError::InvalidPublication);
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Result<NodeKeyPublicationDigest, KeyAuthorityError> {
        let mut canonical = self.clone();
        canonical.publication_digest = NodeKeyPublicationDigest([0; 32]);
        hash_canonical(PUBLICATION_DIGEST_DOMAIN, &canonical).map(NodeKeyPublicationDigest)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedNodeIdentity {
    pub cluster_id: String,
    pub node_name: String,
    pub node_uid: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublicationAdmission {
    Accepted,
    Idempotent,
}

/// Admits a public-key update only under its authenticated Node identity.
///
/// # Errors
///
/// Rejects unauthenticated identity, Node replacement without an explicit
/// fence, revision replay/mutation, epoch regression, or invalid publication.
pub fn admit_authenticated_publication(
    authenticated: &AuthenticatedNodeIdentity,
    publication: &NodeKeyPublication,
    previous: Option<&NodeKeyPublication>,
) -> Result<PublicationAdmission, KeyAuthorityError> {
    publication.verify()?;
    if authenticated.cluster_id != publication.cluster_id
        || authenticated.node_name != publication.node_name
        || authenticated.node_uid != publication.node_uid
    {
        return Err(KeyAuthorityError::UnauthenticatedPublication);
    }
    let Some(previous) = previous else {
        return Ok(PublicationAdmission::Accepted);
    };
    previous.verify()?;
    if previous.cluster_id != publication.cluster_id
        || previous.node_name != publication.node_name
        || previous.node_uid != publication.node_uid
    {
        return Err(KeyAuthorityError::NodeReplacementRequiresFence);
    }
    if publication.key_revision < previous.key_revision {
        return Err(KeyAuthorityError::PublicationReplay);
    }
    if publication.key_revision == previous.key_revision {
        return if publication == previous {
            Ok(PublicationAdmission::Idempotent)
        } else {
            Err(KeyAuthorityError::PublicationMutation)
        };
    }
    if publication.next_epoch < previous.next_epoch
        || publication.retired_through_epoch < previous.retired_through_epoch
        || publication.revoked_through_epoch < previous.revoked_through_epoch
        || previous.epochs.iter().any(|old| {
            match publication.epochs.iter().find(|new| new.epoch == old.epoch) {
                Some(new) => new.public_key != old.public_key || new.phase < old.phase,
                None => {
                    old.epoch > publication.retired_through_epoch
                        && old.epoch > publication.revoked_through_epoch
                }
            }
        })
    {
        return Err(KeyAuthorityError::PublicationRegression);
    }
    Ok(PublicationAdmission::Accepted)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EpochDrainProof {
    pub node_uid: String,
    pub epoch: u64,
    pub observation_revision: Revision,
    pub observed_at_unix_ms: u64,
    pub established_flow_count: u64,
    pub owned_route_count: u32,
    pub proof_digest: EpochDrainProofDigest,
}

impl EpochDrainProof {
    /// Issues a digest-bound observation of remaining flow and route state.
    ///
    /// # Errors
    ///
    /// Rejects invalid Node identity, epoch, revision, time, or encoding.
    pub fn issue(
        node_uid: String,
        epoch: u64,
        observation_revision: Revision,
        observed_at_unix_ms: u64,
        established_flow_count: u64,
        owned_route_count: u32,
    ) -> Result<Self, KeyAuthorityError> {
        if !validate_text(&node_uid)
            || epoch == 0
            || observation_revision == Revision::INITIAL
            || observed_at_unix_ms == 0
        {
            return Err(KeyAuthorityError::InvalidDrainProof);
        }
        let mut proof = Self {
            node_uid,
            epoch,
            observation_revision,
            observed_at_unix_ms,
            established_flow_count,
            owned_route_count,
            proof_digest: EpochDrainProofDigest([0; 32]),
        };
        proof.proof_digest = proof.calculate_digest()?;
        Ok(proof)
    }

    /// Independently verifies the drain-proof digest and shape.
    ///
    /// # Errors
    ///
    /// Rejects malformed or digest-mismatched proof.
    pub fn verify(&self) -> Result<(), KeyAuthorityError> {
        if !validate_text(&self.node_uid)
            || self.epoch == 0
            || self.observation_revision == Revision::INITIAL
            || self.observed_at_unix_ms == 0
            || self.proof_digest != self.calculate_digest()?
        {
            return Err(KeyAuthorityError::InvalidDrainProof);
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Result<EpochDrainProofDigest, KeyAuthorityError> {
        let mut canonical = self.clone();
        canonical.proof_digest = EpochDrainProofDigest([0; 32]);
        hash_canonical(DRAIN_PROOF_DIGEST_DOMAIN, &canonical).map(EpochDrainProofDigest)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum EpochRevocationReason {
    SuspectedCompromise,
    NodeReplacement,
    OperatorEmergency,
    /// A key expired before it ever gained mutually attested packet authority.
    ExpiredBeforeActivation,
    /// A peer advanced the public fleet frontier before this local key became
    /// active, so the unpublished transition is causally obsolete.
    FleetEpochSuperseded,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EpochRevocationReceipt {
    pub node_uid: String,
    pub revoked_through_epoch: u64,
    pub reason: EpochRevocationReason,
    pub revoked_at_unix_ms: u64,
    pub key_revision: Revision,
    pub receipt_digest: EpochRevocationDigest,
}

impl EpochRevocationReceipt {
    fn issue(
        node_uid: String,
        revoked_through_epoch: u64,
        reason: EpochRevocationReason,
        revoked_at_unix_ms: u64,
        key_revision: Revision,
    ) -> Result<Self, KeyAuthorityError> {
        let mut receipt = Self {
            node_uid,
            revoked_through_epoch,
            reason,
            revoked_at_unix_ms,
            key_revision,
            receipt_digest: EpochRevocationDigest([0; 32]),
        };
        receipt.receipt_digest = receipt.calculate_digest()?;
        Ok(receipt)
    }

    /// Verifies the public emergency-revocation receipt.
    ///
    /// # Errors
    ///
    /// Rejects malformed identity, epoch, revision, time, or digest.
    pub fn verify(&self) -> Result<(), KeyAuthorityError> {
        if !validate_text(&self.node_uid)
            || self.revoked_through_epoch == 0
            || self.revoked_at_unix_ms == 0
            || self.key_revision == Revision::INITIAL
            || self.receipt_digest != self.calculate_digest()?
        {
            return Err(KeyAuthorityError::InvalidRevocationReceipt);
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Result<EpochRevocationDigest, KeyAuthorityError> {
        let mut canonical = self.clone();
        canonical.receipt_digest = EpochRevocationDigest([0; 32]);
        hash_canonical(REVOCATION_DIGEST_DOMAIN, &canonical).map(EpochRevocationDigest)
    }
}

pub trait NodeKeyStateStore {
    /// Atomically persists the complete local authority before it is published.
    ///
    /// # Errors
    ///
    /// Returns an error without committing the in-memory candidate.
    fn persist(&self, authority: &NodeKeyAuthority) -> Result<(), KeyAuthorityError>;
}

#[derive(Debug, Clone)]
pub struct FileNodeKeyStateStore {
    path: PathBuf,
}

impl FileNodeKeyStateStore {
    #[must_use]
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    /// Restores an owner-only checkpoint for the exact immutable Node UID.
    ///
    /// # Errors
    ///
    /// Rejects unsafe files/directories, schema or digest corruption, identity
    /// replacement, invalid private/public pairs, or I/O failure.
    pub fn restore(
        &self,
        expected_cluster_id: &str,
        expected_node_name: &str,
        expected_node_uid: &str,
    ) -> Result<NodeKeyAuthority, KeyAuthorityError> {
        validate_storage_path(&self.path, true)?;
        let bytes = Zeroizing::new(fs::read(&self.path)?);
        let document: PersistedAuthorityDocument = serde_json::from_slice(&bytes)?;
        document.into_authority(expected_cluster_id, expected_node_name, expected_node_uid)
    }
}

impl NodeKeyStateStore for FileNodeKeyStateStore {
    fn persist(&self, authority: &NodeKeyAuthority) -> Result<(), KeyAuthorityError> {
        authority.validate()?;
        validate_storage_path(&self.path, false)?;
        let parent = self
            .path
            .parent()
            .ok_or(KeyAuthorityError::UnsafeStoragePath)?;
        let temporary = temporary_path(&self.path)?;
        if temporary.exists() {
            return Err(KeyAuthorityError::UnsafeStoragePath);
        }
        let document = PersistedAuthorityDocument::from_authority(authority)?;
        let mut bytes = Zeroizing::new(serde_json::to_vec(&document)?);
        bytes.push(b'\n');
        let result = (|| -> Result<(), KeyAuthorityError> {
            let mut output = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(KEY_FILE_MODE)
                .open(&temporary)?;
            output.write_all(&bytes)?;
            output.sync_all()?;
            fs::rename(&temporary, &self.path)?;
            File::open(parent)?.sync_all()?;
            validate_storage_path(&self.path, true)?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result
    }
}

pub struct DurableNodeKeyAuthority<S, G> {
    authority: NodeKeyAuthority,
    store: S,
    generator: G,
}

impl<S: NodeKeyStateStore, G: WireGuardKeyGenerator> DurableNodeKeyAuthority<S, G> {
    /// Persists an initial empty authority before exposing it to callers.
    ///
    /// # Errors
    ///
    /// Returns the storage or state-validation failure without creating a live
    /// durable authority.
    pub fn create(
        authority: NodeKeyAuthority,
        store: S,
        generator: G,
    ) -> Result<Self, KeyAuthorityError> {
        store.persist(&authority)?;
        Ok(Self {
            authority,
            store,
            generator,
        })
    }

    #[must_use]
    pub const fn authority(&self) -> &NodeKeyAuthority {
        &self.authority
    }

    /// Durably prepares a key epoch before committing it in memory.
    ///
    /// # Errors
    ///
    /// Returns generation, validation, capacity, or persistence failure.
    pub fn prepare_epoch(
        &mut self,
        topology_revision: Revision,
        required_peer_uids: BTreeSet<String>,
        valid_from_unix_ms: u64,
        valid_until_unix_ms: u64,
    ) -> Result<u64, KeyAuthorityError> {
        let mut candidate = self.authority.clone();
        let epoch = candidate.prepare_epoch(
            topology_revision,
            required_peer_uids,
            valid_from_unix_ms,
            valid_until_unix_ms,
            &mut self.generator,
        )?;
        self.commit(candidate)?;
        Ok(epoch)
    }

    /// Durably records one authenticated peer acknowledgement.
    ///
    /// # Errors
    ///
    /// Returns authentication, barrier, state, or persistence failure.
    pub fn acknowledge_epoch(
        &mut self,
        authenticated_peer_node_uid: &str,
        acknowledgement: PeerEpochAcknowledgement,
        now_unix_ms: u64,
    ) -> Result<bool, KeyAuthorityError> {
        let mut candidate = self.authority.clone();
        let changed = candidate.acknowledge_epoch(
            authenticated_peer_node_uid,
            acknowledgement,
            now_unix_ms,
        )?;
        if changed {
            self.commit(candidate)?;
        }
        Ok(changed)
    }

    /// Durably activates an epoch and begins prior-epoch draining.
    ///
    /// # Errors
    ///
    /// Returns barrier, topology, time, state, or persistence failure.
    pub fn activate_epoch(
        &mut self,
        epoch: u64,
        current_topology_revision: Revision,
        now_unix_ms: u64,
        drain_window_ms: u64,
    ) -> Result<(), KeyAuthorityError> {
        let mut candidate = self.authority.clone();
        candidate.activate_epoch(
            epoch,
            current_topology_revision,
            now_unix_ms,
            drain_window_ms,
        )?;
        self.commit(candidate)
    }

    /// Durably retires an epoch after exact zero-state proof.
    ///
    /// # Errors
    ///
    /// Returns proof, state, or persistence failure.
    pub fn retire_drained_epoch(
        &mut self,
        proof: &EpochDrainProof,
        now_unix_ms: u64,
    ) -> Result<(), KeyAuthorityError> {
        let mut candidate = self.authority.clone();
        candidate.retire_drained_epoch(proof, now_unix_ms)?;
        self.commit(candidate)
    }

    /// Durably emergency-revokes and zeroizes issued epochs.
    ///
    /// # Errors
    ///
    /// Returns epoch, state, receipt-encoding, or persistence failure.
    pub fn revoke_through(
        &mut self,
        epoch: u64,
        reason: EpochRevocationReason,
        now_unix_ms: u64,
    ) -> Result<EpochRevocationReceipt, KeyAuthorityError> {
        let mut candidate = self.authority.clone();
        let receipt = candidate.revoke_through(epoch, reason, now_unix_ms)?;
        self.commit(candidate)?;
        Ok(receipt)
    }

    fn commit(&mut self, candidate: NodeKeyAuthority) -> Result<(), KeyAuthorityError> {
        self.store.persist(&candidate)?;
        self.authority = candidate;
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct PersistedAuthorityDocument {
    schema_version: u16,
    cluster_id: String,
    node_name: String,
    node_uid: String,
    key_revision: Revision,
    next_epoch: u64,
    retired_through_epoch: u64,
    revoked_through_epoch: u64,
    epochs: Vec<PersistedLocalKeyEpoch>,
    checkpoint_digest: [u8; 32],
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct PersistedLocalKeyEpoch {
    epoch: u64,
    public_key: WireGuardPublicKey,
    private_key: Zeroizing<[u8; 32]>,
    valid_from_unix_ms: u64,
    valid_until_unix_ms: u64,
    phase: KeyEpochPhase,
    barrier: CausalEpochBarrier,
    acknowledgements: BTreeMap<String, PeerEpochAcknowledgement>,
    readiness: Option<EpochReadinessCertificate>,
    drain_deadline_unix_ms: Option<u64>,
}

impl PersistedAuthorityDocument {
    fn from_authority(authority: &NodeKeyAuthority) -> Result<Self, KeyAuthorityError> {
        let mut document = Self {
            schema_version: authority.schema_version,
            cluster_id: authority.cluster_id.clone(),
            node_name: authority.node_name.clone(),
            node_uid: authority.node_uid.clone(),
            key_revision: authority.key_revision,
            next_epoch: authority.next_epoch,
            retired_through_epoch: authority.retired_through_epoch,
            revoked_through_epoch: authority.revoked_through_epoch,
            epochs: authority
                .epochs
                .iter()
                .map(|epoch| PersistedLocalKeyEpoch {
                    epoch: epoch.epoch,
                    public_key: epoch.public_key,
                    private_key: epoch.private_key.clone_bytes(),
                    valid_from_unix_ms: epoch.valid_from_unix_ms,
                    valid_until_unix_ms: epoch.valid_until_unix_ms,
                    phase: epoch.phase,
                    barrier: epoch.barrier.clone(),
                    acknowledgements: epoch.acknowledgements.clone(),
                    readiness: epoch.readiness.clone(),
                    drain_deadline_unix_ms: epoch.drain_deadline_unix_ms,
                })
                .collect(),
            checkpoint_digest: [0; 32],
        };
        document.checkpoint_digest = document.calculate_digest()?;
        Ok(document)
    }

    fn into_authority(
        mut self,
        expected_cluster_id: &str,
        expected_node_name: &str,
        expected_node_uid: &str,
    ) -> Result<NodeKeyAuthority, KeyAuthorityError> {
        if self.schema_version != NODE_KEY_AUTHORITY_SCHEMA_VERSION {
            return Err(KeyAuthorityError::UnsupportedSchema(self.schema_version));
        }
        let expected_digest = self.calculate_digest()?;
        if self.checkpoint_digest != expected_digest {
            return Err(KeyAuthorityError::CheckpointDigestMismatch);
        }
        if self.cluster_id != expected_cluster_id
            || self.node_name != expected_node_name
            || self.node_uid != expected_node_uid
        {
            return Err(KeyAuthorityError::NodeReplacementRequiresFence);
        }
        let epochs = self
            .epochs
            .drain(..)
            .map(|epoch| {
                Ok(LocalKeyEpoch {
                    epoch: epoch.epoch,
                    public_key: epoch.public_key,
                    private_key: WireGuardPrivateKey::from_zeroizing(epoch.private_key)?,
                    valid_from_unix_ms: epoch.valid_from_unix_ms,
                    valid_until_unix_ms: epoch.valid_until_unix_ms,
                    phase: epoch.phase,
                    barrier: epoch.barrier,
                    acknowledgements: epoch.acknowledgements,
                    readiness: epoch.readiness,
                    drain_deadline_unix_ms: epoch.drain_deadline_unix_ms,
                })
            })
            .collect::<Result<Vec<_>, KeyAuthorityError>>()?;
        let authority = NodeKeyAuthority {
            schema_version: self.schema_version,
            cluster_id: self.cluster_id,
            node_name: self.node_name,
            node_uid: self.node_uid,
            key_revision: self.key_revision,
            next_epoch: self.next_epoch,
            retired_through_epoch: self.retired_through_epoch,
            revoked_through_epoch: self.revoked_through_epoch,
            epochs,
        };
        authority.validate()?;
        Ok(authority)
    }

    fn calculate_digest(&self) -> Result<[u8; 32], KeyAuthorityError> {
        let canonical = PersistedAuthorityDocumentDigestView {
            schema_version: self.schema_version,
            cluster_id: &self.cluster_id,
            node_name: &self.node_name,
            node_uid: &self.node_uid,
            key_revision: self.key_revision,
            next_epoch: self.next_epoch,
            retired_through_epoch: self.retired_through_epoch,
            revoked_through_epoch: self.revoked_through_epoch,
            epochs: &self.epochs,
        };
        hash_canonical(CHECKPOINT_DIGEST_DOMAIN, &canonical)
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PersistedAuthorityDocumentDigestView<'a> {
    schema_version: u16,
    cluster_id: &'a str,
    node_name: &'a str,
    node_uid: &'a str,
    key_revision: Revision,
    next_epoch: u64,
    retired_through_epoch: u64,
    revoked_through_epoch: u64,
    epochs: &'a [PersistedLocalKeyEpoch],
}

#[derive(Debug, Error)]
pub enum KeyAuthorityError {
    #[error("unsupported Node key-authority schema {0}")]
    UnsupportedSchema(u16),
    #[error("invalid bounded Node key-authority identity")]
    InvalidIdentity,
    #[error("OS cryptographic entropy is unavailable: {0}")]
    EntropyUnavailable(String),
    #[error("WireGuard private key is invalid")]
    InvalidPrivateKey,
    #[error("kernel plan does not match a locally ready Node key epoch")]
    KernelPlanMismatch,
    #[error("generated public key duplicates a live epoch")]
    DuplicatePublicKey,
    #[error("key lifetime is invalid or exceeds the configured bound")]
    InvalidLifetime,
    #[error("epoch capacity or transition precondition is not satisfied")]
    EpochCapacityOrTransition,
    #[error("key epoch counter overflow")]
    EpochOverflow,
    #[error("key revision counter overflow")]
    RevisionOverflow,
    #[error("unknown key epoch {0}")]
    UnknownEpoch(u64),
    #[error("causal epoch barrier is malformed")]
    InvalidBarrier,
    #[error("causal epoch barrier digest does not match")]
    BarrierDigestMismatch,
    #[error("peer acknowledgement is not authenticated as its Node UID")]
    UnauthenticatedPeer,
    #[error("peer epoch acknowledgement is invalid, stale, or outside the barrier")]
    InvalidAcknowledgement,
    #[error("same peer mutated an acknowledgement at one epoch")]
    AcknowledgementMutation,
    #[error("the complete causal epoch barrier is not satisfied")]
    ActivationBarrierNotSatisfied,
    #[error("epoch drain window is invalid")]
    InvalidDrainWindow,
    #[error("epoch drain proof is invalid or does not prove zero owned state")]
    InvalidDrainProof,
    #[error("epoch revocation receipt is invalid")]
    InvalidRevocationReceipt,
    #[error("durable Node key-authority state is invalid")]
    InvalidDurableState,
    #[error("Node key publication is invalid")]
    InvalidPublication,
    #[error("publication does not match the authenticated Node identity")]
    UnauthenticatedPublication,
    #[error("Node replacement must be explicitly fenced before key admission")]
    NodeReplacementRequiresFence,
    #[error("Node key publication revision replay")]
    PublicationReplay,
    #[error("Node key publication mutated at one revision")]
    PublicationMutation,
    #[error("Node key publication regressed epoch authority")]
    PublicationRegression,
    #[error("Node-local key storage path is not an owner-only regular path")]
    UnsafeStoragePath,
    #[error("Node-local key checkpoint digest does not match")]
    CheckpointDigestMismatch,
    #[error("canonical key-authority encoding failed: {0}")]
    CanonicalEncoding(String),
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

fn issue_readiness_certificate(
    epoch: &LocalKeyEpoch,
) -> Result<EpochReadinessCertificate, KeyAuthorityError> {
    let acknowledged_peer_uids = epoch.acknowledgements.keys().cloned().collect::<Vec<_>>();
    if acknowledged_peer_uids
        != epoch
            .barrier
            .required_peer_uids
            .iter()
            .cloned()
            .collect::<Vec<_>>()
    {
        return Err(KeyAuthorityError::ActivationBarrierNotSatisfied);
    }
    let canonical = (
        epoch.barrier.barrier_digest,
        &acknowledged_peer_uids,
        &epoch.acknowledgements,
    );
    let readiness_digest =
        hash_canonical(READINESS_DIGEST_DOMAIN, &canonical).map(EpochReadinessDigest)?;
    Ok(EpochReadinessCertificate {
        barrier_digest: epoch.barrier.barrier_digest,
        acknowledged_peer_uids,
        readiness_digest,
    })
}

fn validate_identity(
    cluster_id: &str,
    node_name: &str,
    node_uid: &str,
) -> Result<(), KeyAuthorityError> {
    if [cluster_id, node_name, node_uid]
        .into_iter()
        .all(validate_text)
    {
        Ok(())
    } else {
        Err(KeyAuthorityError::InvalidIdentity)
    }
}

fn validate_peer_frontier(
    target_node_uid: &str,
    peers: &BTreeSet<String>,
) -> Result<(), KeyAuthorityError> {
    if peers.len() > MAX_ROTATION_PEERS
        || peers
            .iter()
            .any(|peer| !validate_text(peer) || peer == target_node_uid)
    {
        return Err(KeyAuthorityError::InvalidBarrier);
    }
    Ok(())
}

fn validate_lifetime(from: u64, until: u64) -> Result<(), KeyAuthorityError> {
    if from == 0 || from >= until || until.saturating_sub(from) > MAX_KEY_LIFETIME_MS {
        Err(KeyAuthorityError::InvalidLifetime)
    } else {
        Ok(())
    }
}

fn validate_text(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_KEY_AUTHORITY_TEXT_BYTES
        && !value.chars().any(char::is_control)
}

fn hash_canonical<T: Serialize>(domain: &[u8], value: &T) -> Result<[u8; 32], KeyAuthorityError> {
    let bytes = Zeroizing::new(
        serde_json::to_vec(value)
            .map_err(|error| KeyAuthorityError::CanonicalEncoding(error.to_string()))?,
    );
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(&bytes[..]);
    Ok(hasher.finalize().into())
}

fn validate_storage_path(path: &Path, file_required: bool) -> Result<(), KeyAuthorityError> {
    if !path.is_absolute() || path.file_name().is_none() {
        return Err(KeyAuthorityError::UnsafeStoragePath);
    }
    let parent = path.parent().ok_or(KeyAuthorityError::UnsafeStoragePath)?;
    reject_symlink_components(parent)?;
    let parent_metadata = fs::symlink_metadata(parent)?;
    if !parent_metadata.is_dir() || parent_metadata.mode() & 0o777 != KEY_DIRECTORY_MODE {
        return Err(KeyAuthorityError::UnsafeStoragePath);
    }
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.is_file()
                || metadata.file_type().is_symlink()
                || metadata.nlink() != 1
                || metadata.mode() & 0o777 != KEY_FILE_MODE
                || metadata.uid() != parent_metadata.uid()
            {
                return Err(KeyAuthorityError::UnsafeStoragePath);
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound && !file_required => {}
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

fn reject_symlink_components(path: &Path) -> Result<(), KeyAuthorityError> {
    let mut current = PathBuf::new();
    for component in path.components() {
        match component {
            Component::RootDir => current.push(Path::new("/")),
            Component::Normal(part) => current.push(part),
            _ => return Err(KeyAuthorityError::UnsafeStoragePath),
        }
        if fs::symlink_metadata(&current)?.file_type().is_symlink() {
            return Err(KeyAuthorityError::UnsafeStoragePath);
        }
    }
    Ok(())
}

fn temporary_path(path: &Path) -> Result<PathBuf, KeyAuthorityError> {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(KeyAuthorityError::UnsafeStoragePath)?;
    Ok(path.with_file_name(format!(".{name}.tmp")))
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::os::unix::fs::PermissionsExt as _;

    use tempfile::TempDir;

    use super::*;
    use crate::{
        EncryptionGenerationRecipient, NodeKeyTransparencyError, NodeKeyTransparencyLedger,
        NodeKeyTransparencyOutcome,
    };

    const NOW: u64 = 1_000_000;

    #[derive(Debug)]
    struct FixedGenerator {
        next: u8,
    }

    impl WireGuardKeyGenerator for FixedGenerator {
        fn generate(&mut self) -> Result<WireGuardPrivateKey, KeyAuthorityError> {
            let key = WireGuardPrivateKey::from_zeroizing(Zeroizing::new([self.next; 32]))?;
            self.next = self.next.saturating_add(1);
            Ok(key)
        }
    }

    #[derive(Debug, Default)]
    struct FailingStore {
        fail: Cell<bool>,
        writes: Cell<u64>,
    }

    impl NodeKeyStateStore for FailingStore {
        fn persist(&self, _authority: &NodeKeyAuthority) -> Result<(), KeyAuthorityError> {
            if self.fail.get() {
                return Err(KeyAuthorityError::Io(io::Error::other("injected failure")));
            }
            self.writes.set(self.writes.get() + 1);
            Ok(())
        }
    }

    fn authority() -> NodeKeyAuthority {
        NodeKeyAuthority::new(
            "cluster-a".to_owned(),
            "worker-a".to_owned(),
            "node-uid-a".to_owned(),
        )
        .unwrap()
    }

    fn peers() -> BTreeSet<String> {
        ["node-uid-b".to_owned(), "node-uid-c".to_owned()]
            .into_iter()
            .collect()
    }

    fn acknowledgement(
        epoch: &LocalKeyEpoch,
        peer: &str,
        observed: u64,
    ) -> PeerEpochAcknowledgement {
        PeerEpochAcknowledgement {
            peer_node_uid: peer.to_owned(),
            target_node_uid: "node-uid-a".to_owned(),
            epoch: epoch.epoch,
            barrier_digest: epoch.barrier.barrier_digest,
            peer_public_epoch: 7,
            observed_at_unix_ms: observed,
        }
    }

    fn prepare_and_attest(authority: &mut NodeKeyAuthority, generator: &mut FixedGenerator) -> u64 {
        let epoch = authority
            .prepare_epoch(Revision::new(4), peers(), NOW, NOW + 100_000, generator)
            .unwrap();
        for peer in peers() {
            let ack = acknowledgement(&authority.epochs[0], &peer, NOW + 1);
            authority.acknowledge_epoch(&peer, ack, NOW + 1).unwrap();
        }
        epoch
    }

    #[test]
    fn os_generator_produces_distinct_nonzero_wireguard_keys() {
        let mut generator = OsWireGuardKeyGenerator;
        let first = generator.generate().unwrap();
        let second = generator.generate().unwrap();
        assert_ne!(first.public_key(), second.public_key());
        assert_ne!(first.expose_for_kernel(), &[0; 32]);
        assert_eq!(format!("{first:?}"), "WireGuardPrivateKey(<redacted>)");
    }

    #[test]
    fn kernel_plan_receives_only_the_exact_ready_local_epoch() {
        let mut authority = authority();
        let mut generator = FixedGenerator { next: 1 };
        let epoch = authority
            .prepare_epoch(
                Revision::new(4),
                peers(),
                NOW,
                NOW + 100_000,
                &mut generator,
            )
            .unwrap();
        let local_public_key = authority.epochs()[0].public_key();
        let build_plan = |cluster_id: &str| {
            crate::WireGuardKernelPlan::new(crate::WireGuardKernelPlanInput {
                cluster_id: cluster_id.to_owned(),
                local_node_uid: "node-uid-a".to_owned(),
                epoch,
                revision: Revision::new(5),
                interface_name: "unfwg000000001".to_owned(),
                local_public_key,
                listen_port: 51_820,
                fwmark: 0x0055_0100,
                route_table: 20_001,
                mtu_envelope: crate::WireGuardMtuEnvelope::derive(&[
                    crate::UnderlayMtuObservation {
                        peer_node_uid: "node-uid-b".to_owned(),
                        family: crate::UnderlayAddressFamily::Ipv4,
                        underlay_mtu: 1_500,
                    },
                    crate::UnderlayMtuObservation {
                        peer_node_uid: "node-uid-c".to_owned(),
                        family: crate::UnderlayAddressFamily::Ipv4,
                        underlay_mtu: 1_500,
                    },
                ])
                .unwrap(),
                local_pod_cidrs: vec![
                    crate::IpPrefix {
                        address: "10.244.1.0".parse().unwrap(),
                        prefix_len: 24,
                    },
                    crate::IpPrefix {
                        address: "fd00:244:1::".parse().unwrap(),
                        prefix_len: 64,
                    },
                ],
                activation: crate::WireGuardEpochActivation::InactiveStaged,
                peers: vec![
                    crate::WireGuardPeerPlan {
                        node_uid: "node-uid-b".to_owned(),
                        public_key: WireGuardPublicKey([42; 32]),
                        endpoint: "192.0.2.42:51820".parse().unwrap(),
                        persistent_keepalive_seconds: 0,
                        allowed_ips: vec![crate::IpPrefix {
                            address: "10.42.0.0".parse().unwrap(),
                            prefix_len: 24,
                        }],
                    },
                    crate::WireGuardPeerPlan {
                        node_uid: "node-uid-c".to_owned(),
                        public_key: WireGuardPublicKey([43; 32]),
                        endpoint: "192.0.2.43:51820".parse().unwrap(),
                        persistent_keepalive_seconds: 0,
                        allowed_ips: vec![crate::IpPrefix {
                            address: "10.43.0.0".parse().unwrap(),
                            prefix_len: 24,
                        }],
                    },
                ],
            })
            .unwrap()
        };
        let plan = build_plan("cluster-a");
        assert!(matches!(
            authority.private_key_for_kernel_plan(&plan),
            Err(KeyAuthorityError::KernelPlanMismatch)
        ));
        for peer in peers() {
            let acknowledgement = acknowledgement(&authority.epochs[0], &peer, NOW + 1);
            authority
                .acknowledge_epoch(&peer, acknowledgement, NOW + 1)
                .unwrap();
        }
        assert_eq!(
            authority
                .private_key_for_kernel_plan(&plan)
                .unwrap()
                .public_key(),
            plan.local_public_key
        );
        assert!(matches!(
            authority.private_key_for_kernel_plan(&build_plan("replacement-cluster")),
            Err(KeyAuthorityError::KernelPlanMismatch)
        ));
    }

    #[test]
    fn causal_epoch_barrier_requires_every_exact_authenticated_peer() {
        let mut authority = authority();
        let mut generator = FixedGenerator { next: 1 };
        let epoch = authority
            .prepare_epoch(
                Revision::new(4),
                peers(),
                NOW,
                NOW + 100_000,
                &mut generator,
            )
            .unwrap();
        let first = acknowledgement(&authority.epochs[0], "node-uid-b", NOW + 1);
        authority
            .acknowledge_epoch("node-uid-b", first.clone(), NOW + 1)
            .unwrap();
        assert_eq!(authority.epochs[0].phase, KeyEpochPhase::Prepared);
        assert!(
            !authority
                .acknowledge_epoch("node-uid-b", first, NOW + 1)
                .unwrap()
        );
        assert!(matches!(
            authority.activate_epoch(epoch, Revision::new(4), NOW + 2, 1_000),
            Err(KeyAuthorityError::ActivationBarrierNotSatisfied)
        ));
        let second = acknowledgement(&authority.epochs[0], "node-uid-c", NOW + 2);
        authority
            .acknowledge_epoch("node-uid-c", second, NOW + 2)
            .unwrap();
        assert_eq!(authority.epochs[0].phase, KeyEpochPhase::MutuallyAttested);
        authority
            .activate_epoch(epoch, Revision::new(4), NOW + 2, 1_000)
            .unwrap();
        assert_eq!(authority.epochs[0].phase, KeyEpochPhase::Active);
    }

    #[test]
    fn forged_mutated_expired_and_topology_stale_acknowledgements_fail_closed() {
        let mut authority = authority();
        let mut generator = FixedGenerator { next: 1 };
        authority
            .prepare_epoch(Revision::new(4), peers(), NOW, NOW + 100, &mut generator)
            .unwrap();
        let ack = acknowledgement(&authority.epochs[0], "node-uid-b", NOW + 1);
        assert!(matches!(
            authority.acknowledge_epoch("node-uid-c", ack.clone(), NOW + 1),
            Err(KeyAuthorityError::UnauthenticatedPeer)
        ));
        authority
            .acknowledge_epoch("node-uid-b", ack.clone(), NOW + 1)
            .unwrap();
        let mut mutated = ack;
        mutated.peer_public_epoch += 1;
        assert!(matches!(
            authority.acknowledge_epoch("node-uid-b", mutated, NOW + 2),
            Err(KeyAuthorityError::AcknowledgementMutation)
        ));
        let late = acknowledgement(&authority.epochs[0], "node-uid-c", NOW + 101);
        assert!(matches!(
            authority.acknowledge_epoch("node-uid-c", late, NOW + 101),
            Err(KeyAuthorityError::InvalidAcknowledgement)
        ));
        let valid = acknowledgement(&authority.epochs[0], "node-uid-c", NOW + 2);
        authority
            .acknowledge_epoch("node-uid-c", valid, NOW + 2)
            .unwrap();
        assert!(matches!(
            authority.activate_epoch(1, Revision::new(5), NOW + 3, 10),
            Err(KeyAuthorityError::ActivationBarrierNotSatisfied)
        ));
    }

    #[test]
    fn two_epoch_rotation_moves_new_epoch_and_requires_positive_drain_proof() {
        let mut authority = authority();
        let mut generator = FixedGenerator { next: 1 };
        let first = prepare_and_attest(&mut authority, &mut generator);
        authority
            .activate_epoch(first, Revision::new(4), NOW + 2, 2_000)
            .unwrap();
        let second = authority
            .prepare_epoch(
                Revision::new(5),
                peers(),
                NOW + 10,
                NOW + 90_000,
                &mut generator,
            )
            .unwrap();
        for peer in peers() {
            let ack = acknowledgement(&authority.epochs[1], &peer, NOW + 11);
            authority.acknowledge_epoch(&peer, ack, NOW + 11).unwrap();
        }
        authority
            .activate_epoch(second, Revision::new(5), NOW + 12, 1_000)
            .unwrap();
        assert_eq!(authority.epochs[0].phase, KeyEpochPhase::Draining);
        assert_eq!(authority.epochs[1].phase, KeyEpochPhase::Active);
        assert_eq!(
            authority
                .drained_epoch_ready_for_retirement(NOW + 1_011)
                .unwrap(),
            None
        );
        assert_eq!(
            authority
                .drained_epoch_ready_for_retirement(NOW + 1_012)
                .unwrap(),
            Some(first)
        );
        let nonempty = EpochDrainProof::issue(
            "node-uid-a".to_owned(),
            first,
            Revision::new(9),
            NOW + 20,
            1,
            0,
        )
        .unwrap();
        assert!(matches!(
            authority.retire_drained_epoch(&nonempty, NOW + 20),
            Err(KeyAuthorityError::InvalidDrainProof)
        ));
        let empty = EpochDrainProof::issue(
            "node-uid-a".to_owned(),
            first,
            Revision::new(10),
            NOW + 21,
            0,
            0,
        )
        .unwrap();
        authority.retire_drained_epoch(&empty, NOW + 21).unwrap();
        assert_eq!(authority.epochs.len(), 1);
        assert_eq!(authority.retired_through_epoch, first);
        assert_eq!(authority.epochs[0].phase, KeyEpochPhase::Active);
    }

    #[test]
    fn emergency_revocation_drops_secret_epochs_and_denies_reuse() {
        let mut authority = authority();
        let mut generator = FixedGenerator { next: 1 };
        let first = prepare_and_attest(&mut authority, &mut generator);
        authority
            .activate_epoch(first, Revision::new(4), NOW + 2, 1_000)
            .unwrap();
        let receipt = authority
            .revoke_through(first, EpochRevocationReason::SuspectedCompromise, NOW + 3)
            .unwrap();
        receipt.verify().unwrap();
        assert!(authority.epochs.is_empty());
        assert_eq!(authority.revoked_through_epoch, first);
        assert_ne!(receipt.receipt_digest, EpochRevocationDigest([0; 32]));
        let mut forged = receipt.clone();
        forged.revoked_through_epoch += 1;
        assert!(matches!(
            forged.verify(),
            Err(KeyAuthorityError::InvalidRevocationReceipt)
        ));
        let next = authority
            .prepare_epoch(
                Revision::new(5),
                BTreeSet::new(),
                NOW + 4,
                NOW + 10_000,
                &mut generator,
            )
            .unwrap();
        assert_eq!(next, first + 1);
    }

    #[test]
    fn public_wire_shape_contains_no_private_material() {
        let mut authority = authority();
        let mut generator = FixedGenerator { next: 73 };
        prepare_and_attest(&mut authority, &mut generator);
        let json = serde_json::to_string(&authority.publication().unwrap()).unwrap();
        assert!(!json.contains("private"));
        assert!(!json.contains("73,73,73"));
        assert!(format!("{authority:?}").contains("<redacted>"));
        assert!(!format!("{authority:?}").contains("73, 73, 73"));
    }

    #[test]
    fn authenticated_publication_rejects_replay_mutation_and_node_replacement() {
        let mut authority = authority();
        let mut generator = FixedGenerator { next: 1 };
        prepare_and_attest(&mut authority, &mut generator);
        let publication = authority.publication().unwrap();
        let identity = AuthenticatedNodeIdentity {
            cluster_id: "cluster-a".to_owned(),
            node_name: "worker-a".to_owned(),
            node_uid: "node-uid-a".to_owned(),
        };
        assert_eq!(
            admit_authenticated_publication(&identity, &publication, None).unwrap(),
            PublicationAdmission::Accepted
        );
        assert_eq!(
            admit_authenticated_publication(&identity, &publication, Some(&publication)).unwrap(),
            PublicationAdmission::Idempotent
        );
        let mut mutation = publication.clone();
        mutation.epochs[0].public_key.0[0] ^= 1;
        assert!(matches!(
            admit_authenticated_publication(&identity, &mutation, Some(&publication)),
            Err(KeyAuthorityError::InvalidPublication)
        ));
        let mut mutation = publication.clone();
        mutation.epochs[0].topology_revision = mutation.epochs[0].topology_revision.next();
        mutation.publication_digest = mutation.calculate_digest().unwrap();
        assert!(matches!(
            admit_authenticated_publication(&identity, &mutation, Some(&publication)),
            Err(KeyAuthorityError::PublicationMutation)
        ));
        let mut stale = publication.clone();
        stale.key_revision = Revision::INITIAL;
        stale.publication_digest = stale.calculate_digest().unwrap();
        assert!(matches!(
            admit_authenticated_publication(&identity, &stale, Some(&publication)),
            Err(KeyAuthorityError::PublicationReplay)
        ));
        let mut omitted = publication.clone();
        omitted.key_revision = omitted.key_revision.next();
        omitted.epochs.clear();
        omitted.publication_digest = omitted.calculate_digest().unwrap();
        assert!(matches!(
            admit_authenticated_publication(&identity, &omitted, Some(&publication)),
            Err(KeyAuthorityError::PublicationRegression)
        ));

        let replacement_authority = NodeKeyAuthority::new(
            "cluster-a".to_owned(),
            "worker-a".to_owned(),
            "replacement-uid".to_owned(),
        )
        .unwrap();
        let replacement_publication = replacement_authority.publication().unwrap();
        let replacement_identity = AuthenticatedNodeIdentity {
            node_uid: "replacement-uid".to_owned(),
            ..identity
        };
        assert!(matches!(
            admit_authenticated_publication(
                &replacement_identity,
                &replacement_publication,
                Some(&publication)
            ),
            Err(KeyAuthorityError::NodeReplacementRequiresFence)
        ));
    }

    #[test]
    fn owner_only_checkpoint_round_trips_and_rejects_uid_reuse_and_tamper() {
        let temporary = TempDir::new().unwrap();
        let directory = temporary.path().join("keys");
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        let path = directory.join("authority.json");
        let store = FileNodeKeyStateStore::new(path.clone());
        let mut authority = authority();
        let mut generator = FixedGenerator { next: 1 };
        let epoch = prepare_and_attest(&mut authority, &mut generator);
        authority
            .activate_epoch(epoch, Revision::new(4), NOW + 2, 1_000)
            .unwrap();
        store.persist(&authority).unwrap();
        let metadata = fs::metadata(&path).unwrap();
        assert_eq!(metadata.mode() & 0o777, 0o600);
        let restored = store
            .restore("cluster-a", "worker-a", "node-uid-a")
            .unwrap();
        assert_eq!(
            restored.publication().unwrap(),
            authority.publication().unwrap()
        );
        assert!(matches!(
            store.restore("cluster-a", "worker-a", "replacement-uid"),
            Err(KeyAuthorityError::NodeReplacementRequiresFence)
        ));
        let mut value: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        value["nextEpoch"] = serde_json::json!(99);
        fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(matches!(
            store.restore("cluster-a", "worker-a", "node-uid-a"),
            Err(KeyAuthorityError::CheckpointDigestMismatch)
        ));

        store.persist(&authority).unwrap();
        let mut document: PersistedAuthorityDocument =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        document.epochs[0].private_key[10] ^= 1;
        document.checkpoint_digest = document.calculate_digest().unwrap();
        fs::write(&path, serde_json::to_vec(&document).unwrap()).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(matches!(
            store.restore("cluster-a", "worker-a", "node-uid-a"),
            Err(KeyAuthorityError::InvalidDurableState)
        ));
    }

    #[test]
    fn storage_rejects_permissive_directory_symlink_and_hardlink() {
        let temporary = TempDir::new().unwrap();
        let permissive = temporary.path().join("permissive");
        fs::create_dir(&permissive).unwrap();
        let store = FileNodeKeyStateStore::new(permissive.join("keys.json"));
        assert!(matches!(
            store.persist(&authority()),
            Err(KeyAuthorityError::UnsafeStoragePath)
        ));

        let secure = temporary.path().join("secure");
        fs::create_dir(&secure).unwrap();
        fs::set_permissions(&secure, fs::Permissions::from_mode(0o700)).unwrap();
        let path = secure.join("keys.json");
        let store = FileNodeKeyStateStore::new(path.clone());
        store.persist(&authority()).unwrap();
        fs::hard_link(&path, secure.join("alias.json")).unwrap();
        assert!(matches!(
            store.restore("cluster-a", "worker-a", "node-uid-a"),
            Err(KeyAuthorityError::UnsafeStoragePath)
        ));
    }

    #[test]
    fn durability_failure_never_advances_live_authority() {
        let store = FailingStore::default();
        let mut durable =
            DurableNodeKeyAuthority::create(authority(), store, FixedGenerator { next: 1 })
                .unwrap();
        durable.store.fail.set(true);
        assert!(
            durable
                .prepare_epoch(Revision::new(1), BTreeSet::new(), NOW, NOW + 10_000,)
                .is_err()
        );
        assert!(durable.authority().epochs().is_empty());
        assert_eq!(durable.authority().key_revision(), Revision::INITIAL);
    }

    #[test]
    fn epoch_capacity_and_lifetime_are_bounded_before_generation() {
        let mut authority = authority();
        let mut generator = FixedGenerator { next: 1 };
        assert!(matches!(
            authority.prepare_epoch(
                Revision::new(1),
                BTreeSet::new(),
                NOW,
                NOW + MAX_KEY_LIFETIME_MS + 1,
                &mut generator,
            ),
            Err(KeyAuthorityError::InvalidLifetime)
        ));
        authority
            .prepare_epoch(
                Revision::new(1),
                BTreeSet::new(),
                NOW,
                NOW + 10_000,
                &mut generator,
            )
            .unwrap();
        assert!(matches!(
            authority.prepare_epoch(
                Revision::new(2),
                BTreeSet::new(),
                NOW,
                NOW + 10_000,
                &mut generator,
            ),
            Err(KeyAuthorityError::EpochCapacityOrTransition)
        ));
    }

    fn transparency_publication(
        node_name: &str,
        node_uid: &str,
        key_byte: u8,
        topology_revision: Revision,
    ) -> (AuthenticatedNodeIdentity, NodeKeyPublication) {
        let mut authority = NodeKeyAuthority::new(
            "cluster-a".to_owned(),
            node_name.to_owned(),
            node_uid.to_owned(),
        )
        .unwrap();
        authority
            .prepare_epoch(
                topology_revision,
                BTreeSet::new(),
                NOW,
                NOW + 10_000,
                &mut FixedGenerator { next: key_byte },
            )
            .unwrap();
        (
            AuthenticatedNodeIdentity {
                cluster_id: "cluster-a".to_owned(),
                node_name: node_name.to_owned(),
                node_uid: node_uid.to_owned(),
            },
            authority.publication().unwrap(),
        )
    }

    #[test]
    fn public_key_transparency_requires_the_complete_exact_membership_cut() {
        let revision = Revision::new(7);
        let (identity_a, publication_a) =
            transparency_publication("worker-a", "uid-a", 21, revision);
        let (identity_b, publication_b) =
            transparency_publication("worker-b", "uid-b", 22, revision);
        let mut members = vec![
            EncryptionGenerationRecipient {
                node_name: "worker-b".to_owned(),
                node_uid: "uid-b".to_owned(),
            },
            EncryptionGenerationRecipient {
                node_name: "worker-a".to_owned(),
                node_uid: "uid-a".to_owned(),
            },
        ];
        let mut ledger = NodeKeyTransparencyLedger::default();
        ledger
            .replace_membership("cluster-a".to_owned(), revision, members.clone())
            .unwrap();
        assert_eq!(
            ledger.observe(&identity_a, publication_a).unwrap(),
            NodeKeyTransparencyOutcome::Accepted
        );
        assert!(ledger.complete_cut().unwrap().is_none());
        assert_eq!(
            ledger.observe(&identity_b, publication_b).unwrap(),
            NodeKeyTransparencyOutcome::Accepted
        );
        let cut = ledger.complete_cut().unwrap().unwrap();
        cut.verify().unwrap();
        members.sort();
        assert_eq!(cut.members, members);
        let wire = serde_json::to_string(&cut).unwrap();
        assert!(!wire.contains("private"));
        assert_eq!(cut.publications.len(), 2);
    }

    #[test]
    fn public_key_transparency_clears_on_membership_change_and_refuses_replacement() {
        let revision = Revision::new(7);
        let member = EncryptionGenerationRecipient {
            node_name: "worker-a".to_owned(),
            node_uid: "uid-a".to_owned(),
        };
        let (identity, publication) = transparency_publication("worker-a", "uid-a", 31, revision);
        let mut ledger = NodeKeyTransparencyLedger::default();
        assert!(
            ledger
                .replace_membership("cluster-a".to_owned(), revision, vec![member.clone()])
                .unwrap()
        );
        assert_eq!(
            ledger.observe(&identity, publication.clone()).unwrap(),
            NodeKeyTransparencyOutcome::Accepted
        );
        assert_eq!(
            ledger.observe(&identity, publication).unwrap(),
            NodeKeyTransparencyOutcome::Idempotent
        );
        assert!(ledger.complete_cut().unwrap().is_some());
        assert!(
            ledger
                .replace_membership(
                    "cluster-a".to_owned(),
                    revision.next(),
                    vec![member.clone()],
                )
                .unwrap()
        );
        assert!(ledger.complete_cut().unwrap().is_none());

        let (replacement, replacement_publication) =
            transparency_publication("worker-a", "replacement-uid", 32, revision.next());
        assert!(matches!(
            ledger.observe(&replacement, replacement_publication),
            Err(NodeKeyTransparencyError::ForeignMembership)
        ));
        assert!(matches!(
            ledger.replace_membership("cluster-a".to_owned(), revision, vec![member]),
            Err(NodeKeyTransparencyError::MembershipRegression)
        ));
    }
}
