//! Crash-recoverable activation contract for encryption fast-path map banks.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use unf_common::Revision;

use crate::{EncryptionFastPathDigest, EncryptionFastPathState, FastPathEpochState, FastPathError};

pub const CAUSAL_COMMIT_VECTOR_SCHEMA_VERSION: u16 = 1;
pub const FAST_PATH_MAP_TRANSACTION_SCHEMA_VERSION: u16 = 1;

const COMMIT_VECTOR_DIGEST_DOMAIN: &[u8] = b"unf.encryption-causal-commit-vector.v1\0";
const MAP_TRANSACTION_DIGEST_DOMAIN: &[u8] = b"unf.encryption-map-transaction.v1\0";

/// Serializable commitment to one complete bank. This is deliberately not a
/// substitute for map readback; recovery must supply the observed digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct FastPathPublishedGeneration {
    pub generation: Revision,
    pub policy_revision: Revision,
    pub service_revision: Revision,
    pub egress_revision: Revision,
    pub bank: u8,
    pub epoch_count: u8,
    pub decision_count: u32,
    pub transport_count: u32,
    pub state_digest: EncryptionFastPathDigest,
}

impl FastPathPublishedGeneration {
    /// Creates a durable record only from independently replayed state.
    ///
    /// # Errors
    ///
    /// Rejects any mutated fast-path state.
    pub fn issue(state: &EncryptionFastPathState) -> Result<Self, FastPathTransactionError> {
        state
            .verify_integrity()
            .map_err(FastPathTransactionError::InvalidFastPath)?;
        Ok(Self {
            generation: Revision::new(state.config.generation),
            policy_revision: Revision::new(state.config.policy_revision),
            service_revision: Revision::new(state.config.service_revision),
            egress_revision: Revision::new(state.config.egress_revision),
            bank: state.config.active_bank,
            epoch_count: state.config.epoch_count,
            decision_count: state.config.decision_count,
            transport_count: state.config.transport_count,
            state_digest: state.state_digest,
        })
    }
}

/// Cross-domain activation proof. One digest binds the BPF generation to all
/// distinct committed kernel configurations and its exact two-epoch state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CausalCommitVector {
    pub schema_version: u16,
    pub published: FastPathPublishedGeneration,
    pub active_epoch: u64,
    pub draining_epoch: Option<u64>,
    pub kernel_configuration_digests: Vec<[u8; 32]>,
    pub vector_digest: CausalCommitVectorDigest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CausalCommitVectorDigest(pub [u8; 32]);

impl CausalCommitVector {
    /// Seals a canonical active/draining epoch set and every exact kernel
    /// configuration referenced by the desired map bank.
    ///
    /// # Errors
    ///
    /// Rejects mutated state, missing/multiple active epochs, inconsistent
    /// lifecycle state for an epoch, or an invalid two-epoch frontier.
    pub fn issue(state: &EncryptionFastPathState) -> Result<Self, FastPathTransactionError> {
        let published = FastPathPublishedGeneration::issue(state)?;
        let epochs = canonical_epochs(state)?;
        let active_epoch = epochs
            .iter()
            .find_map(|(epoch, lifecycle)| {
                (*lifecycle == FastPathEpochState::Active).then_some(*epoch)
            })
            .ok_or(FastPathTransactionError::InvalidEpochFrontier)?;
        let draining_epoch = epochs.iter().find_map(|(epoch, lifecycle)| {
            (*lifecycle == FastPathEpochState::Draining).then_some(*epoch)
        });
        let kernel_configuration_digests = state
            .transport_authority
            .iter()
            .map(|transport| transport.kernel_configuration_digest)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        if kernel_configuration_digests.is_empty()
            || kernel_configuration_digests.contains(&[0; 32])
        {
            return Err(FastPathTransactionError::InvalidKernelCommitment);
        }
        let mut vector = Self {
            schema_version: CAUSAL_COMMIT_VECTOR_SCHEMA_VERSION,
            published,
            active_epoch,
            draining_epoch,
            kernel_configuration_digests,
            vector_digest: CausalCommitVectorDigest([0; 32]),
        };
        vector.vector_digest = vector.calculate_digest()?;
        Ok(vector)
    }

    /// Replays the vector and its canonical epoch/kernel commitments.
    ///
    /// # Errors
    ///
    /// Rejects schema, revision, count, epoch, ordering, zero-digest, or digest
    /// mutation.
    pub fn verify(&self) -> Result<(), FastPathTransactionError> {
        if self.schema_version != CAUSAL_COMMIT_VECTOR_SCHEMA_VERSION
            || self.published.generation == Revision::INITIAL
            || self.published.policy_revision == Revision::INITIAL
            || self.published.service_revision == Revision::INITIAL
            || self.published.egress_revision == Revision::INITIAL
            || self.published.epoch_count == 0
            || self.published.epoch_count > 2
            || self.published.transport_count == 0
            || self.active_epoch == 0
            || self.draining_epoch == Some(0)
            || self.draining_epoch == Some(self.active_epoch)
            || usize::from(self.published.epoch_count)
                != 1 + usize::from(self.draining_epoch.is_some())
            || self.kernel_configuration_digests.is_empty()
            || self
                .kernel_configuration_digests
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
            || self.kernel_configuration_digests.contains(&[0; 32])
            || self.vector_digest != self.calculate_digest()?
        {
            return Err(FastPathTransactionError::InvalidCommitVector);
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Result<CausalCommitVectorDigest, FastPathTransactionError> {
        let mut canonical = self.clone();
        canonical.vector_digest = CausalCommitVectorDigest([0; 32]);
        hash_canonical(COMMIT_VECTOR_DIGEST_DOMAIN, &canonical).map(CausalCommitVectorDigest)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum FastPathMapTransactionPhase {
    Prepared,
    Staged,
    Committed,
    RolledBack,
}

/// Durable intent around the one map-config pointer flip. Map entry writes are
/// performed by the platform adapter, but every crash boundary is total here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct FastPathMapTransaction {
    pub schema_version: u16,
    pub transaction_revision: Revision,
    pub prior: Option<FastPathPublishedGeneration>,
    pub desired: CausalCommitVector,
    pub phase: FastPathMapTransactionPhase,
    pub staged_readback_digest: Option<EncryptionFastPathDigest>,
    pub transaction_digest: FastPathMapTransactionDigest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct FastPathMapTransactionDigest(pub [u8; 32]);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FastPathMapRecoveryAction {
    ClearAndRestageInactive,
    ActivateDesired,
    CommitObservedDesired,
    ReuseCommitted,
    RollbackComplete,
    RefuseUnknownState,
}

impl FastPathMapTransaction {
    /// Persists intent before any inactive-bank mutation.
    ///
    /// # Errors
    ///
    /// Rejects invalid vectors, nonmonotonic generations/revisions, or staging
    /// into the currently active bank.
    pub fn begin(
        transaction_revision: Revision,
        desired: CausalCommitVector,
        prior: Option<FastPathPublishedGeneration>,
    ) -> Result<Self, FastPathTransactionError> {
        desired.verify()?;
        if transaction_revision == Revision::INITIAL
            || prior.is_some_and(|prior| {
                desired.published.bank == prior.bank
                    || desired.published.generation <= prior.generation
            })
        {
            return Err(FastPathTransactionError::InvalidTransaction);
        }
        let mut transaction = Self {
            schema_version: FAST_PATH_MAP_TRANSACTION_SCHEMA_VERSION,
            transaction_revision,
            prior,
            desired,
            phase: FastPathMapTransactionPhase::Prepared,
            staged_readback_digest: None,
            transaction_digest: FastPathMapTransactionDigest([0; 32]),
        };
        transaction.transaction_digest = transaction.calculate_digest()?;
        Ok(transaction)
    }

    /// Records exact inactive-bank readback before the config pointer may move.
    ///
    /// # Errors
    ///
    /// Rejects wrong phase, corrupt transaction, or any desired/readback drift.
    pub fn record_staged(
        &mut self,
        readback: &EncryptionFastPathState,
    ) -> Result<(), FastPathTransactionError> {
        self.verify()?;
        readback
            .verify_integrity()
            .map_err(FastPathTransactionError::InvalidFastPath)?;
        if self.phase != FastPathMapTransactionPhase::Prepared
            || FastPathPublishedGeneration::issue(readback)? != self.desired.published
        {
            return Err(FastPathTransactionError::StagedReadbackMismatch);
        }
        self.phase = FastPathMapTransactionPhase::Staged;
        self.staged_readback_digest = Some(readback.state_digest);
        self.transaction_digest = self.calculate_digest()?;
        Ok(())
    }

    /// Commits only after the published config and complete bank read back as
    /// the desired generation.
    ///
    /// # Errors
    ///
    /// Rejects wrong phase, corruption, or partial/mixed observed state.
    pub fn commit(
        &mut self,
        observed: &EncryptionFastPathState,
    ) -> Result<(), FastPathTransactionError> {
        self.verify()?;
        if self.phase != FastPathMapTransactionPhase::Staged
            || FastPathPublishedGeneration::issue(observed)? != self.desired.published
            || self.staged_readback_digest != Some(observed.state_digest)
        {
            return Err(FastPathTransactionError::PublishedReadbackMismatch);
        }
        self.phase = FastPathMapTransactionPhase::Committed;
        self.transaction_digest = self.calculate_digest()?;
        Ok(())
    }

    /// Records cleanup only when the prior config is still authoritative and
    /// the inactive target bank is positively absent.
    ///
    /// # Errors
    ///
    /// Rejects wrong phase, active-config drift, or incomplete cleanup.
    pub fn record_rollback(
        &mut self,
        observed_active: Option<FastPathPublishedGeneration>,
        target_bank_absent: bool,
    ) -> Result<(), FastPathTransactionError> {
        self.verify()?;
        if !matches!(
            self.phase,
            FastPathMapTransactionPhase::Prepared | FastPathMapTransactionPhase::Staged
        ) || observed_active != self.prior
            || !target_bank_absent
        {
            return Err(FastPathTransactionError::RollbackMismatch);
        }
        self.phase = FastPathMapTransactionPhase::RolledBack;
        self.staged_readback_digest = None;
        self.transaction_digest = self.calculate_digest()?;
        Ok(())
    }

    /// Selects one deterministic restart action from durable intent, the active
    /// config, and exact target-bank readback.
    ///
    /// # Errors
    ///
    /// Rejects a corrupt checkpoint before interpreting observations.
    pub fn recover(
        &self,
        observed_active: Option<FastPathPublishedGeneration>,
        observed_target_digest: Option<EncryptionFastPathDigest>,
    ) -> Result<FastPathMapRecoveryAction, FastPathTransactionError> {
        self.verify()?;
        let target_exact = observed_target_digest == Some(self.desired.published.state_digest);
        let active_is_prior = observed_active == self.prior;
        let active_is_desired = observed_active == Some(self.desired.published);
        Ok(match self.phase {
            FastPathMapTransactionPhase::Prepared if active_is_prior => {
                FastPathMapRecoveryAction::ClearAndRestageInactive
            }
            FastPathMapTransactionPhase::Staged if active_is_prior && target_exact => {
                FastPathMapRecoveryAction::ActivateDesired
            }
            FastPathMapTransactionPhase::Prepared | FastPathMapTransactionPhase::Staged
                if active_is_desired && target_exact =>
            {
                FastPathMapRecoveryAction::CommitObservedDesired
            }
            FastPathMapTransactionPhase::Committed if active_is_desired && target_exact => {
                FastPathMapRecoveryAction::ReuseCommitted
            }
            FastPathMapTransactionPhase::RolledBack
                if active_is_prior && observed_target_digest.is_none() =>
            {
                FastPathMapRecoveryAction::RollbackComplete
            }
            _ => FastPathMapRecoveryAction::RefuseUnknownState,
        })
    }

    /// Replays schema, nested vector, phase invariants, and digest.
    ///
    /// # Errors
    ///
    /// Rejects any malformed or mutated checkpoint.
    pub fn verify(&self) -> Result<(), FastPathTransactionError> {
        self.desired.verify()?;
        if self.schema_version != FAST_PATH_MAP_TRANSACTION_SCHEMA_VERSION
            || self.transaction_revision == Revision::INITIAL
            || self.prior.is_some_and(|prior| {
                prior.bank == self.desired.published.bank
                    || prior.generation >= self.desired.published.generation
            })
            || matches!(
                self.phase,
                FastPathMapTransactionPhase::Staged | FastPathMapTransactionPhase::Committed
            ) != self.staged_readback_digest.is_some()
            || self
                .staged_readback_digest
                .is_some_and(|digest| digest != self.desired.published.state_digest)
            || self.transaction_digest != self.calculate_digest()?
        {
            return Err(FastPathTransactionError::InvalidTransaction);
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Result<FastPathMapTransactionDigest, FastPathTransactionError> {
        let mut canonical = self.clone();
        canonical.transaction_digest = FastPathMapTransactionDigest([0; 32]);
        hash_canonical(MAP_TRANSACTION_DIGEST_DOMAIN, &canonical).map(FastPathMapTransactionDigest)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum FastPathTransactionError {
    #[error("invalid encryption fast-path state: {0}")]
    InvalidFastPath(FastPathError),
    #[error("invalid active/draining epoch frontier")]
    InvalidEpochFrontier,
    #[error("invalid or missing kernel configuration commitment")]
    InvalidKernelCommitment,
    #[error("invalid causal commit vector")]
    InvalidCommitVector,
    #[error("invalid encryption map transaction")]
    InvalidTransaction,
    #[error("inactive encryption map bank differs from desired state")]
    StagedReadbackMismatch,
    #[error("published encryption map bank differs from desired state")]
    PublishedReadbackMismatch,
    #[error("encryption map rollback lacks exact prior/absence evidence")]
    RollbackMismatch,
    #[error("encryption transaction canonical encoding failed: {0}")]
    CanonicalEncoding(String),
}

fn canonical_epochs(
    state: &EncryptionFastPathState,
) -> Result<BTreeMap<u64, FastPathEpochState>, FastPathTransactionError> {
    let mut epochs = BTreeMap::new();
    for transport in &state.transport_authority {
        if let Some(previous) = epochs.insert(transport.key_epoch, transport.state)
            && previous != transport.state
        {
            return Err(FastPathTransactionError::InvalidEpochFrontier);
        }
    }
    if epochs.is_empty()
        || epochs.len() > 2
        || epochs
            .values()
            .filter(|state| **state == FastPathEpochState::Active)
            .count()
            != 1
        || epochs
            .values()
            .filter(|state| **state == FastPathEpochState::Draining)
            .count()
            > 1
        || epochs.len() != usize::from(state.config.epoch_count)
    {
        return Err(FastPathTransactionError::InvalidEpochFrontier);
    }
    Ok(epochs)
}

fn hash_canonical<T: Serialize>(
    domain: &[u8],
    value: &T,
) -> Result<[u8; 32], FastPathTransactionError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| FastPathTransactionError::CanonicalEncoding(error.to_string()))?;
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(bytes);
    Ok(hasher.finalize().into())
}
