//! Authenticated, Node-scoped delivery contract for prepared generations.
//!
//! The controller carries only secret-free fast-path authority. A fresh pull
//! nonce and an exact predecessor cursor bind every response to one current
//! agent request; kernel proof and map publication remain Node-local.

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use unf_ebpf_common::{
    ENCRYPTION_BANK_COUNT, ENCRYPTION_DECISION_MAP_CAPACITY, ENCRYPTION_TRANSPORT_MAP_CAPACITY,
};

use crate::{
    FastPathMapCheckpoint, FastPathMapTransactionPhase, FastPathPublishedGeneration,
    FastPathTransactionError,
};

pub const ENCRYPTION_GENERATION_REQUEST_SCHEMA_VERSION: u16 = 1;
pub const ENCRYPTION_GENERATION_CAPSULE_SCHEMA_VERSION: u16 = 1;
pub const ADMITTED_ENCRYPTION_GENERATION_SCHEMA_VERSION: u16 = 1;
const MAX_NODE_IDENTITY_BYTES: usize = 253;
const CAPSULE_DIGEST_DOMAIN: &[u8] = b"unf.encryption-generation-capsule.v1\0";
const ADMITTED_DIGEST_DOMAIN: &[u8] = b"unf.admitted-encryption-generation.v1\0";

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EncryptionGenerationRecipient {
    pub node_name: String,
    pub node_uid: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EncryptionGenerationCursor {
    pub controller_epoch: u64,
    pub recipient: EncryptionGenerationRecipient,
    pub published: FastPathPublishedGeneration,
}

/// Fresh pull request carrying the exact locally accepted predecessor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EncryptionGenerationRequest {
    pub schema_version: u16,
    pub node_name: String,
    pub current: Option<EncryptionGenerationCursor>,
    pub nonce: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EncryptionGenerationCapsuleDigest(pub [u8; 32]);

/// Nonce-bound controller response for one authenticated Node identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct NodeSealedGenerationCapsule {
    pub schema_version: u16,
    pub controller_epoch: u64,
    pub recipient: EncryptionGenerationRecipient,
    pub request_nonce: [u8; 32],
    pub checkpoint: FastPathMapCheckpoint,
    pub capsule_digest: EncryptionGenerationCapsuleDigest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AdmittedEncryptionGenerationDigest(pub [u8; 32]);

/// Durable last accepted distribution cursor. It is desired state, not proof
/// that Linux routes or Aya maps have been activated.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AdmittedEncryptionGeneration {
    pub schema_version: u16,
    pub controller_epoch: u64,
    pub recipient: EncryptionGenerationRecipient,
    pub checkpoint: FastPathMapCheckpoint,
    pub admitted_digest: AdmittedEncryptionGenerationDigest,
}

impl EncryptionGenerationRequest {
    /// Generates an OS-CSPRNG challenge and binds the exact accepted cursor.
    ///
    /// # Errors
    ///
    /// Rejects an invalid Node name/current record or unavailable randomness.
    pub fn fresh(
        node_name: String,
        current: Option<&AdmittedEncryptionGeneration>,
    ) -> Result<Self, EncryptionGenerationDistributionError> {
        let mut nonce = [0_u8; 32];
        getrandom::fill(&mut nonce).map_err(|error| {
            EncryptionGenerationDistributionError::Randomness(error.to_string())
        })?;
        Self::issue(node_name, current, nonce)
    }

    /// Deterministic constructor used by replay tests and constrained callers.
    ///
    /// # Errors
    ///
    /// Rejects invalid identity, cursor, or an all-zero nonce.
    pub fn issue(
        node_name: String,
        current: Option<&AdmittedEncryptionGeneration>,
        nonce: [u8; 32],
    ) -> Result<Self, EncryptionGenerationDistributionError> {
        if !valid_identity(&node_name) || nonce == [0; 32] {
            return Err(EncryptionGenerationDistributionError::InvalidRequest);
        }
        let current = current
            .map(|current| {
                current.verify()?;
                if current.recipient.node_name != node_name {
                    return Err(EncryptionGenerationDistributionError::RecipientMismatch);
                }
                Ok(current.cursor())
            })
            .transpose()?;
        Ok(Self {
            schema_version: ENCRYPTION_GENERATION_REQUEST_SCHEMA_VERSION,
            node_name,
            current,
            nonce,
        })
    }

    /// # Errors
    ///
    /// Rejects malformed or internally inconsistent requests.
    pub fn verify(&self) -> Result<(), EncryptionGenerationDistributionError> {
        if self.schema_version != ENCRYPTION_GENERATION_REQUEST_SCHEMA_VERSION
            || !valid_identity(&self.node_name)
            || self.nonce == [0; 32]
        {
            return Err(EncryptionGenerationDistributionError::InvalidRequest);
        }
        if let Some(current) = &self.current {
            validate_recipient(&current.recipient)?;
            validate_published(&current.published)?;
            if current.controller_epoch == 0 || current.recipient.node_name != self.node_name {
                return Err(EncryptionGenerationDistributionError::InvalidRequest);
            }
        }
        Ok(())
    }
}

impl NodeSealedGenerationCapsule {
    /// Seals one exact prepared successor for a fresh authenticated request.
    ///
    /// # Errors
    ///
    /// Rejects cross-Node delivery, UID reuse, non-prepared state, skipped or
    /// regressing generations, and predecessor disagreement.
    pub fn issue(
        controller_epoch: u64,
        recipient: EncryptionGenerationRecipient,
        request: &EncryptionGenerationRequest,
        checkpoint: FastPathMapCheckpoint,
    ) -> Result<Self, EncryptionGenerationDistributionError> {
        request.verify()?;
        validate_recipient(&recipient)?;
        checkpoint
            .verify()
            .map_err(EncryptionGenerationDistributionError::InvalidCheckpoint)?;
        if controller_epoch == 0
            || request.node_name != recipient.node_name
            || request
                .current
                .as_ref()
                .is_some_and(|current| current.recipient != recipient)
            || checkpoint.transaction.phase != FastPathMapTransactionPhase::Prepared
            || checkpoint.transaction.prior
                != request.current.as_ref().map(|current| current.published)
        {
            return Err(EncryptionGenerationDistributionError::InvalidTransition);
        }
        if request.current.as_ref().is_some_and(|current| {
            checkpoint.transaction.desired.published.generation <= current.published.generation
        }) {
            return Err(EncryptionGenerationDistributionError::GenerationRegression);
        }
        let mut capsule = Self {
            schema_version: ENCRYPTION_GENERATION_CAPSULE_SCHEMA_VERSION,
            controller_epoch,
            recipient,
            request_nonce: request.nonce,
            checkpoint,
            capsule_digest: EncryptionGenerationCapsuleDigest([0; 32]),
        };
        capsule.capsule_digest = capsule.calculate_digest()?;
        capsule.verify()?;
        Ok(capsule)
    }

    /// # Errors
    ///
    /// Rejects schema, identity, phase, transition, or digest mutation.
    pub fn verify(&self) -> Result<(), EncryptionGenerationDistributionError> {
        validate_recipient(&self.recipient)?;
        self.checkpoint
            .verify()
            .map_err(EncryptionGenerationDistributionError::InvalidCheckpoint)?;
        if self.schema_version != ENCRYPTION_GENERATION_CAPSULE_SCHEMA_VERSION
            || self.controller_epoch == 0
            || self.request_nonce == [0; 32]
            || self.checkpoint.transaction.phase != FastPathMapTransactionPhase::Prepared
            || self.capsule_digest != self.calculate_digest()?
        {
            return Err(EncryptionGenerationDistributionError::InvalidCapsule);
        }
        Ok(())
    }

    /// Admits the response against the exact request and durable predecessor.
    ///
    /// # Errors
    ///
    /// Rejects replay to another nonce/Node, controller rollback, local UID
    /// replacement, skipped predecessors, or generation mutation/regression.
    pub fn admit(
        &self,
        request: &EncryptionGenerationRequest,
        current: Option<&AdmittedEncryptionGeneration>,
    ) -> Result<AdmittedEncryptionGeneration, EncryptionGenerationDistributionError> {
        self.verify()?;
        request.verify()?;
        if self.request_nonce != request.nonce
            || self.recipient.node_name != request.node_name
            || request.current
                != current
                    .map(|generation| {
                        generation.verify()?;
                        Ok(generation.cursor())
                    })
                    .transpose()?
        {
            return Err(EncryptionGenerationDistributionError::RequestMismatch);
        }
        if let Some(current) = current {
            if self.recipient != current.recipient {
                return Err(EncryptionGenerationDistributionError::RecipientMismatch);
            }
            if self.checkpoint.transaction.prior != Some(current.published()) {
                return Err(EncryptionGenerationDistributionError::PredecessorMismatch);
            }
            if self.checkpoint.transaction.desired.published.generation
                <= current.published().generation
            {
                return Err(EncryptionGenerationDistributionError::GenerationRegression);
            }
        } else if self.checkpoint.transaction.prior.is_some() {
            return Err(EncryptionGenerationDistributionError::PredecessorMismatch);
        }
        let mut admitted = AdmittedEncryptionGeneration {
            schema_version: ADMITTED_ENCRYPTION_GENERATION_SCHEMA_VERSION,
            controller_epoch: self.controller_epoch,
            recipient: self.recipient.clone(),
            checkpoint: self.checkpoint.clone(),
            admitted_digest: AdmittedEncryptionGenerationDigest([0; 32]),
        };
        admitted.admitted_digest = admitted.calculate_digest()?;
        admitted.verify()?;
        Ok(admitted)
    }

    fn calculate_digest(
        &self,
    ) -> Result<EncryptionGenerationCapsuleDigest, EncryptionGenerationDistributionError> {
        let mut canonical = self.clone();
        canonical.capsule_digest = EncryptionGenerationCapsuleDigest([0; 32]);
        hash_canonical(CAPSULE_DIGEST_DOMAIN, &canonical).map(EncryptionGenerationCapsuleDigest)
    }
}

impl AdmittedEncryptionGeneration {
    #[must_use]
    pub const fn published(&self) -> FastPathPublishedGeneration {
        self.checkpoint.transaction.desired.published
    }

    #[must_use]
    pub fn cursor(&self) -> EncryptionGenerationCursor {
        EncryptionGenerationCursor {
            controller_epoch: self.controller_epoch,
            recipient: self.recipient.clone(),
            published: self.published(),
        }
    }

    /// # Errors
    ///
    /// Rejects durable schema, identity, checkpoint, phase, or digest drift.
    pub fn verify(&self) -> Result<(), EncryptionGenerationDistributionError> {
        validate_recipient(&self.recipient)?;
        self.checkpoint
            .verify()
            .map_err(EncryptionGenerationDistributionError::InvalidCheckpoint)?;
        if self.schema_version != ADMITTED_ENCRYPTION_GENERATION_SCHEMA_VERSION
            || self.controller_epoch == 0
            || self.checkpoint.transaction.phase != FastPathMapTransactionPhase::Prepared
            || self.admitted_digest != self.calculate_digest()?
        {
            return Err(EncryptionGenerationDistributionError::InvalidAdmittedGeneration);
        }
        Ok(())
    }

    fn calculate_digest(
        &self,
    ) -> Result<AdmittedEncryptionGenerationDigest, EncryptionGenerationDistributionError> {
        let mut canonical = self.clone();
        canonical.admitted_digest = AdmittedEncryptionGenerationDigest([0; 32]);
        hash_canonical(ADMITTED_DIGEST_DOMAIN, &canonical).map(AdmittedEncryptionGenerationDigest)
    }
}

pub(crate) fn validate_recipient(
    recipient: &EncryptionGenerationRecipient,
) -> Result<(), EncryptionGenerationDistributionError> {
    if !valid_identity(&recipient.node_name) || !valid_identity(&recipient.node_uid) {
        return Err(EncryptionGenerationDistributionError::InvalidRecipient);
    }
    Ok(())
}

fn validate_published(
    published: &FastPathPublishedGeneration,
) -> Result<(), EncryptionGenerationDistributionError> {
    if published.generation.get() == 0
        || published.policy_revision.get() == 0
        || published.service_revision.get() == 0
        || published.egress_revision.get() == 0
        || published.bank >= ENCRYPTION_BANK_COUNT
        || published.epoch_count > 2
        || published.decision_count > ENCRYPTION_DECISION_MAP_CAPACITY
        || published.transport_count > ENCRYPTION_TRANSPORT_MAP_CAPACITY
        || published.state_digest.0 == [0; 32]
    {
        return Err(EncryptionGenerationDistributionError::InvalidRequest);
    }
    Ok(())
}

fn valid_identity(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_NODE_IDENTITY_BYTES
        && !value.chars().any(char::is_control)
}

fn hash_canonical<T: Serialize>(
    domain: &[u8],
    value: &T,
) -> Result<[u8; 32], EncryptionGenerationDistributionError> {
    let encoded = serde_json::to_vec(value).map_err(|error| {
        EncryptionGenerationDistributionError::CanonicalEncoding(error.to_string())
    })?;
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(encoded);
    Ok(hasher.finalize().into())
}

#[derive(Debug, Error)]
pub enum EncryptionGenerationDistributionError {
    #[error("invalid encryption generation pull request")]
    InvalidRequest,
    #[error("invalid encryption generation recipient")]
    InvalidRecipient,
    #[error("encryption generation recipient does not match local Node identity")]
    RecipientMismatch,
    #[error("invalid proof-carrying encryption checkpoint: {0}")]
    InvalidCheckpoint(FastPathTransactionError),
    #[error("invalid encryption generation transition")]
    InvalidTransition,
    #[error("encryption generation regressed or replayed")]
    GenerationRegression,
    #[error("encryption generation predecessor differs from the durable cursor")]
    PredecessorMismatch,
    #[error("encryption capsule does not answer the exact request")]
    RequestMismatch,
    #[error("invalid or mutated Node-sealed encryption generation capsule")]
    InvalidCapsule,
    #[error("invalid or mutated admitted encryption generation")]
    InvalidAdmittedGeneration,
    #[error("operating-system randomness failed: {0}")]
    Randomness(String),
    #[error("canonical encryption distribution encoding failed: {0}")]
    CanonicalEncoding(String),
}
