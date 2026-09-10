//! Single-use join between remote desired state and Node-local kernel proof.
//!
//! No control-plane payload, route proof, or Aya image can independently
//! publish encryption authority. The latch joins all three at one causal
//! predecessor and is intentionally neither serializable nor cloneable.

use serde::Serialize;
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::{
    AdmittedEncryptionGeneration, AdmittedEncryptionGenerationDigest, EncryptionFastPathState,
    EncryptionGenerationDistributionError, EncryptionGenerationPathProofPermit,
    EncryptionGenerationPathProofWitness, EncryptionGenerationRecipient, EncryptionPathProofError,
    EncryptionRouteAuthorityDigest, EncryptionRouteAuthorityError,
    EncryptionRoutePublicationPermit, FastPathMapCheckpoint, FastPathPublishedGeneration,
    FastPathTransactionError,
};

pub const ENCRYPTION_ACTIVATION_LATCH_SCHEMA_VERSION: u16 = 1;
const ACTIVATION_WITNESS_DOMAIN: &[u8] = b"unf.encryption-activation-latch.v1\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncryptionActivationWitness(pub [u8; 32]);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum EncryptionActivationMode {
    PublishSuccessor,
    RevalidateCurrent,
}

/// Non-transferable, single-use authority joining controller intent with one
/// exact Node-local route permit. It deliberately implements neither `Clone`
/// nor `Serialize`.
pub struct EncryptionActivationLatch {
    admitted: AdmittedEncryptionGeneration,
    route_permit: EncryptionRoutePublicationPermit,
    mode: EncryptionActivationMode,
    witness: EncryptionActivationWitness,
}

/// Verified material consumed by the Aya transaction adapter. Private fields
/// prevent callers from manufacturing a partially joined activation.
pub struct EncryptionActivationMaterial {
    checkpoint: FastPathMapCheckpoint,
    desired: EncryptionFastPathState,
    route_permit: EncryptionRoutePublicationPermit,
    mode: EncryptionActivationMode,
    witness: EncryptionActivationWitness,
}

/// Single-use activation that retains the complete live-path capability until
/// immediately before inactive-bank staging.
pub struct PathProvenEncryptionActivationLatch {
    latch: EncryptionActivationLatch,
    path_permit: EncryptionGenerationPathProofPermit,
    recipient: EncryptionGenerationRecipient,
    path_witness: EncryptionGenerationPathProofWitness,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ActivationWitnessInput<'a> {
    schema_version: u16,
    controller_epoch: u64,
    recipient: &'a EncryptionGenerationRecipient,
    published: FastPathPublishedGeneration,
    admitted_digest: AdmittedEncryptionGenerationDigest,
    route_authority_digest: EncryptionRouteAuthorityDigest,
    mode: EncryptionActivationMode,
}

impl EncryptionActivationLatch {
    /// Joins one durably admitted controller successor with exact local route
    /// evidence at the map adapter's currently published predecessor.
    ///
    /// # Errors
    ///
    /// Rejects cross-Node state, a stale/skipped map predecessor, checkpoint
    /// mutation, or a route permit for any other generation/image.
    pub(crate) fn issue(
        admitted: &AdmittedEncryptionGeneration,
        local_recipient: &EncryptionGenerationRecipient,
        applied: Option<FastPathPublishedGeneration>,
        route_permit: EncryptionRoutePublicationPermit,
    ) -> Result<Self, EncryptionActivationLatchError> {
        admitted
            .verify()
            .map_err(EncryptionActivationLatchError::InvalidDistribution)?;
        if &admitted.recipient != local_recipient {
            return Err(EncryptionActivationLatchError::RecipientMismatch);
        }
        let mode = activation_mode(admitted, applied)?;
        let desired = admitted
            .checkpoint
            .desired_state()
            .map_err(EncryptionActivationLatchError::InvalidCheckpoint)?;
        route_permit
            .verify_for(&desired)
            .map_err(EncryptionActivationLatchError::InvalidRoutePermit)?;
        let witness = activation_witness(admitted, &route_permit, mode)?;
        Ok(Self {
            admitted: admitted.clone(),
            route_permit,
            mode,
            witness,
        })
    }

    #[must_use]
    pub const fn witness(&self) -> EncryptionActivationWitness {
        self.witness
    }

    /// Revalidates and consumes the single-use latch immediately before map
    /// staging. The returned material cannot be constructed by callers.
    ///
    /// # Errors
    ///
    /// Rejects any predecessor movement or joined-proof inconsistency.
    pub fn open(
        self,
        applied: Option<FastPathPublishedGeneration>,
        quarantined: Option<&FastPathMapCheckpoint>,
    ) -> Result<EncryptionActivationMaterial, EncryptionActivationLatchError> {
        self.admitted
            .verify()
            .map_err(EncryptionActivationLatchError::InvalidDistribution)?;
        let mode = activation_mode(&self.admitted, applied)?;
        let desired = self
            .admitted
            .checkpoint
            .desired_state()
            .map_err(EncryptionActivationLatchError::InvalidCheckpoint)?;
        self.route_permit
            .verify_for(&desired)
            .map_err(EncryptionActivationLatchError::InvalidRoutePermit)?;
        if self.mode != mode
            || self.witness != activation_witness(&self.admitted, &self.route_permit, mode)?
        {
            return Err(EncryptionActivationLatchError::WitnessMismatch);
        }
        let checkpoint = match quarantined {
            Some(pending) if mode == EncryptionActivationMode::PublishSuccessor => {
                pending
                    .verify()
                    .map_err(EncryptionActivationLatchError::InvalidCheckpoint)?;
                if !same_activation_transaction(&self.admitted.checkpoint, pending) {
                    return Err(EncryptionActivationLatchError::PendingTransactionMismatch);
                }
                pending.clone()
            }
            Some(_) => return Err(EncryptionActivationLatchError::PendingTransactionMismatch),
            None => self.admitted.checkpoint,
        };
        Ok(EncryptionActivationMaterial {
            checkpoint,
            desired,
            route_permit: self.route_permit,
            mode,
            witness: self.witness,
        })
    }
}

impl PathProvenEncryptionActivationLatch {
    pub(crate) fn issue(
        latch: EncryptionActivationLatch,
        path_permit: EncryptionGenerationPathProofPermit,
        recipient: EncryptionGenerationRecipient,
    ) -> Self {
        let path_witness = path_permit.witness();
        Self {
            latch,
            path_permit,
            recipient,
            path_witness,
        }
    }

    #[must_use]
    pub const fn path_witness(&self) -> EncryptionGenerationPathProofWitness {
        self.path_witness
    }

    #[must_use]
    pub const fn activation_witness(&self) -> EncryptionActivationWitness {
        self.latch.witness()
    }

    /// Consumes and revalidates route, map, and live duplex-path authority at
    /// the final pre-mutation boundary.
    ///
    /// # Errors
    ///
    /// Rejects predecessor movement, route/checkpoint drift, path expiry, or
    /// generation/Node substitution.
    pub fn open(
        self,
        applied: Option<FastPathPublishedGeneration>,
        quarantined: Option<&FastPathMapCheckpoint>,
        now_unix_ms: u64,
    ) -> Result<EncryptionActivationMaterial, EncryptionActivationLatchError> {
        let material = self.latch.open(applied, quarantined)?;
        self.path_permit
            .verify_for(&material.desired, &self.recipient, now_unix_ms)
            .map_err(EncryptionActivationLatchError::InvalidPathProof)?;
        if self.path_witness != self.path_permit.witness() {
            return Err(EncryptionActivationLatchError::WitnessMismatch);
        }
        Ok(material)
    }
}

fn same_activation_transaction(
    distributed: &FastPathMapCheckpoint,
    pending: &FastPathMapCheckpoint,
) -> bool {
    distributed.schema_version == pending.schema_version
        && distributed.transaction.transaction_revision == pending.transaction.transaction_revision
        && distributed.transaction.prior == pending.transaction.prior
        && distributed.transaction.desired == pending.transaction.desired
        && distributed.decision_authority == pending.decision_authority
        && distributed.transport_authority == pending.transport_authority
}

impl EncryptionActivationMaterial {
    #[must_use]
    pub const fn witness(&self) -> EncryptionActivationWitness {
        self.witness
    }

    #[must_use]
    pub const fn mode(&self) -> EncryptionActivationMode {
        self.mode
    }

    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        FastPathMapCheckpoint,
        EncryptionFastPathState,
        EncryptionRoutePublicationPermit,
        EncryptionActivationMode,
    ) {
        (self.checkpoint, self.desired, self.route_permit, self.mode)
    }
}

fn activation_mode(
    admitted: &AdmittedEncryptionGeneration,
    applied: Option<FastPathPublishedGeneration>,
) -> Result<EncryptionActivationMode, EncryptionActivationLatchError> {
    if admitted.checkpoint.transaction.prior == applied {
        Ok(EncryptionActivationMode::PublishSuccessor)
    } else if Some(admitted.published()) == applied {
        Ok(EncryptionActivationMode::RevalidateCurrent)
    } else {
        Err(EncryptionActivationLatchError::PredecessorMismatch)
    }
}

fn activation_witness(
    admitted: &AdmittedEncryptionGeneration,
    route_permit: &EncryptionRoutePublicationPermit,
    mode: EncryptionActivationMode,
) -> Result<EncryptionActivationWitness, EncryptionActivationLatchError> {
    let input = ActivationWitnessInput {
        schema_version: ENCRYPTION_ACTIVATION_LATCH_SCHEMA_VERSION,
        controller_epoch: admitted.controller_epoch,
        recipient: &admitted.recipient,
        published: admitted.published(),
        admitted_digest: admitted.admitted_digest,
        route_authority_digest: route_permit.authority_digest(),
        mode,
    };
    let encoded = serde_json::to_vec(&input)
        .map_err(|error| EncryptionActivationLatchError::Encoding(error.to_string()))?;
    let mut hasher = Sha256::new();
    hasher.update(ACTIVATION_WITNESS_DOMAIN);
    hasher.update(encoded);
    Ok(EncryptionActivationWitness(hasher.finalize().into()))
}

#[derive(Debug, Error)]
pub enum EncryptionActivationLatchError {
    #[error("invalid admitted encryption generation: {0}")]
    InvalidDistribution(EncryptionGenerationDistributionError),
    #[error("admitted encryption generation belongs to a different Node")]
    RecipientMismatch,
    #[error("admitted encryption generation does not follow the active map predecessor")]
    PredecessorMismatch,
    #[error("invalid admitted encryption checkpoint: {0}")]
    InvalidCheckpoint(FastPathTransactionError),
    #[error("local route permit does not authorize the admitted generation: {0}")]
    InvalidRoutePermit(EncryptionRouteAuthorityError),
    #[error("live duplex path proof does not authorize the generation: {0}")]
    InvalidPathProof(EncryptionPathProofError),
    #[error("Required encryption activation has no live duplex path proof")]
    MissingPathProof,
    #[error("encryption activation witness changed before map staging")]
    WitnessMismatch,
    #[error("quarantined encryption transaction differs from the renewed activation latch")]
    PendingTransactionMismatch,
    #[error("encode encryption activation witness: {0}")]
    Encoding(String),
}
