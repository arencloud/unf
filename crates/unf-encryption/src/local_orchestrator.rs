//! Capability-typed Node-local generation proof ladder.
//!
//! A Node proposal, controller admission, route proof, and Aya activation are
//! deliberately different Rust types. Each transition consumes the preceding
//! capability, so callers cannot reorder the proof ladder or reuse a route
//! permit across generations. No serialized value becomes kernel authority.

use thiserror::Error;
use unf_common::Revision;

use crate::{
    AdmittedEncryptionGeneration, EncryptionActivationLatch, EncryptionActivationLatchError,
    EncryptionGenerationDistributionError, EncryptionGenerationFact, EncryptionGenerationFactError,
    EncryptionGenerationRecipient, EncryptionRoutePublicationPermit, FastPathMapCheckpoint,
    FastPathPublishedGeneration,
};

/// Retryable, secret-free Node proposal. This value is intentionally not the
/// authority to mutate maps; it only produces the authenticated controller fact.
#[derive(Debug, Clone)]
pub struct NodeLocalGenerationProposal {
    fact: EncryptionGenerationFact,
}

/// Single-use proof that the controller returned the exact Node proposal.
/// It is intentionally neither `Clone` nor serializable.
pub struct ControllerAdmittedLocalGeneration {
    admitted: AdmittedEncryptionGeneration,
}

impl NodeLocalGenerationProposal {
    /// Begins the proof ladder from one independently prepared Node checkpoint.
    ///
    /// # Errors
    ///
    /// Rejects malformed membership, recipient, or checkpoint authority.
    pub fn issue(
        membership_revision: Revision,
        recipient: EncryptionGenerationRecipient,
        checkpoint: FastPathMapCheckpoint,
    ) -> Result<Self, NodeLocalOrchestratorError> {
        let fact = EncryptionGenerationFact::issue(membership_revision, recipient, checkpoint)
            .map_err(NodeLocalOrchestratorError::InvalidFact)?;
        Ok(Self { fact })
    }

    /// Returns the exact retryable public fact for authenticated submission.
    #[must_use]
    pub fn fact(&self) -> &EncryptionGenerationFact {
        &self.fact
    }

    /// Consumes the local proposal only when controller admission returns the
    /// byte-exact checkpoint and Node identity originally proposed.
    ///
    /// # Errors
    ///
    /// Rejects malformed, cross-Node, or substituted controller admission.
    pub fn bind_controller_admission(
        self,
        admitted: AdmittedEncryptionGeneration,
    ) -> Result<ControllerAdmittedLocalGeneration, NodeLocalOrchestratorError> {
        self.fact
            .verify()
            .map_err(NodeLocalOrchestratorError::InvalidFact)?;
        admitted
            .verify()
            .map_err(NodeLocalOrchestratorError::InvalidAdmission)?;
        if admitted.recipient != self.fact.recipient || admitted.checkpoint != self.fact.checkpoint
        {
            return Err(NodeLocalOrchestratorError::ControllerSubstitution);
        }
        Ok(ControllerAdmittedLocalGeneration { admitted })
    }
}

impl ControllerAdmittedLocalGeneration {
    /// Consumes the controller-bound step and one fresh Node-local route permit
    /// to create the existing single-use tri-plane Aya latch.
    ///
    /// # Errors
    ///
    /// Rejects a wrong predecessor, Node, generation, fast-path image, or route
    /// authority. The permit cannot be recovered after this call.
    pub fn authorize_map_activation(
        self,
        applied: Option<FastPathPublishedGeneration>,
        route_permit: EncryptionRoutePublicationPermit,
    ) -> Result<EncryptionActivationLatch, NodeLocalOrchestratorError> {
        let recipient = self.admitted.recipient.clone();
        EncryptionActivationLatch::issue(&self.admitted, &recipient, applied, route_permit)
            .map_err(NodeLocalOrchestratorError::InvalidActivation)
    }

    #[must_use]
    pub const fn admitted(&self) -> &AdmittedEncryptionGeneration {
        &self.admitted
    }
}

#[derive(Debug, Error)]
pub enum NodeLocalOrchestratorError {
    #[error("invalid Node-local generation fact: {0}")]
    InvalidFact(EncryptionGenerationFactError),
    #[error("invalid controller generation admission: {0}")]
    InvalidAdmission(EncryptionGenerationDistributionError),
    #[error("controller admission substituted the Node-local prepared generation")]
    ControllerSubstitution,
    #[error("Node-local activation proof ladder failed: {0}")]
    InvalidActivation(EncryptionActivationLatchError),
}
