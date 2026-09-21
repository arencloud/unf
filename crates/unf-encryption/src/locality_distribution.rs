//! Nonce-bound placement distribution over the independently authenticated
//! controller channel. Checksums and this wire envelope do not authenticate a
//! sender, prove device lifetime, or grant plaintext packet permission.

use std::io::{self, Write};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    EncryptionLocalityCertificate, EncryptionLocalityContext, EncryptionLocalityError,
    KubernetesEncryptionNodeSnapshot, KubernetesEncryptionWorkloadSnapshot,
    VerifiedEncryptionLocality, project_kubernetes_encryption_placement,
};

pub const ENCRYPTION_LOCALITY_DISTRIBUTION_SCHEMA_VERSION: u16 = 1;
/// Includes the certificate and its replay source. Enforced before decoding.
pub const MAX_ENCRYPTION_LOCALITY_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
/// Public compiler input plus its original request, not a serialized capability.
pub const MAX_ENCRYPTION_LOCALITY_CHECKPOINT_BYTES: usize = 32 * 1024 * 1024;

/// Authenticated source retained for exact-cut offline replay. Private fields
/// and no Deserialize prevent confusing an arbitrary decoded file with a
/// captured source. This holds no bank, lease, device, map or packet authority.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CapturedEncryptionLocality {
    schema_version: u16,
    request: EncryptionLocalityRequest,
    response: EncryptionLocalityResponse,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct LocalityCheckpoint {
    schema_version: u16,
    request: EncryptionLocalityRequest,
    response: EncryptionLocalityResponse,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EncryptionLocalityRequest {
    pub schema_version: u16,
    pub context: EncryptionLocalityContext,
    pub nonce: [u8; 32],
}

/// Private fields prevent source replacement after issuance. Deserialization
/// alone is not verification. Source facts must arrive on an authenticated
/// controller connection, independently of the certificate's integrity digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EncryptionLocalityResponse {
    schema_version: u16,
    request_nonce: [u8; 32],
    certificate: EncryptionLocalityCertificate,
    nodes: Vec<KubernetesEncryptionNodeSnapshot>,
    workloads: Vec<KubernetesEncryptionWorkloadSnapshot>,
}

#[derive(Debug, Error)]
pub enum EncryptionLocalityDistributionError {
    #[error("invalid locality request schema, context, or nonce")]
    InvalidRequest,
    #[error("locality response does not match the outstanding request and current applied cut")]
    StaleResponse,
    #[error("locality response exceeds its bounded wire budget")]
    Capacity,
    #[error("invalid locality wire encoding: {0}")]
    Encoding(String),
    #[error("invalid authenticated locality placement: {0}")]
    Placement(String),
    #[error(transparent)]
    Locality(#[from] EncryptionLocalityError),
}

impl EncryptionLocalityRequest {
    /// Each actual fetch needs a fresh, unpredictable nonce. Callers must not
    /// reuse this request after completion or across controller reconnects.
    ///
    /// # Errors
    /// Rejects invalid coordinates or an unavailable OS random source.
    pub fn issue(
        context: EncryptionLocalityContext,
    ) -> Result<Self, EncryptionLocalityDistributionError> {
        let mut nonce = [0; 32];
        getrandom::fill(&mut nonce)
            .map_err(|error| EncryptionLocalityDistributionError::Encoding(error.to_string()))?;
        let request = Self {
            schema_version: ENCRYPTION_LOCALITY_DISTRIBUTION_SCHEMA_VERSION,
            context,
            nonce,
        };
        request.verify()?;
        Ok(request)
    }

    /// # Errors
    /// Rejects unknown schema, empty nonce, and invalid placement coordinates.
    pub fn verify(&self) -> Result<(), EncryptionLocalityDistributionError> {
        if self.schema_version != ENCRYPTION_LOCALITY_DISTRIBUTION_SCHEMA_VERSION
            || self.nonce == [0; 32]
            || super::locality::validate_context(&self.context).is_err()
        {
            return Err(EncryptionLocalityDistributionError::InvalidRequest);
        }
        Ok(())
    }
}

impl EncryptionLocalityResponse {
    /// Issues from one guarded controller cut, without policy-pair expansion.
    /// The caller must authenticate the current recipient before calling this.
    ///
    /// # Errors
    /// Rejects malformed/bounded-out source data and a stale request.
    pub fn issue(
        request: &EncryptionLocalityRequest,
        current: &EncryptionLocalityContext,
        nodes: Vec<KubernetesEncryptionNodeSnapshot>,
        workloads: Vec<KubernetesEncryptionWorkloadSnapshot>,
    ) -> Result<Self, EncryptionLocalityDistributionError> {
        request.verify()?;
        if &request.context != current {
            return Err(EncryptionLocalityDistributionError::StaleResponse);
        }
        check_wire_budget(&(&nodes, &workloads))?;
        let placement = project_kubernetes_encryption_placement(
            &current.cluster_id,
            nodes.clone(),
            workloads.clone(),
        )
        .map_err(|error| EncryptionLocalityDistributionError::Placement(error.to_string()))?;
        let response = Self {
            schema_version: ENCRYPTION_LOCALITY_DISTRIBUTION_SCHEMA_VERSION,
            request_nonce: request.nonce,
            certificate: EncryptionLocalityCertificate::issue(current.clone(), &placement)?,
            nodes,
            workloads,
        };
        check_wire_budget(&response)?;
        Ok(response)
    }

    /// Decodes bytes only after a transport has authenticated the controller.
    /// The HTTP reader must also cap streaming collection at this budget; a
    /// Content-Length header alone is insufficient. Returns placement evidence,
    /// never an admitted generation, route or packet verdict.
    ///
    /// # Errors
    /// Rejects oversized/malformed wire, nonce/context drift, and failed replay.
    pub fn decode_authenticated(
        bytes: &[u8],
        request: &EncryptionLocalityRequest,
        current_applied: &EncryptionLocalityContext,
    ) -> Result<VerifiedEncryptionLocality, EncryptionLocalityDistributionError> {
        request.verify()?;
        if &request.context != current_applied {
            return Err(EncryptionLocalityDistributionError::StaleResponse);
        }
        Self::decode_bounded(bytes)?.replay(request, current_applied)
    }

    /// Capture only after independently authenticated transport. Persist this
    /// source in an owner-only, bounded, atomic file; the returned placement is
    /// still not kernel or packet authority. Each fetch uses a fresh nonce.
    ///
    /// # Errors
    /// Rejects the same bounds, nonce, full-cut and source replay failures as
    /// `decode_authenticated`. Retaining source adds one bounded replay clone.
    pub fn capture_authenticated(
        bytes: &[u8],
        request: &EncryptionLocalityRequest,
        current_applied: &EncryptionLocalityContext,
    ) -> Result<
        (CapturedEncryptionLocality, VerifiedEncryptionLocality),
        EncryptionLocalityDistributionError,
    > {
        request.verify()?;
        if &request.context != current_applied {
            return Err(EncryptionLocalityDistributionError::StaleResponse);
        }
        let response = Self::decode_bounded(bytes)?;
        let verified = response.clone().replay(request, current_applied)?;
        check_wire_budget(&response)?;
        Ok((
            CapturedEncryptionLocality {
                schema_version: 1,
                request: request.clone(),
                response,
            },
            verified,
        ))
    }

    fn decode_bounded(bytes: &[u8]) -> Result<Self, EncryptionLocalityDistributionError> {
        if bytes.len() > MAX_ENCRYPTION_LOCALITY_RESPONSE_BYTES {
            return Err(EncryptionLocalityDistributionError::Capacity);
        }
        serde_json::from_slice(bytes)
            .map_err(|error| EncryptionLocalityDistributionError::Encoding(error.to_string()))
    }

    fn replay(
        self,
        request: &EncryptionLocalityRequest,
        current_applied: &EncryptionLocalityContext,
    ) -> Result<VerifiedEncryptionLocality, EncryptionLocalityDistributionError> {
        request.verify()?;
        if self.schema_version != ENCRYPTION_LOCALITY_DISTRIBUTION_SCHEMA_VERSION
            || self.request_nonce != request.nonce
            || &request.context != current_applied
        {
            return Err(EncryptionLocalityDistributionError::StaleResponse);
        }
        let placement = project_kubernetes_encryption_placement(
            &current_applied.cluster_id,
            self.nodes,
            self.workloads,
        )
        .map_err(|error| EncryptionLocalityDistributionError::Placement(error.to_string()))?;
        Ok(self
            .certificate
            .verify_against(current_applied, &placement)?)
    }
}

impl CapturedEncryptionLocality {
    #[must_use]
    pub fn context(&self) -> &EncryptionLocalityContext {
        &self.request.context
    }

    /// Replay only bytes read from the trusted, root-owned private checkpoint
    /// written by the authenticated receiver. A checksum or JSON file does not
    /// authenticate its origin. The caller must independently establish the
    /// entire current applied cut, and must freshly observe/bind every actual
    /// journal incarnation, device and route before any bank publication.
    ///
    /// This is last-known-good source replay, not a fresh controller response;
    /// the original request/nonce must never be reused for a new network fetch.
    ///
    /// # Errors
    /// Rejects unknown schema/fields, size, full-cut drift and failed independent
    /// source replay. No serialized verified evidence is accepted as authority.
    pub fn replay_private_checkpoint(
        bytes: &[u8],
        current_applied: &EncryptionLocalityContext,
    ) -> Result<VerifiedEncryptionLocality, EncryptionLocalityDistributionError> {
        if bytes.len() > MAX_ENCRYPTION_LOCALITY_CHECKPOINT_BYTES {
            return Err(EncryptionLocalityDistributionError::Capacity);
        }
        let checkpoint: LocalityCheckpoint = serde_json::from_slice(bytes)
            .map_err(|error| EncryptionLocalityDistributionError::Encoding(error.to_string()))?;
        if checkpoint.schema_version != 1 {
            return Err(EncryptionLocalityDistributionError::InvalidRequest);
        }
        check_wire_budget(&checkpoint.response)?;
        checkpoint
            .response
            .replay(&checkpoint.request, current_applied)
    }
}

/// Streaming counting sink avoids allocating a second full JSON envelope just
/// to decide whether a response fits. Serialization stops at the wire budget.
struct WireBudget(usize);

impl Write for WireBudget {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.0 {
            return Err(io::Error::other("locality wire budget exceeded"));
        }
        self.0 -= bytes.len();
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn check_wire_budget(value: &impl Serialize) -> Result<(), EncryptionLocalityDistributionError> {
    serde_json::to_writer(WireBudget(MAX_ENCRYPTION_LOCALITY_RESPONSE_BYTES), value)
        .map_err(|_| EncryptionLocalityDistributionError::Capacity)
}

#[cfg(test)]
mod tests;
