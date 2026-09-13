//! Replayable exact-address placement evidence for Required locality.
//!
//! This is not policy permission, kernel route/attachment proof, an encrypted
//! path witness, or a plaintext fallback. The consuming dataplane must establish
//! those independent prerequisites before treating a local tuple as no-underlay.

use std::collections::BTreeMap;
use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use unf_common::{IdentityId, Revision};

use crate::{
    EncryptionEndpointAddressFact, EncryptionGenerationRecipient, IpPrefix,
    KubernetesEncryptionPlacement, MAX_ENCRYPTION_ENDPOINT_ADDRESSES, MAX_ENCRYPTION_ENDPOINTS,
    MAX_ENCRYPTION_PREFIXES_PER_NODE, derive_wireguard_proof_addresses,
};

pub const ENCRYPTION_LOCALITY_CERTIFICATE_SCHEMA_VERSION: u16 = 1;
const LOCALITY_DIGEST_DOMAIN: &[u8] = b"unf.encryption-locality-certificate.v1\0";

/// Independently observed placement coordinates; never inferred from a digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EncryptionLocalityContext {
    pub cluster_id: String,
    pub recipient: EncryptionGenerationRecipient,
    pub membership_revision: Revision,
    pub identity_epoch: u64,
    pub identity_revision: Revision,
    pub routing_revision: Revision,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EncryptionLocalityDigest(pub [u8; 32]);

/// Canonical placement certificate. Deserialization does not admit authority.
/// Its digest is an integrity checksum, not a signature or proof of delivery.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EncryptionLocalityCertificate {
    schema_version: u16,
    context: EncryptionLocalityContext,
    pod_cidrs: Vec<IpPrefix>,
    addresses: Vec<EncryptionEndpointAddressFact>,
    certificate_digest: EncryptionLocalityDigest,
}

/// Constructed only by independent replay; not deserializable or mutable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedEncryptionLocality {
    certificate: EncryptionLocalityCertificate,
}

/// Both exact owners are local in the replayed cut. This carries no verdict,
/// transport disposition, fwmark, device index, route or cryptographic lease.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncryptionLocalTuple<'a> {
    pub source: &'a EncryptionEndpointAddressFact,
    pub destination: &'a EncryptionEndpointAddressFact,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum EncryptionLocalityError {
    #[error("invalid or foreign locality context")]
    InvalidContext,
    #[error("invalid locality certificate shape or address ownership")]
    InvalidShape,
    #[error("locality certificate digest mismatch")]
    IntegrityMismatch,
    #[error("locality certificate does not match current placement")]
    PlacementMismatch,
    #[error("cannot encode locality certificate: {0}")]
    Encoding(String),
}

impl EncryptionLocalityCertificate {
    /// Issues placement evidence only, without enumerating identity pairs.
    ///
    /// # Errors
    ///
    /// Rejects invalid revisions, foreign recipient/cluster, or malformed local
    /// address ownership. Empty local placement is a valid explicit empty cut.
    pub fn issue(
        context: EncryptionLocalityContext,
        placement: &KubernetesEncryptionPlacement,
    ) -> Result<Self, EncryptionLocalityError> {
        validate_context(&context)?;
        if context.cluster_id != placement.cluster_id() {
            return Err(EncryptionLocalityError::InvalidContext);
        }
        let node = placement
            .nodes()
            .iter()
            .find(|node| {
                node.name == context.recipient.node_name && node.uid == context.recipient.node_uid
            })
            .ok_or(EncryptionLocalityError::InvalidContext)?;
        let mut pod_cidrs = node.pod_cidrs.clone();
        pod_cidrs.sort_unstable();
        pod_cidrs.dedup();
        let addresses = placement
            .addresses()
            .iter()
            .filter(|owner| owner.node_uid == context.recipient.node_uid)
            .cloned()
            .collect();
        let mut certificate = Self {
            schema_version: ENCRYPTION_LOCALITY_CERTIFICATE_SCHEMA_VERSION,
            context,
            pod_cidrs,
            addresses,
            certificate_digest: EncryptionLocalityDigest([0; 32]),
        };
        certificate.validate_shape()?;
        certificate.certificate_digest = certificate.digest()?;
        Ok(certificate)
    }

    #[must_use]
    pub fn context(&self) -> &EncryptionLocalityContext {
        &self.context
    }

    #[must_use]
    pub const fn certificate_digest(&self) -> EncryptionLocalityDigest {
        self.certificate_digest
    }

    #[must_use]
    pub fn addresses(&self) -> &[EncryptionEndpointAddressFact] {
        &self.addresses
    }

    /// Checks structure and checksum, not authenticity or current placement.
    ///
    /// # Errors
    ///
    /// Rejects unsupported schema, invalid/noncanonical ownership and tampering.
    pub fn verify_integrity(&self) -> Result<(), EncryptionLocalityError> {
        self.validate_shape()?;
        if self.certificate_digest != self.digest()? {
            return Err(EncryptionLocalityError::IntegrityMismatch);
        }
        Ok(())
    }

    /// Replays against independently authenticated, current placement/context.
    /// The caller must not derive either expected input from this certificate.
    ///
    /// # Errors
    ///
    /// Rejects corrupted, stale, incomplete, substituted or foreign evidence.
    pub fn verify_against(
        &self,
        expected: &EncryptionLocalityContext,
        placement: &KubernetesEncryptionPlacement,
    ) -> Result<VerifiedEncryptionLocality, EncryptionLocalityError> {
        self.verify_integrity()?;
        let replayed = Self::issue(expected.clone(), placement)?;
        if self != &replayed {
            return Err(EncryptionLocalityError::PlacementMismatch);
        }
        Ok(VerifiedEncryptionLocality {
            certificate: replayed,
        })
    }

    fn validate_shape(&self) -> Result<(), EncryptionLocalityError> {
        validate_context(&self.context)?;
        if self.schema_version != ENCRYPTION_LOCALITY_CERTIFICATE_SCHEMA_VERSION
            || self.pod_cidrs.is_empty()
            || self.pod_cidrs.len() > MAX_ENCRYPTION_PREFIXES_PER_NODE
            || self.pod_cidrs.iter().any(|prefix| !prefix.is_canonical())
            || self.pod_cidrs.windows(2).any(|pair| pair[0] >= pair[1])
            || self.addresses.len() > MAX_ENCRYPTION_ENDPOINT_ADDRESSES
            || self
                .addresses
                .windows(2)
                .any(|pair| pair[0].address >= pair[1].address)
        {
            return Err(EncryptionLocalityError::InvalidShape);
        }
        let beacons = derive_wireguard_proof_addresses(&self.pod_cidrs)
            .map_err(|_| EncryptionLocalityError::InvalidShape)?;
        let mut identities = BTreeMap::new();
        for owner in &self.addresses {
            if owner.identity.get() == 0
                || !crate::validate_text(&owner.workload_uid)
                || owner.node_uid != self.context.recipient.node_uid
                || !valid_workload_address(owner.address)
                || !self
                    .pod_cidrs
                    .iter()
                    .any(|prefix| prefix.contains(owner.address))
                || beacons.iter().any(|beacon| beacon.address == owner.address)
                || identities
                    .insert(&owner.workload_uid, owner.identity)
                    .is_some_and(|identity| identity != owner.identity)
            {
                return Err(EncryptionLocalityError::InvalidShape);
            }
            if identities.len() > MAX_ENCRYPTION_ENDPOINTS {
                return Err(EncryptionLocalityError::InvalidShape);
            }
        }
        Ok(())
    }

    fn digest(&self) -> Result<EncryptionLocalityDigest, EncryptionLocalityError> {
        // Stream canonical bytes directly into SHA-256 instead of allocating
        // a second, potentially large JSON buffer for the complete address cut.
        let mut writer = LocalityDigestWriter(Sha256::new());
        writer.0.update(LOCALITY_DIGEST_DOMAIN);
        serde_json::to_writer(
            &mut writer,
            &(
                self.schema_version,
                &self.context,
                &self.pod_cidrs,
                &self.addresses,
            ),
        )
        .map_err(|error| EncryptionLocalityError::Encoding(error.to_string()))?;
        Ok(EncryptionLocalityDigest(writer.0.finalize().into()))
    }
}

struct LocalityDigestWriter(Sha256);

impl std::io::Write for LocalityDigestWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl VerifiedEncryptionLocality {
    #[must_use]
    pub fn certificate(&self) -> &EncryptionLocalityCertificate {
        &self.certificate
    }

    /// Resolves exact owners with two binary searches, without per-pair state.
    /// The final post-Service backend address is required, never a Service VIP.
    /// `None` means locality is unproven, not Native transport permission.
    ///
    /// # Errors
    ///
    /// Rejects a changed expected cut, including identity epoch and Node UID.
    /// This metadata lookup cannot replace current kernel attachment/route and
    /// policy checks at the later consuming boundary.
    pub fn local_tuple(
        &self,
        expected: &EncryptionLocalityContext,
        source_identity: IdentityId,
        source_address: IpAddr,
        destination_identity: IdentityId,
        destination_address: IpAddr,
    ) -> Result<Option<EncryptionLocalTuple<'_>>, EncryptionLocalityError> {
        if expected != &self.certificate.context {
            return Err(EncryptionLocalityError::InvalidContext);
        }
        if source_address.is_ipv4() != destination_address.is_ipv4() {
            return Ok(None);
        }
        Ok(self
            .owner(source_identity, source_address)
            .zip(self.owner(destination_identity, destination_address))
            .map(|(source, destination)| EncryptionLocalTuple {
                source,
                destination,
            }))
    }

    fn owner(
        &self,
        identity: IdentityId,
        address: IpAddr,
    ) -> Option<&EncryptionEndpointAddressFact> {
        let owners = &self.certificate.addresses;
        let index = owners
            .binary_search_by_key(&address, |owner| owner.address)
            .ok()?;
        let owner = &owners[index];
        (owner.identity == identity).then_some(owner)
    }
}

fn validate_context(context: &EncryptionLocalityContext) -> Result<(), EncryptionLocalityError> {
    if !crate::validate_text(&context.cluster_id)
        || !crate::validate_text(&context.recipient.node_name)
        || !crate::validate_text(&context.recipient.node_uid)
        || context.membership_revision.get() == 0
        || context.identity_epoch == 0
        || context.identity_revision.get() == 0
        || context.routing_revision.get() == 0
    {
        return Err(EncryptionLocalityError::InvalidContext);
    }
    Ok(())
}

fn valid_workload_address(address: IpAddr) -> bool {
    if address.is_unspecified() || address.is_loopback() || address.is_multicast() {
        return false;
    }
    match address {
        IpAddr::V4(address) => !address.is_broadcast() && !address.is_link_local(),
        IpAddr::V6(address) => {
            !address.is_unicast_link_local() && address.to_ipv4_mapped().is_none()
        }
    }
}

#[cfg(test)]
mod tests;
