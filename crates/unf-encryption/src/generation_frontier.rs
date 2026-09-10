//! Cluster-complete publication frontier for prepared encryption generations.
//!
//! A controller must not advance fast-path desired state one Node at a time:
//! doing so can strand a slow Node behind a skipped predecessor and create a
//! mixed-revision cluster. This module makes one complete Node set the unit of
//! publication and applies backpressure until every member acknowledges the
//! exact preceding cut.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use unf_common::Revision;

use crate::{
    EncryptionGenerationRecipient, FastPathMapCheckpoint, FastPathMapTransactionPhase,
    FastPathPublishedGeneration, FastPathTransactionError,
};

pub const ENCRYPTION_GENERATION_FRONTIER_SCHEMA_VERSION: u16 = 1;
pub const ENCRYPTION_GENERATION_PRODUCER_CHECKPOINT_SCHEMA_VERSION: u16 = 1;
pub const MAX_ENCRYPTION_GENERATION_FRONTIER_NODES: usize = 4_096;
const FRONTIER_DIGEST_DOMAIN: &[u8] = b"unf.encryption-generation-frontier.v1\0";
const PRODUCER_CHECKPOINT_DIGEST_DOMAIN: &[u8] =
    b"unf.encryption-generation-producer-checkpoint.v1\0";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PreparedNodeEncryptionGeneration {
    pub recipient: EncryptionGenerationRecipient,
    pub checkpoint: FastPathMapCheckpoint,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EncryptionGenerationFrontierDigest(pub [u8; 32]);

/// One atomic, complete desired-state cut across the authoritative Node set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EncryptionGenerationFrontier {
    pub schema_version: u16,
    pub revision: Revision,
    pub members: Vec<EncryptionGenerationRecipient>,
    pub generations: Vec<PreparedNodeEncryptionGeneration>,
    pub frontier_digest: EncryptionGenerationFrontierDigest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EncryptionGenerationAcknowledgement {
    pub recipient: EncryptionGenerationRecipient,
    pub published: FastPathPublishedGeneration,
    pub frontier_digest: EncryptionGenerationFrontierDigest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EncryptionGenerationProducerCheckpointDigest(pub [u8; 32]);

/// Durable anti-entropy image of the exact published cut and its receipts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EncryptionGenerationProducerCheckpoint {
    pub schema_version: u16,
    pub active: Option<EncryptionGenerationFrontier>,
    pub acknowledgements: Vec<EncryptionGenerationAcknowledgement>,
    pub checkpoint_digest: EncryptionGenerationProducerCheckpointDigest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncryptionFrontierPublishOutcome {
    Published,
    Unchanged,
}

/// In-memory publication authority. Durable controller integration is a later
/// boundary; callers cannot advance it past an unacknowledged cluster cut.
#[derive(Debug, Default)]
pub struct EncryptionGenerationProducer {
    active: Option<EncryptionGenerationFrontier>,
    acknowledged: BTreeMap<EncryptionGenerationRecipient, EncryptionGenerationAcknowledgement>,
}

impl EncryptionGenerationFrontier {
    /// Builds one canonical complete frontier from an independently supplied
    /// authoritative membership snapshot.
    ///
    /// # Errors
    ///
    /// Rejects empty/duplicate membership, partial or extra generations,
    /// non-prepared checkpoints, cross-Node transport authority, mixed
    /// revisions, and malformed checkpoints.
    pub fn issue(
        revision: Revision,
        mut authoritative_members: Vec<EncryptionGenerationRecipient>,
        mut generations: Vec<PreparedNodeEncryptionGeneration>,
    ) -> Result<Self, EncryptionGenerationFrontierError> {
        authoritative_members.sort();
        generations.sort_by(|left, right| left.recipient.cmp(&right.recipient));
        let mut frontier = Self {
            schema_version: ENCRYPTION_GENERATION_FRONTIER_SCHEMA_VERSION,
            revision,
            members: authoritative_members,
            generations,
            frontier_digest: EncryptionGenerationFrontierDigest([0; 32]),
        };
        frontier.validate_shape()?;
        frontier.frontier_digest = frontier.calculate_digest()?;
        Ok(frontier)
    }

    /// Replays canonical membership, checkpoint, cross-Node, and digest
    /// validation without trusting the producer that created the frontier.
    ///
    /// # Errors
    ///
    /// Rejects any structural, ordering, authority, or digest mutation.
    pub fn verify(&self) -> Result<(), EncryptionGenerationFrontierError> {
        self.validate_shape()?;
        if self.frontier_digest != self.calculate_digest()? {
            return Err(EncryptionGenerationFrontierError::DigestMismatch);
        }
        Ok(())
    }

    #[must_use]
    pub fn checkpoint_for(
        &self,
        recipient: &EncryptionGenerationRecipient,
    ) -> Option<&FastPathMapCheckpoint> {
        self.generations
            .binary_search_by(|candidate| candidate.recipient.cmp(recipient))
            .ok()
            .map(|index| &self.generations[index].checkpoint)
    }

    fn validate_shape(&self) -> Result<(), EncryptionGenerationFrontierError> {
        let unique_node_names = self
            .members
            .iter()
            .map(|member| member.node_name.as_str())
            .collect::<BTreeSet<_>>();
        let unique_node_uids = self
            .members
            .iter()
            .map(|member| member.node_uid.as_str())
            .collect::<BTreeSet<_>>();
        if self.schema_version != ENCRYPTION_GENERATION_FRONTIER_SCHEMA_VERSION
            || self.revision == Revision::INITIAL
            || self.members.is_empty()
            || self.members.len() > MAX_ENCRYPTION_GENERATION_FRONTIER_NODES
            || unique_node_names.len() != self.members.len()
            || unique_node_uids.len() != self.members.len()
            || self.members.windows(2).any(|pair| pair[0] >= pair[1])
            || self
                .generations
                .windows(2)
                .any(|pair| pair[0].recipient >= pair[1].recipient)
        {
            return Err(EncryptionGenerationFrontierError::InvalidShape);
        }
        if self.generations.len() != self.members.len() {
            return Err(EncryptionGenerationFrontierError::IncompleteMembership);
        }
        let generated_members = self
            .generations
            .iter()
            .map(|generation| generation.recipient.clone())
            .collect::<Vec<_>>();
        if generated_members != self.members {
            return Err(EncryptionGenerationFrontierError::IncompleteMembership);
        }
        let mut common_revisions = None;
        let mut common_trust_domain = None;
        for generation in &self.generations {
            super::generation_distribution::validate_recipient(&generation.recipient)
                .map_err(|_| EncryptionGenerationFrontierError::InvalidRecipient)?;
            generation
                .checkpoint
                .verify()
                .map_err(EncryptionGenerationFrontierError::InvalidCheckpoint)?;
            let transaction = &generation.checkpoint.transaction;
            let published = transaction.desired.published;
            let trust_domains = generation
                .checkpoint
                .transport_authority
                .iter()
                .map(|transport| transport.trust_domain.as_str())
                .collect::<BTreeSet<_>>();
            let dormant = published.epoch_count == 0
                && published.transport_count == 0
                && generation.checkpoint.transport_authority.is_empty();
            if transaction.phase != FastPathMapTransactionPhase::Prepared
                || transaction.transaction_revision != self.revision
                || published.generation != self.revision
                || if dormant {
                    !trust_domains.is_empty()
                } else {
                    trust_domains.len() != 1
                }
                || generation
                    .checkpoint
                    .transport_authority
                    .iter()
                    .any(|transport| transport.local_node_uid != generation.recipient.node_uid)
            {
                return Err(EncryptionGenerationFrontierError::CrossDomainAuthority);
            }
            if let Some(trust_domain) = trust_domains.first() {
                let trust_domain = (*trust_domain).to_owned();
                if common_trust_domain
                    .replace(trust_domain.clone())
                    .is_some_and(|seen| seen != trust_domain)
                {
                    return Err(EncryptionGenerationFrontierError::CrossDomainAuthority);
                }
            }
            let revisions = (
                published.policy_revision,
                published.service_revision,
                published.egress_revision,
            );
            if common_revisions
                .replace(revisions)
                .is_some_and(|seen| seen != revisions)
            {
                return Err(EncryptionGenerationFrontierError::MixedRevisionCut);
            }
        }
        Ok(())
    }

    fn calculate_digest(
        &self,
    ) -> Result<EncryptionGenerationFrontierDigest, EncryptionGenerationFrontierError> {
        let mut canonical = self.clone();
        canonical.frontier_digest = EncryptionGenerationFrontierDigest([0; 32]);
        let encoded = serde_json::to_vec(&canonical)
            .map_err(|error| EncryptionGenerationFrontierError::Encoding(error.to_string()))?;
        let mut hasher = Sha256::new();
        hasher.update(FRONTIER_DIGEST_DOMAIN);
        hasher.update(encoded);
        Ok(EncryptionGenerationFrontierDigest(hasher.finalize().into()))
    }
}

impl EncryptionGenerationProducer {
    /// Reconstructs publication authority only from an independently replayed
    /// checkpoint. Serialized receipts never imply local kernel authority.
    ///
    /// # Errors
    ///
    /// Rejects schema/digest mutation, noncanonical or foreign receipts, and
    /// any receipt that does not exactly name the active frontier generation.
    pub fn restore(
        checkpoint: EncryptionGenerationProducerCheckpoint,
    ) -> Result<Self, EncryptionGenerationFrontierError> {
        checkpoint.verify()?;
        let acknowledged = checkpoint
            .acknowledgements
            .into_iter()
            .map(|acknowledgement| (acknowledgement.recipient.clone(), acknowledgement))
            .collect();
        Ok(Self {
            active: checkpoint.active,
            acknowledged,
        })
    }

    /// Creates a canonical proof-carrying anti-entropy checkpoint.
    ///
    /// # Errors
    ///
    /// Returns an encoding error only if canonical JSON serialization fails.
    pub fn checkpoint(
        &self,
    ) -> Result<EncryptionGenerationProducerCheckpoint, EncryptionGenerationFrontierError> {
        let mut checkpoint = EncryptionGenerationProducerCheckpoint {
            schema_version: ENCRYPTION_GENERATION_PRODUCER_CHECKPOINT_SCHEMA_VERSION,
            active: self.active.clone(),
            acknowledgements: self.acknowledged.values().cloned().collect(),
            checkpoint_digest: EncryptionGenerationProducerCheckpointDigest([0; 32]),
        };
        checkpoint.checkpoint_digest = checkpoint.calculate_digest()?;
        checkpoint.verify()?;
        Ok(checkpoint)
    }

    #[must_use]
    pub const fn active(&self) -> Option<&EncryptionGenerationFrontier> {
        self.active.as_ref()
    }

    #[must_use]
    pub fn desired_for(
        &self,
        recipient: &EncryptionGenerationRecipient,
    ) -> Option<&FastPathMapCheckpoint> {
        self.active.as_ref()?.checkpoint_for(recipient)
    }

    /// Atomically publishes a complete successor, but only after every Node
    /// acknowledged the preceding cut. Identical replay is idempotent.
    ///
    /// # Errors
    ///
    /// Rejects partial acknowledgement, membership/UID drift, skipped or
    /// regressing predecessors, and mutated frontiers.
    pub fn publish(
        &mut self,
        candidate: EncryptionGenerationFrontier,
    ) -> Result<EncryptionFrontierPublishOutcome, EncryptionGenerationFrontierError> {
        candidate.verify()?;
        let Some(active) = &self.active else {
            require_initial(&candidate)?;
            self.active = Some(candidate);
            return Ok(EncryptionFrontierPublishOutcome::Published);
        };
        if active == &candidate {
            return Ok(EncryptionFrontierPublishOutcome::Unchanged);
        }
        if self.acknowledged.len() != active.members.len() {
            return Err(EncryptionGenerationFrontierError::PredecessorNotAcknowledged);
        }
        require_successor(active, &candidate)?;
        self.active = Some(candidate);
        self.acknowledged.clear();
        Ok(EncryptionFrontierPublishOutcome::Published)
    }

    /// Records authenticated durable adoption of the exact current Node cut.
    /// This receipt is backpressure, not local kernel or packet proof.
    ///
    /// # Errors
    ///
    /// Rejects an unknown/replaced Node or any stale/mutated generation.
    pub fn acknowledge(
        &mut self,
        recipient: &EncryptionGenerationRecipient,
        published: FastPathPublishedGeneration,
    ) -> Result<bool, EncryptionGenerationFrontierError> {
        let active = self
            .active
            .as_ref()
            .ok_or(EncryptionGenerationFrontierError::NoActiveFrontier)?;
        let expected = active
            .checkpoint_for(recipient)
            .ok_or(EncryptionGenerationFrontierError::UnknownRecipient)?
            .transaction
            .desired
            .published;
        if expected != published {
            return Err(EncryptionGenerationFrontierError::AcknowledgementMismatch);
        }
        let acknowledgement = EncryptionGenerationAcknowledgement {
            recipient: recipient.clone(),
            published,
            frontier_digest: active.frontier_digest,
        };
        Ok(self
            .acknowledged
            .insert(recipient.clone(), acknowledgement)
            .is_none())
    }

    #[must_use]
    pub fn is_fully_acknowledged(&self) -> bool {
        self.active
            .as_ref()
            .is_none_or(|active| self.acknowledged.len() == active.members.len())
    }
}

impl EncryptionGenerationProducerCheckpoint {
    /// Replays the complete active cut and every exact receipt.
    ///
    /// # Errors
    ///
    /// Rejects unsupported schema, noncanonical ordering, unknown Nodes,
    /// cross-frontier receipts, generation drift, and digest mutation.
    pub fn verify(&self) -> Result<(), EncryptionGenerationFrontierError> {
        if self.schema_version != ENCRYPTION_GENERATION_PRODUCER_CHECKPOINT_SCHEMA_VERSION
            || self
                .acknowledgements
                .windows(2)
                .any(|pair| pair[0].recipient >= pair[1].recipient)
        {
            return Err(EncryptionGenerationFrontierError::InvalidProducerCheckpoint);
        }
        match &self.active {
            None if !self.acknowledgements.is_empty() => {
                return Err(EncryptionGenerationFrontierError::InvalidProducerCheckpoint);
            }
            None => {}
            Some(active) => {
                active.verify()?;
                if self.acknowledgements.len() > active.members.len() {
                    return Err(EncryptionGenerationFrontierError::InvalidProducerCheckpoint);
                }
                for acknowledgement in &self.acknowledgements {
                    super::generation_distribution::validate_recipient(&acknowledgement.recipient)
                        .map_err(|_| {
                            EncryptionGenerationFrontierError::InvalidProducerCheckpoint
                        })?;
                    let expected = active
                        .checkpoint_for(&acknowledgement.recipient)
                        .ok_or(EncryptionGenerationFrontierError::InvalidProducerCheckpoint)?
                        .transaction
                        .desired
                        .published;
                    if acknowledgement.published != expected
                        || acknowledgement.frontier_digest != active.frontier_digest
                    {
                        return Err(EncryptionGenerationFrontierError::InvalidProducerCheckpoint);
                    }
                }
            }
        }
        if self.checkpoint_digest != self.calculate_digest()? {
            return Err(EncryptionGenerationFrontierError::ProducerCheckpointDigestMismatch);
        }
        Ok(())
    }

    fn calculate_digest(
        &self,
    ) -> Result<EncryptionGenerationProducerCheckpointDigest, EncryptionGenerationFrontierError>
    {
        let mut canonical = self.clone();
        canonical.checkpoint_digest = EncryptionGenerationProducerCheckpointDigest([0; 32]);
        let encoded = serde_json::to_vec(&canonical)
            .map_err(|error| EncryptionGenerationFrontierError::Encoding(error.to_string()))?;
        let mut hasher = Sha256::new();
        hasher.update(PRODUCER_CHECKPOINT_DIGEST_DOMAIN);
        hasher.update(encoded);
        Ok(EncryptionGenerationProducerCheckpointDigest(
            hasher.finalize().into(),
        ))
    }
}

fn require_initial(
    candidate: &EncryptionGenerationFrontier,
) -> Result<(), EncryptionGenerationFrontierError> {
    if candidate
        .generations
        .iter()
        .any(|generation| generation.checkpoint.transaction.prior.is_some())
    {
        return Err(EncryptionGenerationFrontierError::PredecessorMismatch);
    }
    Ok(())
}

fn require_successor(
    active: &EncryptionGenerationFrontier,
    candidate: &EncryptionGenerationFrontier,
) -> Result<(), EncryptionGenerationFrontierError> {
    active.verify()?;
    if candidate.revision <= active.revision || candidate.members != active.members {
        return Err(EncryptionGenerationFrontierError::MembershipOrRevisionDrift);
    }
    let prior_by_recipient = active
        .generations
        .iter()
        .map(|generation| {
            (
                &generation.recipient,
                generation.checkpoint.transaction.desired.published,
            )
        })
        .collect::<BTreeMap<_, _>>();
    if candidate.generations.iter().any(|generation| {
        generation.checkpoint.transaction.prior
            != prior_by_recipient.get(&generation.recipient).copied()
    }) {
        return Err(EncryptionGenerationFrontierError::PredecessorMismatch);
    }
    Ok(())
}

#[derive(Debug, Error)]
pub enum EncryptionGenerationFrontierError {
    #[error("invalid encryption generation frontier shape")]
    InvalidShape,
    #[error("invalid encryption generation frontier recipient")]
    InvalidRecipient,
    #[error("encryption generation frontier is missing or adds a Node")]
    IncompleteMembership,
    #[error("encryption generation frontier mixes policy, Service, or egress revisions")]
    MixedRevisionCut,
    #[error("prepared generation crosses its Node, revision, or transaction authority")]
    CrossDomainAuthority,
    #[error("invalid prepared encryption checkpoint: {0}")]
    InvalidCheckpoint(FastPathTransactionError),
    #[error("encryption generation frontier digest mismatch")]
    DigestMismatch,
    #[error("cannot advance encryption frontier before every Node acknowledges its predecessor")]
    PredecessorNotAcknowledged,
    #[error("encryption generation frontier membership or revision changed unsafely")]
    MembershipOrRevisionDrift,
    #[error("encryption generation frontier predecessor mismatch")]
    PredecessorMismatch,
    #[error("encryption generation producer has no active frontier")]
    NoActiveFrontier,
    #[error("encryption generation acknowledgement belongs to an unknown or replaced Node")]
    UnknownRecipient,
    #[error("encryption generation acknowledgement differs from current desired state")]
    AcknowledgementMismatch,
    #[error("invalid encryption generation producer checkpoint")]
    InvalidProducerCheckpoint,
    #[error("encryption generation producer checkpoint digest mismatch")]
    ProducerCheckpointDigestMismatch,
    #[error("encode encryption generation frontier: {0}")]
    Encoding(String),
}
