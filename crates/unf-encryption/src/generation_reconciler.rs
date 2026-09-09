//! Authenticated Node-fact reconciliation for complete encryption generations.
//!
//! Each Node prepares its own secret-free map checkpoint from local kernel
//! evidence. The controller admits those reports only against one exact
//! authoritative Kubernetes membership cut and publishes nothing until every
//! member reports the same generation. This deliberately has no majority or
//! best-effort mode: a mixed cluster truth is not encryption authority.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use unf_common::Revision;

use crate::{
    EncryptionGenerationFrontier, EncryptionGenerationFrontierError, EncryptionGenerationRecipient,
    FastPathMapCheckpoint, PreparedNodeEncryptionGeneration,
};

pub const ENCRYPTION_GENERATION_FACT_SCHEMA_VERSION: u16 = 1;
const GENERATION_FACT_DIGEST_DOMAIN: &[u8] = b"unf.encryption-generation-fact.v1\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EncryptionGenerationFactDigest(pub [u8; 32]);

/// One authenticated Node's independently prepared contribution to a fleet
/// generation. It is secret-free and does not transfer local kernel authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EncryptionGenerationFact {
    pub schema_version: u16,
    pub membership_revision: Revision,
    pub recipient: EncryptionGenerationRecipient,
    pub checkpoint: FastPathMapCheckpoint,
    pub fact_digest: EncryptionGenerationFactDigest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncryptionGenerationFactOutcome {
    Accepted,
    Unchanged,
}

/// Exact-membership anti-entropy accumulator. Membership changes invalidate
/// every staged report so Node UIDs from different Kubernetes cuts cannot mix.
#[derive(Debug, Default)]
pub struct EncryptionGenerationFactReconciler {
    membership_revision: Revision,
    members: Vec<EncryptionGenerationRecipient>,
    facts: BTreeMap<EncryptionGenerationRecipient, EncryptionGenerationFact>,
}

impl EncryptionGenerationFact {
    /// Seals a Node-local prepared checkpoint to one membership observation.
    ///
    /// # Errors
    ///
    /// Rejects an initial membership revision or any malformed, non-prepared,
    /// cross-Node checkpoint.
    pub fn issue(
        membership_revision: Revision,
        recipient: EncryptionGenerationRecipient,
        checkpoint: FastPathMapCheckpoint,
    ) -> Result<Self, EncryptionGenerationFactError> {
        let mut fact = Self {
            schema_version: ENCRYPTION_GENERATION_FACT_SCHEMA_VERSION,
            membership_revision,
            recipient,
            checkpoint,
            fact_digest: EncryptionGenerationFactDigest([0; 32]),
        };
        fact.validate_authority()?;
        fact.fact_digest = fact.calculate_digest()?;
        Ok(fact)
    }

    /// Independently replays the fact and its nested map checkpoint.
    ///
    /// # Errors
    ///
    /// Rejects schema, membership, recipient, checkpoint, or digest mutation.
    pub fn verify(&self) -> Result<(), EncryptionGenerationFactError> {
        self.validate_authority()?;
        if self.fact_digest != self.calculate_digest()? {
            return Err(EncryptionGenerationFactError::DigestMismatch);
        }
        Ok(())
    }

    fn validate_authority(&self) -> Result<(), EncryptionGenerationFactError> {
        if self.schema_version != ENCRYPTION_GENERATION_FACT_SCHEMA_VERSION
            || self.membership_revision == Revision::INITIAL
        {
            return Err(EncryptionGenerationFactError::InvalidFact);
        }
        EncryptionGenerationFrontier::issue(
            self.checkpoint.transaction.transaction_revision,
            vec![self.recipient.clone()],
            vec![PreparedNodeEncryptionGeneration {
                recipient: self.recipient.clone(),
                checkpoint: self.checkpoint.clone(),
            }],
        )
        .map_err(EncryptionGenerationFactError::InvalidFrontier)?;
        Ok(())
    }

    fn calculate_digest(
        &self,
    ) -> Result<EncryptionGenerationFactDigest, EncryptionGenerationFactError> {
        let mut canonical = self.clone();
        canonical.fact_digest = EncryptionGenerationFactDigest([0; 32]);
        let encoded = serde_json::to_vec(&canonical)
            .map_err(|error| EncryptionGenerationFactError::Encoding(error.to_string()))?;
        let mut hasher = Sha256::new();
        hasher.update(GENERATION_FACT_DIGEST_DOMAIN);
        hasher.update(encoded);
        Ok(EncryptionGenerationFactDigest(hasher.finalize().into()))
    }
}

impl EncryptionGenerationFactReconciler {
    /// Replaces the complete Kubernetes membership authority. Any revision or
    /// Node name/UID change discards all staged facts as one atomic cut.
    ///
    /// # Errors
    ///
    /// Rejects initial, empty, duplicate, or malformed membership.
    pub fn replace_membership(
        &mut self,
        membership_revision: Revision,
        mut members: Vec<EncryptionGenerationRecipient>,
    ) -> Result<bool, EncryptionGenerationFactError> {
        members.sort();
        let unique_node_names = members
            .iter()
            .map(|member| member.node_name.as_str())
            .collect::<BTreeSet<_>>();
        let unique_node_uids = members
            .iter()
            .map(|member| member.node_uid.as_str())
            .collect::<BTreeSet<_>>();
        if membership_revision == Revision::INITIAL || members.is_empty() {
            return Err(EncryptionGenerationFactError::InvalidMembership);
        }
        if unique_node_names.len() != members.len()
            || unique_node_uids.len() != members.len()
            || members.windows(2).any(|pair| pair[0] >= pair[1])
            || members
                .iter()
                .any(|member| super::generation_distribution::validate_recipient(member).is_err())
        {
            return Err(EncryptionGenerationFactError::InvalidMembership);
        }
        if self.membership_revision == membership_revision && self.members == members {
            return Ok(false);
        }
        self.membership_revision = membership_revision;
        self.members = members;
        self.facts.clear();
        Ok(true)
    }

    /// Admits one independently verified fact without weakening a newer fact.
    ///
    /// # Errors
    ///
    /// Rejects foreign membership, unknown/replaced Nodes, regression, or
    /// equivocation at one generation.
    pub fn observe(
        &mut self,
        fact: EncryptionGenerationFact,
    ) -> Result<EncryptionGenerationFactOutcome, EncryptionGenerationFactError> {
        fact.verify()?;
        if fact.membership_revision != self.membership_revision
            || self.members.binary_search(&fact.recipient).is_err()
        {
            return Err(EncryptionGenerationFactError::ForeignMembership);
        }
        if let Some(current) = self.facts.get(&fact.recipient) {
            let current_revision = current.checkpoint.transaction.transaction_revision;
            let candidate_revision = fact.checkpoint.transaction.transaction_revision;
            if current == &fact {
                return Ok(EncryptionGenerationFactOutcome::Unchanged);
            }
            if candidate_revision == current_revision {
                return Err(EncryptionGenerationFactError::Equivocation);
            }
            if candidate_revision < current_revision {
                return Err(EncryptionGenerationFactError::Regression);
            }
        }
        self.facts.insert(fact.recipient.clone(), fact);
        Ok(EncryptionGenerationFactOutcome::Accepted)
    }

    /// Returns one publishable complete cut only when every authoritative Node
    /// has supplied the same generation. Mixed revisions remain pending.
    ///
    /// # Errors
    ///
    /// Rejects a complete set whose nested frontier facts do not agree.
    pub fn candidate(
        &self,
    ) -> Result<Option<EncryptionGenerationFrontier>, EncryptionGenerationFactError> {
        if self.members.is_empty() || self.facts.len() != self.members.len() {
            return Ok(None);
        }
        let mut revisions = self
            .facts
            .values()
            .map(|fact| fact.checkpoint.transaction.transaction_revision);
        let Some(revision) = revisions.next() else {
            return Ok(None);
        };
        if revisions.any(|candidate| candidate != revision) {
            return Ok(None);
        }
        let generations = self
            .facts
            .values()
            .map(|fact| PreparedNodeEncryptionGeneration {
                recipient: fact.recipient.clone(),
                checkpoint: fact.checkpoint.clone(),
            })
            .collect();
        EncryptionGenerationFrontier::issue(revision, self.members.clone(), generations)
            .map(Some)
            .map_err(EncryptionGenerationFactError::InvalidFrontier)
    }

    #[must_use]
    pub fn observed(&self) -> usize {
        self.facts.len()
    }

    #[must_use]
    pub fn expected(&self) -> usize {
        self.members.len()
    }
}

#[derive(Debug, Error)]
pub enum EncryptionGenerationFactError {
    #[error("invalid encryption generation fact")]
    InvalidFact,
    #[error("invalid encryption generation membership")]
    InvalidMembership,
    #[error("encryption generation fact belongs to a stale or foreign membership cut")]
    ForeignMembership,
    #[error("encryption generation fact regressed")]
    Regression,
    #[error("encryption generation fact equivocated at one generation")]
    Equivocation,
    #[error("encryption generation fact digest mismatch")]
    DigestMismatch,
    #[error("invalid encryption generation frontier: {0}")]
    InvalidFrontier(EncryptionGenerationFrontierError),
    #[error("encode encryption generation fact: {0}")]
    Encoding(String),
}
