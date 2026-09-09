//! Complete-cut public-key transparency for plan production.
//!
//! Agents remain the sole private-key owners. The controller can observe and
//! join authenticated public publications, but a plan producer sees them only
//! after every exact current member has contributed one monotonic record.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use unf_common::Revision;

use crate::{
    AuthenticatedNodeIdentity, EncryptionGenerationRecipient, KeyAuthorityError,
    NodeKeyPublication, PublicationAdmission, admit_authenticated_publication,
};

pub const NODE_KEY_TRANSPARENCY_CUT_SCHEMA_VERSION: u16 = 1;
pub const MAX_KEY_TRANSPARENCY_MEMBERS: usize = 4_096;
const NODE_KEY_TRANSPARENCY_CUT_DIGEST_DOMAIN: &[u8] = b"unf.node-key-transparency-cut.v1\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct NodeKeyTransparencyCutDigest(pub [u8; 32]);

/// One public-only, exact-membership view of Node key epochs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct NodeKeyTransparencyCut {
    pub schema_version: u16,
    pub cluster_id: String,
    pub membership_revision: Revision,
    pub members: Vec<EncryptionGenerationRecipient>,
    pub publications: Vec<NodeKeyPublication>,
    pub cut_digest: NodeKeyTransparencyCutDigest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeKeyTransparencyOutcome {
    Accepted,
    Idempotent,
}

#[derive(Debug, Default)]
pub struct NodeKeyTransparencyLedger {
    cluster_id: Option<String>,
    membership_revision: Revision,
    members: Vec<EncryptionGenerationRecipient>,
    publications: BTreeMap<EncryptionGenerationRecipient, NodeKeyPublication>,
}

impl NodeKeyTransparencyCut {
    /// # Errors
    ///
    /// Replays every public publication, exact membership coverage, topology
    /// revision, canonical order, and the domain-separated cut digest.
    pub fn verify(&self) -> Result<(), NodeKeyTransparencyError> {
        validate_membership(&self.cluster_id, self.membership_revision, &self.members)?;
        if self.schema_version != NODE_KEY_TRANSPARENCY_CUT_SCHEMA_VERSION
            || self.publications.len() != self.members.len()
            || self.publications.windows(2).any(|pair| {
                (&pair[0].node_name, &pair[0].node_uid) >= (&pair[1].node_name, &pair[1].node_uid)
            })
        {
            return Err(NodeKeyTransparencyError::InvalidCut);
        }
        for (member, publication) in self.members.iter().zip(&self.publications) {
            publication
                .verify()
                .map_err(NodeKeyTransparencyError::InvalidPublication)?;
            if publication.cluster_id != self.cluster_id
                || publication.node_name != member.node_name
                || publication.node_uid != member.node_uid
                || publication
                    .epochs
                    .iter()
                    .any(|epoch| epoch.topology_revision != self.membership_revision)
            {
                return Err(NodeKeyTransparencyError::InvalidCut);
            }
        }
        if self.cut_digest != self.calculate_digest()? {
            return Err(NodeKeyTransparencyError::InvalidCut);
        }
        Ok(())
    }

    fn issue(
        cluster_id: String,
        membership_revision: Revision,
        members: Vec<EncryptionGenerationRecipient>,
        publications: Vec<NodeKeyPublication>,
    ) -> Result<Self, NodeKeyTransparencyError> {
        let mut cut = Self {
            schema_version: NODE_KEY_TRANSPARENCY_CUT_SCHEMA_VERSION,
            cluster_id,
            membership_revision,
            members,
            publications,
            cut_digest: NodeKeyTransparencyCutDigest([0; 32]),
        };
        cut.cut_digest = cut.calculate_digest()?;
        cut.verify()?;
        Ok(cut)
    }

    fn calculate_digest(&self) -> Result<NodeKeyTransparencyCutDigest, NodeKeyTransparencyError> {
        let mut canonical = self.clone();
        canonical.cut_digest = NodeKeyTransparencyCutDigest([0; 32]);
        let encoded = serde_json::to_vec(&canonical)
            .map_err(|error| NodeKeyTransparencyError::Encoding(error.to_string()))?;
        let mut hasher = Sha256::new();
        hasher.update(NODE_KEY_TRANSPARENCY_CUT_DIGEST_DOMAIN);
        hasher.update(encoded);
        Ok(NodeKeyTransparencyCutDigest(hasher.finalize().into()))
    }
}

impl NodeKeyTransparencyLedger {
    /// Replaces the exact membership frontier. Any real change drops all
    /// observations atomically so publications cannot cross topology cuts.
    ///
    /// # Errors
    ///
    /// Rejects malformed membership, revision rollback, or mutation at one
    /// revision.
    pub fn replace_membership(
        &mut self,
        cluster_id: String,
        membership_revision: Revision,
        mut members: Vec<EncryptionGenerationRecipient>,
    ) -> Result<bool, NodeKeyTransparencyError> {
        members.sort();
        validate_membership(&cluster_id, membership_revision, &members)?;
        if self.membership_revision != Revision::INITIAL {
            if membership_revision < self.membership_revision {
                return Err(NodeKeyTransparencyError::MembershipRegression);
            }
            if membership_revision == self.membership_revision {
                if self.cluster_id.as_deref() == Some(cluster_id.as_str())
                    && self.members == members
                {
                    return Ok(false);
                }
                return Err(NodeKeyTransparencyError::MembershipEquivocation);
            }
        }
        self.cluster_id = Some(cluster_id);
        self.membership_revision = membership_revision;
        self.members = members;
        self.publications.clear();
        Ok(true)
    }

    /// Admits one authenticated public-only Node publication.
    ///
    /// # Errors
    ///
    /// Rejects uninitialized/foreign membership, Node replacement, publication
    /// replay/mutation/regression, or topology-revision mismatch.
    pub fn observe(
        &mut self,
        authenticated: &AuthenticatedNodeIdentity,
        publication: NodeKeyPublication,
    ) -> Result<NodeKeyTransparencyOutcome, NodeKeyTransparencyError> {
        let cluster_id = self
            .cluster_id
            .as_deref()
            .ok_or(NodeKeyTransparencyError::Uninitialized)?;
        let recipient = EncryptionGenerationRecipient {
            node_name: authenticated.node_name.clone(),
            node_uid: authenticated.node_uid.clone(),
        };
        if authenticated.cluster_id != cluster_id
            || self.members.binary_search(&recipient).is_err()
            || publication
                .epochs
                .iter()
                .any(|epoch| epoch.topology_revision != self.membership_revision)
        {
            return Err(NodeKeyTransparencyError::ForeignMembership);
        }
        let admission = admit_authenticated_publication(
            authenticated,
            &publication,
            self.publications.get(&recipient),
        )
        .map_err(NodeKeyTransparencyError::InvalidPublication)?;
        match admission {
            PublicationAdmission::Accepted => {
                self.publications.insert(recipient, publication);
                Ok(NodeKeyTransparencyOutcome::Accepted)
            }
            PublicationAdmission::Idempotent => Ok(NodeKeyTransparencyOutcome::Idempotent),
        }
    }

    /// Returns a cut only after every exact current member has published.
    ///
    /// # Errors
    ///
    /// Rejects any internal inconsistency while sealing the complete cut.
    pub fn complete_cut(&self) -> Result<Option<NodeKeyTransparencyCut>, NodeKeyTransparencyError> {
        if self.membership_revision == Revision::INITIAL
            || self.publications.len() != self.members.len()
        {
            return Ok(None);
        }
        let cluster_id = self
            .cluster_id
            .clone()
            .ok_or(NodeKeyTransparencyError::Uninitialized)?;
        let publications = self
            .members
            .iter()
            .map(|member| {
                self.publications
                    .get(member)
                    .cloned()
                    .ok_or(NodeKeyTransparencyError::InvalidCut)
            })
            .collect::<Result<Vec<_>, _>>()?;
        NodeKeyTransparencyCut::issue(
            cluster_id,
            self.membership_revision,
            self.members.clone(),
            publications,
        )
        .map(Some)
    }
}

fn validate_membership(
    cluster_id: &str,
    membership_revision: Revision,
    members: &[EncryptionGenerationRecipient],
) -> Result<(), NodeKeyTransparencyError> {
    let valid_text = |value: &str| {
        !value.is_empty() && value.len() <= 253 && !value.chars().any(char::is_control)
    };
    if !valid_text(cluster_id)
        || membership_revision == Revision::INITIAL
        || members.is_empty()
        || members.len() > MAX_KEY_TRANSPARENCY_MEMBERS
        || members.windows(2).any(|pair| pair[0] >= pair[1])
        || members
            .iter()
            .any(|member| !valid_text(&member.node_name) || !valid_text(&member.node_uid))
    {
        return Err(NodeKeyTransparencyError::InvalidMembership);
    }
    Ok(())
}

#[derive(Debug, Error)]
pub enum NodeKeyTransparencyError {
    #[error("invalid encryption key-transparency membership")]
    InvalidMembership,
    #[error("encryption key-transparency membership regressed")]
    MembershipRegression,
    #[error("encryption key-transparency membership equivocated at one revision")]
    MembershipEquivocation,
    #[error("encryption key-transparency ledger is uninitialized")]
    Uninitialized,
    #[error("public key publication is outside the exact membership cut")]
    ForeignMembership,
    #[error("invalid authenticated public key publication: {0}")]
    InvalidPublication(KeyAuthorityError),
    #[error("invalid or incomplete public key transparency cut")]
    InvalidCut,
    #[error("canonical public key transparency encoding failed: {0}")]
    Encoding(String),
}
