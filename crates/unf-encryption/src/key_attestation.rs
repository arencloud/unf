//! Fleet-synchronous mutual acknowledgement of Node-local key epochs.
//!
//! A transparency snapshot is frozen into one immutable proposal round. Each
//! authenticated Node contributes exactly one row of the reciprocal witness
//! matrix. No Node receives an activation-capable acknowledgement column until
//! the complete N×(N-1) matrix exists, preventing partial-fleet key readiness.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use unf_common::Revision;

use crate::{
    AuthenticatedNodeIdentity, CausalEpochBarrierDigest, EncryptionGenerationRecipient,
    KeyEpochPhase, NodeKeyTransparencyCut, NodeKeyTransparencyCutDigest, PeerEpochAcknowledgement,
};

pub const NODE_KEY_ATTESTATION_SCHEMA_VERSION: u16 = 1;
const ROUND_DIGEST_DOMAIN: &[u8] = b"unf.node-key-attestation-round.v1\0";
const ROW_DIGEST_DOMAIN: &[u8] = b"unf.node-key-attestation-row.v1\0";
const CUT_DIGEST_DOMAIN: &[u8] = b"unf.node-key-attestation-cut.v1\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct NodeKeyAttestationRoundDigest(pub [u8; 32]);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct NodeKeyAttestationRowDigest(pub [u8; 32]);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct NodeKeyAttestationCutDigest(pub [u8; 32]);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct NodeKeyAttestationProposal {
    pub recipient: EncryptionGenerationRecipient,
    pub epoch: u64,
    pub barrier_digest: CausalEpochBarrierDigest,
    pub valid_from_unix_ms: u64,
    pub valid_until_unix_ms: u64,
}

/// Immutable public-key proposal cut used by every participant in one round.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct NodeKeyAttestationRound {
    pub schema_version: u16,
    pub cluster_id: String,
    pub membership_revision: Revision,
    pub members: Vec<EncryptionGenerationRecipient>,
    pub proposals: Vec<NodeKeyAttestationProposal>,
    pub source_transparency_cut_digest: NodeKeyTransparencyCutDigest,
    pub issued_at_unix_ms: u64,
    pub round_digest: NodeKeyAttestationRoundDigest,
}

/// One authenticated Node's exact acknowledgement of every other proposal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct NodeKeyAttestationRow {
    pub schema_version: u16,
    pub round_digest: NodeKeyAttestationRoundDigest,
    pub peer: EncryptionGenerationRecipient,
    pub acknowledgements: Vec<PeerEpochAcknowledgement>,
    pub row_digest: NodeKeyAttestationRowDigest,
}

/// Complete, independently replayable acknowledgement column for one Node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct NodeKeyAttestationCut {
    pub schema_version: u16,
    pub round: NodeKeyAttestationRound,
    pub recipient: EncryptionGenerationRecipient,
    pub acknowledgements: Vec<PeerEpochAcknowledgement>,
    pub cut_digest: NodeKeyAttestationCutDigest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeKeyAttestationOutcome {
    Accepted,
    Idempotent,
}

#[derive(Debug, Default)]
pub struct NodeKeyAttestationLedger {
    round: Option<NodeKeyAttestationRound>,
    rows: BTreeMap<EncryptionGenerationRecipient, NodeKeyAttestationRow>,
}

impl NodeKeyAttestationRound {
    /// Freezes a complete public transparency cut into one reciprocal witness
    /// round. Every multi-Node member must expose exactly one prepared epoch.
    ///
    /// # Errors
    ///
    /// Rejects incomplete, expired, already-progressed, or ambiguous input.
    pub fn issue(
        transparency: &NodeKeyTransparencyCut,
        issued_at_unix_ms: u64,
    ) -> Result<Self, NodeKeyAttestationError> {
        transparency
            .verify()
            .map_err(NodeKeyAttestationError::InvalidTransparencyCut)?;
        if issued_at_unix_ms == 0 {
            return Err(NodeKeyAttestationError::InvalidRound);
        }
        let peer_count = u32::try_from(transparency.members.len().saturating_sub(1))
            .map_err(|_| NodeKeyAttestationError::InvalidRound)?;
        let proposals = transparency
            .members
            .iter()
            .zip(&transparency.publications)
            .map(|(member, publication)| {
                let candidates = publication
                    .epochs
                    .iter()
                    .filter(|epoch| {
                        epoch.phase == KeyEpochPhase::Prepared
                            || transparency.members.len() == 1
                                && epoch.phase == KeyEpochPhase::MutuallyAttested
                    })
                    .collect::<Vec<_>>();
                let [epoch] = candidates.as_slice() else {
                    return Err(NodeKeyAttestationError::AmbiguousProposal);
                };
                if epoch.required_peer_count != peer_count
                    || epoch.acknowledged_peer_count != 0
                    || transparency.members.len() > 1 && epoch.readiness_digest.is_some()
                    || issued_at_unix_ms < epoch.valid_from_unix_ms
                    || issued_at_unix_ms >= epoch.valid_until_unix_ms
                {
                    return Err(NodeKeyAttestationError::InvalidRound);
                }
                Ok(NodeKeyAttestationProposal {
                    recipient: member.clone(),
                    epoch: epoch.epoch,
                    barrier_digest: epoch.barrier_digest,
                    valid_from_unix_ms: epoch.valid_from_unix_ms,
                    valid_until_unix_ms: epoch.valid_until_unix_ms,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let mut round = Self {
            schema_version: NODE_KEY_ATTESTATION_SCHEMA_VERSION,
            cluster_id: transparency.cluster_id.clone(),
            membership_revision: transparency.membership_revision,
            members: transparency.members.clone(),
            proposals,
            source_transparency_cut_digest: transparency.cut_digest,
            issued_at_unix_ms,
            round_digest: NodeKeyAttestationRoundDigest([0; 32]),
        };
        round.round_digest = round.calculate_digest()?;
        round.verify()?;
        Ok(round)
    }

    /// Replays canonical membership, proposal coverage, lifetime, and digest.
    ///
    /// # Errors
    ///
    /// Rejects malformed or mutated rounds.
    pub fn verify(&self) -> Result<(), NodeKeyAttestationError> {
        if self.schema_version != NODE_KEY_ATTESTATION_SCHEMA_VERSION
            || self.cluster_id.is_empty()
            || self.membership_revision == Revision::INITIAL
            || self.members.is_empty()
            || self.proposals.len() != self.members.len()
            || self.issued_at_unix_ms == 0
            || self.members.windows(2).any(|pair| pair[0] >= pair[1])
            || self
                .members
                .iter()
                .zip(&self.proposals)
                .any(|(member, proposal)| {
                    member != &proposal.recipient
                        || proposal.epoch == 0
                        || proposal.valid_from_unix_ms > self.issued_at_unix_ms
                        || proposal.valid_until_unix_ms <= self.issued_at_unix_ms
                })
            || self.round_digest != self.calculate_digest()?
        {
            return Err(NodeKeyAttestationError::InvalidRound);
        }
        Ok(())
    }

    /// Deterministically emits the caller's complete matrix row. The round's
    /// issuance time makes retry and restart byte-identical.
    ///
    /// # Errors
    ///
    /// Rejects a caller absent from the immutable membership cut.
    pub fn row_for(
        &self,
        peer: &EncryptionGenerationRecipient,
    ) -> Result<NodeKeyAttestationRow, NodeKeyAttestationError> {
        self.verify()?;
        let origin = self
            .proposals
            .iter()
            .find(|proposal| &proposal.recipient == peer)
            .ok_or(NodeKeyAttestationError::ForeignPeer)?;
        let acknowledgements = self
            .proposals
            .iter()
            .filter(|proposal| proposal.recipient != *peer)
            .map(|target| PeerEpochAcknowledgement {
                peer_node_uid: peer.node_uid.clone(),
                target_node_uid: target.recipient.node_uid.clone(),
                epoch: target.epoch,
                barrier_digest: target.barrier_digest,
                peer_public_epoch: origin.epoch,
                observed_at_unix_ms: self.issued_at_unix_ms,
            })
            .collect();
        NodeKeyAttestationRow::issue(self, peer.clone(), acknowledgements)
    }

    fn calculate_digest(&self) -> Result<NodeKeyAttestationRoundDigest, NodeKeyAttestationError> {
        let mut canonical = self.clone();
        canonical.round_digest = NodeKeyAttestationRoundDigest([0; 32]);
        hash(ROUND_DIGEST_DOMAIN, &canonical).map(NodeKeyAttestationRoundDigest)
    }
}

impl NodeKeyAttestationRow {
    fn issue(
        round: &NodeKeyAttestationRound,
        peer: EncryptionGenerationRecipient,
        acknowledgements: Vec<PeerEpochAcknowledgement>,
    ) -> Result<Self, NodeKeyAttestationError> {
        let mut row = Self {
            schema_version: NODE_KEY_ATTESTATION_SCHEMA_VERSION,
            round_digest: round.round_digest,
            peer,
            acknowledgements,
            row_digest: NodeKeyAttestationRowDigest([0; 32]),
        };
        row.row_digest = row.calculate_digest()?;
        row.verify(round)?;
        Ok(row)
    }

    /// Replays exact target coverage and every acknowledgement field.
    ///
    /// # Errors
    ///
    /// Rejects a foreign, incomplete, reordered, or mutated row.
    pub fn verify(&self, round: &NodeKeyAttestationRound) -> Result<(), NodeKeyAttestationError> {
        round.verify()?;
        let expected = round
            .members
            .iter()
            .position(|member| member == &self.peer)
            .ok_or(NodeKeyAttestationError::ForeignPeer)?;
        let origin_epoch = round.proposals[expected].epoch;
        let targets = round
            .proposals
            .iter()
            .filter(|proposal| proposal.recipient != self.peer)
            .collect::<Vec<_>>();
        if self.schema_version != NODE_KEY_ATTESTATION_SCHEMA_VERSION
            || self.round_digest != round.round_digest
            || self.acknowledgements.len() != targets.len()
            || self
                .acknowledgements
                .iter()
                .zip(targets)
                .any(|(acknowledgement, target)| {
                    acknowledgement.peer_node_uid != self.peer.node_uid
                        || acknowledgement.target_node_uid != target.recipient.node_uid
                        || acknowledgement.epoch != target.epoch
                        || acknowledgement.barrier_digest != target.barrier_digest
                        || acknowledgement.peer_public_epoch != origin_epoch
                        || acknowledgement.observed_at_unix_ms != round.issued_at_unix_ms
                })
            || self.row_digest != self.calculate_digest()?
        {
            return Err(NodeKeyAttestationError::InvalidRow);
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Result<NodeKeyAttestationRowDigest, NodeKeyAttestationError> {
        let mut canonical = self.clone();
        canonical.row_digest = NodeKeyAttestationRowDigest([0; 32]);
        hash(ROW_DIGEST_DOMAIN, &canonical).map(NodeKeyAttestationRowDigest)
    }
}

impl NodeKeyAttestationCut {
    fn issue(
        round: NodeKeyAttestationRound,
        recipient: EncryptionGenerationRecipient,
        acknowledgements: Vec<PeerEpochAcknowledgement>,
    ) -> Result<Self, NodeKeyAttestationError> {
        let mut cut = Self {
            schema_version: NODE_KEY_ATTESTATION_SCHEMA_VERSION,
            round,
            recipient,
            acknowledgements,
            cut_digest: NodeKeyAttestationCutDigest([0; 32]),
        };
        cut.cut_digest = cut.calculate_digest()?;
        cut.verify()?;
        Ok(cut)
    }

    /// Replays the frozen round and exact authenticated peer column.
    ///
    /// # Errors
    ///
    /// Rejects incomplete, foreign, reordered, or mutated cuts.
    pub fn verify(&self) -> Result<(), NodeKeyAttestationError> {
        self.round.verify()?;
        let target = self
            .round
            .proposals
            .iter()
            .find(|proposal| proposal.recipient == self.recipient)
            .ok_or(NodeKeyAttestationError::ForeignPeer)?;
        let peers = self
            .round
            .proposals
            .iter()
            .filter(|proposal| proposal.recipient != self.recipient)
            .collect::<Vec<_>>();
        if self.schema_version != NODE_KEY_ATTESTATION_SCHEMA_VERSION
            || self.acknowledgements.len() != peers.len()
            || self
                .acknowledgements
                .iter()
                .zip(peers)
                .any(|(acknowledgement, peer)| {
                    acknowledgement.peer_node_uid != peer.recipient.node_uid
                        || acknowledgement.target_node_uid != self.recipient.node_uid
                        || acknowledgement.epoch != target.epoch
                        || acknowledgement.barrier_digest != target.barrier_digest
                        || acknowledgement.peer_public_epoch != peer.epoch
                        || acknowledgement.observed_at_unix_ms != self.round.issued_at_unix_ms
                })
            || self.cut_digest != self.calculate_digest()?
        {
            return Err(NodeKeyAttestationError::InvalidCut);
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Result<NodeKeyAttestationCutDigest, NodeKeyAttestationError> {
        let mut canonical = self.clone();
        canonical.cut_digest = NodeKeyAttestationCutDigest([0; 32]);
        hash(CUT_DIGEST_DOMAIN, &canonical).map(NodeKeyAttestationCutDigest)
    }
}

impl NodeKeyAttestationLedger {
    /// Starts a round once per exact topology membership. Later public phase
    /// updates cannot rewrite the frozen proposal round.
    ///
    /// # Errors
    ///
    /// Rejects malformed transparency, revision rollback, or membership
    /// equivocation.
    pub fn begin_if_needed(
        &mut self,
        transparency: &NodeKeyTransparencyCut,
        issued_at_unix_ms: u64,
    ) -> Result<bool, NodeKeyAttestationError> {
        transparency
            .verify()
            .map_err(NodeKeyAttestationError::InvalidTransparencyCut)?;
        if let Some(current) = &self.round {
            if transparency.membership_revision < current.membership_revision {
                return Err(NodeKeyAttestationError::MembershipRegression);
            }
            if transparency.membership_revision == current.membership_revision {
                if transparency.cluster_id == current.cluster_id
                    && transparency.members == current.members
                {
                    return Ok(false);
                }
                return Err(NodeKeyAttestationError::MembershipEquivocation);
            }
        }
        self.round = Some(NodeKeyAttestationRound::issue(
            transparency,
            issued_at_unix_ms,
        )?);
        self.rows.clear();
        Ok(true)
    }

    #[must_use]
    pub fn round(&self) -> Option<&NodeKeyAttestationRound> {
        self.round.as_ref()
    }

    /// Authenticates and admits one exact reciprocal witness row.
    ///
    /// # Errors
    ///
    /// Rejects an uninitialized, forged, expired, incomplete, or mutated row.
    pub fn observe_row(
        &mut self,
        authenticated: &AuthenticatedNodeIdentity,
        row: NodeKeyAttestationRow,
        now_unix_ms: u64,
    ) -> Result<NodeKeyAttestationOutcome, NodeKeyAttestationError> {
        let round = self
            .round
            .as_ref()
            .ok_or(NodeKeyAttestationError::Uninitialized)?;
        row.verify(round)?;
        if authenticated.cluster_id != round.cluster_id
            || authenticated.node_name != row.peer.node_name
            || authenticated.node_uid != row.peer.node_uid
            || now_unix_ms < round.issued_at_unix_ms
            || round
                .proposals
                .iter()
                .any(|proposal| now_unix_ms >= proposal.valid_until_unix_ms)
        {
            return Err(NodeKeyAttestationError::UnauthenticatedOrExpiredRow);
        }
        if let Some(previous) = self.rows.get(&row.peer) {
            return if previous == &row {
                Ok(NodeKeyAttestationOutcome::Idempotent)
            } else {
                Err(NodeKeyAttestationError::RowMutation)
            };
        }
        self.rows.insert(row.peer.clone(), row);
        Ok(NodeKeyAttestationOutcome::Accepted)
    }

    /// Returns a recipient column only after every member row is present.
    ///
    /// # Errors
    ///
    /// Rejects an uninitialized, foreign, or internally inconsistent cut.
    pub fn complete_cut_for(
        &self,
        recipient: &EncryptionGenerationRecipient,
    ) -> Result<Option<NodeKeyAttestationCut>, NodeKeyAttestationError> {
        let round = self
            .round
            .as_ref()
            .ok_or(NodeKeyAttestationError::Uninitialized)?;
        if round.members.binary_search(recipient).is_err() {
            return Err(NodeKeyAttestationError::ForeignPeer);
        }
        if self.rows.len() != round.members.len() {
            return Ok(None);
        }
        let acknowledgements = round
            .members
            .iter()
            .filter(|peer| *peer != recipient)
            .map(|peer| {
                self.rows
                    .get(peer)
                    .and_then(|row| {
                        row.acknowledgements
                            .iter()
                            .find(|ack| ack.target_node_uid == recipient.node_uid)
                    })
                    .cloned()
                    .ok_or(NodeKeyAttestationError::InvalidCut)
            })
            .collect::<Result<Vec<_>, _>>()?;
        NodeKeyAttestationCut::issue(round.clone(), recipient.clone(), acknowledgements).map(Some)
    }
}

fn hash<T: Serialize>(domain: &[u8], value: &T) -> Result<[u8; 32], NodeKeyAttestationError> {
    let encoded = serde_json::to_vec(value)
        .map_err(|error| NodeKeyAttestationError::Encoding(error.to_string()))?;
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(encoded);
    Ok(hasher.finalize().into())
}

#[derive(Debug, Error)]
pub enum NodeKeyAttestationError {
    #[error("invalid key transparency input: {0}")]
    InvalidTransparencyCut(crate::NodeKeyTransparencyError),
    #[error("key attestation proposal is missing or ambiguous")]
    AmbiguousProposal,
    #[error("invalid key attestation round")]
    InvalidRound,
    #[error("key attestation membership regressed")]
    MembershipRegression,
    #[error("key attestation membership equivocated")]
    MembershipEquivocation,
    #[error("key attestation round is uninitialized")]
    Uninitialized,
    #[error("key attestation peer is outside the exact membership")]
    ForeignPeer,
    #[error("key attestation row is invalid")]
    InvalidRow,
    #[error("key attestation row is unauthenticated or expired")]
    UnauthenticatedOrExpiredRow,
    #[error("key attestation peer mutated its row")]
    RowMutation,
    #[error("key attestation cut is invalid or incomplete")]
    InvalidCut,
    #[error("canonical key attestation encoding failed: {0}")]
    Encoding(String),
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;
    use crate::{NodeKeyAuthority, NodeKeyTransparencyLedger, OsWireGuardKeyGenerator};

    const NOW: u64 = 1_800_000_000_000;

    fn recipient(name: &str) -> EncryptionGenerationRecipient {
        EncryptionGenerationRecipient {
            node_name: name.to_owned(),
            node_uid: format!("uid-{name}"),
        }
    }

    fn identity(member: &EncryptionGenerationRecipient) -> AuthenticatedNodeIdentity {
        AuthenticatedNodeIdentity {
            cluster_id: "cluster-a".to_owned(),
            node_name: member.node_name.clone(),
            node_uid: member.node_uid.clone(),
        }
    }

    fn prepared_fleet() -> (
        Vec<EncryptionGenerationRecipient>,
        Vec<NodeKeyAuthority>,
        NodeKeyTransparencyCut,
    ) {
        let members = vec![recipient("a"), recipient("b"), recipient("c")];
        let peer_uids = members
            .iter()
            .map(|member| member.node_uid.clone())
            .collect::<BTreeSet<_>>();
        let mut authorities = Vec::new();
        let mut transparency = NodeKeyTransparencyLedger::default();
        transparency
            .replace_membership("cluster-a".to_owned(), Revision::new(7), members.clone())
            .unwrap();
        for member in &members {
            let mut authority = NodeKeyAuthority::new(
                "cluster-a".to_owned(),
                member.node_name.clone(),
                member.node_uid.clone(),
            )
            .unwrap();
            let mut required = peer_uids.clone();
            required.remove(&member.node_uid);
            authority
                .prepare_epoch(
                    Revision::new(7),
                    required,
                    NOW,
                    NOW + 100_000,
                    &mut OsWireGuardKeyGenerator,
                )
                .unwrap();
            transparency
                .observe(&identity(member), authority.publication().unwrap())
                .unwrap();
            authorities.push(authority);
        }
        let cut = transparency.complete_cut().unwrap().unwrap();
        (members, authorities, cut)
    }

    #[test]
    fn reciprocal_witness_matrix_releases_only_complete_columns() {
        let (members, mut authorities, transparency) = prepared_fleet();
        let mut ledger = NodeKeyAttestationLedger::default();
        ledger.begin_if_needed(&transparency, NOW + 1).unwrap();
        let round = ledger.round().unwrap().clone();
        for member in &members[..2] {
            ledger
                .observe_row(&identity(member), round.row_for(member).unwrap(), NOW + 2)
                .unwrap();
        }
        assert!(ledger.complete_cut_for(&members[0]).unwrap().is_none());
        ledger
            .observe_row(
                &identity(&members[2]),
                round.row_for(&members[2]).unwrap(),
                NOW + 2,
            )
            .unwrap();

        for (member, authority) in members.iter().zip(&mut authorities) {
            let cut = ledger.complete_cut_for(member).unwrap().unwrap();
            cut.verify().unwrap();
            for acknowledgement in cut.acknowledgements {
                authority
                    .acknowledge_epoch(
                        &acknowledgement.peer_node_uid.clone(),
                        acknowledgement,
                        NOW + 2,
                    )
                    .unwrap();
            }
            assert_eq!(
                authority.epochs()[0].phase(),
                KeyEpochPhase::MutuallyAttested
            );
        }
    }

    #[test]
    fn reciprocal_witness_rows_are_restart_stable_authenticated_and_frozen() {
        let (members, _authorities, transparency) = prepared_fleet();
        let mut ledger = NodeKeyAttestationLedger::default();
        ledger.begin_if_needed(&transparency, NOW + 1).unwrap();
        let round = ledger.round().unwrap().clone();
        let row = round.row_for(&members[0]).unwrap();
        assert_eq!(row, round.row_for(&members[0]).unwrap());
        assert!(matches!(
            ledger.observe_row(&identity(&members[1]), row.clone(), NOW + 2),
            Err(NodeKeyAttestationError::UnauthenticatedOrExpiredRow)
        ));
        assert_eq!(
            ledger
                .observe_row(&identity(&members[0]), row.clone(), NOW + 2)
                .unwrap(),
            NodeKeyAttestationOutcome::Accepted
        );
        assert_eq!(
            ledger
                .observe_row(&identity(&members[0]), row, NOW + 2)
                .unwrap(),
            NodeKeyAttestationOutcome::Idempotent
        );
        assert!(!ledger.begin_if_needed(&transparency, NOW + 3).unwrap());
    }
}
