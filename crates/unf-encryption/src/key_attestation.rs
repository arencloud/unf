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
    KeyEpochPhase, NodeKeyPublication, NodeKeyTransparencyCut, NodeKeyTransparencyCutDigest,
    PeerEpochAcknowledgement,
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
    /// round for a common unfinished epoch. Already-active members may witness
    /// a peer's unfinished activation after controller replacement.
    ///
    /// # Errors
    ///
    /// Rejects incomplete, expired, fully active, or ambiguous input.
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
        // Publications contain at most two epochs. Intersect that bounded set,
        // rather than requiring every peer to have retained the Prepared phase.
        // Never reopen a fully active cut or use a draining/expired predecessor.
        let candidates = transparency.publications[0]
            .epochs
            .iter()
            .filter(|candidate| {
                transparency.publications.iter().all(|publication| {
                    publication.epochs.iter().any(|epoch| {
                        epoch.epoch == candidate.epoch
                            && epoch.phase != KeyEpochPhase::Draining
                            && epoch.topology_revision == transparency.membership_revision
                            && epoch.required_peer_count == peer_count
                            && issued_at_unix_ms >= epoch.valid_from_unix_ms
                            && issued_at_unix_ms < epoch.valid_until_unix_ms
                    })
                }) && transparency.publications.iter().any(|publication| {
                    publication.epochs.iter().any(|epoch| {
                        epoch.epoch == candidate.epoch && epoch.phase != KeyEpochPhase::Active
                    })
                })
            })
            .map(|epoch| epoch.epoch)
            .collect::<Vec<_>>();
        let [common_epoch] = candidates.as_slice() else {
            return Err(NodeKeyAttestationError::AmbiguousProposal);
        };
        let proposals = transparency
            .members
            .iter()
            .zip(&transparency.publications)
            .map(|(member, publication)| {
                let epoch = publication
                    .epochs
                    .iter()
                    .find(|epoch| epoch.epoch == *common_epoch)
                    .ok_or(NodeKeyAttestationError::AmbiguousProposal)?;
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

    /// Binds a witness or activation to the caller's exact retained public epoch.
    /// A controller's digest is not evidence that the local key still exists.
    ///
    /// # Errors
    ///
    /// Rejects foreign identity, changed barrier/lifetime, topology drift,
    /// draining or missing authority, and any expired proposal in the round.
    pub fn verify_publication(
        &self,
        publication: &NodeKeyPublication,
        now_unix_ms: u64,
    ) -> Result<(), NodeKeyAttestationError> {
        self.verify()?;
        publication
            .verify()
            .map_err(|_| NodeKeyAttestationError::InvalidRound)?;
        let proposal = self
            .proposals
            .iter()
            .find(|proposal| {
                proposal.recipient.node_name == publication.node_name
                    && proposal.recipient.node_uid == publication.node_uid
            })
            .ok_or(NodeKeyAttestationError::ForeignPeer)?;
        if self.cluster_id != publication.cluster_id
            || now_unix_ms < self.issued_at_unix_ms
            || self
                .proposals
                .iter()
                .any(|proposal| now_unix_ms >= proposal.valid_until_unix_ms)
            || !publication.epochs.iter().any(|epoch| {
                epoch.epoch == proposal.epoch
                    && epoch.phase != KeyEpochPhase::Draining
                    && epoch.topology_revision == self.membership_revision
                    && epoch.barrier_digest == proposal.barrier_digest
                    && epoch.valid_from_unix_ms == proposal.valid_from_unix_ms
                    && epoch.valid_until_unix_ms == proposal.valid_until_unix_ms
                    && epoch.required_peer_count as usize == self.members.len() - 1
            })
        {
            return Err(NodeKeyAttestationError::InvalidRound);
        }
        Ok(())
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
    /// Starts a round once per exact public proposal cut. Later phase updates
    /// cannot rewrite a frozen round, while a complete fleet-wide successor
    /// epoch may open a new round without manufacturing topology churn.
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
                if transparency.cluster_id != current.cluster_id
                    || transparency.members != current.members
                {
                    return Err(NodeKeyAttestationError::MembershipEquivocation);
                }
                let successor =
                    match NodeKeyAttestationRound::issue(transparency, issued_at_unix_ms) {
                        Ok(successor) => successor,
                        Err(NodeKeyAttestationError::AmbiguousProposal) => return Ok(false),
                        Err(error) => return Err(error),
                    };
                if successor.proposals == current.proposals {
                    return Ok(false);
                }
                if successor
                    .proposals
                    .iter()
                    .zip(&current.proposals)
                    .any(|(next, previous)| next.epoch <= previous.epoch)
                {
                    return Err(NodeKeyAttestationError::ProposalRegression);
                }
                self.round = Some(successor);
                self.rows.clear();
                return Ok(true);
            }
        }
        self.round = Some(
            match NodeKeyAttestationRound::issue(transparency, issued_at_unix_ms) {
                Ok(round) => round,
                Err(NodeKeyAttestationError::AmbiguousProposal) => return Ok(false),
                Err(error) => return Err(error),
            },
        );
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
    #[error("key attestation proposal epoch regressed")]
    ProposalRegression,
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
    use std::{cell::Cell, collections::BTreeSet, rc::Rc};

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

    fn public_cut(
        members: &[EncryptionGenerationRecipient],
        authorities: &[NodeKeyAuthority],
    ) -> NodeKeyTransparencyCut {
        let mut transparency = NodeKeyTransparencyLedger::default();
        transparency
            .replace_membership("cluster-a".to_owned(), Revision::new(7), members.to_vec())
            .unwrap();
        for (member, authority) in members.iter().zip(authorities) {
            transparency
                .observe(&identity(member), authority.publication().unwrap())
                .unwrap();
        }
        transparency.complete_cut().unwrap().unwrap()
    }

    fn complete_round(transparency: &NodeKeyTransparencyCut, now: u64) -> NodeKeyAttestationLedger {
        let mut ledger = NodeKeyAttestationLedger::default();
        assert!(ledger.begin_if_needed(transparency, now).unwrap());
        let round = ledger.round().unwrap().clone();
        for member in &transparency.members {
            ledger
                .observe_row(&identity(member), round.row_for(member).unwrap(), now)
                .unwrap();
        }
        ledger
    }

    #[test]
    fn replacement_resumes_prepared_attested_and_active_peers_without_reopening_active_cut() {
        let (members, mut authorities, transparency) = prepared_fleet();
        let original = complete_round(&transparency, NOW + 1);
        for index in 1..3 {
            for ack in original
                .complete_cut_for(&members[index])
                .unwrap()
                .unwrap()
                .acknowledgements
            {
                authorities[index]
                    .acknowledge_epoch(&ack.peer_node_uid.clone(), ack, NOW + 2)
                    .unwrap();
            }
        }
        authorities[2]
            .activate_epoch(1, Revision::new(7), NOW + 3, 1_000)
            .unwrap();
        let mixed = public_cut(&members, &authorities);
        let mut restarted = NodeKeyAttestationLedger::default();
        assert!(restarted.begin_if_needed(&mixed, NOW + 4).unwrap());
        let round = restarted.round().unwrap().clone();
        assert_ne!(round.round_digest, original.round().unwrap().round_digest);
        assert_eq!(round.proposals, original.round().unwrap().proposals);
        for (member, authority) in members.iter().zip(&authorities).take(2) {
            round
                .verify_publication(&authority.publication().unwrap(), NOW + 4)
                .unwrap();
            restarted
                .observe_row(&identity(member), round.row_for(member).unwrap(), NOW + 4)
                .unwrap();
        }
        assert!(restarted.complete_cut_for(&members[0]).unwrap().is_none());
        round
            .verify_publication(&authorities[2].publication().unwrap(), NOW + 4)
            .unwrap();
        restarted
            .observe_row(
                &identity(&members[2]),
                round.row_for(&members[2]).unwrap(),
                NOW + 4,
            )
            .unwrap();
        for ack in restarted
            .complete_cut_for(&members[0])
            .unwrap()
            .unwrap()
            .acknowledgements
        {
            authorities[0]
                .acknowledge_epoch(&ack.peer_node_uid.clone(), ack, NOW + 4)
                .unwrap();
        }
        for authority in &mut authorities[..2] {
            authority
                .activate_epoch(1, Revision::new(7), NOW + 5, 1_000)
                .unwrap();
        }
        let all_active = public_cut(&members, &authorities);
        assert!(
            !NodeKeyAttestationLedger::default()
                .begin_if_needed(&all_active, NOW + 6)
                .unwrap()
        );
        assert!(!restarted.begin_if_needed(&all_active, NOW + 6).unwrap());
        assert_eq!(restarted.round().unwrap(), &round);
    }

    #[derive(Clone, Default)]
    struct CountingStore {
        writes: Rc<Cell<usize>>,
        fail: Rc<Cell<bool>>,
    }

    impl crate::NodeKeyStateStore for CountingStore {
        fn persist(&self, _: &NodeKeyAuthority) -> Result<(), crate::KeyAuthorityError> {
            if self.fail.get() {
                return Err(crate::KeyAuthorityError::Io(std::io::Error::other(
                    "injected failure",
                )));
            }
            self.writes.set(self.writes.get() + 1);
            Ok(())
        }
    }

    #[test]
    fn reconstructed_cut_preserves_partial_acknowledgements_in_one_atomic_write() {
        let (members, mut authorities, transparency) = prepared_fleet();
        let original = complete_round(&transparency, NOW + 1);
        let old_cut = original.complete_cut_for(&members[0]).unwrap().unwrap();
        let first = old_cut.acknowledgements[0].clone();
        let mut conflicting = authorities[0].clone();
        let mut wrong_binding = first.clone();
        wrong_binding.peer_public_epoch += 1;
        conflicting
            .acknowledge_epoch(&first.peer_node_uid, wrong_binding, NOW + 1)
            .unwrap();
        let mut conflicting = crate::DurableNodeKeyAuthority::create(
            conflicting,
            CountingStore::default(),
            OsWireGuardKeyGenerator,
        )
        .unwrap();
        let conflict_before = conflicting.authority().publication().unwrap();
        assert!(matches!(
            conflicting.acknowledge_attestation_cut(&old_cut, NOW + 2),
            Err(crate::KeyAuthorityError::AcknowledgementMutation)
        ));
        assert_eq!(
            conflicting.authority().publication().unwrap(),
            conflict_before
        );
        authorities[0]
            .acknowledge_epoch(&first.peer_node_uid, first.clone(), NOW + 1)
            .unwrap();
        let restarted = complete_round(&public_cut(&members, &authorities), NOW + 2);
        let cut = restarted.complete_cut_for(&members[0]).unwrap().unwrap();
        // The ordinary single-ack API still refuses a changed observation.
        assert!(matches!(
            authorities[0].acknowledge_epoch(
                &first.peer_node_uid,
                cut.acknowledgements[0].clone(),
                NOW + 2
            ),
            Err(crate::KeyAuthorityError::AcknowledgementMutation)
        ));
        let store = CountingStore::default();
        let mut durable = crate::DurableNodeKeyAuthority::create(
            authorities.remove(0),
            store.clone(),
            OsWireGuardKeyGenerator,
        )
        .unwrap();
        let before = durable.authority().publication().unwrap();
        store.fail.set(true);
        assert!(durable.acknowledge_attestation_cut(&cut, NOW + 2).is_err());
        assert_eq!(durable.authority().publication().unwrap(), before);
        assert_eq!(store.writes.get(), 1);
        store.fail.set(false);
        assert!(durable.acknowledge_attestation_cut(&cut, NOW + 2).unwrap());
        assert_eq!(store.writes.get(), 2);
        assert_eq!(
            durable.authority().epochs()[0].phase(),
            KeyEpochPhase::MutuallyAttested
        );
        assert!(!durable.acknowledge_attestation_cut(&cut, NOW + 3).unwrap());
        assert_eq!(store.writes.get(), 2);
        assert!(
            durable
                .acknowledge_attestation_cut(&cut, NOW + 100_000)
                .is_err()
        );
    }

    #[test]
    fn witness_requires_retained_identity_barrier_and_live_common_epoch() {
        let (members, mut authorities, transparency) = prepared_fleet();
        let round = NodeKeyAttestationRound::issue(&transparency, NOW + 1).unwrap();
        let publication = authorities[0].publication().unwrap();
        let mut changed = round.clone();
        changed.proposals[0].valid_until_unix_ms += 1;
        changed.round_digest = changed.calculate_digest().unwrap();
        assert!(changed.verify_publication(&publication, NOW + 2).is_err());
        let mut changed = round.clone();
        changed.membership_revision = Revision::new(8);
        changed.round_digest = changed.calculate_digest().unwrap();
        assert!(changed.verify_publication(&publication, NOW + 2).is_err());
        assert!(round.verify_publication(&publication, NOW).is_err());
        assert!(
            round
                .verify_publication(&publication, NOW + 100_000)
                .is_err()
        );
        // Same identity and epoch number, but newly generated authority/barrier.
        let (_, replacement, _) = prepared_fleet();
        assert!(
            round
                .verify_publication(&replacement[0].publication().unwrap(), NOW + 2)
                .is_err()
        );
        let foreign = NodeKeyAuthority::new(
            "cluster-a".to_owned(),
            "a".to_owned(),
            "replacement-uid".to_owned(),
        )
        .unwrap();
        assert!(
            round
                .verify_publication(&foreign.publication().unwrap(), NOW + 2)
                .is_err()
        );
        authorities[0]
            .revoke_through(
                1,
                crate::EpochRevocationReason::FleetEpochSuperseded,
                NOW + 2,
            )
            .unwrap();
        assert!(
            round
                .verify_publication(&authorities[0].publication().unwrap(), NOW + 2)
                .is_err()
        );
        let incomplete = public_cut(&members, &authorities);
        assert!(
            !NodeKeyAttestationLedger::default()
                .begin_if_needed(&incomplete, NOW + 3)
                .unwrap()
        );
        assert!(
            !NodeKeyAttestationLedger::default()
                .begin_if_needed(&transparency, NOW + 100_000)
                .unwrap()
        );
    }

    #[test]
    fn draining_predecessor_cannot_witness_a_reconstructed_round() {
        let (members, mut authorities, first) = prepared_fleet();
        let original = complete_round(&first, NOW + 1);
        for (member, authority) in members.iter().zip(&mut authorities) {
            for ack in original
                .complete_cut_for(member)
                .unwrap()
                .unwrap()
                .acknowledgements
            {
                authority
                    .acknowledge_epoch(&ack.peer_node_uid.clone(), ack, NOW + 2)
                    .unwrap();
            }
            authority
                .activate_epoch(1, Revision::new(7), NOW + 3, 1_000)
                .unwrap();
            authority
                .prepare_epoch(
                    Revision::new(7),
                    members
                        .iter()
                        .filter(|peer| *peer != member)
                        .map(|peer| peer.node_uid.clone())
                        .collect(),
                    NOW + 4,
                    NOW + 200_000,
                    &mut OsWireGuardKeyGenerator,
                )
                .unwrap();
        }
        let successor = complete_round(&public_cut(&members, &authorities), NOW + 5);
        for ack in successor
            .complete_cut_for(&members[0])
            .unwrap()
            .unwrap()
            .acknowledgements
        {
            authorities[0]
                .acknowledge_epoch(&ack.peer_node_uid.clone(), ack, NOW + 6)
                .unwrap();
        }
        authorities[0]
            .activate_epoch(2, Revision::new(7), NOW + 7, 1_000)
            .unwrap();
        assert!(
            original
                .round()
                .unwrap()
                .verify_publication(&authorities[0].publication().unwrap(), NOW + 8)
                .is_err()
        );
        let recovered =
            NodeKeyAttestationRound::issue(&public_cut(&members, &authorities), NOW + 8).unwrap();
        assert!(
            recovered
                .proposals
                .iter()
                .all(|proposal| proposal.epoch == 2)
        );
        assert!(
            recovered
                .verify_publication(&authorities[0].publication().unwrap(), NOW + 8)
                .is_ok()
        );
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

    #[test]
    fn complete_successor_epoch_opens_a_new_round_without_membership_churn() {
        let (members, mut authorities, first_transparency) = prepared_fleet();
        let mut attestations = NodeKeyAttestationLedger::default();
        attestations
            .begin_if_needed(&first_transparency, NOW + 1)
            .unwrap();
        let first_round = attestations.round().unwrap().clone();
        for member in &members {
            attestations
                .observe_row(
                    &identity(member),
                    first_round.row_for(member).unwrap(),
                    NOW + 2,
                )
                .unwrap();
        }
        let peer_uids = members
            .iter()
            .map(|member| member.node_uid.clone())
            .collect::<BTreeSet<_>>();
        for (member, authority) in members.iter().zip(&mut authorities) {
            let cut = attestations.complete_cut_for(member).unwrap().unwrap();
            for acknowledgement in cut.acknowledgements {
                authority
                    .acknowledge_epoch(
                        &acknowledgement.peer_node_uid.clone(),
                        acknowledgement,
                        NOW + 2,
                    )
                    .unwrap();
            }
            authority
                .activate_epoch(1, Revision::new(7), NOW + 3, 1_000)
                .unwrap();
            let mut required = peer_uids.clone();
            required.remove(&member.node_uid);
            authority
                .prepare_epoch(
                    Revision::new(7),
                    required,
                    NOW + 4,
                    NOW + 200_000,
                    &mut OsWireGuardKeyGenerator,
                )
                .unwrap();
        }

        let mut transparency = NodeKeyTransparencyLedger::default();
        transparency
            .replace_membership("cluster-a".to_owned(), Revision::new(7), members.clone())
            .unwrap();
        for (member, authority) in members.iter().zip(&authorities) {
            transparency
                .observe(&identity(member), authority.publication().unwrap())
                .unwrap();
        }
        let successor = transparency.complete_cut().unwrap().unwrap();
        assert!(attestations.begin_if_needed(&successor, NOW + 5).unwrap());
        assert!(
            attestations
                .round()
                .unwrap()
                .proposals
                .iter()
                .all(|proposal| proposal.epoch == 2)
        );
    }
}
