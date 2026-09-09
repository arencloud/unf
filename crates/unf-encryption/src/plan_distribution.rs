//! Authenticated pull protocol for complete Node-local plan manifolds.
//!
//! A plan is desired input only. Nonce binding, exact predecessor continuity,
//! and durable admission prevent delivery skew without turning a controller
//! response into local key, kernel, route, or eBPF authority.

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use unf_common::Revision;

use crate::{
    EncryptionGenerationRecipient, NodeLocalPlanCompilerError, NodeLocalPlanSnapshot,
    NodeLocalPlanSnapshotDigest,
};

pub const NODE_LOCAL_PLAN_REQUEST_SCHEMA_VERSION: u16 = 1;
pub const NODE_SEALED_PLAN_CAPSULE_SCHEMA_VERSION: u16 = 1;
pub const ADMITTED_NODE_LOCAL_PLAN_SCHEMA_VERSION: u16 = 1;
const MAX_NODE_IDENTITY_BYTES: usize = 253;
const NODE_SEALED_PLAN_CAPSULE_DIGEST_DOMAIN: &[u8] = b"unf.node-sealed-plan-capsule.v1\0";
const ADMITTED_NODE_LOCAL_PLAN_DIGEST_DOMAIN: &[u8] = b"unf.admitted-node-local-plan.v1\0";
pub const NODE_LOCAL_PLAN_FLEET_CUT_SCHEMA_VERSION: u16 = 1;
pub const MAX_ENCRYPTION_PLAN_MEMBERS: usize = 4_096;
const NODE_LOCAL_PLAN_FLEET_CUT_DIGEST_DOMAIN: &[u8] = b"unf.node-local-plan-fleet-cut.v1\0";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct NodeLocalPlanCursor {
    pub controller_epoch: u64,
    pub recipient: EncryptionGenerationRecipient,
    pub membership_revision: Revision,
    pub generation: Revision,
    pub snapshot_digest: NodeLocalPlanSnapshotDigest,
}

/// Fresh request bound to the exact locally durable plan predecessor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct NodeLocalPlanRequest {
    pub schema_version: u16,
    pub node_name: String,
    pub current: Option<NodeLocalPlanCursor>,
    pub nonce: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct NodeSealedPlanCapsuleDigest(pub [u8; 32]);

/// Controller response sealed to one request, recipient, and complete plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct NodeSealedPlanCapsule {
    pub schema_version: u16,
    pub controller_epoch: u64,
    pub recipient: EncryptionGenerationRecipient,
    pub request_nonce: [u8; 32],
    pub snapshot: NodeLocalPlanSnapshot,
    pub capsule_digest: NodeSealedPlanCapsuleDigest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AdmittedNodeLocalPlanDigest(pub [u8; 32]);

/// Durable desired input accepted by an agent. This object is deliberately
/// insufficient to mutate keys, `WireGuard`, policy routes, or Aya maps.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AdmittedNodeLocalPlan {
    pub schema_version: u16,
    pub controller_epoch: u64,
    pub snapshot: NodeLocalPlanSnapshot,
    pub admitted_digest: AdmittedNodeLocalPlanDigest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct NodeLocalPlanFleetCutDigest(pub [u8; 32]);

/// One atomic fleet-wide set of Node-local plan manifolds. Explicit membership
/// makes omission distinguishable from an intentionally smaller cluster.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct NodeLocalPlanFleetCut {
    pub schema_version: u16,
    pub membership_revision: Revision,
    pub generation: Revision,
    pub members: Vec<EncryptionGenerationRecipient>,
    pub plans: Vec<NodeLocalPlanSnapshot>,
    pub cut_digest: NodeLocalPlanFleetCutDigest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeLocalPlanCatalogOutcome {
    Published,
    Unchanged,
}

/// In-memory publication boundary. Readers can observe one verified complete
/// cut or no cut, never incremental per-Node updates.
#[derive(Debug, Default)]
pub struct NodeLocalPlanCatalog {
    active: Option<NodeLocalPlanFleetCut>,
}

impl NodeLocalPlanRequest {
    /// Generates a fresh OS-CSPRNG nonce and binds the durable predecessor.
    ///
    /// # Errors
    ///
    /// Rejects malformed local identity/state or unavailable randomness.
    pub fn fresh(
        node_name: String,
        current: Option<&AdmittedNodeLocalPlan>,
    ) -> Result<Self, NodeLocalPlanDistributionError> {
        let mut nonce = [0_u8; 32];
        getrandom::fill(&mut nonce)
            .map_err(|error| NodeLocalPlanDistributionError::Randomness(error.to_string()))?;
        Self::issue(node_name, current, nonce)
    }

    /// Deterministic constructor for replay tests and constrained callers.
    ///
    /// # Errors
    ///
    /// Rejects an invalid name, predecessor, or all-zero nonce.
    pub fn issue(
        node_name: String,
        current: Option<&AdmittedNodeLocalPlan>,
        nonce: [u8; 32],
    ) -> Result<Self, NodeLocalPlanDistributionError> {
        if !valid_identity(&node_name) || nonce == [0; 32] {
            return Err(NodeLocalPlanDistributionError::InvalidRequest);
        }
        let current = current
            .map(|admitted| {
                admitted.verify()?;
                if admitted.snapshot.recipient.node_name != node_name {
                    return Err(NodeLocalPlanDistributionError::RecipientMismatch);
                }
                Ok(admitted.cursor())
            })
            .transpose()?;
        Ok(Self {
            schema_version: NODE_LOCAL_PLAN_REQUEST_SCHEMA_VERSION,
            node_name,
            current,
            nonce,
        })
    }

    /// # Errors
    ///
    /// Rejects malformed or internally inconsistent request state.
    pub fn verify(&self) -> Result<(), NodeLocalPlanDistributionError> {
        if self.schema_version != NODE_LOCAL_PLAN_REQUEST_SCHEMA_VERSION
            || !valid_identity(&self.node_name)
            || self.nonce == [0; 32]
        {
            return Err(NodeLocalPlanDistributionError::InvalidRequest);
        }
        if let Some(current) = &self.current {
            validate_cursor(current)?;
            if current.recipient.node_name != self.node_name {
                return Err(NodeLocalPlanDistributionError::InvalidRequest);
            }
        }
        Ok(())
    }
}

impl NodeLocalPlanCursor {
    #[must_use]
    pub fn matches(&self, snapshot: &NodeLocalPlanSnapshot) -> bool {
        self.recipient == snapshot.recipient
            && self.membership_revision == snapshot.membership_revision
            && self.generation == snapshot.generation
            && self.snapshot_digest == snapshot.snapshot_digest
    }
}

impl NodeSealedPlanCapsule {
    /// Seals one complete monotonic plan successor to a fresh request.
    ///
    /// # Errors
    ///
    /// Rejects cross-Node delivery, Node replacement, rollback, mutation, or
    /// a response that does not extend the exact durable predecessor.
    pub fn issue(
        controller_epoch: u64,
        request: &NodeLocalPlanRequest,
        snapshot: NodeLocalPlanSnapshot,
    ) -> Result<Self, NodeLocalPlanDistributionError> {
        request.verify()?;
        snapshot
            .verify()
            .map_err(NodeLocalPlanDistributionError::InvalidSnapshot)?;
        if controller_epoch == 0
            || snapshot.recipient.node_name != request.node_name
            || request.current.as_ref().is_some_and(|current| {
                current.recipient != snapshot.recipient
                    || controller_epoch < current.controller_epoch
                    || snapshot.membership_revision < current.membership_revision
                    || snapshot.generation <= current.generation
            })
        {
            return Err(NodeLocalPlanDistributionError::InvalidTransition);
        }
        let recipient = snapshot.recipient.clone();
        let mut capsule = Self {
            schema_version: NODE_SEALED_PLAN_CAPSULE_SCHEMA_VERSION,
            controller_epoch,
            recipient,
            request_nonce: request.nonce,
            snapshot,
            capsule_digest: NodeSealedPlanCapsuleDigest([0; 32]),
        };
        capsule.capsule_digest = capsule.calculate_digest()?;
        capsule.verify()?;
        Ok(capsule)
    }

    /// # Errors
    ///
    /// Rejects schema, recipient, nested snapshot, or digest mutation.
    pub fn verify(&self) -> Result<(), NodeLocalPlanDistributionError> {
        self.snapshot
            .verify()
            .map_err(NodeLocalPlanDistributionError::InvalidSnapshot)?;
        if self.schema_version != NODE_SEALED_PLAN_CAPSULE_SCHEMA_VERSION
            || self.controller_epoch == 0
            || self.request_nonce == [0; 32]
            || self.recipient != self.snapshot.recipient
            || self.capsule_digest != self.calculate_digest()?
        {
            return Err(NodeLocalPlanDistributionError::InvalidCapsule);
        }
        Ok(())
    }

    /// Admits this response only against the exact request and durable cursor.
    ///
    /// # Errors
    ///
    /// Rejects nonce replay, Node replacement, predecessor disagreement,
    /// controller-epoch rollback, plan regression, or any nested mutation.
    pub fn admit(
        &self,
        request: &NodeLocalPlanRequest,
        current: Option<&AdmittedNodeLocalPlan>,
    ) -> Result<AdmittedNodeLocalPlan, NodeLocalPlanDistributionError> {
        self.verify()?;
        request.verify()?;
        let current_cursor = current
            .map(|admitted| {
                admitted.verify()?;
                Ok(admitted.cursor())
            })
            .transpose()?;
        if self.request_nonce != request.nonce
            || self.recipient.node_name != request.node_name
            || request.current != current_cursor
        {
            return Err(NodeLocalPlanDistributionError::RequestMismatch);
        }
        if let Some(current) = current {
            let cursor = current.cursor();
            if self.recipient != cursor.recipient {
                return Err(NodeLocalPlanDistributionError::RecipientMismatch);
            }
            if self.controller_epoch < cursor.controller_epoch
                || self.snapshot.membership_revision < cursor.membership_revision
                || self.snapshot.generation <= cursor.generation
            {
                return Err(NodeLocalPlanDistributionError::PlanRegression);
            }
        }
        let mut admitted = AdmittedNodeLocalPlan {
            schema_version: ADMITTED_NODE_LOCAL_PLAN_SCHEMA_VERSION,
            controller_epoch: self.controller_epoch,
            snapshot: self.snapshot.clone(),
            admitted_digest: AdmittedNodeLocalPlanDigest([0; 32]),
        };
        admitted.admitted_digest = admitted.calculate_digest()?;
        admitted.verify()?;
        Ok(admitted)
    }

    fn calculate_digest(
        &self,
    ) -> Result<NodeSealedPlanCapsuleDigest, NodeLocalPlanDistributionError> {
        let mut canonical = self.clone();
        canonical.capsule_digest = NodeSealedPlanCapsuleDigest([0; 32]);
        hash_canonical(NODE_SEALED_PLAN_CAPSULE_DIGEST_DOMAIN, &canonical)
            .map(NodeSealedPlanCapsuleDigest)
    }
}

impl AdmittedNodeLocalPlan {
    #[must_use]
    pub fn cursor(&self) -> NodeLocalPlanCursor {
        NodeLocalPlanCursor {
            controller_epoch: self.controller_epoch,
            recipient: self.snapshot.recipient.clone(),
            membership_revision: self.snapshot.membership_revision,
            generation: self.snapshot.generation,
            snapshot_digest: self.snapshot.snapshot_digest,
        }
    }

    /// # Errors
    ///
    /// Rejects durable schema, nested plan, epoch, or digest drift.
    pub fn verify(&self) -> Result<(), NodeLocalPlanDistributionError> {
        self.snapshot
            .verify()
            .map_err(NodeLocalPlanDistributionError::InvalidSnapshot)?;
        if self.schema_version != ADMITTED_NODE_LOCAL_PLAN_SCHEMA_VERSION
            || self.controller_epoch == 0
            || self.admitted_digest != self.calculate_digest()?
        {
            return Err(NodeLocalPlanDistributionError::InvalidAdmittedPlan);
        }
        Ok(())
    }

    fn calculate_digest(
        &self,
    ) -> Result<AdmittedNodeLocalPlanDigest, NodeLocalPlanDistributionError> {
        let mut canonical = self.clone();
        canonical.admitted_digest = AdmittedNodeLocalPlanDigest([0; 32]);
        hash_canonical(ADMITTED_NODE_LOCAL_PLAN_DIGEST_DOMAIN, &canonical)
            .map(AdmittedNodeLocalPlanDigest)
    }
}

impl NodeLocalPlanFleetCut {
    /// Canonicalizes and seals a complete membership-aligned fleet cut.
    ///
    /// # Errors
    ///
    /// Rejects empty/oversized membership, duplicates, omissions, foreign
    /// recipients, mixed revisions/generations, or invalid nested plans.
    pub fn issue(
        membership_revision: Revision,
        generation: Revision,
        mut members: Vec<EncryptionGenerationRecipient>,
        mut plans: Vec<NodeLocalPlanSnapshot>,
    ) -> Result<Self, NodeLocalPlanCatalogError> {
        members.sort();
        plans.sort_by(|left, right| left.recipient.cmp(&right.recipient));
        let mut cut = Self {
            schema_version: NODE_LOCAL_PLAN_FLEET_CUT_SCHEMA_VERSION,
            membership_revision,
            generation,
            members,
            plans,
            cut_digest: NodeLocalPlanFleetCutDigest([0; 32]),
        };
        cut.validate()?;
        cut.cut_digest = cut.calculate_digest()?;
        Ok(cut)
    }

    /// # Errors
    ///
    /// Replays nested plans, exact membership coverage, common causal
    /// revisions, canonical order, and the fleet digest.
    pub fn verify(&self) -> Result<(), NodeLocalPlanCatalogError> {
        self.validate()?;
        if self.cut_digest != self.calculate_digest()? {
            return Err(NodeLocalPlanCatalogError::InvalidCut(
                "fleet plan cut digest does not match",
            ));
        }
        Ok(())
    }

    fn validate(&self) -> Result<(), NodeLocalPlanCatalogError> {
        if self.schema_version != NODE_LOCAL_PLAN_FLEET_CUT_SCHEMA_VERSION
            || self.membership_revision == Revision::INITIAL
            || self.generation == Revision::INITIAL
            || self.members.is_empty()
            || self.members.len() > MAX_ENCRYPTION_PLAN_MEMBERS
            || self.members.len() != self.plans.len()
            || self.members.windows(2).any(|pair| pair[0] >= pair[1])
            || self
                .plans
                .windows(2)
                .any(|pair| pair[0].recipient >= pair[1].recipient)
        {
            return Err(NodeLocalPlanCatalogError::InvalidCut(
                "fleet plan cut shape is invalid or noncanonical",
            ));
        }
        for (member, plan) in self.members.iter().zip(&self.plans) {
            plan.verify()
                .map_err(NodeLocalPlanCatalogError::InvalidPlan)?;
            if member != &plan.recipient
                || plan.membership_revision != self.membership_revision
                || plan.generation != self.generation
            {
                return Err(NodeLocalPlanCatalogError::InvalidCut(
                    "fleet plan membership or generation is incomplete",
                ));
            }
        }
        let first = &self.plans[0];
        if self.plans.iter().any(|plan| {
            plan.policy_revision != first.policy_revision
                || plan.service_revision != first.service_revision
                || plan.egress_revision != first.egress_revision
        }) {
            return Err(NodeLocalPlanCatalogError::InvalidCut(
                "fleet plan causal revisions are mixed",
            ));
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Result<NodeLocalPlanFleetCutDigest, NodeLocalPlanCatalogError> {
        let mut canonical = self.clone();
        canonical.cut_digest = NodeLocalPlanFleetCutDigest([0; 32]);
        let encoded = serde_json::to_vec(&canonical)
            .map_err(|error| NodeLocalPlanCatalogError::Encoding(error.to_string()))?;
        let mut hasher = Sha256::new();
        hasher.update(NODE_LOCAL_PLAN_FLEET_CUT_DIGEST_DOMAIN);
        hasher.update(encoded);
        Ok(NodeLocalPlanFleetCutDigest(hasher.finalize().into()))
    }
}

impl NodeLocalPlanCatalog {
    /// Atomically publishes one complete successor cut.
    ///
    /// # Errors
    ///
    /// Rejects rollback and same-generation equivocation without changing the
    /// active catalog.
    pub fn publish(
        &mut self,
        candidate: NodeLocalPlanFleetCut,
    ) -> Result<NodeLocalPlanCatalogOutcome, NodeLocalPlanCatalogError> {
        candidate.verify()?;
        if let Some(active) = &self.active {
            if candidate.generation < active.generation
                || candidate.membership_revision < active.membership_revision
            {
                return Err(NodeLocalPlanCatalogError::Regression);
            }
            if candidate.generation == active.generation {
                if &candidate == active {
                    return Ok(NodeLocalPlanCatalogOutcome::Unchanged);
                }
                return Err(NodeLocalPlanCatalogError::Equivocation);
            }
        }
        self.active = Some(candidate);
        Ok(NodeLocalPlanCatalogOutcome::Published)
    }

    #[must_use]
    pub fn active(&self) -> Option<&NodeLocalPlanFleetCut> {
        self.active.as_ref()
    }

    #[must_use]
    pub fn desired_for(
        &self,
        recipient: &EncryptionGenerationRecipient,
    ) -> Option<&NodeLocalPlanSnapshot> {
        let active = self.active.as_ref()?;
        active
            .plans
            .binary_search_by(|plan| plan.recipient.cmp(recipient))
            .ok()
            .and_then(|position| active.plans.get(position))
    }
}

fn validate_cursor(cursor: &NodeLocalPlanCursor) -> Result<(), NodeLocalPlanDistributionError> {
    if cursor.controller_epoch == 0
        || !valid_identity(&cursor.recipient.node_name)
        || !valid_identity(&cursor.recipient.node_uid)
        || cursor.membership_revision == Revision::INITIAL
        || cursor.generation == Revision::INITIAL
        || cursor.snapshot_digest.0 == [0; 32]
    {
        return Err(NodeLocalPlanDistributionError::InvalidRequest);
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
) -> Result<[u8; 32], NodeLocalPlanDistributionError> {
    let encoded = serde_json::to_vec(value)
        .map_err(|error| NodeLocalPlanDistributionError::Encoding(error.to_string()))?;
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(encoded);
    Ok(hasher.finalize().into())
}

#[derive(Debug, Error)]
pub enum NodeLocalPlanDistributionError {
    #[error("invalid Node-local plan pull request")]
    InvalidRequest,
    #[error("Node-local plan recipient does not match local Node identity")]
    RecipientMismatch,
    #[error("invalid Node-local plan snapshot: {0}")]
    InvalidSnapshot(NodeLocalPlanCompilerError),
    #[error("invalid Node-local plan transition")]
    InvalidTransition,
    #[error("Node-local plan regressed or replayed")]
    PlanRegression,
    #[error("Node-sealed plan capsule does not answer the exact request")]
    RequestMismatch,
    #[error("invalid or mutated Node-sealed plan capsule")]
    InvalidCapsule,
    #[error("invalid or mutated admitted Node-local plan")]
    InvalidAdmittedPlan,
    #[error("operating-system randomness failed: {0}")]
    Randomness(String),
    #[error("canonical Node-local plan distribution encoding failed: {0}")]
    Encoding(String),
}

#[derive(Debug, Error)]
pub enum NodeLocalPlanCatalogError {
    #[error("invalid fleet-local encryption plan cut: {0}")]
    InvalidCut(&'static str),
    #[error("invalid Node-local plan in fleet cut: {0}")]
    InvalidPlan(NodeLocalPlanCompilerError),
    #[error("fleet-local encryption plan catalog regressed")]
    Regression,
    #[error("fleet-local encryption plan catalog equivocated at one generation")]
    Equivocation,
    #[error("canonical fleet-local encryption plan encoding failed: {0}")]
    Encoding(String),
}
