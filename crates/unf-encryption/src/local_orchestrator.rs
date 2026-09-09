//! Capability-typed Node-local generation proof ladder and Linux convergence.
//!
//! A Node proposal, controller admission, route proof, and Aya activation are
//! deliberately different Rust types. Each transition consumes the preceding
//! capability, so callers cannot reorder the proof ladder or reuse a route
//! permit across generations. No serialized value becomes kernel authority.

use std::collections::{BTreeMap, BTreeSet};

use sha2::{Digest as _, Sha256};
use thiserror::Error;
use unf_common::Revision;

use crate::{
    AdmittedEncryptionGeneration, EncryptionActivationLatch, EncryptionActivationLatchError,
    EncryptionGenerationDistributionError, EncryptionGenerationFact, EncryptionGenerationFactError,
    EncryptionGenerationRecipient, EncryptionRouteAuthority, EncryptionRouteAuthorityError,
    EncryptionRoutePublicationPermit, FastPathMapCheckpoint, FastPathPublishedGeneration,
    FastPathTransactionError, KeyAuthorityError, NodeKeyAuthority, WireGuardEpochActivation,
    WireGuardKernelConfigurationDigest, WireGuardKernelError, WireGuardKernelPlan,
    WireGuardKernelPlanDigest, WireGuardKernelSnapshot,
};

#[cfg(target_os = "linux")]
use crate::{LinuxEncryptionRouteProvider, LinuxWireGuardProvider};

const CONVERGENCE_WITNESS_DOMAIN: &[u8] = b"unf.node-local-linux-convergence.v1\0";

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

/// Compact, secret-free evidence that the complete local kernel set was read
/// back and joined to one exact proposed generation. It is provenance, never
/// reusable activation authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NodeLocalConvergenceWitness(pub [u8; 32]);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct KernelConvergenceCommitment {
    epoch: u64,
    plan_digest: WireGuardKernelPlanDigest,
    configuration_digest: WireGuardKernelConfigurationDigest,
}

/// Non-serializable capability proving that every `WireGuard` interface and
/// route needed by the proposal has exact Node-local kernel readback. Linux
/// policy rules and Aya publication still require controller admission.
pub struct LinuxPreparedLocalGeneration {
    proposal: NodeLocalGenerationProposal,
    route_authority: EncryptionRouteAuthority,
    commitments: Vec<KernelConvergenceCommitment>,
    witness: NodeLocalConvergenceWitness,
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

impl LinuxPreparedLocalGeneration {
    /// Stages every required `WireGuard` epoch through the real Linux provider,
    /// which is idempotent for already-exact state and rolls back a failed
    /// fresh interface. No policy rule or Aya map is activated here.
    ///
    /// All plans and local key bindings are preflighted before the first kernel
    /// mutation. If a later plan fails, earlier plans remain safely staged and
    /// exact; retry converges without recreating or broadening authority.
    ///
    /// # Errors
    ///
    /// Rejects malformed/cross-Node plans, unready or mismatched local keys,
    /// kernel readback drift, and any mismatch with the proposed map image.
    #[cfg(target_os = "linux")]
    pub async fn stage_linux(
        membership_revision: Revision,
        recipient: EncryptionGenerationRecipient,
        checkpoint: FastPathMapCheckpoint,
        key_authority: &NodeKeyAuthority,
        plans: &[WireGuardKernelPlan],
    ) -> Result<Self, NodeLocalOrchestratorError> {
        let desired = checkpoint
            .desired_state()
            .map_err(NodeLocalOrchestratorError::InvalidCheckpoint)?;
        NodeLocalGenerationProposal::issue(
            membership_revision,
            recipient.clone(),
            checkpoint.clone(),
        )?;
        preflight_plan_cut(&recipient, &desired, plans)?;
        preflight_linux_plans(&recipient, key_authority, plans)?;
        let provider = LinuxWireGuardProvider;
        let mut ordered = plans.iter().collect::<Vec<_>>();
        ordered.sort_by_key(|plan| (plan.epoch, plan.interface_name.as_str()));
        let mut snapshots = Vec::with_capacity(ordered.len());
        for plan in ordered {
            let private_key = key_authority
                .private_key_for_kernel_plan(plan)
                .map_err(NodeLocalOrchestratorError::InvalidKeyAuthority)?;
            let (_, snapshot) = provider
                .apply(plan, private_key)
                .await
                .map_err(NodeLocalOrchestratorError::InvalidKernel)?;
            snapshots.push(snapshot);
        }
        Self::bind_exact_readback(
            membership_revision,
            recipient,
            checkpoint,
            plans,
            &snapshots,
        )
    }

    /// Binds independently obtained exact kernel readback to a proposal. This
    /// constructor performs no mutation and is also the deterministic audit
    /// boundary used by tests and recovery.
    ///
    /// # Errors
    ///
    /// Accepts any input order, while rejecting partial, duplicate, foreign,
    /// or substituted kernel evidence and any plan-to-fast-path mismatch.
    pub fn bind_exact_readback(
        membership_revision: Revision,
        recipient: EncryptionGenerationRecipient,
        checkpoint: FastPathMapCheckpoint,
        plans: &[WireGuardKernelPlan],
        snapshots: &[WireGuardKernelSnapshot],
    ) -> Result<Self, NodeLocalOrchestratorError> {
        let desired = checkpoint
            .desired_state()
            .map_err(NodeLocalOrchestratorError::InvalidCheckpoint)?;
        let commitments = validate_exact_kernel_cut(&recipient, &desired, plans, snapshots)?;
        let route_authority = EncryptionRouteAuthority::issue(&desired, snapshots)
            .map_err(NodeLocalOrchestratorError::InvalidRouteAuthority)?;
        let proposal =
            NodeLocalGenerationProposal::issue(membership_revision, recipient, checkpoint)?;
        let witness = convergence_witness(proposal.fact(), &route_authority, &commitments)?;
        Ok(Self {
            proposal,
            route_authority,
            commitments,
            witness,
        })
    }

    /// Returns the retryable secret-free fact submitted over the existing
    /// authenticated agent endpoint.
    #[must_use]
    pub fn fact(&self) -> &EncryptionGenerationFact {
        self.proposal.fact()
    }

    #[must_use]
    pub const fn witness(&self) -> NodeLocalConvergenceWitness {
        self.witness
    }

    /// Consumes exact kernel convergence, verifies the controller returned the
    /// same proposal, installs/read-backs the real Linux policy rules, and
    /// returns the only latch accepted by the Aya transaction adapter.
    ///
    /// # Errors
    ///
    /// Rejects internal witness drift, controller substitution, Linux route
    /// drift/conflicts, or a stale map predecessor. A rule-only partial result
    /// is safe because no unpublished generation can emit its selector.
    #[cfg(target_os = "linux")]
    pub async fn admit_and_activate_linux(
        self,
        admitted: AdmittedEncryptionGeneration,
        applied: Option<FastPathPublishedGeneration>,
    ) -> Result<EncryptionActivationLatch, NodeLocalOrchestratorError> {
        if self.witness
            != convergence_witness(
                self.proposal.fact(),
                &self.route_authority,
                &self.commitments,
            )?
        {
            return Err(NodeLocalOrchestratorError::ConvergenceWitnessMismatch);
        }
        let controller_bound = self.proposal.bind_controller_admission(admitted)?;
        let permit = LinuxEncryptionRouteProvider
            .activate(&self.route_authority)
            .await
            .map_err(NodeLocalOrchestratorError::InvalidRouteAuthority)?;
        controller_bound.authorize_map_activation(applied, permit)
    }
}

fn preflight_linux_plans(
    recipient: &EncryptionGenerationRecipient,
    key_authority: &NodeKeyAuthority,
    plans: &[WireGuardKernelPlan],
) -> Result<(), NodeLocalOrchestratorError> {
    if key_authority.node_name() != recipient.node_name
        || key_authority.node_uid() != recipient.node_uid
        || plans.is_empty()
    {
        return Err(NodeLocalOrchestratorError::KernelCommitmentMismatch);
    }
    let mut epochs = BTreeSet::new();
    let mut interfaces = BTreeSet::new();
    for plan in plans {
        plan.verify()
            .map_err(NodeLocalOrchestratorError::InvalidKernel)?;
        if plan.activation != WireGuardEpochActivation::InactiveStaged
            || !epochs.insert(plan.epoch)
            || !interfaces.insert(plan.interface_name.as_str())
        {
            return Err(NodeLocalOrchestratorError::KernelCommitmentMismatch);
        }
        key_authority
            .private_key_for_kernel_plan(plan)
            .map_err(NodeLocalOrchestratorError::InvalidKeyAuthority)?;
    }
    Ok(())
}

fn validate_exact_kernel_cut(
    recipient: &EncryptionGenerationRecipient,
    desired: &crate::EncryptionFastPathState,
    plans: &[WireGuardKernelPlan],
    snapshots: &[WireGuardKernelSnapshot],
) -> Result<Vec<KernelConvergenceCommitment>, NodeLocalOrchestratorError> {
    if plans.is_empty() || plans.len() != snapshots.len() {
        return Err(NodeLocalOrchestratorError::KernelCommitmentMismatch);
    }
    let expected = preflight_plan_cut(recipient, desired, plans)?;

    let mut indexed = BTreeMap::new();
    let mut commitments = Vec::with_capacity(plans.len());
    for snapshot in snapshots {
        snapshot
            .verify_integrity()
            .map_err(NodeLocalOrchestratorError::InvalidKernel)?;
    }
    for plan in plans {
        let mut matches = snapshots
            .iter()
            .filter(|snapshot| snapshot.verify_against(plan).is_ok());
        let snapshot = matches
            .next()
            .ok_or(NodeLocalOrchestratorError::KernelCommitmentMismatch)?;
        if matches.next().is_some() {
            return Err(NodeLocalOrchestratorError::KernelCommitmentMismatch);
        }
        let digest = snapshot.configuration_digest.0;
        if !expected.contains(&digest) || indexed.insert(digest, (plan, snapshot)).is_some() {
            return Err(NodeLocalOrchestratorError::KernelCommitmentMismatch);
        }
        commitments.push(KernelConvergenceCommitment {
            epoch: plan.epoch,
            plan_digest: plan.plan_digest,
            configuration_digest: snapshot.configuration_digest,
        });
    }
    for transport in &desired.transport_authority {
        let (plan, snapshot) = indexed
            .get(&transport.kernel_configuration_digest)
            .ok_or(NodeLocalOrchestratorError::KernelCommitmentMismatch)?;
        if plan.epoch != transport.key_epoch
            || plan.interface_name != transport.interface_name
            || plan.route_table != transport.route_table
            || plan.fwmark != transport.fwmark
            || plan.mtu_envelope.interface_mtu != transport.mtu
            || snapshot.interface_index != transport.interface_index
            || !plan
                .peers
                .iter()
                .any(|peer| peer.node_uid == transport.destination_node_uid)
        {
            return Err(NodeLocalOrchestratorError::KernelCommitmentMismatch);
        }
    }
    commitments.sort_by_key(|entry| {
        (
            entry.epoch,
            entry.plan_digest.0,
            entry.configuration_digest.0,
        )
    });
    Ok(commitments)
}

fn preflight_plan_cut(
    recipient: &EncryptionGenerationRecipient,
    desired: &crate::EncryptionFastPathState,
    plans: &[WireGuardKernelPlan],
) -> Result<BTreeSet<[u8; 32]>, NodeLocalOrchestratorError> {
    let expected = desired
        .transport_authority
        .iter()
        .map(|transport| transport.kernel_configuration_digest)
        .collect::<BTreeSet<_>>();
    if plans.is_empty() || expected.len() != plans.len() {
        return Err(NodeLocalOrchestratorError::KernelCommitmentMismatch);
    }
    let mut epochs = BTreeSet::new();
    let mut interfaces = BTreeSet::new();
    for plan in plans {
        plan.verify()
            .map_err(NodeLocalOrchestratorError::InvalidKernel)?;
        if plan.activation != WireGuardEpochActivation::InactiveStaged
            || plan.local_node_uid != recipient.node_uid
            || !epochs.insert(plan.epoch)
            || !interfaces.insert(plan.interface_name.as_str())
        {
            return Err(NodeLocalOrchestratorError::KernelCommitmentMismatch);
        }
    }
    let mut matched_plans = BTreeSet::new();
    for transport in &desired.transport_authority {
        if transport.local_node_uid != recipient.node_uid {
            return Err(NodeLocalOrchestratorError::KernelCommitmentMismatch);
        }
        let matches = plans
            .iter()
            .enumerate()
            .filter(|(_, plan)| {
                plan.epoch == transport.key_epoch
                    && plan.cluster_id == transport.trust_domain
                    && plan.interface_name == transport.interface_name
                    && plan.route_table == transport.route_table
                    && plan.fwmark == transport.fwmark
                    && plan.mtu_envelope.interface_mtu == transport.mtu
                    && plan
                        .peers
                        .iter()
                        .any(|peer| peer.node_uid == transport.destination_node_uid)
            })
            .map(|(index, _)| index)
            .collect::<Vec<_>>();
        if matches.len() != 1 {
            return Err(NodeLocalOrchestratorError::KernelCommitmentMismatch);
        }
        matched_plans.insert(matches[0]);
    }
    if matched_plans.len() != plans.len() {
        return Err(NodeLocalOrchestratorError::KernelCommitmentMismatch);
    }
    Ok(expected)
}

fn convergence_witness(
    fact: &EncryptionGenerationFact,
    route_authority: &EncryptionRouteAuthority,
    commitments: &[KernelConvergenceCommitment],
) -> Result<NodeLocalConvergenceWitness, NodeLocalOrchestratorError> {
    fact.verify()
        .map_err(NodeLocalOrchestratorError::InvalidFact)?;
    route_authority
        .verify()
        .map_err(NodeLocalOrchestratorError::InvalidRouteAuthority)?;
    let input = (
        fact.fact_digest,
        route_authority.authority_digest,
        commitments
            .iter()
            .map(|entry| (entry.epoch, entry.plan_digest, entry.configuration_digest))
            .collect::<Vec<_>>(),
    );
    let encoded = serde_json::to_vec(&input)
        .map_err(|error| NodeLocalOrchestratorError::Encoding(error.to_string()))?;
    let mut hasher = Sha256::new();
    hasher.update(CONVERGENCE_WITNESS_DOMAIN);
    hasher.update(encoded);
    Ok(NodeLocalConvergenceWitness(hasher.finalize().into()))
}

#[derive(Debug, Error)]
pub enum NodeLocalOrchestratorError {
    #[error("invalid Node-local generation fact: {0}")]
    InvalidFact(EncryptionGenerationFactError),
    #[error("invalid Node-local map checkpoint: {0}")]
    InvalidCheckpoint(FastPathTransactionError),
    #[error("invalid Node-local key authority: {0}")]
    InvalidKeyAuthority(KeyAuthorityError),
    #[error("invalid Node-local WireGuard kernel state: {0}")]
    InvalidKernel(WireGuardKernelError),
    #[error("invalid Node-local encryption route authority: {0}")]
    InvalidRouteAuthority(EncryptionRouteAuthorityError),
    #[error("WireGuard plans, kernel readback, and fast-path commitments differ")]
    KernelCommitmentMismatch,
    #[error("Node-local convergence witness does not match")]
    ConvergenceWitnessMismatch,
    #[error("Node-local convergence canonical encoding failed: {0}")]
    Encoding(String),
    #[error("invalid controller generation admission: {0}")]
    InvalidAdmission(EncryptionGenerationDistributionError),
    #[error("controller admission substituted the Node-local prepared generation")]
    ControllerSubstitution,
    #[error("Node-local activation proof ladder failed: {0}")]
    InvalidActivation(EncryptionActivationLatchError),
}
