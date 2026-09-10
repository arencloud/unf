//! Capability-typed Node-local generation proof ladder and Linux convergence.
//!
//! A Node proposal, controller admission, route proof, and Aya activation are
//! deliberately different Rust types. Each transition consumes the preceding
//! capability, so callers cannot reorder the proof ladder or reuse a route
//! permit across generations. No serialized value becomes kernel authority.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use unf_common::Revision;

use crate::{
    AdmittedEncryptionGeneration, EncryptionActivationLatch, EncryptionActivationLatchError,
    EncryptionGenerationDistributionError, EncryptionGenerationFact, EncryptionGenerationFactError,
    EncryptionGenerationPathProofPermit, EncryptionGenerationRecipient, EncryptionRouteAuthority,
    EncryptionRouteAuthorityError, EncryptionRoutePublicationPermit, FastPathMapCheckpoint,
    FastPathPublishedGeneration, FastPathTransactionError, KernelApplyOutcome, KeyAuthorityError,
    NodeKeyAuthority, PathProvenEncryptionActivationLatch, WireGuardEpochActivation,
    WireGuardKernelConfigurationDigest, WireGuardKernelError, WireGuardKernelPlan,
    WireGuardKernelPlanDigest, WireGuardKernelSnapshot,
};

#[cfg(target_os = "linux")]
use crate::{LinuxEncryptionRouteProvider, LinuxWireGuardProvider};

const CONVERGENCE_WITNESS_DOMAIN: &[u8] = b"unf.node-local-linux-convergence.v1\0";
const RECOVERY_PLAN_DIGEST_DOMAIN: &[u8] = b"unf.node-local-recovery-plan.v1\0";
pub const NODE_LOCAL_RECOVERY_PLAN_SCHEMA_VERSION: u16 = 1;

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct NodeLocalRecoveryPlanDigest(pub [u8; 32]);

/// Secret-free durable recipe for reconstructing fresh Node-local proof after
/// restart. It contains no private key, route permit, latch, or map authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct NodeLocalRecoveryPlan {
    pub schema_version: u16,
    pub fact: EncryptionGenerationFact,
    pub plans: Vec<WireGuardKernelPlan>,
    pub recovery_digest: NodeLocalRecoveryPlanDigest,
}

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
    recovery_plan: NodeLocalRecoveryPlan,
    route_authority: EncryptionRouteAuthority,
    commitments: Vec<KernelConvergenceCommitment>,
    witness: NodeLocalConvergenceWitness,
}

impl NodeLocalRecoveryPlan {
    /// Seals the exact public plan set needed to reconstruct a local
    /// convergence capability after process or Node-service restart.
    ///
    /// # Errors
    ///
    /// Rejects malformed facts, plans, ordering conflicts, or a plan set that
    /// differs from the checkpoint's complete transport commitments.
    pub fn issue(
        membership_revision: Revision,
        recipient: EncryptionGenerationRecipient,
        checkpoint: FastPathMapCheckpoint,
        mut plans: Vec<WireGuardKernelPlan>,
    ) -> Result<Self, NodeLocalOrchestratorError> {
        plans.sort_by(|left, right| {
            (left.epoch, left.interface_name.as_str(), left.plan_digest.0).cmp(&(
                right.epoch,
                right.interface_name.as_str(),
                right.plan_digest.0,
            ))
        });
        let fact = EncryptionGenerationFact::issue(membership_revision, recipient, checkpoint)
            .map_err(NodeLocalOrchestratorError::InvalidFact)?;
        let mut recovery = Self {
            schema_version: NODE_LOCAL_RECOVERY_PLAN_SCHEMA_VERSION,
            fact,
            plans,
            recovery_digest: NodeLocalRecoveryPlanDigest([0; 32]),
        };
        recovery.validate_authority()?;
        recovery.recovery_digest = recovery.calculate_digest()?;
        Ok(recovery)
    }

    /// Independently replays the nested fact, canonical plan set, transport
    /// commitments, and domain-separated recovery digest.
    ///
    /// # Errors
    ///
    /// Rejects any mutation or incomplete/cross-Node plan set.
    pub fn verify(&self) -> Result<(), NodeLocalOrchestratorError> {
        self.validate_authority()?;
        if self.recovery_digest != self.calculate_digest()? {
            return Err(NodeLocalOrchestratorError::RecoveryPlanDigestMismatch);
        }
        Ok(())
    }

    /// Reconstructs a fresh non-serializable capability from independently
    /// obtained exact kernel snapshots. Snapshot order is irrelevant.
    ///
    /// # Errors
    ///
    /// Rejects partial, stale, foreign, duplicate, or substituted readback.
    pub fn rehydrate_exact_readback(
        &self,
        snapshots: &[WireGuardKernelSnapshot],
    ) -> Result<LinuxPreparedLocalGeneration, NodeLocalOrchestratorError> {
        self.verify()?;
        LinuxPreparedLocalGeneration::bind_recovery_plan(self.clone(), snapshots)
    }

    /// Reads every real Linux `WireGuard` interface and route afresh before
    /// reconstructing the single-use local capability.
    ///
    /// # Errors
    ///
    /// Rejects absent, foreign, partial, or mutated kernel state.
    #[cfg(target_os = "linux")]
    pub async fn rehydrate_linux(
        &self,
    ) -> Result<LinuxPreparedLocalGeneration, NodeLocalOrchestratorError> {
        self.verify()?;
        let provider = LinuxWireGuardProvider;
        let mut snapshots = Vec::with_capacity(self.plans.len());
        for plan in &self.plans {
            snapshots.push(
                provider
                    .readback(plan)
                    .await
                    .map_err(NodeLocalOrchestratorError::InvalidKernel)?,
            );
        }
        self.rehydrate_exact_readback(&snapshots)
    }

    /// Repairs only digest-bound UNF-owned kernel state before reconstructing
    /// fresh volatile proof for an already admitted generation.
    ///
    /// This is the restart counterpart to initial staging: a down link can
    /// make Linux withdraw its connected policy-table routes even after the
    /// link is raised again. Read-only rehydration must reject that drift, but
    /// a restart must also be able to restore the exact durable plan without
    /// inventing a successor generation. The provider refuses foreign links,
    /// aliases, route keys, public keys, and private-key mismatches.
    ///
    /// # Errors
    ///
    /// Rejects mutated recovery authority, foreign kernel state, unavailable
    /// key authority, partial convergence, or incomplete rollback.
    #[cfg(target_os = "linux")]
    pub async fn repair_and_rehydrate_linux(
        &self,
        key_authority: &NodeKeyAuthority,
    ) -> Result<LinuxPreparedLocalGeneration, NodeLocalOrchestratorError> {
        self.verify()?;
        preflight_linux_plans(&self.fact.recipient, key_authority, &self.plans)?;
        let provider = LinuxWireGuardProvider;
        let mut snapshots = Vec::with_capacity(self.plans.len());
        let mut created = Vec::new();
        for plan in &self.plans {
            let private_key = key_authority
                .private_key_for_kernel_plan(plan)
                .map_err(NodeLocalOrchestratorError::InvalidKeyAuthority)?;
            match provider.apply(plan, private_key).await {
                Ok((outcome, snapshot)) => {
                    if outcome == KernelApplyOutcome::Created {
                        created.push(plan.clone());
                    }
                    snapshots.push(snapshot);
                }
                Err(cause) => {
                    return rollback_recovery_created(&provider, &created, cause).await;
                }
            }
        }
        match self.rehydrate_exact_readback(&snapshots) {
            Ok(prepared) => Ok(prepared),
            Err(cause) => {
                for plan in created.iter().rev() {
                    provider
                        .delete(plan)
                        .await
                        .map_err(NodeLocalOrchestratorError::InvalidKernel)?;
                }
                Err(cause)
            }
        }
    }

    fn validate_authority(&self) -> Result<(), NodeLocalOrchestratorError> {
        if self.schema_version != NODE_LOCAL_RECOVERY_PLAN_SCHEMA_VERSION {
            return Err(NodeLocalOrchestratorError::InvalidRecoveryPlan);
        }
        self.fact
            .verify()
            .map_err(NodeLocalOrchestratorError::InvalidFact)?;
        if self.plans.windows(2).any(|pair| {
            (
                pair[0].epoch,
                pair[0].interface_name.as_str(),
                pair[0].plan_digest.0,
            ) >= (
                pair[1].epoch,
                pair[1].interface_name.as_str(),
                pair[1].plan_digest.0,
            )
        }) {
            return Err(NodeLocalOrchestratorError::InvalidRecoveryPlan);
        }
        let desired = self
            .fact
            .checkpoint
            .desired_state()
            .map_err(NodeLocalOrchestratorError::InvalidCheckpoint)?;
        preflight_plan_cut(&self.fact.recipient, &desired, &self.plans)?;
        Ok(())
    }

    fn calculate_digest(&self) -> Result<NodeLocalRecoveryPlanDigest, NodeLocalOrchestratorError> {
        let mut canonical = self.clone();
        canonical.recovery_digest = NodeLocalRecoveryPlanDigest([0; 32]);
        let encoded = serde_json::to_vec(&canonical)
            .map_err(|error| NodeLocalOrchestratorError::Encoding(error.to_string()))?;
        let mut hasher = Sha256::new();
        hasher.update(RECOVERY_PLAN_DIGEST_DOMAIN);
        hasher.update(encoded);
        Ok(NodeLocalRecoveryPlanDigest(hasher.finalize().into()))
    }
}

#[cfg(target_os = "linux")]
async fn rollback_recovery_created<T>(
    provider: &LinuxWireGuardProvider,
    created: &[WireGuardKernelPlan],
    cause: WireGuardKernelError,
) -> Result<T, NodeLocalOrchestratorError> {
    for plan in created.iter().rev() {
        if let Err(rollback) = provider.delete(plan).await {
            return Err(NodeLocalOrchestratorError::InvalidKernel(
                WireGuardKernelError::Rollback {
                    cause: cause.to_string(),
                    rollback: rollback.to_string(),
                },
            ));
        }
    }
    Err(NodeLocalOrchestratorError::InvalidKernel(cause))
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
        let desired = self
            .admitted
            .checkpoint
            .desired_state()
            .map_err(NodeLocalOrchestratorError::InvalidCheckpoint)?;
        if desired
            .decision_authority
            .iter()
            .any(|decision| decision.disposition == crate::EncryptionDisposition::Required)
        {
            return Err(NodeLocalOrchestratorError::InvalidActivation(
                EncryptionActivationLatchError::MissingPathProof,
            ));
        }
        EncryptionActivationLatch::issue(&self.admitted, &recipient, applied, route_permit)
            .map_err(NodeLocalOrchestratorError::InvalidActivation)
    }

    /// Consumes controller admission, route proof, and complete current duplex
    /// path evidence into one final pre-map capability.
    ///
    /// # Errors
    ///
    /// Rejects any Node, generation, predecessor, route, or path-proof drift.
    pub fn authorize_path_proven_map_activation(
        self,
        applied: Option<FastPathPublishedGeneration>,
        route_permit: EncryptionRoutePublicationPermit,
        path_permit: EncryptionGenerationPathProofPermit,
        now_unix_ms: u64,
    ) -> Result<PathProvenEncryptionActivationLatch, NodeLocalOrchestratorError> {
        let recipient = self.admitted.recipient.clone();
        let desired = self
            .admitted
            .checkpoint
            .desired_state()
            .map_err(NodeLocalOrchestratorError::InvalidCheckpoint)?;
        path_permit
            .verify_for(&desired, &recipient, now_unix_ms)
            .map_err(|error| {
                NodeLocalOrchestratorError::InvalidActivation(
                    EncryptionActivationLatchError::InvalidPathProof(error),
                )
            })?;
        let latch =
            EncryptionActivationLatch::issue(&self.admitted, &recipient, applied, route_permit)
                .map_err(NodeLocalOrchestratorError::InvalidActivation)?;
        Ok(PathProvenEncryptionActivationLatch::issue(
            latch,
            path_permit,
            recipient,
        ))
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
        // Preserve the established local-kernel error boundary before sealing
        // the durable recovery recipe. Cross-Node or partial readback is a
        // kernel commitment mismatch, never remotely supplied fact authority.
        let desired = checkpoint
            .desired_state()
            .map_err(NodeLocalOrchestratorError::InvalidCheckpoint)?;
        validate_exact_kernel_cut(&recipient, &desired, plans, snapshots)?;
        let recovery_plan = NodeLocalRecoveryPlan::issue(
            membership_revision,
            recipient,
            checkpoint,
            plans.to_vec(),
        )?;
        Self::bind_recovery_plan(recovery_plan, snapshots)
    }

    fn bind_recovery_plan(
        recovery_plan: NodeLocalRecoveryPlan,
        snapshots: &[WireGuardKernelSnapshot],
    ) -> Result<Self, NodeLocalOrchestratorError> {
        recovery_plan.verify()?;
        let desired = recovery_plan
            .fact
            .checkpoint
            .desired_state()
            .map_err(NodeLocalOrchestratorError::InvalidCheckpoint)?;
        let commitments = validate_exact_kernel_cut(
            &recovery_plan.fact.recipient,
            &desired,
            &recovery_plan.plans,
            snapshots,
        )?;
        let route_authority = EncryptionRouteAuthority::issue(&desired, snapshots)
            .map_err(NodeLocalOrchestratorError::InvalidRouteAuthority)?;
        let proposal = NodeLocalGenerationProposal {
            fact: recovery_plan.fact.clone(),
        };
        let witness = convergence_witness(proposal.fact(), &route_authority, &commitments)?;
        Ok(Self {
            proposal,
            recovery_plan,
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

    /// Returns the secret-free durable recipe used to reconstruct this proof.
    #[must_use]
    pub const fn recovery_plan(&self) -> &NodeLocalRecoveryPlan {
        &self.recovery_plan
    }

    #[must_use]
    pub const fn witness(&self) -> NodeLocalConvergenceWitness {
        self.witness
    }

    /// Verifies that a remotely admitted generation is the byte-exact echo of
    /// this Node's locally prepared fact. This check deliberately does not
    /// consume or grant activation authority, so the same prepared capability
    /// can survive authenticated publication retries and `204` responses.
    ///
    /// # Errors
    ///
    /// Rejects malformed admission or any recipient/checkpoint substitution.
    pub fn verify_controller_admission(
        &self,
        admitted: &AdmittedEncryptionGeneration,
    ) -> Result<(), NodeLocalOrchestratorError> {
        self.proposal
            .fact()
            .verify()
            .map_err(NodeLocalOrchestratorError::InvalidFact)?;
        admitted
            .verify()
            .map_err(NodeLocalOrchestratorError::InvalidAdmission)?;
        if admitted.recipient != self.proposal.fact().recipient
            || admitted.checkpoint != self.proposal.fact().checkpoint
        {
            return Err(NodeLocalOrchestratorError::ControllerSubstitution);
        }
        Ok(())
    }

    /// Installs and independently reads the exact policy-route rules while the
    /// packet-map generation is still unpublished. The returned authority is
    /// consuming; the prepared generation itself remains available for a
    /// bounded live-path exchange or retry.
    ///
    /// # Errors
    ///
    /// Rejects convergence drift, controller substitution, route mutation, or
    /// a conflicting foreign rule.
    #[cfg(target_os = "linux")]
    pub async fn activate_linux_routes_for_probe(
        &self,
        admitted: &AdmittedEncryptionGeneration,
    ) -> Result<EncryptionRoutePublicationPermit, NodeLocalOrchestratorError> {
        if self.witness
            != convergence_witness(
                self.proposal.fact(),
                &self.route_authority,
                &self.commitments,
            )?
        {
            return Err(NodeLocalOrchestratorError::ConvergenceWitnessMismatch);
        }
        self.verify_controller_admission(admitted)?;
        LinuxEncryptionRouteProvider
            .activate(&self.route_authority)
            .await
            .map_err(NodeLocalOrchestratorError::InvalidRouteAuthority)
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
        self.verify_controller_admission(&admitted)?;
        let controller_bound = self.proposal.bind_controller_admission(admitted)?;
        let permit = LinuxEncryptionRouteProvider
            .activate(&self.route_authority)
            .await
            .map_err(NodeLocalOrchestratorError::InvalidRouteAuthority)?;
        controller_bound.authorize_map_activation(applied, permit)
    }

    /// Performs the Linux route join and retains current two-ended path proof
    /// until the final map boundary for a Required generation.
    ///
    /// # Errors
    ///
    /// Rejects convergence/controller/route drift or incomplete, expired, or
    /// substituted path evidence.
    #[cfg(target_os = "linux")]
    pub fn admit_and_activate_linux_path_proven(
        self,
        admitted: AdmittedEncryptionGeneration,
        applied: Option<FastPathPublishedGeneration>,
        route_permit: EncryptionRoutePublicationPermit,
        path_permit: EncryptionGenerationPathProofPermit,
        now_unix_ms: u64,
    ) -> Result<PathProvenEncryptionActivationLatch, NodeLocalOrchestratorError> {
        if self.witness
            != convergence_witness(
                self.proposal.fact(),
                &self.route_authority,
                &self.commitments,
            )?
        {
            return Err(NodeLocalOrchestratorError::ConvergenceWitnessMismatch);
        }
        self.verify_controller_admission(&admitted)?;
        let controller_bound = self.proposal.bind_controller_admission(admitted)?;
        controller_bound.authorize_path_proven_map_activation(
            applied,
            route_permit,
            path_permit,
            now_unix_ms,
        )
    }
}

fn preflight_linux_plans(
    recipient: &EncryptionGenerationRecipient,
    key_authority: &NodeKeyAuthority,
    plans: &[WireGuardKernelPlan],
) -> Result<(), NodeLocalOrchestratorError> {
    if key_authority.node_name() != recipient.node_name
        || key_authority.node_uid() != recipient.node_uid
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
    if plans.len() != snapshots.len() || plans.is_empty() && !dormant_fast_path(desired) {
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
    if expected.len() != plans.len() || plans.is_empty() && !dormant_fast_path(desired) {
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

/// A zero-kernel-authority generation is dormant from the kernel provider's
/// perspective even when its map carries explicit Native decisions.
fn dormant_fast_path(desired: &crate::EncryptionFastPathState) -> bool {
    desired.config.epoch_count == 0
        && desired.config.transport_count == 0
        && desired.config.path_count == 0
        && desired.transport_authority.is_empty()
        && desired.path_authority.is_empty()
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
    #[error("invalid Node-local recovery plan")]
    InvalidRecoveryPlan,
    #[error("Node-local recovery plan digest does not match")]
    RecoveryPlanDigestMismatch,
    #[error("Node-local convergence canonical encoding failed: {0}")]
    Encoding(String),
    #[error("invalid controller generation admission: {0}")]
    InvalidAdmission(EncryptionGenerationDistributionError),
    #[error("controller admission substituted the Node-local prepared generation")]
    ControllerSubstitution,
    #[error("Node-local activation proof ladder failed: {0}")]
    InvalidActivation(EncryptionActivationLatchError),
}
