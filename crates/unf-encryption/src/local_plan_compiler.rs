//! Snapshot-first Node-local encryption generation compiler.
//!
//! The compiler removes the circular dependency between kernel readback and
//! fast-path authority: it derives one coalesced `WireGuard` plan per epoch,
//! stages and reads that plan, then compiles the exact readback digests into a
//! map checkpoint. Identity cardinality therefore never creates per-policy or
//! per-workload tunnels.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use unf_common::{IdentityId, Revision};

use crate::{
    AttestedEncryptionPathContract, EncryptionContractError, EncryptionDisposition,
    EncryptionGenerationRecipient, FastPathCompileContext, FastPathDecisionInput,
    FastPathEpochAdmission, FastPathEpochState, FastPathError, FastPathMapCheckpoint,
    FastPathPublishedGeneration, FastPathTransactionError, KeyAuthorityError,
    LinuxPreparedLocalGeneration, MAX_FAST_PATH_DECISIONS, NodeKeyAuthority,
    NodeLocalOrchestratorError, ProofCarryingKernelTransaction, UnderlayAddressFamily,
    UnderlayMtuObservation, WIREGUARD_IPV4_OVERHEAD, WIREGUARD_IPV6_OVERHEAD,
    WireGuardEpochActivation, WireGuardKernelError, WireGuardKernelPlan, WireGuardKernelPlanInput,
    WireGuardKernelSnapshot, WireGuardMtuEnvelope, WireGuardPeerPlan, compile_encryption_fast_path,
};

pub const NODE_LOCAL_PLAN_SNAPSHOT_SCHEMA_VERSION: u16 = 2;
const NODE_LOCAL_PLAN_SNAPSHOT_DIGEST_DOMAIN: &[u8] = b"unf.node-local-plan-snapshot.v2\0";

#[cfg(target_os = "linux")]
use crate::LinuxWireGuardProvider;

/// One active or draining epoch admitted to a Node-local generation.
#[derive(Clone, Copy)]
pub struct NodeLocalEpochPlan<'a> {
    pub contract: &'a AttestedEncryptionPathContract,
    pub readiness_digest: [u8; 32],
    pub state: FastPathEpochState,
    pub drain_until_monotonic_ns: u64,
}

/// Exact revisions and bounded transport behavior for one local compilation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeLocalPlanCompileContext {
    pub membership_revision: Revision,
    pub kernel_transaction_revision: Revision,
    pub map_transaction_revision: Revision,
    pub recipient: EncryptionGenerationRecipient,
    pub fast_path: FastPathCompileContext,
    pub listen_port: u16,
    pub persistent_keepalive_seconds: u16,
    pub prior: Option<FastPathPublishedGeneration>,
}

/// Serializable epoch recipe. It carries no private key, kernel readback,
/// route permit, or map authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct NodeLocalEpochPlanRecord {
    pub contract: AttestedEncryptionPathContract,
    pub readiness_digest: [u8; 32],
    pub state: FastPathEpochState,
    pub drain_until_monotonic_ns: u64,
}

/// Serializable identity decision recipe. Required records point to one exact
/// plan in one epoch contract; native records carry no transport reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct NodeLocalDecisionPlan {
    pub source_identity: IdentityId,
    pub destination_identity: IdentityId,
    pub disposition: EncryptionDisposition,
    pub contract_epoch: Option<u64>,
    pub plan_index: Option<usize>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct NodeLocalPlanSnapshotDigest(pub [u8; 32]);

/// Whether this Node owns an encrypted transport in the current demand cut.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum NodeLocalPlanMode {
    Active,
    Dormant,
}

/// One complete, Node-scoped, secret-free input manifold. Its digest and exact
/// coverage rule prevent partial controller updates from reaching the local
/// compiler independently.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct NodeLocalPlanSnapshot {
    pub schema_version: u16,
    pub membership_revision: Revision,
    pub generation: Revision,
    pub recipient: EncryptionGenerationRecipient,
    pub mode: NodeLocalPlanMode,
    pub policy_revision: Revision,
    pub service_revision: Revision,
    pub egress_revision: Revision,
    pub listen_port: u16,
    pub persistent_keepalive_seconds: u16,
    pub epochs: Vec<NodeLocalEpochPlanRecord>,
    pub decisions: Vec<NodeLocalDecisionPlan>,
    pub snapshot_digest: NodeLocalPlanSnapshotDigest,
}

/// Unsealed fields used to issue one canonical Node-local plan snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeLocalPlanSnapshotFields {
    pub membership_revision: Revision,
    pub generation: Revision,
    pub recipient: EncryptionGenerationRecipient,
    pub mode: NodeLocalPlanMode,
    pub policy_revision: Revision,
    pub service_revision: Revision,
    pub egress_revision: Revision,
    pub listen_port: u16,
    pub persistent_keepalive_seconds: u16,
    pub epochs: Vec<NodeLocalEpochPlanRecord>,
    pub decisions: Vec<NodeLocalDecisionPlan>,
}

#[derive(Debug, Error)]
pub enum NodeLocalPlanCompilerError {
    #[error("invalid Node-local encryption compiler input: {0}")]
    InvalidInput(&'static str),
    #[error("invalid attested encryption contract: {0}")]
    InvalidContract(#[from] EncryptionContractError),
    #[error("invalid WireGuard plan or readback: {0}")]
    InvalidKernel(#[from] WireGuardKernelError),
    #[error("invalid Node-local key authority: {0}")]
    InvalidKeyAuthority(#[from] KeyAuthorityError),
    #[error("invalid encryption fast-path compilation: {0}")]
    InvalidFastPath(#[from] FastPathError),
    #[error("invalid encryption map checkpoint: {0}")]
    InvalidCheckpoint(#[from] FastPathTransactionError),
    #[error("Node-local convergence failed: {0}")]
    InvalidConvergence(#[from] NodeLocalOrchestratorError),
}

impl NodeLocalPlanSnapshot {
    /// Canonicalizes and seals one all-or-nothing local compiler input.
    ///
    /// # Errors
    ///
    /// Rejects malformed revisions, contracts, epoch state, decision coverage,
    /// transport bounds, or cross-Node authority.
    pub fn issue(
        mut fields: NodeLocalPlanSnapshotFields,
    ) -> Result<Self, NodeLocalPlanCompilerError> {
        fields
            .epochs
            .sort_by_key(|epoch| contract_epoch(&epoch.contract).unwrap_or_default());
        fields
            .decisions
            .sort_by_key(|decision| (decision.source_identity, decision.destination_identity));
        let mut snapshot = Self {
            schema_version: NODE_LOCAL_PLAN_SNAPSHOT_SCHEMA_VERSION,
            membership_revision: fields.membership_revision,
            generation: fields.generation,
            recipient: fields.recipient,
            mode: fields.mode,
            policy_revision: fields.policy_revision,
            service_revision: fields.service_revision,
            egress_revision: fields.egress_revision,
            listen_port: fields.listen_port,
            persistent_keepalive_seconds: fields.persistent_keepalive_seconds,
            epochs: fields.epochs,
            decisions: fields.decisions,
            snapshot_digest: NodeLocalPlanSnapshotDigest([0; 32]),
        };
        snapshot.validate_authority()?;
        snapshot.snapshot_digest = snapshot.calculate_digest()?;
        Ok(snapshot)
    }

    /// Replays every nested contract, exact decision-to-plan coverage, and the
    /// domain-separated digest without trusting a controller-side verdict.
    ///
    /// # Errors
    ///
    /// Rejects any mutation, unknown field, reordering, omission, or mixed
    /// recipient/revision/epoch authority.
    pub fn verify(&self) -> Result<(), NodeLocalPlanCompilerError> {
        self.validate_authority()?;
        if self.snapshot_digest != self.calculate_digest()? {
            return Err(NodeLocalPlanCompilerError::InvalidInput(
                "Node-local plan snapshot digest does not match",
            ));
        }
        Ok(())
    }

    /// Builds the non-serializable borrowed epoch inputs used only during one
    /// local compilation attempt.
    ///
    /// # Errors
    ///
    /// Rejects a mutated snapshot before returning any compiler input.
    pub fn epoch_plans(&self) -> Result<Vec<NodeLocalEpochPlan<'_>>, NodeLocalPlanCompilerError> {
        self.verify()?;
        Ok(self
            .epochs
            .iter()
            .map(|epoch| NodeLocalEpochPlan {
                contract: &epoch.contract,
                readiness_digest: epoch.readiness_digest,
                state: epoch.state,
                drain_until_monotonic_ns: epoch.drain_until_monotonic_ns,
            })
            .collect())
    }

    /// Reconstructs the pure fast-path decision input after snapshot replay.
    ///
    /// # Errors
    ///
    /// Rejects a mutated snapshot before returning any decision.
    pub fn fast_path_decisions(
        &self,
    ) -> Result<Vec<FastPathDecisionInput>, NodeLocalPlanCompilerError> {
        self.verify()?;
        Ok(self
            .decisions
            .iter()
            .map(|decision| FastPathDecisionInput {
                source_identity: decision.source_identity,
                destination_identity: decision.destination_identity,
                disposition: decision.disposition,
                contract_epoch: decision.contract_epoch,
                plan_index: decision.plan_index,
            })
            .collect())
    }

    /// Produces the exact local compiler context while keeping observations and
    /// the durable predecessor Node-local.
    ///
    /// # Errors
    ///
    /// Rejects invalid time or a mutated snapshot.
    pub fn compile_context(
        &self,
        prior: Option<FastPathPublishedGeneration>,
        now_unix_ms: u64,
        now_monotonic_ns: u64,
    ) -> Result<NodeLocalPlanCompileContext, NodeLocalPlanCompilerError> {
        self.verify()?;
        if now_unix_ms == 0 || now_monotonic_ns == 0 {
            return Err(NodeLocalPlanCompilerError::InvalidInput(
                "local compiler observation time must be nonzero",
            ));
        }
        let bank = prior.map_or(0, |published| published.bank ^ 1);
        Ok(NodeLocalPlanCompileContext {
            membership_revision: self.membership_revision,
            kernel_transaction_revision: self.generation,
            map_transaction_revision: self.generation,
            recipient: self.recipient.clone(),
            fast_path: FastPathCompileContext {
                generation: self.generation,
                policy_revision: self.policy_revision,
                service_revision: self.service_revision,
                egress_revision: self.egress_revision,
                bank,
                now_unix_ms,
                now_monotonic_ns,
            },
            listen_port: self.listen_port,
            persistent_keepalive_seconds: self.persistent_keepalive_seconds,
            prior,
        })
    }

    /// Replays this complete snapshot and compiles exact supplied kernel
    /// readback into a fresh non-serializable local capability.
    ///
    /// # Errors
    ///
    /// Rejects invalid snapshot authority, time, predecessor, or readback.
    pub fn prepare_exact_readback(
        &self,
        prior: Option<FastPathPublishedGeneration>,
        now_unix_ms: u64,
        now_monotonic_ns: u64,
        snapshots: &[WireGuardKernelSnapshot],
    ) -> Result<LinuxPreparedLocalGeneration, NodeLocalPlanCompilerError> {
        let context = self.compile_context(prior, now_unix_ms, now_monotonic_ns)?;
        let epochs = self.epoch_plans()?;
        let decisions = self.fast_path_decisions()?;
        LinuxPreparedLocalGeneration::compile_exact_readback(
            context, &epochs, &decisions, snapshots,
        )
    }

    /// Replays this complete snapshot and runs the real Linux snapshot-first
    /// compilation path using only the exact Node-local key authority.
    ///
    /// # Errors
    ///
    /// Rejects invalid snapshot authority, time, predecessor, keys, kernel
    /// state, or exact-readback-derived map authority.
    #[cfg(target_os = "linux")]
    pub async fn prepare_linux(
        &self,
        prior: Option<FastPathPublishedGeneration>,
        now_unix_ms: u64,
        now_monotonic_ns: u64,
        key_authority: &NodeKeyAuthority,
    ) -> Result<LinuxPreparedLocalGeneration, NodeLocalPlanCompilerError> {
        let context = self.compile_context(prior, now_unix_ms, now_monotonic_ns)?;
        let epochs = self.epoch_plans()?;
        let decisions = self.fast_path_decisions()?;
        LinuxPreparedLocalGeneration::compile_and_stage_linux(
            context,
            &epochs,
            &decisions,
            key_authority,
        )
        .await
    }

    fn validate_authority(&self) -> Result<(), NodeLocalPlanCompilerError> {
        if self.schema_version != NODE_LOCAL_PLAN_SNAPSHOT_SCHEMA_VERSION
            || self.membership_revision == Revision::INITIAL
            || self.generation == Revision::INITIAL
            || self.policy_revision == Revision::INITIAL
            || self.service_revision == Revision::INITIAL
            || self.egress_revision == Revision::INITIAL
            || self.recipient.node_name.is_empty()
            || self.recipient.node_uid.is_empty()
            || self.listen_port == 0
            || self.persistent_keepalive_seconds > 600
            || self.epochs.len() > 2
            || self.decisions.len() > MAX_FAST_PATH_DECISIONS
        {
            return Err(NodeLocalPlanCompilerError::InvalidInput(
                "Node-local plan snapshot shape is invalid",
            ));
        }
        self.validate_mode()?;
        let epoch_inputs = self
            .epochs
            .iter()
            .map(|epoch| NodeLocalEpochPlan {
                contract: &epoch.contract,
                readiness_digest: epoch.readiness_digest,
                state: epoch.state,
                drain_until_monotonic_ns: epoch.drain_until_monotonic_ns,
            })
            .collect::<Vec<_>>();
        let structural_context = NodeLocalPlanCompileContext {
            membership_revision: self.membership_revision,
            kernel_transaction_revision: self.generation,
            map_transaction_revision: self.generation,
            recipient: self.recipient.clone(),
            fast_path: FastPathCompileContext {
                generation: self.generation,
                policy_revision: self.policy_revision,
                service_revision: self.service_revision,
                egress_revision: self.egress_revision,
                bank: 0,
                now_unix_ms: 1,
                now_monotonic_ns: 1,
            },
            listen_port: self.listen_port,
            persistent_keepalive_seconds: self.persistent_keepalive_seconds,
            prior: None,
        };
        if self.mode == NodeLocalPlanMode::Active {
            validate_context(&structural_context, &epoch_inputs)?;
            compile_inactive_kernel_plans(&structural_context, &epoch_inputs)?;
        }

        let epoch_numbers = self
            .epochs
            .iter()
            .map(|epoch| contract_epoch(&epoch.contract))
            .collect::<Result<Vec<_>, _>>()?;
        if epoch_numbers.windows(2).any(|pair| pair[0] >= pair[1])
            || self.decisions.windows(2).any(|pair| {
                (pair[0].source_identity, pair[0].destination_identity)
                    >= (pair[1].source_identity, pair[1].destination_identity)
            })
        {
            return Err(NodeLocalPlanCompilerError::InvalidInput(
                "Node-local plan snapshot is not canonical",
            ));
        }
        validate_decision_coverage(self, &epoch_numbers)?;
        if self.epochs.iter().any(|epoch| {
            epoch.readiness_digest == [0; 32]
                || epoch.contract.plans[0].revisions.policy != self.policy_revision
        }) {
            return Err(NodeLocalPlanCompilerError::InvalidInput(
                "epoch readiness or policy revision is not exact",
            ));
        }
        Ok(())
    }

    fn validate_mode(&self) -> Result<(), NodeLocalPlanCompilerError> {
        match self.mode {
            NodeLocalPlanMode::Active
                if self.epochs.is_empty()
                    || self
                        .epochs
                        .iter()
                        .filter(|epoch| epoch.state == FastPathEpochState::Active)
                        .count()
                        != 1 =>
            {
                return Err(NodeLocalPlanCompilerError::InvalidInput(
                    "active Node-local plan has no unique active epoch",
                ));
            }
            NodeLocalPlanMode::Dormant if !self.epochs.is_empty() || !self.decisions.is_empty() => {
                return Err(NodeLocalPlanCompilerError::InvalidInput(
                    "dormant Node-local plan carries transport authority",
                ));
            }
            NodeLocalPlanMode::Active | NodeLocalPlanMode::Dormant => {}
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Result<NodeLocalPlanSnapshotDigest, NodeLocalPlanCompilerError> {
        let mut canonical = self.clone();
        canonical.snapshot_digest = NodeLocalPlanSnapshotDigest([0; 32]);
        let encoded = serde_json::to_vec(&canonical).map_err(|_| {
            NodeLocalPlanCompilerError::InvalidInput("Node-local plan snapshot encoding failed")
        })?;
        let mut hasher = Sha256::new();
        hasher.update(NODE_LOCAL_PLAN_SNAPSHOT_DIGEST_DOMAIN);
        hasher.update(encoded);
        Ok(NodeLocalPlanSnapshotDigest(hasher.finalize().into()))
    }
}

fn validate_decision_coverage(
    snapshot: &NodeLocalPlanSnapshot,
    epoch_numbers: &[u64],
) -> Result<(), NodeLocalPlanCompilerError> {
    let mut covered = BTreeSet::new();
    for decision in &snapshot.decisions {
        if decision.source_identity.get() == 0 || decision.destination_identity.get() == 0 {
            return Err(NodeLocalPlanCompilerError::InvalidInput(
                "decision identity zero is reserved",
            ));
        }
        match decision.disposition {
            EncryptionDisposition::Native
                if decision.contract_epoch.is_none() && decision.plan_index.is_none() => {}
            EncryptionDisposition::Required => {
                let epoch =
                    decision
                        .contract_epoch
                        .ok_or(NodeLocalPlanCompilerError::InvalidInput(
                            "required decision has no contract epoch",
                        ))?;
                let plan_index =
                    decision
                        .plan_index
                        .ok_or(NodeLocalPlanCompilerError::InvalidInput(
                            "required decision has no contract plan",
                        ))?;
                let epoch_position = epoch_numbers.binary_search(&epoch).map_err(|_| {
                    NodeLocalPlanCompilerError::InvalidInput(
                        "required decision references an unknown epoch",
                    )
                })?;
                let plan = snapshot.epochs[epoch_position]
                    .contract
                    .plans
                    .get(plan_index)
                    .ok_or(NodeLocalPlanCompilerError::InvalidInput(
                        "required decision references an unknown contract plan",
                    ))?;
                if plan.source.identity != decision.source_identity
                    || plan.destination.identity != decision.destination_identity
                    || !covered.insert((epoch_position, plan_index))
                {
                    return Err(NodeLocalPlanCompilerError::InvalidInput(
                        "required decision does not exactly cover its contract plan",
                    ));
                }
            }
            EncryptionDisposition::Native => {
                return Err(NodeLocalPlanCompilerError::InvalidInput(
                    "native decision carries transport authority",
                ));
            }
        }
    }
    let expected: usize = snapshot
        .epochs
        .iter()
        .map(|epoch| epoch.contract.plans.len())
        .sum();
    if covered.len() != expected {
        return Err(NodeLocalPlanCompilerError::InvalidInput(
            "required contract plans are not completely covered",
        ));
    }
    Ok(())
}

impl LinuxPreparedLocalGeneration {
    /// Compiles a generation only after exact snapshots exist. This pure
    /// boundary is deterministic and is used for independent replay/testing.
    ///
    /// # Errors
    ///
    /// Rejects malformed contracts, epoch ambiguity, cross-Node authority,
    /// partial readback, revision drift, or a noncanonical map generation.
    pub fn compile_exact_readback(
        context: NodeLocalPlanCompileContext,
        epochs: &[NodeLocalEpochPlan<'_>],
        decisions: &[FastPathDecisionInput],
        snapshots: &[WireGuardKernelSnapshot],
    ) -> Result<Self, NodeLocalPlanCompilerError> {
        validate_context(&context, epochs)?;
        let plans = compile_inactive_kernel_plans(&context, epochs)?;
        if snapshots.len() != plans.len() {
            return Err(NodeLocalPlanCompilerError::InvalidInput(
                "the complete epoch snapshot cut is required",
            ));
        }

        let mut ordered_snapshots = Vec::with_capacity(plans.len());
        let mut transactions = Vec::with_capacity(plans.len());
        for plan in &plans {
            let mut matches = snapshots
                .iter()
                .filter(|snapshot| snapshot.verify_against(plan).is_ok());
            let snapshot = matches
                .next()
                .ok_or(NodeLocalPlanCompilerError::InvalidInput(
                    "an exact epoch snapshot is missing",
                ))?;
            if matches.next().is_some() {
                return Err(NodeLocalPlanCompilerError::InvalidInput(
                    "duplicate epoch snapshots are ambiguous",
                ));
            }
            let active_plan = with_activation(plan, WireGuardEpochActivation::Active)?;
            let mut transaction = ProofCarryingKernelTransaction::begin(
                context.kernel_transaction_revision,
                active_plan,
                None,
            )?;
            transaction.commit(snapshot)?;
            ordered_snapshots.push(snapshot);
            transactions.push(transaction);
        }

        let admissions = epochs
            .iter()
            .map(|epoch| {
                let epoch_number = contract_epoch(epoch.contract)?;
                let position = plans
                    .iter()
                    .position(|plan| plan.epoch == epoch_number)
                    .ok_or(NodeLocalPlanCompilerError::InvalidInput(
                        "compiled epoch plan disappeared",
                    ))?;
                Ok(FastPathEpochAdmission {
                    contract: epoch.contract,
                    transaction: &transactions[position],
                    readback: ordered_snapshots[position],
                    readiness_digest: epoch.readiness_digest,
                    state: epoch.state,
                    drain_until_monotonic_ns: epoch.drain_until_monotonic_ns,
                })
            })
            .collect::<Result<Vec<_>, NodeLocalPlanCompilerError>>()?;
        let desired = compile_encryption_fast_path(context.fast_path, &admissions, decisions)?;
        let checkpoint = FastPathMapCheckpoint::begin(
            context.map_transaction_revision,
            &desired,
            context.prior,
        )?;
        LinuxPreparedLocalGeneration::bind_exact_readback(
            context.membership_revision,
            context.recipient,
            checkpoint,
            &plans,
            snapshots,
        )
        .map_err(NodeLocalPlanCompilerError::from)
    }

    /// Executes the snapshot-first algorithm against real Linux: derive one
    /// interface per epoch, preflight every local key before mutation, stage
    /// exact kernel state, and only then compile map authority from readback.
    ///
    /// # Errors
    ///
    /// In addition to compilation errors, rejects missing/mismatched local key
    /// authority and any real kernel convergence failure.
    #[cfg(target_os = "linux")]
    pub async fn compile_and_stage_linux(
        context: NodeLocalPlanCompileContext,
        epochs: &[NodeLocalEpochPlan<'_>],
        decisions: &[FastPathDecisionInput],
        key_authority: &NodeKeyAuthority,
    ) -> Result<Self, NodeLocalPlanCompilerError> {
        validate_context(&context, epochs)?;
        let plans = compile_inactive_kernel_plans(&context, epochs)?;
        let keys = plans
            .iter()
            .map(|plan| key_authority.private_key_for_kernel_plan(plan))
            .collect::<Result<Vec<_>, _>>()?;
        let provider = LinuxWireGuardProvider;
        let mut snapshots = Vec::with_capacity(plans.len());
        for (plan, private_key) in plans.iter().zip(keys) {
            let (_, snapshot) = provider.apply(plan, private_key).await?;
            snapshots.push(snapshot);
        }
        Self::compile_exact_readback(context, epochs, decisions, &snapshots)
    }
}

fn validate_context(
    context: &NodeLocalPlanCompileContext,
    epochs: &[NodeLocalEpochPlan<'_>],
) -> Result<(), NodeLocalPlanCompilerError> {
    if context.membership_revision == Revision::INITIAL
        || context.kernel_transaction_revision == Revision::INITIAL
        || context.map_transaction_revision == Revision::INITIAL
        || context.map_transaction_revision != context.fast_path.generation
        || context.recipient.node_name.is_empty()
        || context.recipient.node_uid.is_empty()
        || context.listen_port == 0
        || context.persistent_keepalive_seconds > 600
        || epochs.is_empty()
        || epochs.len() > 2
        || epochs
            .iter()
            .filter(|epoch| epoch.state == FastPathEpochState::Active)
            .count()
            != 1
    {
        return Err(NodeLocalPlanCompilerError::InvalidInput(
            "revisions, recipient, transport bounds, or epoch frontier are invalid",
        ));
    }
    Ok(())
}

fn compile_inactive_kernel_plans(
    context: &NodeLocalPlanCompileContext,
    epochs: &[NodeLocalEpochPlan<'_>],
) -> Result<Vec<WireGuardKernelPlan>, NodeLocalPlanCompilerError> {
    let mut plans = epochs
        .iter()
        .map(|epoch| compile_epoch_plan(context, epoch.contract))
        .collect::<Result<Vec<_>, _>>()?;
    plans.sort_by_key(|plan| plan.epoch);
    if plans.windows(2).any(|pair| pair[0].epoch >= pair[1].epoch) {
        return Err(NodeLocalPlanCompilerError::InvalidInput(
            "epoch plans must be unique",
        ));
    }
    Ok(plans)
}

fn compile_epoch_plan(
    context: &NodeLocalPlanCompileContext,
    contract: &AttestedEncryptionPathContract,
) -> Result<WireGuardKernelPlan, NodeLocalPlanCompilerError> {
    contract.verify_integrity()?;
    if contract.local_node.name != context.recipient.node_name
        || contract.local_node.uid != context.recipient.node_uid
        || contract.plans.is_empty()
    {
        return Err(NodeLocalPlanCompilerError::InvalidInput(
            "contract does not bind the local Node recipient",
        ));
    }
    let first = &contract.plans[0];
    let path = &first.transport.forward;
    let epoch = first.source_key.epoch;
    let local_public_key = first.source_key.public_key;
    let mut peers = BTreeMap::<String, WireGuardPeerPlan>::new();
    for plan in &contract.plans {
        let forward = &plan.transport.forward;
        if plan.disposition != EncryptionDisposition::Required
            || plan.source.node != contract.local_node
            || plan.source_key.node_uid != context.recipient.node_uid
            || plan.source_key.epoch != epoch
            || plan.source_key.public_key != local_public_key
            || forward.source_node_uid != context.recipient.node_uid
            || forward.epoch != epoch
            || forward.interface_name != path.interface_name
            || forward.route_table != path.route_table
            || forward.fwmark != path.fwmark
            || forward.mtu != path.mtu
            || plan.destination.node.uid != forward.destination_node_uid
            || plan.destination_key.node_uid != forward.destination_node_uid
            || plan.destination_key.epoch != epoch
        {
            return Err(NodeLocalPlanCompilerError::InvalidInput(
                "contract plans do not share one exact local epoch transport",
            ));
        }
        let peer = WireGuardPeerPlan {
            node_uid: forward.destination_node_uid.clone(),
            public_key: plan.destination_key.public_key,
            endpoint: forward.peer_endpoint,
            persistent_keepalive_seconds: context.persistent_keepalive_seconds,
            allowed_ips: forward.allowed_ips.clone(),
        };
        if let Some(existing) = peers.insert(peer.node_uid.clone(), peer.clone())
            && existing != peer
        {
            return Err(NodeLocalPlanCompilerError::InvalidInput(
                "one destination Node has conflicting peer authority",
            ));
        }
    }
    let observations = peers
        .values()
        .map(|peer| {
            let (family, overhead) = match peer.endpoint.ip() {
                std::net::IpAddr::V4(_) => (UnderlayAddressFamily::Ipv4, WIREGUARD_IPV4_OVERHEAD),
                std::net::IpAddr::V6(_) => (UnderlayAddressFamily::Ipv6, WIREGUARD_IPV6_OVERHEAD),
            };
            Ok(UnderlayMtuObservation {
                peer_node_uid: peer.node_uid.clone(),
                family,
                underlay_mtu: path.mtu.checked_add(overhead).ok_or(
                    NodeLocalPlanCompilerError::InvalidInput("underlay MTU overflows"),
                )?,
            })
        })
        .collect::<Result<Vec<_>, NodeLocalPlanCompilerError>>()?;
    let mtu_envelope = WireGuardMtuEnvelope::derive(&observations)?;
    if mtu_envelope.interface_mtu != path.mtu {
        return Err(NodeLocalPlanCompilerError::InvalidInput(
            "derived MTU differs from attested path MTU",
        ));
    }
    WireGuardKernelPlan::new(WireGuardKernelPlanInput {
        cluster_id: contract.local_node.cluster_id.clone(),
        local_node_uid: context.recipient.node_uid.clone(),
        epoch,
        revision: context.kernel_transaction_revision,
        interface_name: path.interface_name.clone(),
        local_public_key,
        listen_port: context.listen_port,
        fwmark: path.fwmark,
        route_table: path.route_table,
        mtu_envelope,
        activation: WireGuardEpochActivation::InactiveStaged,
        peers: peers.into_values().collect(),
    })
    .map_err(NodeLocalPlanCompilerError::from)
}

fn with_activation(
    plan: &WireGuardKernelPlan,
    activation: WireGuardEpochActivation,
) -> Result<WireGuardKernelPlan, WireGuardKernelError> {
    WireGuardKernelPlan::new(WireGuardKernelPlanInput {
        cluster_id: plan.cluster_id.clone(),
        local_node_uid: plan.local_node_uid.clone(),
        epoch: plan.epoch,
        revision: plan.revision,
        interface_name: plan.interface_name.clone(),
        local_public_key: plan.local_public_key,
        listen_port: plan.listen_port,
        fwmark: plan.fwmark,
        route_table: plan.route_table,
        mtu_envelope: plan.mtu_envelope.clone(),
        activation,
        peers: plan.peers.clone(),
    })
}

fn contract_epoch(
    contract: &AttestedEncryptionPathContract,
) -> Result<u64, NodeLocalPlanCompilerError> {
    contract
        .plans
        .first()
        .map(|plan| plan.source_key.epoch)
        .ok_or(NodeLocalPlanCompilerError::InvalidInput(
            "contract has no required plans",
        ))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use unf_common::{IdentityId, PolicyId, PolicyReason};

    use super::*;
    use crate::{
        AdmittedNodeLocalPlan, EncryptionBaseline, EncryptionCapability, EncryptionContractFacts,
        EncryptionContractRevisions, EncryptionEndpointFact, EncryptionKeyFact, EncryptionKeyPhase,
        EncryptionModel, EncryptionNode, EncryptionPathClass, EncryptionPathFact,
        EncryptionPolicyFact, IpPrefix, NodeLocalPlanCatalog, NodeLocalPlanCatalogError,
        NodeLocalPlanCatalogOutcome, NodeLocalPlanDistributionError, NodeLocalPlanFleetCut,
        NodeLocalPlanRequest, NodeSealedPlanCapsule, UNF_WIREGUARD_ROUTE_PROTOCOL,
        WireGuardKernelSnapshotInput, WireGuardPeerReadback, WireGuardPublicKey,
        WireGuardRouteReadback, WireGuardRouteScope,
    };

    fn node(name: &str, uid: &str, pod_octet: u8, underlay_octet: u8) -> EncryptionNode {
        EncryptionNode {
            cluster_id: "cluster-a".to_owned(),
            name: name.to_owned(),
            uid: uid.to_owned(),
            pod_cidrs: vec![IpPrefix {
                address: IpAddr::V4(Ipv4Addr::new(10, pod_octet, 0, 0)),
                prefix_len: 24,
            }],
            underlay_addresses: vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, underlay_octet))],
            capabilities: BTreeSet::from([
                EncryptionCapability::KernelWireGuard,
                EncryptionCapability::DualStackUnderlay,
                EncryptionCapability::PolicyRouting,
                EncryptionCapability::TwoEpochRotation,
                EncryptionCapability::EncryptedPathChallenge,
            ]),
        }
    }

    fn contract() -> AttestedEncryptionPathContract {
        let local = node("worker-a", "uid-a", 42, 1);
        let remote = node("worker-b", "uid-b", 43, 2);
        let sources = [IdentityId::new(11), IdentityId::new(12)];
        let destinations = [IdentityId::new(21), IdentityId::new(22)];
        let model = EncryptionModel::normalize(
            "cluster-a".to_owned(),
            EncryptionBaseline::Required,
            Vec::new(),
        )
        .unwrap();
        let endpoints = sources
            .into_iter()
            .map(|identity| EncryptionEndpointFact {
                identity,
                workload_uid: format!("source-{}", identity.get()),
                node: local.clone(),
            })
            .chain(
                destinations
                    .into_iter()
                    .map(|identity| EncryptionEndpointFact {
                        identity,
                        workload_uid: format!("destination-{}", identity.get()),
                        node: remote.clone(),
                    }),
            )
            .collect();
        let policies = sources
            .into_iter()
            .flat_map(|source| {
                destinations
                    .into_iter()
                    .map(move |destination| EncryptionPolicyFact {
                        source,
                        destination,
                        allowed: true,
                        reason: PolicyReason::ExplicitRule,
                        policy_ids: vec![PolicyId::new(9)],
                    })
            })
            .collect();
        let path = |source: &EncryptionNode, destination: &EncryptionNode| EncryptionPathFact {
            source_node_uid: source.uid.clone(),
            destination_node_uid: destination.uid.clone(),
            epoch: 7,
            path_class: EncryptionPathClass::ManagedPod,
            peer_endpoint: SocketAddr::new(destination.underlay_addresses[0], 51_820),
            allowed_ips: destination.pod_cidrs.clone(),
            interface_name: "unfwg000000007".to_owned(),
            route_table: 20_007,
            fwmark: 0x0055_0700,
            mtu: 1_420,
        };
        let facts = EncryptionContractFacts {
            revisions: EncryptionContractRevisions {
                intent: Revision::new(1),
                identity: Revision::new(2),
                policy: Revision::new(3),
                routing: Revision::new(4),
                key: Revision::new(5),
            },
            active_epoch: 7,
            endpoints,
            policies,
            keys: vec![
                EncryptionKeyFact {
                    node_uid: local.uid.clone(),
                    epoch: 7,
                    public_key: WireGuardPublicKey([1; 32]),
                    phase: EncryptionKeyPhase::Active,
                    valid_from_unix_ms: 900,
                    valid_until_unix_ms: 3_000,
                },
                EncryptionKeyFact {
                    node_uid: remote.uid.clone(),
                    epoch: 7,
                    public_key: WireGuardPublicKey([2; 32]),
                    phase: EncryptionKeyPhase::Active,
                    valid_from_unix_ms: 900,
                    valid_until_unix_ms: 3_000,
                },
            ],
            paths: vec![path(&local, &remote), path(&remote, &local)],
        };
        AttestedEncryptionPathContract::issue(&model, &facts, local, Revision::new(8), 950, 2_500)
            .unwrap()
    }

    fn context() -> NodeLocalPlanCompileContext {
        NodeLocalPlanCompileContext {
            membership_revision: Revision::new(6),
            kernel_transaction_revision: Revision::new(9),
            map_transaction_revision: Revision::new(20),
            recipient: EncryptionGenerationRecipient {
                node_name: "worker-a".to_owned(),
                node_uid: "uid-a".to_owned(),
            },
            fast_path: FastPathCompileContext {
                generation: Revision::new(20),
                policy_revision: Revision::new(3),
                service_revision: Revision::new(30),
                egress_revision: Revision::new(40),
                bank: 1,
                now_unix_ms: 1_000,
                now_monotonic_ns: 10_000,
            },
            listen_port: 51_820,
            persistent_keepalive_seconds: 25,
            prior: None,
        }
    }

    fn snapshot(plan: &WireGuardKernelPlan) -> WireGuardKernelSnapshot {
        WireGuardKernelSnapshot::issue(WireGuardKernelSnapshotInput {
            interface_name: plan.interface_name.clone(),
            interface_index: 17,
            owner_alias: plan.owner_alias.clone(),
            is_up: true,
            mtu: plan.mtu_envelope.interface_mtu,
            public_key: plan.local_public_key,
            listen_port: plan.listen_port,
            fwmark: plan.fwmark,
            peers: plan
                .peers
                .iter()
                .map(|peer| WireGuardPeerReadback {
                    public_key: peer.public_key,
                    endpoint: peer.endpoint,
                    persistent_keepalive_seconds: peer.persistent_keepalive_seconds,
                    allowed_ips: peer.allowed_ips.clone(),
                    last_handshake_unix_seconds: 1,
                    received_bytes: 1,
                    transmitted_bytes: 1,
                })
                .collect(),
            routes: plan
                .route_prefixes()
                .into_iter()
                .map(|prefix| WireGuardRouteReadback {
                    prefix,
                    interface_index: 17,
                    table: plan.route_table,
                    protocol: UNF_WIREGUARD_ROUTE_PROTOCOL,
                    scope: WireGuardRouteScope::for_prefix(prefix),
                })
                .collect(),
        })
        .unwrap()
    }

    fn manifold_with_port(
        generation: u64,
        reverse_decisions: bool,
        listen_port: u16,
    ) -> NodeLocalPlanSnapshot {
        let contract = contract();
        let mut decisions = contract
            .plans
            .iter()
            .enumerate()
            .map(|(index, plan)| NodeLocalDecisionPlan {
                source_identity: plan.source.identity,
                destination_identity: plan.destination.identity,
                disposition: EncryptionDisposition::Required,
                contract_epoch: Some(7),
                plan_index: Some(index),
            })
            .collect::<Vec<_>>();
        if reverse_decisions {
            decisions.reverse();
        }
        NodeLocalPlanSnapshot::issue(NodeLocalPlanSnapshotFields {
            membership_revision: Revision::new(6),
            generation: Revision::new(generation),
            recipient: EncryptionGenerationRecipient {
                node_name: "worker-a".to_owned(),
                node_uid: "uid-a".to_owned(),
            },
            mode: NodeLocalPlanMode::Active,
            policy_revision: Revision::new(3),
            service_revision: Revision::new(30),
            egress_revision: Revision::new(40),
            listen_port,
            persistent_keepalive_seconds: 25,
            epochs: vec![NodeLocalEpochPlanRecord {
                contract,
                readiness_digest: [7; 32],
                state: FastPathEpochState::Active,
                drain_until_monotonic_ns: 0,
            }],
            decisions,
        })
        .unwrap()
    }

    fn manifold(generation: u64, reverse_decisions: bool) -> NodeLocalPlanSnapshot {
        manifold_with_port(generation, reverse_decisions, 51_820)
    }

    #[test]
    fn snapshot_first_compiler_coalesces_identity_cartesian_product_to_one_peer() {
        let contract = contract();
        assert_eq!(contract.plans.len(), 4);
        let epoch = NodeLocalEpochPlan {
            contract: &contract,
            readiness_digest: [7; 32],
            state: FastPathEpochState::Active,
            drain_until_monotonic_ns: 0,
        };
        let plans = compile_inactive_kernel_plans(&context(), &[epoch]).unwrap();
        assert_eq!(plans.len(), 1);
        assert_eq!(plans[0].peers.len(), 1);
        let decisions = contract
            .plans
            .iter()
            .enumerate()
            .map(|(index, plan)| FastPathDecisionInput {
                source_identity: plan.source.identity,
                destination_identity: plan.destination.identity,
                disposition: EncryptionDisposition::Required,
                contract_epoch: Some(7),
                plan_index: Some(index),
            })
            .collect::<Vec<_>>();
        let prepared = LinuxPreparedLocalGeneration::compile_exact_readback(
            context(),
            &[epoch],
            &decisions,
            &[snapshot(&plans[0])],
        )
        .unwrap();
        let desired = prepared
            .fact()
            .checkpoint
            .desired_state()
            .expect("checkpoint independently replays");
        assert_eq!(desired.decision_authority.len(), 4);
        assert_eq!(desired.transport_authority.len(), 1);
        assert_eq!(prepared.recovery_plan().plans, plans);
    }

    #[test]
    fn snapshot_first_compiler_refuses_partial_or_cross_node_authority() {
        let contract = contract();
        let epoch = NodeLocalEpochPlan {
            contract: &contract,
            readiness_digest: [7; 32],
            state: FastPathEpochState::Active,
            drain_until_monotonic_ns: 0,
        };
        let decisions = [FastPathDecisionInput {
            source_identity: IdentityId::new(11),
            destination_identity: IdentityId::new(21),
            disposition: EncryptionDisposition::Required,
            contract_epoch: Some(7),
            plan_index: Some(0),
        }];
        assert!(
            LinuxPreparedLocalGeneration::compile_exact_readback(
                context(),
                &[epoch],
                &decisions,
                &[],
            )
            .is_err()
        );
        let mut foreign = context();
        foreign.recipient.node_uid = "uid-foreign".to_owned();
        let plans = compile_inactive_kernel_plans(&context(), &[epoch]).unwrap();
        assert!(
            LinuxPreparedLocalGeneration::compile_exact_readback(
                foreign,
                &[epoch],
                &decisions,
                &[snapshot(&plans[0])],
            )
            .is_err()
        );
    }

    #[test]
    fn causal_input_manifold_is_canonical_complete_and_strict() {
        let plan = manifold(20, false);
        assert_eq!(plan, manifold(20, true));
        plan.verify().unwrap();

        let epoch = plan.epoch_plans().unwrap()[0];
        let plans = compile_inactive_kernel_plans(
            &plan.compile_context(None, 1_000, 10_000).unwrap(),
            &[epoch],
        )
        .unwrap();
        let prepared = plan
            .prepare_exact_readback(None, 1_000, 10_000, &[snapshot(&plans[0])])
            .unwrap();
        assert_eq!(
            prepared
                .fact()
                .checkpoint
                .desired_state()
                .unwrap()
                .decision_authority
                .len(),
            4
        );

        let mut partial = plan.clone();
        partial.decisions.pop();
        assert!(partial.verify().is_err());
        let mut unknown = serde_json::to_value(plan).unwrap();
        unknown
            .as_object_mut()
            .unwrap()
            .insert("serializedAuthority".to_owned(), serde_json::json!([7]));
        assert!(serde_json::from_value::<NodeLocalPlanSnapshot>(unknown).is_err());
    }

    #[test]
    fn node_sealed_plan_delivery_is_nonce_bound_monotonic_and_non_authoritative() {
        let first_snapshot = manifold(20, false);
        let first_request = NodeLocalPlanRequest::issue("worker-a".to_owned(), None, [8; 32])
            .expect("issue fresh predecessor-free request");
        let first_capsule =
            NodeSealedPlanCapsule::issue(41, &first_request, first_snapshot.clone())
                .expect("seal first plan");
        let first = first_capsule
            .admit(&first_request, None)
            .expect("admit first plan");
        first.verify().unwrap();
        assert!(first.cursor().matches(&first_snapshot));

        let next_request =
            NodeLocalPlanRequest::issue("worker-a".to_owned(), Some(&first), [9; 32]).unwrap();
        let next = NodeSealedPlanCapsule::issue(42, &next_request, manifold(21, false)).unwrap();
        let admitted = next.admit(&next_request, Some(&first)).unwrap();
        assert_eq!(admitted.snapshot.generation, Revision::new(21));

        let replay_request =
            NodeLocalPlanRequest::issue("worker-a".to_owned(), Some(&first), [10; 32]).unwrap();
        assert!(matches!(
            next.admit(&replay_request, Some(&first)),
            Err(NodeLocalPlanDistributionError::RequestMismatch)
        ));
        assert!(matches!(
            NodeSealedPlanCapsule::issue(42, &next_request, first_snapshot),
            Err(NodeLocalPlanDistributionError::InvalidTransition)
        ));

        let mut replaced = manifold(21, false);
        replaced.recipient.node_uid = "uid-replaced".to_owned();
        assert!(NodeSealedPlanCapsule::issue(42, &next_request, replaced).is_err());

        let mut serialized = serde_json::to_value(admitted).unwrap();
        serialized.as_object_mut().unwrap().insert(
            "routePermit".to_owned(),
            serde_json::json!("must-never-cross-wire"),
        );
        assert!(serde_json::from_value::<AdmittedNodeLocalPlan>(serialized).is_err());
    }

    #[test]
    fn fleet_synchronous_plan_cut_refuses_omission_and_is_canonical() {
        let plan = manifold(20, false);
        let member = plan.recipient.clone();
        let cut = NodeLocalPlanFleetCut::issue(
            Revision::new(6),
            Revision::new(20),
            vec![member.clone()],
            vec![plan],
        )
        .unwrap();
        cut.verify().unwrap();

        let mut incomplete_members = vec![
            member,
            EncryptionGenerationRecipient {
                node_name: "worker-b".to_owned(),
                node_uid: "uid-b".to_owned(),
            },
        ];
        incomplete_members.reverse();
        assert!(
            NodeLocalPlanFleetCut::issue(
                Revision::new(6),
                Revision::new(20),
                incomplete_members,
                vec![manifold(20, false)],
            )
            .is_err()
        );
    }

    #[test]
    fn fleet_synchronous_catalog_is_atomic_monotonic_and_equivocation_safe() {
        let issue_cut = |plan: NodeLocalPlanSnapshot| {
            NodeLocalPlanFleetCut::issue(
                plan.membership_revision,
                plan.generation,
                vec![plan.recipient.clone()],
                vec![plan],
            )
            .unwrap()
        };
        let first = issue_cut(manifold(20, false));
        let recipient = first.members[0].clone();
        let mut catalog = NodeLocalPlanCatalog::default();
        assert_eq!(
            catalog.publish(first.clone()).unwrap(),
            NodeLocalPlanCatalogOutcome::Published
        );
        assert_eq!(
            catalog.publish(first.clone()).unwrap(),
            NodeLocalPlanCatalogOutcome::Unchanged
        );
        assert_eq!(
            catalog.desired_for(&recipient).unwrap().snapshot_digest,
            first.plans[0].snapshot_digest
        );

        let equivocation = issue_cut(manifold_with_port(20, false, 51_821));
        assert!(matches!(
            catalog.publish(equivocation),
            Err(NodeLocalPlanCatalogError::Equivocation)
        ));
        let successor = issue_cut(manifold(21, false));
        assert_eq!(
            catalog.publish(successor).unwrap(),
            NodeLocalPlanCatalogOutcome::Published
        );
        assert!(matches!(
            catalog.publish(first),
            Err(NodeLocalPlanCatalogError::Regression)
        ));
        assert_eq!(catalog.active().unwrap().generation, Revision::new(21));
    }
}
