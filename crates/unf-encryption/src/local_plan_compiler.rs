//! Snapshot-first Node-local encryption generation compiler.
//!
//! The compiler removes the circular dependency between kernel readback and
//! fast-path authority: it derives one coalesced `WireGuard` plan per epoch,
//! stages and reads that plan, then compiles the exact readback digests into a
//! map checkpoint. Identity cardinality therefore never creates per-policy or
//! per-workload tunnels.

use std::collections::BTreeMap;

use thiserror::Error;
use unf_common::Revision;

use crate::{
    AttestedEncryptionPathContract, EncryptionContractError, EncryptionDisposition,
    EncryptionGenerationRecipient, FastPathCompileContext, FastPathDecisionInput,
    FastPathEpochAdmission, FastPathEpochState, FastPathError, FastPathMapCheckpoint,
    FastPathPublishedGeneration, FastPathTransactionError, KeyAuthorityError,
    LinuxPreparedLocalGeneration, NodeKeyAuthority, NodeLocalOrchestratorError,
    ProofCarryingKernelTransaction, UnderlayAddressFamily, UnderlayMtuObservation,
    WIREGUARD_IPV4_OVERHEAD, WIREGUARD_IPV6_OVERHEAD, WireGuardEpochActivation,
    WireGuardKernelError, WireGuardKernelPlan, WireGuardKernelPlanInput, WireGuardKernelSnapshot,
    WireGuardMtuEnvelope, WireGuardPeerPlan, compile_encryption_fast_path,
};

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

    use unf_common::{IdentityId, PolicyId};

    use super::*;
    use crate::{
        EncryptionBaseline, EncryptionCapability, EncryptionContractFacts,
        EncryptionContractRevisions, EncryptionEndpointFact, EncryptionKeyFact, EncryptionKeyPhase,
        EncryptionModel, EncryptionNode, EncryptionPathClass, EncryptionPathFact,
        EncryptionPolicyFact, IpPrefix, UNF_WIREGUARD_ROUTE_PROTOCOL, WireGuardKernelSnapshotInput,
        WireGuardPeerReadback, WireGuardPublicKey, WireGuardRouteReadback, WireGuardRouteScope,
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
}
