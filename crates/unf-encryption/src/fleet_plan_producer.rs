//! Authoritative, demand-sparse production of a fleet Node-local plan cut.
//!
//! The producer joins independently verified public-key readiness with one
//! causal model/fact snapshot. Nodes without a required cross-Node path receive
//! an explicit dormant plan instead of an unnecessary tunnel or fake workload.

use std::collections::{BTreeMap, BTreeSet};

use thiserror::Error;
use unf_common::Revision;

use crate::{
    AttestedEncryptionPathContract, EncryptionContractError, EncryptionContractFacts,
    EncryptionContractRevisions, EncryptionEndpointFact, EncryptionGenerationRecipient,
    EncryptionKeyFact, EncryptionKeyPhase, EncryptionModel, EncryptionPathFact,
    EncryptionPolicyFact, FastPathEpochState, KeyEpochPhase, NodeKeyTransparencyCut,
    NodeLocalDecisionPlan, NodeLocalEpochPlanRecord, NodeLocalPlanCatalogError,
    NodeLocalPlanFleetCut, NodeLocalPlanMode, NodeLocalPlanSnapshot, NodeLocalPlanSnapshotFields,
};

/// One causal controller snapshot. Public key facts are intentionally derived
/// from `key_cut` instead of accepted as a second, tearable input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FleetPlanProductionInput {
    pub membership_revision: Revision,
    pub generation: Revision,
    pub intent_revision: Revision,
    pub identity_revision: Revision,
    pub policy_revision: Revision,
    pub routing_revision: Revision,
    pub service_revision: Revision,
    pub egress_revision: Revision,
    pub contract_revision: Revision,
    pub valid_from_unix_ms: u64,
    pub valid_until_unix_ms: u64,
    pub listen_port: u16,
    pub persistent_keepalive_seconds: u16,
    pub model: EncryptionModel,
    pub nodes: Vec<crate::EncryptionNode>,
    pub endpoints: Vec<EncryptionEndpointFact>,
    pub policies: Vec<EncryptionPolicyFact>,
    pub paths: Vec<EncryptionPathFact>,
    pub draining: Option<FleetDrainingEpochInput>,
    pub key_cut: NodeKeyTransparencyCut,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FleetDrainingEpochInput {
    pub epoch: u64,
    /// Retains the exact contract coordinate that admitted established flows
    /// while this epoch was active. Reissuing a draining contract at the
    /// successor revision would change its content-addressed transport ID and
    /// strand every still-valid Causal Epoch Lease at the bank cut.
    pub contract_revision: Revision,
    pub valid_until_unix_ms: u64,
    pub paths: Vec<EncryptionPathFact>,
}

/// Produces one atomic all-member plan cut from a single causal input.
///
/// # Errors
///
/// Rejects revision drift, incomplete membership, unready/ambiguous keys,
/// invalid contracts, path overlap, or any noncanonical Node plan.
pub fn produce_fleet_plan_cut(
    mut input: FleetPlanProductionInput,
) -> Result<NodeLocalPlanFleetCut, FleetPlanProductionError> {
    input
        .key_cut
        .verify()
        .map_err(FleetPlanProductionError::InvalidKeyCut)?;
    input.nodes.sort_by(|left, right| {
        (left.name.as_str(), left.uid.as_str()).cmp(&(right.name.as_str(), right.uid.as_str()))
    });
    let members = input
        .nodes
        .iter()
        .map(|node| EncryptionGenerationRecipient {
            node_name: node.name.clone(),
            node_uid: node.uid.clone(),
        })
        .collect::<Vec<_>>();
    if input.membership_revision == Revision::INITIAL
        || input.generation == Revision::INITIAL
        || input.service_revision == Revision::INITIAL
        || input.egress_revision == Revision::INITIAL
        || input.key_cut.membership_revision != input.membership_revision
        || input.key_cut.members != members
        || input.nodes.len() != input.key_cut.publications.len()
    {
        return Err(FleetPlanProductionError::InvalidMembership);
    }

    let (active_epoch, key_revision, keys, readiness) = derive_ready_key_facts(&input)?;
    let facts = EncryptionContractFacts {
        revisions: EncryptionContractRevisions {
            intent: input.intent_revision,
            identity: input.identity_revision,
            policy: input.policy_revision,
            routing: input.routing_revision,
            key: key_revision,
        },
        active_epoch,
        endpoints: input.endpoints.clone(),
        policies: input.policies.clone(),
        keys,
        paths: input.paths.clone(),
    };
    let draining = input
        .draining
        .as_ref()
        .map(|draining| {
            if draining.epoch >= active_epoch
                || draining.valid_until_unix_ms <= input.valid_from_unix_ms
                || draining.valid_until_unix_ms > input.valid_until_unix_ms
            {
                return Err(FleetPlanProductionError::UnreadyOrAmbiguousKey);
            }
            let (draining_keys, draining_readiness) = derive_epoch_key_facts(
                &input,
                draining.epoch,
                input.valid_from_unix_ms,
                draining.valid_until_unix_ms,
                KeyEpochPhase::Draining,
                EncryptionKeyPhase::Draining,
            )?;
            Ok((
                EncryptionContractFacts {
                    revisions: facts.revisions,
                    active_epoch: draining.epoch,
                    endpoints: input.endpoints.clone(),
                    policies: input.policies.clone(),
                    keys: draining_keys,
                    paths: draining.paths.clone(),
                },
                draining_readiness,
                draining.valid_until_unix_ms,
            ))
        })
        .transpose()?;

    let plans = input
        .nodes
        .iter()
        .cloned()
        .zip(&members)
        .map(|(node, recipient)| {
            produce_node_plan(
                &input,
                &facts,
                draining.as_ref(),
                node,
                recipient,
                active_epoch,
                &readiness,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    NodeLocalPlanFleetCut::issue(input.membership_revision, input.generation, members, plans)
        .map_err(FleetPlanProductionError::InvalidFleetCut)
}

fn derive_epoch_key_facts(
    input: &FleetPlanProductionInput,
    epoch_number: u64,
    valid_from_unix_ms: u64,
    valid_until_unix_ms: u64,
    required_phase: KeyEpochPhase,
    contract_phase: EncryptionKeyPhase,
) -> Result<(Vec<EncryptionKeyFact>, ReadinessByNode), FleetPlanProductionError> {
    let mut keys = Vec::with_capacity(input.key_cut.publications.len());
    let mut readiness = BTreeMap::new();
    for publication in &input.key_cut.publications {
        let candidates = publication
            .epochs
            .iter()
            .filter(|epoch| {
                epoch.epoch == epoch_number
                    && epoch.phase == required_phase
                    && epoch.readiness_digest.is_some()
                    && epoch.valid_from_unix_ms <= valid_from_unix_ms
                    && epoch.valid_until_unix_ms >= valid_until_unix_ms
            })
            .collect::<Vec<_>>();
        let [epoch] = candidates.as_slice() else {
            return Err(FleetPlanProductionError::UnreadyOrAmbiguousKey);
        };
        keys.push(EncryptionKeyFact {
            node_uid: publication.node_uid.clone(),
            epoch: epoch.epoch,
            public_key: epoch.public_key,
            phase: contract_phase,
            valid_from_unix_ms: epoch.valid_from_unix_ms,
            valid_until_unix_ms: epoch.valid_until_unix_ms,
        });
        readiness.insert(
            publication.node_uid.clone(),
            epoch
                .readiness_digest
                .ok_or(FleetPlanProductionError::UnreadyOrAmbiguousKey)?
                .0,
        );
    }
    Ok((keys, readiness))
}

type ReadinessByNode = BTreeMap<String, [u8; 32]>;

fn derive_ready_key_facts(
    input: &FleetPlanProductionInput,
) -> Result<(u64, Revision, Vec<EncryptionKeyFact>, ReadinessByNode), FleetPlanProductionError> {
    let mut active_epoch = None;
    let mut keys = Vec::with_capacity(input.key_cut.publications.len());
    let mut readiness = BTreeMap::new();
    let mut key_revision = Revision::INITIAL;
    for publication in &input.key_cut.publications {
        let candidates = publication
            .epochs
            .iter()
            .filter(|epoch| {
                matches!(
                    epoch.phase,
                    KeyEpochPhase::MutuallyAttested | KeyEpochPhase::Active
                ) && epoch.readiness_digest.is_some()
                    && epoch.valid_from_unix_ms <= input.valid_from_unix_ms
                    && epoch.valid_until_unix_ms >= input.valid_until_unix_ms
            })
            .collect::<Vec<_>>();
        let [epoch] = candidates.as_slice() else {
            return Err(FleetPlanProductionError::UnreadyOrAmbiguousKey);
        };
        if active_epoch
            .replace(epoch.epoch)
            .is_some_and(|prior| prior != epoch.epoch)
        {
            return Err(FleetPlanProductionError::UnreadyOrAmbiguousKey);
        }
        let phase = match epoch.phase {
            KeyEpochPhase::MutuallyAttested => EncryptionKeyPhase::MutuallyAttested,
            KeyEpochPhase::Active => EncryptionKeyPhase::Active,
            KeyEpochPhase::Prepared | KeyEpochPhase::Draining => {
                return Err(FleetPlanProductionError::UnreadyOrAmbiguousKey);
            }
        };
        keys.push(EncryptionKeyFact {
            node_uid: publication.node_uid.clone(),
            epoch: epoch.epoch,
            public_key: epoch.public_key,
            phase,
            valid_from_unix_ms: epoch.valid_from_unix_ms,
            valid_until_unix_ms: epoch.valid_until_unix_ms,
        });
        readiness.insert(
            publication.node_uid.clone(),
            epoch
                .readiness_digest
                .ok_or(FleetPlanProductionError::UnreadyOrAmbiguousKey)?
                .0,
        );
        key_revision = key_revision.max(publication.key_revision);
    }
    Ok((
        active_epoch.ok_or(FleetPlanProductionError::UnreadyOrAmbiguousKey)?,
        key_revision,
        keys,
        readiness,
    ))
}

fn produce_node_plan(
    input: &FleetPlanProductionInput,
    facts: &EncryptionContractFacts,
    draining: Option<&(EncryptionContractFacts, ReadinessByNode, u64)>,
    node: crate::EncryptionNode,
    recipient: &EncryptionGenerationRecipient,
    active_epoch: u64,
    readiness: &ReadinessByNode,
) -> Result<NodeLocalPlanSnapshot, FleetPlanProductionError> {
    let contract = AttestedEncryptionPathContract::issue(
        &input.model,
        facts,
        node.clone(),
        input.contract_revision,
        input.valid_from_unix_ms,
        input.valid_until_unix_ms,
    )?;
    let mut decisions = contract
        .plans
        .iter()
        .enumerate()
        .map(|(plan_index, plan)| NodeLocalDecisionPlan {
            source_identity: plan.source.identity,
            destination_identity: plan.destination.identity,
            disposition: plan.disposition,
            contract_epoch: Some(active_epoch),
            plan_index: Some(plan_index),
        })
        .collect::<Vec<_>>();
    decisions.extend(native_decisions(input, facts, &node));
    let mode = if decisions.is_empty() {
        NodeLocalPlanMode::Dormant
    } else {
        NodeLocalPlanMode::Active
    };
    let epochs = if contract.plans.is_empty() {
        Vec::new()
    } else {
        let mut epochs = vec![NodeLocalEpochPlanRecord {
            contract,
            readiness_digest: *readiness
                .get(&recipient.node_uid)
                .ok_or(FleetPlanProductionError::InvalidMembership)?,
            state: FastPathEpochState::Active,
            drain_until_monotonic_ns: 0,
        }];
        if let Some((draining_facts, draining_readiness, valid_until_unix_ms)) = draining {
            let draining_contract = AttestedEncryptionPathContract::issue(
                &input.model,
                draining_facts,
                node,
                input
                    .draining
                    .as_ref()
                    .expect("draining facts require draining input")
                    .contract_revision,
                input.valid_from_unix_ms,
                *valid_until_unix_ms,
            )?;
            if !draining_contract.plans.is_empty() {
                epochs.push(NodeLocalEpochPlanRecord {
                    contract: draining_contract,
                    readiness_digest: *draining_readiness
                        .get(&recipient.node_uid)
                        .ok_or(FleetPlanProductionError::InvalidMembership)?,
                    state: FastPathEpochState::Draining,
                    drain_until_monotonic_ns: 0,
                });
            }
        }
        epochs
    };
    NodeLocalPlanSnapshot::issue(NodeLocalPlanSnapshotFields {
        membership_revision: input.membership_revision,
        generation: input.generation,
        recipient: recipient.clone(),
        mode,
        policy_revision: input.policy_revision,
        service_revision: input.service_revision,
        egress_revision: input.egress_revision,
        listen_port: input.listen_port,
        persistent_keepalive_seconds: input.persistent_keepalive_seconds,
        epochs,
        decisions,
    })
    .map_err(FleetPlanProductionError::from)
}

fn native_decisions(
    input: &FleetPlanProductionInput,
    facts: &EncryptionContractFacts,
    node: &crate::EncryptionNode,
) -> Vec<NodeLocalDecisionPlan> {
    let allowed = facts
        .policies
        .iter()
        .filter(|policy| policy.allowed)
        .map(|policy| (policy.source, policy.destination))
        .collect::<BTreeSet<_>>();
    facts
        .endpoints
        .iter()
        .flat_map(|source| {
            facts
                .endpoints
                .iter()
                .filter(|destination| destination.node.uid != source.node.uid)
                .filter_map(|destination| {
                    let pair = (source.identity, destination.identity);
                    ((source.node.uid == node.uid || destination.node.uid == node.uid)
                        && allowed.contains(&pair)
                        && input.model.requirement(pair.0, pair.1).disposition
                            == crate::EncryptionDisposition::Native)
                        .then_some(pair)
                })
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(
            |(source_identity, destination_identity)| NodeLocalDecisionPlan {
                source_identity,
                destination_identity,
                disposition: crate::EncryptionDisposition::Native,
                contract_epoch: None,
                plan_index: None,
            },
        )
        .collect()
}

#[derive(Debug, Error)]
pub enum FleetPlanProductionError {
    #[error("invalid public key transparency cut: {0}")]
    InvalidKeyCut(crate::NodeKeyTransparencyError),
    #[error("fleet plan membership or causal revisions are incomplete")]
    InvalidMembership,
    #[error("fleet plan keys are not one common mutually attested epoch")]
    UnreadyOrAmbiguousKey,
    #[error("invalid attested encryption path contract: {0}")]
    InvalidContract(#[from] EncryptionContractError),
    #[error("invalid Node-local plan: {0}")]
    InvalidPlan(#[from] crate::NodeLocalPlanCompilerError),
    #[error("invalid fleet plan cut: {0}")]
    InvalidFleetCut(NodeLocalPlanCatalogError),
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use unf_common::{IdentityId, PolicyId, PolicyReason};

    use super::*;
    use crate::{
        AuthenticatedNodeIdentity, EncryptionBaseline, EncryptionCapability, EncryptionNode,
        EncryptionPathClass, IpPrefix, NodeKeyAuthority, NodeKeyTransparencyLedger,
        OsWireGuardKeyGenerator, PeerEpochAcknowledgement,
    };

    const NOW: u64 = 1_800_000_000_000;

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

    fn path_at(
        source: &EncryptionNode,
        destination: &EncryptionNode,
        epoch: u64,
    ) -> EncryptionPathFact {
        EncryptionPathFact {
            source_node_uid: source.uid.clone(),
            destination_node_uid: destination.uid.clone(),
            epoch,
            path_class: EncryptionPathClass::ManagedPod,
            peer_endpoint: SocketAddr::new(destination.underlay_addresses[0], 51_820),
            allowed_ips: destination.pod_cidrs.clone(),
            interface_name: format!("unfwg{epoch:010}"),
            route_table: 20_000 + u32::try_from(epoch).unwrap(),
            fwmark: 0x0055_0000 | (u32::try_from(epoch).unwrap() << 8),
            mtu: 1_420,
        }
    }

    fn path(source: &EncryptionNode, destination: &EncryptionNode) -> EncryptionPathFact {
        path_at(source, destination, 1)
    }

    fn ready_key_cut(nodes: &[EncryptionNode], attest_all: bool) -> NodeKeyTransparencyCut {
        let members = nodes
            .iter()
            .map(|node| EncryptionGenerationRecipient {
                node_name: node.name.clone(),
                node_uid: node.uid.clone(),
            })
            .collect::<Vec<_>>();
        let mut ledger = NodeKeyTransparencyLedger::default();
        ledger
            .replace_membership("cluster-a".to_owned(), Revision::new(7), members.clone())
            .unwrap();
        for node in nodes {
            let mut authority =
                NodeKeyAuthority::new("cluster-a".to_owned(), node.name.clone(), node.uid.clone())
                    .unwrap();
            authority
                .prepare_epoch(
                    Revision::new(7),
                    nodes
                        .iter()
                        .filter(|peer| peer.uid != node.uid)
                        .map(|peer| peer.uid.clone())
                        .collect(),
                    NOW,
                    NOW + 100_000,
                    &mut OsWireGuardKeyGenerator,
                )
                .unwrap();
            if attest_all {
                let barrier = authority.epochs()[0].barrier().clone();
                for peer in nodes.iter().filter(|peer| peer.uid != node.uid) {
                    authority
                        .acknowledge_epoch(
                            &peer.uid,
                            PeerEpochAcknowledgement {
                                peer_node_uid: peer.uid.clone(),
                                target_node_uid: node.uid.clone(),
                                epoch: 1,
                                barrier_digest: barrier.barrier_digest,
                                peer_public_epoch: 1,
                                observed_at_unix_ms: NOW + 1,
                            },
                            NOW + 1,
                        )
                        .unwrap();
                }
            }
            ledger
                .observe(
                    &AuthenticatedNodeIdentity {
                        cluster_id: "cluster-a".to_owned(),
                        node_name: node.name.clone(),
                        node_uid: node.uid.clone(),
                    },
                    authority.publication().unwrap(),
                )
                .unwrap();
        }
        ledger.complete_cut().unwrap().unwrap()
    }

    fn rotating_key_cut(nodes: &[EncryptionNode]) -> NodeKeyTransparencyCut {
        let members = nodes
            .iter()
            .map(|node| EncryptionGenerationRecipient {
                node_name: node.name.clone(),
                node_uid: node.uid.clone(),
            })
            .collect::<Vec<_>>();
        let mut ledger = NodeKeyTransparencyLedger::default();
        ledger
            .replace_membership("cluster-a".to_owned(), Revision::new(7), members)
            .unwrap();
        for node in nodes {
            let peers = nodes
                .iter()
                .filter(|peer| peer.uid != node.uid)
                .map(|peer| peer.uid.clone())
                .collect::<BTreeSet<_>>();
            let mut authority =
                NodeKeyAuthority::new("cluster-a".to_owned(), node.name.clone(), node.uid.clone())
                    .unwrap();
            authority
                .prepare_epoch(
                    Revision::new(7),
                    peers.clone(),
                    NOW,
                    NOW + 100_000,
                    &mut OsWireGuardKeyGenerator,
                )
                .unwrap();
            for peer in nodes.iter().filter(|peer| peer.uid != node.uid) {
                let barrier = authority.epochs()[0].barrier().clone();
                authority
                    .acknowledge_epoch(
                        &peer.uid,
                        PeerEpochAcknowledgement {
                            peer_node_uid: peer.uid.clone(),
                            target_node_uid: node.uid.clone(),
                            epoch: 1,
                            barrier_digest: barrier.barrier_digest,
                            peer_public_epoch: 1,
                            observed_at_unix_ms: NOW + 1,
                        },
                        NOW + 1,
                    )
                    .unwrap();
            }
            authority
                .activate_epoch(1, Revision::new(7), NOW + 2, 20_000)
                .unwrap();
            authority
                .prepare_epoch(
                    Revision::new(7),
                    peers,
                    NOW + 3,
                    NOW + 100_000,
                    &mut OsWireGuardKeyGenerator,
                )
                .unwrap();
            for peer in nodes.iter().filter(|peer| peer.uid != node.uid) {
                let barrier = authority.epochs()[1].barrier().clone();
                authority
                    .acknowledge_epoch(
                        &peer.uid,
                        PeerEpochAcknowledgement {
                            peer_node_uid: peer.uid.clone(),
                            target_node_uid: node.uid.clone(),
                            epoch: 2,
                            barrier_digest: barrier.barrier_digest,
                            peer_public_epoch: 2,
                            observed_at_unix_ms: NOW + 4,
                        },
                        NOW + 4,
                    )
                    .unwrap();
            }
            authority
                .activate_epoch(2, Revision::new(7), NOW + 5, 20_000)
                .unwrap();
            ledger
                .observe(
                    &AuthenticatedNodeIdentity {
                        cluster_id: "cluster-a".to_owned(),
                        node_name: node.name.clone(),
                        node_uid: node.uid.clone(),
                    },
                    authority.publication().unwrap(),
                )
                .unwrap();
        }
        ledger.complete_cut().unwrap().unwrap()
    }

    fn input(attest_all: bool) -> FleetPlanProductionInput {
        let nodes = vec![
            node("worker-a", "uid-a", 42, 1),
            node("worker-b", "uid-b", 43, 2),
            node("worker-c", "uid-c", 44, 3),
        ];
        let endpoints = vec![
            EncryptionEndpointFact {
                identity: IdentityId::new(11),
                workload_uid: "pod-a".to_owned(),
                node: nodes[0].clone(),
            },
            EncryptionEndpointFact {
                identity: IdentityId::new(21),
                workload_uid: "pod-b".to_owned(),
                node: nodes[1].clone(),
            },
        ];
        let key_cut = ready_key_cut(&nodes, attest_all);
        FleetPlanProductionInput {
            membership_revision: Revision::new(7),
            generation: Revision::new(8),
            intent_revision: Revision::new(1),
            identity_revision: Revision::new(2),
            policy_revision: Revision::new(3),
            routing_revision: Revision::new(4),
            service_revision: Revision::new(5),
            egress_revision: Revision::new(6),
            contract_revision: Revision::new(8),
            valid_from_unix_ms: NOW + 2,
            valid_until_unix_ms: NOW + 90_000,
            listen_port: 51_820,
            persistent_keepalive_seconds: 25,
            model: EncryptionModel::normalize(
                "cluster-a".to_owned(),
                EncryptionBaseline::Required,
                Vec::new(),
            )
            .unwrap(),
            nodes: nodes.clone(),
            endpoints,
            policies: vec![
                EncryptionPolicyFact {
                    source: IdentityId::new(11),
                    destination: IdentityId::new(21),
                    allowed: true,
                    reason: PolicyReason::ExplicitRule,
                    policy_ids: vec![PolicyId::new(9)],
                },
                EncryptionPolicyFact {
                    source: IdentityId::new(21),
                    destination: IdentityId::new(11),
                    allowed: true,
                    reason: PolicyReason::ExplicitRule,
                    policy_ids: vec![PolicyId::new(10)],
                },
            ],
            paths: vec![path(&nodes[0], &nodes[1]), path(&nodes[1], &nodes[0])],
            draining: None,
            key_cut,
        }
    }

    #[test]
    fn demand_sparse_plan_cut_is_atomic_and_keeps_idle_nodes_dormant() {
        let cut = produce_fleet_plan_cut(input(true)).unwrap();
        cut.verify().unwrap();
        assert_eq!(cut.plans.len(), 3);
        assert_eq!(cut.plans[0].mode, NodeLocalPlanMode::Active);
        assert_eq!(cut.plans[1].mode, NodeLocalPlanMode::Active);
        assert_eq!(cut.plans[2].mode, NodeLocalPlanMode::Dormant);
        assert_eq!(cut.plans[0].epochs.len(), 1);
        assert_eq!(cut.plans[1].epochs.len(), 1);
        assert!(cut.plans[2].decisions.is_empty());
    }

    #[test]
    fn required_five_node_cluster_scale_remains_bounded() {
        const NODES: usize = 5;
        const ENDPOINTS_PER_NODE: usize = 24;
        let nodes = (0..NODES)
            .map(|index| {
                node(
                    &format!("worker-{index}"),
                    &format!("uid-{index}"),
                    42 + u8::try_from(index).unwrap(),
                    1 + u8::try_from(index).unwrap(),
                )
            })
            .collect::<Vec<_>>();
        let endpoints = nodes
            .iter()
            .enumerate()
            .flat_map(|(node_index, node)| {
                (0..ENDPOINTS_PER_NODE).map(move |endpoint_index| {
                    let ordinal = node_index * ENDPOINTS_PER_NODE + endpoint_index + 1;
                    EncryptionEndpointFact {
                        identity: IdentityId::new(u32::try_from(ordinal).unwrap()),
                        workload_uid: format!("pod-{ordinal}"),
                        node: node.clone(),
                    }
                })
            })
            .collect::<Vec<_>>();
        let policies = endpoints
            .iter()
            .flat_map(|source| {
                endpoints
                    .iter()
                    .filter(|destination| destination.node.uid != source.node.uid)
                    .map(move |destination| EncryptionPolicyFact {
                        source: source.identity,
                        destination: destination.identity,
                        allowed: true,
                        reason: PolicyReason::NoApplicablePolicy,
                        policy_ids: Vec::new(),
                    })
            })
            .collect::<Vec<_>>();
        let paths = nodes
            .iter()
            .flat_map(|source| {
                nodes
                    .iter()
                    .filter(|destination| destination.uid != source.uid)
                    .map(move |destination| path(source, destination))
            })
            .collect::<Vec<_>>();
        let mut scale = input(true);
        scale.nodes = nodes.clone();
        scale.endpoints = endpoints;
        scale.policies = policies;
        scale.paths = paths;
        scale.key_cut = ready_key_cut(&nodes, true);

        let cut = produce_fleet_plan_cut(scale).unwrap();
        cut.verify().unwrap();
        assert_eq!(cut.plans.len(), NODES);
        assert_eq!(
            cut.plans
                .iter()
                .map(|plan| plan.decisions.len())
                .sum::<usize>(),
            NODES * ENDPOINTS_PER_NODE * (NODES - 1) * ENDPOINTS_PER_NODE
        );
    }

    #[test]
    fn selective_cut_proves_native_authority_without_a_fake_kernel_epoch() {
        let mut input = input(true);
        input.model = EncryptionModel::normalize(
            "cluster-a".to_owned(),
            EncryptionBaseline::Native,
            vec![crate::EncryptionIntent {
                name: "encrypt-client-to-server".to_owned(),
                uid: "uid-selective-forward".to_owned(),
                priority: 100,
                sources: crate::ManagedIdentitySelector::Identities(BTreeSet::from([
                    IdentityId::new(11),
                ])),
                destinations: crate::ManagedIdentitySelector::Identities(BTreeSet::from([
                    IdentityId::new(21),
                ])),
            }],
        )
        .unwrap();
        let cut = produce_fleet_plan_cut(input).unwrap();
        let source = cut
            .plans
            .iter()
            .find(|plan| plan.recipient.node_uid == "uid-a")
            .unwrap();
        assert_eq!(source.epochs.len(), 1);
        assert_eq!(
            source.decisions[0].disposition,
            crate::EncryptionDisposition::Required
        );

        let reverse = cut
            .plans
            .iter()
            .find(|plan| plan.recipient.node_uid == "uid-b")
            .unwrap();
        assert_eq!(reverse.mode, NodeLocalPlanMode::Active);
        assert!(reverse.epochs.is_empty());
        assert_eq!(reverse.decisions.len(), 1);
        assert_eq!(
            reverse.decisions[0].disposition,
            crate::EncryptionDisposition::Native
        );
        reverse.verify().unwrap();
        let prepared = reverse
            .prepare_exact_readback(None, NOW + 3, 1, &[])
            .unwrap();
        let desired = prepared.fact().checkpoint.desired_state().unwrap();
        assert_eq!(desired.config.epoch_count, 0);
        assert_eq!(desired.config.decision_count, 1);
        assert_eq!(desired.config.transport_count, 0);
        assert!(unf_ebpf_common::encryption_config_is_active(
            &desired.config
        ));
    }

    #[test]
    fn native_delivery_authority_reaches_both_ends_of_the_exact_path() {
        let mut input = input(true);
        input.model = EncryptionModel::normalize(
            "cluster-a".to_owned(),
            EncryptionBaseline::Native,
            Vec::new(),
        )
        .unwrap();
        let cut = produce_fleet_plan_cut(input).unwrap();
        for plan in cut
            .plans
            .iter()
            .filter(|plan| matches!(plan.recipient.node_uid.as_str(), "uid-a" | "uid-b"))
        {
            assert_eq!(plan.mode, NodeLocalPlanMode::Active);
            assert!(plan.epochs.is_empty());
            assert_eq!(plan.decisions.len(), 2);
            assert!(plan.decisions.iter().all(|decision| {
                decision.disposition == crate::EncryptionDisposition::Native
                    && decision.contract_epoch.is_none()
                    && decision.plan_index.is_none()
            }));
            plan.verify().unwrap();
        }
        assert_eq!(cut.plans[2].mode, NodeLocalPlanMode::Dormant);
    }

    #[test]
    fn fleet_plan_production_refuses_any_unattested_member() {
        assert!(matches!(
            produce_fleet_plan_cut(input(false)),
            Err(FleetPlanProductionError::UnreadyOrAmbiguousKey)
        ));
    }

    #[test]
    fn fleet_plan_preserves_all_replicas_for_address_exact_late_binding() {
        let mut input = input(true);
        let source = input.nodes[0].clone();
        let replica = input.nodes[2].clone();
        input.endpoints.push(EncryptionEndpointFact {
            identity: IdentityId::new(21),
            workload_uid: "pod-c-replica".to_owned(),
            node: replica.clone(),
        });
        input.paths.push(path(&source, &replica));
        input.paths.push(path(&replica, &source));
        input.paths.push(path(&input.nodes[1].clone(), &replica));
        input.paths.push(path(&replica, &input.nodes[1].clone()));
        input.policies.push(EncryptionPolicyFact {
            source: IdentityId::new(21),
            destination: IdentityId::new(21),
            allowed: true,
            reason: PolicyReason::ExplicitRule,
            policy_ids: vec![PolicyId::new(11)],
        });
        let cut = produce_fleet_plan_cut(input).unwrap();
        let source_plan = cut
            .plans
            .iter()
            .find(|plan| plan.recipient.node_uid == "uid-a")
            .unwrap();
        let replicas = source_plan
            .decisions
            .iter()
            .filter(|decision| {
                decision.source_identity == IdentityId::new(11)
                    && decision.destination_identity == IdentityId::new(21)
            })
            .count();
        assert_eq!(replicas, 2);
        source_plan.verify().unwrap();
    }

    #[test]
    fn two_epoch_cut_sends_new_flows_only_to_active_and_keeps_drain_portable() {
        let mut input = input(true);
        input.key_cut = rotating_key_cut(&input.nodes);
        input.valid_from_unix_ms = NOW + 6;
        input.paths = vec![
            path_at(&input.nodes[0], &input.nodes[1], 2),
            path_at(&input.nodes[1], &input.nodes[0], 2),
        ];
        input.draining = Some(FleetDrainingEpochInput {
            epoch: 1,
            contract_revision: Revision::new(7),
            valid_until_unix_ms: NOW + 25_000,
            paths: vec![
                path_at(&input.nodes[0], &input.nodes[1], 1),
                path_at(&input.nodes[1], &input.nodes[0], 1),
            ],
        });
        let cut = produce_fleet_plan_cut(input).unwrap();
        for plan in cut
            .plans
            .iter()
            .filter(|plan| plan.mode == NodeLocalPlanMode::Active)
        {
            assert_eq!(plan.epochs.len(), 2);
            let active = plan
                .epochs
                .iter()
                .find(|epoch| epoch.state == FastPathEpochState::Active)
                .unwrap();
            let draining = plan
                .epochs
                .iter()
                .find(|epoch| epoch.state == FastPathEpochState::Draining)
                .unwrap();
            assert!(
                active
                    .contract
                    .plans
                    .iter()
                    .all(|contract| contract.source_key.epoch == 2)
            );
            assert!(
                draining
                    .contract
                    .plans
                    .iter()
                    .all(|contract| contract.source_key.epoch == 1)
            );
            assert_eq!(draining.contract.contract_revision, Revision::new(7));
            assert_eq!(active.contract.contract_revision, Revision::new(8));
            assert_eq!(draining.drain_until_monotonic_ns, 0);
            assert!(
                plan.decisions
                    .iter()
                    .all(|decision| decision.contract_epoch == Some(2))
            );
            plan.verify().unwrap();
        }
    }
}
