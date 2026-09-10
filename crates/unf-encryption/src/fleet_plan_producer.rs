//! Authoritative, demand-sparse production of a fleet Node-local plan cut.
//!
//! The producer joins independently verified public-key readiness with one
//! causal model/fact snapshot. Nodes without a required cross-Node path receive
//! an explicit dormant plan instead of an unnecessary tunnel or fake workload.

use std::collections::BTreeMap;

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
    pub key_cut: NodeKeyTransparencyCut,
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

    let plans = input
        .nodes
        .iter()
        .cloned()
        .zip(&members)
        .map(|(node, recipient)| {
            produce_node_plan(&input, &facts, node, recipient, active_epoch, &readiness)
        })
        .collect::<Result<Vec<_>, _>>()?;
    NodeLocalPlanFleetCut::issue(input.membership_revision, input.generation, members, plans)
        .map_err(FleetPlanProductionError::InvalidFleetCut)
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
    node: crate::EncryptionNode,
    recipient: &EncryptionGenerationRecipient,
    active_epoch: u64,
    readiness: &ReadinessByNode,
) -> Result<NodeLocalPlanSnapshot, FleetPlanProductionError> {
    let contract = AttestedEncryptionPathContract::issue(
        &input.model,
        facts,
        node,
        input.contract_revision,
        input.valid_from_unix_ms,
        input.valid_until_unix_ms,
    )?;
    let mode = if contract.plans.is_empty() {
        NodeLocalPlanMode::Dormant
    } else {
        NodeLocalPlanMode::Active
    };
    let decisions = contract
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
    let epochs = if mode == NodeLocalPlanMode::Dormant {
        Vec::new()
    } else {
        vec![NodeLocalEpochPlanRecord {
            contract,
            readiness_digest: *readiness
                .get(&recipient.node_uid)
                .ok_or(FleetPlanProductionError::InvalidMembership)?,
            state: FastPathEpochState::Active,
            drain_until_monotonic_ns: 0,
        }]
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

    use unf_common::{IdentityId, PolicyId};

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
        let path = |source: &EncryptionNode, destination: &EncryptionNode| EncryptionPathFact {
            source_node_uid: source.uid.clone(),
            destination_node_uid: destination.uid.clone(),
            epoch: 1,
            path_class: EncryptionPathClass::ManagedPod,
            peer_endpoint: SocketAddr::new(destination.underlay_addresses[0], 51_820),
            allowed_ips: destination.pod_cidrs.clone(),
            interface_name: "unfwg000000001".to_owned(),
            route_table: 20_001,
            fwmark: 0x0055_0100,
            mtu: 1_420,
        };
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
                    policy_ids: vec![PolicyId::new(9)],
                },
                EncryptionPolicyFact {
                    source: IdentityId::new(21),
                    destination: IdentityId::new(11),
                    allowed: true,
                    policy_ids: vec![PolicyId::new(10)],
                },
            ],
            paths: vec![path(&nodes[0], &nodes[1]), path(&nodes[1], &nodes[0])],
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
    fn fleet_plan_production_refuses_any_unattested_member() {
        assert!(matches!(
            produce_fleet_plan_cut(input(false)),
            Err(FleetPlanProductionError::UnreadyOrAmbiguousKey)
        ));
    }
}
