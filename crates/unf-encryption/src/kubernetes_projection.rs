//! Fail-closed projection of Kubernetes placement into encryption facts.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, SocketAddr};

use thiserror::Error;
use unf_common::IdentityId;

use crate::{
    EncryptionCapability, EncryptionEndpointFact, EncryptionIdentityPair, EncryptionNode,
    EncryptionPathClass, EncryptionPathFact, EncryptionPolicyFact, EncryptionPolicyObservation,
    IpPrefix, MAX_ENCRYPTION_ENDPOINTS, MAX_ENCRYPTION_MTU, MAX_ENCRYPTION_PATHS,
    MAX_ENCRYPTION_PREFIXES_PER_NODE, MAX_ENCRYPTION_UNDERLAY_ADDRESSES_PER_NODE,
    MIN_DUAL_STACK_ENCRYPTION_MTU, project_encryption_policy_facts,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KubernetesEncryptionNodeSnapshot {
    pub name: String,
    pub uid: String,
    pub ready: bool,
    pub managed: bool,
    pub pod_cidrs: Vec<IpPrefix>,
    pub underlay_addresses: Vec<IpAddr>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KubernetesEncryptionWorkloadSnapshot {
    pub workload_uid: String,
    pub identity: IdentityId,
    pub node_name: String,
    pub host_network: bool,
    pub addresses: Vec<IpAddr>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KubernetesEncryptionProjectionInput {
    pub cluster_id: String,
    pub active_epoch: u64,
    pub interface_name: String,
    pub listen_port: u16,
    pub route_table: u32,
    pub fwmark: u32,
    pub mtu: u32,
    pub nodes: Vec<KubernetesEncryptionNodeSnapshot>,
    pub workloads: Vec<KubernetesEncryptionWorkloadSnapshot>,
    pub policy_observations: Vec<EncryptionPolicyObservation>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KubernetesEncryptionProjection {
    pub nodes: Vec<EncryptionNode>,
    pub endpoints: Vec<EncryptionEndpointFact>,
    pub policies: Vec<EncryptionPolicyFact>,
    pub paths: Vec<EncryptionPathFact>,
}

/// Projects one exact placement/policy cut without reading mutable state.
///
/// # Errors
///
/// Rejects incomplete Nodes, conflicting workload identity, IPAM drift,
/// foreign policy observations, ambiguous prefixes, or capacity overflow.
pub fn project_kubernetes_encryption(
    mut input: KubernetesEncryptionProjectionInput,
) -> Result<KubernetesEncryptionProjection, KubernetesEncryptionProjectionError> {
    validate_shape(&input)?;
    input
        .nodes
        .sort_by(|left, right| left.name.cmp(&right.name));
    input
        .workloads
        .sort_by(|left, right| left.workload_uid.cmp(&right.workload_uid));
    let capabilities = BTreeSet::from([
        EncryptionCapability::KernelWireGuard,
        EncryptionCapability::DualStackUnderlay,
        EncryptionCapability::PolicyRouting,
        EncryptionCapability::TwoEpochRotation,
        EncryptionCapability::EncryptedPathChallenge,
    ]);
    let nodes = input
        .nodes
        .iter()
        .cloned()
        .map(|mut node| {
            node.pod_cidrs.sort_unstable();
            node.underlay_addresses.sort_unstable();
            EncryptionNode {
                cluster_id: input.cluster_id.clone(),
                name: node.name,
                uid: node.uid,
                pod_cidrs: node.pod_cidrs,
                underlay_addresses: node.underlay_addresses,
                capabilities: capabilities.clone(),
            }
        })
        .collect::<Vec<_>>();
    let nodes_by_name = nodes
        .iter()
        .map(|node| (node.name.as_str(), node))
        .collect::<BTreeMap<_, _>>();
    let mut endpoints = Vec::new();
    for workload in input
        .workloads
        .iter()
        .filter(|workload| !workload.host_network)
        .cloned()
    {
        let node = nodes_by_name
            .get(workload.node_name.as_str())
            .ok_or(KubernetesEncryptionProjectionError::InvalidWorkload)?;
        if workload.identity.get() == 0
            || workload.workload_uid.is_empty()
            || workload.addresses.is_empty()
            || workload.addresses.iter().any(|address| {
                !node
                    .pod_cidrs
                    .iter()
                    .any(|prefix| prefix.contains(*address))
            })
        {
            return Err(KubernetesEncryptionProjectionError::InvalidWorkload);
        }
        endpoints.push(EncryptionEndpointFact {
            identity: workload.identity,
            workload_uid: workload.workload_uid,
            node: (*node).clone(),
        });
    }
    if endpoints.len() > MAX_ENCRYPTION_ENDPOINTS {
        return Err(KubernetesEncryptionProjectionError::Capacity);
    }
    let pairs = demanded_identity_pairs(&endpoints);
    let policies = if pairs.is_empty() {
        if !input.policy_observations.is_empty() {
            return Err(KubernetesEncryptionProjectionError::InvalidPolicy);
        }
        Vec::new()
    } else {
        project_encryption_policy_facts(
            pairs.iter().copied(),
            input.policy_observations.iter().copied(),
        )
        .map_err(|_| KubernetesEncryptionProjectionError::InvalidPolicy)?
    };
    let paths = demanded_paths(&input, &nodes_by_name, &endpoints, &policies)?;
    Ok(KubernetesEncryptionProjection {
        nodes,
        endpoints,
        policies,
        paths,
    })
}

fn validate_shape(
    input: &KubernetesEncryptionProjectionInput,
) -> Result<(), KubernetesEncryptionProjectionError> {
    if input.cluster_id.is_empty()
        || input.active_epoch == 0
        || input.interface_name.is_empty()
        || input.interface_name.len() > 15
        || input.listen_port == 0
        || input.route_table == 0
        || input.fwmark == 0
        || !(MIN_DUAL_STACK_ENCRYPTION_MTU..=MAX_ENCRYPTION_MTU).contains(&input.mtu)
        || input.nodes.is_empty()
    {
        return Err(KubernetesEncryptionProjectionError::InvalidInput);
    }
    let mut names = BTreeSet::new();
    let mut uids = BTreeSet::new();
    let mut prefixes = Vec::new();
    for node in &input.nodes {
        if !node.ready
            || !node.managed
            || node.name.is_empty()
            || node.uid.is_empty()
            || !names.insert(node.name.as_str())
            || !uids.insert(node.uid.as_str())
            || node.pod_cidrs.is_empty()
            || node.pod_cidrs.len() > MAX_ENCRYPTION_PREFIXES_PER_NODE
            || node.underlay_addresses.is_empty()
            || node.underlay_addresses.len() > MAX_ENCRYPTION_UNDERLAY_ADDRESSES_PER_NODE
            || node.pod_cidrs.iter().any(|prefix| !prefix.is_canonical())
        {
            return Err(KubernetesEncryptionProjectionError::InvalidNode);
        }
        prefixes.extend(
            node.pod_cidrs
                .iter()
                .map(|prefix| (*prefix, node.uid.as_str())),
        );
    }
    if prefixes.iter().enumerate().any(|(index, (prefix, uid))| {
        prefixes
            .iter()
            .skip(index + 1)
            .any(|(other, other_uid)| uid != other_uid && prefix.overlaps(*other))
    }) {
        return Err(KubernetesEncryptionProjectionError::AmbiguousPrefix);
    }
    Ok(())
}

fn demanded_identity_pairs(
    endpoints: &[EncryptionEndpointFact],
) -> BTreeSet<EncryptionIdentityPair> {
    endpoints
        .iter()
        .flat_map(|source| {
            endpoints.iter().filter_map(move |destination| {
                (source.node.uid != destination.node.uid).then_some(EncryptionIdentityPair {
                    source: source.identity,
                    destination: destination.identity,
                })
            })
        })
        .collect()
}

fn demanded_paths(
    input: &KubernetesEncryptionProjectionInput,
    nodes: &BTreeMap<&str, &EncryptionNode>,
    endpoints: &[EncryptionEndpointFact],
    policies: &[EncryptionPolicyFact],
) -> Result<Vec<EncryptionPathFact>, KubernetesEncryptionProjectionError> {
    let allowed = policies
        .iter()
        .filter(|policy| policy.allowed)
        .map(|policy| (policy.source, policy.destination))
        .collect::<BTreeSet<_>>();
    let mut pairs = BTreeSet::new();
    for source in endpoints {
        for destination in endpoints {
            if source.node.uid != destination.node.uid
                && allowed.contains(&(source.identity, destination.identity))
            {
                pairs.insert((source.node.name.as_str(), destination.node.name.as_str()));
                pairs.insert((destination.node.name.as_str(), source.node.name.as_str()));
            }
        }
    }
    if pairs.len() > MAX_ENCRYPTION_PATHS * 2 {
        return Err(KubernetesEncryptionProjectionError::Capacity);
    }
    pairs
        .into_iter()
        .map(|(source_name, destination_name)| {
            let source = nodes
                .get(source_name)
                .ok_or(KubernetesEncryptionProjectionError::InvalidNode)?;
            let destination = nodes
                .get(destination_name)
                .ok_or(KubernetesEncryptionProjectionError::InvalidNode)?;
            Ok(EncryptionPathFact {
                source_node_uid: source.uid.clone(),
                destination_node_uid: destination.uid.clone(),
                epoch: input.active_epoch,
                path_class: EncryptionPathClass::ManagedPod,
                peer_endpoint: SocketAddr::new(
                    destination.underlay_addresses[0],
                    input.listen_port,
                ),
                allowed_ips: destination.pod_cidrs.clone(),
                interface_name: input.interface_name.clone(),
                route_table: input.route_table,
                fwmark: input.fwmark,
                mtu: input.mtu,
            })
        })
        .collect()
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum KubernetesEncryptionProjectionError {
    #[error("Kubernetes encryption projection input is invalid")]
    InvalidInput,
    #[error("Kubernetes encryption Node cut is incomplete or invalid")]
    InvalidNode,
    #[error("Kubernetes encryption workload placement is invalid")]
    InvalidWorkload,
    #[error("Kubernetes encryption policy projection is invalid")]
    InvalidPolicy,
    #[error("Kubernetes encryption Node prefixes overlap")]
    AmbiguousPrefix,
    #[error("Kubernetes encryption projection capacity exceeded")]
    Capacity,
}

#[cfg(test)]
mod tests {
    use super::*;
    use unf_common::{PolicyId, PolicyReason};

    fn prefix(value: &str, prefix_len: u8) -> IpPrefix {
        IpPrefix {
            address: value.parse().unwrap(),
            prefix_len,
        }
    }

    fn input() -> KubernetesEncryptionProjectionInput {
        KubernetesEncryptionProjectionInput {
            cluster_id: "cluster-a".to_owned(),
            active_epoch: 7,
            interface_name: "unfwg000000007".to_owned(),
            listen_port: 51_820,
            route_table: 20_007,
            fwmark: 0x0055_0700,
            mtu: 1_420,
            nodes: vec![
                KubernetesEncryptionNodeSnapshot {
                    name: "worker-a".to_owned(),
                    uid: "uid-a".to_owned(),
                    ready: true,
                    managed: true,
                    pod_cidrs: vec![prefix("10.42.1.0", 24), prefix("fd42:1::", 64)],
                    underlay_addresses: vec!["192.0.2.1".parse().unwrap()],
                },
                KubernetesEncryptionNodeSnapshot {
                    name: "worker-b".to_owned(),
                    uid: "uid-b".to_owned(),
                    ready: true,
                    managed: true,
                    pod_cidrs: vec![prefix("10.42.2.0", 24), prefix("fd42:2::", 64)],
                    underlay_addresses: vec!["192.0.2.2".parse().unwrap()],
                },
            ],
            workloads: vec![
                KubernetesEncryptionWorkloadSnapshot {
                    workload_uid: "pod-a".to_owned(),
                    identity: IdentityId::new(11),
                    node_name: "worker-a".to_owned(),
                    host_network: false,
                    addresses: vec!["10.42.1.8".parse().unwrap(), "fd42:1::8".parse().unwrap()],
                },
                KubernetesEncryptionWorkloadSnapshot {
                    workload_uid: "pod-b".to_owned(),
                    identity: IdentityId::new(21),
                    node_name: "worker-b".to_owned(),
                    host_network: false,
                    addresses: vec!["10.42.2.8".parse().unwrap(), "fd42:2::8".parse().unwrap()],
                },
            ],
            policy_observations: vec![EncryptionPolicyObservation {
                pair: EncryptionIdentityPair {
                    source: IdentityId::new(11),
                    destination: IdentityId::new(21),
                },
                allowed: true,
                reason: PolicyReason::ExplicitRule,
                policy_id: Some(PolicyId::new(9)),
            }],
        }
    }

    #[test]
    fn kubernetes_projection_is_demand_sparse_and_policy_truthful() {
        let projected = project_kubernetes_encryption(input()).unwrap();
        assert_eq!(projected.nodes.len(), 2);
        assert_eq!(projected.endpoints.len(), 2);
        assert_eq!(projected.policies.len(), 2);
        assert_eq!(projected.paths.len(), 2);
        assert!(projected.policies.iter().any(|policy| {
            policy.source == IdentityId::new(21)
                && policy.reason == PolicyReason::NoApplicablePolicy
                && policy.policy_ids.is_empty()
        }));
    }

    #[test]
    fn kubernetes_projection_excludes_host_network_but_refuses_ipam_drift() {
        let mut valid = input();
        valid.workloads.push(KubernetesEncryptionWorkloadSnapshot {
            workload_uid: "host".to_owned(),
            identity: IdentityId::new(31),
            node_name: "worker-a".to_owned(),
            host_network: true,
            addresses: vec!["192.0.2.1".parse().unwrap()],
        });
        assert_eq!(
            project_kubernetes_encryption(valid)
                .unwrap()
                .endpoints
                .len(),
            2
        );
        let mut drift = input();
        drift.workloads[0].addresses[0] = "10.99.0.8".parse().unwrap();
        assert_eq!(
            project_kubernetes_encryption(drift),
            Err(KubernetesEncryptionProjectionError::InvalidWorkload)
        );
    }

    #[test]
    fn kubernetes_projection_refuses_unready_members_and_overlapping_blocks() {
        let mut unready = input();
        unready.nodes[1].ready = false;
        assert_eq!(
            project_kubernetes_encryption(unready),
            Err(KubernetesEncryptionProjectionError::InvalidNode)
        );
        let mut overlap = input();
        overlap.nodes[1].pod_cidrs[0] = prefix("10.42.1.128", 25);
        assert_eq!(
            project_kubernetes_encryption(overlap),
            Err(KubernetesEncryptionProjectionError::AmbiguousPrefix)
        );
    }

    #[test]
    fn kubernetes_projection_keeps_a_local_only_cluster_dormant() {
        let mut local = input();
        local.workloads.truncate(1);
        local.policy_observations.clear();
        let projected = project_kubernetes_encryption(local).unwrap();
        assert!(projected.policies.is_empty());
        assert!(projected.paths.is_empty());
    }
}
