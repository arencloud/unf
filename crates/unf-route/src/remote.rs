use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use serde::{Deserialize, Serialize};
use unf_ipam::{Ipv4NodeBlock, Ipv6NodeBlock, NodeBlockProvider};

use super::{
    MAIN_ROUTE_TABLE, NetworkNamespace, RouteError, RouteScope, RouteSpec, UNF_ROUTE_PROTOCOL,
};

/// Prevents an untrusted desired-state snapshot from causing unbounded memory
/// or kernel reconciliation work. Validation remains O(n log n).
pub const MAX_REMOTE_NODES: usize = 65_536;

/// Provider-neutral remote Node intent. Routing backends may lower the same
/// identity and block provenance into native, overlay, BGP, or hybrid state.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RemoteNodeIntent {
    pub node_name: String,
    pub node_uid: String,
    pub assignment_revision: u64,
    pub blocks: NodeBlockProvider,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeIpv4NextHop {
    pub gateway: Ipv4Addr,
    pub output_interface: u32,
    pub onlink: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeIpv6NextHop {
    pub gateway: Ipv6Addr,
    pub output_interface: u32,
    pub onlink: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeRemoteNode {
    pub intent: RemoteNodeIntent,
    pub ipv4_next_hop: NativeIpv4NextHop,
    pub ipv6_next_hop: NativeIpv6NextHop,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeRemoteRoutingProvider {
    node_name: String,
    node_uid: String,
    blocks: NodeBlockProvider,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeRemoteRoutePlan {
    pub(super) local_node_name: String,
    pub(super) local_node_uid: String,
    pub(super) remote_nodes: Vec<RemoteNodeIntent>,
    pub(super) routes: Vec<RouteSpec>,
}

impl NativeRemoteRoutingProvider {
    /// Creates a native remote-routing provider for one authoritative local
    /// Node assignment.
    ///
    /// # Errors
    ///
    /// Rejects malformed local Node provenance before any remote state can be
    /// planned.
    pub fn new(
        local_node_name: impl Into<String>,
        local_node_uid: impl Into<String>,
        local_blocks: NodeBlockProvider,
    ) -> Result<Self, RouteError> {
        let local_node_name = local_node_name.into();
        let local_node_uid = local_node_uid.into();
        validate_node_identity(&local_node_name, &local_node_uid)?;
        Ok(Self {
            node_name: local_node_name,
            node_uid: local_node_uid,
            blocks: local_blocks,
        })
    }

    /// Lowers provider-neutral remote Node intent into exact native host routes.
    ///
    /// # Errors
    ///
    /// Rejects duplicate identity, overlapping Pod blocks, Pod-space next hops,
    /// invalid interface indexes, invalid revisions, or an oversized snapshot.
    pub fn plan(
        &self,
        mut remotes: Vec<NativeRemoteNode>,
    ) -> Result<NativeRemoteRoutePlan, RouteError> {
        if remotes.len() > MAX_REMOTE_NODES {
            return Err(RouteError::TooManyRemoteNodes {
                actual: remotes.len(),
                limit: MAX_REMOTE_NODES,
            });
        }
        remotes.sort_by(|left, right| {
            left.intent
                .node_name
                .cmp(&right.intent.node_name)
                .then_with(|| left.intent.node_uid.cmp(&right.intent.node_uid))
        });
        validate_remote_identities(self, &remotes)?;
        let (ipv4_blocks, ipv6_blocks) = validated_blocks(self, &remotes)?;
        validate_next_hops(&remotes, &ipv4_blocks, &ipv6_blocks)?;

        let mut routes = BTreeSet::new();
        for remote in &remotes {
            routes.insert(remote_route(
                IpAddr::V4(remote.intent.blocks.ipv4_block.network()),
                remote.intent.blocks.ipv4_block.prefix_len(),
                IpAddr::V4(remote.ipv4_next_hop.gateway),
                remote.ipv4_next_hop.output_interface,
                remote.ipv4_next_hop.onlink,
            ));
            routes.insert(remote_route(
                IpAddr::V6(remote.intent.blocks.ipv6_block.network()),
                remote.intent.blocks.ipv6_block.prefix_len(),
                IpAddr::V6(remote.ipv6_next_hop.gateway),
                remote.ipv6_next_hop.output_interface,
                remote.ipv6_next_hop.onlink,
            ));
        }
        Ok(NativeRemoteRoutePlan {
            local_node_name: self.node_name.clone(),
            local_node_uid: self.node_uid.clone(),
            remote_nodes: remotes.into_iter().map(|remote| remote.intent).collect(),
            routes: routes.into_iter().collect(),
        })
    }
}

impl NativeRemoteRoutePlan {
    #[must_use]
    pub fn local_node_name(&self) -> &str {
        &self.local_node_name
    }

    #[must_use]
    pub fn local_node_uid(&self) -> &str {
        &self.local_node_uid
    }

    #[must_use]
    pub fn remote_nodes(&self) -> &[RemoteNodeIntent] {
        &self.remote_nodes
    }

    #[must_use]
    pub fn routes(&self) -> &[RouteSpec] {
        &self.routes
    }
}

fn validate_remote_identities(
    provider: &NativeRemoteRoutingProvider,
    remotes: &[NativeRemoteNode],
) -> Result<(), RouteError> {
    let mut names = BTreeSet::new();
    let mut uids = BTreeSet::new();
    for remote in remotes {
        let intent = &remote.intent;
        validate_node_identity(&intent.node_name, &intent.node_uid)?;
        if intent.assignment_revision == 0 {
            return Err(invalid_remote(
                intent,
                "assignment revision must be nonzero",
            ));
        }
        if intent.node_name == provider.node_name || intent.node_uid == provider.node_uid {
            return Err(invalid_remote(
                intent,
                "remote identity aliases the local Node",
            ));
        }
        if !names.insert(intent.node_name.as_str()) {
            return Err(invalid_remote(intent, "Node name is duplicated"));
        }
        if !uids.insert(intent.node_uid.as_str()) {
            return Err(invalid_remote(intent, "Node UID is duplicated"));
        }
        validate_next_hop_shape(
            intent,
            IpAddr::V4(remote.ipv4_next_hop.gateway),
            remote.ipv4_next_hop.output_interface,
        )?;
        validate_next_hop_shape(
            intent,
            IpAddr::V6(remote.ipv6_next_hop.gateway),
            remote.ipv6_next_hop.output_interface,
        )?;
    }
    Ok(())
}

type Ipv4Blocks = Vec<(String, Ipv4NodeBlock)>;
type Ipv6Blocks = Vec<(String, Ipv6NodeBlock)>;

fn validated_blocks(
    provider: &NativeRemoteRoutingProvider,
    remotes: &[NativeRemoteNode],
) -> Result<(Ipv4Blocks, Ipv6Blocks), RouteError> {
    let mut ipv4 = vec![(provider.node_name.clone(), provider.blocks.ipv4_block)];
    let mut ipv6 = vec![(provider.node_name.clone(), provider.blocks.ipv6_block)];
    for remote in remotes {
        ipv4.push((
            remote.intent.node_name.clone(),
            remote.intent.blocks.ipv4_block,
        ));
        ipv6.push((
            remote.intent.node_name.clone(),
            remote.intent.blocks.ipv6_block,
        ));
    }
    ipv4.sort_by_key(|(_, block)| (u32::from(block.network()), block.prefix_len()));
    ipv6.sort_by_key(|(_, block)| (u128::from(block.network()), block.prefix_len()));
    validate_ipv4_overlaps(&ipv4)?;
    validate_ipv6_overlaps(&ipv6)?;
    Ok((ipv4, ipv6))
}

fn validate_ipv4_overlaps(blocks: &Ipv4Blocks) -> Result<(), RouteError> {
    for pair in blocks.windows(2) {
        if pair[0].1.overlaps(pair[1].1) {
            return Err(RouteError::RemoteBlockOverlap {
                family: "IPv4",
                left: pair[0].0.clone(),
                right: pair[1].0.clone(),
            });
        }
    }
    Ok(())
}

fn validate_ipv6_overlaps(blocks: &Ipv6Blocks) -> Result<(), RouteError> {
    for pair in blocks.windows(2) {
        if pair[0].1.overlaps(pair[1].1) {
            return Err(RouteError::RemoteBlockOverlap {
                family: "IPv6",
                left: pair[0].0.clone(),
                right: pair[1].0.clone(),
            });
        }
    }
    Ok(())
}

fn validate_next_hops(
    remotes: &[NativeRemoteNode],
    ipv4_blocks: &Ipv4Blocks,
    ipv6_blocks: &Ipv6Blocks,
) -> Result<(), RouteError> {
    for remote in remotes {
        if let Some(owner) = ipv4_block_owner(ipv4_blocks, remote.ipv4_next_hop.gateway) {
            return Err(invalid_remote(
                &remote.intent,
                format!("IPv4 next hop belongs to Pod block owned by {owner:?}"),
            ));
        }
        if let Some(owner) = ipv6_block_owner(ipv6_blocks, remote.ipv6_next_hop.gateway) {
            return Err(invalid_remote(
                &remote.intent,
                format!("IPv6 next hop belongs to Pod block owned by {owner:?}"),
            ));
        }
    }
    Ok(())
}

fn ipv4_block_owner(blocks: &Ipv4Blocks, address: Ipv4Addr) -> Option<&str> {
    let index = blocks.partition_point(|(_, block)| block.network() <= address);
    index
        .checked_sub(1)
        .and_then(|index| blocks.get(index))
        .filter(|(_, block)| block.contains(address))
        .map(|(owner, _)| owner.as_str())
}

fn ipv6_block_owner(blocks: &Ipv6Blocks, address: Ipv6Addr) -> Option<&str> {
    let index = blocks.partition_point(|(_, block)| block.network() <= address);
    index
        .checked_sub(1)
        .and_then(|index| blocks.get(index))
        .filter(|(_, block)| block.contains(address))
        .map(|(owner, _)| owner.as_str())
}

fn validate_node_identity(node_name: &str, node_uid: &str) -> Result<(), RouteError> {
    let valid_name = !node_name.is_empty()
        && node_name.len() <= 253
        && node_name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
                && label
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .as_bytes()
                    .last()
                    .is_some_and(u8::is_ascii_alphanumeric)
        });
    if !valid_name {
        return Err(RouteError::InvalidRemoteNode {
            node: node_name.to_owned(),
            reason: "Node name is not a valid DNS subdomain".to_owned(),
        });
    }
    if node_uid.is_empty()
        || node_uid.len() > 128
        || node_uid
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        return Err(RouteError::InvalidRemoteNode {
            node: node_name.to_owned(),
            reason: "Node UID is empty, oversized, or contains whitespace/control bytes".to_owned(),
        });
    }
    Ok(())
}

fn validate_next_hop_shape(
    intent: &RemoteNodeIntent,
    gateway: IpAddr,
    output_interface: u32,
) -> Result<(), RouteError> {
    if output_interface == 0 {
        return Err(invalid_remote(
            intent,
            format!("{gateway} next hop has a zero output interface"),
        ));
    }
    let invalid = match gateway {
        IpAddr::V4(address) => {
            address.is_unspecified()
                || address.is_loopback()
                || address.is_multicast()
                || address == Ipv4Addr::BROADCAST
        }
        IpAddr::V6(address) => {
            address.is_unspecified() || address.is_loopback() || address.is_multicast()
        }
    };
    if invalid {
        return Err(invalid_remote(
            intent,
            format!("{gateway} is not a usable unicast next hop"),
        ));
    }
    Ok(())
}

fn invalid_remote(intent: &RemoteNodeIntent, reason: impl Into<String>) -> RouteError {
    RouteError::InvalidRemoteNode {
        node: intent.node_name.clone(),
        reason: reason.into(),
    }
}

fn remote_route(
    destination: IpAddr,
    prefix_len: u8,
    gateway: IpAddr,
    output_interface: u32,
    onlink: bool,
) -> RouteSpec {
    RouteSpec {
        namespace: NetworkNamespace::Host,
        destination,
        prefix_len,
        gateway: Some(gateway),
        output_interface,
        onlink,
        protocol: UNF_ROUTE_PROTOCOL,
        table: MAIN_ROUTE_TABLE,
        scope: RouteScope::Universe,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn blocks(ipv4: &str, ipv6: &str) -> NodeBlockProvider {
        NodeBlockProvider::new(ipv4.parse().unwrap(), ipv6.parse().unwrap())
    }

    fn provider() -> NativeRemoteRoutingProvider {
        NativeRemoteRoutingProvider::new(
            "worker-a",
            "worker-a-uid",
            blocks("10.42.0.0/24", "fd00:42::/64"),
        )
        .unwrap()
    }

    fn remote(
        name: &str,
        uid: &str,
        ipv4: &str,
        ipv6: &str,
        ipv4_gateway: &str,
        ipv6_gateway: &str,
    ) -> NativeRemoteNode {
        NativeRemoteNode {
            intent: RemoteNodeIntent {
                node_name: name.to_owned(),
                node_uid: uid.to_owned(),
                assignment_revision: 7,
                blocks: blocks(ipv4, ipv6),
            },
            ipv4_next_hop: NativeIpv4NextHop {
                gateway: ipv4_gateway.parse().unwrap(),
                output_interface: 3,
                onlink: false,
            },
            ipv6_next_hop: NativeIpv6NextHop {
                gateway: ipv6_gateway.parse().unwrap(),
                output_interface: 4,
                onlink: true,
            },
        }
    }

    #[test]
    fn native_remote_plan_is_dual_stack_deterministic_and_provider_neutral() {
        let worker_b = remote(
            "worker-b",
            "worker-b-uid",
            "10.43.0.0/24",
            "fd00:43::/64",
            "192.0.2.2",
            "fdff::2",
        );
        let worker_c = remote(
            "worker-c",
            "worker-c-uid",
            "10.44.0.0/24",
            "fd00:44::/64",
            "192.0.2.3",
            "fdff::3",
        );
        let forward = provider()
            .plan(vec![worker_b.clone(), worker_c.clone()])
            .unwrap();
        let reversed = provider().plan(vec![worker_c, worker_b]).unwrap();
        assert_eq!(forward, reversed);
        assert_eq!(forward.local_node_name(), "worker-a");
        assert_eq!(forward.local_node_uid(), "worker-a-uid");
        assert_eq!(forward.remote_nodes().len(), 2);
        assert_eq!(forward.routes().len(), 4);
        assert!(forward.routes().iter().all(|route| {
            route.namespace == NetworkNamespace::Host
                && route.gateway.is_some()
                && route.protocol == UNF_ROUTE_PROTOCOL
                && route.table == MAIN_ROUTE_TABLE
                && route.scope == RouteScope::Universe
        }));
        assert!(forward.routes().iter().any(|route| {
            route.destination == "10.43.0.0".parse::<IpAddr>().unwrap()
                && route.prefix_len == 24
                && route.gateway == Some("192.0.2.2".parse().unwrap())
                && route.output_interface == 3
                && !route.onlink
        }));
        assert!(forward.routes().iter().any(|route| {
            route.destination == "fd00:43::".parse::<IpAddr>().unwrap()
                && route.prefix_len == 64
                && route.gateway == Some("fdff::2".parse().unwrap())
                && route.output_interface == 4
                && route.onlink
        }));
    }

    #[test]
    fn remote_intent_wire_shape_is_strict_and_backend_independent() {
        let intent = remote(
            "worker-b",
            "worker-b-uid",
            "10.43.0.0/24",
            "fd00:43::/64",
            "192.0.2.2",
            "fdff::2",
        )
        .intent;
        let mut encoded = serde_json::to_value(&intent).unwrap();
        assert_eq!(encoded["assignmentRevision"], 7);
        assert_eq!(encoded["blocks"]["ipv6Block"], "fd00:43::/64");
        assert_eq!(
            serde_json::from_value::<RemoteNodeIntent>(encoded.clone()).unwrap(),
            intent
        );
        encoded["backend"] = serde_json::json!("native");
        assert!(serde_json::from_value::<RemoteNodeIntent>(encoded).is_err());
    }

    #[test]
    fn remote_plan_rejects_identity_revision_path_and_scale_drift() {
        let valid = remote(
            "worker-b",
            "worker-b-uid",
            "10.43.0.0/24",
            "fd00:43::/64",
            "192.0.2.2",
            "fdff::2",
        );

        let mut invalid = valid.clone();
        invalid.intent.assignment_revision = 0;
        assert!(matches!(
            provider().plan(vec![invalid]),
            Err(RouteError::InvalidRemoteNode { .. })
        ));
        let mut invalid = valid.clone();
        invalid.ipv4_next_hop.output_interface = 0;
        assert!(matches!(
            provider().plan(vec![invalid]),
            Err(RouteError::InvalidRemoteNode { .. })
        ));
        let mut invalid = valid.clone();
        invalid.ipv6_next_hop.gateway = "ff02::1".parse().unwrap();
        assert!(matches!(
            provider().plan(vec![invalid]),
            Err(RouteError::InvalidRemoteNode { .. })
        ));
        let mut alias = valid.clone();
        alias.intent.node_uid = "worker-a-uid".to_owned();
        assert!(matches!(
            provider().plan(vec![alias]),
            Err(RouteError::InvalidRemoteNode { .. })
        ));

        let oversized = vec![valid; MAX_REMOTE_NODES + 1];
        assert_eq!(
            provider().plan(oversized).unwrap_err(),
            RouteError::TooManyRemoteNodes {
                actual: MAX_REMOTE_NODES + 1,
                limit: MAX_REMOTE_NODES,
            }
        );
    }

    #[test]
    fn remote_plan_rejects_every_ambiguous_address_domain() {
        let valid = remote(
            "worker-b",
            "worker-b-uid",
            "10.43.0.0/24",
            "fd00:43::/64",
            "192.0.2.2",
            "fdff::2",
        );
        let duplicate = NativeRemoteNode {
            intent: RemoteNodeIntent {
                node_name: "worker-b".to_owned(),
                node_uid: "different-uid".to_owned(),
                assignment_revision: 8,
                blocks: blocks("10.44.0.0/24", "fd00:44::/64"),
            },
            ..valid.clone()
        };
        assert!(matches!(
            provider().plan(vec![valid.clone(), duplicate]),
            Err(RouteError::InvalidRemoteNode { .. })
        ));

        let overlaps_local = remote(
            "worker-c",
            "worker-c-uid",
            "10.42.0.128/25",
            "fd00:44::/64",
            "192.0.2.3",
            "fdff::3",
        );
        assert!(matches!(
            provider().plan(vec![overlaps_local]),
            Err(RouteError::RemoteBlockOverlap { family: "IPv4", .. })
        ));

        let overlaps_remote = remote(
            "worker-c",
            "worker-c-uid",
            "10.43.0.128/25",
            "fd00:44::/64",
            "192.0.2.3",
            "fdff::3",
        );
        assert!(matches!(
            provider().plan(vec![valid.clone(), overlaps_remote]),
            Err(RouteError::RemoteBlockOverlap { family: "IPv4", .. })
        ));

        let mut recursive = valid;
        recursive.ipv4_next_hop.gateway = "10.43.0.1".parse().unwrap();
        assert!(matches!(
            provider().plan(vec![recursive]),
            Err(RouteError::InvalidRemoteNode { .. })
        ));
    }
}
