//! Bounded, proof-carrying BGP advertisement transactions.
//!
//! UNF does not implement BGP. This module defines the canonical safety
//! boundary consumed by an evaluated routing daemon adapter. Every exported
//! host route carries a Causal Route Capsule: three transitive BGP large
//! communities that identify the UNF schema and bind a 128-bit fingerprint of
//! the exact owner, lease, desired revision, action, and reachability plan.
//! This lets external observers distinguish a stale route from a later reuse of
//! the same address.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use unf_common::Revision;

use crate::{
    EGRESS_REACHABILITY_ALGORITHM_DIVERSITY_QUORUM_V1, EGRESS_REACHABILITY_SCHEMA_VERSION,
    EgressGatewayDesired, EgressIntentOwner, EgressIntentScope, EgressProviderRef,
    EgressReachabilityPath, EgressReachabilityPlan, EgressReachabilityPlanDigest,
    EgressReachabilityVantage, MAX_EGRESS_ADDRESSES_PER_INTENT, MAX_EGRESS_INTENTS,
    MAX_EGRESS_REACHABILITY_ID_BYTES, seal_egress_reachability_plan,
};

pub const EGRESS_BGP_SCHEMA_VERSION: u16 = 1;
pub const EGRESS_BGP_ALGORITHM: &str = "causal-constrained-convergence-v1";
pub const EGRESS_BGP_CAPSULE_MARKER: u32 = 0x554e_4601;
pub const MAX_EGRESS_BGP_PEERS: usize = 64;
pub const MAX_EGRESS_BGP_PREFIXES: usize = MAX_EGRESS_INTENTS * MAX_EGRESS_ADDRESSES_PER_INTENT;
pub const MAX_EGRESS_BGP_PREFIXES_PER_TRANSACTION: usize = 4_096;
pub const MAX_EGRESS_BGP_GRACEFUL_RESTART_SECONDS: u16 = 300;
pub const MAX_EGRESS_BGP_STALE_PATH_SECONDS: u16 = 900;
pub const EGRESS_BFD_SINGLE_HOP_PORT: u16 = 3_784;
pub const MIN_EGRESS_BFD_INTERVAL_MICROSECONDS: u32 = 100_000;
pub const MAX_EGRESS_BFD_INTERVAL_MICROSECONDS: u32 = 10_000_000;
pub const MIN_EGRESS_BFD_DETECTION_MULTIPLIER: u8 = 2;
pub const MAX_EGRESS_BFD_DETECTION_MULTIPLIER: u8 = 50;
pub const EGRESS_BGP_REACHABILITY_OBSERVATION_AGE_SECONDS: u64 = 90;

const CONFIG_DIGEST_DOMAIN: &[u8] = b"unf.egress.bgp.config.v1\0";
const ROUTE_DIGEST_DOMAIN: &[u8] = b"unf.egress.bgp.route.v1\0";
const SNAPSHOT_DIGEST_DOMAIN: &[u8] = b"unf.egress.bgp.snapshot.v1\0";
const TRANSACTION_DIGEST_DOMAIN: &[u8] = b"unf.egress.bgp.transaction.v1\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum EgressBgpAddressFamily {
    Ipv4,
    Ipv6,
}

impl EgressBgpAddressFamily {
    const fn contains(self, address: IpAddr) -> bool {
        matches!(
            (self, address),
            (Self::Ipv4, IpAddr::V4(_)) | (Self::Ipv6, IpAddr::V6(_))
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EgressBgpPrefix {
    pub address: IpAddr,
    pub length: u8,
}

impl EgressBgpPrefix {
    #[must_use]
    pub const fn host(address: IpAddr) -> Self {
        Self {
            address,
            length: if address.is_ipv4() { 32 } else { 128 },
        }
    }

    fn is_canonical(self) -> bool {
        match self.address {
            IpAddr::V4(address) if self.length <= 32 => {
                let host_bits = 32_u8.saturating_sub(self.length);
                host_bits == 32 || u32::from(address) & ((1_u32 << host_bits) - 1) == 0
            }
            IpAddr::V6(address) if self.length <= 128 => {
                let host_bits = 128_u8.saturating_sub(self.length);
                host_bits == 128 || u128::from(address) & ((1_u128 << host_bits) - 1) == 0
            }
            _ => false,
        }
    }

    fn contains(self, address: IpAddr) -> bool {
        if !self.is_canonical() {
            return false;
        }
        match (self.address, address) {
            (IpAddr::V4(network), IpAddr::V4(address)) => {
                let shift = 32_u8.saturating_sub(self.length);
                shift == 32 || u32::from(network) >> shift == u32::from(address) >> shift
            }
            (IpAddr::V6(network), IpAddr::V6(address)) => {
                let shift = 128_u8.saturating_sub(self.length);
                shift == 128 || u128::from(network) >> shift == u128::from(address) >> shift
            }
            _ => false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EgressBgpLargeCommunity {
    pub global_admin: u32,
    pub local_data_one: u32,
    pub local_data_two: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EgressBgpCausalRouteCapsule {
    pub communities: [EgressBgpLargeCommunity; 3],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EgressBgpConfigDigest(pub [u8; 32]);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EgressBgpRouteDigest(pub [u8; 32]);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EgressBgpSnapshotDigest(pub [u8; 32]);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EgressBgpTransactionDigest(pub [u8; 32]);

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EgressBgpPeer {
    pub name: String,
    pub address: IpAddr,
    pub remote_asn: u32,
    pub failure_domain: String,
    pub families: BTreeSet<EgressBgpAddressFamily>,
    pub multihop_ttl: u8,
    pub maximum_received_prefixes: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bfd: Option<EgressBgpBfdConfig>,
}

/// Bounded single-hop asynchronous BFD policy. Absence is deliberately
/// disabled because enabling BFD unilaterally would tear down a valid BGP peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EgressBgpBfdConfig {
    pub port: u16,
    pub desired_minimum_tx_interval_microseconds: u32,
    pub required_minimum_receive_interval_microseconds: u32,
    pub detection_multiplier: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EgressBgpGracefulRestart {
    pub restart_seconds: u16,
    pub stale_path_seconds: u16,
}

/// Exact local-speaker policy. Export is default-deny and every mutation is
/// limited independently from the total retained route set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EgressBgpConfig {
    pub schema_version: u16,
    pub algorithm: String,
    pub revision: Revision,
    pub instance: String,
    pub local_asn: u32,
    pub router_id: Ipv4Addr,
    pub ipv4_next_hop: Option<IpAddr>,
    pub ipv6_next_hop: Option<IpAddr>,
    pub peers: Vec<EgressBgpPeer>,
    pub permitted_export_prefixes: Vec<EgressBgpPrefix>,
    pub maximum_changed_prefixes: u16,
    pub maximum_total_prefixes: u32,
    pub maximum_paths_per_prefix: u16,
    pub graceful_restart: EgressBgpGracefulRestart,
    pub digest: EgressBgpConfigDigest,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EgressBgpRoute {
    pub owner: EgressIntentOwner,
    pub provider: EgressProviderRef,
    pub desired_revision: Revision,
    pub lease_epoch: u64,
    pub prefix: EgressBgpPrefix,
    pub next_hop: IpAddr,
    pub gateway_name: String,
    pub gateway_uid: String,
    pub reachability_plan_digest: EgressReachabilityPlanDigest,
    pub capsule: EgressBgpCausalRouteCapsule,
    pub digest: EgressBgpRouteDigest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EgressBgpSnapshot {
    pub schema_version: u16,
    pub algorithm: String,
    pub revision: Revision,
    pub config_digest: EgressBgpConfigDigest,
    pub routes: Vec<EgressBgpRoute>,
    pub digest: EgressBgpSnapshotDigest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EgressBgpTransaction {
    pub schema_version: u16,
    pub algorithm: String,
    pub revision: Revision,
    pub previous_snapshot: EgressBgpSnapshot,
    pub desired_snapshot: EgressBgpSnapshot,
    pub additions: Vec<EgressBgpRoute>,
    pub withdrawals: Vec<EgressBgpRoute>,
    pub retained: Vec<EgressBgpRoute>,
    pub digest: EgressBgpTransactionDigest,
}

/// Independently read daemon state. A route is accepted only after it exists in
/// the local RIB and the exact capsule is present in every required Adj-RIB-Out.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EgressBgpRouteReadback {
    pub route: EgressBgpRoute,
    pub local_rib: bool,
    pub advertised_to_peers: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum EgressBgpError {
    #[error("unsupported or invalid BGP configuration")]
    InvalidConfig,
    #[error("BGP configuration digest does not match")]
    ConfigDigestMismatch,
    #[error("unsupported or invalid BGP route")]
    InvalidRoute,
    #[error("BGP route digest does not match")]
    RouteDigestMismatch,
    #[error("unsupported or invalid BGP snapshot")]
    InvalidSnapshot,
    #[error("BGP snapshot digest does not match")]
    SnapshotDigestMismatch,
    #[error("BGP transaction exceeds its changed-prefix blast-radius budget")]
    BlastRadiusExceeded,
    #[error("BGP transaction conflicts with a foreign or stale owner")]
    RouteConflict,
    #[error("BGP provider readback does not exactly match desired state")]
    ReadbackMismatch,
    #[error("BGP canonical encoding failed: {0}")]
    Encoding(String),
    #[error("BGP reachability plan could not be derived")]
    InvalidReachabilityPlan,
}

/// Derives the exact DQR contract shared by the controller and every local BGP
/// speaker. This common replay is what binds Causal Route Capsules to the
/// controller-owned plan rather than to an adapter-local approximation.
///
/// # Errors
///
/// Rejects a non-BGP desired record, empty gateway set, or revision overflow.
pub fn derive_egress_bgp_reachability_plan(
    desired: &EgressGatewayDesired,
) -> Result<EgressReachabilityPlan, EgressBgpError> {
    if desired.provider.name != "bgp" || desired.nodes.is_empty() {
        return Err(EgressBgpError::InvalidReachabilityPlan);
    }
    let revision = desired
        .revision
        .get()
        .checked_mul(2)
        .and_then(|revision| revision.checked_add(1))
        .map(Revision::new)
        .ok_or(EgressBgpError::InvalidReachabilityPlan)?;
    let maximum_paths_per_address =
        u16::try_from(desired.nodes.len()).map_err(|_| EgressBgpError::InvalidReachabilityPlan)?;
    seal_egress_reachability_plan(EgressReachabilityPlan {
        schema_version: EGRESS_REACHABILITY_SCHEMA_VERSION,
        algorithm: EGRESS_REACHABILITY_ALGORITHM_DIVERSITY_QUORUM_V1.to_owned(),
        revision,
        desired_revision: desired.revision,
        allocation_revision: desired.allocation_revision,
        owner: desired.owner.clone(),
        provider: desired.provider.clone(),
        lease_epoch: desired.lease_epoch,
        action: desired.action,
        addresses: desired.addresses.clone(),
        expected_paths: desired
            .nodes
            .iter()
            .map(|node| EgressReachabilityPath {
                gateway_uid: node.uid.clone(),
                forwarding_identity: format!("bgp-node/{}", node.uid),
            })
            .collect(),
        minimum_paths_per_address: 1,
        maximum_paths_per_address,
        vantages: vec![
            EgressReachabilityVantage {
                name: "adj-rib-out".to_owned(),
                minimum_failure_domains: 1,
            },
            EgressReachabilityVantage {
                name: "fabric".to_owned(),
                minimum_failure_domains: 2,
            },
        ],
        max_observation_age_seconds: EGRESS_BGP_REACHABILITY_OBSERVATION_AGE_SECONDS,
        digest: EgressReachabilityPlanDigest([0; 32]),
    })
    .map_err(|_| EgressBgpError::InvalidReachabilityPlan)
}

/// Canonicalizes and seals a local BGP speaker configuration.
///
/// # Errors
///
/// Rejects unsafe defaults, invalid peers, unbounded route budgets, and
/// noncanonical export prefixes.
pub fn seal_egress_bgp_config(
    mut config: EgressBgpConfig,
) -> Result<EgressBgpConfig, EgressBgpError> {
    if config.schema_version != EGRESS_BGP_SCHEMA_VERSION
        || config.algorithm != EGRESS_BGP_ALGORITHM
        || config.revision == Revision::INITIAL
        || !valid_id(&config.instance)
        || config.local_asn == 0
        || config.router_id.is_unspecified()
        || config.peers.is_empty()
        || config.peers.len() > MAX_EGRESS_BGP_PEERS
        || config.permitted_export_prefixes.is_empty()
        || usize::from(config.maximum_changed_prefixes) > MAX_EGRESS_BGP_PREFIXES_PER_TRANSACTION
        || config.maximum_changed_prefixes == 0
        || config.maximum_total_prefixes == 0
        || usize::try_from(config.maximum_total_prefixes)
            .ok()
            .is_none_or(|limit| limit > MAX_EGRESS_BGP_PREFIXES)
        || config.maximum_paths_per_prefix == 0
        || usize::from(config.maximum_paths_per_prefix) > crate::MAX_EGRESS_GATEWAY_NODES
        || config.graceful_restart.restart_seconds == 0
        || config.graceful_restart.restart_seconds > MAX_EGRESS_BGP_GRACEFUL_RESTART_SECONDS
        || config.graceful_restart.stale_path_seconds < config.graceful_restart.restart_seconds
        || config.graceful_restart.stale_path_seconds > MAX_EGRESS_BGP_STALE_PATH_SECONDS
        || config
            .ipv4_next_hop
            .is_some_and(|address| !address.is_ipv4() || invalid_unicast(address))
        || config
            .ipv6_next_hop
            .is_some_and(|address| !address.is_ipv6() || invalid_unicast(address))
    {
        return Err(EgressBgpError::InvalidConfig);
    }
    if config.peers.iter().any(|peer| {
        !valid_id(&peer.name)
            || !valid_id(&peer.failure_domain)
            || peer.remote_asn == 0
            || invalid_unicast(peer.address)
            || peer.families.is_empty()
            || peer.multihop_ttl == 0
            || peer.maximum_received_prefixes == 0
            || peer.bfd.as_ref().is_some_and(|bfd| {
                !peer.address.is_ipv4()
                    || peer.multihop_ttl != 1
                    || bfd.port != EGRESS_BFD_SINGLE_HOP_PORT
                    || !(MIN_EGRESS_BFD_INTERVAL_MICROSECONDS
                        ..=MAX_EGRESS_BFD_INTERVAL_MICROSECONDS)
                        .contains(&bfd.desired_minimum_tx_interval_microseconds)
                    || !(MIN_EGRESS_BFD_INTERVAL_MICROSECONDS
                        ..=MAX_EGRESS_BFD_INTERVAL_MICROSECONDS)
                        .contains(&bfd.required_minimum_receive_interval_microseconds)
                    || !(MIN_EGRESS_BFD_DETECTION_MULTIPLIER..=MAX_EGRESS_BFD_DETECTION_MULTIPLIER)
                        .contains(&bfd.detection_multiplier)
            })
    }) || config.permitted_export_prefixes.iter().any(|prefix| {
        !prefix.is_canonical() || prefix.length == 0 || invalid_unicast(prefix.address)
    }) {
        return Err(EgressBgpError::InvalidConfig);
    }
    config.peers.sort_unstable();
    config.permitted_export_prefixes.sort_unstable();
    if config
        .peers
        .windows(2)
        .any(|pair| pair[0].name == pair[1].name || pair[0].address == pair[1].address)
        || has_duplicates(&config.permitted_export_prefixes)
    {
        return Err(EgressBgpError::InvalidConfig);
    }
    config.digest = digest_without(&config, CONFIG_DIGEST_DOMAIN, |value| {
        value.digest = EgressBgpConfigDigest([0; 32]);
    })
    .map(EgressBgpConfigDigest)?;
    Ok(config)
}

/// Verifies that a sealed speaker configuration has not drifted.
///
/// # Errors
///
/// Rejects semantic, canonical, or digest mutation.
pub fn verify_egress_bgp_config(
    config: EgressBgpConfig,
) -> Result<EgressBgpConfig, EgressBgpError> {
    let expected = config.digest;
    let replayed = seal_egress_bgp_config(config)?;
    if replayed.digest != expected {
        return Err(EgressBgpError::ConfigDigestMismatch);
    }
    Ok(replayed)
}

/// Builds one exact host route and its default-on causal capsule.
///
/// # Errors
///
/// Rejects foreign providers, addresses outside the export envelope, malformed
/// identity, or a missing family-specific next hop.
#[allow(clippy::too_many_arguments)]
pub fn seal_egress_bgp_route(
    config: &EgressBgpConfig,
    owner: EgressIntentOwner,
    provider: EgressProviderRef,
    desired_revision: Revision,
    lease_epoch: u64,
    address: IpAddr,
    gateway_name: String,
    gateway_uid: String,
    reachability_plan_digest: EgressReachabilityPlanDigest,
) -> Result<EgressBgpRoute, EgressBgpError> {
    let config = verify_egress_bgp_config(config.clone())?;
    let next_hop = match address {
        IpAddr::V4(_) => config.ipv4_next_hop,
        IpAddr::V6(_) => config.ipv6_next_hop,
    }
    .ok_or(EgressBgpError::InvalidRoute)?;
    let prefix = EgressBgpPrefix::host(address);
    if provider.name != "bgp"
        || provider.instance != config.instance
        || desired_revision == Revision::INITIAL
        || lease_epoch == 0
        || invalid_unicast(address)
        || !valid_owner(&owner)
        || !valid_id(&gateway_name)
        || !valid_id(&gateway_uid)
        || reachability_plan_digest.0 == [0; 32]
        || !config
            .permitted_export_prefixes
            .iter()
            .any(|allowed| allowed.contains(address))
        || !config
            .peers
            .iter()
            .any(|peer| peer.families.iter().any(|family| family.contains(address)))
    {
        return Err(EgressBgpError::InvalidRoute);
    }
    let fingerprint = route_fingerprint(
        &owner,
        &provider,
        desired_revision,
        lease_epoch,
        prefix,
        next_hop,
        &gateway_uid,
        reachability_plan_digest,
    )?;
    let words = [
        u32::from_be_bytes([
            fingerprint[0],
            fingerprint[1],
            fingerprint[2],
            fingerprint[3],
        ]),
        u32::from_be_bytes([
            fingerprint[4],
            fingerprint[5],
            fingerprint[6],
            fingerprint[7],
        ]),
        u32::from_be_bytes([
            fingerprint[8],
            fingerprint[9],
            fingerprint[10],
            fingerprint[11],
        ]),
        u32::from_be_bytes([
            fingerprint[12],
            fingerprint[13],
            fingerprint[14],
            fingerprint[15],
        ]),
    ];
    let capsule = EgressBgpCausalRouteCapsule {
        communities: [
            EgressBgpLargeCommunity {
                global_admin: config.local_asn,
                local_data_one: EGRESS_BGP_CAPSULE_MARKER,
                local_data_two: words[0],
            },
            EgressBgpLargeCommunity {
                global_admin: config.local_asn,
                local_data_one: words[1],
                local_data_two: words[2],
            },
            EgressBgpLargeCommunity {
                global_admin: config.local_asn,
                local_data_one: words[3],
                local_data_two: u32::from(EGRESS_BGP_SCHEMA_VERSION),
            },
        ],
    };
    let mut route = EgressBgpRoute {
        owner,
        provider,
        desired_revision,
        lease_epoch,
        prefix,
        next_hop,
        gateway_name,
        gateway_uid,
        reachability_plan_digest,
        capsule,
        digest: EgressBgpRouteDigest([0; 32]),
    };
    route.digest = digest_without(&route, ROUTE_DIGEST_DOMAIN, |value| {
        value.digest = EgressBgpRouteDigest([0; 32]);
    })
    .map(EgressBgpRouteDigest)?;
    Ok(route)
}

/// Seals a complete per-speaker advertisement snapshot.
///
/// # Errors
///
/// Rejects duplicate prefixes, foreign configuration, route mutation, and
/// snapshots larger than the configured total-prefix budget.
pub fn seal_egress_bgp_snapshot(
    config: &EgressBgpConfig,
    revision: Revision,
    mut routes: Vec<EgressBgpRoute>,
) -> Result<EgressBgpSnapshot, EgressBgpError> {
    let config = verify_egress_bgp_config(config.clone())?;
    if revision == Revision::INITIAL
        || routes.len() > usize::try_from(config.maximum_total_prefixes).unwrap_or(usize::MAX)
    {
        return Err(EgressBgpError::InvalidSnapshot);
    }
    for route in &routes {
        let expected = route.digest;
        let replayed = seal_egress_bgp_route(
            &config,
            route.owner.clone(),
            route.provider.clone(),
            route.desired_revision,
            route.lease_epoch,
            route.prefix.address,
            route.gateway_name.clone(),
            route.gateway_uid.clone(),
            route.reachability_plan_digest,
        )?;
        if route.prefix != EgressBgpPrefix::host(route.prefix.address)
            || replayed.digest != expected
        {
            return Err(EgressBgpError::RouteDigestMismatch);
        }
    }
    routes.sort_by_key(|route| route.prefix);
    if routes
        .windows(2)
        .any(|pair| pair[0].prefix == pair[1].prefix)
    {
        return Err(EgressBgpError::RouteConflict);
    }
    let mut snapshot = EgressBgpSnapshot {
        schema_version: EGRESS_BGP_SCHEMA_VERSION,
        algorithm: EGRESS_BGP_ALGORITHM.to_owned(),
        revision,
        config_digest: config.digest,
        routes,
        digest: EgressBgpSnapshotDigest([0; 32]),
    };
    snapshot.digest = digest_without(&snapshot, SNAPSHOT_DIGEST_DOMAIN, |value| {
        value.digest = EgressBgpSnapshotDigest([0; 32]);
    })
    .map(EgressBgpSnapshotDigest)?;
    Ok(snapshot)
}

/// Computes a complete, bounded replacement without touching daemon state.
///
/// # Errors
///
/// Rejects stale inputs, same-prefix ownership changes, or a delta beyond the
/// configured blast-radius budget.
pub fn prepare_egress_bgp_transaction(
    config: &EgressBgpConfig,
    previous: EgressBgpSnapshot,
    desired: EgressBgpSnapshot,
) -> Result<EgressBgpTransaction, EgressBgpError> {
    let config = verify_egress_bgp_config(config.clone())?;
    let previous = replay_snapshot(&config, previous)?;
    let desired = replay_snapshot(&config, desired)?;
    if desired.revision <= previous.revision {
        return Err(EgressBgpError::InvalidSnapshot);
    }
    let old = previous
        .routes
        .iter()
        .map(|route| (route.prefix, route))
        .collect::<BTreeMap<_, _>>();
    let new = desired
        .routes
        .iter()
        .map(|route| (route.prefix, route))
        .collect::<BTreeMap<_, _>>();
    if old.iter().any(|(prefix, route)| {
        new.get(prefix).is_some_and(|candidate| {
            route.owner != candidate.owner || route.lease_epoch != candidate.lease_epoch
        })
    }) {
        return Err(EgressBgpError::RouteConflict);
    }
    let additions = new
        .iter()
        .filter(|(prefix, route)| old.get(prefix).is_none_or(|old| old.digest != route.digest))
        .map(|(_, route)| (*route).clone())
        .collect::<Vec<_>>();
    let withdrawals = old
        .iter()
        .filter(|(prefix, route)| new.get(prefix).is_none_or(|new| new.digest != route.digest))
        .map(|(_, route)| (*route).clone())
        .collect::<Vec<_>>();
    let retained = new
        .iter()
        .filter(|(prefix, route)| {
            old.get(prefix)
                .is_some_and(|old| old.digest == route.digest)
        })
        .map(|(_, route)| (*route).clone())
        .collect::<Vec<_>>();
    if additions.len().saturating_add(withdrawals.len())
        > usize::from(config.maximum_changed_prefixes)
    {
        return Err(EgressBgpError::BlastRadiusExceeded);
    }
    let mut transaction = EgressBgpTransaction {
        schema_version: EGRESS_BGP_SCHEMA_VERSION,
        algorithm: EGRESS_BGP_ALGORITHM.to_owned(),
        revision: desired.revision,
        previous_snapshot: previous,
        desired_snapshot: desired,
        additions,
        withdrawals,
        retained,
        digest: EgressBgpTransactionDigest([0; 32]),
    };
    transaction.digest = digest_without(&transaction, TRANSACTION_DIGEST_DOMAIN, |value| {
        value.digest = EgressBgpTransactionDigest([0; 32]);
    })
    .map(EgressBgpTransactionDigest)?;
    Ok(transaction)
}

/// Verifies local-RIB and per-peer Adj-RIB-Out state after a transaction.
///
/// # Errors
///
/// Rejects missing, extra, stale-capsule, or partially advertised routes.
pub fn verify_egress_bgp_readback(
    config: &EgressBgpConfig,
    transaction: &EgressBgpTransaction,
    mut readback: Vec<EgressBgpRouteReadback>,
) -> Result<EgressBgpSnapshot, EgressBgpError> {
    let config = verify_egress_bgp_config(config.clone())?;
    let expected_transaction_digest = transaction.digest;
    let replayed = prepare_egress_bgp_transaction(
        &config,
        rollback_snapshot(transaction),
        transaction.desired_snapshot.clone(),
    )?;
    if replayed.digest != expected_transaction_digest {
        return Err(EgressBgpError::ReadbackMismatch);
    }
    readback.sort_by_key(|entry| entry.route.prefix);
    if readback.len() != transaction.desired_snapshot.routes.len()
        || readback
            .iter()
            .zip(&transaction.desired_snapshot.routes)
            .any(|(actual, expected)| {
                let expected_peers = config
                    .peers
                    .iter()
                    .filter(|peer| {
                        peer.families
                            .iter()
                            .any(|family| family.contains(expected.prefix.address))
                    })
                    .map(|peer| peer.name.clone())
                    .collect::<BTreeSet<_>>();
                actual.route != *expected
                    || !actual.local_rib
                    || actual.advertised_to_peers != expected_peers
            })
    {
        return Err(EgressBgpError::ReadbackMismatch);
    }
    Ok(transaction.desired_snapshot.clone())
}

/// Returns the exact pre-transaction state for scoped rollback.
#[must_use]
pub fn rollback_snapshot(transaction: &EgressBgpTransaction) -> EgressBgpSnapshot {
    transaction.previous_snapshot.clone()
}

fn replay_snapshot(
    config: &EgressBgpConfig,
    snapshot: EgressBgpSnapshot,
) -> Result<EgressBgpSnapshot, EgressBgpError> {
    if snapshot.schema_version != EGRESS_BGP_SCHEMA_VERSION
        || snapshot.algorithm != EGRESS_BGP_ALGORITHM
        || snapshot.config_digest != config.digest
    {
        return Err(EgressBgpError::InvalidSnapshot);
    }
    let expected = snapshot.digest;
    let replayed = seal_egress_bgp_snapshot(config, snapshot.revision, snapshot.routes)?;
    if replayed.digest != expected {
        return Err(EgressBgpError::SnapshotDigestMismatch);
    }
    Ok(replayed)
}

#[allow(clippy::too_many_arguments)]
fn route_fingerprint(
    owner: &EgressIntentOwner,
    provider: &EgressProviderRef,
    desired_revision: Revision,
    lease_epoch: u64,
    prefix: EgressBgpPrefix,
    next_hop: IpAddr,
    gateway_uid: &str,
    reachability_plan_digest: EgressReachabilityPlanDigest,
) -> Result<[u8; 16], EgressBgpError> {
    let value = serde_json::to_vec(&(
        owner,
        provider,
        desired_revision,
        lease_epoch,
        prefix,
        next_hop,
        gateway_uid,
        reachability_plan_digest,
    ))
    .map_err(|error| EgressBgpError::Encoding(error.to_string()))?;
    let mut hasher = Sha256::new();
    hasher.update(ROUTE_DIGEST_DOMAIN);
    hasher.update(value);
    let digest: [u8; 32] = hasher.finalize().into();
    Ok(digest[..16].try_into().expect("128-bit digest prefix"))
}

fn digest_without<T: Serialize + Clone>(
    value: &T,
    domain: &[u8],
    clear: impl FnOnce(&mut T),
) -> Result<[u8; 32], EgressBgpError> {
    let mut unsigned = value.clone();
    clear(&mut unsigned);
    let encoded = serde_json::to_vec(&unsigned)
        .map_err(|error| EgressBgpError::Encoding(error.to_string()))?;
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(encoded);
    Ok(hasher.finalize().into())
}

fn valid_owner(owner: &EgressIntentOwner) -> bool {
    valid_id(&owner.name)
        && valid_id(&owner.uid)
        && match &owner.scope {
            EgressIntentScope::Cluster => true,
            EgressIntentScope::Namespace(namespace) => valid_id(namespace),
        }
}

fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_EGRESS_REACHABILITY_ID_BYTES
        && !value.chars().any(char::is_control)
}

fn invalid_unicast(address: IpAddr) -> bool {
    address.is_unspecified() || address.is_multicast() || address.is_loopback()
}

fn has_duplicates<T: PartialEq>(values: &[T]) -> bool {
    values.windows(2).any(|pair| pair[0] == pair[1])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(changed: u16) -> EgressBgpConfig {
        seal_egress_bgp_config(EgressBgpConfig {
            schema_version: EGRESS_BGP_SCHEMA_VERSION,
            algorithm: EGRESS_BGP_ALGORITHM.to_owned(),
            revision: Revision::new(7),
            instance: "fabric-a".to_owned(),
            local_asn: 64_512,
            router_id: "192.0.2.10".parse().unwrap(),
            ipv4_next_hop: Some("198.51.100.10".parse().unwrap()),
            ipv6_next_hop: Some("2001:db8:100::10".parse().unwrap()),
            peers: vec![EgressBgpPeer {
                name: "tor-a".to_owned(),
                address: "198.51.100.1".parse().unwrap(),
                remote_asn: 64_513,
                failure_domain: "rack-a".to_owned(),
                families: BTreeSet::from([EgressBgpAddressFamily::Ipv4]),
                multihop_ttl: 1,
                maximum_received_prefixes: 1_024,
                bfd: None,
            }],
            permitted_export_prefixes: vec![
                EgressBgpPrefix {
                    address: "192.0.2.0".parse().unwrap(),
                    length: 24,
                },
                EgressBgpPrefix {
                    address: "2001:db8:ffff::".parse().unwrap(),
                    length: 64,
                },
            ],
            maximum_changed_prefixes: changed,
            maximum_total_prefixes: 256,
            maximum_paths_per_prefix: 4,
            graceful_restart: EgressBgpGracefulRestart {
                restart_seconds: 30,
                stale_path_seconds: 90,
            },
            digest: EgressBgpConfigDigest([0; 32]),
        })
        .unwrap()
    }

    fn owner() -> EgressIntentOwner {
        EgressIntentOwner {
            scope: EgressIntentScope::Cluster,
            name: "payments".to_owned(),
            uid: "policy-uid-a".to_owned(),
        }
    }

    fn provider() -> EgressProviderRef {
        EgressProviderRef {
            name: "bgp".to_owned(),
            instance: "fabric-a".to_owned(),
        }
    }

    fn route(config: &EgressBgpConfig, address: &str, lease_epoch: u64) -> EgressBgpRoute {
        seal_egress_bgp_route(
            config,
            owner(),
            provider(),
            Revision::new(11),
            lease_epoch,
            address.parse().unwrap(),
            "worker-a".to_owned(),
            "node-uid-a".to_owned(),
            EgressReachabilityPlanDigest([9; 32]),
        )
        .unwrap()
    }

    fn snapshot(
        config: &EgressBgpConfig,
        revision: u64,
        routes: Vec<EgressBgpRoute>,
    ) -> EgressBgpSnapshot {
        seal_egress_bgp_snapshot(config, Revision::new(revision), routes).unwrap()
    }

    #[test]
    fn causal_capsule_changes_across_safe_address_reuse() {
        let config = config(8);
        let first = route(&config, "192.0.2.240", 41);
        let reused = route(&config, "192.0.2.240", 42);
        assert_ne!(first.capsule, reused.capsule);
        assert_ne!(first.digest, reused.digest);
        assert_eq!(
            first.capsule.communities[0].local_data_one,
            EGRESS_BGP_CAPSULE_MARKER
        );
    }

    #[test]
    fn export_policy_is_default_deny_and_configuration_is_tamper_evident() {
        let config = config(8);
        assert_eq!(
            seal_egress_bgp_route(
                &config,
                owner(),
                provider(),
                Revision::new(11),
                41,
                "198.51.100.240".parse().unwrap(),
                "worker-a".to_owned(),
                "node-uid-a".to_owned(),
                EgressReachabilityPlanDigest([9; 32]),
            )
            .unwrap_err(),
            EgressBgpError::InvalidRoute
        );

        let mut tampered = config;
        tampered.maximum_total_prefixes += 1;
        assert_eq!(
            verify_egress_bgp_config(tampered).unwrap_err(),
            EgressBgpError::ConfigDigestMismatch
        );
    }

    #[test]
    fn bfd_is_explicit_bounded_and_single_hop_only() {
        let mut valid = config(8);
        valid.peers[0].bfd = Some(EgressBgpBfdConfig {
            port: EGRESS_BFD_SINGLE_HOP_PORT,
            desired_minimum_tx_interval_microseconds: 300_000,
            required_minimum_receive_interval_microseconds: 300_000,
            detection_multiplier: 3,
        });
        valid.digest = EgressBgpConfigDigest([0; 32]);
        let valid = seal_egress_bgp_config(valid).unwrap();
        assert!(verify_egress_bgp_config(valid.clone()).is_ok());

        let mut multihop = valid.clone();
        multihop.peers[0].multihop_ttl = 2;
        multihop.digest = EgressBgpConfigDigest([0; 32]);
        assert_eq!(
            seal_egress_bgp_config(multihop),
            Err(EgressBgpError::InvalidConfig)
        );

        let mut too_fast = valid;
        too_fast.peers[0]
            .bfd
            .as_mut()
            .unwrap()
            .desired_minimum_tx_interval_microseconds = MIN_EGRESS_BFD_INTERVAL_MICROSECONDS - 1;
        too_fast.digest = EgressBgpConfigDigest([0; 32]);
        assert_eq!(
            seal_egress_bgp_config(too_fast),
            Err(EgressBgpError::InvalidConfig)
        );

        let mut ipv6_transport = config(8);
        ipv6_transport.peers[0].address = "2001:db8::1".parse().unwrap();
        ipv6_transport.peers[0].bfd = Some(EgressBgpBfdConfig {
            port: EGRESS_BFD_SINGLE_HOP_PORT,
            desired_minimum_tx_interval_microseconds: 300_000,
            required_minimum_receive_interval_microseconds: 300_000,
            detection_multiplier: 3,
        });
        ipv6_transport.digest = EgressBgpConfigDigest([0; 32]);
        assert_eq!(
            seal_egress_bgp_config(ipv6_transport),
            Err(EgressBgpError::InvalidConfig)
        );
    }

    #[test]
    fn blast_radius_and_same_prefix_takeover_deny_before_mutation() {
        let limited = config(1);
        let empty = snapshot(&limited, 1, Vec::new());
        let two = snapshot(
            &limited,
            2,
            vec![
                route(&limited, "192.0.2.240", 41),
                route(&limited, "192.0.2.241", 41),
            ],
        );
        assert_eq!(
            prepare_egress_bgp_transaction(&limited, empty, two).unwrap_err(),
            EgressBgpError::BlastRadiusExceeded
        );

        let config = config(8);
        let first = snapshot(&config, 1, vec![route(&config, "192.0.2.240", 41)]);
        let reused = snapshot(&config, 2, vec![route(&config, "192.0.2.240", 42)]);
        assert_eq!(
            prepare_egress_bgp_transaction(&config, first, reused).unwrap_err(),
            EgressBgpError::RouteConflict
        );
    }

    #[test]
    fn exact_rib_chain_requires_every_peer_and_preserves_rollback() {
        let config = config(8);
        let previous = snapshot(&config, 1, Vec::new());
        let desired = snapshot(&config, 2, vec![route(&config, "192.0.2.240", 41)]);
        let transaction =
            prepare_egress_bgp_transaction(&config, previous.clone(), desired.clone()).unwrap();
        assert_eq!(rollback_snapshot(&transaction), previous);
        let missing_peer = vec![EgressBgpRouteReadback {
            route: desired.routes[0].clone(),
            local_rib: true,
            advertised_to_peers: BTreeSet::new(),
        }];
        assert_eq!(
            verify_egress_bgp_readback(&config, &transaction, missing_peer).unwrap_err(),
            EgressBgpError::ReadbackMismatch
        );
        let exact = vec![EgressBgpRouteReadback {
            route: desired.routes[0].clone(),
            local_rib: true,
            advertised_to_peers: BTreeSet::from(["tor-a".to_owned()]),
        }];
        assert_eq!(
            verify_egress_bgp_readback(&config, &transaction, exact).unwrap(),
            desired
        );
    }
}
