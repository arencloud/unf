//! Transactional kernel `WireGuard` desired state and proof-carrying recovery.

use std::collections::BTreeSet;
use std::net::{IpAddr, SocketAddr};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use unf_common::Revision;
use unf_ipam::{Ipv4NodeBlock, Ipv6NodeBlock};

use crate::{IpPrefix, WireGuardPrivateKey, WireGuardPublicKey};

#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "linux")]
pub use linux::LinuxWireGuardProvider;

pub const WIREGUARD_KERNEL_PROVIDER_SCHEMA_VERSION: u16 = 3;
pub const WIREGUARD_KERNEL_SNAPSHOT_SCHEMA_VERSION: u16 = 3;
pub const PROOF_CARRYING_KERNEL_TRANSACTION_SCHEMA_VERSION: u16 = 1;
pub const MAX_WIREGUARD_PEERS: usize = 4_096;
pub const MAX_WIREGUARD_ALLOWED_IPS: usize = 65_536;
pub const MAX_UNDERLAY_MTU_OBSERVATIONS: usize = 65_536;
pub const WIREGUARD_IPV4_OVERHEAD: u32 = 60;
pub const WIREGUARD_IPV6_OVERHEAD: u32 = 80;
pub const MIN_WIREGUARD_MTU: u32 = 1_280;
pub const MAX_WIREGUARD_MTU: u32 = 9_216;
pub const UNF_WIREGUARD_ROUTE_PROTOCOL: u8 = 0x55;
pub const MAX_WIREGUARD_INTERFACE_NAME_BYTES: usize = 15;
pub const MAX_WIREGUARD_OWNER_ALIAS_BYTES: usize = 255;

const PLAN_DIGEST_DOMAIN: &[u8] = b"unf.wireguard-kernel-plan.v3\0";
const CONFIGURATION_DIGEST_DOMAIN: &[u8] = b"unf.wireguard-kernel-configuration.v3\0";
const OBSERVATION_DIGEST_DOMAIN: &[u8] = b"unf.wireguard-kernel-observation.v3\0";
const TRANSACTION_DIGEST_DOMAIN: &[u8] = b"unf.proof-carrying-kernel-transaction.v1\0";
const MAX_TEXT_BYTES: usize = 253;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum WireGuardKernelCapability {
    GenericNetlinkV1,
    ReplacePeersAtomically,
    ExactAllowedIpReadback,
    DualStackRoutes,
    LinkOwnershipAlias,
    InactiveEpochStaging,
    ExactProofBeaconAddresses,
    ExactIpv4ReversePathAcceptance,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct WireGuardProviderCapabilities {
    pub minimum_schema: u16,
    pub maximum_schema: u16,
    pub maximum_peers: u32,
    pub maximum_allowed_ips: u32,
    pub capabilities: BTreeSet<WireGuardKernelCapability>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct NegotiatedWireGuardProvider {
    pub schema_version: u16,
    pub maximum_peers: u32,
    pub maximum_allowed_ips: u32,
    pub capabilities: BTreeSet<WireGuardKernelCapability>,
}

impl WireGuardProviderCapabilities {
    #[must_use]
    pub fn current() -> Self {
        Self {
            minimum_schema: WIREGUARD_KERNEL_PROVIDER_SCHEMA_VERSION,
            maximum_schema: WIREGUARD_KERNEL_PROVIDER_SCHEMA_VERSION,
            maximum_peers: 4_096,
            maximum_allowed_ips: 65_536,
            capabilities: required_capabilities(),
        }
    }

    /// Negotiates the newest common schema without silently losing a required
    /// kernel capability.
    ///
    /// # Errors
    ///
    /// Rejects disjoint schema ranges, zero/oversized capacities, or missing
    /// required capabilities.
    pub fn negotiate(
        &self,
        remote: &Self,
    ) -> Result<NegotiatedWireGuardProvider, WireGuardKernelError> {
        self.validate()?;
        remote.validate()?;
        let minimum = self.minimum_schema.max(remote.minimum_schema);
        let maximum = self.maximum_schema.min(remote.maximum_schema);
        if minimum > maximum {
            return Err(WireGuardKernelError::IncompatibleProviderSchema);
        }
        let capabilities = self
            .capabilities
            .intersection(&remote.capabilities)
            .copied()
            .collect::<BTreeSet<_>>();
        let required = required_capabilities();
        if !required.is_subset(&capabilities) {
            return Err(WireGuardKernelError::MissingProviderCapability);
        }
        Ok(NegotiatedWireGuardProvider {
            schema_version: maximum,
            maximum_peers: self.maximum_peers.min(remote.maximum_peers),
            maximum_allowed_ips: self.maximum_allowed_ips.min(remote.maximum_allowed_ips),
            capabilities,
        })
    }

    fn validate(&self) -> Result<(), WireGuardKernelError> {
        if self.minimum_schema == 0
            || self.minimum_schema > self.maximum_schema
            || self.maximum_peers == 0
            || usize::try_from(self.maximum_peers)
                .map_or(true, |maximum| maximum > MAX_WIREGUARD_PEERS)
            || self.maximum_allowed_ips == 0
            || usize::try_from(self.maximum_allowed_ips)
                .map_or(true, |maximum| maximum > MAX_WIREGUARD_ALLOWED_IPS)
        {
            return Err(WireGuardKernelError::InvalidProviderCapabilities);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum UnderlayAddressFamily {
    Ipv4,
    Ipv6,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct UnderlayMtuObservation {
    pub peer_node_uid: String,
    pub family: UnderlayAddressFamily,
    pub underlay_mtu: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct WireGuardMtuEnvelope {
    pub interface_mtu: u32,
    pub limiting_peer_node_uid: String,
    pub limiting_family: UnderlayAddressFamily,
    pub limiting_underlay_mtu: u32,
    pub encapsulation_overhead: u32,
    pub observations: Vec<UnderlayMtuObservation>,
}

impl WireGuardMtuEnvelope {
    /// Derives the largest safe common MTU for one coalesced transport group.
    ///
    /// # Errors
    ///
    /// Rejects empty/oversized input, invalid Node identities, arithmetic
    /// underflow, or a result outside the IPv6-safe kernel boundary.
    pub fn derive(observations: &[UnderlayMtuObservation]) -> Result<Self, WireGuardKernelError> {
        if observations.is_empty() || observations.len() > MAX_UNDERLAY_MTU_OBSERVATIONS {
            return Err(WireGuardKernelError::InvalidMtuEnvelope);
        }
        let mut canonical = observations.to_vec();
        canonical.sort_by(|left, right| {
            (&left.peer_node_uid, left.family, left.underlay_mtu).cmp(&(
                &right.peer_node_uid,
                right.family,
                right.underlay_mtu,
            ))
        });
        if canonical.windows(2).any(|pair| {
            pair[0].peer_node_uid == pair[1].peer_node_uid && pair[0].family == pair[1].family
        }) || canonical
            .iter()
            .any(|observation| !validate_text(&observation.peer_node_uid))
        {
            return Err(WireGuardKernelError::InvalidMtuEnvelope);
        }
        let limiting = canonical
            .iter()
            .map(|observation| {
                let overhead = match observation.family {
                    UnderlayAddressFamily::Ipv4 => WIREGUARD_IPV4_OVERHEAD,
                    UnderlayAddressFamily::Ipv6 => WIREGUARD_IPV6_OVERHEAD,
                };
                let mtu = observation
                    .underlay_mtu
                    .checked_sub(overhead)
                    .ok_or(WireGuardKernelError::InvalidMtuEnvelope)?;
                Ok((mtu, observation, overhead))
            })
            .collect::<Result<Vec<_>, WireGuardKernelError>>()?
            .into_iter()
            .min_by_key(|(mtu, observation, _)| {
                (*mtu, &observation.peer_node_uid, observation.family)
            })
            .ok_or(WireGuardKernelError::InvalidMtuEnvelope)?;
        if !(MIN_WIREGUARD_MTU..=MAX_WIREGUARD_MTU).contains(&limiting.0) {
            return Err(WireGuardKernelError::InvalidMtuEnvelope);
        }
        let interface_mtu = limiting.0;
        let limiting_peer_node_uid = limiting.1.peer_node_uid.clone();
        let limiting_family = limiting.1.family;
        let limiting_underlay_mtu = limiting.1.underlay_mtu;
        let encapsulation_overhead = limiting.2;
        Ok(Self {
            interface_mtu,
            limiting_peer_node_uid,
            limiting_family,
            limiting_underlay_mtu,
            encapsulation_overhead,
            observations: canonical,
        })
    }

    fn verify(&self) -> Result<(), WireGuardKernelError> {
        if Self::derive(&self.observations)? != *self {
            return Err(WireGuardKernelError::InvalidMtuEnvelope);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum WireGuardEpochActivation {
    /// The device is operational in an isolated route table, but no fast-path
    /// epoch bank selects it for workload traffic.
    InactiveStaged,
    /// The separately committed fast-path epoch bank may select the device.
    Active,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct WireGuardPeerPlan {
    pub node_uid: String,
    pub public_key: WireGuardPublicKey,
    pub endpoint: SocketAddr,
    pub persistent_keepalive_seconds: u16,
    pub allowed_ips: Vec<IpPrefix>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct WireGuardKernelPlan {
    pub schema_version: u16,
    pub cluster_id: String,
    pub local_node_uid: String,
    pub epoch: u64,
    pub revision: Revision,
    pub interface_name: String,
    pub owner_alias: String,
    pub local_public_key: WireGuardPublicKey,
    pub listen_port: u16,
    pub fwmark: u32,
    pub route_table: u32,
    pub mtu_envelope: WireGuardMtuEnvelope,
    pub local_pod_cidrs: Vec<IpPrefix>,
    pub proof_addresses: Vec<IpPrefix>,
    pub activation: WireGuardEpochActivation,
    pub peers: Vec<WireGuardPeerPlan>,
    pub plan_digest: WireGuardKernelPlanDigest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireGuardKernelPlanInput {
    pub cluster_id: String,
    pub local_node_uid: String,
    pub epoch: u64,
    pub revision: Revision,
    pub interface_name: String,
    pub local_public_key: WireGuardPublicKey,
    pub listen_port: u16,
    pub fwmark: u32,
    pub route_table: u32,
    pub mtu_envelope: WireGuardMtuEnvelope,
    pub local_pod_cidrs: Vec<IpPrefix>,
    pub activation: WireGuardEpochActivation,
    pub peers: Vec<WireGuardPeerPlan>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct WireGuardKernelPlanDigest(pub [u8; 32]);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct WireGuardKernelConfigurationDigest(pub [u8; 32]);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct WireGuardKernelObservationDigest(pub [u8; 32]);

/// Derives one workload-IPAM-excluded host address per local Pod CIDR. These
/// addresses let a Node prove the encrypted route itself without depending on
/// the lifecycle, policy, or availability of any workload Pod.
///
/// # Errors
///
/// Rejects noncanonical, overlapping, or too-small Node blocks.
pub fn derive_wireguard_proof_addresses(
    pod_cidrs: &[IpPrefix],
) -> Result<Vec<IpPrefix>, WireGuardKernelError> {
    if pod_cidrs.is_empty() || pod_cidrs.len() > crate::MAX_ENCRYPTION_PREFIXES_PER_NODE {
        return Err(WireGuardKernelError::InvalidPlan);
    }
    let mut blocks = pod_cidrs.to_vec();
    blocks.sort_unstable();
    if blocks.iter().any(|prefix| !prefix.is_canonical())
        || blocks.windows(2).any(|pair| pair[0].overlaps(pair[1]))
    {
        return Err(WireGuardKernelError::InvalidPlan);
    }
    let mut addresses = blocks
        .into_iter()
        .map(|prefix| match prefix.address {
            IpAddr::V4(network) => Ipv4NodeBlock::new(network, prefix.prefix_len)
                .map(|block| IpPrefix {
                    address: IpAddr::V4(block.proof_beacon()),
                    prefix_len: 32,
                })
                .map_err(|_| WireGuardKernelError::InvalidPlan),
            IpAddr::V6(network) => Ipv6NodeBlock::new(network, prefix.prefix_len)
                .map(|block| IpPrefix {
                    address: IpAddr::V6(block.proof_beacon()),
                    prefix_len: 128,
                })
                .map_err(|_| WireGuardKernelError::InvalidPlan),
        })
        .collect::<Result<Vec<_>, _>>()?;
    addresses.sort_unstable();
    if addresses.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(WireGuardKernelError::InvalidPlan);
    }
    Ok(addresses)
}

impl WireGuardKernelPlan {
    /// Creates a canonical, bounded, exact kernel plan.
    ///
    /// # Errors
    ///
    /// Rejects malformed ownership, unsupported schema/capacity, duplicate or
    /// overlapping peers/prefixes, unsafe MTU, and noncanonical inputs.
    pub fn new(mut input: WireGuardKernelPlanInput) -> Result<Self, WireGuardKernelError> {
        input.local_pod_cidrs.sort_unstable();
        input.peers.sort_by(|left, right| {
            (&left.node_uid, left.public_key).cmp(&(&right.node_uid, right.public_key))
        });
        for peer in &mut input.peers {
            peer.allowed_ips.sort();
        }
        let owner_alias = format!(
            "unf:encryption:v2:{}:{}:{}",
            input.cluster_id, input.local_node_uid, input.epoch
        );
        let proof_addresses = derive_wireguard_proof_addresses(&input.local_pod_cidrs)?;
        let mut plan = Self {
            schema_version: WIREGUARD_KERNEL_PROVIDER_SCHEMA_VERSION,
            cluster_id: input.cluster_id,
            local_node_uid: input.local_node_uid,
            epoch: input.epoch,
            revision: input.revision,
            interface_name: input.interface_name,
            owner_alias,
            local_public_key: input.local_public_key,
            listen_port: input.listen_port,
            fwmark: input.fwmark,
            route_table: input.route_table,
            mtu_envelope: input.mtu_envelope,
            local_pod_cidrs: input.local_pod_cidrs,
            proof_addresses,
            activation: input.activation,
            peers: input.peers,
            plan_digest: WireGuardKernelPlanDigest([0; 32]),
        };
        plan.validate_shape()?;
        plan.plan_digest = plan.calculate_digest()?;
        Ok(plan)
    }

    /// Verifies canonical shape and the domain-separated plan digest.
    ///
    /// # Errors
    ///
    /// Rejects malformed, noncanonical, or digest-mismatched plans.
    pub fn verify(&self) -> Result<(), WireGuardKernelError> {
        self.validate_shape()?;
        if self.plan_digest != self.calculate_digest()? {
            return Err(WireGuardKernelError::PlanDigestMismatch);
        }
        Ok(())
    }

    #[must_use]
    pub fn route_prefixes(&self) -> BTreeSet<IpPrefix> {
        self.peers
            .iter()
            .flat_map(|peer| peer.allowed_ips.iter().copied())
            .collect()
    }

    pub(crate) fn verify_private_key(
        &self,
        private_key: &WireGuardPrivateKey,
    ) -> Result<(), WireGuardKernelError> {
        if private_key.public_key() != self.local_public_key {
            return Err(WireGuardKernelError::PrivateKeyMismatch);
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Result<WireGuardKernelPlanDigest, WireGuardKernelError> {
        let mut canonical = self.clone();
        canonical.plan_digest = WireGuardKernelPlanDigest([0; 32]);
        hash_canonical(PLAN_DIGEST_DOMAIN, &canonical).map(WireGuardKernelPlanDigest)
    }

    fn validate_shape(&self) -> Result<(), WireGuardKernelError> {
        self.mtu_envelope.verify()?;
        let proof_addresses_match = derive_wireguard_proof_addresses(&self.local_pod_cidrs)
            .is_ok_and(|derived| derived == self.proof_addresses);
        if self.schema_version != WIREGUARD_KERNEL_PROVIDER_SCHEMA_VERSION {
            return Err(WireGuardKernelError::UnsupportedProviderSchema(
                self.schema_version,
            ));
        }
        if !validate_text(&self.cluster_id)
            || !validate_text(&self.local_node_uid)
            || self.epoch == 0
            || self.revision == Revision::INITIAL
            || !valid_interface_name(&self.interface_name)
            || self.owner_alias
                != format!(
                    "unf:encryption:v2:{}:{}:{}",
                    self.cluster_id, self.local_node_uid, self.epoch
                )
            || self.owner_alias.len() > MAX_WIREGUARD_OWNER_ALIAS_BYTES
            || self.local_public_key.0 == [0; 32]
            || self.listen_port == 0
            || self.fwmark == 0
            || self.route_table == 0
            || !proof_addresses_match
            || self.proof_addresses.is_empty()
            || self.proof_addresses.len() > crate::MAX_ENCRYPTION_PREFIXES_PER_NODE
            || self
                .proof_addresses
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
            || self.proof_addresses.iter().any(|prefix| {
                !prefix.is_canonical()
                    || match prefix.address {
                        IpAddr::V4(_) => prefix.prefix_len != 32,
                        IpAddr::V6(_) => prefix.prefix_len != 128,
                    }
            })
            || self.peers.is_empty()
            || self.peers.len() > MAX_WIREGUARD_PEERS
        {
            return Err(WireGuardKernelError::InvalidPlan);
        }
        let mut peer_uids = BTreeSet::new();
        let mut peer_keys = BTreeSet::new();
        let mut prefixes = Vec::new();
        let mut total_prefixes = 0_usize;
        let mut prior: Option<(&str, WireGuardPublicKey)> = None;
        for peer in &self.peers {
            if !validate_text(&peer.node_uid)
                || peer.node_uid == self.local_node_uid
                || peer.public_key.0 == [0; 32]
                || peer.public_key == self.local_public_key
                || !valid_endpoint(peer.endpoint)
                || peer.persistent_keepalive_seconds > 600
                || peer.allowed_ips.is_empty()
                || !peer_uids.insert(peer.node_uid.as_str())
                || !peer_keys.insert(peer.public_key)
                || prior.is_some_and(|previous| previous >= (&peer.node_uid, peer.public_key))
                || peer.allowed_ips.windows(2).any(|pair| pair[0] >= pair[1])
            {
                return Err(WireGuardKernelError::InvalidPlan);
            }
            prior = Some((&peer.node_uid, peer.public_key));
            let endpoint_family = match peer.endpoint {
                SocketAddr::V4(_) => UnderlayAddressFamily::Ipv4,
                SocketAddr::V6(_) => UnderlayAddressFamily::Ipv6,
            };
            if !self.mtu_envelope.observations.iter().any(|observation| {
                observation.peer_node_uid == peer.node_uid && observation.family == endpoint_family
            }) {
                return Err(WireGuardKernelError::InvalidMtuEnvelope);
            }
            for prefix in &peer.allowed_ips {
                if !prefix.is_canonical() {
                    return Err(WireGuardKernelError::InvalidPlan);
                }
                prefixes.push(*prefix);
                total_prefixes = total_prefixes
                    .checked_add(1)
                    .ok_or(WireGuardKernelError::CapacityExceeded)?;
                if total_prefixes > MAX_WIREGUARD_ALLOWED_IPS {
                    return Err(WireGuardKernelError::CapacityExceeded);
                }
            }
        }
        let mtu_peer_uids = self
            .mtu_envelope
            .observations
            .iter()
            .map(|observation| observation.peer_node_uid.as_str())
            .collect::<BTreeSet<_>>();
        if mtu_peer_uids != peer_uids {
            return Err(WireGuardKernelError::InvalidMtuEnvelope);
        }
        prefixes.sort_unstable();
        if prefixes.windows(2).any(|pair| pair[0].overlaps(pair[1])) {
            return Err(WireGuardKernelError::AmbiguousAllowedIp);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct WireGuardPeerReadback {
    pub public_key: WireGuardPublicKey,
    pub endpoint: SocketAddr,
    pub persistent_keepalive_seconds: u16,
    pub allowed_ips: Vec<IpPrefix>,
    pub last_handshake_unix_seconds: i64,
    pub received_bytes: u64,
    pub transmitted_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct WireGuardRouteReadback {
    pub prefix: IpPrefix,
    pub interface_index: u32,
    pub table: u32,
    pub protocol: u8,
    pub scope: WireGuardRouteScope,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum WireGuardRouteScope {
    Link,
    Universe,
}

impl WireGuardRouteScope {
    #[must_use]
    pub fn for_prefix(prefix: IpPrefix) -> Self {
        match prefix.address {
            std::net::IpAddr::V4(_) => Self::Link,
            std::net::IpAddr::V6(_) => Self::Universe,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct WireGuardKernelSnapshot {
    pub schema_version: u16,
    pub interface_name: String,
    pub interface_index: u32,
    pub owner_alias: String,
    pub is_up: bool,
    pub mtu: u32,
    pub public_key: WireGuardPublicKey,
    pub listen_port: u16,
    pub fwmark: u32,
    pub proof_addresses: Vec<IpPrefix>,
    pub peers: Vec<WireGuardPeerReadback>,
    pub routes: Vec<WireGuardRouteReadback>,
    pub configuration_digest: WireGuardKernelConfigurationDigest,
    pub observation_digest: WireGuardKernelObservationDigest,
}

pub(crate) struct WireGuardKernelSnapshotInput {
    pub interface_name: String,
    pub interface_index: u32,
    pub owner_alias: String,
    pub is_up: bool,
    pub mtu: u32,
    pub public_key: WireGuardPublicKey,
    pub listen_port: u16,
    pub fwmark: u32,
    pub proof_addresses: Vec<IpPrefix>,
    pub peers: Vec<WireGuardPeerReadback>,
    pub routes: Vec<WireGuardRouteReadback>,
}

impl WireGuardKernelSnapshot {
    pub(crate) fn issue(
        mut input: WireGuardKernelSnapshotInput,
    ) -> Result<Self, WireGuardKernelError> {
        input.proof_addresses.sort_unstable();
        input.peers.sort_by_key(|peer| peer.public_key);
        for peer in &mut input.peers {
            peer.allowed_ips.sort();
        }
        input.routes.sort_by_key(|route| route.prefix);
        let mut snapshot = Self {
            schema_version: WIREGUARD_KERNEL_SNAPSHOT_SCHEMA_VERSION,
            interface_name: input.interface_name,
            interface_index: input.interface_index,
            owner_alias: input.owner_alias,
            is_up: input.is_up,
            mtu: input.mtu,
            public_key: input.public_key,
            listen_port: input.listen_port,
            fwmark: input.fwmark,
            proof_addresses: input.proof_addresses,
            peers: input.peers,
            routes: input.routes,
            configuration_digest: WireGuardKernelConfigurationDigest([0; 32]),
            observation_digest: WireGuardKernelObservationDigest([0; 32]),
        };
        snapshot.configuration_digest = snapshot.calculate_configuration_digest()?;
        snapshot.observation_digest = snapshot.calculate_observation_digest()?;
        Ok(snapshot)
    }

    /// Verifies the canonical self-contained readback envelope without
    /// trusting its stored digests. Exact desired-state comparison remains in
    /// [`Self::verify_against`].
    ///
    /// # Errors
    ///
    /// Rejects malformed, reordered, duplicate, or digest-mutated readback.
    pub fn verify_integrity(&self) -> Result<(), WireGuardKernelError> {
        if self.schema_version != WIREGUARD_KERNEL_SNAPSHOT_SCHEMA_VERSION
            || !valid_interface_name(&self.interface_name)
            || self.interface_index == 0
            || self.owner_alias.is_empty()
            || self.owner_alias.len() > MAX_WIREGUARD_OWNER_ALIAS_BYTES
            || !self.owner_alias.starts_with("unf:encryption:v2:")
            || self.proof_addresses.is_empty()
            || self.proof_addresses.len() > crate::MAX_ENCRYPTION_PREFIXES_PER_NODE
            || self
                .proof_addresses
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
            || self.proof_addresses.iter().any(|prefix| {
                !prefix.is_canonical()
                    || match prefix.address {
                        IpAddr::V4(_) => prefix.prefix_len != 32,
                        IpAddr::V6(_) => prefix.prefix_len != 128,
                    }
            })
            || !self.is_up
            || !(MIN_WIREGUARD_MTU..=MAX_WIREGUARD_MTU).contains(&self.mtu)
            || self.public_key.0 == [0; 32]
            || self.listen_port == 0
            || self.fwmark == 0
            || self.peers.is_empty()
            || self.peers.len() > MAX_WIREGUARD_PEERS
            || self.routes.is_empty()
            || self.routes.len() > MAX_WIREGUARD_ALLOWED_IPS
            || self
                .peers
                .windows(2)
                .any(|pair| pair[0].public_key >= pair[1].public_key)
            || self
                .routes
                .windows(2)
                .any(|pair| pair[0].prefix >= pair[1].prefix)
            || self.configuration_digest != self.calculate_configuration_digest()?
            || self.observation_digest != self.calculate_observation_digest()?
        {
            return Err(WireGuardKernelError::ReadbackMismatch);
        }
        let mut allowed_ips = BTreeSet::new();
        for peer in &self.peers {
            if peer.public_key.0 == [0; 32]
                || !valid_endpoint(peer.endpoint)
                || peer.persistent_keepalive_seconds > 600
                || peer.allowed_ips.is_empty()
                || peer.allowed_ips.windows(2).any(|pair| pair[0] >= pair[1])
                || peer
                    .allowed_ips
                    .iter()
                    .any(|prefix| !prefix.is_canonical() || !allowed_ips.insert(*prefix))
            {
                return Err(WireGuardKernelError::ReadbackMismatch);
            }
        }
        if self.routes.iter().any(|route| {
            !route.prefix.is_canonical()
                || route.interface_index != self.interface_index
                || route.table == 0
                || route.protocol != UNF_WIREGUARD_ROUTE_PROTOCOL
                || route.scope != WireGuardRouteScope::for_prefix(route.prefix)
                || !allowed_ips.contains(&route.prefix)
        }) {
            return Err(WireGuardKernelError::ReadbackMismatch);
        }
        Ok(())
    }

    /// Verifies exact desired configuration while deliberately excluding
    /// counters and handshake time from the stable configuration digest.
    ///
    /// # Errors
    ///
    /// Rejects ownership, link, key, peer, endpoint, `AllowedIP`, route, MTU,
    /// activation, or digest drift.
    pub fn verify_against(&self, plan: &WireGuardKernelPlan) -> Result<(), WireGuardKernelError> {
        plan.verify()?;
        self.verify_integrity()?;
        if self.schema_version != WIREGUARD_KERNEL_SNAPSHOT_SCHEMA_VERSION
            || self.interface_name != plan.interface_name
            || self.interface_index == 0
            || self.owner_alias != plan.owner_alias
            || !self.is_up
            || self.mtu != plan.mtu_envelope.interface_mtu
            || self.public_key != plan.local_public_key
            || self.listen_port != plan.listen_port
            || self.fwmark != plan.fwmark
            || self.proof_addresses != plan.proof_addresses
            || self.configuration_digest != self.calculate_configuration_digest()?
            || self.observation_digest != self.calculate_observation_digest()?
        {
            return Err(WireGuardKernelError::ReadbackMismatch);
        }
        let expected_peers = plan
            .peers
            .iter()
            .map(|peer| {
                (
                    peer.public_key,
                    peer.endpoint,
                    peer.persistent_keepalive_seconds,
                    peer.allowed_ips.clone(),
                )
            })
            .collect::<Vec<_>>();
        let observed_peers = self
            .peers
            .iter()
            .map(|peer| {
                (
                    peer.public_key,
                    peer.endpoint,
                    peer.persistent_keepalive_seconds,
                    peer.allowed_ips.clone(),
                )
            })
            .collect::<Vec<_>>();
        if expected_peers != observed_peers {
            return Err(WireGuardKernelError::ReadbackMismatch);
        }
        let expected_routes = plan.route_prefixes();
        if self.routes.len() != expected_routes.len()
            || self.routes.iter().any(|route| {
                !expected_routes.contains(&route.prefix)
                    || route.interface_index != self.interface_index
                    || route.table != plan.route_table
                    || route.protocol != UNF_WIREGUARD_ROUTE_PROTOCOL
                    || route.scope != WireGuardRouteScope::for_prefix(route.prefix)
            })
        {
            return Err(WireGuardKernelError::ReadbackMismatch);
        }
        Ok(())
    }

    fn calculate_configuration_digest(
        &self,
    ) -> Result<WireGuardKernelConfigurationDigest, WireGuardKernelError> {
        let peers = self
            .peers
            .iter()
            .map(|peer| {
                (
                    peer.public_key,
                    peer.endpoint,
                    peer.persistent_keepalive_seconds,
                    &peer.allowed_ips,
                )
            })
            .collect::<Vec<_>>();
        let stable = (
            self.schema_version,
            &self.interface_name,
            self.interface_index,
            &self.owner_alias,
            self.is_up,
            self.mtu,
            self.public_key,
            self.listen_port,
            self.fwmark,
            &self.proof_addresses,
            peers,
            &self.routes,
        );
        hash_canonical(CONFIGURATION_DIGEST_DOMAIN, &stable).map(WireGuardKernelConfigurationDigest)
    }

    fn calculate_observation_digest(
        &self,
    ) -> Result<WireGuardKernelObservationDigest, WireGuardKernelError> {
        let stable = (
            self.configuration_digest,
            self.peers
                .iter()
                .map(|peer| {
                    (
                        peer.public_key,
                        peer.last_handshake_unix_seconds,
                        peer.received_bytes,
                        peer.transmitted_bytes,
                    )
                })
                .collect::<Vec<_>>(),
        );
        hash_canonical(OBSERVATION_DIGEST_DOMAIN, &stable).map(WireGuardKernelObservationDigest)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum KernelTransactionPhase {
    Prepared,
    Committed,
    RolledBack,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ProofCarryingKernelTransaction {
    pub schema_version: u16,
    pub transaction_revision: Revision,
    pub plan: WireGuardKernelPlan,
    pub before_configuration_digest: Option<WireGuardKernelConfigurationDigest>,
    pub phase: KernelTransactionPhase,
    pub readback_configuration_digest: Option<WireGuardKernelConfigurationDigest>,
    pub transaction_digest: ProofCarryingKernelTransactionDigest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ProofCarryingKernelTransactionDigest(pub [u8; 32]);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KernelRecoveryAction {
    ApplyDesired,
    CommitObservedDesired,
    RollbackComplete,
    RefuseUnknownState,
}

impl ProofCarryingKernelTransaction {
    /// Begins a secret-free transaction bound to before and desired digests.
    ///
    /// # Errors
    ///
    /// Rejects invalid revision/plan, or before-state ownership that does not
    /// exactly match the desired plan.
    pub fn begin(
        transaction_revision: Revision,
        plan: WireGuardKernelPlan,
        before: Option<&WireGuardKernelSnapshot>,
    ) -> Result<Self, WireGuardKernelError> {
        plan.verify()?;
        if transaction_revision == Revision::INITIAL {
            return Err(WireGuardKernelError::InvalidTransaction);
        }
        if let Some(snapshot) = before {
            snapshot.verify_against(&plan)?;
        }
        let mut transaction = Self {
            schema_version: PROOF_CARRYING_KERNEL_TRANSACTION_SCHEMA_VERSION,
            transaction_revision,
            plan,
            before_configuration_digest: before.map(|value| value.configuration_digest),
            phase: KernelTransactionPhase::Prepared,
            readback_configuration_digest: None,
            transaction_digest: ProofCarryingKernelTransactionDigest([0; 32]),
        };
        transaction.transaction_digest = transaction.calculate_digest()?;
        Ok(transaction)
    }

    /// Commits only an independently verified exact readback.
    ///
    /// # Errors
    ///
    /// Rejects wrong phase, plan/readback mismatch, or corrupt transaction.
    pub fn commit(
        &mut self,
        readback: &WireGuardKernelSnapshot,
    ) -> Result<(), WireGuardKernelError> {
        self.verify()?;
        if self.phase != KernelTransactionPhase::Prepared {
            return Err(WireGuardKernelError::InvalidTransaction);
        }
        readback.verify_against(&self.plan)?;
        self.phase = KernelTransactionPhase::Committed;
        self.readback_configuration_digest = Some(readback.configuration_digest);
        self.transaction_digest = self.calculate_digest()?;
        Ok(())
    }

    /// Marks exact cleanup after a failed fresh-stage transaction.
    ///
    /// # Errors
    ///
    /// Rejects a non-prepared/corrupt transaction or a still-present interface.
    pub fn record_rollback(&mut self, observed_absent: bool) -> Result<(), WireGuardKernelError> {
        self.verify()?;
        if self.phase != KernelTransactionPhase::Prepared || !observed_absent {
            return Err(WireGuardKernelError::InvalidTransaction);
        }
        self.phase = KernelTransactionPhase::RolledBack;
        self.transaction_digest = self.calculate_digest()?;
        Ok(())
    }

    /// Chooses a deterministic restart action without mutating the kernel.
    ///
    /// # Errors
    ///
    /// Rejects a corrupt checkpoint or observed snapshot.
    pub fn recover(
        &self,
        observed: Option<&WireGuardKernelSnapshot>,
    ) -> Result<KernelRecoveryAction, WireGuardKernelError> {
        self.verify()?;
        match (self.phase, observed) {
            (KernelTransactionPhase::Prepared, None) => Ok(KernelRecoveryAction::ApplyDesired),
            (KernelTransactionPhase::Prepared, Some(snapshot)) => {
                if snapshot.verify_against(&self.plan).is_ok() {
                    Ok(KernelRecoveryAction::CommitObservedDesired)
                } else {
                    Ok(KernelRecoveryAction::RefuseUnknownState)
                }
            }
            (KernelTransactionPhase::Committed, Some(snapshot)) => {
                if snapshot.verify_against(&self.plan).is_ok()
                    && self.readback_configuration_digest == Some(snapshot.configuration_digest)
                {
                    Ok(KernelRecoveryAction::CommitObservedDesired)
                } else {
                    Ok(KernelRecoveryAction::RefuseUnknownState)
                }
            }
            (KernelTransactionPhase::RolledBack, None) => {
                Ok(KernelRecoveryAction::RollbackComplete)
            }
            _ => Ok(KernelRecoveryAction::RefuseUnknownState),
        }
    }

    /// Verifies schema, phase invariants, nested plan, and digest.
    ///
    /// # Errors
    ///
    /// Rejects malformed or digest-mismatched transactions.
    pub fn verify(&self) -> Result<(), WireGuardKernelError> {
        self.plan.verify()?;
        if self.schema_version != PROOF_CARRYING_KERNEL_TRANSACTION_SCHEMA_VERSION
            || self.transaction_revision == Revision::INITIAL
            || (self.phase == KernelTransactionPhase::Committed)
                != self.readback_configuration_digest.is_some()
            || self.transaction_digest != self.calculate_digest()?
        {
            return Err(WireGuardKernelError::InvalidTransaction);
        }
        Ok(())
    }

    fn calculate_digest(
        &self,
    ) -> Result<ProofCarryingKernelTransactionDigest, WireGuardKernelError> {
        let mut canonical = self.clone();
        canonical.transaction_digest = ProofCarryingKernelTransactionDigest([0; 32]);
        hash_canonical(TRANSACTION_DIGEST_DOMAIN, &canonical)
            .map(ProofCarryingKernelTransactionDigest)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KernelApplyOutcome {
    Created,
    AlreadyExact,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KernelDeleteOutcome {
    Deleted,
    AlreadyAbsent,
}

#[derive(Debug, Error)]
pub enum WireGuardKernelError {
    #[error("invalid WireGuard provider capabilities")]
    InvalidProviderCapabilities,
    #[error("WireGuard provider schema ranges do not overlap")]
    IncompatibleProviderSchema,
    #[error("required WireGuard provider capability is missing")]
    MissingProviderCapability,
    #[error("invalid bounded underlay MTU envelope")]
    InvalidMtuEnvelope,
    #[error("unsupported WireGuard kernel provider schema {0}")]
    UnsupportedProviderSchema(u16),
    #[error("invalid or noncanonical WireGuard kernel plan")]
    InvalidPlan,
    #[error("WireGuard plan exceeds a bounded capacity")]
    CapacityExceeded,
    #[error("WireGuard AllowedIPs overlap or have ambiguous ownership")]
    AmbiguousAllowedIp,
    #[error("WireGuard kernel-plan digest does not match")]
    PlanDigestMismatch,
    #[error("Node-local private key does not match the planned public key")]
    PrivateKeyMismatch,
    #[error("WireGuard kernel readback differs from the exact plan")]
    ReadbackMismatch,
    #[error("WireGuard interface or route key contains foreign state: {0}")]
    ForeignState(String),
    #[error("WireGuard kernel state is absent")]
    Absent,
    #[error("invalid proof-carrying kernel transaction")]
    InvalidTransaction,
    #[error("WireGuard kernel operation {operation} failed: {message}")]
    Kernel {
        operation: &'static str,
        message: String,
    },
    #[error("WireGuard apply failed ({cause}); rollback also failed ({rollback})")]
    Rollback { cause: String, rollback: String },
    #[error("canonical WireGuard encoding failed: {0}")]
    CanonicalEncoding(String),
}

fn required_capabilities() -> BTreeSet<WireGuardKernelCapability> {
    BTreeSet::from([
        WireGuardKernelCapability::GenericNetlinkV1,
        WireGuardKernelCapability::ReplacePeersAtomically,
        WireGuardKernelCapability::ExactAllowedIpReadback,
        WireGuardKernelCapability::DualStackRoutes,
        WireGuardKernelCapability::LinkOwnershipAlias,
        WireGuardKernelCapability::InactiveEpochStaging,
        WireGuardKernelCapability::ExactProofBeaconAddresses,
        WireGuardKernelCapability::ExactIpv4ReversePathAcceptance,
    ])
}

fn validate_text(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_TEXT_BYTES && !value.chars().any(char::is_control)
}

fn valid_interface_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_WIREGUARD_INTERFACE_NAME_BYTES
        && value.starts_with("unfwg")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

fn valid_endpoint(value: SocketAddr) -> bool {
    if value.port() == 0 || value.ip().is_unspecified() || value.ip().is_multicast() {
        return false;
    }
    match value.ip() {
        std::net::IpAddr::V4(address) => address.octets() != [u8::MAX; 4],
        std::net::IpAddr::V6(_) => true,
    }
}

fn hash_canonical<T: Serialize>(
    domain: &[u8],
    value: &T,
) -> Result<[u8; 32], WireGuardKernelError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| WireGuardKernelError::CanonicalEncoding(error.to_string()))?;
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(bytes);
    Ok(hasher.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{OsWireGuardKeyGenerator, WireGuardKeyGenerator};

    fn mtu() -> WireGuardMtuEnvelope {
        WireGuardMtuEnvelope::derive(&[
            UnderlayMtuObservation {
                peer_node_uid: "node-b".to_owned(),
                family: UnderlayAddressFamily::Ipv4,
                underlay_mtu: 1_500,
            },
            UnderlayMtuObservation {
                peer_node_uid: "node-b".to_owned(),
                family: UnderlayAddressFamily::Ipv6,
                underlay_mtu: 1_500,
            },
        ])
        .unwrap()
    }

    fn plan() -> (WireGuardKernelPlan, WireGuardPrivateKey) {
        let mut generator = OsWireGuardKeyGenerator;
        let private = generator.generate().unwrap();
        let local_public_key = private.public_key();
        let plan = WireGuardKernelPlan::new(WireGuardKernelPlanInput {
            cluster_id: "cluster-a".to_owned(),
            local_node_uid: "node-a".to_owned(),
            epoch: 7,
            revision: Revision::new(9),
            interface_name: "unfwg000000007".to_owned(),
            local_public_key,
            listen_port: 51_820,
            fwmark: 0x554e_0007,
            route_table: 20_007,
            mtu_envelope: mtu(),
            local_pod_cidrs: vec![
                IpPrefix {
                    address: "10.244.1.0".parse().unwrap(),
                    prefix_len: 24,
                },
                IpPrefix {
                    address: "fd00:244:1::".parse().unwrap(),
                    prefix_len: 64,
                },
            ],
            activation: WireGuardEpochActivation::InactiveStaged,
            peers: vec![WireGuardPeerPlan {
                node_uid: "node-b".to_owned(),
                public_key: WireGuardPublicKey([8; 32]),
                endpoint: "192.0.2.20:51820".parse().unwrap(),
                persistent_keepalive_seconds: 25,
                allowed_ips: vec![
                    IpPrefix {
                        address: "10.244.2.0".parse().unwrap(),
                        prefix_len: 24,
                    },
                    IpPrefix {
                        address: "fd00:244:2::".parse().unwrap(),
                        prefix_len: 64,
                    },
                ],
            }],
        })
        .unwrap();
        (plan, private)
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
            proof_addresses: plan.proof_addresses.clone(),
            peers: plan
                .peers
                .iter()
                .map(|peer| WireGuardPeerReadback {
                    public_key: peer.public_key,
                    endpoint: peer.endpoint,
                    persistent_keepalive_seconds: peer.persistent_keepalive_seconds,
                    allowed_ips: peer.allowed_ips.clone(),
                    last_handshake_unix_seconds: 50,
                    received_bytes: 100,
                    transmitted_bytes: 200,
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
    fn mtu_envelope_is_dual_stack_safe_and_names_its_limiter() {
        let envelope = WireGuardMtuEnvelope::derive(&[
            UnderlayMtuObservation {
                peer_node_uid: "node-c".to_owned(),
                family: UnderlayAddressFamily::Ipv4,
                underlay_mtu: 9_000,
            },
            UnderlayMtuObservation {
                peer_node_uid: "node-b".to_owned(),
                family: UnderlayAddressFamily::Ipv6,
                underlay_mtu: 1_500,
            },
        ])
        .unwrap();
        assert_eq!(envelope.interface_mtu, 1_420);
        assert_eq!(envelope.limiting_peer_node_uid, "node-b");
        assert_eq!(envelope.encapsulation_overhead, WIREGUARD_IPV6_OVERHEAD);
    }

    #[test]
    fn mtu_envelope_rejects_duplicates_underflow_and_ipv6_unsafe_results() {
        let duplicate = UnderlayMtuObservation {
            peer_node_uid: "node-b".to_owned(),
            family: UnderlayAddressFamily::Ipv6,
            underlay_mtu: 1_500,
        };
        assert!(WireGuardMtuEnvelope::derive(&[duplicate.clone(), duplicate]).is_err());
        assert!(
            WireGuardMtuEnvelope::derive(&[UnderlayMtuObservation {
                peer_node_uid: "node-b".to_owned(),
                family: UnderlayAddressFamily::Ipv6,
                underlay_mtu: 1_300,
            }])
            .is_err()
        );
        let (mut malformed, _) = plan();
        malformed.mtu_envelope.encapsulation_overhead = WIREGUARD_IPV4_OVERHEAD;
        assert!(matches!(
            malformed.verify(),
            Err(WireGuardKernelError::InvalidMtuEnvelope)
        ));
        let (mut plan, _) = plan();
        plan.mtu_envelope = WireGuardMtuEnvelope::derive(&[UnderlayMtuObservation {
            peer_node_uid: "node-b".to_owned(),
            family: UnderlayAddressFamily::Ipv6,
            underlay_mtu: 1_500,
        }])
        .unwrap();
        plan.plan_digest = plan.calculate_digest().unwrap();
        assert!(matches!(
            plan.verify(),
            Err(WireGuardKernelError::InvalidMtuEnvelope)
        ));
    }

    #[test]
    fn plan_is_canonical_bounded_disjoint_and_secret_separate() {
        let (plan, private) = plan();
        plan.verify().unwrap();
        plan.verify_private_key(&private).unwrap();
        let json = serde_json::to_string(&plan).unwrap();
        assert!(!json.contains("private"));
        assert_eq!(plan.route_prefixes().len(), 2);
        assert_eq!(
            plan.proof_addresses,
            vec![
                IpPrefix {
                    address: "10.244.1.254".parse().unwrap(),
                    prefix_len: 32,
                },
                IpPrefix {
                    address: "fd00:244:1::".parse().unwrap(),
                    prefix_len: 128,
                },
            ]
        );
        let mut wrong_generator = OsWireGuardKeyGenerator;
        let wrong = wrong_generator.generate().unwrap();
        assert!(matches!(
            plan.verify_private_key(&wrong),
            Err(WireGuardKernelError::PrivateKeyMismatch)
        ));
    }

    #[test]
    fn overlapping_allowed_ips_and_duplicate_peer_authority_fail_closed() {
        let (plan, _) = plan();
        let mut input = WireGuardKernelPlanInput {
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
            local_pod_cidrs: plan.local_pod_cidrs.clone(),
            activation: plan.activation,
            peers: plan.peers.clone(),
        };
        let mut second = input.peers[0].clone();
        second.node_uid = "node-c".to_owned();
        second.public_key = WireGuardPublicKey([9; 32]);
        second.allowed_ips[0] = IpPrefix {
            address: "10.244.2.0".parse().unwrap(),
            prefix_len: 25,
        };
        input.peers.push(second);
        let mut observations = input.mtu_envelope.observations.clone();
        observations.extend([
            UnderlayMtuObservation {
                peer_node_uid: "node-c".to_owned(),
                family: UnderlayAddressFamily::Ipv4,
                underlay_mtu: 1_500,
            },
            UnderlayMtuObservation {
                peer_node_uid: "node-c".to_owned(),
                family: UnderlayAddressFamily::Ipv6,
                underlay_mtu: 1_500,
            },
        ]);
        input.mtu_envelope = WireGuardMtuEnvelope::derive(&observations).unwrap();
        assert!(matches!(
            WireGuardKernelPlan::new(input),
            Err(WireGuardKernelError::AmbiguousAllowedIp)
        ));
    }

    #[test]
    fn readback_has_stable_config_and_lossless_observation_digests() {
        let (plan, _) = plan();
        let mut first = snapshot(&plan);
        first.verify_against(&plan).unwrap();
        let config = first.configuration_digest;
        let observation = first.observation_digest;
        first.peers[0].received_bytes += 1;
        first.configuration_digest = first.calculate_configuration_digest().unwrap();
        first.observation_digest = first.calculate_observation_digest().unwrap();
        assert_eq!(first.configuration_digest, config);
        assert_ne!(first.observation_digest, observation);
        first.verify_against(&plan).unwrap();
    }

    #[test]
    fn any_configuration_mutation_breaks_exact_readback() {
        let (plan, _) = plan();
        let mut observed = snapshot(&plan);
        observed.peers[0].endpoint.set_port(51_821);
        observed.configuration_digest = observed.calculate_configuration_digest().unwrap();
        observed.observation_digest = observed.calculate_observation_digest().unwrap();
        assert!(matches!(
            observed.verify_against(&plan),
            Err(WireGuardKernelError::ReadbackMismatch)
        ));

        let mut observed = snapshot(&plan);
        observed.proof_addresses[0].address = "10.244.1.253".parse().unwrap();
        observed.configuration_digest = observed.calculate_configuration_digest().unwrap();
        observed.observation_digest = observed.calculate_observation_digest().unwrap();
        assert!(matches!(
            observed.verify_against(&plan),
            Err(WireGuardKernelError::ReadbackMismatch)
        ));
    }

    #[test]
    fn proof_beacons_are_derived_only_from_ipam_excluded_node_boundaries() {
        assert_eq!(
            derive_wireguard_proof_addresses(&[
                IpPrefix {
                    address: "10.42.7.0".parse().unwrap(),
                    prefix_len: 24,
                },
                IpPrefix {
                    address: "fd42:7::".parse().unwrap(),
                    prefix_len: 64,
                },
            ])
            .unwrap(),
            vec![
                IpPrefix {
                    address: "10.42.7.254".parse().unwrap(),
                    prefix_len: 32,
                },
                IpPrefix {
                    address: "fd42:7::".parse().unwrap(),
                    prefix_len: 128,
                },
            ]
        );
        assert!(
            derive_wireguard_proof_addresses(&[IpPrefix {
                address: "10.42.7.0".parse().unwrap(),
                prefix_len: 31,
            }])
            .is_err()
        );
    }

    #[test]
    fn proof_carrying_transaction_recovery_is_total_and_fail_closed() {
        let (plan, _) = plan();
        let desired = snapshot(&plan);
        let mut transaction =
            ProofCarryingKernelTransaction::begin(Revision::new(1), plan.clone(), None).unwrap();
        let encoded = serde_json::to_string(&transaction).unwrap();
        assert!(!encoded.contains("private"));
        serde_json::from_str::<ProofCarryingKernelTransaction>(&encoded)
            .unwrap()
            .verify()
            .unwrap();
        let mut unknown: serde_json::Value = serde_json::from_str(&encoded).unwrap();
        unknown["unknownAuthority"] = serde_json::json!(true);
        assert!(serde_json::from_value::<ProofCarryingKernelTransaction>(unknown).is_err());
        assert_eq!(
            transaction.recover(None).unwrap(),
            KernelRecoveryAction::ApplyDesired
        );
        assert_eq!(
            transaction.recover(Some(&desired)).unwrap(),
            KernelRecoveryAction::CommitObservedDesired
        );
        let mut foreign = desired.clone();
        foreign.owner_alias.push_str("-foreign");
        foreign.configuration_digest = foreign.calculate_configuration_digest().unwrap();
        foreign.observation_digest = foreign.calculate_observation_digest().unwrap();
        assert_eq!(
            transaction.recover(Some(&foreign)).unwrap(),
            KernelRecoveryAction::RefuseUnknownState
        );
        transaction.commit(&desired).unwrap();
        assert_eq!(
            transaction.recover(Some(&desired)).unwrap(),
            KernelRecoveryAction::CommitObservedDesired
        );
        let mut mutated = transaction.clone();
        mutated.plan.route_table += 1;
        assert!(mutated.verify().is_err());
    }

    #[test]
    fn rollback_requires_positive_absence() {
        let (plan, _) = plan();
        let mut transaction =
            ProofCarryingKernelTransaction::begin(Revision::new(1), plan, None).unwrap();
        assert!(transaction.record_rollback(false).is_err());
        transaction.record_rollback(true).unwrap();
        assert_eq!(
            transaction.recover(None).unwrap(),
            KernelRecoveryAction::RollbackComplete
        );
    }

    #[test]
    fn capability_negotiation_selects_overlap_and_never_drops_requirements() {
        let local = WireGuardProviderCapabilities::current();
        let mut adjacent = local.clone();
        adjacent.minimum_schema = 2;
        adjacent.maximum_peers = 2_048;
        let negotiated = local.negotiate(&adjacent).unwrap();
        assert_eq!(
            negotiated.schema_version,
            WIREGUARD_KERNEL_PROVIDER_SCHEMA_VERSION
        );
        assert_eq!(negotiated.maximum_peers, 2_048);
        adjacent
            .capabilities
            .remove(&WireGuardKernelCapability::ExactAllowedIpReadback);
        assert!(matches!(
            local.negotiate(&adjacent),
            Err(WireGuardKernelError::MissingProviderCapability)
        ));
    }
}
