use std::collections::BTreeSet;
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Bounds deterministic allocation work and retained leases for one node.
pub const MAX_NODE_LEASES: usize = 65_536;
pub const NODE_BLOCK_SNAPSHOT_SCHEMA_VERSION: u16 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AddressFamily {
    Ipv4,
    Ipv6,
}

impl fmt::Display for AddressFamily {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ipv4 => formatter.write_str("IPv4"),
            Self::Ipv6 => formatter.write_str("IPv6"),
        }
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum IpamError {
    #[error("invalid {family} node block {value:?}: {reason}")]
    InvalidBlock {
        family: AddressFamily,
        value: String,
        reason: String,
    },
    #[error("{family} node block is exhausted within the {limit}-lease node bound")]
    Exhausted { family: AddressFamily, limit: usize },
    #[error("restored leases contain duplicate {family} address {address}")]
    DuplicateLease {
        family: AddressFamily,
        address: String,
    },
    #[error("cannot release an unknown or incomplete dual-stack lease")]
    MissingLease,
    #[error("lease does not belong to this node-block provider: {0}")]
    ForeignLease(String),
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Ipv4Lease {
    pub address: Ipv4Addr,
    pub gateway: Ipv4Addr,
    pub prefix_len: u8,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Ipv6Lease {
    pub address: Ipv6Addr,
    pub gateway: Ipv6Addr,
    pub prefix_len: u8,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct DualStackLease {
    pub ipv4: Ipv4Lease,
    pub ipv6: Ipv6Lease,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ipv4NodeBlock {
    network: Ipv4Addr,
    prefix_len: u8,
}

impl Ipv4NodeBlock {
    /// Creates a canonical node block with space for network, gateway, Pod, and
    /// broadcast addresses.
    ///
    /// # Errors
    ///
    /// Returns an error for a prefix longer than /30 or a non-network address.
    pub fn new(network: Ipv4Addr, prefix_len: u8) -> Result<Self, IpamError> {
        if prefix_len > 30 {
            return Err(invalid_block(
                AddressFamily::Ipv4,
                format!("{network}/{prefix_len}"),
                "prefix must be between /0 and /30",
            ));
        }
        let mask = prefix_mask_v4(prefix_len);
        if u32::from(network) & mask != u32::from(network) {
            return Err(invalid_block(
                AddressFamily::Ipv4,
                format!("{network}/{prefix_len}"),
                "address is not the canonical network boundary",
            ));
        }
        Ok(Self {
            network,
            prefix_len,
        })
    }

    #[must_use]
    pub const fn network(self) -> Ipv4Addr {
        self.network
    }

    #[must_use]
    pub const fn prefix_len(self) -> u8 {
        self.prefix_len
    }

    #[must_use]
    pub fn gateway(self) -> Ipv4Addr {
        Ipv4Addr::from(u32::from(self.network) + 1)
    }

    #[must_use]
    pub fn bounded_capacity(self) -> usize {
        let addresses = 1_u64 << (32 - self.prefix_len);
        usize::try_from((addresses - 3).min(MAX_NODE_LEASES as u64)).unwrap_or(MAX_NODE_LEASES)
    }

    #[must_use]
    pub fn overlaps(self, other: Self) -> bool {
        let prefix = self.prefix_len.min(other.prefix_len);
        let mask = prefix_mask_v4(prefix);
        u32::from(self.network) & mask == u32::from(other.network) & mask
    }

    fn candidate(self, index: usize) -> Ipv4Addr {
        let offset = u32::try_from(index).expect("bounded index fits u32") + 2;
        Ipv4Addr::from(u32::from(self.network) + offset)
    }

    fn contains_workload(self, address: Ipv4Addr) -> bool {
        let value = u32::from(address);
        let network = u32::from(self.network);
        let total = 1_u64 << (32 - self.prefix_len);
        let offset = u64::from(value.saturating_sub(network));
        value >= network && offset >= 2 && offset < total - 1
    }
}

impl fmt::Display for Ipv4NodeBlock {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}/{}", self.network, self.prefix_len)
    }
}

impl FromStr for Ipv4NodeBlock {
    type Err = IpamError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (address, prefix) = split_cidr(value, AddressFamily::Ipv4)?;
        let address = address.parse::<Ipv4Addr>().map_err(|error| {
            invalid_block(
                AddressFamily::Ipv4,
                value,
                format!("invalid address: {error}"),
            )
        })?;
        let prefix = parse_prefix(prefix, value, AddressFamily::Ipv4)?;
        Self::new(address, prefix)
    }
}

impl Serialize for Ipv4NodeBlock {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Ipv4NodeBlock {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ipv6NodeBlock {
    network: Ipv6Addr,
    prefix_len: u8,
}

impl Ipv6NodeBlock {
    /// Creates a canonical node block with space for a gateway and Pod address.
    ///
    /// # Errors
    ///
    /// Returns an error for a prefix longer than /126 or a non-network address.
    pub fn new(network: Ipv6Addr, prefix_len: u8) -> Result<Self, IpamError> {
        if prefix_len > 126 {
            return Err(invalid_block(
                AddressFamily::Ipv6,
                format!("{network}/{prefix_len}"),
                "prefix must be between /0 and /126",
            ));
        }
        let mask = prefix_mask_v6(prefix_len);
        if u128::from(network) & mask != u128::from(network) {
            return Err(invalid_block(
                AddressFamily::Ipv6,
                format!("{network}/{prefix_len}"),
                "address is not the canonical network boundary",
            ));
        }
        Ok(Self {
            network,
            prefix_len,
        })
    }

    #[must_use]
    pub const fn network(self) -> Ipv6Addr {
        self.network
    }

    #[must_use]
    pub const fn prefix_len(self) -> u8 {
        self.prefix_len
    }

    #[must_use]
    pub fn gateway(self) -> Ipv6Addr {
        Ipv6Addr::from(u128::from(self.network) + 1)
    }

    #[must_use]
    pub fn bounded_capacity(self) -> usize {
        if self.prefix_len <= 111 {
            return MAX_NODE_LEASES;
        }
        let addresses = 1_u32 << (128 - self.prefix_len);
        usize::try_from(addresses - 2).unwrap_or(MAX_NODE_LEASES)
    }

    #[must_use]
    pub fn overlaps(self, other: Self) -> bool {
        let prefix = self.prefix_len.min(other.prefix_len);
        let mask = prefix_mask_v6(prefix);
        u128::from(self.network) & mask == u128::from(other.network) & mask
    }

    fn candidate(self, index: usize) -> Ipv6Addr {
        let offset = u128::try_from(index).expect("bounded index fits u128") + 2;
        Ipv6Addr::from(u128::from(self.network) + offset)
    }

    fn contains_workload(self, address: Ipv6Addr) -> bool {
        let value = u128::from(address);
        let network = u128::from(self.network);
        value >= network
            && value & prefix_mask_v6(self.prefix_len) == network
            && value.saturating_sub(network) >= 2
    }
}

impl fmt::Display for Ipv6NodeBlock {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}/{}", self.network, self.prefix_len)
    }
}

impl FromStr for Ipv6NodeBlock {
    type Err = IpamError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (address, prefix) = split_cidr(value, AddressFamily::Ipv6)?;
        let address = address.parse::<Ipv6Addr>().map_err(|error| {
            invalid_block(
                AddressFamily::Ipv6,
                value,
                format!("invalid address: {error}"),
            )
        })?;
        let prefix = parse_prefix(prefix, value, AddressFamily::Ipv6)?;
        Self::new(address, prefix)
    }
}

impl Serialize for Ipv6NodeBlock {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Ipv6NodeBlock {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct UsedAddresses {
    leases: BTreeSet<DualStackLease>,
    ipv4: BTreeSet<Ipv4Addr>,
    ipv6: BTreeSet<Ipv6Addr>,
}

impl UsedAddresses {
    /// Reconstructs collision-checked usage from durable leases.
    ///
    /// # Errors
    ///
    /// Returns an error when either address family contains a duplicate.
    pub fn from_leases(
        leases: impl IntoIterator<Item = DualStackLease>,
    ) -> Result<Self, IpamError> {
        let mut used = Self::default();
        for lease in leases {
            used.insert(lease)?;
        }
        Ok(used)
    }

    /// Adds one dual-stack lease atomically.
    ///
    /// # Errors
    ///
    /// Returns an error without mutation if either family is already present.
    pub fn insert(&mut self, lease: DualStackLease) -> Result<(), IpamError> {
        if self.ipv4.contains(&lease.ipv4.address) {
            return Err(IpamError::DuplicateLease {
                family: AddressFamily::Ipv4,
                address: lease.ipv4.address.to_string(),
            });
        }
        if self.ipv6.contains(&lease.ipv6.address) {
            return Err(IpamError::DuplicateLease {
                family: AddressFamily::Ipv6,
                address: lease.ipv6.address.to_string(),
            });
        }
        self.ipv4.insert(lease.ipv4.address);
        self.ipv6.insert(lease.ipv6.address);
        self.leases.insert(lease);
        Ok(())
    }

    /// Releases both families or leaves the snapshot unchanged.
    ///
    /// # Errors
    ///
    /// Returns an error when either family is not currently retained.
    pub fn remove(&mut self, lease: &DualStackLease) -> Result<(), IpamError> {
        if !self.leases.contains(lease) {
            return Err(IpamError::MissingLease);
        }
        self.ipv4.remove(&lease.ipv4.address);
        self.ipv6.remove(&lease.ipv6.address);
        self.leases.remove(lease);
        Ok(())
    }

    #[must_use]
    pub fn len(&self) -> usize {
        debug_assert_eq!(self.leases.len(), self.ipv4.len());
        debug_assert_eq!(self.leases.len(), self.ipv6.len());
        self.leases.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.leases.is_empty() && self.ipv4.is_empty() && self.ipv6.is_empty()
    }
}

pub trait IpamProvider {
    /// Selects one complete lease without mutating the supplied usage snapshot.
    ///
    /// # Errors
    ///
    /// Returns an error when either address family is exhausted.
    fn allocate(&self, used: &UsedAddresses) -> Result<DualStackLease, IpamError>;

    /// Confirms that a restored lease belongs to this provider's exact blocks.
    ///
    /// # Errors
    ///
    /// Returns an error for addresses, prefixes, or gateways outside the blocks.
    fn validate(&self, lease: &DualStackLease) -> Result<(), IpamError>;
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct NodeBlockProvider {
    pub ipv4_block: Ipv4NodeBlock,
    pub ipv6_block: Ipv6NodeBlock,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct NodeBlockSnapshot {
    pub schema_version: u16,
    pub revision: u64,
    pub node_name: String,
    pub node_uid: String,
    pub provider: NodeBlockProvider,
}

impl NodeBlockProvider {
    #[must_use]
    pub const fn new(ipv4_block: Ipv4NodeBlock, ipv6_block: Ipv6NodeBlock) -> Self {
        Self {
            ipv4_block,
            ipv6_block,
        }
    }
}

impl IpamProvider for NodeBlockProvider {
    fn allocate(&self, used: &UsedAddresses) -> Result<DualStackLease, IpamError> {
        if used.len() >= MAX_NODE_LEASES {
            return Err(IpamError::Exhausted {
                family: AddressFamily::Ipv4,
                limit: MAX_NODE_LEASES,
            });
        }
        let ipv4 = (0..self.ipv4_block.bounded_capacity())
            .map(|index| self.ipv4_block.candidate(index))
            .find(|candidate| !used.ipv4.contains(candidate))
            .ok_or(IpamError::Exhausted {
                family: AddressFamily::Ipv4,
                limit: self.ipv4_block.bounded_capacity(),
            })?;
        let ipv6 = (0..self.ipv6_block.bounded_capacity())
            .map(|index| self.ipv6_block.candidate(index))
            .find(|candidate| !used.ipv6.contains(candidate))
            .ok_or(IpamError::Exhausted {
                family: AddressFamily::Ipv6,
                limit: self.ipv6_block.bounded_capacity(),
            })?;
        Ok(DualStackLease {
            ipv4: Ipv4Lease {
                address: ipv4,
                gateway: self.ipv4_block.gateway(),
                prefix_len: self.ipv4_block.prefix_len(),
            },
            ipv6: Ipv6Lease {
                address: ipv6,
                gateway: self.ipv6_block.gateway(),
                prefix_len: self.ipv6_block.prefix_len(),
            },
        })
    }

    fn validate(&self, lease: &DualStackLease) -> Result<(), IpamError> {
        let valid = lease.ipv4.prefix_len == self.ipv4_block.prefix_len()
            && lease.ipv4.gateway == self.ipv4_block.gateway()
            && self.ipv4_block.contains_workload(lease.ipv4.address)
            && lease.ipv6.prefix_len == self.ipv6_block.prefix_len()
            && lease.ipv6.gateway == self.ipv6_block.gateway()
            && self.ipv6_block.contains_workload(lease.ipv6.address);
        if valid {
            Ok(())
        } else {
            Err(IpamError::ForeignLease(format!(
                "{} and {} do not match blocks {} and {}",
                lease.ipv4.address, lease.ipv6.address, self.ipv4_block, self.ipv6_block
            )))
        }
    }
}

const fn prefix_mask_v4(prefix_len: u8) -> u32 {
    if prefix_len == 0 {
        0
    } else {
        u32::MAX << (32 - prefix_len)
    }
}

const fn prefix_mask_v6(prefix_len: u8) -> u128 {
    if prefix_len == 0 {
        0
    } else {
        u128::MAX << (128 - prefix_len)
    }
}

fn split_cidr(value: &str, family: AddressFamily) -> Result<(&str, &str), IpamError> {
    let Some((address, prefix)) = value.split_once('/') else {
        return Err(invalid_block(family, value, "CIDR must contain one slash"));
    };
    if address.is_empty() || prefix.is_empty() || prefix.contains('/') {
        return Err(invalid_block(
            family,
            value,
            "CIDR must contain exactly one address and prefix",
        ));
    }
    Ok((address, prefix))
}

fn parse_prefix(prefix: &str, value: &str, family: AddressFamily) -> Result<u8, IpamError> {
    prefix
        .parse::<u8>()
        .map_err(|error| invalid_block(family, value, format!("invalid prefix: {error}")))
}

fn invalid_block(
    family: AddressFamily,
    value: impl Into<String>,
    reason: impl Into<String>,
) -> IpamError {
    IpamError::InvalidBlock {
        family,
        value: value.into(),
        reason: reason.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn provider(ipv4: &str, ipv6: &str) -> NodeBlockProvider {
        NodeBlockProvider::new(
            ipv4.parse().expect("valid IPv4 block"),
            ipv6.parse().expect("valid IPv6 block"),
        )
    }

    #[test]
    fn blocks_require_canonical_usable_dual_stack_cidrs() {
        assert!("10.42.0.0/24".parse::<Ipv4NodeBlock>().is_ok());
        assert!("fd00:42::/64".parse::<Ipv6NodeBlock>().is_ok());
        for invalid in ["10.42.0.1/24", "10.42.0.0/31", "10.42.0.0", "bad/24"] {
            assert!(invalid.parse::<Ipv4NodeBlock>().is_err(), "{invalid}");
        }
        for invalid in ["fd00:42::1/64", "fd00:42::/127", "fd00:42::", "bad/64"] {
            assert!(invalid.parse::<Ipv6NodeBlock>().is_err(), "{invalid}");
        }
    }

    #[test]
    fn block_overlap_and_snapshot_wire_shape_are_exact() {
        let ipv4: Ipv4NodeBlock = "10.42.0.0/24".parse().unwrap();
        assert!(ipv4.overlaps("10.42.0.128/25".parse().unwrap()));
        assert!(!ipv4.overlaps("10.42.1.0/24".parse().unwrap()));
        let ipv6: Ipv6NodeBlock = "fd00:42::/64".parse().unwrap();
        assert!(ipv6.overlaps("fd00:42::/80".parse().unwrap()));
        assert!(!ipv6.overlaps("fd00:43::/64".parse().unwrap()));

        let snapshot = NodeBlockSnapshot {
            schema_version: NODE_BLOCK_SNAPSHOT_SCHEMA_VERSION,
            revision: 7,
            node_name: "worker-a".to_owned(),
            node_uid: "worker-a-uid".to_owned(),
            provider: provider("10.42.0.0/24", "fd00:42::/64"),
        };
        let encoded = serde_json::to_value(&snapshot).unwrap();
        assert_eq!(encoded["schemaVersion"], 1);
        assert_eq!(encoded["provider"]["ipv4Block"], "10.42.0.0/24");
        assert_eq!(
            serde_json::from_value::<NodeBlockSnapshot>(encoded).unwrap(),
            snapshot
        );
    }

    #[test]
    fn allocation_is_lowest_free_dual_stack_and_reserves_boundaries() {
        let provider = provider("10.42.0.0/29", "fd00:42::/125");
        let mut used = UsedAddresses::default();
        let first = provider.allocate(&used).expect("first lease");
        assert_eq!(first.ipv4.address, Ipv4Addr::new(10, 42, 0, 2));
        assert_eq!(first.ipv4.gateway, Ipv4Addr::new(10, 42, 0, 1));
        assert_eq!(first.ipv4.prefix_len, 29);
        assert_eq!(
            first.ipv6.address,
            "fd00:42::2".parse::<Ipv6Addr>().unwrap()
        );
        assert_eq!(
            first.ipv6.gateway,
            "fd00:42::1".parse::<Ipv6Addr>().unwrap()
        );
        assert_eq!(first.ipv6.prefix_len, 125);
        used.insert(first).expect("record first lease");

        let second = provider.allocate(&used).expect("second lease");
        assert_eq!(second.ipv4.address, Ipv4Addr::new(10, 42, 0, 3));
        assert_eq!(
            second.ipv6.address,
            "fd00:42::3".parse::<Ipv6Addr>().unwrap()
        );
        provider.validate(&second).expect("lease belongs to blocks");
    }

    #[test]
    fn either_family_exhaustion_fails_without_partial_usage_mutation() {
        let ipv4_limited = provider("10.42.0.0/30", "fd00:42::/125");
        let mut used = UsedAddresses::default();
        let first = ipv4_limited.allocate(&used).expect("only IPv4 lease");
        used.insert(first).expect("record lease");
        let before = used.clone();
        assert_eq!(
            ipv4_limited.allocate(&used),
            Err(IpamError::Exhausted {
                family: AddressFamily::Ipv4,
                limit: 1
            })
        );
        assert_eq!(used, before);

        let ipv6_limited = provider("10.42.1.0/29", "fd00:43::/126");
        let mut used = UsedAddresses::default();
        for _ in 0..2 {
            let lease = ipv6_limited
                .allocate(&used)
                .expect("available dual-stack lease");
            used.insert(lease).expect("record lease");
        }
        assert_eq!(
            ipv6_limited.allocate(&used),
            Err(IpamError::Exhausted {
                family: AddressFamily::Ipv6,
                limit: 2
            })
        );
    }

    #[test]
    fn collision_checked_restore_release_and_reuse_are_deterministic() {
        let provider = provider("10.42.0.0/29", "fd00:42::/125");
        let first = provider
            .allocate(&UsedAddresses::default())
            .expect("first lease");
        assert!(matches!(
            UsedAddresses::from_leases([first, first]),
            Err(IpamError::DuplicateLease { .. })
        ));
        let mut restored = UsedAddresses::from_leases([first]).expect("restore leases");
        let second = provider.allocate(&restored).expect("second lease");
        restored.remove(&first).expect("release complete lease");
        assert_eq!(provider.allocate(&restored).expect("reused lease"), first);
        assert_eq!(restored.len(), 0);
        assert_eq!(restored.remove(&first), Err(IpamError::MissingLease));
        restored.insert(second).expect("state remains usable");

        let both = UsedAddresses::from_leases([first, second]).expect("restore both leases");
        let mut crossed = both.clone();
        let crossed_lease = DualStackLease {
            ipv4: first.ipv4,
            ipv6: second.ipv6,
        };
        assert_eq!(crossed.remove(&crossed_lease), Err(IpamError::MissingLease));
        assert_eq!(crossed, both);
    }

    #[test]
    fn provider_validation_rejects_foreign_or_modified_leases() {
        let provider = provider("10.42.0.0/24", "fd00:42::/64");
        let lease = provider.allocate(&UsedAddresses::default()).expect("lease");
        provider.validate(&lease).expect("own lease");

        let mut foreign = lease;
        foreign.ipv4.address = Ipv4Addr::new(10, 43, 0, 2);
        assert!(matches!(
            provider.validate(&foreign),
            Err(IpamError::ForeignLease(_))
        ));
        let mut changed_gateway = lease;
        changed_gateway.ipv6.gateway = "fd00:42::ffff".parse().unwrap();
        assert!(provider.validate(&changed_gateway).is_err());
    }

    #[test]
    fn large_blocks_remain_bounded_and_small_blocks_report_exact_capacity() {
        let all_ipv4 = "0.0.0.0/0".parse::<Ipv4NodeBlock>().expect("IPv4 /0");
        let all_ipv6 = "::/0".parse::<Ipv6NodeBlock>().expect("IPv6 /0");
        assert_eq!(all_ipv4.bounded_capacity(), MAX_NODE_LEASES);
        assert_eq!(all_ipv6.bounded_capacity(), MAX_NODE_LEASES);
        assert_eq!(
            "10.0.0.0/30"
                .parse::<Ipv4NodeBlock>()
                .unwrap()
                .bounded_capacity(),
            1
        );
        assert_eq!(
            "fd00::/126"
                .parse::<Ipv6NodeBlock>()
                .unwrap()
                .bounded_capacity(),
            2
        );
    }

    #[test]
    fn provider_and_lease_wire_shapes_are_stable_and_strict() {
        let provider = provider("10.42.0.0/24", "fd00:42::/64");
        let encoded = serde_json::to_value(provider).expect("encode provider");
        assert_eq!(encoded["ipv4Block"], "10.42.0.0/24");
        assert_eq!(encoded["ipv6Block"], "fd00:42::/64");
        assert_eq!(
            serde_json::from_value::<NodeBlockProvider>(encoded).expect("decode provider"),
            provider
        );

        let lease = provider.allocate(&UsedAddresses::default()).expect("lease");
        let encoded = serde_json::to_value(lease).expect("encode lease");
        assert_eq!(encoded["ipv4"]["address"], "10.42.0.2");
        assert_eq!(encoded["ipv6"]["address"], "fd00:42::2");
        let mut object = encoded.as_object().expect("lease object").clone();
        object.insert("unknown".to_owned(), serde_json::Value::Bool(true));
        assert!(serde_json::from_value::<DualStackLease>(object.into()).is_err());
    }

    #[test]
    fn provider_trait_keeps_allocation_independent_from_routing() {
        fn allocate(provider: &impl IpamProvider) -> DualStackLease {
            provider
                .allocate(&UsedAddresses::default())
                .expect("generic provider allocation")
        }

        let lease = allocate(&provider("192.0.2.0/29", "2001:db8::/125"));
        assert_eq!(lease.ipv4.address, Ipv4Addr::new(192, 0, 2, 2));
        assert_eq!(
            lease.ipv6.address,
            "2001:db8::2".parse::<Ipv6Addr>().unwrap()
        );
    }
}
