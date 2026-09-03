//! Durable conflict-safe egress address allocation.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use unf_common::Revision;

use crate::{
    AddressFamily, EgressAddressPool, EgressAddressRequest, EgressIntent, EgressIntentOwner,
    EgressProviderRef, MAX_EGRESS_ADDRESSES_PER_INTENT, MAX_EGRESS_INTENTS, normalize_intent,
    normalize_pools,
};

pub const EGRESS_ALLOCATION_CHECKPOINT_SCHEMA_VERSION: u16 = 1;
pub const MAX_EGRESS_POOL_ALLOCATION_SCAN: usize = 1_048_576;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EgressAllocationRequest {
    pub intent: EgressIntent,
    pub explicit_provider: Option<EgressProviderRef>,
    pub intent_epoch: u64,
    pub intent_revision: Revision,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EgressAllocatedPool {
    pub name: String,
    pub uid: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EgressAddressLease {
    pub intent: EgressIntent,
    pub pool: Option<EgressAllocatedPool>,
    pub provider: EgressProviderRef,
    pub addresses: Vec<IpAddr>,
    pub lease_epoch: u64,
    pub intent_epoch: u64,
    pub intent_revision: Revision,
    pub allocation_revision: Revision,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EgressAllocationCheckpoint {
    pub schema_version: u16,
    pub revision: Revision,
    pub last_lease_epoch: u64,
    pub pools: Vec<EgressAddressPool>,
    pub leases: Vec<EgressAddressLease>,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum EgressAllocationError {
    #[error("unsupported egress allocation schema {actual}; expected {expected}")]
    UnsupportedSchema { actual: u16, expected: u16 },
    #[error("invalid egress allocation model: {0}")]
    InvalidModel(String),
    #[error("allocation request revisions must be nonzero")]
    ZeroIntentRevision,
    #[error("egress allocation has {actual} leases; limit is {limit}")]
    TooManyLeases { actual: usize, limit: usize },
    #[error("egress allocation request for {0:?} has invalid provider ownership")]
    InvalidProvider(EgressIntentOwner),
    #[error("egress allocation request refers to unknown pool {0:?}")]
    UnknownPool(String),
    #[error("egress allocation request for {owner:?} changed immutable address intent")]
    ImmutableIntentChanged { owner: EgressIntentOwner },
    #[error("egress allocation intent tuple regressed for {owner:?}")]
    IntentRevisionRegression { owner: EgressIntentOwner },
    #[error("egress allocation intent mutated at the same tuple for {owner:?}")]
    IntentRevisionMutation { owner: EgressIntentOwner },
    #[error("egress address {address} is already owned by {owner:?}")]
    AddressConflict {
        address: IpAddr,
        owner: EgressIntentOwner,
    },
    #[error("egress pool {pool:?} is exhausted for {family:?} within scan limit {limit}")]
    Exhausted {
        pool: String,
        family: AddressFamily,
        limit: usize,
    },
    #[error("egress allocation checkpoint contains a foreign or malformed lease for {0:?}")]
    ForeignLease(EgressIntentOwner),
    #[error("cannot release unknown egress owner {0:?}")]
    UnknownOwner(EgressIntentOwner),
    #[error("egress allocation revision or lease epoch is exhausted")]
    CounterExhausted,
}

#[derive(Debug, Clone)]
pub struct EgressAllocator {
    pools: BTreeMap<String, EgressAddressPool>,
    leases: BTreeMap<EgressIntentOwner, EgressAddressLease>,
    address_owners: BTreeMap<IpAddr, EgressIntentOwner>,
    revision: Revision,
    last_lease_epoch: u64,
}

impl EgressAllocator {
    /// Creates an empty allocator for one canonical, non-overlapping pool set.
    ///
    /// # Errors
    ///
    /// Rejects invalid or overlapping pools before exposing allocator state.
    pub fn new(pools: Vec<EgressAddressPool>) -> Result<Self, EgressAllocationError> {
        let pools = normalize_pools(pools)
            .map_err(|error| EgressAllocationError::InvalidModel(error.to_string()))?
            .into_iter()
            .map(|pool| (pool.name.clone(), pool))
            .collect();
        Ok(Self {
            pools,
            leases: BTreeMap::new(),
            address_owners: BTreeMap::new(),
            revision: Revision::INITIAL,
            last_lease_epoch: 0,
        })
    }

    /// Restores a complete durable checkpoint only after validating all state.
    ///
    /// # Errors
    ///
    /// Rejects schema, revision, pool, provider, address, epoch, ordering, and
    /// collision drift without returning partially restored state.
    pub fn restore(checkpoint: EgressAllocationCheckpoint) -> Result<Self, EgressAllocationError> {
        if checkpoint.schema_version != EGRESS_ALLOCATION_CHECKPOINT_SCHEMA_VERSION {
            return Err(EgressAllocationError::UnsupportedSchema {
                actual: checkpoint.schema_version,
                expected: EGRESS_ALLOCATION_CHECKPOINT_SCHEMA_VERSION,
            });
        }
        if checkpoint.leases.len() > MAX_EGRESS_INTENTS {
            return Err(EgressAllocationError::TooManyLeases {
                actual: checkpoint.leases.len(),
                limit: MAX_EGRESS_INTENTS,
            });
        }
        if !checkpoint.leases.is_empty()
            && (checkpoint.revision == Revision::INITIAL || checkpoint.last_lease_epoch == 0)
        {
            return Err(EgressAllocationError::ForeignLease(
                checkpoint.leases[0].intent.owner.clone(),
            ));
        }
        let original_leases = checkpoint.leases.clone();
        let mut allocator = Self::new(checkpoint.pools)?;
        allocator.revision = checkpoint.revision;
        allocator.last_lease_epoch = checkpoint.last_lease_epoch;
        for lease in checkpoint.leases {
            allocator.restore_lease(lease)?;
        }
        if allocator.leases.values().cloned().collect::<Vec<_>>() != original_leases {
            let owner = original_leases
                .first()
                .map_or_else(invalid_owner, |lease| lease.intent.owner.clone());
            return Err(EgressAllocationError::ForeignLease(owner));
        }
        Ok(allocator)
    }

    /// Allocates or idempotently refreshes one intent without partial mutation.
    ///
    /// # Errors
    ///
    /// Rejects malformed provenance, immutable-intent changes, tuple regression,
    /// address conflict, exhaustion, or counter wrap.
    pub fn allocate(
        &mut self,
        request: EgressAllocationRequest,
    ) -> Result<EgressAddressLease, EgressAllocationError> {
        let request = validate_request(request)?;
        let owner = request.intent.owner.clone();
        let provider = self.provider_for(&request)?;
        if let Some(existing) = self.leases.get(&owner) {
            if existing.intent.addresses != request.intent.addresses
                || existing.provider != provider
            {
                return Err(EgressAllocationError::ImmutableIntentChanged { owner });
            }
            if request.intent_epoch < existing.intent_epoch
                || (request.intent_epoch == existing.intent_epoch
                    && request.intent_revision < existing.intent_revision)
            {
                return Err(EgressAllocationError::IntentRevisionRegression { owner });
            }
            if request.intent_epoch == existing.intent_epoch
                && request.intent_revision == existing.intent_revision
            {
                if request.intent == existing.intent {
                    return Ok(existing.clone());
                }
                return Err(EgressAllocationError::IntentRevisionMutation { owner });
            }
            let revision = checked_next_revision(self.revision)?;
            let mut refreshed = existing.clone();
            refreshed.intent = request.intent;
            refreshed.intent_epoch = request.intent_epoch;
            refreshed.intent_revision = request.intent_revision;
            refreshed.allocation_revision = revision;
            self.leases.insert(owner, refreshed.clone());
            self.revision = revision;
            return Ok(refreshed);
        }
        if self.leases.len() == MAX_EGRESS_INTENTS {
            return Err(EgressAllocationError::TooManyLeases {
                actual: self.leases.len() + 1,
                limit: MAX_EGRESS_INTENTS,
            });
        }
        let (pool, addresses) = self.plan_addresses(&request)?;
        let revision = checked_next_revision(self.revision)?;
        let lease_epoch = self
            .last_lease_epoch
            .checked_add(1)
            .ok_or(EgressAllocationError::CounterExhausted)?;
        let lease = EgressAddressLease {
            intent: request.intent,
            pool,
            provider,
            addresses,
            lease_epoch,
            intent_epoch: request.intent_epoch,
            intent_revision: request.intent_revision,
            allocation_revision: revision,
        };
        for address in &lease.addresses {
            self.address_owners.insert(*address, owner.clone());
        }
        self.leases.insert(owner, lease.clone());
        self.revision = revision;
        self.last_lease_epoch = lease_epoch;
        Ok(lease)
    }

    /// Releases an exact owner and advances the durable allocation revision.
    ///
    /// # Errors
    ///
    /// Rejects unknown ownership or revision exhaustion without mutation.
    pub fn release(
        &mut self,
        owner: &EgressIntentOwner,
    ) -> Result<EgressAddressLease, EgressAllocationError> {
        let revision = checked_next_revision(self.revision)?;
        let lease = self
            .leases
            .get(owner)
            .cloned()
            .ok_or_else(|| EgressAllocationError::UnknownOwner(owner.clone()))?;
        self.leases.remove(owner);
        for address in &lease.addresses {
            self.address_owners.remove(address);
        }
        self.revision = revision;
        Ok(lease)
    }

    #[must_use]
    pub fn lease(&self, owner: &EgressIntentOwner) -> Option<&EgressAddressLease> {
        self.leases.get(owner)
    }

    #[must_use]
    pub fn checkpoint(&self) -> EgressAllocationCheckpoint {
        EgressAllocationCheckpoint {
            schema_version: EGRESS_ALLOCATION_CHECKPOINT_SCHEMA_VERSION,
            revision: self.revision,
            last_lease_epoch: self.last_lease_epoch,
            pools: self.pools.values().cloned().collect(),
            leases: self.leases.values().cloned().collect(),
        }
    }

    fn provider_for(
        &self,
        request: &EgressAllocationRequest,
    ) -> Result<EgressProviderRef, EgressAllocationError> {
        match &request.intent.addresses {
            EgressAddressRequest::Pool { name, .. } => {
                if request.explicit_provider.is_some() {
                    return Err(EgressAllocationError::InvalidProvider(
                        request.intent.owner.clone(),
                    ));
                }
                self.pools
                    .get(name)
                    .map(|pool| pool.provider.clone())
                    .ok_or_else(|| EgressAllocationError::UnknownPool(name.clone()))
            }
            EgressAddressRequest::Explicit { .. } => request
                .explicit_provider
                .clone()
                .filter(valid_provider)
                .ok_or_else(|| {
                    EgressAllocationError::InvalidProvider(request.intent.owner.clone())
                }),
        }
    }

    fn plan_addresses(
        &self,
        request: &EgressAllocationRequest,
    ) -> Result<(Option<EgressAllocatedPool>, Vec<IpAddr>), EgressAllocationError> {
        match &request.intent.addresses {
            EgressAddressRequest::Explicit { addresses } => {
                for address in addresses {
                    if let Some(owner) = self.address_owners.get(address) {
                        return Err(EgressAllocationError::AddressConflict {
                            address: *address,
                            owner: owner.clone(),
                        });
                    }
                }
                Ok((None, addresses.clone()))
            }
            EgressAddressRequest::Pool {
                name,
                families,
                addresses_per_family,
            } => {
                let pool = self
                    .pools
                    .get(name)
                    .ok_or_else(|| EgressAllocationError::UnknownPool(name.clone()))?;
                let mut reserved = self.address_owners.keys().copied().collect::<BTreeSet<_>>();
                let mut addresses = Vec::new();
                for family in families {
                    for _ in 0..*addresses_per_family {
                        let address = allocate_from_pool(pool, *family, &reserved)?;
                        reserved.insert(address);
                        addresses.push(address);
                    }
                }
                addresses.sort_unstable();
                Ok((
                    Some(EgressAllocatedPool {
                        name: pool.name.clone(),
                        uid: pool.uid.clone(),
                    }),
                    addresses,
                ))
            }
        }
    }

    fn restore_lease(&mut self, lease: EgressAddressLease) -> Result<(), EgressAllocationError> {
        let owner = lease.intent.owner.clone();
        let normalized = normalize_intent(lease.intent.clone())
            .map_err(|_| EgressAllocationError::ForeignLease(owner.clone()))?;
        if normalized != lease.intent
            || self.leases.contains_key(&owner)
            || lease.intent_epoch == 0
            || lease.intent_revision == Revision::INITIAL
            || lease.allocation_revision == Revision::INITIAL
            || lease.allocation_revision > self.revision
            || lease.lease_epoch == 0
            || lease.lease_epoch > self.last_lease_epoch
            || lease.addresses.is_empty()
            || lease.addresses.len() > MAX_EGRESS_ADDRESSES_PER_INTENT * 2
            || lease.addresses.windows(2).any(|pair| pair[0] >= pair[1])
            || !valid_provider(&lease.provider)
            || !self.lease_matches_request(&lease)
        {
            return Err(EgressAllocationError::ForeignLease(owner));
        }
        for address in &lease.addresses {
            if let Some(existing) = self.address_owners.insert(*address, owner.clone()) {
                return Err(EgressAllocationError::AddressConflict {
                    address: *address,
                    owner: existing,
                });
            }
        }
        self.leases.insert(owner, lease);
        Ok(())
    }

    fn lease_matches_request(&self, lease: &EgressAddressLease) -> bool {
        match &lease.intent.addresses {
            EgressAddressRequest::Explicit { addresses } => {
                lease.pool.is_none() && &lease.addresses == addresses
            }
            EgressAddressRequest::Pool {
                name,
                families,
                addresses_per_family,
            } => {
                let Some(pool) = self.pools.get(name) else {
                    return false;
                };
                lease.pool
                    == Some(EgressAllocatedPool {
                        name: pool.name.clone(),
                        uid: pool.uid.clone(),
                    })
                    && lease.provider == pool.provider
                    && lease.addresses.len() == families.len() * usize::from(*addresses_per_family)
                    && families.iter().all(|family| {
                        lease
                            .addresses
                            .iter()
                            .filter(|address| address_family(**address) == *family)
                            .count()
                            == usize::from(*addresses_per_family)
                    })
                    && lease.addresses.iter().all(|address| {
                        pool.prefixes
                            .iter()
                            .any(|prefix| usable_prefix_address(*prefix, *address))
                    })
            }
        }
    }
}

impl EgressAddressLease {
    /// Projects exact durable allocation provenance into contract input.
    #[must_use]
    pub fn contract_fact(&self) -> crate::EgressAllocationFact {
        crate::EgressAllocationFact {
            intent_uid: self.intent.owner.uid.clone(),
            pool_name: self.pool.as_ref().map(|pool| pool.name.clone()),
            pool_uid: self.pool.as_ref().map(|pool| pool.uid.clone()),
            addresses: self.addresses.clone(),
            lease_epoch: self.lease_epoch,
        }
    }
}

fn validate_request(
    mut request: EgressAllocationRequest,
) -> Result<EgressAllocationRequest, EgressAllocationError> {
    if request.intent_epoch == 0 || request.intent_revision == Revision::INITIAL {
        return Err(EgressAllocationError::ZeroIntentRevision);
    }
    request.intent = normalize_intent(request.intent)
        .map_err(|error| EgressAllocationError::InvalidModel(error.to_string()))?;
    Ok(request)
}

fn allocate_from_pool(
    pool: &EgressAddressPool,
    family: AddressFamily,
    reserved: &BTreeSet<IpAddr>,
) -> Result<IpAddr, EgressAllocationError> {
    let mut scanned = 0_usize;
    for prefix in pool
        .prefixes
        .iter()
        .filter(|prefix| prefix.family() == family)
    {
        let mut index = 0_usize;
        while scanned < MAX_EGRESS_POOL_ALLOCATION_SCAN {
            let Some(candidate) = pool_candidate(*prefix, index) else {
                break;
            };
            if !reserved.contains(&candidate) {
                return Ok(candidate);
            }
            index += 1;
            scanned += 1;
        }
    }
    Err(EgressAllocationError::Exhausted {
        pool: pool.name.clone(),
        family,
        limit: MAX_EGRESS_POOL_ALLOCATION_SCAN,
    })
}

fn pool_candidate(prefix: crate::IpPrefix, index: usize) -> Option<IpAddr> {
    match prefix.address {
        IpAddr::V4(network) => {
            let host_bits = 32 - prefix.prefix_len;
            let size = 1_u64 << host_bits;
            let first = u64::from(u32::from(network)) + u64::from(host_bits != 0);
            let usable = size.saturating_sub(if host_bits == 0 { 0 } else { 2 });
            let index = u64::try_from(index).ok()?;
            (index < usable).then(|| {
                IpAddr::V4(Ipv4Addr::from(
                    u32::try_from(first + index).expect("IPv4 prefix candidate is bounded"),
                ))
            })
        }
        IpAddr::V6(network) => {
            let host_bits = 128 - prefix.prefix_len;
            let first = u128::from(network) + u128::from(host_bits != 0);
            let index = u128::try_from(index).ok()?;
            let within = match host_bits {
                128 => true,
                0 => index == 0,
                bits => index < (1_u128 << bits).saturating_sub(1),
            };
            within.then(|| IpAddr::V6(Ipv6Addr::from(first + index)))
        }
    }
}

fn usable_prefix_address(prefix: crate::IpPrefix, address: IpAddr) -> bool {
    if !prefix.contains(address) {
        return false;
    }
    match (prefix.address, address) {
        (IpAddr::V4(network), IpAddr::V4(address)) if prefix.prefix_len < 32 => {
            let network = u64::from(u32::from(network));
            let address = u64::from(u32::from(address));
            let last = network + (1_u64 << (32 - prefix.prefix_len)) - 1;
            address > network && address < last
        }
        (IpAddr::V6(network), IpAddr::V6(address)) if prefix.prefix_len < 128 => {
            u128::from(address) > u128::from(network)
        }
        _ => true,
    }
}

const fn address_family(address: IpAddr) -> AddressFamily {
    match address {
        IpAddr::V4(_) => AddressFamily::Ipv4,
        IpAddr::V6(_) => AddressFamily::Ipv6,
    }
}

fn valid_provider(provider: &EgressProviderRef) -> bool {
    !provider.name.is_empty()
        && provider.name.len() <= 253
        && !provider.instance.is_empty()
        && provider.instance.len() <= 128
}

fn checked_next_revision(revision: Revision) -> Result<Revision, EgressAllocationError> {
    let next = revision.next();
    (next != revision)
        .then_some(next)
        .ok_or(EgressAllocationError::CounterExhausted)
}

fn invalid_owner() -> EgressIntentOwner {
    EgressIntentOwner {
        scope: crate::EgressIntentScope::Cluster,
        name: "invalid".to_owned(),
        uid: "invalid".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        DEFAULT_EGRESS_INTENT_PRIORITY, EgressDestinations, EgressIntentScope, EgressProviderRef,
        EgressSourceSelector, IpPrefix,
    };

    fn ip(value: &str) -> IpAddr {
        value.parse().expect("valid test IP")
    }

    fn provider(name: &str) -> EgressProviderRef {
        EgressProviderRef {
            name: name.to_owned(),
            instance: "lab".to_owned(),
        }
    }

    fn pool() -> EgressAddressPool {
        EgressAddressPool {
            name: "finance".to_owned(),
            uid: "uid-finance-pool".to_owned(),
            provider: provider("static"),
            prefixes: vec![
                IpPrefix {
                    address: ip("192.0.2.0"),
                    prefix_len: 29,
                },
                IpPrefix {
                    address: ip("2001:db8::"),
                    prefix_len: 125,
                },
            ],
        }
    }

    fn intent(name: &str, count: u16) -> EgressIntent {
        EgressIntent {
            owner: EgressIntentOwner {
                scope: EgressIntentScope::Namespace("finance".to_owned()),
                name: name.to_owned(),
                uid: format!("uid-{name}"),
            },
            priority: DEFAULT_EGRESS_INTENT_PRIORITY,
            source: EgressSourceSelector::default(),
            destinations: EgressDestinations::Any,
            addresses: EgressAddressRequest::Pool {
                name: "finance".to_owned(),
                families: vec![AddressFamily::Ipv4, AddressFamily::Ipv6],
                addresses_per_family: count,
            },
        }
    }

    fn request(name: &str, count: u16, revision: u64) -> EgressAllocationRequest {
        EgressAllocationRequest {
            intent: intent(name, count),
            explicit_provider: None,
            intent_epoch: 1,
            intent_revision: Revision::new(revision),
        }
    }

    #[test]
    fn allocates_multiple_dual_stack_addresses_deterministically_and_atomically() {
        let mut allocator = EgressAllocator::new(vec![pool()]).expect("valid pools");
        let first = allocator
            .allocate(request("payments", 2, 1))
            .expect("first lease");
        assert_eq!(
            first.addresses,
            vec![
                ip("192.0.2.1"),
                ip("192.0.2.2"),
                ip("2001:db8::1"),
                ip("2001:db8::2")
            ]
        );
        let second = allocator
            .allocate(request("ledger", 1, 2))
            .expect("second lease");
        assert_eq!(second.addresses, vec![ip("192.0.2.3"), ip("2001:db8::3")]);

        let before = allocator.checkpoint();
        assert!(allocator.allocate(request("exhausted", 4, 3)).is_err());
        assert_eq!(allocator.checkpoint(), before, "failure must be atomic");
    }

    #[test]
    fn replay_refresh_and_immutable_intent_are_fenced() {
        let mut allocator = EgressAllocator::new(vec![pool()]).expect("valid pools");
        let first = allocator
            .allocate(request("payments", 1, 1))
            .expect("lease");
        assert_eq!(
            allocator
                .allocate(request("payments", 1, 1))
                .expect("replay"),
            first
        );
        let mut refresh = request("payments", 1, 2);
        refresh.intent.destinations = EgressDestinations::Networks(vec![IpPrefix {
            address: ip("203.0.113.0"),
            prefix_len: 24,
        }]);
        let refreshed = allocator.allocate(refresh).expect("mutable intent refresh");
        assert_eq!(refreshed.addresses, first.addresses);
        assert_eq!(refreshed.lease_epoch, first.lease_epoch);
        assert!(refreshed.allocation_revision > first.allocation_revision);
        assert!(matches!(
            allocator.allocate(request("payments", 2, 3)),
            Err(EgressAllocationError::ImmutableIntentChanged { .. })
        ));
        assert!(matches!(
            allocator.allocate(request("payments", 1, 1)),
            Err(EgressAllocationError::IntentRevisionRegression { .. })
        ));
        let mut same_revision_mutation = request("payments", 1, 2);
        same_revision_mutation.intent.destinations = EgressDestinations::Any;
        assert!(matches!(
            allocator.allocate(same_revision_mutation),
            Err(EgressAllocationError::IntentRevisionMutation { .. })
        ));
    }

    #[test]
    fn release_reuse_gets_a_new_monotonic_lease_epoch() {
        let mut allocator = EgressAllocator::new(vec![pool()]).expect("valid pools");
        let first = allocator
            .allocate(request("payments", 1, 1))
            .expect("lease");
        allocator
            .release(&first.intent.owner)
            .expect("exact release");
        let second = allocator
            .allocate(request("replacement", 1, 2))
            .expect("reused lease");
        assert_eq!(second.addresses, first.addresses);
        assert!(second.lease_epoch > first.lease_epoch);
        assert!(second.allocation_revision > first.allocation_revision);
        assert_eq!(second.contract_fact().lease_epoch, second.lease_epoch);
    }

    #[test]
    fn explicit_addresses_require_provider_and_conflict_globally() {
        let explicit = |name: &str, address: &str, with_provider: bool| {
            let mut intent = intent(name, 1);
            intent.addresses = EgressAddressRequest::Explicit {
                addresses: vec![ip(address)],
            };
            EgressAllocationRequest {
                intent,
                explicit_provider: with_provider.then(|| provider("openshift-compat")),
                intent_epoch: 1,
                intent_revision: Revision::new(1),
            }
        };
        let mut allocator = EgressAllocator::new(vec![pool()]).expect("valid pools");
        assert!(matches!(
            allocator.allocate(explicit("missing", "198.51.100.10", false)),
            Err(EgressAllocationError::InvalidProvider(_))
        ));
        let first = allocator
            .allocate(explicit("first", "198.51.100.10", true))
            .expect("explicit lease");
        assert_eq!(first.pool, None);
        assert!(matches!(
            allocator.allocate(explicit("second", "198.51.100.10", true)),
            Err(EgressAllocationError::AddressConflict { .. })
        ));
    }

    #[test]
    fn checkpoint_round_trip_rejects_collision_and_provenance_drift() {
        let mut allocator = EgressAllocator::new(vec![pool()]).expect("valid pools");
        allocator
            .allocate(request("payments", 1, 1))
            .expect("first lease");
        allocator
            .allocate(request("ledger", 1, 2))
            .expect("second lease");
        let checkpoint = allocator.checkpoint();
        let encoded = serde_json::to_vec(&checkpoint).expect("checkpoint serializes");
        let decoded = serde_json::from_slice(&encoded).expect("checkpoint decodes");
        assert_eq!(
            EgressAllocator::restore(decoded)
                .expect("restore")
                .checkpoint(),
            checkpoint
        );

        let mut collision = checkpoint.clone();
        collision.leases[1].addresses = collision.leases[0].addresses.clone();
        assert!(EgressAllocator::restore(collision).is_err());
        let mut foreign = checkpoint;
        foreign.leases[0].pool.as_mut().expect("pool lease").uid = "foreign".to_owned();
        assert!(EgressAllocator::restore(foreign).is_err());
    }
}
