//! Provider-neutral `LoadBalancer` allocation and reachability transactions.
//!
//! This crate does not call Kubernetes, mutate host state, or send routing
//! protocol messages. It owns the deterministic state machines that adapters
//! must persist and execute without conflating allocation, advertisement,
//! dataplane, or API publication readiness.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use unf_common::{LOAD_BALANCER_REACHABILITY_SCHEMA_VERSION, Revision, ServiceId};
use unf_ebpf_common::{
    LOAD_BALANCER_BANK_COUNT, LOAD_BALANCER_FRONTEND_FLAG_LOCAL,
    LOAD_BALANCER_FRONTEND_FLAG_SOURCE_RANGES, LOAD_BALANCER_MAP_ABI_VERSION, SERVICE_BANK_COUNT,
    SERVICE_SELECTION_TIER_CLUSTER, SERVICE_SELECTION_TIER_SAME_NODE,
    SERVICE_SELECTION_TIER_SAME_ZONE,
};
use unf_service::{
    AddressFamily, NetworkBehaviorContract, SelectionFrontend, SelectionPlanKey, SelectionTier,
    ServiceForwardingMode, ServiceIpPrefix, ServiceIr, ServiceSelectionAlgorithm,
    ServiceSessionAffinity, ServiceTrafficPolicy, UNF_LOAD_BALANCER_CLASS,
    load_balancer_local_frontend_index,
};

pub const ALLOCATION_CHECKPOINT_SCHEMA_VERSION: u16 = 2;
pub const LEGACY_ALLOCATION_CHECKPOINT_SCHEMA_VERSION: u16 = 1;
pub const REACHABILITY_SNAPSHOT_SCHEMA_VERSION: u16 = 1;
pub const REACHABILITY_ACK_SCHEMA_VERSION: u16 = 1;
pub const NODE_REACHABILITY_SCHEMA_VERSION: u16 = LOAD_BALANCER_REACHABILITY_SCHEMA_VERSION;
pub const NODE_REACHABILITY_CHECKPOINT_SCHEMA_VERSION: u16 = 1;
pub const MAX_LOAD_BALANCER_POOLS: usize = 64;
pub const MAX_LOAD_BALANCER_LEASES: usize = 65_536;
pub const MAX_LOAD_BALANCER_NODES: usize = 4_096;
pub const MAX_POOL_ALLOCATION_SCAN: usize = 65_536;
pub const MAX_REACHABILITY_TARGETS: usize = 524_288;
pub const MAX_STATUS_INGRESS: usize = 256;
pub const LOAD_BALANCER_FRONTEND_BANK_CAPACITY: usize = 262_144;
pub const UNF_LOAD_BALANCER_FINALIZER: &str = "network.unf.io/load-balancer-protection";

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct LoadBalancerOwner {
    pub service_id: ServiceId,
    pub namespace: String,
    pub name: String,
    pub uid: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ReachabilityMode {
    DirectNode,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ReachabilityProviderRef {
    pub name: String,
    pub instance: String,
    pub mode: ReachabilityMode,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct LoadBalancerPool {
    pub name: String,
    pub uid: String,
    pub provider: ReachabilityProviderRef,
    pub ipv4: Option<ServiceIpPrefix>,
    pub ipv6: Option<ServiceIpPrefix>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllocationRequest {
    pub owner: LoadBalancerOwner,
    pub pool: String,
    pub families: Vec<AddressFamily>,
    pub requested_ips: Vec<IpAddr>,
    pub intent_epoch: u64,
    pub intent_revision: Revision,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct LoadBalancerLease {
    pub owner: LoadBalancerOwner,
    pub pool: String,
    pub pool_uid: String,
    pub provider: ReachabilityProviderRef,
    pub families: Vec<AddressFamily>,
    pub requested_ips: Vec<IpAddr>,
    pub addresses: Vec<IpAddr>,
    #[serde(default)]
    pub intent_epoch: u64,
    pub intent_revision: Revision,
    pub allocation_revision: Revision,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AllocationCheckpoint {
    pub schema_version: u16,
    pub revision: Revision,
    pub pools: Vec<LoadBalancerPool>,
    pub leases: Vec<LoadBalancerLease>,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum AllocationError {
    #[error("unsupported allocation checkpoint schema {actual}; expected {expected}")]
    UnsupportedSchema { actual: u16, expected: u16 },
    #[error("allocation revision must be nonzero when leases exist")]
    ZeroRevision,
    #[error("allocation has {actual} pools; limit is {limit}")]
    TooManyPools { actual: usize, limit: usize },
    #[error("allocation has {actual} leases; limit is {limit}")]
    TooManyLeases { actual: usize, limit: usize },
    #[error("invalid pool {pool:?}: {reason}")]
    InvalidPool { pool: String, reason: &'static str },
    #[error("duplicate pool name {0:?}")]
    DuplicatePoolName(String),
    #[error("duplicate pool UID {0:?}")]
    DuplicatePoolUid(String),
    #[error("pool {left:?} overlaps pool {right:?} for {family:?}")]
    OverlappingPools {
        left: String,
        right: String,
        family: AddressFamily,
    },
    #[error("unknown LoadBalancer pool {0:?}")]
    UnknownPool(String),
    #[error("invalid allocation owner for {namespace}/{name}: {reason}")]
    InvalidOwner {
        namespace: String,
        name: String,
        reason: &'static str,
    },
    #[error("allocation request must have a nonzero intent epoch and revision")]
    ZeroIntentRevision,
    #[error("allocation request has invalid address-family intent: {0}")]
    InvalidFamilies(&'static str),
    #[error("requested address {address} is outside pool {pool:?}")]
    RequestedAddressOutsidePool { address: IpAddr, pool: String },
    #[error("address {address} is already owned by {owner:?}")]
    AddressConflict {
        address: IpAddr,
        owner: LoadBalancerOwner,
    },
    #[error("pool {pool:?} is exhausted for {family:?} within scan limit {limit}")]
    Exhausted {
        pool: String,
        family: AddressFamily,
        limit: usize,
    },
    #[error("restored lease for {owner:?} no longer matches pool ownership")]
    ForeignLease { owner: LoadBalancerOwner },
    #[error("owner {owner:?} already has different immutable allocation intent")]
    ImmutableIntentChanged { owner: LoadBalancerOwner },
    #[error(
        "owner {owner:?} intent tuple regressed from epoch {current_epoch} revision {current_revision:?} to epoch {candidate_epoch} revision {candidate_revision:?}"
    )]
    IntentRevisionRegression {
        owner: LoadBalancerOwner,
        current_epoch: u64,
        current_revision: Revision,
        candidate_epoch: u64,
        candidate_revision: Revision,
    },
    #[error("cannot release unknown owner {0:?}")]
    UnknownOwner(LoadBalancerOwner),
    #[error("LoadBalancer status has {actual} ingress entries; limit is {limit}")]
    TooManyStatusIngress { actual: usize, limit: usize },
    #[error("LoadBalancer status address {0} is already foreign-owned")]
    ForeignStatusAddress(IpAddr),
}

/// Minimal Kubernetes `status.loadBalancer.ingress` representation retained by
/// the ownership adapter. Unknown/foreign entries are never normalized away.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct StatusIngress {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
}

/// Converts one admitted schema-v3 Service into exact allocation ownership.
///
/// Classless, foreign-class, and non-LoadBalancer Services return `None`; they
/// must not acquire a UNF lease or finalizer.
///
/// # Errors
///
/// Rejects an empty Kubernetes UID or pool name. The Service IR itself has
/// already passed the schema-v3 validator before reaching this boundary.
pub fn allocation_request_for_service(
    service: &ServiceIr,
    uid: &str,
    pool: &str,
    intent_epoch: u64,
    intent_revision: Revision,
) -> Result<Option<AllocationRequest>, AllocationError> {
    let Some(load_balancer) = &service.load_balancer else {
        return Ok(None);
    };
    if load_balancer.class != UNF_LOAD_BALANCER_CLASS {
        return Ok(None);
    }
    let owner = LoadBalancerOwner {
        service_id: service.id,
        namespace: service.namespace.clone(),
        name: service.name.clone(),
        uid: uid.to_owned(),
    };
    validate_owner(&owner)?;
    if !valid_name(pool) {
        return Err(AllocationError::UnknownPool(pool.to_owned()));
    }
    Ok(Some(AllocationRequest {
        owner,
        pool: pool.to_owned(),
        families: load_balancer.ip_families.clone(),
        requested_ips: load_balancer.requested_ips.clone(),
        intent_epoch,
        intent_revision,
    }))
}

/// Adds or removes only the exact UNF finalizer while retaining every foreign
/// finalizer byte-for-byte and in its observed order.
#[must_use]
pub fn reconcile_finalizers(existing: &[String], retain_unf: bool) -> Vec<String> {
    let mut reconciled = existing
        .iter()
        .filter(|finalizer| finalizer.as_str() != UNF_LOAD_BALANCER_FINALIZER)
        .cloned()
        .collect::<Vec<_>>();
    if retain_unf {
        reconciled.push(UNF_LOAD_BALANCER_FINALIZER.to_owned());
    }
    reconciled
}

/// Replaces only addresses previously published by UNF and preserves every
/// foreign IP/hostname status entry. A desired address already present outside
/// the prior UNF ownership set is a conflict, not an adoption opportunity.
///
/// # Errors
///
/// Rejects oversized status, duplicate desired ownership, and foreign address
/// conflicts without returning a partial mutation.
pub fn reconcile_status_ingress(
    existing: &[StatusIngress],
    previously_owned: &[IpAddr],
    desired_owned: &[IpAddr],
) -> Result<Vec<StatusIngress>, AllocationError> {
    if existing.len() > MAX_STATUS_INGRESS {
        return Err(AllocationError::TooManyStatusIngress {
            actual: existing.len(),
            limit: MAX_STATUS_INGRESS,
        });
    }
    let previous = previously_owned.iter().copied().collect::<BTreeSet<_>>();
    let desired = desired_owned.iter().copied().collect::<BTreeSet<_>>();
    if desired.len() != desired_owned.len() {
        return Err(AllocationError::InvalidFamilies(
            "published addresses must be unique",
        ));
    }
    for entry in existing {
        if let Some(address) = entry.ip.as_deref().and_then(|ip| ip.parse().ok())
            && desired.contains(&address)
            && !previous.contains(&address)
        {
            return Err(AllocationError::ForeignStatusAddress(address));
        }
    }
    let mut reconciled = existing
        .iter()
        .filter(|entry| {
            entry
                .ip
                .as_deref()
                .and_then(|ip| ip.parse().ok())
                .is_none_or(|address| !previous.contains(&address))
        })
        .cloned()
        .collect::<Vec<_>>();
    if reconciled.len().saturating_add(desired.len()) > MAX_STATUS_INGRESS {
        return Err(AllocationError::TooManyStatusIngress {
            actual: reconciled.len().saturating_add(desired.len()),
            limit: MAX_STATUS_INGRESS,
        });
    }
    reconciled.extend(desired.into_iter().map(|address| StatusIngress {
        ip: Some(address.to_string()),
        hostname: None,
    }));
    Ok(reconciled)
}

#[derive(Debug, Clone)]
pub struct LoadBalancerAllocator {
    pools: BTreeMap<String, LoadBalancerPool>,
    leases: BTreeMap<LoadBalancerOwner, LoadBalancerLease>,
    address_owners: BTreeMap<IpAddr, LoadBalancerOwner>,
    revision: Revision,
}

impl LoadBalancerAllocator {
    /// Creates an empty allocator after validating canonical, disjoint pools.
    ///
    /// # Errors
    ///
    /// Rejects duplicate/invalid provider ownership, missing address families,
    /// overlapping address space, and pool counts outside the fixed bound.
    pub fn new(pools: Vec<LoadBalancerPool>) -> Result<Self, AllocationError> {
        let pools = validate_pools(pools)?;
        Ok(Self {
            pools,
            leases: BTreeMap::new(),
            address_owners: BTreeMap::new(),
            revision: Revision::INITIAL,
        })
    }

    /// Restores an exact validated allocation checkpoint.
    ///
    /// # Errors
    ///
    /// Rejects schema, pool, lease, collision, provenance, and revision drift
    /// before returning any usable allocator state.
    pub fn restore(checkpoint: AllocationCheckpoint) -> Result<Self, AllocationError> {
        if checkpoint.schema_version != ALLOCATION_CHECKPOINT_SCHEMA_VERSION
            && checkpoint.schema_version != LEGACY_ALLOCATION_CHECKPOINT_SCHEMA_VERSION
        {
            return Err(AllocationError::UnsupportedSchema {
                actual: checkpoint.schema_version,
                expected: ALLOCATION_CHECKPOINT_SCHEMA_VERSION,
            });
        }
        if checkpoint.leases.len() > MAX_LOAD_BALANCER_LEASES {
            return Err(AllocationError::TooManyLeases {
                actual: checkpoint.leases.len(),
                limit: MAX_LOAD_BALANCER_LEASES,
            });
        }
        if !checkpoint.leases.is_empty() && checkpoint.revision == Revision::INITIAL {
            return Err(AllocationError::ZeroRevision);
        }
        let legacy = checkpoint.schema_version == LEGACY_ALLOCATION_CHECKPOINT_SCHEMA_VERSION;
        let mut allocator = Self::new(checkpoint.pools)?;
        allocator.revision = checkpoint.revision;
        for mut lease in checkpoint.leases {
            if legacy && lease.intent_epoch == 0 {
                lease.intent_epoch = 1;
            }
            allocator.restore_lease(lease)?;
        }
        Ok(allocator)
    }

    /// Allocates or exactly replays one owner request.
    ///
    /// # Errors
    ///
    /// Rejects changed immutable intent, pool/family/request mismatches,
    /// collisions, and bounded exhaustion without mutating existing leases.
    pub fn allocate(
        &mut self,
        mut request: AllocationRequest,
    ) -> Result<LoadBalancerLease, AllocationError> {
        validate_owner(&request.owner)?;
        validate_allocation_request(&mut request)?;
        let pool = self
            .pools
            .get(&request.pool)
            .ok_or_else(|| AllocationError::UnknownPool(request.pool.clone()))?;
        if let Some(existing) = self.leases.get(&request.owner) {
            if existing.pool != request.pool
                || existing.families != request.families
                || existing.requested_ips != request.requested_ips
            {
                return Err(AllocationError::ImmutableIntentChanged {
                    owner: request.owner,
                });
            }
            if request.intent_epoch < existing.intent_epoch
                || (request.intent_epoch == existing.intent_epoch
                    && request.intent_revision < existing.intent_revision)
            {
                return Err(AllocationError::IntentRevisionRegression {
                    owner: request.owner,
                    current_epoch: existing.intent_epoch,
                    current_revision: existing.intent_revision,
                    candidate_epoch: request.intent_epoch,
                    candidate_revision: request.intent_revision,
                });
            }
            if request.intent_epoch == existing.intent_epoch
                && request.intent_revision == existing.intent_revision
            {
                return Ok(existing.clone());
            }
            let allocation_revision = self.revision.next();
            let mut refreshed = existing.clone();
            refreshed.intent_epoch = request.intent_epoch;
            refreshed.intent_revision = request.intent_revision;
            refreshed.allocation_revision = allocation_revision;
            self.leases.insert(request.owner, refreshed.clone());
            self.revision = allocation_revision;
            return Ok(refreshed);
        }

        let addresses = self.plan_addresses(pool, &request)?;
        let allocation_revision = self.revision.next();
        let lease = LoadBalancerLease {
            owner: request.owner.clone(),
            pool: pool.name.clone(),
            pool_uid: pool.uid.clone(),
            provider: pool.provider.clone(),
            families: request.families,
            requested_ips: request.requested_ips,
            addresses,
            intent_epoch: request.intent_epoch,
            intent_revision: request.intent_revision,
            allocation_revision,
        };
        for address in &lease.addresses {
            self.address_owners.insert(*address, request.owner.clone());
        }
        self.leases.insert(request.owner, lease.clone());
        self.revision = allocation_revision;
        Ok(lease)
    }

    /// Releases one exact owner lease and advances the durable revision.
    ///
    /// # Errors
    ///
    /// Rejects unknown owners without mutating retained allocation state.
    pub fn release(
        &mut self,
        owner: &LoadBalancerOwner,
    ) -> Result<LoadBalancerLease, AllocationError> {
        let lease = self
            .leases
            .remove(owner)
            .ok_or_else(|| AllocationError::UnknownOwner(owner.clone()))?;
        for address in &lease.addresses {
            self.address_owners.remove(address);
        }
        self.revision = self.revision.next();
        Ok(lease)
    }

    #[must_use]
    pub fn lease(&self, owner: &LoadBalancerOwner) -> Option<&LoadBalancerLease> {
        self.leases.get(owner)
    }

    #[must_use]
    pub fn checkpoint(&self) -> AllocationCheckpoint {
        AllocationCheckpoint {
            schema_version: ALLOCATION_CHECKPOINT_SCHEMA_VERSION,
            revision: self.revision,
            pools: self.pools.values().cloned().collect(),
            leases: self.leases.values().cloned().collect(),
        }
    }

    fn restore_lease(&mut self, lease: LoadBalancerLease) -> Result<(), AllocationError> {
        validate_owner(&lease.owner)?;
        if self.leases.contains_key(&lease.owner) {
            return Err(AllocationError::ImmutableIntentChanged { owner: lease.owner });
        }
        let Some(pool) = self.pools.get(&lease.pool) else {
            return Err(AllocationError::ForeignLease { owner: lease.owner });
        };
        if lease.pool_uid != pool.uid
            || lease.provider != pool.provider
            || lease.allocation_revision == Revision::INITIAL
            || lease.allocation_revision > self.revision
            || lease.intent_epoch == 0
            || lease.intent_revision == Revision::INITIAL
            || lease.families.is_empty()
            || lease.families.len() > 2
            || lease.families.windows(2).any(|pair| pair[0] >= pair[1])
            || lease
                .requested_ips
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
            || lease.addresses.windows(2).any(|pair| pair[0] >= pair[1])
            || lease.addresses.is_empty()
            || lease.addresses.len() != lease.families.len()
            || lease.requested_ips.len() > lease.families.len()
            || lease
                .addresses
                .iter()
                .copied()
                .map(address_family)
                .ne(lease.families.iter().copied())
            || !lease
                .requested_ips
                .iter()
                .all(|address| lease.addresses.contains(address))
            || lease
                .addresses
                .iter()
                .any(|address| !pool_usable_address(pool, *address))
        {
            return Err(AllocationError::ForeignLease { owner: lease.owner });
        }
        for address in &lease.addresses {
            if let Some(owner) = self.address_owners.insert(*address, lease.owner.clone()) {
                return Err(AllocationError::AddressConflict {
                    address: *address,
                    owner,
                });
            }
        }
        self.leases.insert(lease.owner.clone(), lease);
        Ok(())
    }

    fn plan_addresses(
        &self,
        pool: &LoadBalancerPool,
        request: &AllocationRequest,
    ) -> Result<Vec<IpAddr>, AllocationError> {
        let requested = request
            .requested_ips
            .iter()
            .copied()
            .map(|address| {
                if !pool_usable_address(pool, address) {
                    return Err(AllocationError::RequestedAddressOutsidePool {
                        address,
                        pool: pool.name.clone(),
                    });
                }
                if let Some(owner) = self.address_owners.get(&address) {
                    return Err(AllocationError::AddressConflict {
                        address,
                        owner: owner.clone(),
                    });
                }
                Ok((address_family(address), address))
            })
            .collect::<Result<BTreeMap<_, _>, _>>()?;
        let mut planned = Vec::with_capacity(request.families.len());
        for family in &request.families {
            if let Some(address) = requested.get(family) {
                planned.push(*address);
            } else {
                planned.push(self.allocate_family(pool, *family)?);
            }
        }
        planned.sort();
        Ok(planned)
    }

    fn allocate_family(
        &self,
        pool: &LoadBalancerPool,
        family: AddressFamily,
    ) -> Result<IpAddr, AllocationError> {
        let prefix = match family {
            AddressFamily::Ipv4 => pool.ipv4,
            AddressFamily::Ipv6 => pool.ipv6,
        }
        .ok_or(AllocationError::InvalidFamilies(
            "requested family is absent from the selected pool",
        ))?;
        for index in 0..MAX_POOL_ALLOCATION_SCAN {
            let Some(candidate) = pool_candidate(prefix, index) else {
                break;
            };
            if !self.address_owners.contains_key(&candidate) {
                return Ok(candidate);
            }
        }
        Err(AllocationError::Exhausted {
            pool: pool.name.clone(),
            family,
            limit: MAX_POOL_ALLOCATION_SCAN,
        })
    }
}

fn validate_pools(
    pools: Vec<LoadBalancerPool>,
) -> Result<BTreeMap<String, LoadBalancerPool>, AllocationError> {
    if pools.len() > MAX_LOAD_BALANCER_POOLS {
        return Err(AllocationError::TooManyPools {
            actual: pools.len(),
            limit: MAX_LOAD_BALANCER_POOLS,
        });
    }
    let mut by_name = BTreeMap::new();
    let mut uids = BTreeSet::new();
    for pool in pools {
        validate_pool(&pool)?;
        if !uids.insert(pool.uid.clone()) {
            return Err(AllocationError::DuplicatePoolUid(pool.uid));
        }
        if by_name.insert(pool.name.clone(), pool.clone()).is_some() {
            return Err(AllocationError::DuplicatePoolName(pool.name));
        }
    }
    let values = by_name.values().collect::<Vec<_>>();
    for (index, left) in values.iter().enumerate() {
        for right in values.iter().skip(index + 1) {
            for family in [AddressFamily::Ipv4, AddressFamily::Ipv6] {
                let left_prefix = pool_prefix(left, family);
                let right_prefix = pool_prefix(right, family);
                if left_prefix
                    .zip(right_prefix)
                    .is_some_and(|(left, right)| prefixes_overlap(left, right))
                {
                    return Err(AllocationError::OverlappingPools {
                        left: left.name.clone(),
                        right: right.name.clone(),
                        family,
                    });
                }
            }
        }
    }
    Ok(by_name)
}

fn validate_pool(pool: &LoadBalancerPool) -> Result<(), AllocationError> {
    if !valid_name(&pool.name) || !valid_uid(&pool.uid) {
        return Err(AllocationError::InvalidPool {
            pool: pool.name.clone(),
            reason: "name and UID must be nonempty and bounded",
        });
    }
    if !valid_name(&pool.provider.name) || !valid_uid(&pool.provider.instance) {
        return Err(AllocationError::InvalidPool {
            pool: pool.name.clone(),
            reason: "provider name and instance must be nonempty and bounded",
        });
    }
    if pool.ipv4.is_none() && pool.ipv6.is_none() {
        return Err(AllocationError::InvalidPool {
            pool: pool.name.clone(),
            reason: "at least one address family is required",
        });
    }
    if pool.ipv4.is_some_and(|prefix| {
        prefix.family() != AddressFamily::Ipv4
            || !prefix.is_canonical()
            || pool_candidate(prefix, 0).is_none()
    }) || pool.ipv6.is_some_and(|prefix| {
        prefix.family() != AddressFamily::Ipv6
            || !prefix.is_canonical()
            || pool_candidate(prefix, 0).is_none()
    }) {
        return Err(AllocationError::InvalidPool {
            pool: pool.name.clone(),
            reason: "pool prefixes must be canonical and family exact",
        });
    }
    Ok(())
}

fn validate_owner(owner: &LoadBalancerOwner) -> Result<(), AllocationError> {
    if owner.service_id.get() == 0 {
        return Err(AllocationError::InvalidOwner {
            namespace: owner.namespace.clone(),
            name: owner.name.clone(),
            reason: "service ID zero is reserved",
        });
    }
    if !valid_name(&owner.namespace) || !valid_name(&owner.name) || !valid_uid(&owner.uid) {
        return Err(AllocationError::InvalidOwner {
            namespace: owner.namespace.clone(),
            name: owner.name.clone(),
            reason: "namespace, name, and UID must be nonempty and bounded",
        });
    }
    Ok(())
}

fn validate_allocation_request(request: &mut AllocationRequest) -> Result<(), AllocationError> {
    if request.intent_epoch == 0 || request.intent_revision == Revision::INITIAL {
        return Err(AllocationError::ZeroIntentRevision);
    }
    if request.families.is_empty() || request.families.len() > 2 {
        return Err(AllocationError::InvalidFamilies(
            "one or two families are required",
        ));
    }
    request.families.sort();
    if request.families.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(AllocationError::InvalidFamilies("families must be unique"));
    }
    request.requested_ips.sort();
    if request.requested_ips.len() > request.families.len()
        || request
            .requested_ips
            .windows(2)
            .any(|pair| pair[0] == pair[1])
    {
        return Err(AllocationError::InvalidFamilies(
            "requested addresses must be unique and family bounded",
        ));
    }
    let requested_families = request
        .requested_ips
        .iter()
        .copied()
        .map(address_family)
        .collect::<BTreeSet<_>>();
    if requested_families.len() != request.requested_ips.len()
        || !requested_families
            .iter()
            .all(|family| request.families.contains(family))
    {
        return Err(AllocationError::InvalidFamilies(
            "at most one requested address per admitted family is allowed",
        ));
    }
    Ok(())
}

fn pool_prefix(pool: &LoadBalancerPool, family: AddressFamily) -> Option<ServiceIpPrefix> {
    match family {
        AddressFamily::Ipv4 => pool.ipv4,
        AddressFamily::Ipv6 => pool.ipv6,
    }
}

fn pool_usable_address(pool: &LoadBalancerPool, address: IpAddr) -> bool {
    pool_prefix(pool, address_family(address))
        .is_some_and(|prefix| usable_prefix_address(prefix, address))
}

fn usable_prefix_address(prefix: ServiceIpPrefix, address: IpAddr) -> bool {
    if !prefix_contains(prefix, address) {
        return false;
    }
    match (prefix.address, address) {
        (IpAddr::V4(network), IpAddr::V4(address)) if prefix.prefix_length < 32 => {
            let network = u64::from(u32::from(network));
            let address = u64::from(u32::from(address));
            let last = network + (1_u64 << (32 - prefix.prefix_length)) - 1;
            address > network && address < last
        }
        (IpAddr::V6(network), IpAddr::V6(address)) if prefix.prefix_length < 128 => {
            u128::from(address) > u128::from(network)
        }
        (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_)) => true,
        _ => false,
    }
}

fn prefix_contains(prefix: ServiceIpPrefix, address: IpAddr) -> bool {
    match (prefix.address, address) {
        (IpAddr::V4(network), IpAddr::V4(address)) => {
            let mask = prefix_mask_v4(prefix.prefix_length);
            u32::from(network) & mask == u32::from(address) & mask
        }
        (IpAddr::V6(network), IpAddr::V6(address)) => {
            let mask = prefix_mask_v6(prefix.prefix_length);
            u128::from(network) & mask == u128::from(address) & mask
        }
        _ => false,
    }
}

fn prefixes_overlap(left: ServiceIpPrefix, right: ServiceIpPrefix) -> bool {
    if left.family() != right.family() {
        return false;
    }
    let prefix_length = left.prefix_length.min(right.prefix_length);
    match (left.address, right.address) {
        (IpAddr::V4(left), IpAddr::V4(right)) => {
            let mask = prefix_mask_v4(prefix_length);
            u32::from(left) & mask == u32::from(right) & mask
        }
        (IpAddr::V6(left), IpAddr::V6(right)) => {
            let mask = prefix_mask_v6(prefix_length);
            u128::from(left) & mask == u128::from(right) & mask
        }
        _ => false,
    }
}

fn pool_candidate(prefix: ServiceIpPrefix, index: usize) -> Option<IpAddr> {
    match prefix.address {
        IpAddr::V4(network) => {
            let host_bits = 32 - prefix.prefix_length;
            let size = 1_u64 << host_bits;
            let first = u64::from(u32::from(network)) + u64::from(host_bits != 0);
            let usable = size.saturating_sub(if host_bits == 0 { 0 } else { 2 });
            let index = u64::try_from(index).ok()?;
            if index >= usable {
                return None;
            }
            Some(IpAddr::V4(Ipv4Addr::from(
                u32::try_from(first + index).ok()?,
            )))
        }
        IpAddr::V6(network) => {
            let host_bits = 128 - prefix.prefix_length;
            let first = u128::from(network) + u128::from(host_bits != 0);
            let index = u128::try_from(index).ok()?;
            let within = if host_bits == 0 {
                index == 0
            } else if host_bits == 128 {
                true
            } else {
                index < (1_u128 << host_bits).saturating_sub(1)
            };
            within.then(|| IpAddr::V6(Ipv6Addr::from(first + index)))
        }
    }
}

const fn prefix_mask_v4(prefix_length: u8) -> u32 {
    if prefix_length == 0 {
        0
    } else {
        u32::MAX << (32 - prefix_length)
    }
}

const fn prefix_mask_v6(prefix_length: u8) -> u128 {
    if prefix_length == 0 {
        0
    } else {
        u128::MAX << (128 - prefix_length)
    }
}

const fn address_family(address: IpAddr) -> AddressFamily {
    match address {
        IpAddr::V4(_) => AddressFamily::Ipv4,
        IpAddr::V6(_) => AddressFamily::Ipv6,
    }
}

fn valid_name(value: &str) -> bool {
    !value.is_empty() && value.len() <= 253
}

fn valid_uid(value: &str) -> bool {
    !value.is_empty() && value.len() <= 128
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ReachabilityNode {
    pub name: String,
    pub uid: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ReachabilityTarget {
    pub owner: LoadBalancerOwner,
    pub address: IpAddr,
    pub node: ReachabilityNode,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ReachabilitySnapshot {
    pub schema_version: u16,
    pub source_epoch: u64,
    pub revision: Revision,
    pub allocation_revision: Revision,
    pub provider: ReachabilityProviderRef,
    pub targets: Vec<ReachabilityTarget>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ReachabilityOutcome {
    Ready,
    Rejected,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ReachabilityAcknowledgement {
    pub schema_version: u16,
    pub source_epoch: u64,
    pub provider: ReachabilityProviderRef,
    pub desired_revision: Revision,
    pub applied_revision: Revision,
    pub outcome: ReachabilityOutcome,
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ReachabilityError {
    #[error("unsupported reachability schema {actual}; expected {expected}")]
    UnsupportedSchema { actual: u16, expected: u16 },
    #[error("reachability source epoch and revision must be nonzero")]
    ZeroRevision,
    #[error("reachability has {actual} nodes; limit is {limit}")]
    TooManyNodes { actual: usize, limit: usize },
    #[error("reachability has {actual} targets; limit is {limit}")]
    TooManyTargets { actual: usize, limit: usize },
    #[error("invalid reachability provider identity")]
    InvalidProvider,
    #[error("invalid or duplicate reachability Node {0:?}")]
    InvalidNode(ReachabilityNode),
    #[error("lease provider does not match the selected reachability provider")]
    ForeignLease,
    #[error("duplicate reachability target")]
    DuplicateTarget,
    #[error("reachability targets are incomplete or non-canonical")]
    NonCanonicalTargets,
    #[error("reachability acknowledgement does not match desired provider/revision")]
    AcknowledgementMismatch,
    #[error("reachability rejection must include a bounded error")]
    MissingRejectionError,
    #[error("node reachability projection does not match its exact Node identity")]
    NodeProjectionMismatch,
    #[error("node reachability revision regressed or mutated at one revision")]
    NodeRevisionConflict,
}

/// Compiles complete desired state for the bounded direct-Node provider.
///
/// Every active VIP is placed on every selected Node. External reachability is
/// supplied by the qualification environment; this provider does not pretend
/// to be BGP, L2 discovery, or a cloud load-balancer implementation.
///
/// # Errors
///
/// Rejects invalid provenance, foreign leases, duplicate Nodes/targets, zero
/// revisions, and target multiplication beyond the fixed global bound.
pub fn compile_direct_node_reachability(
    source_epoch: u64,
    revision: Revision,
    allocation_revision: Revision,
    provider: ReachabilityProviderRef,
    leases: &[LoadBalancerLease],
    mut nodes: Vec<ReachabilityNode>,
) -> Result<ReachabilitySnapshot, ReachabilityError> {
    validate_provider(&provider)?;
    if source_epoch == 0
        || revision == Revision::INITIAL
        || (!leases.is_empty() && allocation_revision == Revision::INITIAL)
    {
        return Err(ReachabilityError::ZeroRevision);
    }
    if nodes.len() > MAX_LOAD_BALANCER_NODES {
        return Err(ReachabilityError::TooManyNodes {
            actual: nodes.len(),
            limit: MAX_LOAD_BALANCER_NODES,
        });
    }
    nodes.sort();
    for pair in nodes.windows(2) {
        if pair[0] == pair[1] {
            return Err(ReachabilityError::InvalidNode(pair[0].clone()));
        }
    }
    if let Some(node) = nodes
        .iter()
        .find(|node| !valid_name(&node.name) || !valid_uid(&node.uid))
    {
        return Err(ReachabilityError::InvalidNode(node.clone()));
    }
    let target_count = leases
        .iter()
        .try_fold(0_usize, |count, lease| {
            count.checked_add(lease.addresses.len().saturating_mul(nodes.len()))
        })
        .unwrap_or(usize::MAX);
    if target_count > MAX_REACHABILITY_TARGETS {
        return Err(ReachabilityError::TooManyTargets {
            actual: target_count,
            limit: MAX_REACHABILITY_TARGETS,
        });
    }
    let mut targets = Vec::with_capacity(target_count);
    for lease in leases {
        if lease.provider != provider
            || validate_owner(&lease.owner).is_err()
            || lease.allocation_revision == Revision::INITIAL
            || lease.allocation_revision > allocation_revision
            || lease.addresses.is_empty()
            || lease.addresses.len() > 2
            || lease.addresses.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(ReachabilityError::ForeignLease);
        }
        for address in &lease.addresses {
            for node in &nodes {
                targets.push(ReachabilityTarget {
                    owner: lease.owner.clone(),
                    address: *address,
                    node: node.clone(),
                });
            }
        }
    }
    targets.sort();
    for pair in targets.windows(2) {
        if pair[0] == pair[1] {
            return Err(ReachabilityError::DuplicateTarget);
        }
    }
    Ok(ReachabilitySnapshot {
        schema_version: REACHABILITY_SNAPSHOT_SCHEMA_VERSION,
        source_epoch,
        revision,
        allocation_revision,
        provider,
        targets,
    })
}

impl ReachabilitySnapshot {
    /// Validates a decoded complete provider snapshot.
    ///
    /// # Errors
    ///
    /// Returns the same validation errors as direct-Node compilation.
    pub fn validate(self) -> Result<Self, ReachabilityError> {
        if self.schema_version != REACHABILITY_SNAPSHOT_SCHEMA_VERSION {
            return Err(ReachabilityError::UnsupportedSchema {
                actual: self.schema_version,
                expected: REACHABILITY_SNAPSHOT_SCHEMA_VERSION,
            });
        }
        let nodes = self
            .targets
            .iter()
            .map(|target| target.node.clone())
            .collect::<BTreeSet<_>>();
        let leases = reachability_leases(&self.targets, &self.provider);
        let expected = compile_direct_node_reachability(
            self.source_epoch,
            self.revision,
            self.allocation_revision,
            self.provider.clone(),
            &leases,
            nodes.into_iter().collect(),
        )?;
        if expected != self {
            return Err(ReachabilityError::NonCanonicalTargets);
        }
        Ok(self)
    }

    #[must_use]
    pub fn converged(&self, acknowledgement: &ReachabilityAcknowledgement) -> bool {
        acknowledgement.validate_for(self).is_ok()
            && acknowledgement.outcome == ReachabilityOutcome::Ready
    }
}

impl ReachabilityAcknowledgement {
    /// Validates acknowledgement provenance against one desired snapshot.
    ///
    /// # Errors
    ///
    /// Rejects schema/provenance/revision mismatch and malformed outcome/error
    /// combinations.
    pub fn validate_for(&self, desired: &ReachabilitySnapshot) -> Result<(), ReachabilityError> {
        if self.schema_version != REACHABILITY_ACK_SCHEMA_VERSION {
            return Err(ReachabilityError::UnsupportedSchema {
                actual: self.schema_version,
                expected: REACHABILITY_ACK_SCHEMA_VERSION,
            });
        }
        if self.source_epoch != desired.source_epoch
            || self.provider != desired.provider
            || self.desired_revision != desired.revision
            || self.applied_revision != desired.revision
        {
            return Err(ReachabilityError::AcknowledgementMismatch);
        }
        match (&self.outcome, &self.error) {
            (ReachabilityOutcome::Ready, None) => Ok(()),
            (ReachabilityOutcome::Rejected, Some(error))
                if !error.is_empty() && error.len() <= 512 =>
            {
                Ok(())
            }
            _ => Err(ReachabilityError::MissingRejectionError),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct NodeReachabilityTarget {
    pub owner: LoadBalancerOwner,
    pub address: IpAddr,
}

/// Complete owner-only reachability state distributed to one authenticated
/// Node. This is intentionally distinct from service and dataplane snapshots.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct NodeReachabilitySnapshot {
    pub schema_version: u16,
    pub source_epoch: u64,
    pub revision: Revision,
    pub allocation_revision: Revision,
    pub provider: ReachabilityProviderRef,
    pub node: ReachabilityNode,
    pub targets: Vec<NodeReachabilityTarget>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct NodeReachabilityCheckpoint {
    pub schema_version: u16,
    pub applied: NodeReachabilitySnapshot,
}

impl ReachabilitySnapshot {
    /// Projects complete provider intent to one authenticated Node identity.
    ///
    /// # Errors
    ///
    /// Rejects an invalid global snapshot, invalid Node identity, or any target
    /// whose matching Node name carries a different UID.
    pub fn for_node(
        &self,
        node_name: &str,
        node_uid: &str,
    ) -> Result<NodeReachabilitySnapshot, ReachabilityError> {
        self.clone().validate()?;
        let node = ReachabilityNode {
            name: node_name.to_owned(),
            uid: node_uid.to_owned(),
        };
        if !valid_name(node_name) || !valid_uid(node_uid) {
            return Err(ReachabilityError::InvalidNode(node));
        }
        if self
            .targets
            .iter()
            .any(|target| target.node.name == node_name && target.node.uid != node_uid)
        {
            return Err(ReachabilityError::NodeProjectionMismatch);
        }
        let targets = self
            .targets
            .iter()
            .filter(|target| target.node == node)
            .map(|target| NodeReachabilityTarget {
                owner: target.owner.clone(),
                address: target.address,
            })
            .collect();
        NodeReachabilitySnapshot {
            schema_version: NODE_REACHABILITY_SCHEMA_VERSION,
            source_epoch: self.source_epoch,
            revision: self.revision,
            allocation_revision: self.allocation_revision,
            provider: self.provider.clone(),
            node,
            targets,
        }
        .validate()
    }
}

impl NodeReachabilitySnapshot {
    /// Validates canonical bounded state before persistence or host staging.
    ///
    /// # Errors
    ///
    /// Rejects schema/provenance, Node identity, duplicate target, ordering, and
    /// revision violations.
    pub fn validate(mut self) -> Result<Self, ReachabilityError> {
        if self.schema_version != NODE_REACHABILITY_SCHEMA_VERSION {
            return Err(ReachabilityError::UnsupportedSchema {
                actual: self.schema_version,
                expected: NODE_REACHABILITY_SCHEMA_VERSION,
            });
        }
        validate_provider(&self.provider)?;
        if self.source_epoch == 0
            || self.revision == Revision::INITIAL
            || (!self.targets.is_empty() && self.allocation_revision == Revision::INITIAL)
        {
            return Err(ReachabilityError::ZeroRevision);
        }
        if !valid_name(&self.node.name) || !valid_uid(&self.node.uid) {
            return Err(ReachabilityError::InvalidNode(self.node));
        }
        if self.targets.len() > MAX_LOAD_BALANCER_LEASES.saturating_mul(2) {
            return Err(ReachabilityError::TooManyTargets {
                actual: self.targets.len(),
                limit: MAX_LOAD_BALANCER_LEASES.saturating_mul(2),
            });
        }
        for target in &self.targets {
            validate_owner(&target.owner).map_err(|_| ReachabilityError::ForeignLease)?;
        }
        let owner_families = self
            .targets
            .iter()
            .map(|target| (target.owner.clone(), address_family(target.address)))
            .collect::<BTreeSet<_>>();
        if owner_families.len() != self.targets.len() {
            return Err(ReachabilityError::ForeignLease);
        }
        let original = self.targets.clone();
        self.targets.sort();
        if self.targets != original || self.targets.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(ReachabilityError::NonCanonicalTargets);
        }
        Ok(self)
    }

    /// Fences replay, regression, and same-revision mutation against durable
    /// last-known-good state. A newer epoch or revision is an admissible change.
    ///
    /// # Errors
    ///
    /// Rejects any regression or mutation at the currently applied tuple.
    pub fn validate_transition(&self, applied: Option<&Self>) -> Result<bool, ReachabilityError> {
        self.clone().validate()?;
        let Some(applied) = applied else {
            return Ok(true);
        };
        applied.clone().validate()?;
        if self.source_epoch < applied.source_epoch
            || (self.source_epoch == applied.source_epoch && self.revision < applied.revision)
        {
            return Err(ReachabilityError::NodeRevisionConflict);
        }
        if self.source_epoch == applied.source_epoch && self.revision == applied.revision {
            if self == applied {
                return Ok(false);
            }
            return Err(ReachabilityError::NodeRevisionConflict);
        }
        Ok(true)
    }
}

impl NodeReachabilityCheckpoint {
    /// Validates an exact durable Node snapshot.
    ///
    /// # Errors
    ///
    /// Rejects unsupported checkpoint or embedded snapshot schemas.
    pub fn validate(self) -> Result<Self, ReachabilityError> {
        if self.schema_version != NODE_REACHABILITY_CHECKPOINT_SCHEMA_VERSION {
            return Err(ReachabilityError::UnsupportedSchema {
                actual: self.schema_version,
                expected: NODE_REACHABILITY_CHECKPOINT_SCHEMA_VERSION,
            });
        }
        self.applied.clone().validate()?;
        Ok(self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadBalancerDataplaneState {
    pub source_epoch: u64,
    pub service_revision: Revision,
    pub reachability_revision: Revision,
    pub allocation_revision: Revision,
    pub service_bank: u8,
    pub bank: u8,
    pub ipv4_frontends: BTreeMap<[u8; 8], [u8; 48]>,
    pub ipv6_frontends: BTreeMap<[u8; 20], [u8; 48]>,
    pub ipv4_source_ranges: BTreeMap<(u32, [u8; 12]), [u8; 32]>,
    pub ipv6_source_ranges: BTreeMap<(u32, [u8; 24]), [u8; 32]>,
    pub config: [u8; 48],
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum LoadBalancerDataplaneError {
    #[error("invalid service snapshot: {0}")]
    InvalidService(String),
    #[error("invalid selection contract: {0}")]
    InvalidSelectionContract(String),
    #[error("selection contract does not belong to the authenticated reachability Node")]
    SelectionNodeMismatch,
    #[error("selection contract contains behavior reserved for a later Phase 7 milestone")]
    UnsupportedSelectionBehavior,
    #[error("selection contract has no exact LoadBalancer plan")]
    MissingSelectionPlan,
    #[error(transparent)]
    InvalidReachability(#[from] ReachabilityError),
    #[error("service and reachability snapshots have different source epochs")]
    SourceEpochMismatch,
    #[error("invalid service bank {0}; expected 0 or 1")]
    InvalidServiceBank(u8),
    #[error("invalid LoadBalancer bank {0}; expected 0 or 1")]
    InvalidLoadBalancerBank(u8),
    #[error("reachability owner {0:?} has no exact schema-v3 Service")]
    MissingService(LoadBalancerOwner),
    #[error("reachability owner {0:?} does not match the referenced Service")]
    OwnerMismatch(LoadBalancerOwner),
    #[error("LoadBalancer frontend has no exact ClusterIP service-bank linkage")]
    MissingFrontendLink,
    #[error("VIP address {0} is owned by more than one Service")]
    AddressCollision(IpAddr),
    #[error("LoadBalancer frontend key collided")]
    FrontendCollision,
    #[error("LoadBalancer map {map} requires {actual} entries; per-bank limit is {limit}")]
    Capacity {
        map: &'static str,
        actual: usize,
        limit: usize,
    },
}

/// Lowers one authenticated Node projection into an inactive, readback-safe VIP
/// frontend bank. It does not activate or consume the bank in a packet path.
///
/// # Errors
///
/// Rejects invalid schemas, provenance, bank selectors, owner/address
/// collisions, inexact service linkage, and fixed map-capacity overflow.
#[allow(clippy::too_many_lines)]
pub fn compile_load_balancer_dataplane(
    services: &unf_service::ServiceSnapshot,
    reachability: &NodeReachabilitySnapshot,
    service_bank: u8,
    bank: u8,
) -> Result<LoadBalancerDataplaneState, LoadBalancerDataplaneError> {
    compile_load_balancer_dataplane_inner(services, reachability, None, service_bank, bank)
}

/// Lowers VIP frontends against one verified per-Node selection contract.
///
/// # Errors
///
/// Returns the ordinary `LoadBalancer` admission errors plus contract ownership,
/// integrity, exact-plan, and later-milestone behavior failures.
pub fn compile_load_balancer_selection_dataplane(
    services: &unf_service::ServiceSnapshot,
    reachability: &NodeReachabilitySnapshot,
    contract: &NetworkBehaviorContract,
    service_bank: u8,
    bank: u8,
) -> Result<LoadBalancerDataplaneState, LoadBalancerDataplaneError> {
    compile_load_balancer_dataplane_inner(
        services,
        reachability,
        Some(contract),
        service_bank,
        bank,
    )
}

#[allow(clippy::too_many_lines)]
fn compile_load_balancer_dataplane_inner(
    services: &unf_service::ServiceSnapshot,
    reachability: &NodeReachabilitySnapshot,
    contract: Option<&NetworkBehaviorContract>,
    service_bank: u8,
    bank: u8,
) -> Result<LoadBalancerDataplaneState, LoadBalancerDataplaneError> {
    let services = services
        .clone()
        .validate_and_normalize()
        .map_err(|error| LoadBalancerDataplaneError::InvalidService(error.to_string()))?;
    let reachability = reachability.clone().validate()?;
    if let Some(contract) = contract {
        if contract.node.name != reachability.node.name
            || contract.node.uid != reachability.node.uid
        {
            return Err(LoadBalancerDataplaneError::SelectionNodeMismatch);
        }
        contract
            .verify(&services, &contract.node)
            .map_err(|error| {
                LoadBalancerDataplaneError::InvalidSelectionContract(error.to_string())
            })?;
        if contract.plans.iter().any(|plan| {
            plan.session_affinity != ServiceSessionAffinity::None
                || plan.selection_algorithm != ServiceSelectionAlgorithm::StableHash
                || plan.forwarding_mode != ServiceForwardingMode::Nat
        }) {
            return Err(LoadBalancerDataplaneError::UnsupportedSelectionBehavior);
        }
    }
    if services.source_epoch != reachability.source_epoch {
        return Err(LoadBalancerDataplaneError::SourceEpochMismatch);
    }
    if service_bank >= SERVICE_BANK_COUNT {
        return Err(LoadBalancerDataplaneError::InvalidServiceBank(service_bank));
    }
    if bank >= LOAD_BALANCER_BANK_COUNT {
        return Err(LoadBalancerDataplaneError::InvalidLoadBalancerBank(bank));
    }
    let by_id = services
        .services
        .iter()
        .map(|service| (service.id, service))
        .collect::<BTreeMap<_, _>>();
    let mut address_owners = BTreeMap::<IpAddr, ServiceId>::new();
    let mut ipv4_frontends = BTreeMap::new();
    let mut ipv6_frontends = BTreeMap::new();
    let mut ipv4_source_ranges = BTreeMap::new();
    let mut ipv6_source_ranges = BTreeMap::new();
    let mut range_services = BTreeSet::new();
    for target in &reachability.targets {
        let service = by_id
            .get(&target.owner.service_id)
            .ok_or_else(|| LoadBalancerDataplaneError::MissingService(target.owner.clone()))?;
        if service.namespace != target.owner.namespace || service.name != target.owner.name {
            return Err(LoadBalancerDataplaneError::OwnerMismatch(
                target.owner.clone(),
            ));
        }
        if let Some(existing) = address_owners.insert(target.address, service.id)
            && existing != service.id
        {
            return Err(LoadBalancerDataplaneError::AddressCollision(target.address));
        }
        let load_balancer = service
            .load_balancer
            .as_ref()
            .ok_or_else(|| LoadBalancerDataplaneError::MissingService(target.owner.clone()))?;
        if range_services.insert(service.id) {
            for source_range in &load_balancer.source_ranges {
                let value = encode_load_balancer_source_range_value(
                    services.revision,
                    reachability.revision,
                    reachability.allocation_revision,
                );
                match source_range.address {
                    IpAddr::V4(address) => {
                        ipv4_source_ranges.insert(
                            (
                                64 + u32::from(source_range.prefix_length),
                                encode_ipv4_load_balancer_source_range_key(
                                    service.id,
                                    bank,
                                    address.octets(),
                                ),
                            ),
                            value,
                        );
                    }
                    IpAddr::V6(address) => {
                        ipv6_source_ranges.insert(
                            (
                                64 + u32::from(source_range.prefix_length),
                                encode_ipv6_load_balancer_source_range_key(
                                    service.id,
                                    bank,
                                    address.octets(),
                                ),
                            ),
                            value,
                        );
                    }
                }
            }
        }
        for frontend in load_balancer
            .frontends
            .iter()
            .filter(|frontend| frontend.family == address_family(target.address))
        {
            let matching = service
                .frontends
                .iter()
                .enumerate()
                .filter(|(_, candidate)| {
                    address_family(candidate.address) == frontend.family
                        && candidate.port == frontend.service_port
                        && candidate.protocol == frontend.protocol
                        && candidate.name == frontend.name
                        && candidate.app_protocol == frontend.app_protocol
                        && candidate.backend_ids == frontend.backend_ids
                })
                .collect::<Vec<_>>();
            if matching.len() != 1 {
                return Err(LoadBalancerDataplaneError::MissingFrontendLink);
            }
            let (cluster_frontend_index, _) = matching[0];
            let cluster_frontend_index = u32::try_from(cluster_frontend_index)
                .map_err(|_| LoadBalancerDataplaneError::MissingFrontendLink)?;
            let (frontend_index, backend_count, mut flags, selection_tier) =
                if let Some(contract) = contract {
                    let key = SelectionPlanKey {
                        service_id: service.id,
                        frontend: SelectionFrontend::LoadBalancer {
                            family: frontend.family,
                            service_port: frontend.service_port,
                            protocol: frontend.protocol,
                        },
                    };
                    let plan = contract
                        .plan(&key)
                        .ok_or(LoadBalancerDataplaneError::MissingSelectionPlan)?;
                    let selected = plan
                        .selected_tier()
                        .ok_or(LoadBalancerDataplaneError::MissingSelectionPlan)?;
                    let index = load_balancer_local_frontend_index(
                        service,
                        cluster_frontend_index as usize,
                        &reachability.node.name,
                    )
                    .ok_or(LoadBalancerDataplaneError::MissingFrontendLink)?;
                    (
                        index,
                        selected.backend_ids.len(),
                        if plan.traffic_policy == ServiceTrafficPolicy::Local {
                            LOAD_BALANCER_FRONTEND_FLAG_LOCAL
                        } else {
                            0
                        },
                        selection_tier_code(selected.tier),
                    )
                } else {
                    match load_balancer.traffic_policy {
                        unf_service::ServiceTrafficPolicy::Cluster => (
                            cluster_frontend_index,
                            frontend.backend_ids.len(),
                            0,
                            SERVICE_SELECTION_TIER_CLUSTER,
                        ),
                        unf_service::ServiceTrafficPolicy::Local => {
                            let local_index = load_balancer_local_frontend_index(
                                service,
                                cluster_frontend_index as usize,
                                &reachability.node.name,
                            )
                            .ok_or(LoadBalancerDataplaneError::MissingFrontendLink)?;
                            let backend_count = frontend
                                .backend_ids
                                .iter()
                                .filter(|backend_id| {
                                    service.backends.iter().any(|backend| {
                                        backend.id == **backend_id
                                            && backend.ready
                                            && !backend.terminating
                                            && backend.node_name.as_deref()
                                                == Some(reachability.node.name.as_str())
                                    })
                                })
                                .count();
                            (
                                local_index,
                                backend_count,
                                LOAD_BALANCER_FRONTEND_FLAG_LOCAL,
                                SERVICE_SELECTION_TIER_SAME_NODE,
                            )
                        }
                    }
                };
            if !load_balancer.source_ranges.is_empty() {
                flags |= LOAD_BALANCER_FRONTEND_FLAG_SOURCE_RANGES;
            }
            let value = encode_load_balancer_frontend_value(
                service.id,
                frontend_index,
                backend_count,
                flags,
                services.revision,
                reachability.revision,
                reachability.allocation_revision,
                service_bank,
                selection_tier,
            );
            let collision = match target.address {
                IpAddr::V4(address) => ipv4_frontends
                    .insert(
                        encode_ipv4_load_balancer_key(
                            address.octets(),
                            frontend.service_port,
                            frontend.protocol,
                            bank,
                        ),
                        value,
                    )
                    .is_some(),
                IpAddr::V6(address) => ipv6_frontends
                    .insert(
                        encode_ipv6_load_balancer_key(
                            address.octets(),
                            frontend.service_port,
                            frontend.protocol,
                            bank,
                        ),
                        value,
                    )
                    .is_some(),
            };
            if collision {
                return Err(LoadBalancerDataplaneError::FrontendCollision);
            }
        }
    }
    validate_load_balancer_capacity("LOAD_BALANCER_FRONTENDS_V4", ipv4_frontends.len())?;
    validate_load_balancer_capacity("LOAD_BALANCER_FRONTENDS_V6", ipv6_frontends.len())?;
    validate_load_balancer_capacity("LOAD_BALANCER_SOURCE_RANGES_V4", ipv4_source_ranges.len())?;
    validate_load_balancer_capacity("LOAD_BALANCER_SOURCE_RANGES_V6", ipv6_source_ranges.len())?;
    let config = encode_load_balancer_config(
        services.source_epoch,
        services.revision,
        reachability.revision,
        reachability.allocation_revision,
        ipv4_frontends.len(),
        ipv6_frontends.len(),
        bank,
        service_bank,
    );
    Ok(LoadBalancerDataplaneState {
        source_epoch: services.source_epoch,
        service_revision: services.revision,
        reachability_revision: reachability.revision,
        allocation_revision: reachability.allocation_revision,
        service_bank,
        bank,
        ipv4_frontends,
        ipv6_frontends,
        ipv4_source_ranges,
        ipv6_source_ranges,
        config,
    })
}

fn encode_ipv4_load_balancer_source_range_key(
    service_id: ServiceId,
    bank: u8,
    address: [u8; 4],
) -> [u8; 12] {
    let mut key = [0_u8; 12];
    key[0..4].copy_from_slice(&service_id.get().to_ne_bytes());
    key[4] = bank;
    key[8..12].copy_from_slice(&address);
    key
}

fn encode_ipv6_load_balancer_source_range_key(
    service_id: ServiceId,
    bank: u8,
    address: [u8; 16],
) -> [u8; 24] {
    let mut key = [0_u8; 24];
    key[0..4].copy_from_slice(&service_id.get().to_ne_bytes());
    key[4] = bank;
    key[8..24].copy_from_slice(&address);
    key
}

fn encode_load_balancer_source_range_value(
    service_revision: Revision,
    reachability_revision: Revision,
    allocation_revision: Revision,
) -> [u8; 32] {
    let mut value = [0_u8; 32];
    value[0..8].copy_from_slice(&service_revision.get().to_ne_bytes());
    value[8..16].copy_from_slice(&reachability_revision.get().to_ne_bytes());
    value[16..24].copy_from_slice(&allocation_revision.get().to_ne_bytes());
    value[24..26].copy_from_slice(&LOAD_BALANCER_MAP_ABI_VERSION.to_ne_bytes());
    value
}

fn encode_ipv4_load_balancer_key(
    address: [u8; 4],
    port: u16,
    protocol: unf_common::Protocol,
    bank: u8,
) -> [u8; 8] {
    let mut key = [0_u8; 8];
    key[0..4].copy_from_slice(&address);
    key[4..6].copy_from_slice(&port.to_be_bytes());
    key[6] = protocol as u8;
    key[7] = bank;
    key
}

fn encode_ipv6_load_balancer_key(
    address: [u8; 16],
    port: u16,
    protocol: unf_common::Protocol,
    bank: u8,
) -> [u8; 20] {
    let mut key = [0_u8; 20];
    key[0..16].copy_from_slice(&address);
    key[16..18].copy_from_slice(&port.to_be_bytes());
    key[18] = protocol as u8;
    key[19] = bank;
    key
}

const fn selection_tier_code(tier: SelectionTier) -> u8 {
    match tier {
        SelectionTier::SameNode => SERVICE_SELECTION_TIER_SAME_NODE,
        SelectionTier::SameZone => SERVICE_SELECTION_TIER_SAME_ZONE,
        SelectionTier::Cluster => SERVICE_SELECTION_TIER_CLUSTER,
    }
}

#[allow(clippy::too_many_arguments)]
fn encode_load_balancer_frontend_value(
    service_id: ServiceId,
    frontend_index: u32,
    backend_count: usize,
    flags: u16,
    service_revision: Revision,
    reachability_revision: Revision,
    allocation_revision: Revision,
    service_bank: u8,
    selection_tier: u8,
) -> [u8; 48] {
    let mut value = [0_u8; 48];
    value[0..4].copy_from_slice(&service_id.get().to_ne_bytes());
    value[4..8].copy_from_slice(&frontend_index.to_ne_bytes());
    value[8..12].copy_from_slice(&bounded_u32(backend_count).to_ne_bytes());
    value[12..14].copy_from_slice(&LOAD_BALANCER_MAP_ABI_VERSION.to_ne_bytes());
    value[14..16].copy_from_slice(&flags.to_ne_bytes());
    value[16..24].copy_from_slice(&service_revision.get().to_ne_bytes());
    value[24..32].copy_from_slice(&reachability_revision.get().to_ne_bytes());
    value[32..40].copy_from_slice(&allocation_revision.get().to_ne_bytes());
    value[40] = service_bank;
    value[41] = selection_tier;
    value
}

#[allow(clippy::too_many_arguments)]
fn encode_load_balancer_config(
    source_epoch: u64,
    service_revision: Revision,
    reachability_revision: Revision,
    allocation_revision: Revision,
    ipv4_count: usize,
    ipv6_count: usize,
    bank: u8,
    service_bank: u8,
) -> [u8; 48] {
    let mut config = [0_u8; 48];
    config[0..8].copy_from_slice(&source_epoch.to_ne_bytes());
    config[8..16].copy_from_slice(&service_revision.get().to_ne_bytes());
    config[16..24].copy_from_slice(&reachability_revision.get().to_ne_bytes());
    config[24..32].copy_from_slice(&allocation_revision.get().to_ne_bytes());
    config[32..36].copy_from_slice(&bounded_u32(ipv4_count).to_ne_bytes());
    config[36..40].copy_from_slice(&bounded_u32(ipv6_count).to_ne_bytes());
    config[40..42].copy_from_slice(&LOAD_BALANCER_MAP_ABI_VERSION.to_ne_bytes());
    config[42] = bank;
    config[43] = service_bank;
    config
}

fn validate_load_balancer_capacity(
    map: &'static str,
    actual: usize,
) -> Result<(), LoadBalancerDataplaneError> {
    if actual > LOAD_BALANCER_FRONTEND_BANK_CAPACITY {
        return Err(LoadBalancerDataplaneError::Capacity {
            map,
            actual,
            limit: LOAD_BALANCER_FRONTEND_BANK_CAPACITY,
        });
    }
    Ok(())
}

fn bounded_u32(value: usize) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}

fn reachability_leases(
    targets: &[ReachabilityTarget],
    provider: &ReachabilityProviderRef,
) -> Vec<LoadBalancerLease> {
    let mut owners = BTreeMap::<LoadBalancerOwner, BTreeSet<IpAddr>>::new();
    for target in targets {
        owners
            .entry(target.owner.clone())
            .or_default()
            .insert(target.address);
    }
    owners
        .into_iter()
        .map(|(owner, addresses)| {
            let addresses = addresses.into_iter().collect::<Vec<_>>();
            LoadBalancerLease {
                owner,
                pool: "validation-only".to_owned(),
                pool_uid: "validation-only".to_owned(),
                provider: provider.clone(),
                families: addresses.iter().copied().map(address_family).collect(),
                requested_ips: Vec::new(),
                addresses,
                intent_epoch: 1,
                intent_revision: Revision::new(1),
                allocation_revision: Revision::new(1),
            }
        })
        .collect()
}

fn validate_provider(provider: &ReachabilityProviderRef) -> Result<(), ReachabilityError> {
    if provider.mode != ReachabilityMode::DirectNode
        || !valid_name(&provider.name)
        || !valid_uid(&provider.instance)
    {
        return Err(ReachabilityError::InvalidProvider);
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublicationLifecycle {
    Active,
    Deleting,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublicationResourceState {
    Absent,
    Pending,
    Ready,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicationState {
    pub owner: LoadBalancerOwner,
    pub lifecycle: PublicationLifecycle,
    pub finalizer_present: bool,
    pub lease_addresses: Vec<IpAddr>,
    pub reachability: PublicationResourceState,
    pub dataplane: PublicationResourceState,
    pub published_addresses: Vec<IpAddr>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublicationAction {
    EnsureFinalizer,
    EnsureAllocation,
    EnsureReachability,
    EnsureDataplane,
    PublishStatus { addresses: Vec<IpAddr> },
    ClearStatus,
    WithdrawReachability,
    RemoveDataplane,
    ReleaseAllocation,
    RemoveFinalizer,
    Stable,
}

/// Returns exactly one next action for the fail-closed API transaction.
///
/// Publication waits for allocation, reachability, and dataplane readiness.
/// Deletion clears the external promise first, then withdraws reachability,
/// removes dataplane state, releases allocation, and removes the finalizer.
///
/// # Errors
///
/// Rejects invalid owner identity and internally inconsistent readiness.
pub fn next_publication_action(
    mut state: PublicationState,
) -> Result<PublicationAction, AllocationError> {
    validate_owner(&state.owner)?;
    state.lease_addresses.sort();
    state.published_addresses.sort();
    if state.lifecycle == PublicationLifecycle::Deleting {
        return Ok(if !state.published_addresses.is_empty() {
            PublicationAction::ClearStatus
        } else if state.reachability != PublicationResourceState::Absent {
            PublicationAction::WithdrawReachability
        } else if state.dataplane != PublicationResourceState::Absent {
            PublicationAction::RemoveDataplane
        } else if !state.lease_addresses.is_empty() {
            PublicationAction::ReleaseAllocation
        } else if state.finalizer_present {
            PublicationAction::RemoveFinalizer
        } else {
            PublicationAction::Stable
        });
    }
    Ok(if !state.finalizer_present {
        PublicationAction::EnsureFinalizer
    } else if state.lease_addresses.is_empty() {
        PublicationAction::EnsureAllocation
    } else if state.reachability != PublicationResourceState::Ready {
        PublicationAction::EnsureReachability
    } else if state.dataplane != PublicationResourceState::Ready {
        PublicationAction::EnsureDataplane
    } else if state.published_addresses != state.lease_addresses {
        PublicationAction::PublishStatus {
            addresses: state.lease_addresses,
        }
    } else {
        PublicationAction::Stable
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn provider() -> ReachabilityProviderRef {
        ReachabilityProviderRef {
            name: "direct-node".to_owned(),
            instance: "qualification-a".to_owned(),
            mode: ReachabilityMode::DirectNode,
        }
    }

    fn pool(name: &str, uid: &str, ipv4: &str, ipv6: &str) -> LoadBalancerPool {
        LoadBalancerPool {
            name: name.to_owned(),
            uid: uid.to_owned(),
            provider: provider(),
            ipv4: Some(ipv4.parse().unwrap()),
            ipv6: Some(ipv6.parse().unwrap()),
        }
    }

    fn owner(id: u32, name: &str) -> LoadBalancerOwner {
        LoadBalancerOwner {
            service_id: ServiceId::new(id),
            namespace: "default".to_owned(),
            name: name.to_owned(),
            uid: format!("{name}-uid"),
        }
    }

    fn request(
        owner: LoadBalancerOwner,
        revision: u64,
        requested_ips: Vec<IpAddr>,
    ) -> AllocationRequest {
        AllocationRequest {
            owner,
            pool: "public".to_owned(),
            families: vec![AddressFamily::Ipv6, AddressFamily::Ipv4],
            requested_ips,
            intent_epoch: 7,
            intent_revision: Revision::new(revision),
        }
    }

    #[test]
    fn allocation_is_deterministic_replayable_reusable_and_durable() {
        let pools = vec![pool(
            "public",
            "public-uid",
            "192.0.2.0/29",
            "2001:db8::/125",
        )];
        let mut allocator = LoadBalancerAllocator::new(pools).unwrap();
        let api = owner(10, "api");
        let first = allocator
            .allocate(request(api.clone(), 1, Vec::new()))
            .unwrap();
        assert_eq!(
            first.addresses,
            [
                "192.0.2.1".parse::<IpAddr>().unwrap(),
                "2001:db8::1".parse::<IpAddr>().unwrap()
            ]
        );
        assert_eq!(first.allocation_revision, Revision::new(1));
        let checkpoint = allocator.checkpoint();
        assert_eq!(
            allocator
                .allocate(request(api.clone(), 1, Vec::new()))
                .unwrap(),
            first
        );
        assert_eq!(allocator.checkpoint(), checkpoint);

        let refreshed = allocator
            .allocate(request(api.clone(), 2, Vec::new()))
            .unwrap();
        assert_eq!(refreshed.addresses, first.addresses);
        assert_eq!(refreshed.intent_revision, Revision::new(2));
        assert_eq!(refreshed.allocation_revision, Revision::new(2));

        let mut new_epoch = request(api.clone(), 1, Vec::new());
        new_epoch.intent_epoch = 8;
        let after_restart = allocator.allocate(new_epoch).unwrap();
        assert_eq!(after_restart.addresses, first.addresses);
        assert_eq!(after_restart.intent_epoch, 8);
        assert_eq!(after_restart.intent_revision, Revision::new(1));
        assert_eq!(after_restart.allocation_revision, Revision::new(3));
        assert!(matches!(
            allocator.allocate(request(api.clone(), 3, Vec::new())),
            Err(AllocationError::IntentRevisionRegression { .. })
        ));

        let web = owner(11, "web");
        let explicit = allocator
            .allocate(request(
                web.clone(),
                2,
                vec!["2001:db8::3".parse().unwrap(), "192.0.2.3".parse().unwrap()],
            ))
            .unwrap();
        assert_eq!(explicit.allocation_revision, Revision::new(4));
        let before_conflict = allocator.checkpoint();
        assert!(matches!(
            allocator.allocate(request(
                owner(12, "conflict"),
                2,
                vec!["192.0.2.3".parse().unwrap()]
            )),
            Err(AllocationError::AddressConflict { .. })
        ));
        assert_eq!(allocator.checkpoint(), before_conflict);

        allocator.release(&api).unwrap();
        let replacement = allocator
            .allocate(request(owner(13, "replacement"), 3, Vec::new()))
            .unwrap();
        assert_eq!(replacement.addresses, first.addresses);
        let encoded = serde_json::to_vec(&allocator.checkpoint()).unwrap();
        let decoded: AllocationCheckpoint = serde_json::from_slice(&encoded).unwrap();
        let restored = LoadBalancerAllocator::restore(decoded).unwrap();
        assert_eq!(restored.checkpoint(), allocator.checkpoint());
        assert_eq!(restored.lease(&web), Some(&explicit));

        let mut legacy = serde_json::to_value(allocator.checkpoint()).unwrap();
        legacy["schemaVersion"] = serde_json::json!(LEGACY_ALLOCATION_CHECKPOINT_SCHEMA_VERSION);
        for lease in legacy["leases"].as_array_mut().unwrap() {
            lease.as_object_mut().unwrap().remove("intentEpoch");
        }
        let legacy: AllocationCheckpoint = serde_json::from_value(legacy).unwrap();
        let migrated = LoadBalancerAllocator::restore(legacy).unwrap();
        assert_eq!(
            migrated.checkpoint().schema_version,
            ALLOCATION_CHECKPOINT_SCHEMA_VERSION
        );
        assert!(
            migrated
                .checkpoint()
                .leases
                .iter()
                .all(|lease| lease.intent_epoch == 1)
        );
    }

    #[test]
    fn allocation_rejects_overlap_drift_collision_and_exhaustion_atomically() {
        assert!(matches!(
            LoadBalancerAllocator::new(vec![
                pool("first", "first-uid", "192.0.2.0/29", "2001:db8::/125"),
                pool("second", "second-uid", "192.0.2.4/30", "2001:db8:1::/125")
            ]),
            Err(AllocationError::OverlappingPools { .. })
        ));

        let tiny = pool("public", "public-uid", "192.0.2.10/32", "2001:db8::10/128");
        let mut allocator = LoadBalancerAllocator::new(vec![tiny]).unwrap();
        allocator
            .allocate(request(owner(1, "one"), 1, Vec::new()))
            .unwrap();
        let retained = allocator.checkpoint();
        assert!(matches!(
            allocator.allocate(request(owner(2, "two"), 1, Vec::new())),
            Err(AllocationError::Exhausted { .. })
        ));
        assert_eq!(allocator.checkpoint(), retained);

        let mut corrupt = retained;
        corrupt.pools[0].uid = "foreign-uid".to_owned();
        assert!(matches!(
            LoadBalancerAllocator::restore(corrupt),
            Err(AllocationError::ForeignLease { .. })
        ));
    }

    #[test]
    fn direct_node_reachability_is_complete_revisioned_and_withdrawable() {
        let mut allocator = LoadBalancerAllocator::new(vec![pool(
            "public",
            "public-uid",
            "192.0.2.0/29",
            "2001:db8::/125",
        )])
        .unwrap();
        let api = owner(10, "api");
        let lease = allocator.allocate(request(api, 1, Vec::new())).unwrap();
        let nodes = vec![
            ReachabilityNode {
                name: "worker-b".to_owned(),
                uid: "worker-b-uid".to_owned(),
            },
            ReachabilityNode {
                name: "worker-a".to_owned(),
                uid: "worker-a-uid".to_owned(),
            },
        ];
        let desired = compile_direct_node_reachability(
            7,
            Revision::new(1),
            lease.allocation_revision,
            provider(),
            std::slice::from_ref(&lease),
            nodes.clone(),
        )
        .unwrap();
        assert_eq!(desired.targets.len(), 4);
        assert_eq!(desired.clone().validate().unwrap(), desired);
        let ready = ReachabilityAcknowledgement {
            schema_version: REACHABILITY_ACK_SCHEMA_VERSION,
            source_epoch: 7,
            provider: provider(),
            desired_revision: Revision::new(1),
            applied_revision: Revision::new(1),
            outcome: ReachabilityOutcome::Ready,
            error: None,
        };
        assert!(desired.converged(&ready));
        let mut stale = ready.clone();
        stale.applied_revision = Revision::new(0);
        assert!(!desired.converged(&stale));

        let withdrawn = compile_direct_node_reachability(
            7,
            Revision::new(2),
            allocator.checkpoint().revision,
            provider(),
            &[],
            nodes,
        )
        .unwrap();
        assert!(withdrawn.targets.is_empty());
        let mut withdrawn_ack = ready;
        withdrawn_ack.desired_revision = Revision::new(2);
        withdrawn_ack.applied_revision = Revision::new(2);
        assert!(withdrawn.converged(&withdrawn_ack));

        let mut malformed = desired;
        malformed.targets.pop();
        assert_eq!(
            malformed.validate(),
            Err(ReachabilityError::NonCanonicalTargets)
        );
    }

    #[test]
    fn authenticated_node_projection_is_strict_replayable_and_recoverable() {
        let mut allocator = LoadBalancerAllocator::new(vec![pool(
            "public",
            "public-uid",
            "192.0.2.0/29",
            "2001:db8::/125",
        )])
        .unwrap();
        let lease = allocator
            .allocate(request(owner(10, "api"), 1, Vec::new()))
            .unwrap();
        let nodes = vec![
            ReachabilityNode {
                name: "worker-a".to_owned(),
                uid: "worker-a-uid".to_owned(),
            },
            ReachabilityNode {
                name: "worker-b".to_owned(),
                uid: "worker-b-uid".to_owned(),
            },
        ];
        let desired = compile_direct_node_reachability(
            7,
            Revision::new(3),
            lease.allocation_revision,
            provider(),
            &[lease],
            nodes,
        )
        .unwrap();
        let worker = desired.for_node("worker-a", "worker-a-uid").unwrap();
        assert_eq!(worker.targets.len(), 2);
        assert!(
            worker
                .targets
                .iter()
                .all(|target| target.owner.name == "api")
        );
        assert!(!worker.validate_transition(Some(&worker)).unwrap());
        assert_eq!(
            desired.for_node("worker-a", "replacement-uid"),
            Err(ReachabilityError::NodeProjectionMismatch)
        );

        let checkpoint = NodeReachabilityCheckpoint {
            schema_version: NODE_REACHABILITY_CHECKPOINT_SCHEMA_VERSION,
            applied: worker.clone(),
        };
        let encoded = serde_json::to_vec(&checkpoint).unwrap();
        let restored: NodeReachabilityCheckpoint = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(restored.validate().unwrap(), checkpoint);

        let mut newer = worker.clone();
        newer.revision = Revision::new(4);
        assert!(newer.validate_transition(Some(&worker)).unwrap());
        let mut mutation = worker.clone();
        mutation.targets.pop();
        assert_eq!(
            mutation.validate_transition(Some(&worker)),
            Err(ReachabilityError::NodeRevisionConflict)
        );
        let mut regression = worker;
        regression.revision = Revision::new(2);
        assert_eq!(
            regression.validate_transition(Some(&newer)),
            Err(ReachabilityError::NodeRevisionConflict)
        );
    }

    #[test]
    #[allow(clippy::default_trait_access, clippy::too_many_lines)]
    fn load_balancer_host_bank_is_exact_banked_and_revision_bound() {
        let service_id = ServiceId::new(44);
        let frontends = vec![
            unf_service::ServiceFrontend {
                address: "10.96.0.10".parse().unwrap(),
                port: 80,
                protocol: unf_common::Protocol::Tcp,
                name: Some("http".to_owned()),
                app_protocol: None,
                backend_ids: Vec::new(),
            },
            unf_service::ServiceFrontend {
                address: "fd00:96::10".parse().unwrap(),
                port: 80,
                protocol: unf_common::Protocol::Tcp,
                name: Some("http".to_owned()),
                app_protocol: None,
                backend_ids: Vec::new(),
            },
        ];
        let load_balancer_frontends = vec![
            unf_service::ServiceLoadBalancerFrontend {
                family: AddressFamily::Ipv4,
                service_port: 80,
                protocol: unf_common::Protocol::Tcp,
                name: Some("http".to_owned()),
                app_protocol: None,
                backend_ids: Vec::new(),
            },
            unf_service::ServiceLoadBalancerFrontend {
                family: AddressFamily::Ipv6,
                service_port: 80,
                protocol: unf_common::Protocol::Tcp,
                name: Some("http".to_owned()),
                app_protocol: None,
                backend_ids: Vec::new(),
            },
        ];
        let services = unf_service::ServiceSnapshot {
            schema_version: unf_service::SERVICE_SNAPSHOT_SCHEMA_VERSION,
            source_epoch: 7,
            revision: Revision::new(5),
            services: vec![ServiceIr {
                id: service_id,
                namespace: "apps".to_owned(),
                name: "api".to_owned(),
                internal_traffic_policy: Default::default(),
                session_affinity: Default::default(),
                traffic_distribution: Default::default(),
                selection_algorithm: Default::default(),
                forwarding_mode: Default::default(),
                frontends,
                node_ports: Vec::new(),
                load_balancer: Some(unf_service::ServiceLoadBalancer {
                    class: UNF_LOAD_BALANCER_CLASS.to_owned(),
                    ip_families: vec![AddressFamily::Ipv4, AddressFamily::Ipv6],
                    ip_family_policy: unf_service::ServiceIpFamilyPolicy::RequireDualStack,
                    requested_ips: Vec::new(),
                    traffic_policy: unf_service::ServiceTrafficPolicy::Local,
                    source_ranges: vec![
                        "203.0.113.0/24".parse().unwrap(),
                        "2001:db8::/64".parse().unwrap(),
                    ],
                    allocate_node_ports: false,
                    health_check_node_port: None,
                    frontends: load_balancer_frontends,
                }),
                backends: Vec::new(),
            }],
        };
        let owner = LoadBalancerOwner {
            service_id,
            namespace: "apps".to_owned(),
            name: "api".to_owned(),
            uid: "api-uid".to_owned(),
        };
        let reachability = NodeReachabilitySnapshot {
            schema_version: NODE_REACHABILITY_SCHEMA_VERSION,
            source_epoch: 7,
            revision: Revision::new(4),
            allocation_revision: Revision::new(3),
            provider: provider(),
            node: ReachabilityNode {
                name: "worker-a".to_owned(),
                uid: "worker-a-uid".to_owned(),
            },
            targets: vec![
                NodeReachabilityTarget {
                    owner: owner.clone(),
                    address: "192.0.2.4".parse().unwrap(),
                },
                NodeReachabilityTarget {
                    owner,
                    address: "2001:db8::4".parse().unwrap(),
                },
            ],
        };
        let state = compile_load_balancer_dataplane(&services, &reachability, 1, 0).unwrap();
        assert_eq!(state.ipv4_frontends.len(), 1);
        assert_eq!(state.ipv6_frontends.len(), 1);
        assert_eq!(state.ipv4_source_ranges.len(), 1);
        assert_eq!(state.ipv6_source_ranges.len(), 1);
        assert_eq!(state.ipv4_source_ranges.keys().next().unwrap().0, 88);
        assert_eq!(state.ipv6_source_ranges.keys().next().unwrap().0, 128);
        assert_eq!(state.config[42], 0);
        assert_eq!(state.config[43], 1);
        assert_eq!(
            u64::from_ne_bytes(state.config[16..24].try_into().unwrap()),
            4
        );
        let v4_value = state.ipv4_frontends.values().next().unwrap();
        assert_eq!(u32::from_ne_bytes(v4_value[0..4].try_into().unwrap()), 44);
        assert_eq!(v4_value[40], 1);
        assert_eq!(
            u16::from_ne_bytes(v4_value[14..16].try_into().unwrap()),
            LOAD_BALANCER_FRONTEND_FLAG_LOCAL | LOAD_BALANCER_FRONTEND_FLAG_SOURCE_RANGES
        );
        assert_eq!(v4_value[41], SERVICE_SELECTION_TIER_SAME_NODE);

        let contract = NetworkBehaviorContract::compile(
            &services,
            Revision::new(6),
            Revision::new(7),
            unf_service::SelectionNode {
                name: "worker-a".to_owned(),
                uid: "worker-a-uid".to_owned(),
                zone: Some("zone-a".to_owned()),
                capabilities: BTreeSet::from([
                    unf_service::SelectionCapability::StableHash,
                    unf_service::SelectionCapability::Nat,
                ]),
            },
        )
        .unwrap();
        let selected =
            compile_load_balancer_selection_dataplane(&services, &reachability, &contract, 1, 1)
                .unwrap();
        assert!(
            selected
                .ipv4_frontends
                .values()
                .chain(selected.ipv6_frontends.values())
                .all(|value| value[41] == SERVICE_SELECTION_TIER_SAME_NODE)
        );

        let mut wrong_epoch = reachability.clone();
        wrong_epoch.source_epoch = 8;
        assert_eq!(
            compile_load_balancer_dataplane(&services, &wrong_epoch, 1, 0),
            Err(LoadBalancerDataplaneError::SourceEpochMismatch)
        );
        let mut foreign = reachability;
        foreign.targets[0].owner.service_id = ServiceId::new(45);
        foreign.targets.sort();
        assert!(matches!(
            compile_load_balancer_dataplane(&services, &foreign, 1, 0),
            Err(LoadBalancerDataplaneError::MissingService(_))
        ));
    }

    #[test]
    fn publication_waits_for_all_domains_and_deletes_in_safe_order() {
        let owner = owner(10, "api");
        let addresses = vec!["192.0.2.1".parse().unwrap()];
        let mut state = PublicationState {
            owner,
            lifecycle: PublicationLifecycle::Active,
            finalizer_present: false,
            lease_addresses: Vec::new(),
            reachability: PublicationResourceState::Absent,
            dataplane: PublicationResourceState::Absent,
            published_addresses: Vec::new(),
        };
        assert_eq!(
            next_publication_action(state.clone()).unwrap(),
            PublicationAction::EnsureFinalizer
        );
        state.finalizer_present = true;
        assert_eq!(
            next_publication_action(state.clone()).unwrap(),
            PublicationAction::EnsureAllocation
        );
        state.lease_addresses.clone_from(&addresses);
        assert_eq!(
            next_publication_action(state.clone()).unwrap(),
            PublicationAction::EnsureReachability
        );
        state.reachability = PublicationResourceState::Ready;
        assert_eq!(
            next_publication_action(state.clone()).unwrap(),
            PublicationAction::EnsureDataplane
        );
        state.dataplane = PublicationResourceState::Ready;
        assert_eq!(
            next_publication_action(state.clone()).unwrap(),
            PublicationAction::PublishStatus {
                addresses: addresses.clone()
            }
        );
        state.published_addresses.clone_from(&addresses);
        assert_eq!(
            next_publication_action(state.clone()).unwrap(),
            PublicationAction::Stable
        );

        state.lifecycle = PublicationLifecycle::Deleting;
        assert_eq!(
            next_publication_action(state.clone()).unwrap(),
            PublicationAction::ClearStatus
        );
        state.published_addresses.clear();
        assert_eq!(
            next_publication_action(state.clone()).unwrap(),
            PublicationAction::WithdrawReachability
        );
        state.reachability = PublicationResourceState::Absent;
        assert_eq!(
            next_publication_action(state.clone()).unwrap(),
            PublicationAction::RemoveDataplane
        );
        state.dataplane = PublicationResourceState::Absent;
        assert_eq!(
            next_publication_action(state.clone()).unwrap(),
            PublicationAction::ReleaseAllocation
        );
        state.lease_addresses.clear();
        assert_eq!(
            next_publication_action(state.clone()).unwrap(),
            PublicationAction::RemoveFinalizer
        );
        state.finalizer_present = false;
        assert_eq!(
            next_publication_action(state).unwrap(),
            PublicationAction::Stable
        );
    }

    #[test]
    #[allow(clippy::default_trait_access)]
    fn service_adapter_claims_only_explicit_class_and_preserves_exact_intent() {
        let mut service = ServiceIr {
            id: ServiceId::new(44),
            namespace: "apps".to_owned(),
            name: "api".to_owned(),
            internal_traffic_policy: Default::default(),
            session_affinity: Default::default(),
            traffic_distribution: Default::default(),
            selection_algorithm: Default::default(),
            forwarding_mode: Default::default(),
            frontends: Vec::new(),
            node_ports: Vec::new(),
            load_balancer: Some(unf_service::ServiceLoadBalancer {
                class: UNF_LOAD_BALANCER_CLASS.to_owned(),
                ip_families: vec![AddressFamily::Ipv4, AddressFamily::Ipv6],
                ip_family_policy: unf_service::ServiceIpFamilyPolicy::RequireDualStack,
                requested_ips: vec!["192.0.2.4".parse().unwrap(), "2001:db8::4".parse().unwrap()],
                traffic_policy: unf_service::ServiceTrafficPolicy::Cluster,
                source_ranges: Vec::new(),
                allocate_node_ports: false,
                health_check_node_port: None,
                frontends: Vec::new(),
            }),
            backends: Vec::new(),
        };
        let request =
            allocation_request_for_service(&service, "service-uid", "public", 7, Revision::new(9))
                .unwrap()
                .unwrap();
        assert_eq!(
            request.owner,
            LoadBalancerOwner {
                service_id: ServiceId::new(44),
                namespace: "apps".to_owned(),
                name: "api".to_owned(),
                uid: "service-uid".to_owned(),
            }
        );
        assert_eq!(
            request.families,
            vec![AddressFamily::Ipv4, AddressFamily::Ipv6]
        );
        assert_eq!(request.requested_ips.len(), 2);
        assert_eq!(request.intent_revision, Revision::new(9));

        service.load_balancer.as_mut().unwrap().class = "example.com/foreign".to_owned();
        assert_eq!(
            allocation_request_for_service(&service, "service-uid", "public", 7, Revision::new(9),)
                .unwrap(),
            None
        );
        service.load_balancer = None;
        assert_eq!(
            allocation_request_for_service(&service, "service-uid", "public", 7, Revision::new(9),)
                .unwrap(),
            None
        );
    }

    #[test]
    fn kubernetes_ownership_adapter_preserves_foreign_state_and_rejects_adoption() {
        let foreign_finalizer = "example.com/cloud-cleanup".to_owned();
        let observed_finalizers = vec![
            foreign_finalizer.clone(),
            UNF_LOAD_BALANCER_FINALIZER.to_owned(),
        ];
        assert_eq!(
            reconcile_finalizers(&observed_finalizers, false),
            vec![foreign_finalizer.clone()]
        );
        assert_eq!(
            reconcile_finalizers(std::slice::from_ref(&foreign_finalizer), true),
            vec![foreign_finalizer, UNF_LOAD_BALANCER_FINALIZER.to_owned()]
        );

        let old_v4 = "192.0.2.1".parse::<IpAddr>().unwrap();
        let new_v4 = "192.0.2.2".parse::<IpAddr>().unwrap();
        let new_v6 = "2001:db8::2".parse::<IpAddr>().unwrap();
        let existing = vec![
            StatusIngress {
                ip: None,
                hostname: Some("cloud.example.test".to_owned()),
            },
            StatusIngress {
                ip: Some(old_v4.to_string()),
                hostname: None,
            },
            StatusIngress {
                ip: Some("198.51.100.8".to_owned()),
                hostname: None,
            },
        ];
        let reconciled = reconcile_status_ingress(&existing, &[old_v4], &[new_v4, new_v6]).unwrap();
        assert_eq!(
            reconciled,
            vec![
                existing[0].clone(),
                existing[2].clone(),
                StatusIngress {
                    ip: Some(new_v4.to_string()),
                    hostname: None,
                },
                StatusIngress {
                    ip: Some(new_v6.to_string()),
                    hostname: None,
                },
            ]
        );
        assert!(matches!(
            reconcile_status_ingress(&existing, &[], &[old_v4]),
            Err(AllocationError::ForeignStatusAddress(address)) if address == old_v4
        ));
        assert_eq!(
            reconcile_status_ingress(&reconciled, &[new_v4, new_v6], &[]).unwrap(),
            vec![existing[0].clone(), existing[2].clone()]
        );
    }
}
