//! Capacity-bounded, failure-domain-aware egress gateway placement.
//!
//! Continuity-Certified Rendezvous (CCR) compiles expensive placement work in
//! userspace. The packet path consumes fixed assignments; it never evaluates
//! health, capacity, topology, or floating-point scores.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use unf_common::Revision;

use crate::{
    DEFAULT_EGRESS_INTENT_PRIORITY, EgressAddressLease, EgressAddressRequest, EgressDestinations,
    EgressIntent, EgressIntentOwner, EgressNode, EgressProviderRef, EgressSourceSelector,
    MAX_EGRESS_ADDRESSES_PER_INTENT, MAX_EGRESS_GATEWAY_NODES,
};

pub const EGRESS_HA_PLAN_SCHEMA_VERSION: u16 = 1;
pub const EGRESS_HA_ALGORITHM_CONTINUITY_CERTIFIED_RENDEZVOUS_V1: u16 = 1;
pub const MAX_EGRESS_HA_CAPACITY_UNITS: u16 = 10_000;
pub const MAX_EGRESS_HA_FAILURE_DOMAINS: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EgressHaCandidate {
    pub node: EgressNode,
    pub capacity_units: u16,
    pub failure_domains: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EgressAddressShard {
    pub index: u16,
    pub addresses: Vec<IpAddr>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EgressHaAssignment {
    pub shard_index: u16,
    pub gateway: EgressNode,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EgressHaCapacityTarget {
    pub gateway: EgressNode,
    pub capacity_units: u16,
    pub target_shards: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EgressHaDisruptionCertificate {
    pub moved_shards: u16,
    pub unavoidable_moves: u16,
    pub exact_capacity: bool,
    pub minimum_disruption: bool,
    pub domain_diverse_moves: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EgressHaDigest(pub [u8; 32]);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EgressHaContingency {
    pub failed_gateway: EgressNode,
    pub assignments: Vec<EgressHaAssignment>,
    pub capacity_targets: Vec<EgressHaCapacityTarget>,
    pub certificate: EgressHaDisruptionCertificate,
    pub digest: EgressHaDigest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EgressHaPlan {
    pub schema_version: u16,
    pub algorithm: u16,
    pub revision: Revision,
    pub owner: EgressIntentOwner,
    pub allocation_revision: Revision,
    pub lease_epoch: u64,
    pub candidates: Vec<EgressHaCandidate>,
    pub shards: Vec<EgressAddressShard>,
    pub assignments: Vec<EgressHaAssignment>,
    pub capacity_targets: Vec<EgressHaCapacityTarget>,
    pub contingencies: Vec<EgressHaContingency>,
    pub certificate: EgressHaDisruptionCertificate,
    pub membership_digest: EgressHaDigest,
    pub plan_digest: EgressHaDigest,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum EgressHaError {
    #[error("HA placement requires between two and {MAX_EGRESS_GATEWAY_NODES} exact gateways")]
    InvalidCandidateCount,
    #[error("HA gateway candidate {0:?} is invalid")]
    InvalidCandidate(String),
    #[error("HA gateway candidates contain duplicate Node name or UID")]
    DuplicateCandidate,
    #[error("HA placement revision, lease, or address set is invalid")]
    InvalidAuthority,
    #[error("previous HA placement is not an exact plan for this lease")]
    InvalidPreviousPlan,
    #[error("HA placement could not satisfy its exact capacity targets")]
    CapacityInvariant,
    #[error("HA placement encoding failed: {0}")]
    Encoding(String),
}

/// Compiles one deterministic active placement and a complete, pre-certified
/// assignment for every single-gateway failure.
///
/// Address ownership is sharded by ordinal: the first IPv4 and first IPv6
/// address form one dual-stack shard, the second pair forms another, and so on.
/// Each shard has exactly one active gateway, preventing duplicate L2 ownership.
///
/// When a previous plan is supplied, CCR retains the maximum number of legal
/// assignments under the new exact integer capacity targets. The disruption
/// certificate reports both the achieved and mathematical lower-bound move
/// counts; unequal values are rejected.
///
/// # Errors
///
/// Rejects malformed authority, candidates, previous state, capacity, or
/// nondeterministic/ambiguous ownership.
pub fn compile_egress_ha_plan(
    lease: &EgressAddressLease,
    mut candidates: Vec<EgressHaCandidate>,
    previous: Option<&EgressHaPlan>,
    revision: Revision,
) -> Result<EgressHaPlan, EgressHaError> {
    validate_authority(lease, revision)?;
    candidates.sort_unstable();
    validate_candidates(&candidates)?;
    let shards = address_shards(&lease.addresses)?;
    validate_previous(previous, lease, &shards)?;
    let previous_assignments = previous.map(|plan| plan.assignments.as_slice());
    let (assignments, capacity_targets, certificate) = compile_assignments(
        &lease.intent.owner,
        lease.lease_epoch,
        &shards,
        &candidates,
        previous_assignments,
        None,
    )?;
    let mut contingencies = Vec::with_capacity(candidates.len());
    for failed in &candidates {
        let survivors = candidates
            .iter()
            .filter(|candidate| candidate.node.uid != failed.node.uid)
            .cloned()
            .collect::<Vec<_>>();
        let (next, targets, certificate) = compile_assignments(
            &lease.intent.owner,
            lease.lease_epoch,
            &shards,
            &survivors,
            Some(&assignments),
            Some(failed),
        )?;
        let digest = digest(&(failed, &next, &targets, certificate))?;
        contingencies.push(EgressHaContingency {
            failed_gateway: failed.node.clone(),
            assignments: next,
            capacity_targets: targets,
            certificate,
            digest,
        });
    }
    let membership_digest = digest(&candidates)?;
    let mut plan = EgressHaPlan {
        schema_version: EGRESS_HA_PLAN_SCHEMA_VERSION,
        algorithm: EGRESS_HA_ALGORITHM_CONTINUITY_CERTIFIED_RENDEZVOUS_V1,
        revision,
        owner: lease.intent.owner.clone(),
        allocation_revision: lease.allocation_revision,
        lease_epoch: lease.lease_epoch,
        candidates,
        shards,
        assignments,
        capacity_targets,
        contingencies,
        certificate,
        membership_digest,
        plan_digest: EgressHaDigest([0; 32]),
    };
    plan.plan_digest = plan_material_digest(&plan)?;
    Ok(plan)
}

impl EgressHaPlan {
    /// Replays every internal assignment, capacity target, contingency, and
    /// digest when the enclosing transport already binds allocation identity.
    ///
    /// # Errors
    ///
    /// Rejects any malformed or mutated plan field.
    pub fn verify_integrity(&self) -> Result<(), EgressHaError> {
        if self.schema_version != EGRESS_HA_PLAN_SCHEMA_VERSION
            || self.algorithm != EGRESS_HA_ALGORITHM_CONTINUITY_CERTIFIED_RENDEZVOUS_V1
            || self.revision == Revision::INITIAL
        {
            return Err(EgressHaError::InvalidAuthority);
        }
        let addresses = self
            .shards
            .iter()
            .flat_map(|shard| shard.addresses.iter().copied())
            .collect::<Vec<_>>();
        let lease = EgressAddressLease {
            intent: EgressIntent {
                owner: self.owner.clone(),
                priority: DEFAULT_EGRESS_INTENT_PRIORITY,
                source: EgressSourceSelector::default(),
                destinations: EgressDestinations::Any,
                addresses: EgressAddressRequest::Explicit {
                    addresses: addresses.clone(),
                },
            },
            pool: None,
            provider: EgressProviderRef {
                name: "integrity".to_owned(),
                instance: "replay".to_owned(),
            },
            addresses,
            lease_epoch: self.lease_epoch,
            intent_epoch: 1,
            intent_revision: self.revision,
            allocation_revision: self.allocation_revision,
        };
        let expected_shards = address_shards(&lease.addresses)?;
        validate_previous(Some(self), &lease, &expected_shards)?;
        if !self.certificate.exact_capacity
            || !self.certificate.minimum_disruption
            || self.certificate.moved_shards != self.certificate.unavoidable_moves
            || usize::from(self.certificate.moved_shards) > self.shards.len()
        {
            return Err(EgressHaError::InvalidAuthority);
        }
        Ok(())
    }

    /// Recompiles and compares every assignment, contingency, certificate, and
    /// digest. Consumers do not trust serialized placement claims.
    ///
    /// # Errors
    ///
    /// Rejects any mutation or input mismatch.
    pub fn verify(
        &self,
        lease: &EgressAddressLease,
        previous: Option<&Self>,
    ) -> Result<(), EgressHaError> {
        if self.schema_version != EGRESS_HA_PLAN_SCHEMA_VERSION
            || self.algorithm != EGRESS_HA_ALGORITHM_CONTINUITY_CERTIFIED_RENDEZVOUS_V1
        {
            return Err(EgressHaError::InvalidAuthority);
        }
        let expected =
            compile_egress_ha_plan(lease, self.candidates.clone(), previous, self.revision)?;
        if &expected == self {
            Ok(())
        } else {
            Err(EgressHaError::InvalidAuthority)
        }
    }
}

fn validate_authority(lease: &EgressAddressLease, revision: Revision) -> Result<(), EgressHaError> {
    if revision == Revision::INITIAL
        || lease.allocation_revision == Revision::INITIAL
        || lease.lease_epoch == 0
        || lease.addresses.is_empty()
        || lease.addresses.len() > MAX_EGRESS_ADDRESSES_PER_INTENT
        || lease.addresses.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return Err(EgressHaError::InvalidAuthority);
    }
    Ok(())
}

fn validate_candidates(candidates: &[EgressHaCandidate]) -> Result<(), EgressHaError> {
    if !(2..=MAX_EGRESS_GATEWAY_NODES).contains(&candidates.len()) {
        return Err(EgressHaError::InvalidCandidateCount);
    }
    let mut names = BTreeSet::new();
    let mut uids = BTreeSet::new();
    for candidate in candidates {
        if candidate.node.name.is_empty()
            || candidate.node.name.len() > 253
            || candidate.node.uid.is_empty()
            || candidate.node.uid.len() > 128
            || candidate.capacity_units == 0
            || candidate.capacity_units > MAX_EGRESS_HA_CAPACITY_UNITS
            || candidate.failure_domains.len() > MAX_EGRESS_HA_FAILURE_DOMAINS
            || candidate.failure_domains.iter().any(|(name, value)| {
                name.is_empty()
                    || name.len() > 253
                    || value.is_empty()
                    || value.len() > 253
                    || !name.bytes().all(valid_domain_byte)
                    || !value.bytes().all(valid_domain_byte)
            })
        {
            return Err(EgressHaError::InvalidCandidate(candidate.node.name.clone()));
        }
        if !names.insert(candidate.node.name.as_str()) || !uids.insert(candidate.node.uid.as_str())
        {
            return Err(EgressHaError::DuplicateCandidate);
        }
    }
    Ok(())
}

const fn valid_domain_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b'/')
}

fn address_shards(addresses: &[IpAddr]) -> Result<Vec<EgressAddressShard>, EgressHaError> {
    let ipv4 = addresses
        .iter()
        .copied()
        .filter(IpAddr::is_ipv4)
        .collect::<Vec<_>>();
    let ipv6 = addresses
        .iter()
        .copied()
        .filter(IpAddr::is_ipv6)
        .collect::<Vec<_>>();
    let count = ipv4.len().max(ipv6.len());
    let mut shards = Vec::with_capacity(count);
    for index in 0..count {
        let mut shard_addresses = Vec::with_capacity(2);
        if let Some(address) = ipv4.get(index) {
            shard_addresses.push(*address);
        }
        if let Some(address) = ipv6.get(index) {
            shard_addresses.push(*address);
        }
        shards.push(EgressAddressShard {
            index: u16::try_from(index).map_err(|_| EgressHaError::InvalidAuthority)?,
            addresses: shard_addresses,
        });
    }
    Ok(shards)
}

fn validate_previous(
    previous: Option<&EgressHaPlan>,
    lease: &EgressAddressLease,
    shards: &[EgressAddressShard],
) -> Result<(), EgressHaError> {
    let Some(previous) = previous else {
        return Ok(());
    };
    if previous.schema_version != EGRESS_HA_PLAN_SCHEMA_VERSION
        || previous.algorithm != EGRESS_HA_ALGORITHM_CONTINUITY_CERTIFIED_RENDEZVOUS_V1
        || previous.owner != lease.intent.owner
        || previous.allocation_revision != lease.allocation_revision
        || previous.lease_epoch != lease.lease_epoch
        || previous.shards != shards
        || previous.assignments.len() != shards.len()
        || previous.membership_digest != digest(&previous.candidates)?
        || previous.plan_digest != plan_material_digest(previous)?
    {
        return Err(EgressHaError::InvalidPreviousPlan);
    }
    validate_candidates(&previous.candidates).map_err(|_| EgressHaError::InvalidPreviousPlan)?;
    let expected = shards
        .iter()
        .map(|shard| shard.index)
        .collect::<BTreeSet<_>>();
    let observed = previous
        .assignments
        .iter()
        .map(|assignment| assignment.shard_index)
        .collect::<BTreeSet<_>>();
    if expected != observed || observed.len() != previous.assignments.len() {
        return Err(EgressHaError::InvalidPreviousPlan);
    }
    let expected_targets = capacity_targets(
        &previous.owner,
        previous.lease_epoch,
        shards.len(),
        &previous.candidates,
    )?;
    if previous.capacity_targets != expected_targets
        || !assignments_match_targets(&previous.assignments, &expected_targets)
        || previous.contingencies.len() != previous.candidates.len()
    {
        return Err(EgressHaError::InvalidPreviousPlan);
    }
    for failed in &previous.candidates {
        let survivors = previous
            .candidates
            .iter()
            .filter(|candidate| candidate.node.uid != failed.node.uid)
            .cloned()
            .collect::<Vec<_>>();
        let (assignments, targets, certificate) = compile_assignments(
            &previous.owner,
            previous.lease_epoch,
            shards,
            &survivors,
            Some(&previous.assignments),
            Some(failed),
        )?;
        let expected_digest = digest(&(failed, &assignments, &targets, certificate))?;
        let contingency = previous
            .contingencies
            .iter()
            .find(|item| item.failed_gateway.uid == failed.node.uid)
            .ok_or(EgressHaError::InvalidPreviousPlan)?;
        if contingency.failed_gateway != failed.node
            || contingency.assignments != assignments
            || contingency.capacity_targets != targets
            || contingency.certificate != certificate
            || contingency.digest != expected_digest
        {
            return Err(EgressHaError::InvalidPreviousPlan);
        }
    }
    Ok(())
}

fn compile_assignments(
    owner: &EgressIntentOwner,
    lease_epoch: u64,
    shards: &[EgressAddressShard],
    candidates: &[EgressHaCandidate],
    previous: Option<&[EgressHaAssignment]>,
    failed: Option<&EgressHaCandidate>,
) -> Result<
    (
        Vec<EgressHaAssignment>,
        Vec<EgressHaCapacityTarget>,
        EgressHaDisruptionCertificate,
    ),
    EgressHaError,
> {
    if candidates.is_empty() {
        return Err(EgressHaError::CapacityInvariant);
    }
    let targets = capacity_targets(owner, lease_epoch, shards.len(), candidates)?;
    let target_by_uid = targets
        .iter()
        .map(|target| {
            (
                target.gateway.uid.clone(),
                usize::from(target.target_shards),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let (mut assigned, mut remaining, old_gateway_by_shard) = retain_previous_assignments(
        owner,
        lease_epoch,
        shards,
        candidates,
        previous,
        &target_by_uid,
    );
    let context = PlacementContext {
        owner,
        lease_epoch,
        candidates,
        failed,
    };
    let domain_diverse_moves = fill_unassigned_shards(
        &context,
        shards,
        &old_gateway_by_shard,
        &mut assigned,
        &mut remaining,
    )?;
    if remaining.values().any(|remaining| *remaining != 0) || assigned.len() != shards.len() {
        return Err(EgressHaError::CapacityInvariant);
    }
    let assignments = assigned
        .into_iter()
        .map(|(shard_index, gateway)| EgressHaAssignment {
            shard_index,
            gateway: gateway.node.clone(),
        })
        .collect::<Vec<_>>();
    let certificate = disruption_certificate(
        &assignments,
        &targets,
        previous,
        &target_by_uid,
        domain_diverse_moves,
    )?;
    if !certificate.exact_capacity || !certificate.minimum_disruption {
        return Err(EgressHaError::CapacityInvariant);
    }
    Ok((assignments, targets, certificate))
}

type CandidateAssignments<'a> = BTreeMap<u16, &'a EgressHaCandidate>;

struct PlacementContext<'a> {
    owner: &'a EgressIntentOwner,
    lease_epoch: u64,
    candidates: &'a [EgressHaCandidate],
    failed: Option<&'a EgressHaCandidate>,
}

fn retain_previous_assignments<'a>(
    owner: &EgressIntentOwner,
    lease_epoch: u64,
    shards: &[EgressAddressShard],
    candidates: &'a [EgressHaCandidate],
    previous: Option<&[EgressHaAssignment]>,
    targets: &BTreeMap<String, usize>,
) -> (
    CandidateAssignments<'a>,
    BTreeMap<String, usize>,
    BTreeMap<u16, String>,
) {
    let shard_indexes = shards
        .iter()
        .map(|shard| shard.index)
        .collect::<BTreeSet<_>>();
    let mut old_by_uid = BTreeMap::<String, Vec<u16>>::new();
    let mut old_gateway_by_shard = BTreeMap::new();
    for assignment in previous.into_iter().flatten() {
        if shard_indexes.contains(&assignment.shard_index) {
            old_by_uid
                .entry(assignment.gateway.uid.clone())
                .or_default()
                .push(assignment.shard_index);
            old_gateway_by_shard.insert(assignment.shard_index, assignment.gateway.uid.clone());
        }
    }
    let mut assigned = CandidateAssignments::new();
    let mut remaining = targets.clone();
    for candidate in candidates {
        let uid = &candidate.node.uid;
        let mut retained = old_by_uid.remove(uid).unwrap_or_default();
        retained.sort_by(|left, right| {
            score(
                b"unf.egress-ha-retain.v1\0",
                owner,
                lease_epoch,
                *right,
                uid.as_bytes(),
            )
            .cmp(&score(
                b"unf.egress-ha-retain.v1\0",
                owner,
                lease_epoch,
                *left,
                uid.as_bytes(),
            ))
            .then_with(|| left.cmp(right))
        });
        let target = targets.get(uid).copied().unwrap_or_default();
        let kept = retained.len().min(target);
        for shard in retained.into_iter().take(kept) {
            assigned.insert(shard, candidate);
        }
        remaining.insert(uid.clone(), target - kept);
    }
    (assigned, remaining, old_gateway_by_shard)
}

fn fill_unassigned_shards<'a>(
    context: &PlacementContext<'a>,
    shards: &[EgressAddressShard],
    old_gateway_by_shard: &BTreeMap<u16, String>,
    assigned: &mut CandidateAssignments<'a>,
    remaining: &mut BTreeMap<String, usize>,
) -> Result<usize, EgressHaError> {
    let mut unassigned = shards
        .iter()
        .filter(|shard| !assigned.contains_key(&shard.index))
        .map(|shard| shard.index)
        .collect::<Vec<_>>();
    unassigned.sort_by(|left, right| {
        score(
            b"unf.egress-ha-shard-order.v1\0",
            context.owner,
            context.lease_epoch,
            *right,
            b"order",
        )
        .cmp(&score(
            b"unf.egress-ha-shard-order.v1\0",
            context.owner,
            context.lease_epoch,
            *left,
            b"order",
        ))
        .then_with(|| left.cmp(right))
    });
    let mut domain_diverse_moves = 0;
    for shard in unassigned {
        let chosen = choose_candidate(context, shard, remaining)?;
        if let Some(failed) = context.failed
            && old_gateway_by_shard
                .get(&shard)
                .is_some_and(|uid| uid == &failed.node.uid)
            && domain_distance(failed, chosen) > 0
        {
            domain_diverse_moves += 1;
        }
        assigned.insert(shard, chosen);
        let slots = remaining
            .get_mut(&chosen.node.uid)
            .ok_or(EgressHaError::CapacityInvariant)?;
        *slots = slots
            .checked_sub(1)
            .ok_or(EgressHaError::CapacityInvariant)?;
    }
    Ok(domain_diverse_moves)
}

fn choose_candidate<'a>(
    context: &PlacementContext<'a>,
    shard: u16,
    remaining: &BTreeMap<String, usize>,
) -> Result<&'a EgressHaCandidate, EgressHaError> {
    context
        .candidates
        .iter()
        .filter(|candidate| remaining.get(&candidate.node.uid).copied().unwrap_or(0) > 0)
        .max_by(|left, right| {
            let left_diversity = context
                .failed
                .map_or(0, |failed| domain_distance(failed, left));
            let right_diversity = context
                .failed
                .map_or(0, |failed| domain_distance(failed, right));
            left_diversity
                .cmp(&right_diversity)
                .then_with(|| {
                    score(
                        b"unf.egress-ha-place.v1\0",
                        context.owner,
                        context.lease_epoch,
                        shard,
                        left.node.uid.as_bytes(),
                    )
                    .cmp(&score(
                        b"unf.egress-ha-place.v1\0",
                        context.owner,
                        context.lease_epoch,
                        shard,
                        right.node.uid.as_bytes(),
                    ))
                })
                .then_with(|| right.node.uid.cmp(&left.node.uid))
        })
        .ok_or(EgressHaError::CapacityInvariant)
}

fn disruption_certificate(
    assignments: &[EgressHaAssignment],
    targets: &[EgressHaCapacityTarget],
    previous: Option<&[EgressHaAssignment]>,
    target_by_uid: &BTreeMap<String, usize>,
    domain_diverse_moves: usize,
) -> Result<EgressHaDisruptionCertificate, EgressHaError> {
    let moved = previous.map_or(0, |previous| {
        previous
            .iter()
            .filter(|old| {
                assignments.iter().any(|new| {
                    new.shard_index == old.shard_index && new.gateway.uid != old.gateway.uid
                })
            })
            .count()
    });
    let unavoidable = previous.map_or(0, |previous| {
        let old_counts =
            previous
                .iter()
                .fold(BTreeMap::<&str, usize>::new(), |mut counts, item| {
                    *counts.entry(item.gateway.uid.as_str()).or_default() += 1;
                    counts
                });
        old_counts
            .iter()
            .map(|(uid, count)| count.saturating_sub(target_by_uid.get(*uid).copied().unwrap_or(0)))
            .sum()
    });
    let exact_capacity = assignments_match_targets(assignments, targets);
    Ok(EgressHaDisruptionCertificate {
        moved_shards: u16::try_from(moved).map_err(|_| EgressHaError::CapacityInvariant)?,
        unavoidable_moves: u16::try_from(unavoidable)
            .map_err(|_| EgressHaError::CapacityInvariant)?,
        exact_capacity,
        minimum_disruption: moved == unavoidable,
        domain_diverse_moves: u16::try_from(domain_diverse_moves)
            .map_err(|_| EgressHaError::CapacityInvariant)?,
    })
}

fn assignments_match_targets(
    assignments: &[EgressHaAssignment],
    targets: &[EgressHaCapacityTarget],
) -> bool {
    assignments.len()
        == targets
            .iter()
            .map(|target| usize::from(target.target_shards))
            .sum::<usize>()
        && assignments.iter().all(|assignment| {
            targets
                .iter()
                .any(|target| target.gateway == assignment.gateway)
        })
        && targets.iter().all(|target| {
            assignments
                .iter()
                .filter(|assignment| assignment.gateway == target.gateway)
                .count()
                == usize::from(target.target_shards)
        })
}

fn capacity_targets(
    owner: &EgressIntentOwner,
    lease_epoch: u64,
    shard_count: usize,
    candidates: &[EgressHaCandidate],
) -> Result<Vec<EgressHaCapacityTarget>, EgressHaError> {
    let total_capacity = candidates
        .iter()
        .map(|candidate| u64::from(candidate.capacity_units))
        .sum::<u64>();
    if total_capacity == 0 {
        return Err(EgressHaError::CapacityInvariant);
    }
    let shard_count_u64 =
        u64::try_from(shard_count).map_err(|_| EgressHaError::CapacityInvariant)?;
    let mut targets = candidates
        .iter()
        .map(|candidate| {
            let numerator = shard_count_u64 * u64::from(candidate.capacity_units);
            (
                candidate,
                numerator / total_capacity,
                numerator % total_capacity,
            )
        })
        .collect::<Vec<_>>();
    let assigned = targets.iter().map(|(_, target, _)| *target).sum::<u64>();
    let extras = usize::try_from(shard_count_u64 - assigned)
        .map_err(|_| EgressHaError::CapacityInvariant)?;
    targets.sort_by(|left, right| {
        right
            .2
            .cmp(&left.2)
            .then_with(|| {
                score(
                    b"unf.egress-ha-capacity-remainder.v1\0",
                    owner,
                    lease_epoch,
                    0,
                    right.0.node.uid.as_bytes(),
                )
                .cmp(&score(
                    b"unf.egress-ha-capacity-remainder.v1\0",
                    owner,
                    lease_epoch,
                    0,
                    left.0.node.uid.as_bytes(),
                ))
            })
            .then_with(|| left.0.node.uid.cmp(&right.0.node.uid))
    });
    for (_, target, _) in targets.iter_mut().take(extras) {
        *target += 1;
    }
    targets.sort_by(|left, right| left.0.cmp(right.0));
    targets
        .into_iter()
        .map(|(candidate, target, _)| {
            Ok(EgressHaCapacityTarget {
                gateway: candidate.node.clone(),
                capacity_units: candidate.capacity_units,
                target_shards: u16::try_from(target)
                    .map_err(|_| EgressHaError::CapacityInvariant)?,
            })
        })
        .collect()
}

fn domain_distance(left: &EgressHaCandidate, right: &EgressHaCandidate) -> usize {
    left.failure_domains
        .iter()
        .filter(|(name, value)| {
            right
                .failure_domains
                .get(*name)
                .is_some_and(|candidate| candidate != *value)
        })
        .count()
}

fn score(
    domain: &[u8],
    owner: &EgressIntentOwner,
    lease_epoch: u64,
    shard: u16,
    candidate: &[u8],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(owner.uid.as_bytes());
    hasher.update(lease_epoch.to_be_bytes());
    hasher.update(shard.to_be_bytes());
    hasher.update(candidate);
    hasher.finalize().into()
}

fn digest<T: Serialize>(value: &T) -> Result<EgressHaDigest, EgressHaError> {
    let bytes =
        serde_json::to_vec(value).map_err(|error| EgressHaError::Encoding(error.to_string()))?;
    let mut hasher = Sha256::new();
    hasher.update(b"unf.egress-ha-continuity-certificate.v1\0");
    hasher.update(bytes);
    Ok(EgressHaDigest(hasher.finalize().into()))
}

fn plan_material_digest(plan: &EgressHaPlan) -> Result<EgressHaDigest, EgressHaError> {
    digest(&(
        plan.schema_version,
        plan.algorithm,
        plan.revision,
        &plan.owner,
        plan.allocation_revision,
        plan.lease_epoch,
        &plan.candidates,
        &plan.shards,
        &plan.assignments,
        &plan.capacity_targets,
        &plan.contingencies,
        plan.certificate,
        plan.membership_digest,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AddressFamily, DEFAULT_EGRESS_INTENT_PRIORITY, EgressAddressRequest, EgressCapability,
        EgressDestinations, EgressIntent, EgressIntentScope, EgressProviderRef,
        EgressSourceSelector,
    };

    fn lease(addresses_per_family: u16) -> EgressAddressLease {
        let mut addresses = (0..addresses_per_family)
            .map(|index| format!("192.0.2.{}", 20 + index).parse().unwrap())
            .collect::<Vec<IpAddr>>();
        addresses.extend((0..addresses_per_family).map(|index| {
            format!("2001:db8::{}", 20 + index)
                .parse::<IpAddr>()
                .unwrap()
        }));
        let owner = EgressIntentOwner {
            scope: EgressIntentScope::Cluster,
            name: "payments".to_owned(),
            uid: "uid-payments".to_owned(),
        };
        EgressAddressLease {
            intent: EgressIntent {
                owner,
                priority: DEFAULT_EGRESS_INTENT_PRIORITY,
                source: EgressSourceSelector::default(),
                destinations: EgressDestinations::Any,
                addresses: EgressAddressRequest::Pool {
                    name: "public".to_owned(),
                    families: vec![AddressFamily::Ipv4, AddressFamily::Ipv6],
                    addresses_per_family,
                },
            },
            pool: None,
            provider: EgressProviderRef {
                name: "static".to_owned(),
                instance: "lab".to_owned(),
            },
            addresses,
            lease_epoch: 7,
            intent_epoch: 1,
            intent_revision: Revision::new(2),
            allocation_revision: Revision::new(3),
        }
    }

    fn candidate(name: &str, capacity: u16, zone: &str, rack: &str) -> EgressHaCandidate {
        EgressHaCandidate {
            node: EgressNode {
                name: name.to_owned(),
                uid: format!("uid-{name}"),
                capabilities: BTreeSet::from([
                    EgressCapability::LeaseEpochFencing,
                    EgressCapability::Ipv4TcpUdpNat,
                    EgressCapability::Ipv6TcpUdpNat,
                ]),
            },
            capacity_units: capacity,
            failure_domains: BTreeMap::from([
                ("topology.kubernetes.io/zone".to_owned(), zone.to_owned()),
                ("network.unf.io/rack".to_owned(), rack.to_owned()),
            ]),
        }
    }

    fn candidates() -> Vec<EgressHaCandidate> {
        vec![
            candidate("gateway-a", 2, "zone-a", "rack-a"),
            candidate("gateway-b", 1, "zone-b", "rack-b"),
            candidate("gateway-c", 1, "zone-a", "rack-c"),
        ]
    }

    #[test]
    fn dual_stack_addresses_form_one_exclusive_shard_per_ordinal() {
        let lease = lease(4);
        let plan = compile_egress_ha_plan(&lease, candidates(), None, Revision::new(1)).unwrap();
        assert_eq!(plan.shards.len(), 4);
        assert!(plan.shards.iter().all(|shard| shard.addresses.len() == 2));
        assert_eq!(plan.assignments.len(), plan.shards.len());
        assert_eq!(
            plan.capacity_targets
                .iter()
                .map(|item| item.target_shards)
                .collect::<Vec<_>>(),
            vec![2, 1, 1]
        );
        assert!(plan.certificate.exact_capacity);
        assert!(plan.certificate.minimum_disruption);
        plan.verify(&lease, None).unwrap();
    }

    #[test]
    fn single_failure_contingencies_are_capacity_exact_minimal_and_domain_aware() {
        let lease = lease(8);
        let plan = compile_egress_ha_plan(&lease, candidates(), None, Revision::new(4)).unwrap();
        for contingency in &plan.contingencies {
            assert_eq!(contingency.assignments.len(), plan.shards.len());
            assert!(contingency.certificate.exact_capacity);
            assert!(contingency.certificate.minimum_disruption);
            assert_eq!(
                contingency.certificate.moved_shards,
                contingency.certificate.unavoidable_moves
            );
            assert!(
                contingency
                    .assignments
                    .iter()
                    .all(|assignment| assignment.gateway.uid != contingency.failed_gateway.uid)
            );
        }
        let failed_a = plan
            .contingencies
            .iter()
            .find(|item| item.failed_gateway.name == "gateway-a")
            .unwrap();
        assert!(failed_a.certificate.domain_diverse_moves > 0);
    }

    #[test]
    fn capacity_change_moves_only_the_mathematical_minimum() {
        let lease = lease(8);
        let first = compile_egress_ha_plan(&lease, candidates(), None, Revision::new(8)).unwrap();
        let changed = vec![
            candidate("gateway-a", 1, "zone-a", "rack-a"),
            candidate("gateway-b", 2, "zone-b", "rack-b"),
            candidate("gateway-c", 1, "zone-a", "rack-c"),
        ];
        let second =
            compile_egress_ha_plan(&lease, changed, Some(&first), Revision::new(9)).unwrap();
        assert_eq!(second.certificate.moved_shards, 2);
        assert_eq!(second.certificate.unavoidable_moves, 2);
        assert!(second.certificate.minimum_disruption);
        second.verify(&lease, Some(&first)).unwrap();
    }

    #[test]
    fn candidate_reordering_is_byte_deterministic_and_mutation_fails_replay() {
        let lease = lease(4);
        let mut reversed = candidates();
        reversed.reverse();
        let left = compile_egress_ha_plan(&lease, candidates(), None, Revision::new(12)).unwrap();
        let right = compile_egress_ha_plan(&lease, reversed, None, Revision::new(12)).unwrap();
        assert_eq!(left, right);
        assert_eq!(
            serde_json::to_vec(&left).unwrap(),
            serde_json::to_vec(&right).unwrap()
        );

        let mut mutated = left.clone();
        mutated.contingencies[0].certificate.moved_shards += 1;
        assert_eq!(
            mutated.verify(&lease, None),
            Err(EgressHaError::InvalidAuthority)
        );
    }

    #[test]
    fn duplicate_identity_bad_capacity_and_foreign_previous_plan_fail_closed() {
        let lease = lease(2);
        let mut duplicate = candidates();
        duplicate[1].node.uid = duplicate[0].node.uid.clone();
        assert_eq!(
            compile_egress_ha_plan(&lease, duplicate, None, Revision::new(1)),
            Err(EgressHaError::DuplicateCandidate)
        );
        let mut invalid = candidates();
        invalid[0].capacity_units = 0;
        assert!(matches!(
            compile_egress_ha_plan(&lease, invalid, None, Revision::new(1)),
            Err(EgressHaError::InvalidCandidate(_))
        ));
        let first = compile_egress_ha_plan(&lease, candidates(), None, Revision::new(1)).unwrap();
        let mut forged = first.clone();
        forged.contingencies[0].certificate.moved_shards += 1;
        forged.plan_digest = plan_material_digest(&forged).unwrap();
        assert_eq!(
            compile_egress_ha_plan(&lease, candidates(), Some(&forged), Revision::new(2)),
            Err(EgressHaError::InvalidPreviousPlan)
        );
        let mut replacement = lease.clone();
        replacement.lease_epoch += 1;
        assert_eq!(
            compile_egress_ha_plan(&replacement, candidates(), Some(&first), Revision::new(2)),
            Err(EgressHaError::InvalidPreviousPlan)
        );
    }
}
