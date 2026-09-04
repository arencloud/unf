//! Bounded, provenance-carrying DNS destination evidence.
//!
//! DNS names are policy selectors, never workload identity. The compiler keeps
//! split-horizon views separate and turns matching observations into short-lived
//! address leases. Packet processing will consume only independently verified
//! leases; it never parses names, DNS packets, or TTLs.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use unf_common::Revision;

use crate::{EgressIntentOwner, EgressIntentScope};

pub const EGRESS_FQDN_EVIDENCE_SCHEMA_VERSION: u16 = 1;
pub const EGRESS_FQDN_ALGORITHM_PROVENANCE_LEASED_RESOLUTION_V1: u16 = 1;
pub const MAX_EGRESS_FQDN_PATTERNS: usize = 256;
pub const MAX_EGRESS_FQDN_OBSERVATIONS: usize = 4_096;
pub const MAX_EGRESS_FQDN_ANSWERS_PER_OBSERVATION: usize = 64;
pub const MAX_EGRESS_FQDN_CNAME_DEPTH: usize = 16;
pub const MAX_EGRESS_FQDN_OBSERVERS: u16 = 16;
pub const MAX_EGRESS_FQDN_ADDRESSES: u16 = 4_096;
pub const MAX_EGRESS_FQDN_TTL_SECONDS: u32 = 604_800;
pub const MAX_EGRESS_FQDN_ESTABLISHED_GRACE_SECONDS: u32 = 3_600;
pub const MAX_EGRESS_FQDN_FUTURE_SKEW_SECONDS: u64 = 30;

const FQDN_DIGEST_DOMAIN: &[u8] = b"unf.egress.fqdn.provenance-leased-resolution.v1\0";

type FqdnLeaseKey = (String, IpAddr);
type FqdnEvidenceGroups = BTreeMap<FqdnLeaseKey, Vec<EgressFqdnLeaseProvenance>>;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(
    deny_unknown_fields,
    rename_all = "camelCase",
    tag = "kind",
    content = "name"
)]
pub enum EgressFqdnPattern {
    Exact(String),
    /// Matches one or more complete labels before this suffix, but never the
    /// suffix apex. For example, `*.example.test` matches `a.b.example.test`
    /// and not `example.test` or `badexample.test`.
    WildcardSuffix(String),
}

impl EgressFqdnPattern {
    /// Parses an ASCII DNS name or one unambiguous leading-label wildcard.
    /// Unicode input is rejected; callers must supply its DNS A-label form.
    ///
    /// # Errors
    ///
    /// Rejects malformed names, ambiguous wildcard placement, and TLD-wide
    /// wildcards.
    pub fn parse(value: &str) -> Result<Self, EgressFqdnError> {
        let value = value.strip_suffix('.').unwrap_or(value);
        if let Some(suffix) = value.strip_prefix("*.") {
            if suffix.contains('*') {
                return Err(EgressFqdnError::InvalidPattern(value.to_owned()));
            }
            let suffix = normalize_dns_name(suffix)?;
            if suffix.split('.').count() < 2 {
                return Err(EgressFqdnError::InvalidPattern(value.to_owned()));
            }
            return Ok(Self::WildcardSuffix(suffix));
        }
        if value.contains('*') {
            return Err(EgressFqdnError::InvalidPattern(value.to_owned()));
        }
        Ok(Self::Exact(normalize_dns_name(value)?))
    }

    #[must_use]
    pub fn matches(&self, normalized_name: &str) -> bool {
        match self {
            Self::Exact(name) => name == normalized_name,
            Self::WildcardSuffix(suffix) => {
                normalized_name.len() > suffix.len()
                    && normalized_name.ends_with(suffix)
                    && normalized_name.as_bytes()[normalized_name.len() - suffix.len() - 1] == b'.'
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EgressFqdnPolicy {
    pub revision: Revision,
    pub owner: EgressIntentOwner,
    pub patterns: Vec<EgressFqdnPattern>,
    /// An explicit resolver/tenant view. Observations from other views never
    /// contribute to this policy's quorum.
    pub view: String,
    pub required_observers: u16,
    pub max_addresses: u16,
    pub max_ttl_seconds: u32,
    pub established_flow_grace_seconds: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EgressDnsObservationSource {
    pub observer_uid: String,
    pub resolver: IpAddr,
    pub view: String,
    pub source_epoch: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EgressDnsAnswer {
    pub address: IpAddr,
    pub ttl_seconds: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EgressDnsObservation {
    pub source: EgressDnsObservationSource,
    pub observation_revision: Revision,
    pub query_name: String,
    /// The first item must be the query name. Each following item is the next
    /// canonical name; duplicate names are rejected as a loop.
    pub canonical_chain: Vec<String>,
    pub answers: Vec<EgressDnsAnswer>,
    pub observed_at_unix_seconds: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EgressFqdnLeaseProvenance {
    pub source: EgressDnsObservationSource,
    pub observation_revision: Revision,
    pub canonical_chain: Vec<String>,
    pub observed_at_unix_seconds: u64,
    pub ttl_seconds: u32,
    pub expires_at_unix_seconds: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EgressFqdnDestinationLease {
    pub query_name: String,
    pub matched_patterns: Vec<EgressFqdnPattern>,
    pub address: IpAddr,
    /// New flows are authorized strictly before this instant.
    pub new_flows_until_unix_seconds: u64,
    /// Existing flows may drain strictly before this instant.
    pub established_flows_until_unix_seconds: u64,
    pub provenance: Vec<EgressFqdnLeaseProvenance>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EgressFqdnSnapshotDigest(pub [u8; 32]);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EgressFqdnSnapshot {
    pub schema_version: u16,
    pub algorithm: u16,
    pub compiled_at_unix_seconds: u64,
    pub policy: EgressFqdnPolicy,
    pub leases: Vec<EgressFqdnDestinationLease>,
    pub digest: EgressFqdnSnapshotDigest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedEgressFqdnSnapshot(EgressFqdnSnapshot);

impl VerifiedEgressFqdnSnapshot {
    #[must_use]
    pub const fn snapshot(&self) -> &EgressFqdnSnapshot {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EgressFqdnCompilationReport {
    pub accepted_observations: u32,
    pub wrong_view_observations: u32,
    pub unmatched_name_observations: u32,
    pub zero_ttl_answers: u32,
    pub below_quorum_destinations: u32,
    pub admitted_destinations: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EgressFqdnCompilation {
    pub snapshot: EgressFqdnSnapshot,
    pub report: EgressFqdnCompilationReport,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EgressFqdnFlowClass {
    New,
    Established,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EgressFqdnDenyReason {
    NoDestinationEvidence,
    NewFlowEvidenceExpired,
    EstablishedFlowEvidenceExpired,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EgressFqdnDecision {
    AllowActive {
        query_name: String,
        patterns: Vec<EgressFqdnPattern>,
        until_unix_seconds: u64,
        snapshot_digest: EgressFqdnSnapshotDigest,
    },
    AllowEstablishedDrain {
        query_name: String,
        patterns: Vec<EgressFqdnPattern>,
        until_unix_seconds: u64,
        snapshot_digest: EgressFqdnSnapshotDigest,
    },
    Deny(EgressFqdnDenyReason),
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum EgressFqdnError {
    #[error("invalid FQDN pattern {0:?}")]
    InvalidPattern(String),
    #[error("invalid DNS name {0:?}")]
    InvalidDnsName(String),
    #[error("invalid FQDN policy: {0}")]
    InvalidPolicy(&'static str),
    #[error("FQDN observation set has {actual} records; limit is {limit}")]
    TooManyObservations { actual: usize, limit: usize },
    #[error("invalid DNS observation from {observer:?}: {reason}")]
    InvalidObservation {
        observer: String,
        reason: &'static str,
    },
    #[error("observer {observer:?} supplied duplicate evidence for query {query_name:?}")]
    DuplicateObservation {
        observer: String,
        query_name: String,
    },
    #[error("FQDN snapshot needs {actual} leases; policy capacity is {limit}")]
    CapacityExceeded { actual: usize, limit: u16 },
    #[error("FQDN evidence timestamp overflowed")]
    TimestampOverflow,
    #[error("FQDN evidence encoding failed: {0}")]
    Encoding(String),
    #[error("FQDN snapshot failed independent replay: {0}")]
    InvalidSnapshot(&'static str),
}

/// Compiles DNS observations into bounded, quorum-derived destination leases.
///
/// Observers are counted by UID, never by answer count or resolver address. A
/// lease's new-flow expiry is the quorum-th latest capped expiry, ensuring at
/// least the configured number of independent observations support the address
/// for its entire admitted lifetime. Any capacity overflow rejects the whole
/// snapshot; entries are never partially or silently evicted.
///
/// # Errors
///
/// Rejects malformed policy/observations, duplicate observer evidence,
/// timestamp overflow, or a snapshot that cannot fit atomically.
pub fn compile_egress_fqdn_snapshot(
    policy: EgressFqdnPolicy,
    observations: Vec<EgressDnsObservation>,
    now_unix_seconds: u64,
) -> Result<EgressFqdnCompilation, EgressFqdnError> {
    let policy = normalize_policy(policy)?;
    if observations.len() > MAX_EGRESS_FQDN_OBSERVATIONS {
        return Err(EgressFqdnError::TooManyObservations {
            actual: observations.len(),
            limit: MAX_EGRESS_FQDN_OBSERVATIONS,
        });
    }

    let (grouped, mut report) = collect_observations(&policy, observations, now_unix_seconds)?;
    let leases = compile_leases(&policy, grouped, now_unix_seconds, &mut report)?;
    report.admitted_destinations = u32::try_from(leases.len()).unwrap_or(u32::MAX);
    let mut snapshot = EgressFqdnSnapshot {
        schema_version: EGRESS_FQDN_EVIDENCE_SCHEMA_VERSION,
        algorithm: EGRESS_FQDN_ALGORITHM_PROVENANCE_LEASED_RESOLUTION_V1,
        compiled_at_unix_seconds: now_unix_seconds,
        policy,
        leases,
        digest: EgressFqdnSnapshotDigest([0; 32]),
    };
    snapshot.digest = snapshot_digest(&snapshot)?;
    verify_egress_fqdn_snapshot(snapshot.clone())?;
    Ok(EgressFqdnCompilation { snapshot, report })
}

fn collect_observations(
    policy: &EgressFqdnPolicy,
    observations: Vec<EgressDnsObservation>,
    now_unix_seconds: u64,
) -> Result<(FqdnEvidenceGroups, EgressFqdnCompilationReport), EgressFqdnError> {
    let mut report = EgressFqdnCompilationReport::default();
    let mut seen = BTreeSet::new();
    let mut grouped = FqdnEvidenceGroups::new();
    for observation in observations {
        let observation =
            normalize_observation(observation, policy.max_ttl_seconds, now_unix_seconds)?;
        let observation_key = (
            observation.source.observer_uid.clone(),
            observation.query_name.clone(),
        );
        if !seen.insert(observation_key) {
            return Err(EgressFqdnError::DuplicateObservation {
                observer: observation.source.observer_uid,
                query_name: observation.query_name,
            });
        }
        if observation.source.view != policy.view {
            report.wrong_view_observations += 1;
            continue;
        }
        if !policy
            .patterns
            .iter()
            .any(|pattern| pattern.matches(&observation.query_name))
        {
            report.unmatched_name_observations += 1;
            continue;
        }
        report.accepted_observations += 1;
        add_observation_answers(policy, observation, &mut grouped, &mut report)?;
    }
    Ok((grouped, report))
}

fn add_observation_answers(
    policy: &EgressFqdnPolicy,
    observation: EgressDnsObservation,
    grouped: &mut FqdnEvidenceGroups,
    report: &mut EgressFqdnCompilationReport,
) -> Result<(), EgressFqdnError> {
    for answer in observation.answers {
        if answer.ttl_seconds == 0 {
            report.zero_ttl_answers += 1;
            continue;
        }
        let ttl_seconds = answer.ttl_seconds.min(policy.max_ttl_seconds);
        let expires_at_unix_seconds = observation
            .observed_at_unix_seconds
            .checked_add(u64::from(ttl_seconds))
            .ok_or(EgressFqdnError::TimestampOverflow)?;
        grouped
            .entry((observation.query_name.clone(), answer.address))
            .or_default()
            .push(EgressFqdnLeaseProvenance {
                source: observation.source.clone(),
                observation_revision: observation.observation_revision,
                canonical_chain: observation.canonical_chain.clone(),
                observed_at_unix_seconds: observation.observed_at_unix_seconds,
                ttl_seconds,
                expires_at_unix_seconds,
            });
    }
    Ok(())
}

fn compile_leases(
    policy: &EgressFqdnPolicy,
    grouped: FqdnEvidenceGroups,
    now_unix_seconds: u64,
    report: &mut EgressFqdnCompilationReport,
) -> Result<Vec<EgressFqdnDestinationLease>, EgressFqdnError> {
    let mut leases = Vec::new();
    for ((query_name, address), mut provenance) in grouped {
        provenance.sort_unstable();
        let required = usize::from(policy.required_observers);
        if provenance.len() < required {
            report.below_quorum_destinations += 1;
            continue;
        }
        let mut expiries = provenance
            .iter()
            .map(|evidence| evidence.expires_at_unix_seconds)
            .collect::<Vec<_>>();
        expiries.sort_unstable_by(|left, right| right.cmp(left));
        let new_flows_until_unix_seconds = expiries[required - 1];
        let established_flows_until_unix_seconds = new_flows_until_unix_seconds
            .checked_add(u64::from(policy.established_flow_grace_seconds))
            .ok_or(EgressFqdnError::TimestampOverflow)?;
        if established_flows_until_unix_seconds <= now_unix_seconds {
            continue;
        }
        let matched_patterns = policy
            .patterns
            .iter()
            .filter(|pattern| pattern.matches(&query_name))
            .cloned()
            .collect();
        leases.push(EgressFqdnDestinationLease {
            query_name,
            matched_patterns,
            address,
            new_flows_until_unix_seconds,
            established_flows_until_unix_seconds,
            provenance,
        });
    }
    leases.sort_by(|left, right| {
        (&left.query_name, left.address).cmp(&(&right.query_name, right.address))
    });
    if leases.len() > usize::from(policy.max_addresses) {
        return Err(EgressFqdnError::CapacityExceeded {
            actual: leases.len(),
            limit: policy.max_addresses,
        });
    }
    Ok(leases)
}

/// Independently replays lease derivation and the domain-separated digest.
///
/// # Errors
///
/// Rejects schema, policy, ordering, quorum, expiry, provenance, capacity, or
/// digest mutation.
pub fn verify_egress_fqdn_snapshot(
    snapshot: EgressFqdnSnapshot,
) -> Result<VerifiedEgressFqdnSnapshot, EgressFqdnError> {
    if snapshot.schema_version != EGRESS_FQDN_EVIDENCE_SCHEMA_VERSION
        || snapshot.algorithm != EGRESS_FQDN_ALGORITHM_PROVENANCE_LEASED_RESOLUTION_V1
    {
        return Err(EgressFqdnError::InvalidSnapshot(
            "unsupported schema or algorithm",
        ));
    }
    if normalize_policy(snapshot.policy.clone())? != snapshot.policy {
        return Err(EgressFqdnError::InvalidSnapshot("policy is not canonical"));
    }
    if snapshot.leases.len() > usize::from(snapshot.policy.max_addresses) {
        return Err(EgressFqdnError::InvalidSnapshot("lease capacity exceeded"));
    }
    if snapshot.leases.windows(2).any(|pair| {
        (&pair[0].query_name, pair[0].address) >= (&pair[1].query_name, pair[1].address)
    }) {
        return Err(EgressFqdnError::InvalidSnapshot(
            "leases are not uniquely ordered",
        ));
    }
    for lease in &snapshot.leases {
        verify_lease(&snapshot.policy, lease, snapshot.compiled_at_unix_seconds)?;
        if lease.established_flows_until_unix_seconds <= snapshot.compiled_at_unix_seconds {
            return Err(EgressFqdnError::InvalidSnapshot(
                "snapshot retains expired lease",
            ));
        }
    }
    if snapshot_digest(&snapshot)? != snapshot.digest {
        return Err(EgressFqdnError::InvalidSnapshot("digest mismatch"));
    }
    Ok(VerifiedEgressFqdnSnapshot(snapshot))
}

/// Evaluates one address against already verified temporal evidence.
#[must_use]
pub fn decide_egress_fqdn_destination(
    snapshot: &VerifiedEgressFqdnSnapshot,
    address: IpAddr,
    flow_class: EgressFqdnFlowClass,
    now_unix_seconds: u64,
) -> EgressFqdnDecision {
    let raw = snapshot.snapshot();
    let best = raw
        .leases
        .iter()
        .filter(|lease| lease.address == address)
        .max_by_key(|lease| {
            (
                lease.new_flows_until_unix_seconds,
                lease.established_flows_until_unix_seconds,
                &lease.query_name,
            )
        });
    let Some(lease) = best else {
        return EgressFqdnDecision::Deny(EgressFqdnDenyReason::NoDestinationEvidence);
    };
    if now_unix_seconds < lease.new_flows_until_unix_seconds {
        return EgressFqdnDecision::AllowActive {
            query_name: lease.query_name.clone(),
            patterns: lease.matched_patterns.clone(),
            until_unix_seconds: lease.new_flows_until_unix_seconds,
            snapshot_digest: raw.digest,
        };
    }
    if flow_class == EgressFqdnFlowClass::Established
        && now_unix_seconds < lease.established_flows_until_unix_seconds
    {
        return EgressFqdnDecision::AllowEstablishedDrain {
            query_name: lease.query_name.clone(),
            patterns: lease.matched_patterns.clone(),
            until_unix_seconds: lease.established_flows_until_unix_seconds,
            snapshot_digest: raw.digest,
        };
    }
    EgressFqdnDecision::Deny(match flow_class {
        EgressFqdnFlowClass::New => EgressFqdnDenyReason::NewFlowEvidenceExpired,
        EgressFqdnFlowClass::Established => EgressFqdnDenyReason::EstablishedFlowEvidenceExpired,
    })
}

fn normalize_policy(mut policy: EgressFqdnPolicy) -> Result<EgressFqdnPolicy, EgressFqdnError> {
    if policy.revision.0 == 0 {
        return Err(EgressFqdnError::InvalidPolicy("revision zero is reserved"));
    }
    if !valid_token(&policy.owner.name)
        || !valid_token(&policy.owner.uid)
        || matches!(&policy.owner.scope, EgressIntentScope::Namespace(namespace) if !valid_token(namespace))
    {
        return Err(EgressFqdnError::InvalidPolicy("owner identity is invalid"));
    }
    if policy.patterns.is_empty() || policy.patterns.len() > MAX_EGRESS_FQDN_PATTERNS {
        return Err(EgressFqdnError::InvalidPolicy(
            "pattern set is empty or unbounded",
        ));
    }
    policy.patterns = policy
        .patterns
        .iter()
        .map(|pattern| match pattern {
            EgressFqdnPattern::Exact(name) => EgressFqdnPattern::parse(name),
            EgressFqdnPattern::WildcardSuffix(suffix) => {
                EgressFqdnPattern::parse(&format!("*.{suffix}"))
            }
        })
        .collect::<Result<Vec<_>, _>>()?;
    policy.patterns.sort_unstable();
    if policy.patterns.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(EgressFqdnError::InvalidPolicy(
            "duplicate patterns are forbidden",
        ));
    }
    if !valid_token(&policy.view) {
        return Err(EgressFqdnError::InvalidPolicy("DNS view is invalid"));
    }
    if policy.required_observers == 0 || policy.required_observers > MAX_EGRESS_FQDN_OBSERVERS {
        return Err(EgressFqdnError::InvalidPolicy("observer quorum is invalid"));
    }
    if policy.max_addresses == 0 || policy.max_addresses > MAX_EGRESS_FQDN_ADDRESSES {
        return Err(EgressFqdnError::InvalidPolicy(
            "address capacity is invalid",
        ));
    }
    if policy.max_ttl_seconds == 0 || policy.max_ttl_seconds > MAX_EGRESS_FQDN_TTL_SECONDS {
        return Err(EgressFqdnError::InvalidPolicy("TTL cap is invalid"));
    }
    if policy.established_flow_grace_seconds > MAX_EGRESS_FQDN_ESTABLISHED_GRACE_SECONDS {
        return Err(EgressFqdnError::InvalidPolicy(
            "established-flow grace is unbounded",
        ));
    }
    Ok(policy)
}

fn normalize_observation(
    mut observation: EgressDnsObservation,
    max_ttl_seconds: u32,
    now_unix_seconds: u64,
) -> Result<EgressDnsObservation, EgressFqdnError> {
    let invalid = |reason| EgressFqdnError::InvalidObservation {
        observer: observation.source.observer_uid.clone(),
        reason,
    };
    if !valid_token(&observation.source.observer_uid)
        || !valid_token(&observation.source.view)
        || observation.source.resolver.is_unspecified()
        || observation.source.source_epoch == 0
        || observation.observation_revision.0 == 0
    {
        return Err(invalid(
            "source identity, resolver, epoch, or revision is invalid",
        ));
    }
    if observation.observed_at_unix_seconds
        > now_unix_seconds.saturating_add(MAX_EGRESS_FQDN_FUTURE_SKEW_SECONDS)
    {
        return Err(invalid("observation timestamp is too far in the future"));
    }
    if observation.answers.len() > MAX_EGRESS_FQDN_ANSWERS_PER_OBSERVATION {
        return Err(invalid("answer set exceeds its bound"));
    }
    observation.query_name = normalize_dns_name(&observation.query_name)?;
    if observation.canonical_chain.is_empty()
        || observation.canonical_chain.len() > MAX_EGRESS_FQDN_CNAME_DEPTH
    {
        return Err(invalid("canonical chain is empty or exceeds its bound"));
    }
    observation.canonical_chain = observation
        .canonical_chain
        .iter()
        .map(|name| normalize_dns_name(name))
        .collect::<Result<Vec<_>, _>>()?;
    if observation.canonical_chain[0] != observation.query_name
        || observation
            .canonical_chain
            .iter()
            .collect::<BTreeSet<_>>()
            .len()
            != observation.canonical_chain.len()
    {
        return Err(invalid(
            "canonical chain does not start at the query or contains a loop",
        ));
    }
    observation.answers.sort_unstable();
    if observation
        .answers
        .windows(2)
        .any(|pair| pair[0] == pair[1])
        || observation.answers.iter().any(|answer| {
            answer.address.is_unspecified() || answer.ttl_seconds > MAX_EGRESS_FQDN_TTL_SECONDS
        })
    {
        return Err(invalid(
            "answer is duplicate, unspecified, or has an unbounded TTL",
        ));
    }
    for answer in &mut observation.answers {
        answer.ttl_seconds = answer.ttl_seconds.min(max_ttl_seconds);
    }
    Ok(observation)
}

fn verify_lease(
    policy: &EgressFqdnPolicy,
    lease: &EgressFqdnDestinationLease,
    compiled_at_unix_seconds: u64,
) -> Result<(), EgressFqdnError> {
    if normalize_dns_name(&lease.query_name)? != lease.query_name || lease.address.is_unspecified()
    {
        return Err(EgressFqdnError::InvalidSnapshot(
            "lease destination is invalid",
        ));
    }
    let matched_patterns = policy
        .patterns
        .iter()
        .filter(|pattern| pattern.matches(&lease.query_name))
        .cloned()
        .collect::<Vec<_>>();
    if matched_patterns.is_empty() || matched_patterns != lease.matched_patterns {
        return Err(EgressFqdnError::InvalidSnapshot(
            "matched-pattern proof is invalid",
        ));
    }
    if lease.provenance.len() < usize::from(policy.required_observers)
        || !lease.provenance.windows(2).all(|pair| pair[0] < pair[1])
    {
        return Err(EgressFqdnError::InvalidSnapshot(
            "provenance is insufficient or unordered",
        ));
    }
    let mut observers = BTreeSet::new();
    let mut expiries = Vec::with_capacity(lease.provenance.len());
    for evidence in &lease.provenance {
        if !observers.insert(&evidence.source.observer_uid)
            || !valid_token(&evidence.source.observer_uid)
            || !valid_token(&evidence.source.view)
            || evidence.source.view != policy.view
            || evidence.source.resolver.is_unspecified()
            || evidence.source.source_epoch == 0
            || evidence.observation_revision.0 == 0
            || evidence.canonical_chain.is_empty()
            || evidence.canonical_chain.len() > MAX_EGRESS_FQDN_CNAME_DEPTH
            || evidence.canonical_chain[0] != lease.query_name
            || evidence
                .canonical_chain
                .iter()
                .any(|name| !is_canonical_dns_name(name))
            || evidence
                .canonical_chain
                .iter()
                .collect::<BTreeSet<_>>()
                .len()
                != evidence.canonical_chain.len()
            || evidence.ttl_seconds == 0
            || evidence.ttl_seconds > policy.max_ttl_seconds
            || evidence.observed_at_unix_seconds
                > compiled_at_unix_seconds.saturating_add(MAX_EGRESS_FQDN_FUTURE_SKEW_SECONDS)
            || evidence
                .observed_at_unix_seconds
                .checked_add(u64::from(evidence.ttl_seconds))
                != Some(evidence.expires_at_unix_seconds)
        {
            return Err(EgressFqdnError::InvalidSnapshot("provenance replay failed"));
        }
        expiries.push(evidence.expires_at_unix_seconds);
    }
    expiries.sort_unstable_by(|left, right| right.cmp(left));
    let expected_new = expiries[usize::from(policy.required_observers) - 1];
    let expected_established = expected_new
        .checked_add(u64::from(policy.established_flow_grace_seconds))
        .ok_or(EgressFqdnError::TimestampOverflow)?;
    if lease.new_flows_until_unix_seconds != expected_new
        || lease.established_flows_until_unix_seconds != expected_established
    {
        return Err(EgressFqdnError::InvalidSnapshot(
            "quorum expiry replay failed",
        ));
    }
    Ok(())
}

fn snapshot_digest(
    snapshot: &EgressFqdnSnapshot,
) -> Result<EgressFqdnSnapshotDigest, EgressFqdnError> {
    let material = (
        snapshot.schema_version,
        snapshot.algorithm,
        snapshot.compiled_at_unix_seconds,
        &snapshot.policy,
        &snapshot.leases,
    );
    let encoded = serde_json::to_vec(&material)
        .map_err(|error| EgressFqdnError::Encoding(error.to_string()))?;
    let mut hasher = Sha256::new();
    hasher.update(FQDN_DIGEST_DOMAIN);
    hasher.update(encoded);
    Ok(EgressFqdnSnapshotDigest(hasher.finalize().into()))
}

fn normalize_dns_name(value: &str) -> Result<String, EgressFqdnError> {
    let value = value.strip_suffix('.').unwrap_or(value);
    if value.is_empty() || value.len() > 253 || !value.is_ascii() {
        return Err(EgressFqdnError::InvalidDnsName(value.to_owned()));
    }
    let normalized = value.to_ascii_lowercase();
    if normalized.split('.').any(|label| {
        label.is_empty()
            || label.len() > 63
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            || !label.as_bytes()[0].is_ascii_alphanumeric()
            || !label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
    }) {
        return Err(EgressFqdnError::InvalidDnsName(value.to_owned()));
    }
    Ok(normalized)
}

fn is_canonical_dns_name(value: &str) -> bool {
    normalize_dns_name(value).is_ok_and(|normalized| normalized == value)
}

fn valid_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'/'))
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;
    use crate::{EgressIntentOwner, EgressIntentScope};

    const NOW: u64 = 1_000_000;

    fn policy() -> EgressFqdnPolicy {
        EgressFqdnPolicy {
            revision: Revision(7),
            owner: EgressIntentOwner {
                scope: EgressIntentScope::Namespace("finance".to_owned()),
                name: "banks".to_owned(),
                uid: "policy-uid".to_owned(),
            },
            patterns: vec![
                EgressFqdnPattern::parse("*.Bank.Example.").unwrap(),
                EgressFqdnPattern::parse("api.partner.test").unwrap(),
            ],
            view: "finance/production".to_owned(),
            required_observers: 2,
            max_addresses: 8,
            max_ttl_seconds: 300,
            established_flow_grace_seconds: 30,
        }
    }

    fn observation(
        observer: &str,
        view: &str,
        query: &str,
        address: IpAddr,
        ttl_seconds: u32,
        observed_at: u64,
    ) -> EgressDnsObservation {
        EgressDnsObservation {
            source: EgressDnsObservationSource {
                observer_uid: observer.to_owned(),
                resolver: IpAddr::V4(Ipv4Addr::new(10, 96, 0, 10)),
                view: view.to_owned(),
                source_epoch: 3,
            },
            observation_revision: Revision(11),
            query_name: query.to_owned(),
            canonical_chain: vec![query.to_owned(), "edge.provider.test".to_owned()],
            answers: vec![EgressDnsAnswer {
                address,
                ttl_seconds,
            }],
            observed_at_unix_seconds: observed_at,
        }
    }

    #[test]
    fn wildcard_is_label_bounded_and_never_matches_apex() {
        let pattern = EgressFqdnPattern::parse("*.Example.COM.").unwrap();
        assert_eq!(
            pattern,
            EgressFqdnPattern::WildcardSuffix("example.com".to_owned())
        );
        assert!(pattern.matches("a.example.com"));
        assert!(pattern.matches("a.b.example.com"));
        assert!(!pattern.matches("example.com"));
        assert!(!pattern.matches("badexample.com"));
        assert!(EgressFqdnPattern::parse("*.*.example.com").is_err());
        assert!(EgressFqdnPattern::parse("*.com").is_err());
        assert!(EgressFqdnPattern::parse("café.example").is_err());
    }

    #[test]
    fn quorum_expiry_uses_kth_latest_source_and_ttl_cap() {
        let address = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 20));
        let compiled = compile_egress_fqdn_snapshot(
            policy(),
            vec![
                observation(
                    "observer-a",
                    "finance/production",
                    "api.bank.example",
                    address,
                    900,
                    NOW,
                ),
                observation(
                    "observer-b",
                    "finance/production",
                    "API.BANK.EXAMPLE.",
                    address,
                    120,
                    NOW,
                ),
                observation(
                    "observer-c",
                    "finance/production",
                    "api.bank.example",
                    address,
                    60,
                    NOW,
                ),
            ],
            NOW,
        )
        .unwrap();
        assert_eq!(compiled.report.admitted_destinations, 1);
        let lease = &compiled.snapshot.leases[0];
        assert_eq!(lease.new_flows_until_unix_seconds, NOW + 120);
        assert_eq!(lease.established_flows_until_unix_seconds, NOW + 150);
        assert_eq!(lease.provenance[0].ttl_seconds, 300);
        let verified = verify_egress_fqdn_snapshot(compiled.snapshot).unwrap();
        assert!(matches!(
            decide_egress_fqdn_destination(&verified, address, EgressFqdnFlowClass::New, NOW + 119),
            EgressFqdnDecision::AllowActive { .. }
        ));
        assert_eq!(
            decide_egress_fqdn_destination(&verified, address, EgressFqdnFlowClass::New, NOW + 120),
            EgressFqdnDecision::Deny(EgressFqdnDenyReason::NewFlowEvidenceExpired)
        );
        assert!(matches!(
            decide_egress_fqdn_destination(
                &verified,
                address,
                EgressFqdnFlowClass::Established,
                NOW + 120
            ),
            EgressFqdnDecision::AllowEstablishedDrain { .. }
        ));
        assert_eq!(
            decide_egress_fqdn_destination(
                &verified,
                address,
                EgressFqdnFlowClass::Established,
                NOW + 150
            ),
            EgressFqdnDecision::Deny(EgressFqdnDenyReason::EstablishedFlowEvidenceExpired)
        );
    }

    #[test]
    fn split_horizon_views_never_merge_into_quorum() {
        let address = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 4, 0, 0, 0, 9));
        let compiled = compile_egress_fqdn_snapshot(
            policy(),
            vec![
                observation(
                    "observer-a",
                    "finance/production",
                    "v6.bank.example",
                    address,
                    60,
                    NOW,
                ),
                observation(
                    "observer-b",
                    "engineering/production",
                    "v6.bank.example",
                    address,
                    60,
                    NOW,
                ),
            ],
            NOW,
        )
        .unwrap();
        assert!(compiled.snapshot.leases.is_empty());
        assert_eq!(compiled.report.wrong_view_observations, 1);
        assert_eq!(compiled.report.below_quorum_destinations, 1);
    }

    #[test]
    fn below_quorum_and_zero_ttl_fail_closed_with_visible_counts() {
        let address = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 8));
        let compiled = compile_egress_fqdn_snapshot(
            policy(),
            vec![
                observation(
                    "observer-a",
                    "finance/production",
                    "api.partner.test",
                    address,
                    60,
                    NOW,
                ),
                observation(
                    "observer-b",
                    "finance/production",
                    "api.partner.test",
                    address,
                    0,
                    NOW,
                ),
                observation(
                    "observer-c",
                    "finance/production",
                    "unmatched.example",
                    address,
                    60,
                    NOW,
                ),
            ],
            NOW,
        )
        .unwrap();
        assert!(compiled.snapshot.leases.is_empty());
        assert_eq!(compiled.report.zero_ttl_answers, 1);
        assert_eq!(compiled.report.unmatched_name_observations, 1);
        assert_eq!(compiled.report.below_quorum_destinations, 1);
    }

    #[test]
    fn capacity_overflow_rejects_the_complete_snapshot() {
        let mut policy = policy();
        policy.max_addresses = 1;
        let addresses = [
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)),
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 2)),
        ];
        let observations = ["observer-a", "observer-b"]
            .into_iter()
            .flat_map(|observer| {
                addresses.map(|address| {
                    observation(
                        observer,
                        "finance/production",
                        if address == addresses[0] {
                            "one.bank.example"
                        } else {
                            "two.bank.example"
                        },
                        address,
                        60,
                        NOW,
                    )
                })
            })
            .collect();
        assert_eq!(
            compile_egress_fqdn_snapshot(policy, observations, NOW),
            Err(EgressFqdnError::CapacityExceeded {
                actual: 2,
                limit: 1
            })
        );
    }

    #[test]
    fn duplicate_observer_cannot_inflate_quorum() {
        let address = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 3));
        let duplicate = observation(
            "observer-a",
            "finance/production",
            "same.bank.example",
            address,
            60,
            NOW,
        );
        assert!(matches!(
            compile_egress_fqdn_snapshot(policy(), vec![duplicate.clone(), duplicate], NOW),
            Err(EgressFqdnError::DuplicateObservation { .. })
        ));

        let future = observation(
            "observer-a",
            "finance/production",
            "same.bank.example",
            address,
            60,
            NOW + MAX_EGRESS_FQDN_FUTURE_SKEW_SECONDS + 1,
        );
        assert!(matches!(
            compile_egress_fqdn_snapshot(policy(), vec![future], NOW),
            Err(EgressFqdnError::InvalidObservation {
                reason: "observation timestamp is too far in the future",
                ..
            })
        ));
    }

    #[test]
    fn mutation_and_expired_snapshot_fail_independent_replay() {
        let address = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 4));
        let snapshot = compile_egress_fqdn_snapshot(
            policy(),
            vec![
                observation(
                    "observer-a",
                    "finance/production",
                    "api.bank.example",
                    address,
                    60,
                    NOW,
                ),
                observation(
                    "observer-b",
                    "finance/production",
                    "api.bank.example",
                    address,
                    60,
                    NOW,
                ),
            ],
            NOW,
        )
        .unwrap()
        .snapshot;
        let mut outer_mutation = snapshot.clone();
        outer_mutation.leases[0].address = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 99));
        assert!(matches!(
            verify_egress_fqdn_snapshot(outer_mutation),
            Err(EgressFqdnError::InvalidSnapshot("digest mismatch"))
        ));

        let mut inner_mutation = snapshot;
        inner_mutation.leases[0].new_flows_until_unix_seconds += 1;
        inner_mutation.digest = snapshot_digest(&inner_mutation).unwrap();
        assert!(matches!(
            verify_egress_fqdn_snapshot(inner_mutation),
            Err(EgressFqdnError::InvalidSnapshot(
                "quorum expiry replay failed"
            ))
        ));

        let expired = compile_egress_fqdn_snapshot(
            policy(),
            vec![
                observation(
                    "observer-a",
                    "finance/production",
                    "api.bank.example",
                    address,
                    10,
                    NOW,
                ),
                observation(
                    "observer-b",
                    "finance/production",
                    "api.bank.example",
                    address,
                    10,
                    NOW,
                ),
            ],
            NOW + 40,
        )
        .unwrap();
        assert!(expired.snapshot.leases.is_empty());
    }

    #[test]
    fn direct_ip_without_dns_evidence_never_falls_back_to_allow() {
        let address = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5));
        let compiled = compile_egress_fqdn_snapshot(policy(), Vec::new(), NOW).unwrap();
        let verified = verify_egress_fqdn_snapshot(compiled.snapshot).unwrap();
        assert_eq!(
            decide_egress_fqdn_destination(&verified, address, EgressFqdnFlowClass::New, NOW),
            EgressFqdnDecision::Deny(EgressFqdnDenyReason::NoDestinationEvidence)
        );
    }
}
