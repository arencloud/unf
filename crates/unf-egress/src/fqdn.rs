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

use crate::{EgressDestinations, EgressIntentOwner, EgressIntentScope};

pub const EGRESS_FQDN_EVIDENCE_SCHEMA_VERSION: u16 = 1;
pub const EGRESS_FQDN_ALGORITHM_PROVENANCE_LEASED_RESOLUTION_V1: u16 = 1;
pub const MAX_EGRESS_FQDN_PATTERNS: usize = 256;
pub const MAX_EGRESS_FQDN_DISCOVERY_NAMES: usize = 256;
pub const MAX_EGRESS_FQDN_RESOLVERS: usize = 16;
pub const MAX_EGRESS_FQDN_OBSERVATIONS: usize = 4_096;
pub const MAX_EGRESS_FQDN_ANSWERS_PER_OBSERVATION: usize = 64;
pub const MAX_EGRESS_FQDN_CNAME_DEPTH: usize = 16;
pub const MAX_EGRESS_FQDN_OBSERVERS: u16 = 16;
pub const MAX_EGRESS_FQDN_ADDRESSES: u16 = 4_096;
pub const MAX_EGRESS_FQDN_TTL_SECONDS: u32 = 604_800;
pub const MAX_EGRESS_FQDN_ESTABLISHED_GRACE_SECONDS: u32 = 3_600;
pub const MAX_EGRESS_FQDN_FUTURE_SKEW_SECONDS: u64 = 30;
pub const DEFAULT_EGRESS_FQDN_VIEW: &str = "cluster-default";
pub const DEFAULT_EGRESS_FQDN_REQUIRED_OBSERVERS: u16 = 1;
pub const DEFAULT_EGRESS_FQDN_MAX_ADDRESSES: u16 = 256;
pub const DEFAULT_EGRESS_FQDN_MAX_TTL_SECONDS: u32 = 300;
pub const DEFAULT_EGRESS_FQDN_ESTABLISHED_GRACE_SECONDS: u32 = 30;

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

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EgressFqdnDestinationSpec {
    pub patterns: Vec<EgressFqdnPattern>,
    pub view: String,
    pub discovery_names: Vec<String>,
    pub resolver_addresses: Vec<IpAddr>,
    pub required_observers: u16,
    pub max_addresses: u16,
    pub max_ttl_seconds: u32,
    pub established_flow_grace_seconds: u32,
}

/// Canonicalizes and bounds one FQDN destination specification.
///
/// # Errors
///
/// Rejects invalid/duplicate patterns, views, quorums, capacity, TTL, or drain
/// bounds.
pub fn normalize_egress_fqdn_destination_spec(
    mut spec: EgressFqdnDestinationSpec,
) -> Result<EgressFqdnDestinationSpec, EgressFqdnError> {
    if spec.patterns.is_empty() || spec.patterns.len() > MAX_EGRESS_FQDN_PATTERNS {
        return Err(EgressFqdnError::InvalidPolicy(
            "pattern set is empty or unbounded",
        ));
    }
    spec.patterns = spec
        .patterns
        .iter()
        .map(|pattern| match pattern {
            EgressFqdnPattern::Exact(name) => EgressFqdnPattern::parse(name),
            EgressFqdnPattern::WildcardSuffix(suffix) => {
                EgressFqdnPattern::parse(&format!("*.{suffix}"))
            }
        })
        .collect::<Result<Vec<_>, _>>()?;
    spec.patterns.sort_unstable();
    if spec.patterns.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(EgressFqdnError::InvalidPolicy(
            "duplicate patterns are forbidden",
        ));
    }
    if !valid_token(&spec.view) {
        return Err(EgressFqdnError::InvalidPolicy("DNS view is invalid"));
    }
    if spec.discovery_names.len() > MAX_EGRESS_FQDN_DISCOVERY_NAMES {
        return Err(EgressFqdnError::InvalidPolicy(
            "wildcard discovery-name set exceeds its bound",
        ));
    }
    spec.discovery_names = spec
        .discovery_names
        .iter()
        .map(|name| normalize_dns_name(name))
        .collect::<Result<Vec<_>, _>>()?;
    spec.discovery_names.sort_unstable();
    if spec
        .discovery_names
        .windows(2)
        .any(|pair| pair[0] == pair[1])
        || spec
            .discovery_names
            .iter()
            .any(|name| !spec.patterns.iter().any(|pattern| pattern.matches(name)))
    {
        return Err(EgressFqdnError::InvalidPolicy(
            "discovery names must be unique members of the policy patterns",
        ));
    }
    if spec.resolver_addresses.len() > MAX_EGRESS_FQDN_RESOLVERS
        || spec.resolver_addresses.iter().any(IpAddr::is_unspecified)
    {
        return Err(EgressFqdnError::InvalidPolicy(
            "resolver address set is invalid or exceeds its bound",
        ));
    }
    spec.resolver_addresses.sort_unstable();
    if spec
        .resolver_addresses
        .windows(2)
        .any(|pair| pair[0] == pair[1])
        || (spec.view != DEFAULT_EGRESS_FQDN_VIEW && spec.resolver_addresses.is_empty())
    {
        return Err(EgressFqdnError::InvalidPolicy(
            "custom views require a unique explicit resolver-address set",
        ));
    }
    if spec.required_observers == 0 || spec.required_observers > MAX_EGRESS_FQDN_OBSERVERS {
        return Err(EgressFqdnError::InvalidPolicy("observer quorum is invalid"));
    }
    if spec.max_addresses == 0 || spec.max_addresses > MAX_EGRESS_FQDN_ADDRESSES {
        return Err(EgressFqdnError::InvalidPolicy(
            "address capacity is invalid",
        ));
    }
    if spec.max_ttl_seconds == 0 || spec.max_ttl_seconds > MAX_EGRESS_FQDN_TTL_SECONDS {
        return Err(EgressFqdnError::InvalidPolicy("TTL cap is invalid"));
    }
    if spec.established_flow_grace_seconds > MAX_EGRESS_FQDN_ESTABLISHED_GRACE_SECONDS {
        return Err(EgressFqdnError::InvalidPolicy(
            "established-flow grace is unbounded",
        ));
    }
    Ok(spec)
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EgressFqdnPolicy {
    pub revision: Revision,
    pub owner: EgressIntentOwner,
    pub patterns: Vec<EgressFqdnPattern>,
    /// An explicit resolver/tenant view. Observations from other views never
    /// contribute to this policy's quorum.
    pub view: String,
    /// Exact wildcard members authorized for observation. This prevents a
    /// wildcard suffix from becoming an implicit enumeration capability.
    pub discovery_names: Vec<String>,
    /// Resolver identities allowed to contribute evidence for this view.
    pub resolver_addresses: Vec<IpAddr>,
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

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
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

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
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

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EgressFqdnSnapshot {
    pub schema_version: u16,
    pub algorithm: u16,
    pub compiled_at_unix_seconds: u64,
    pub policy: EgressFqdnPolicy,
    pub leases: Vec<EgressFqdnDestinationLease>,
    pub digest: EgressFqdnSnapshotDigest,
}

/// Replaces unresolved FQDN destinations in a normalized model with one
/// independently replayable PLR snapshot per intent. The ledger remains the
/// only evidence source; silence cannot extend a lease.
///
/// # Errors
///
/// Rejects malformed evidence, an invalid policy, capacity overflow, or an
/// already-materialized snapshot that does not replay exactly.
pub fn materialize_egress_fqdn_model(
    mut model: crate::EgressModel,
    ledger: &crate::EgressFqdnObservationLedger,
    policy_revision: Revision,
    now_unix_seconds: u64,
) -> Result<
    (
        crate::EgressModel,
        BTreeMap<EgressIntentOwner, EgressFqdnCompilationReport>,
    ),
    EgressFqdnError,
> {
    let mut reports = BTreeMap::new();
    for intent in &mut model.intents {
        let Some(spec) = intent.fqdn.clone() else {
            continue;
        };
        if policy_revision == Revision::INITIAL {
            return Err(EgressFqdnError::InvalidPolicy("revision zero is reserved"));
        }
        let policy = EgressFqdnPolicy {
            revision: policy_revision,
            owner: intent.owner.clone(),
            patterns: spec.patterns,
            view: spec.view.clone(),
            discovery_names: spec.discovery_names.clone(),
            resolver_addresses: spec.resolver_addresses.clone(),
            required_observers: spec.required_observers,
            max_addresses: spec.max_addresses,
            max_ttl_seconds: spec.max_ttl_seconds,
            established_flow_grace_seconds: spec.established_flow_grace_seconds,
        };
        let compiled = compile_egress_fqdn_snapshot(
            policy,
            ledger.observations_for_view(&spec.view),
            now_unix_seconds,
        )?;
        reports.insert(intent.owner.clone(), compiled.report);
        intent.destinations = EgressDestinations::Fqdn(Box::new(compiled.snapshot));
    }
    Ok((model, reports))
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
    pub authoritative_empty_observations: u32,
    pub wrong_view_observations: u32,
    pub wrong_resolver_observations: u32,
    pub unmatched_name_observations: u32,
    pub unauthorized_name_observations: u32,
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
        if !policy.resolver_addresses.is_empty()
            && !policy
                .resolver_addresses
                .contains(&observation.source.resolver)
        {
            report.wrong_resolver_observations += 1;
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
        if !observation_name_is_authorized(policy, &observation.query_name) {
            report.unauthorized_name_observations += 1;
            continue;
        }
        report.accepted_observations += 1;
        if observation.answers.is_empty() {
            report.authoritative_empty_observations += 1;
        }
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
    let spec = normalize_egress_fqdn_destination_spec(EgressFqdnDestinationSpec {
        patterns: policy.patterns,
        view: policy.view,
        discovery_names: policy.discovery_names,
        resolver_addresses: policy.resolver_addresses,
        required_observers: policy.required_observers,
        max_addresses: policy.max_addresses,
        max_ttl_seconds: policy.max_ttl_seconds,
        established_flow_grace_seconds: policy.established_flow_grace_seconds,
    })?;
    policy.patterns = spec.patterns;
    policy.view = spec.view;
    policy.discovery_names = spec.discovery_names;
    policy.resolver_addresses = spec.resolver_addresses;
    policy.required_observers = spec.required_observers;
    policy.max_addresses = spec.max_addresses;
    policy.max_ttl_seconds = spec.max_ttl_seconds;
    policy.established_flow_grace_seconds = spec.established_flow_grace_seconds;
    Ok(policy)
}

pub(crate) fn normalize_observation(
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
    if matched_patterns.is_empty()
        || matched_patterns != lease.matched_patterns
        || !observation_name_is_authorized(policy, &lease.query_name)
    {
        return Err(EgressFqdnError::InvalidSnapshot(
            "matched-pattern or discovery-authority proof is invalid",
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
            || (!policy.resolver_addresses.is_empty()
                && !policy
                    .resolver_addresses
                    .contains(&evidence.source.resolver))
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

fn observation_name_is_authorized(policy: &EgressFqdnPolicy, query_name: &str) -> bool {
    policy
        .patterns
        .iter()
        .any(|pattern| matches!(pattern, EgressFqdnPattern::Exact(name) if name == query_name))
        || policy
            .discovery_names
            .binary_search_by(|candidate| candidate.as_str().cmp(query_name))
            .is_ok()
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
            discovery_names: [
                "api.bank.example",
                "one.bank.example",
                "same.bank.example",
                "two.bank.example",
                "v6.bank.example",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect(),
            resolver_addresses: vec![IpAddr::V4(Ipv4Addr::new(10, 96, 0, 10))],
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
    fn wildcard_discovery_and_custom_resolver_authority_are_bounded() {
        let normalized = normalize_egress_fqdn_destination_spec(EgressFqdnDestinationSpec {
            patterns: vec![EgressFqdnPattern::parse("*.Bank.Example.").unwrap()],
            view: "finance/production".to_owned(),
            discovery_names: vec![
                "PAYMENTS.BANK.EXAMPLE.".to_owned(),
                "api.bank.example".to_owned(),
            ],
            resolver_addresses: vec![
                "2001:db8::53".parse().unwrap(),
                "10.96.0.53".parse().unwrap(),
            ],
            required_observers: 2,
            max_addresses: 8,
            max_ttl_seconds: 60,
            established_flow_grace_seconds: 5,
        })
        .unwrap();
        assert_eq!(
            normalized.discovery_names,
            ["api.bank.example", "payments.bank.example"]
        );
        assert_eq!(
            normalized.resolver_addresses,
            [
                "10.96.0.53".parse::<IpAddr>().unwrap(),
                "2001:db8::53".parse::<IpAddr>().unwrap()
            ]
        );

        let mut missing_resolver = normalized.clone();
        missing_resolver.resolver_addresses.clear();
        assert!(normalize_egress_fqdn_destination_spec(missing_resolver).is_err());
        let mut foreign_name = normalized;
        foreign_name.discovery_names = vec!["api.partner.test".to_owned()];
        assert!(normalize_egress_fqdn_destination_spec(foreign_name).is_err());
    }

    #[test]
    fn wildcard_evidence_requires_declared_name_and_resolver_authority() {
        let mut policy = policy();
        policy.required_observers = 1;
        policy.discovery_names = vec!["api.bank.example".to_owned()];
        let address = "203.0.113.80".parse().unwrap();
        let mut wrong_resolver = observation(
            "node-a",
            "finance/production",
            "api.bank.example",
            address,
            60,
            NOW,
        );
        wrong_resolver.source.resolver = "10.96.0.99".parse().unwrap();
        let unauthorized = observation(
            "node-b",
            "finance/production",
            "rogue.bank.example",
            address,
            60,
            NOW,
        );
        let authorized = observation(
            "node-c",
            "finance/production",
            "api.bank.example",
            address,
            60,
            NOW,
        );
        let compiled = compile_egress_fqdn_snapshot(
            policy,
            vec![wrong_resolver, unauthorized, authorized],
            NOW,
        )
        .unwrap();
        assert_eq!(compiled.report.wrong_resolver_observations, 1);
        assert_eq!(compiled.report.unauthorized_name_observations, 1);
        assert_eq!(compiled.report.accepted_observations, 1);
        assert_eq!(compiled.snapshot.leases.len(), 1);
        assert_eq!(compiled.snapshot.leases[0].query_name, "api.bank.example");
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

    #[test]
    #[allow(clippy::too_many_lines)]
    fn durable_ledger_materializes_one_quorum_snapshot_and_empty_withdraws_it() {
        fn principal(node: &str) -> crate::AuthenticatedEgressAgent {
            crate::AuthenticatedEgressAgent {
                namespace: "unf-system".to_owned(),
                service_account: crate::EGRESS_AGENT_SERVICE_ACCOUNT.to_owned(),
                pod_name: format!("unf-agent-{node}"),
                pod_uid: format!("pod-{node}"),
                node_name: node.to_owned(),
                node_uid: format!("uid-{node}"),
                audience: crate::EGRESS_AGENT_TOKEN_AUDIENCE.to_owned(),
            }
        }
        fn batch(
            principal: &crate::AuthenticatedEgressAgent,
            mut observations: Vec<EgressDnsObservation>,
            revision: u64,
        ) -> crate::EgressFqdnObservationBatch {
            for observation in &mut observations {
                observation.observation_revision = Revision::new(revision);
            }
            crate::EgressFqdnObservationBatch {
                schema_version: crate::EGRESS_FQDN_OBSERVATION_BATCH_SCHEMA_VERSION,
                observer_node_uid: principal.node_uid.clone(),
                source_epoch: 3,
                batch_revision: Revision::new(revision),
                view: "finance/production".to_owned(),
                collected_at_unix_seconds: NOW,
                observations,
            }
        }

        let owner = policy().owner;
        let spec = EgressFqdnDestinationSpec {
            patterns: policy().patterns,
            view: "finance/production".to_owned(),
            discovery_names: policy().discovery_names,
            resolver_addresses: policy().resolver_addresses,
            required_observers: 2,
            max_addresses: 8,
            max_ttl_seconds: 300,
            established_flow_grace_seconds: 30,
        };
        let model = crate::EgressModel {
            pools: Vec::new(),
            intents: vec![crate::EgressIntent {
                owner: owner.clone(),
                priority: 1,
                source: crate::EgressSourceSelector::default(),
                destinations: EgressDestinations::DenyAll,
                fqdn: Some(spec),
                internet: None,
                addresses: crate::EgressAddressRequest::Explicit {
                    addresses: vec!["198.51.100.10".parse().unwrap()],
                },
            }],
        };
        let destination: IpAddr = "203.0.113.80".parse().unwrap();
        let first = principal("a");
        let second = principal("b");
        let mut ledger = crate::EgressFqdnObservationLedger::default();
        ledger
            .apply(
                &first,
                batch(
                    &first,
                    vec![observation(
                        &first.node_uid,
                        "finance/production",
                        "api.partner.test",
                        destination,
                        60,
                        NOW,
                    )],
                    1,
                ),
                NOW,
            )
            .unwrap();
        ledger
            .apply(
                &second,
                batch(
                    &second,
                    vec![observation(
                        &second.node_uid,
                        "finance/production",
                        "api.partner.test",
                        destination,
                        60,
                        NOW,
                    )],
                    1,
                ),
                NOW,
            )
            .unwrap();
        let (materialized, reports) =
            materialize_egress_fqdn_model(model.clone(), &ledger, Revision::new(9), NOW).unwrap();
        let EgressDestinations::Fqdn(snapshot) = &materialized.intents[0].destinations else {
            panic!("PLR snapshot was not materialized");
        };
        assert_eq!(snapshot.leases.len(), 1);
        assert_eq!(snapshot.leases[0].address, destination);
        assert_eq!(reports[&owner].admitted_destinations, 1);

        ledger
            .apply(&first, batch(&first, Vec::new(), 2), NOW)
            .unwrap();
        let (withdrawn, reports) =
            materialize_egress_fqdn_model(model, &ledger, Revision::new(9), NOW).unwrap();
        let EgressDestinations::Fqdn(snapshot) = &withdrawn.intents[0].destinations else {
            panic!("empty PLR snapshot was not materialized");
        };
        assert!(snapshot.leases.is_empty());
        assert_eq!(reports[&owner].below_quorum_destinations, 1);
    }
}
