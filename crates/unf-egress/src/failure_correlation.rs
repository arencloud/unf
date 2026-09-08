//! Dependency-aware correlation of fast egress failure evidence.
//!
//! The Causal Failure Lattice (CFL) prevents a common failover hazard: one
//! physical fault can produce many BFD, routing, and dataplane symptoms, while
//! replica counts make those correlated symptoms look independent. CFL binds
//! every signal to an exact DQR plan, collapses shared dependencies into one
//! incident, and requires distinct evidence planes before suppressing a path.
//! It deliberately cannot authorize ownership or promotion.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use unf_common::Revision;

use crate::{
    EgressReachabilityPath, EgressReachabilityPlan, EgressReachabilityPlanDigest,
    MAX_EGRESS_REACHABILITY_ID_BYTES, verify_egress_reachability_plan,
};

pub const EGRESS_FAILURE_CORRELATION_SCHEMA_VERSION: u16 = 1;
pub const EGRESS_FAILURE_CORRELATION_ALGORITHM: &str = "causal-failure-lattice-v1";
pub const MAX_EGRESS_FAILURE_SIGNALS: usize = 1_024;
pub const MAX_EGRESS_FAILURE_DEPENDENCIES: usize = 16;
pub const MAX_EGRESS_FAILURE_SIGNAL_AGE_SECONDS: u64 = 300;
pub const MAX_EGRESS_FAILURE_RECOVERY_HOLD_SECONDS: u64 = 900;

const PLAN_DIGEST_DOMAIN: &[u8] = b"unf.egress.failure-correlation.plan.v1\0";
const SIGNAL_DIGEST_DOMAIN: &[u8] = b"unf.egress.failure-correlation.signal.v1\0";
const ASSESSMENT_DIGEST_DOMAIN: &[u8] = b"unf.egress.failure-correlation.assessment.v1\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EgressFailureCorrelationPlanDigest(pub [u8; 32]);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EgressFailureSignalDigest(pub [u8; 32]);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EgressFailureAssessmentDigest(pub [u8; 32]);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum EgressFailurePlane {
    /// Fast session liveness such as BFD. Never sufficient by itself.
    FastLiveness,
    /// BGP/RIB or another provider control-plane view.
    RouteControl,
    /// An independent forwarding-path witness.
    Dataplane,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum EgressFailureSignalState {
    Up,
    Down,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EgressFailureObserver {
    pub name: String,
    pub failure_domain: String,
    pub plane: EgressFailurePlane,
}

/// One finite, replayable signal. `dependencies` names causal atoms such as
/// `gateway/<uid>`, `peer/<address>`, or `fabric/<domain>`. Overlapping atoms
/// are transitively collapsed so duplicate symptoms cannot manufacture votes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EgressFailureSignal {
    pub schema_version: u16,
    pub algorithm: String,
    pub plan_digest: EgressFailureCorrelationPlanDigest,
    pub path: EgressReachabilityPath,
    pub observer: EgressFailureObserver,
    pub dependencies: Vec<String>,
    pub source_epoch: u64,
    pub revision: Revision,
    pub observed_at_unix_seconds: u64,
    pub valid_until_unix_seconds: u64,
    pub stable_since_unix_seconds: u64,
    pub transitions_in_window: u16,
    pub state: EgressFailureSignalState,
    pub digest: EgressFailureSignalDigest,
}

/// Exact safety policy projected from a DQR reachability plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EgressFailureCorrelationPlan {
    pub schema_version: u16,
    pub algorithm: String,
    pub reachability_plan_digest: EgressReachabilityPlanDigest,
    pub expected_paths: Vec<EgressReachabilityPath>,
    pub max_signal_age_seconds: u64,
    pub recovery_hold_seconds: u64,
    pub maximum_transitions_in_window: u16,
    pub digest: EgressFailureCorrelationPlanDigest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum EgressPathFailureStatus {
    Healthy,
    Suspect,
    CorroboratedDown,
    Unstable,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum EgressFailureRecommendation {
    Keep,
    Investigate,
    SuppressPaths,
    /// All planned paths are corroborated down. This asks the existing HA
    /// authority to fence sources; it does not authorize a replacement owner.
    FenceSources,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EgressPathFailureAssessment {
    pub path: EgressReachabilityPath,
    pub status: EgressPathFailureStatus,
    pub planes: Vec<EgressFailurePlane>,
    pub signal_digests: Vec<EgressFailureSignalDigest>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EgressFailureIncident {
    pub dependencies: Vec<String>,
    pub affected_paths: Vec<EgressReachabilityPath>,
    pub signal_digests: Vec<EgressFailureSignalDigest>,
}

/// Advisory output only. There is intentionally no ownership, lease, or
/// promotion capability in this type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EgressFailureAssessment {
    pub schema_version: u16,
    pub algorithm: String,
    pub plan_digest: EgressFailureCorrelationPlanDigest,
    pub compiled_at_unix_seconds: u64,
    pub recommendation: EgressFailureRecommendation,
    pub paths: Vec<EgressPathFailureAssessment>,
    pub incidents: Vec<EgressFailureIncident>,
    pub suppressed_paths: Vec<EgressReachabilityPath>,
    pub digest: EgressFailureAssessmentDigest,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum EgressFailureCorrelationError {
    #[error("invalid or unsupported failure-correlation plan")]
    InvalidPlan,
    #[error("failure-correlation plan digest does not match")]
    PlanDigestMismatch,
    #[error("invalid or noncanonical failure signal")]
    InvalidSignal,
    #[error("failure signal digest does not match")]
    SignalDigestMismatch,
    #[error("failure signal set is oversized or contains duplicate sources")]
    InvalidSignalSet,
    #[error("failure assessment digest does not match")]
    AssessmentDigestMismatch,
    #[error("failure-correlation canonical encoding failed: {0}")]
    Encoding(String),
}

/// Projects a bounded correlation policy from an already sealed DQR plan.
///
/// # Errors
///
/// Rejects an invalid DQR plan or unsafe signal-age, recovery, or flap bounds.
pub fn derive_egress_failure_correlation_plan(
    reachability: &EgressReachabilityPlan,
    max_signal_age_seconds: u64,
    recovery_hold_seconds: u64,
    maximum_transitions_in_window: u16,
) -> Result<EgressFailureCorrelationPlan, EgressFailureCorrelationError> {
    let reachability = verify_egress_reachability_plan(reachability.clone())
        .map_err(|_| EgressFailureCorrelationError::InvalidPlan)?;
    seal_plan(EgressFailureCorrelationPlan {
        schema_version: EGRESS_FAILURE_CORRELATION_SCHEMA_VERSION,
        algorithm: EGRESS_FAILURE_CORRELATION_ALGORITHM.to_owned(),
        reachability_plan_digest: reachability.digest,
        expected_paths: reachability.expected_paths,
        max_signal_age_seconds,
        recovery_hold_seconds,
        maximum_transitions_in_window,
        digest: EgressFailureCorrelationPlanDigest([0; 32]),
    })
}

/// Independently replays a correlation plan.
///
/// # Errors
///
/// Rejects any semantic, canonical, or digest drift.
pub fn verify_egress_failure_correlation_plan(
    plan: EgressFailureCorrelationPlan,
) -> Result<EgressFailureCorrelationPlan, EgressFailureCorrelationError> {
    let expected = plan.digest;
    let replayed = seal_plan(plan)?;
    if replayed.digest != expected {
        return Err(EgressFailureCorrelationError::PlanDigestMismatch);
    }
    Ok(replayed)
}

fn seal_plan(
    mut plan: EgressFailureCorrelationPlan,
) -> Result<EgressFailureCorrelationPlan, EgressFailureCorrelationError> {
    plan.expected_paths.sort_unstable();
    if plan.schema_version != EGRESS_FAILURE_CORRELATION_SCHEMA_VERSION
        || plan.algorithm != EGRESS_FAILURE_CORRELATION_ALGORITHM
        || plan.expected_paths.is_empty()
        || plan
            .expected_paths
            .windows(2)
            .any(|pair| pair[0] == pair[1])
        || plan.max_signal_age_seconds == 0
        || plan.max_signal_age_seconds > MAX_EGRESS_FAILURE_SIGNAL_AGE_SECONDS
        || plan.recovery_hold_seconds > MAX_EGRESS_FAILURE_RECOVERY_HOLD_SECONDS
        || plan.maximum_transitions_in_window == 0
        || plan
            .expected_paths
            .iter()
            .any(|path| !valid_id(&path.gateway_uid) || !valid_id(&path.forwarding_identity))
    {
        return Err(EgressFailureCorrelationError::InvalidPlan);
    }
    plan.digest = EgressFailureCorrelationPlanDigest(hash(
        PLAN_DIGEST_DOMAIN,
        &(
            plan.schema_version,
            &plan.algorithm,
            plan.reachability_plan_digest,
            &plan.expected_paths,
            plan.max_signal_age_seconds,
            plan.recovery_hold_seconds,
            plan.maximum_transitions_in_window,
        ),
    )?);
    Ok(plan)
}

/// Canonicalizes and seals one bounded failure signal.
///
/// # Errors
///
/// Rejects foreign paths/plans, invalid provenance or time bounds, and
/// duplicate or unbounded causal dependencies.
pub fn seal_egress_failure_signal(
    plan: &EgressFailureCorrelationPlan,
    mut signal: EgressFailureSignal,
) -> Result<EgressFailureSignal, EgressFailureCorrelationError> {
    let plan = verify_egress_failure_correlation_plan(plan.clone())?;
    signal.dependencies.sort_unstable();
    if signal.schema_version != EGRESS_FAILURE_CORRELATION_SCHEMA_VERSION
        || signal.algorithm != EGRESS_FAILURE_CORRELATION_ALGORITHM
        || signal.plan_digest != plan.digest
        || !plan.expected_paths.contains(&signal.path)
        || !valid_id(&signal.observer.name)
        || !valid_id(&signal.observer.failure_domain)
        || signal.dependencies.is_empty()
        || signal.dependencies.len() > MAX_EGRESS_FAILURE_DEPENDENCIES
        || signal.dependencies.iter().any(|value| !valid_id(value))
        || signal
            .dependencies
            .windows(2)
            .any(|pair| pair[0] == pair[1])
        || signal.source_epoch == 0
        || signal.revision == Revision::INITIAL
        || signal.observed_at_unix_seconds == 0
        || signal.stable_since_unix_seconds > signal.observed_at_unix_seconds
        || signal.valid_until_unix_seconds <= signal.observed_at_unix_seconds
        || signal.valid_until_unix_seconds - signal.observed_at_unix_seconds
            > plan.max_signal_age_seconds
    {
        return Err(EgressFailureCorrelationError::InvalidSignal);
    }
    signal.digest = EgressFailureSignalDigest(hash(
        SIGNAL_DIGEST_DOMAIN,
        &(
            signal.schema_version,
            &signal.algorithm,
            signal.plan_digest,
            &signal.path,
            &signal.observer,
            &signal.dependencies,
            signal.source_epoch,
            signal.revision,
            signal.observed_at_unix_seconds,
            signal.valid_until_unix_seconds,
            signal.stable_since_unix_seconds,
            signal.transitions_in_window,
            signal.state,
        ),
    )?);
    Ok(signal)
}

/// Independently replays one sealed failure signal.
///
/// # Errors
///
/// Rejects any semantic, canonical, or digest drift.
pub fn verify_egress_failure_signal(
    plan: &EgressFailureCorrelationPlan,
    signal: EgressFailureSignal,
) -> Result<EgressFailureSignal, EgressFailureCorrelationError> {
    let expected = signal.digest;
    let replayed = seal_egress_failure_signal(plan, signal)?;
    if replayed.digest != expected {
        return Err(EgressFailureCorrelationError::SignalDigestMismatch);
    }
    Ok(replayed)
}

/// Correlates current evidence. Suppression requires Down evidence from at
/// least two distinct planes. Recovery requires two Up planes to remain stable
/// for the configured hold; excessive transitions remain `Unstable`.
///
/// # Errors
///
/// Rejects an invalid plan, malformed/replayed signal, duplicate source, or
/// oversized evidence set.
pub fn assess_egress_failures(
    plan: EgressFailureCorrelationPlan,
    signals: Vec<EgressFailureSignal>,
    now_unix_seconds: u64,
) -> Result<EgressFailureAssessment, EgressFailureCorrelationError> {
    let plan = verify_egress_failure_correlation_plan(plan)?;
    if now_unix_seconds == 0 || signals.len() > MAX_EGRESS_FAILURE_SIGNALS {
        return Err(EgressFailureCorrelationError::InvalidSignalSet);
    }
    let mut signals = signals
        .into_iter()
        .map(|signal| verify_egress_failure_signal(&plan, signal))
        .collect::<Result<Vec<_>, _>>()?;
    signals.sort_unstable_by(|left, right| signal_source_key(left).cmp(&signal_source_key(right)));
    if signals
        .windows(2)
        .any(|pair| signal_source_key(&pair[0]) == signal_source_key(&pair[1]))
    {
        return Err(EgressFailureCorrelationError::InvalidSignalSet);
    }
    let current = signals
        .iter()
        .filter(|signal| {
            signal.observed_at_unix_seconds <= now_unix_seconds
                && now_unix_seconds <= signal.valid_until_unix_seconds
                && now_unix_seconds - signal.observed_at_unix_seconds <= plan.max_signal_age_seconds
        })
        .collect::<Vec<_>>();

    let mut paths = Vec::with_capacity(plan.expected_paths.len());
    for path in &plan.expected_paths {
        let evidence = current
            .iter()
            .copied()
            .filter(|signal| signal.path == *path)
            .collect::<Vec<_>>();
        paths.push(assess_path(
            &plan,
            path.clone(),
            &evidence,
            now_unix_seconds,
        ));
    }
    let suppressed_paths = paths
        .iter()
        .filter(|path| path.status == EgressPathFailureStatus::CorroboratedDown)
        .map(|path| path.path.clone())
        .collect::<Vec<_>>();
    let recommendation = if suppressed_paths.len() == plan.expected_paths.len() {
        EgressFailureRecommendation::FenceSources
    } else if !suppressed_paths.is_empty() {
        EgressFailureRecommendation::SuppressPaths
    } else if paths.iter().any(|path| {
        matches!(
            path.status,
            EgressPathFailureStatus::Suspect | EgressPathFailureStatus::Unstable
        )
    }) {
        EgressFailureRecommendation::Investigate
    } else {
        EgressFailureRecommendation::Keep
    };
    let incidents = causal_incidents(&current);
    seal_assessment(EgressFailureAssessment {
        schema_version: EGRESS_FAILURE_CORRELATION_SCHEMA_VERSION,
        algorithm: EGRESS_FAILURE_CORRELATION_ALGORITHM.to_owned(),
        plan_digest: plan.digest,
        compiled_at_unix_seconds: now_unix_seconds,
        recommendation,
        paths,
        incidents,
        suppressed_paths,
        digest: EgressFailureAssessmentDigest([0; 32]),
    })
}

/// Independently replays an advisory failure assessment.
///
/// # Errors
///
/// Rejects invalid evidence or any assessment/digest mutation.
pub fn verify_egress_failure_assessment(
    plan: EgressFailureCorrelationPlan,
    signals: Vec<EgressFailureSignal>,
    assessment: &EgressFailureAssessment,
) -> Result<(), EgressFailureCorrelationError> {
    let replayed = assess_egress_failures(plan, signals, assessment.compiled_at_unix_seconds)?;
    if &replayed != assessment {
        return Err(EgressFailureCorrelationError::AssessmentDigestMismatch);
    }
    Ok(())
}

fn assess_path(
    plan: &EgressFailureCorrelationPlan,
    path: EgressReachabilityPath,
    evidence: &[&EgressFailureSignal],
    now: u64,
) -> EgressPathFailureAssessment {
    let mut plane_evidence =
        BTreeMap::<EgressFailurePlane, BTreeSet<EgressFailureSignalState>>::new();
    let mut planes = BTreeSet::new();
    let mut digests = Vec::with_capacity(evidence.len());
    let mut unstable = false;
    let mut recovery_stable = true;
    for signal in evidence {
        planes.insert(signal.observer.plane);
        plane_evidence
            .entry(signal.observer.plane)
            .or_default()
            .insert(signal.state);
        digests.push(signal.digest);
        unstable |= signal.transitions_in_window > plan.maximum_transitions_in_window;
        recovery_stable &= signal.state == EgressFailureSignalState::Up
            && signal
                .stable_since_unix_seconds
                .checked_add(plan.recovery_hold_seconds)
                .is_some_and(|deadline| deadline <= now);
    }
    unstable |= plane_evidence.values().any(|values| values.len() > 1);
    let down_planes = plane_evidence
        .iter()
        .filter(|(_, values)| values.len() == 1 && values.contains(&EgressFailureSignalState::Down))
        .count();
    let up_planes = plane_evidence
        .iter()
        .filter(|(_, values)| values.len() == 1 && values.contains(&EgressFailureSignalState::Up))
        .count();
    let path_status = if down_planes >= 2 {
        EgressPathFailureStatus::CorroboratedDown
    } else if unstable {
        EgressPathFailureStatus::Unstable
    } else if down_planes == 1 {
        EgressPathFailureStatus::Suspect
    } else if up_planes >= 2 && recovery_stable {
        EgressPathFailureStatus::Healthy
    } else {
        EgressPathFailureStatus::Unknown
    };
    digests.sort_unstable();
    EgressPathFailureAssessment {
        path,
        status: path_status,
        planes: planes.into_iter().collect(),
        signal_digests: digests,
    }
}

fn causal_incidents(signals: &[&EgressFailureSignal]) -> Vec<EgressFailureIncident> {
    let mut groups: Vec<(
        BTreeSet<String>,
        BTreeSet<EgressReachabilityPath>,
        BTreeSet<EgressFailureSignalDigest>,
    )> = Vec::new();
    for signal in signals
        .iter()
        .copied()
        .filter(|signal| signal.state == EgressFailureSignalState::Down)
    {
        let mut dependencies = signal.dependencies.iter().cloned().collect::<BTreeSet<_>>();
        let mut paths = BTreeSet::from([signal.path.clone()]);
        let mut digests = BTreeSet::from([signal.digest]);
        let mut index = 0;
        while index < groups.len() {
            if groups[index].0.is_disjoint(&dependencies) {
                index += 1;
            } else {
                let (other_dependencies, other_paths, other_digests) = groups.remove(index);
                dependencies.extend(other_dependencies);
                paths.extend(other_paths);
                digests.extend(other_digests);
            }
        }
        groups.push((dependencies, paths, digests));
    }
    let mut incidents = groups
        .into_iter()
        .map(|(dependencies, paths, digests)| EgressFailureIncident {
            dependencies: dependencies.into_iter().collect(),
            affected_paths: paths.into_iter().collect(),
            signal_digests: digests.into_iter().collect(),
        })
        .collect::<Vec<_>>();
    incidents.sort_unstable_by(|left, right| left.dependencies.cmp(&right.dependencies));
    incidents
}

fn seal_assessment(
    mut assessment: EgressFailureAssessment,
) -> Result<EgressFailureAssessment, EgressFailureCorrelationError> {
    assessment.digest = EgressFailureAssessmentDigest(hash(
        ASSESSMENT_DIGEST_DOMAIN,
        &(
            assessment.schema_version,
            &assessment.algorithm,
            assessment.plan_digest,
            assessment.compiled_at_unix_seconds,
            assessment.recommendation,
            &assessment.paths,
            &assessment.incidents,
            &assessment.suppressed_paths,
        ),
    )?);
    Ok(assessment)
}

fn signal_source_key(
    signal: &EgressFailureSignal,
) -> (&EgressReachabilityPath, EgressFailurePlane, &str) {
    (&signal.path, signal.observer.plane, &signal.observer.name)
}

fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_EGRESS_REACHABILITY_ID_BYTES
        && !value.chars().any(char::is_control)
}

fn hash<T: Serialize>(domain: &[u8], value: &T) -> Result<[u8; 32], EgressFailureCorrelationError> {
    let encoded = serde_json::to_vec(value)
        .map_err(|error| EgressFailureCorrelationError::Encoding(error.to_string()))?;
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update(encoded);
    Ok(digest.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        EGRESS_REACHABILITY_ALGORITHM_DIVERSITY_QUORUM_V1, EGRESS_REACHABILITY_SCHEMA_VERSION,
        EgressGatewayAction, EgressIntentOwner, EgressIntentScope, EgressProviderRef,
        EgressReachabilityPlanDigest, EgressReachabilityVantage, seal_egress_reachability_plan,
    };

    const NOW: u64 = 10_000;

    fn reachability() -> EgressReachabilityPlan {
        seal_egress_reachability_plan(EgressReachabilityPlan {
            schema_version: EGRESS_REACHABILITY_SCHEMA_VERSION,
            algorithm: EGRESS_REACHABILITY_ALGORITHM_DIVERSITY_QUORUM_V1.to_owned(),
            revision: Revision::new(3),
            desired_revision: Revision::new(2),
            allocation_revision: Revision::new(1),
            owner: EgressIntentOwner {
                scope: EgressIntentScope::Cluster,
                name: "payments".to_owned(),
                uid: "payments-uid".to_owned(),
            },
            provider: EgressProviderRef {
                name: "bgp".to_owned(),
                instance: "edge".to_owned(),
            },
            lease_epoch: 1,
            action: EgressGatewayAction::Ensure,
            addresses: vec![
                "192.0.2.20".parse().unwrap(),
                "2001:db8::20".parse().unwrap(),
            ],
            expected_paths: vec![
                EgressReachabilityPath {
                    gateway_uid: "gateway-a".to_owned(),
                    forwarding_identity: "fabric-a".to_owned(),
                },
                EgressReachabilityPath {
                    gateway_uid: "gateway-b".to_owned(),
                    forwarding_identity: "fabric-b".to_owned(),
                },
            ],
            minimum_paths_per_address: 1,
            maximum_paths_per_address: 2,
            vantages: vec![EgressReachabilityVantage {
                name: "edge".to_owned(),
                minimum_failure_domains: 1,
            }],
            max_observation_age_seconds: 60,
            digest: EgressReachabilityPlanDigest([0; 32]),
        })
        .unwrap()
    }

    fn plan() -> EgressFailureCorrelationPlan {
        derive_egress_failure_correlation_plan(&reachability(), 30, 10, 3).unwrap()
    }

    fn signal(
        plan: &EgressFailureCorrelationPlan,
        path: usize,
        plane: EgressFailurePlane,
        observer: &str,
        state: EgressFailureSignalState,
        dependency: &str,
    ) -> EgressFailureSignal {
        seal_egress_failure_signal(
            plan,
            EgressFailureSignal {
                schema_version: EGRESS_FAILURE_CORRELATION_SCHEMA_VERSION,
                algorithm: EGRESS_FAILURE_CORRELATION_ALGORITHM.to_owned(),
                plan_digest: plan.digest,
                path: plan.expected_paths[path].clone(),
                observer: EgressFailureObserver {
                    name: observer.to_owned(),
                    failure_domain: format!("{observer}-domain"),
                    plane,
                },
                dependencies: vec![dependency.to_owned()],
                source_epoch: 1,
                revision: Revision::new(1),
                observed_at_unix_seconds: NOW - 5,
                valid_until_unix_seconds: NOW + 20,
                stable_since_unix_seconds: NOW - 20,
                transitions_in_window: 1,
                state,
                digest: EgressFailureSignalDigest([0; 32]),
            },
        )
        .unwrap()
    }

    #[test]
    fn bfd_alone_is_suspect_and_never_suppresses() {
        let plan = plan();
        let assessment = assess_egress_failures(
            plan.clone(),
            vec![signal(
                &plan,
                0,
                EgressFailurePlane::FastLiveness,
                "bfd-a",
                EgressFailureSignalState::Down,
                "gateway/gateway-a",
            )],
            NOW,
        )
        .unwrap();
        assert_eq!(
            assessment.recommendation,
            EgressFailureRecommendation::Investigate
        );
        assert!(assessment.suppressed_paths.is_empty());
        assert_eq!(assessment.paths[0].status, EgressPathFailureStatus::Suspect);
    }

    #[test]
    fn duplicate_symptoms_collapse_but_distinct_planes_corroborate() {
        let plan = plan();
        let signals = vec![
            signal(
                &plan,
                0,
                EgressFailurePlane::FastLiveness,
                "bfd-east",
                EgressFailureSignalState::Down,
                "gateway/gateway-a",
            ),
            signal(
                &plan,
                0,
                EgressFailurePlane::FastLiveness,
                "bfd-west",
                EgressFailureSignalState::Down,
                "gateway/gateway-a",
            ),
            signal(
                &plan,
                0,
                EgressFailurePlane::RouteControl,
                "rib",
                EgressFailureSignalState::Down,
                "gateway/gateway-a",
            ),
        ];
        let assessment = assess_egress_failures(plan.clone(), signals.clone(), NOW).unwrap();
        assert_eq!(
            assessment.recommendation,
            EgressFailureRecommendation::SuppressPaths
        );
        assert_eq!(assessment.suppressed_paths, plan.expected_paths[..1]);
        assert_eq!(assessment.incidents.len(), 1);
        assert_eq!(assessment.incidents[0].signal_digests.len(), 3);
        verify_egress_failure_assessment(plan, signals, &assessment).unwrap();
    }

    #[test]
    fn every_corroborated_path_requests_fencing_not_promotion() {
        let plan = plan();
        let signals = (0..2)
            .flat_map(|path| {
                [
                    signal(
                        &plan,
                        path,
                        EgressFailurePlane::FastLiveness,
                        &format!("bfd-{path}"),
                        EgressFailureSignalState::Down,
                        &format!("gateway/gateway-{path}"),
                    ),
                    signal(
                        &plan,
                        path,
                        EgressFailurePlane::Dataplane,
                        &format!("probe-{path}"),
                        EgressFailureSignalState::Down,
                        &format!("gateway/gateway-{path}"),
                    ),
                ]
            })
            .collect();
        let assessment = assess_egress_failures(plan, signals, NOW).unwrap();
        assert_eq!(
            assessment.recommendation,
            EgressFailureRecommendation::FenceSources
        );
    }

    #[test]
    fn recovery_hold_and_flap_budget_prevent_optimistic_restore() {
        let plan = plan();
        let mut bfd = signal(
            &plan,
            0,
            EgressFailurePlane::FastLiveness,
            "bfd",
            EgressFailureSignalState::Up,
            "gateway/gateway-a",
        );
        let route = signal(
            &plan,
            0,
            EgressFailurePlane::RouteControl,
            "rib",
            EgressFailureSignalState::Up,
            "gateway/gateway-a",
        );
        bfd.stable_since_unix_seconds = NOW - 5;
        bfd = seal_egress_failure_signal(&plan, bfd).unwrap();
        let holding =
            assess_egress_failures(plan.clone(), vec![bfd.clone(), route.clone()], NOW).unwrap();
        assert_eq!(holding.paths[0].status, EgressPathFailureStatus::Unknown);
        bfd.stable_since_unix_seconds = NOW - 20;
        bfd.transitions_in_window = 4;
        bfd = seal_egress_failure_signal(&plan, bfd).unwrap();
        let flapping = assess_egress_failures(plan, vec![bfd, route], NOW).unwrap();
        assert_eq!(flapping.paths[0].status, EgressPathFailureStatus::Unstable);
        assert_eq!(
            flapping.recommendation,
            EgressFailureRecommendation::Investigate
        );
    }

    #[test]
    fn mutations_and_duplicate_sources_are_rejected() {
        let plan = plan();
        let signal = signal(
            &plan,
            0,
            EgressFailurePlane::FastLiveness,
            "bfd",
            EgressFailureSignalState::Down,
            "gateway/gateway-a",
        );
        let mut changed = signal.clone();
        changed.state = EgressFailureSignalState::Up;
        assert_eq!(
            verify_egress_failure_signal(&plan, changed),
            Err(EgressFailureCorrelationError::SignalDigestMismatch)
        );
        assert_eq!(
            assess_egress_failures(plan, vec![signal.clone(), signal], NOW),
            Err(EgressFailureCorrelationError::InvalidSignalSet)
        );
    }
}
