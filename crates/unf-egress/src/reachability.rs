//! Provider-neutral, proof-carrying egress reachability decisions.
//!
//! Diversity-Quorum Reachability (DQR) deliberately separates the component
//! that mutates routing state from the observers that prove its effect. A raw
//! provider acknowledgement is never sufficient: every required network
//! vantage must supply a bounded quorum of distinct failure domains, and those
//! witnesses must agree on the exact per-address path set.

use std::collections::BTreeSet;
use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use unf_common::Revision;

use crate::{
    EgressGatewayAction, EgressIntentOwner, EgressProviderRef, MAX_EGRESS_ADDRESSES_PER_INTENT,
    MAX_EGRESS_GATEWAY_NODES,
};

pub const EGRESS_REACHABILITY_SCHEMA_VERSION: u16 = 1;
pub const EGRESS_REACHABILITY_ALGORITHM_DIVERSITY_QUORUM_V1: &str =
    "diversity-quorum-reachability-v1";
pub const MAX_EGRESS_REACHABILITY_VANTAGES: usize = 16;
pub const MAX_EGRESS_REACHABILITY_OBSERVERS: usize = 256;
pub const MAX_EGRESS_REACHABILITY_DOMAINS_PER_VANTAGE: u16 = 16;
pub const MAX_EGRESS_REACHABILITY_OBSERVATION_AGE_SECONDS: u64 = 300;
pub const MAX_EGRESS_REACHABILITY_FUTURE_SKEW_SECONDS: u64 = 30;
pub const MAX_EGRESS_REACHABILITY_ID_BYTES: usize = 253;

const PLAN_DIGEST_DOMAIN: &[u8] = b"unf.egress.reachability.plan.v1\0";
const OBSERVATION_DIGEST_DOMAIN: &[u8] = b"unf.egress.reachability.observation.v1\0";
const ASSESSMENT_DIGEST_DOMAIN: &[u8] = b"unf.egress.reachability.assessment.v1\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EgressReachabilityPlanDigest(pub [u8; 32]);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EgressReachabilityObservationDigest(pub [u8; 32]);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EgressReachabilityAssessmentDigest(pub [u8; 32]);

/// One provider-neutral path that is permitted to make an egress address
/// reachable. `forwarding_identity` is an exact adapter-defined stable key
/// such as a local interface, BGP peer/next-hop tuple, cloud route target, or
/// inter-cluster gateway identity.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EgressReachabilityPath {
    pub gateway_uid: String,
    pub forwarding_identity: String,
}

/// A named observation location and its minimum number of independently
/// administered/failing witness domains.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EgressReachabilityVantage {
    pub name: String,
    pub minimum_failure_domains: u16,
}

/// Exact reachability intent. It is separate from a BGP, cloud, static, or
/// overlay adapter and binds every decision to the allocation lease.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EgressReachabilityPlan {
    pub schema_version: u16,
    pub algorithm: String,
    pub revision: Revision,
    pub desired_revision: Revision,
    pub allocation_revision: Revision,
    pub owner: EgressIntentOwner,
    pub provider: EgressProviderRef,
    pub lease_epoch: u64,
    pub action: EgressGatewayAction,
    pub addresses: Vec<IpAddr>,
    pub expected_paths: Vec<EgressReachabilityPath>,
    pub minimum_paths_per_address: u16,
    pub maximum_paths_per_address: u16,
    pub vantages: Vec<EgressReachabilityVantage>,
    pub max_observation_age_seconds: u64,
    pub digest: EgressReachabilityPlanDigest,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EgressReachabilityObserver {
    pub name: String,
    pub failure_domain: String,
    pub vantage: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EgressReachabilityRouteObservation {
    pub address: IpAddr,
    pub paths: Vec<EgressReachabilityPath>,
}

/// A complete observation of every address from one observer. Empty paths are
/// positive evidence of absence only within the explicitly named vantage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EgressReachabilityObservation {
    pub schema_version: u16,
    pub algorithm: String,
    pub plan_digest: EgressReachabilityPlanDigest,
    pub observer: EgressReachabilityObserver,
    pub source_epoch: u64,
    pub revision: Revision,
    pub observed_at_unix_seconds: u64,
    pub valid_until_unix_seconds: u64,
    pub routes: Vec<EgressReachabilityRouteObservation>,
    pub digest: EgressReachabilityObservationDigest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum EgressReachabilityVerdict {
    Ready,
    Withdrawn,
    DenyClosed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum EgressReachabilityReason {
    Verified,
    MissingDiversityQuorum,
    ExpiredEvidence,
    ConflictingEvidence,
    PathCardinalityMismatch,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EgressReachabilityVantageProof {
    pub vantage: String,
    pub failure_domains: Vec<String>,
    pub observation_digests: Vec<EgressReachabilityObservationDigest>,
}

/// A deterministic, independently replayable reachability result. Positive
/// authority always has a finite absolute deadline; deny-closed assessments
/// have no authority beyond their compilation instant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EgressReachabilityAssessment {
    pub schema_version: u16,
    pub algorithm: String,
    pub plan_digest: EgressReachabilityPlanDigest,
    pub compiled_at_unix_seconds: u64,
    pub authority_until_unix_seconds: u64,
    pub verdict: EgressReachabilityVerdict,
    pub reason: EgressReachabilityReason,
    pub vantages: Vec<EgressReachabilityVantageProof>,
    pub digest: EgressReachabilityAssessmentDigest,
}

/// An assessment admitted only after compiling or independently replaying its
/// complete observation set. The private field prevents a digest-shaped claim
/// from being consumed as authority without evidence verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedEgressReachabilityAssessment(EgressReachabilityAssessment);

impl VerifiedEgressReachabilityAssessment {
    #[must_use]
    pub const fn assessment(&self) -> &EgressReachabilityAssessment {
        &self.0
    }
}

impl std::ops::Deref for VerifiedEgressReachabilityAssessment {
    type Target = EgressReachabilityAssessment;

    fn deref(&self) -> &Self::Target {
        self.assessment()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum EgressReachabilityError {
    #[error("unsupported egress reachability schema or algorithm")]
    UnsupportedVersion,
    #[error("egress reachability plan is invalid or noncanonical")]
    InvalidPlan,
    #[error("egress reachability plan digest does not match")]
    PlanDigestMismatch,
    #[error("egress reachability observation is invalid or noncanonical")]
    InvalidObservation,
    #[error("egress reachability observation digest does not match")]
    ObservationDigestMismatch,
    #[error("egress reachability observation set is oversized")]
    TooManyObservations,
    #[error("egress reachability observer appears more than once")]
    DuplicateObserver,
    #[error("egress reachability assessment is invalid or noncanonical")]
    InvalidAssessment,
    #[error("egress reachability assessment digest does not match")]
    AssessmentDigestMismatch,
    #[error("egress reachability canonical encoding failed: {0}")]
    Encoding(String),
}

/// Canonicalizes and seals one exact reachability plan.
///
/// # Errors
///
/// Rejects unsupported versions, missing lease/revision identity, invalid
/// bounds, duplicate addresses/paths/vantages, or unbounded identifiers.
pub fn seal_egress_reachability_plan(
    mut plan: EgressReachabilityPlan,
) -> Result<EgressReachabilityPlan, EgressReachabilityError> {
    if plan.schema_version != EGRESS_REACHABILITY_SCHEMA_VERSION
        || plan.algorithm != EGRESS_REACHABILITY_ALGORITHM_DIVERSITY_QUORUM_V1
        || plan.revision == Revision::INITIAL
        || plan.desired_revision == Revision::INITIAL
        || plan.allocation_revision == Revision::INITIAL
        || plan.lease_epoch == 0
        || !valid_owner(&plan.owner)
        || !valid_provider(&plan.provider)
        || plan.addresses.is_empty()
        || plan.addresses.len() > MAX_EGRESS_ADDRESSES_PER_INTENT
        || plan.expected_paths.is_empty()
        || plan.expected_paths.len() > MAX_EGRESS_GATEWAY_NODES
        || plan.vantages.is_empty()
        || plan.vantages.len() > MAX_EGRESS_REACHABILITY_VANTAGES
        || plan.minimum_paths_per_address == 0
        || plan.maximum_paths_per_address < plan.minimum_paths_per_address
        || usize::from(plan.maximum_paths_per_address) > plan.expected_paths.len()
        || plan.max_observation_age_seconds == 0
        || plan.max_observation_age_seconds > MAX_EGRESS_REACHABILITY_OBSERVATION_AGE_SECONDS
    {
        return Err(EgressReachabilityError::InvalidPlan);
    }
    if plan.addresses.iter().any(invalid_address)
        || plan
            .expected_paths
            .iter()
            .any(|path| !valid_id(&path.gateway_uid) || !valid_id(&path.forwarding_identity))
        || plan.vantages.iter().any(|vantage| {
            !valid_id(&vantage.name)
                || vantage.minimum_failure_domains == 0
                || vantage.minimum_failure_domains > MAX_EGRESS_REACHABILITY_DOMAINS_PER_VANTAGE
        })
    {
        return Err(EgressReachabilityError::InvalidPlan);
    }
    plan.addresses.sort_unstable();
    plan.expected_paths.sort_unstable();
    plan.vantages.sort_unstable();
    if has_duplicates(&plan.addresses)
        || has_duplicates(&plan.expected_paths)
        || plan
            .vantages
            .windows(2)
            .any(|pair| pair[0].name == pair[1].name)
    {
        return Err(EgressReachabilityError::InvalidPlan);
    }
    plan.digest = plan_digest(&plan)?;
    Ok(plan)
}

/// Replays and verifies a sealed reachability plan.
///
/// # Errors
///
/// Rejects any semantic, canonical, or digest drift.
pub fn verify_egress_reachability_plan(
    plan: EgressReachabilityPlan,
) -> Result<EgressReachabilityPlan, EgressReachabilityError> {
    let expected = plan.digest;
    let replayed = seal_egress_reachability_plan(plan)?;
    if replayed.digest != expected {
        return Err(EgressReachabilityError::PlanDigestMismatch);
    }
    Ok(replayed)
}

/// Canonicalizes a complete observer publication against its exact plan.
///
/// # Errors
///
/// Rejects foreign plans/vantages/paths, incomplete address sets, invalid
/// temporal bounds, duplicate entries, or unbounded identity.
pub fn seal_egress_reachability_observation(
    plan: &EgressReachabilityPlan,
    mut observation: EgressReachabilityObservation,
) -> Result<EgressReachabilityObservation, EgressReachabilityError> {
    let plan = verify_egress_reachability_plan(plan.clone())?;
    if observation.schema_version != EGRESS_REACHABILITY_SCHEMA_VERSION
        || observation.algorithm != EGRESS_REACHABILITY_ALGORITHM_DIVERSITY_QUORUM_V1
        || observation.plan_digest != plan.digest
        || observation.source_epoch == 0
        || observation.revision == Revision::INITIAL
        || !valid_id(&observation.observer.name)
        || !valid_id(&observation.observer.failure_domain)
        || !plan
            .vantages
            .iter()
            .any(|vantage| vantage.name == observation.observer.vantage)
        || observation.valid_until_unix_seconds <= observation.observed_at_unix_seconds
        || observation
            .valid_until_unix_seconds
            .saturating_sub(observation.observed_at_unix_seconds)
            > plan.max_observation_age_seconds
        || observation.routes.len() != plan.addresses.len()
    {
        return Err(EgressReachabilityError::InvalidObservation);
    }
    for route in &mut observation.routes {
        route.paths.sort_unstable();
        if has_duplicates(&route.paths)
            || route
                .paths
                .iter()
                .any(|path| plan.expected_paths.binary_search(path).is_err())
        {
            return Err(EgressReachabilityError::InvalidObservation);
        }
    }
    observation.routes.sort_unstable();
    if has_duplicates_by(&observation.routes, |route| route.address)
        || observation
            .routes
            .iter()
            .map(|route| route.address)
            .ne(plan.addresses.iter().copied())
    {
        return Err(EgressReachabilityError::InvalidObservation);
    }
    observation.digest = observation_digest(&observation)?;
    Ok(observation)
}

/// Replays and verifies a sealed observer publication.
///
/// # Errors
///
/// Rejects any semantic, canonical, or digest drift.
pub fn verify_egress_reachability_observation(
    plan: &EgressReachabilityPlan,
    observation: EgressReachabilityObservation,
) -> Result<EgressReachabilityObservation, EgressReachabilityError> {
    let expected = observation.digest;
    let replayed = seal_egress_reachability_observation(plan, observation)?;
    if replayed.digest != expected {
        return Err(EgressReachabilityError::ObservationDigestMismatch);
    }
    Ok(replayed)
}

/// Compiles independent observer evidence into one finite, fail-closed result.
///
/// Quorum is counted by distinct failure domain inside every required vantage.
/// Multiple replicas in one domain can improve availability but never inflate
/// authority. All fresh observers within a vantage must agree on every route.
///
/// # Errors
///
/// Rejects malformed plans/evidence, duplicate observers, and oversized input.
#[allow(clippy::too_many_lines)]
pub fn assess_egress_reachability(
    plan: EgressReachabilityPlan,
    observations: Vec<EgressReachabilityObservation>,
    now_unix_seconds: u64,
) -> Result<VerifiedEgressReachabilityAssessment, EgressReachabilityError> {
    let plan = verify_egress_reachability_plan(plan)?;
    if observations.len() > MAX_EGRESS_REACHABILITY_OBSERVERS {
        return Err(EgressReachabilityError::TooManyObservations);
    }
    let mut verified = observations
        .into_iter()
        .map(|observation| verify_egress_reachability_observation(&plan, observation))
        .collect::<Result<Vec<_>, _>>()?;
    verified.sort_unstable_by(|left, right| left.observer.cmp(&right.observer));
    if has_duplicates_by(&verified, |observation| observation.observer.clone()) {
        return Err(EgressReachabilityError::DuplicateObserver);
    }

    let mut saw_expired = false;
    let fresh = verified
        .into_iter()
        .filter(|observation| {
            let future_ok = observation.observed_at_unix_seconds
                <= now_unix_seconds.saturating_add(MAX_EGRESS_REACHABILITY_FUTURE_SKEW_SECONDS);
            let age_deadline = observation
                .observed_at_unix_seconds
                .saturating_add(plan.max_observation_age_seconds);
            let is_fresh = future_ok
                && now_unix_seconds < observation.valid_until_unix_seconds
                && now_unix_seconds < age_deadline;
            saw_expired |= !is_fresh;
            is_fresh
        })
        .collect::<Vec<_>>();

    let mut proofs = Vec::new();
    let mut authority_until = u64::MAX;
    let mut failure = None;
    for required in &plan.vantages {
        let witnesses = fresh
            .iter()
            .filter(|observation| observation.observer.vantage == required.name)
            .collect::<Vec<_>>();
        let failure_domains = witnesses
            .iter()
            .map(|observation| observation.observer.failure_domain.clone())
            .collect::<BTreeSet<_>>();
        if failure_domains.len() < usize::from(required.minimum_failure_domains) {
            failure.get_or_insert(if saw_expired {
                EgressReachabilityReason::ExpiredEvidence
            } else {
                EgressReachabilityReason::MissingDiversityQuorum
            });
            continue;
        }

        let baseline = witnesses[0];
        if witnesses
            .iter()
            .skip(1)
            .any(|observation| observation.routes != baseline.routes)
        {
            failure = Some(EgressReachabilityReason::ConflictingEvidence);
            continue;
        }
        let cardinality_valid = baseline.routes.iter().all(|route| match plan.action {
            EgressGatewayAction::Ensure => {
                route.paths.len() >= usize::from(plan.minimum_paths_per_address)
                    && route.paths.len() <= usize::from(plan.maximum_paths_per_address)
            }
            EgressGatewayAction::Withdraw => route.paths.is_empty(),
        });
        if !cardinality_valid {
            failure = Some(EgressReachabilityReason::PathCardinalityMismatch);
            continue;
        }

        for observation in &witnesses {
            authority_until = authority_until.min(
                observation.valid_until_unix_seconds.min(
                    observation
                        .observed_at_unix_seconds
                        .saturating_add(plan.max_observation_age_seconds),
                ),
            );
        }
        proofs.push(EgressReachabilityVantageProof {
            vantage: required.name.clone(),
            failure_domains: failure_domains.into_iter().collect(),
            observation_digests: witnesses
                .iter()
                .map(|observation| observation.digest)
                .collect(),
        });
    }

    let (verdict, reason, authority_until_unix_seconds, vantages) = if let Some(reason) = failure {
        (
            EgressReachabilityVerdict::DenyClosed,
            reason,
            now_unix_seconds,
            Vec::new(),
        )
    } else if proofs.len() != plan.vantages.len() || authority_until <= now_unix_seconds {
        (
            EgressReachabilityVerdict::DenyClosed,
            if saw_expired {
                EgressReachabilityReason::ExpiredEvidence
            } else {
                EgressReachabilityReason::MissingDiversityQuorum
            },
            now_unix_seconds,
            Vec::new(),
        )
    } else {
        (
            match plan.action {
                EgressGatewayAction::Ensure => EgressReachabilityVerdict::Ready,
                EgressGatewayAction::Withdraw => EgressReachabilityVerdict::Withdrawn,
            },
            EgressReachabilityReason::Verified,
            authority_until,
            proofs,
        )
    };
    seal_assessment(EgressReachabilityAssessment {
        schema_version: EGRESS_REACHABILITY_SCHEMA_VERSION,
        algorithm: EGRESS_REACHABILITY_ALGORITHM_DIVERSITY_QUORUM_V1.to_owned(),
        plan_digest: plan.digest,
        compiled_at_unix_seconds: now_unix_seconds,
        authority_until_unix_seconds,
        verdict,
        reason,
        vantages,
        digest: EgressReachabilityAssessmentDigest([0; 32]),
    })
    .map(VerifiedEgressReachabilityAssessment)
}

/// Replays an assessment from its complete evidence set.
///
/// # Errors
///
/// Rejects assessment mutation or any input that no longer compiles exactly.
pub fn verify_egress_reachability_assessment(
    plan: EgressReachabilityPlan,
    observations: Vec<EgressReachabilityObservation>,
    assessment: &EgressReachabilityAssessment,
) -> Result<VerifiedEgressReachabilityAssessment, EgressReachabilityError> {
    let replayed =
        assess_egress_reachability(plan, observations, assessment.compiled_at_unix_seconds)?;
    if replayed.assessment() != assessment {
        return Err(EgressReachabilityError::AssessmentDigestMismatch);
    }
    Ok(replayed)
}

/// Returns the authority that a dataplane or agent may consume at `now`.
/// Positive and withdrawal assessments both become deny-closed at their
/// absolute deadline without requiring a new controller publication.
///
/// # Errors
///
/// Rejects a foreign plan, a malformed assessment, digest mutation, or use
/// before the assessment's compilation instant.
pub fn egress_reachability_verdict_at(
    plan: &EgressReachabilityPlan,
    verified: &VerifiedEgressReachabilityAssessment,
    now_unix_seconds: u64,
) -> Result<EgressReachabilityVerdict, EgressReachabilityError> {
    let plan = verify_egress_reachability_plan(plan.clone())?;
    let assessment = verified.assessment();
    if assessment.plan_digest != plan.digest
        || now_unix_seconds < assessment.compiled_at_unix_seconds
    {
        return Err(EgressReachabilityError::InvalidAssessment);
    }
    if assessment.verdict == EgressReachabilityVerdict::DenyClosed
        || now_unix_seconds >= assessment.authority_until_unix_seconds
    {
        Ok(EgressReachabilityVerdict::DenyClosed)
    } else {
        Ok(assessment.verdict)
    }
}

fn seal_assessment(
    mut assessment: EgressReachabilityAssessment,
) -> Result<EgressReachabilityAssessment, EgressReachabilityError> {
    for proof in &mut assessment.vantages {
        proof.failure_domains.sort_unstable();
        proof.observation_digests.sort_unstable();
    }
    assessment
        .vantages
        .sort_unstable_by(|left, right| left.vantage.cmp(&right.vantage));
    if assessment.schema_version != EGRESS_REACHABILITY_SCHEMA_VERSION
        || assessment.algorithm != EGRESS_REACHABILITY_ALGORITHM_DIVERSITY_QUORUM_V1
        || match assessment.verdict {
            EgressReachabilityVerdict::Ready | EgressReachabilityVerdict::Withdrawn => {
                assessment.reason != EgressReachabilityReason::Verified
                    || assessment.authority_until_unix_seconds
                        <= assessment.compiled_at_unix_seconds
                    || assessment.vantages.is_empty()
            }
            EgressReachabilityVerdict::DenyClosed => {
                assessment.reason == EgressReachabilityReason::Verified
                    || assessment.authority_until_unix_seconds
                        != assessment.compiled_at_unix_seconds
                    || !assessment.vantages.is_empty()
            }
        }
        || assessment
            .vantages
            .windows(2)
            .any(|pair| pair[0].vantage >= pair[1].vantage)
        || assessment.vantages.iter().any(|proof| {
            proof.failure_domains.is_empty()
                || proof.observation_digests.is_empty()
                || has_duplicates(&proof.failure_domains)
                || has_duplicates(&proof.observation_digests)
        })
    {
        return Err(EgressReachabilityError::InvalidAssessment);
    }
    assessment.digest = assessment_digest(&assessment)?;
    Ok(assessment)
}

fn plan_digest(
    plan: &EgressReachabilityPlan,
) -> Result<EgressReachabilityPlanDigest, EgressReachabilityError> {
    let material = (
        plan.schema_version,
        &plan.algorithm,
        plan.revision,
        plan.desired_revision,
        plan.allocation_revision,
        &plan.owner,
        &plan.provider,
        plan.lease_epoch,
        plan.action,
        &plan.addresses,
        &plan.expected_paths,
        plan.minimum_paths_per_address,
        plan.maximum_paths_per_address,
        &plan.vantages,
        plan.max_observation_age_seconds,
    );
    Ok(EgressReachabilityPlanDigest(digest(
        PLAN_DIGEST_DOMAIN,
        &material,
    )?))
}

fn observation_digest(
    observation: &EgressReachabilityObservation,
) -> Result<EgressReachabilityObservationDigest, EgressReachabilityError> {
    let material = (
        observation.schema_version,
        &observation.algorithm,
        observation.plan_digest,
        &observation.observer,
        observation.source_epoch,
        observation.revision,
        observation.observed_at_unix_seconds,
        observation.valid_until_unix_seconds,
        &observation.routes,
    );
    Ok(EgressReachabilityObservationDigest(digest(
        OBSERVATION_DIGEST_DOMAIN,
        &material,
    )?))
}

fn assessment_digest(
    assessment: &EgressReachabilityAssessment,
) -> Result<EgressReachabilityAssessmentDigest, EgressReachabilityError> {
    let material = (
        assessment.schema_version,
        &assessment.algorithm,
        assessment.plan_digest,
        assessment.compiled_at_unix_seconds,
        assessment.authority_until_unix_seconds,
        assessment.verdict,
        assessment.reason,
        &assessment.vantages,
    );
    Ok(EgressReachabilityAssessmentDigest(digest(
        ASSESSMENT_DIGEST_DOMAIN,
        &material,
    )?))
}

fn digest<T: Serialize>(domain: &[u8], value: &T) -> Result<[u8; 32], EgressReachabilityError> {
    let encoded = serde_json::to_vec(value)
        .map_err(|error| EgressReachabilityError::Encoding(error.to_string()))?;
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update(encoded);
    Ok(digest.finalize().into())
}

fn valid_owner(owner: &EgressIntentOwner) -> bool {
    valid_id(&owner.name) && valid_id(&owner.uid)
}

fn valid_provider(provider: &EgressProviderRef) -> bool {
    valid_id(&provider.name) && valid_id(&provider.instance)
}

fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_EGRESS_REACHABILITY_ID_BYTES
        && !value.chars().any(char::is_control)
}

fn invalid_address(address: &IpAddr) -> bool {
    address.is_unspecified() || address.is_multicast()
}

fn has_duplicates<T: PartialEq>(values: &[T]) -> bool {
    values.windows(2).any(|pair| pair[0] == pair[1])
}

fn has_duplicates_by<T, K: PartialEq>(values: &[T], key: impl Fn(&T) -> K) -> bool {
    values.windows(2).any(|pair| key(&pair[0]) == key(&pair[1]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::EgressIntentScope;

    const NOW: u64 = 20_000;

    fn owner() -> EgressIntentOwner {
        EgressIntentOwner {
            scope: EgressIntentScope::Cluster,
            name: "payments".to_owned(),
            uid: "payments-uid".to_owned(),
        }
    }

    fn path(gateway: &str, identity: &str) -> EgressReachabilityPath {
        EgressReachabilityPath {
            gateway_uid: gateway.to_owned(),
            forwarding_identity: identity.to_owned(),
        }
    }

    fn plan(action: EgressGatewayAction) -> EgressReachabilityPlan {
        seal_egress_reachability_plan(EgressReachabilityPlan {
            schema_version: EGRESS_REACHABILITY_SCHEMA_VERSION,
            algorithm: EGRESS_REACHABILITY_ALGORITHM_DIVERSITY_QUORUM_V1.to_owned(),
            revision: Revision::new(9),
            desired_revision: Revision::new(8),
            allocation_revision: Revision::new(7),
            owner: owner(),
            provider: EgressProviderRef {
                name: "bgp".to_owned(),
                instance: "edge-fabric".to_owned(),
            },
            lease_epoch: 4,
            action,
            addresses: vec![
                "2001:db8::10".parse().unwrap(),
                "192.0.2.10".parse().unwrap(),
            ],
            expected_paths: vec![
                path("gateway-b", "edge-b/2001:db8:ffff::2"),
                path("gateway-a", "edge-a/192.0.2.1"),
            ],
            minimum_paths_per_address: 2,
            maximum_paths_per_address: 2,
            vantages: vec![
                EgressReachabilityVantage {
                    name: "internet-west".to_owned(),
                    minimum_failure_domains: 2,
                },
                EgressReachabilityVantage {
                    name: "internet-east".to_owned(),
                    minimum_failure_domains: 2,
                },
            ],
            max_observation_age_seconds: 60,
            digest: EgressReachabilityPlanDigest([0; 32]),
        })
        .unwrap()
    }

    fn observation(
        plan: &EgressReachabilityPlan,
        vantage: &str,
        observer: &str,
        failure_domain: &str,
        paths: &[EgressReachabilityPath],
        valid_until: u64,
    ) -> EgressReachabilityObservation {
        seal_egress_reachability_observation(
            plan,
            EgressReachabilityObservation {
                schema_version: EGRESS_REACHABILITY_SCHEMA_VERSION,
                algorithm: EGRESS_REACHABILITY_ALGORITHM_DIVERSITY_QUORUM_V1.to_owned(),
                plan_digest: plan.digest,
                observer: EgressReachabilityObserver {
                    name: observer.to_owned(),
                    failure_domain: failure_domain.to_owned(),
                    vantage: vantage.to_owned(),
                },
                source_epoch: 3,
                revision: Revision::new(11),
                observed_at_unix_seconds: NOW,
                valid_until_unix_seconds: valid_until,
                routes: plan
                    .addresses
                    .iter()
                    .map(|address| EgressReachabilityRouteObservation {
                        address: *address,
                        paths: paths.to_vec(),
                    })
                    .collect(),
                digest: EgressReachabilityObservationDigest([0; 32]),
            },
        )
        .unwrap()
    }

    fn quorum(
        plan: &EgressReachabilityPlan,
        paths: &[EgressReachabilityPath],
    ) -> Vec<EgressReachabilityObservation> {
        ["internet-east", "internet-west"]
            .into_iter()
            .flat_map(|vantage| {
                [
                    observation(plan, vantage, "observer-a", "cloud-a", paths, NOW + 55),
                    observation(plan, vantage, "observer-b", "cloud-b", paths, NOW + 45),
                ]
            })
            .collect()
    }

    #[test]
    fn dual_stack_ecmp_requires_diverse_agreement_in_every_vantage() {
        let plan = plan(EgressGatewayAction::Ensure);
        let observations = quorum(&plan, &plan.expected_paths);
        let assessment =
            assess_egress_reachability(plan.clone(), observations.clone(), NOW + 5).unwrap();
        assert_eq!(assessment.verdict, EgressReachabilityVerdict::Ready);
        assert_eq!(assessment.reason, EgressReachabilityReason::Verified);
        assert_eq!(assessment.authority_until_unix_seconds, NOW + 45);
        assert_eq!(assessment.vantages.len(), 2);
        assert!(
            assessment
                .vantages
                .iter()
                .all(|proof| proof.failure_domains == ["cloud-a", "cloud-b"])
        );
        verify_egress_reachability_assessment(plan, observations, &assessment).unwrap();
    }

    #[test]
    fn declared_vantages_may_have_different_exact_path_sets() {
        let mut plan = plan(EgressGatewayAction::Ensure);
        plan.minimum_paths_per_address = 1;
        plan = seal_egress_reachability_plan(plan).unwrap();
        let mut observations = Vec::new();
        for (vantage, paths) in [
            ("internet-east", plan.expected_paths.as_slice()),
            ("internet-west", &plan.expected_paths[..1]),
        ] {
            observations.push(observation(
                &plan,
                vantage,
                "observer-a",
                "cloud-a",
                paths,
                NOW + 45,
            ));
            observations.push(observation(
                &plan,
                vantage,
                "observer-b",
                "cloud-b",
                paths,
                NOW + 45,
            ));
        }
        let assessment = assess_egress_reachability(plan, observations, NOW + 1).unwrap();
        assert_eq!(assessment.verdict, EgressReachabilityVerdict::Ready);
    }

    #[test]
    fn replicas_in_one_failure_domain_never_manufacture_quorum() {
        let plan = plan(EgressGatewayAction::Ensure);
        let observations = ["internet-east", "internet-west"]
            .into_iter()
            .flat_map(|vantage| {
                [
                    observation(
                        &plan,
                        vantage,
                        "observer-a",
                        "same-rack",
                        &plan.expected_paths,
                        NOW + 40,
                    ),
                    observation(
                        &plan,
                        vantage,
                        "observer-b",
                        "same-rack",
                        &plan.expected_paths,
                        NOW + 40,
                    ),
                ]
            })
            .collect();
        let assessment = assess_egress_reachability(plan, observations, NOW + 1).unwrap();
        assert_eq!(assessment.verdict, EgressReachabilityVerdict::DenyClosed);
        assert_eq!(
            assessment.reason,
            EgressReachabilityReason::MissingDiversityQuorum
        );
    }

    #[test]
    fn one_observer_cannot_publish_twice_into_the_same_assessment() {
        let plan = plan(EgressGatewayAction::Ensure);
        let duplicate = observation(
            &plan,
            "internet-east",
            "observer-a",
            "cloud-a",
            &plan.expected_paths,
            NOW + 45,
        );
        assert_eq!(
            assess_egress_reachability(plan, vec![duplicate.clone(), duplicate], NOW + 1)
                .unwrap_err(),
            EgressReachabilityError::DuplicateObserver
        );
    }

    #[test]
    fn disagreement_and_partial_ecmp_fail_closed() {
        let plan = plan(EgressGatewayAction::Ensure);
        let mut observations = quorum(&plan, &plan.expected_paths);
        observations[0] = observation(
            &plan,
            "internet-east",
            "observer-a",
            "cloud-a",
            &plan.expected_paths[..1],
            NOW + 45,
        );
        let assessment = assess_egress_reachability(plan, observations, NOW + 1).unwrap();
        assert_eq!(assessment.verdict, EgressReachabilityVerdict::DenyClosed);
        assert_eq!(
            assessment.reason,
            EgressReachabilityReason::ConflictingEvidence
        );
    }

    #[test]
    fn finite_evidence_expires_at_the_consumer_without_a_controller_event() {
        let plan = plan(EgressGatewayAction::Ensure);
        let observations = quorum(&plan, &plan.expected_paths);
        let assessment =
            assess_egress_reachability(plan.clone(), observations.clone(), NOW + 5).unwrap();
        assert_eq!(assessment.verdict, EgressReachabilityVerdict::Ready);
        assert_eq!(
            egress_reachability_verdict_at(&plan, &assessment, NOW + 44).unwrap(),
            EgressReachabilityVerdict::Ready
        );
        assert_eq!(
            egress_reachability_verdict_at(&plan, &assessment, NOW + 45).unwrap(),
            EgressReachabilityVerdict::DenyClosed
        );
        let refreshed = assess_egress_reachability(plan, observations, NOW + 56).unwrap();
        assert_eq!(refreshed.verdict, EgressReachabilityVerdict::DenyClosed);
        assert_eq!(refreshed.reason, EgressReachabilityReason::ExpiredEvidence);
    }

    #[test]
    fn withdrawal_requires_complete_diverse_empty_observation() {
        let plan = plan(EgressGatewayAction::Withdraw);
        let observations = quorum(&plan, &[]);
        let assessment =
            assess_egress_reachability(plan.clone(), observations.clone(), NOW + 1).unwrap();
        assert_eq!(assessment.verdict, EgressReachabilityVerdict::Withdrawn);
        verify_egress_reachability_assessment(plan, observations, &assessment).unwrap();
    }

    #[test]
    fn foreign_paths_and_digest_mutation_are_rejected() {
        let plan = plan(EgressGatewayAction::Ensure);
        let mut foreign = observation(
            &plan,
            "internet-east",
            "observer-a",
            "cloud-a",
            &plan.expected_paths,
            NOW + 45,
        );
        foreign.routes[0].paths[0].gateway_uid = "foreign-gateway".to_owned();
        assert_eq!(
            seal_egress_reachability_observation(&plan, foreign).unwrap_err(),
            EgressReachabilityError::InvalidObservation
        );

        let mut mutated = observation(
            &plan,
            "internet-east",
            "observer-a",
            "cloud-a",
            &plan.expected_paths,
            NOW + 45,
        );
        mutated.valid_until_unix_seconds -= 1;
        assert_eq!(
            verify_egress_reachability_observation(&plan, mutated).unwrap_err(),
            EgressReachabilityError::ObservationDigestMismatch
        );

        let observations = quorum(&plan, &plan.expected_paths);
        let mut assessment =
            assess_egress_reachability(plan.clone(), observations.clone(), NOW + 1)
                .unwrap()
                .assessment()
                .clone();
        assessment.authority_until_unix_seconds -= 1;
        assert_eq!(
            verify_egress_reachability_assessment(plan, observations, &assessment).unwrap_err(),
            EgressReachabilityError::AssessmentDigestMismatch
        );
    }
}
