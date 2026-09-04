//! Provider-neutral, fail-closed internet destination classification.
//!
//! A classifier supplies revisioned prefix rules. The most-specific rule wins,
//! policy exceptions can only subtract authority, and unclassified address
//! space is denied. A bounded last-known-good fallback is explicit and retains
//! the exact classification digest that granted it.

use std::collections::BTreeMap;
use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use unf_common::Revision;

use crate::{AddressFamily, EgressIntentOwner, EgressProviderRef, IpPrefix};

pub const EGRESS_INTERNET_CLASSIFICATION_SCHEMA_VERSION: u16 = 1;
pub const EGRESS_INTERNET_CLASSIFICATION_ALGORITHM_AUTHORITY_CARVING_V1: u16 = 1;
pub const MAX_EGRESS_INTERNET_RULES: usize = 1_024;
pub const MAX_EGRESS_INTERNET_EXCEPTIONS: usize = 256;
pub const MAX_EGRESS_INTERNET_RULE_PROVENANCE_BYTES: usize = 512;
pub const MAX_EGRESS_INTERNET_VALIDITY_SECONDS: u64 = 86_400;
pub const MAX_EGRESS_INTERNET_STALENESS_SECONDS: u64 = 3_600;
pub const MAX_EGRESS_INTERNET_FUTURE_SKEW_SECONDS: u64 = 30;

const CLASSIFICATION_DIGEST_DOMAIN: &[u8] =
    b"unf.egress.internet.classification.authority-carving.v1\0";
const SNAPSHOT_DIGEST_DOMAIN: &[u8] = b"unf.egress.internet.snapshot.authority-carving.v1\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum EgressInternetClass {
    Internet,
    NonInternet,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EgressInternetClassificationRule {
    pub prefix: IpPrefix,
    pub class: EgressInternetClass,
    /// Provider-defined, human-auditable origin such as an RPKI/IANA dataset
    /// revision. It is committed by the classification digest.
    pub provenance: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EgressInternetClassificationDigest(pub [u8; 32]);

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EgressInternetClassification {
    pub schema_version: u16,
    pub algorithm: u16,
    pub revision: Revision,
    pub source: EgressProviderRef,
    pub source_epoch: u64,
    pub observed_at_unix_seconds: u64,
    pub valid_until_unix_seconds: u64,
    pub rules: Vec<EgressInternetClassificationRule>,
    pub digest: EgressInternetClassificationDigest,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "mode")]
pub enum EgressInternetFallback {
    #[default]
    Deny,
    LastKnownGood {
        max_staleness_seconds: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EgressInternetDestinationSpec {
    pub classifier: EgressProviderRef,
    pub exceptions: Vec<IpPrefix>,
    pub fallback: EgressInternetFallback,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EgressInternetPolicy {
    pub revision: Revision,
    pub owner: EgressIntentOwner,
    pub classifier: EgressProviderRef,
    pub exceptions: Vec<IpPrefix>,
    pub fallback: EgressInternetFallback,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "state")]
pub enum EgressInternetAuthority {
    Current,
    LastKnownGood {
        previous_snapshot_digest: EgressInternetSnapshotDigest,
    },
    DenyClosed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EgressInternetSnapshotDigest(pub [u8; 32]);

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EgressInternetSnapshot {
    pub schema_version: u16,
    pub algorithm: u16,
    pub compiled_at_unix_seconds: u64,
    pub authority_until_unix_seconds: u64,
    pub policy: EgressInternetPolicy,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub classification: Option<EgressInternetClassification>,
    pub authority: EgressInternetAuthority,
    pub digest: EgressInternetSnapshotDigest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EgressInternetDecision {
    Internet,
    PolicyException,
    NonInternet,
    Unclassified,
    AuthorityExpired,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum EgressInternetError {
    #[error("unsupported internet classification schema or algorithm")]
    UnsupportedVersion,
    #[error("invalid internet destination policy: {0}")]
    InvalidPolicy(&'static str),
    #[error("invalid internet classification: {0}")]
    InvalidClassification(&'static str),
    #[error("internet classification digest mismatch")]
    ClassificationDigestMismatch,
    #[error("internet classification source does not match the policy")]
    ForeignClassifier,
    #[error("internet classification position regressed")]
    ClassificationRegression,
    #[error("internet classification changed at the same source position")]
    ClassificationMutation,
    #[error("internet snapshot is noncanonical")]
    NoncanonicalSnapshot,
    #[error("internet snapshot digest mismatch")]
    SnapshotDigestMismatch,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedEgressInternetSnapshot(EgressInternetSnapshot);

impl VerifiedEgressInternetSnapshot {
    #[must_use]
    pub const fn snapshot(&self) -> &EgressInternetSnapshot {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EgressInternetCompilationReport {
    pub owner: EgressIntentOwner,
    pub classifier: EgressProviderRef,
    pub classification_revision: Option<Revision>,
    pub authority: EgressInternetAuthority,
    pub internet_rules: usize,
    pub non_internet_rules: usize,
    pub policy_exceptions: usize,
    pub authority_until_unix_seconds: u64,
    pub snapshot_digest: EgressInternetSnapshotDigest,
}

/// Replaces unresolved internet destinations in a normalized model. Provider
/// input and previous snapshots are explicit arguments, so classification loss
/// and fallback can be reproduced without consulting ambient routing state.
///
/// # Errors
///
/// Rejects invalid current or retained evidence, policy mismatch, replay
/// regression/mutation, or a noncanonical materialized model.
pub fn materialize_egress_internet_model(
    mut model: crate::EgressModel,
    classifications: &BTreeMap<EgressProviderRef, EgressInternetClassification>,
    previous: &BTreeMap<EgressIntentOwner, EgressInternetSnapshot>,
    policy_revision: Revision,
    now_unix_seconds: u64,
) -> Result<
    (
        crate::EgressModel,
        BTreeMap<EgressIntentOwner, EgressInternetCompilationReport>,
    ),
    EgressInternetError,
> {
    let mut reports = BTreeMap::new();
    for intent in &mut model.intents {
        let Some(spec) = intent.internet.clone() else {
            continue;
        };
        let previous = previous
            .get(&intent.owner)
            .cloned()
            .map(verify_egress_internet_snapshot)
            .transpose()?;
        let verified = materialize_egress_internet_snapshot(
            policy_revision,
            intent.owner.clone(),
            spec.clone(),
            classifications.get(&spec.classifier).cloned(),
            previous.as_ref(),
            now_unix_seconds,
        )?;
        let snapshot = verified.snapshot();
        let (internet_rules, non_internet_rules) =
            snapshot
                .classification
                .as_ref()
                .map_or((0, 0), |classification| {
                    classification
                        .rules
                        .iter()
                        .fold((0, 0), |counts, rule| match rule.class {
                            EgressInternetClass::Internet => (counts.0 + 1, counts.1),
                            EgressInternetClass::NonInternet => (counts.0, counts.1 + 1),
                        })
                });
        reports.insert(
            intent.owner.clone(),
            EgressInternetCompilationReport {
                owner: intent.owner.clone(),
                classifier: spec.classifier,
                classification_revision: snapshot
                    .classification
                    .as_ref()
                    .map(|classification| classification.revision),
                authority: snapshot.authority,
                internet_rules,
                non_internet_rules,
                policy_exceptions: snapshot.policy.exceptions.len(),
                authority_until_unix_seconds: snapshot.authority_until_unix_seconds,
                snapshot_digest: snapshot.digest,
            },
        );
        intent.destinations = crate::EgressDestinations::Internet(Box::new(snapshot.clone()));
    }
    let model = crate::normalize_model(model.pools, model.intents)
        .map_err(|_| EgressInternetError::InvalidPolicy("materialized model is invalid"))?;
    Ok((model, reports))
}

/// Canonicalizes one policy without broadening it.
///
/// # Errors
///
/// Rejects invalid classifier identity, prefixes, capacity, or fallback bounds.
pub fn normalize_egress_internet_destination_spec(
    mut spec: EgressInternetDestinationSpec,
) -> Result<EgressInternetDestinationSpec, EgressInternetError> {
    if !valid_provider(&spec.classifier) {
        return Err(EgressInternetError::InvalidPolicy(
            "classifier identity is invalid",
        ));
    }
    canonicalize_prefixes(&mut spec.exceptions, MAX_EGRESS_INTERNET_EXCEPTIONS)
        .map_err(EgressInternetError::InvalidPolicy)?;
    if let EgressInternetFallback::LastKnownGood {
        max_staleness_seconds,
    } = spec.fallback
        && (max_staleness_seconds == 0
            || max_staleness_seconds > MAX_EGRESS_INTERNET_STALENESS_SECONDS)
    {
        return Err(EgressInternetError::InvalidPolicy(
            "last-known-good staleness is zero or unbounded",
        ));
    }
    Ok(spec)
}

/// Seals a canonical classifier result. Classification is restriction evidence,
/// not permission from the egress policy or security-policy layer.
///
/// # Errors
///
/// Rejects unsupported versions, invalid identity/time/rule bounds, duplicate
/// prefixes, or evidence that cannot be canonically encoded.
pub fn seal_egress_internet_classification(
    mut classification: EgressInternetClassification,
) -> Result<EgressInternetClassification, EgressInternetError> {
    if classification.schema_version != EGRESS_INTERNET_CLASSIFICATION_SCHEMA_VERSION
        || classification.algorithm != EGRESS_INTERNET_CLASSIFICATION_ALGORITHM_AUTHORITY_CARVING_V1
    {
        return Err(EgressInternetError::UnsupportedVersion);
    }
    if classification.revision == Revision::INITIAL || classification.source_epoch == 0 {
        return Err(EgressInternetError::InvalidClassification(
            "revision and source epoch must be nonzero",
        ));
    }
    if !valid_provider(&classification.source) {
        return Err(EgressInternetError::InvalidClassification(
            "classifier identity is invalid",
        ));
    }
    if classification.rules.is_empty() || classification.rules.len() > MAX_EGRESS_INTERNET_RULES {
        return Err(EgressInternetError::InvalidClassification(
            "rule set is empty or unbounded",
        ));
    }
    let validity = classification
        .valid_until_unix_seconds
        .checked_sub(classification.observed_at_unix_seconds)
        .filter(|validity| *validity > 0 && *validity <= MAX_EGRESS_INTERNET_VALIDITY_SECONDS)
        .ok_or(EgressInternetError::InvalidClassification(
            "validity interval is invalid or unbounded",
        ))?;
    let _ = validity;
    for rule in &classification.rules {
        if !rule.prefix.is_canonical()
            || rule.provenance.is_empty()
            || rule.provenance.len() > MAX_EGRESS_INTERNET_RULE_PROVENANCE_BYTES
        {
            return Err(EgressInternetError::InvalidClassification(
                "rule prefix or provenance is invalid",
            ));
        }
    }
    classification.rules.sort_unstable();
    if classification
        .rules
        .windows(2)
        .any(|pair| pair[0].prefix == pair[1].prefix)
    {
        return Err(EgressInternetError::InvalidClassification(
            "each prefix must have exactly one classification",
        ));
    }
    classification.digest = classification_digest(&classification)?;
    Ok(classification)
}

/// Verifies a sealed provider result by independent canonical replay.
///
/// # Errors
///
/// Rejects every error from sealing plus any digest mismatch.
pub fn verify_egress_internet_classification(
    classification: EgressInternetClassification,
) -> Result<EgressInternetClassification, EgressInternetError> {
    let expected = classification.digest;
    let replayed = seal_egress_internet_classification(classification)?;
    if replayed.digest != expected {
        return Err(EgressInternetError::ClassificationDigestMismatch);
    }
    Ok(replayed)
}

/// Materializes current, explicitly bounded last-known-good, or deny-closed
/// internet authority. An absent classifier can never become allow-all.
///
/// # Errors
///
/// Rejects invalid policy/evidence, a foreign classifier, replay regression or
/// same-position mutation, and noncanonical snapshot construction.
pub fn materialize_egress_internet_snapshot(
    policy_revision: Revision,
    owner: EgressIntentOwner,
    spec: EgressInternetDestinationSpec,
    current: Option<EgressInternetClassification>,
    previous: Option<&VerifiedEgressInternetSnapshot>,
    now_unix_seconds: u64,
) -> Result<VerifiedEgressInternetSnapshot, EgressInternetError> {
    if policy_revision == Revision::INITIAL {
        return Err(EgressInternetError::InvalidPolicy(
            "revision zero is reserved",
        ));
    }
    let spec = normalize_egress_internet_destination_spec(spec)?;
    let policy = EgressInternetPolicy {
        revision: policy_revision,
        owner,
        classifier: spec.classifier,
        exceptions: spec.exceptions,
        fallback: spec.fallback,
    };
    let current = current
        .map(verify_egress_internet_classification)
        .transpose()?;
    if current
        .as_ref()
        .is_some_and(|classification| classification.source != policy.classifier)
    {
        return Err(EgressInternetError::ForeignClassifier);
    }
    if let (Some(current), Some(previous)) = (current.as_ref(), previous)
        && let Some(prior) = previous.snapshot().classification.as_ref()
        && prior.source == current.source
    {
        let current_position = (current.source_epoch, current.revision);
        let prior_position = (prior.source_epoch, prior.revision);
        if current_position < prior_position {
            return Err(EgressInternetError::ClassificationRegression);
        }
        if current_position == prior_position && current.digest != prior.digest {
            return Err(EgressInternetError::ClassificationMutation);
        }
    }
    if let Some(classification) = current.filter(|classification| {
        classification.observed_at_unix_seconds
            <= now_unix_seconds.saturating_add(MAX_EGRESS_INTERNET_FUTURE_SKEW_SECONDS)
            && now_unix_seconds < classification.valid_until_unix_seconds
    }) {
        return seal_snapshot(EgressInternetSnapshot {
            schema_version: EGRESS_INTERNET_CLASSIFICATION_SCHEMA_VERSION,
            algorithm: EGRESS_INTERNET_CLASSIFICATION_ALGORITHM_AUTHORITY_CARVING_V1,
            compiled_at_unix_seconds: now_unix_seconds,
            authority_until_unix_seconds: classification.valid_until_unix_seconds,
            policy,
            classification: Some(classification),
            authority: EgressInternetAuthority::Current,
            digest: EgressInternetSnapshotDigest([0; 32]),
        });
    }
    if let (
        EgressInternetFallback::LastKnownGood {
            max_staleness_seconds,
        },
        Some(previous),
    ) = (policy.fallback, previous)
    {
        let prior = previous.snapshot();
        if prior.policy.owner == policy.owner
            && prior.policy.classifier == policy.classifier
            && prior.policy.exceptions == policy.exceptions
            && let Some(classification) = prior.classification.clone()
        {
            let authority_until = classification
                .valid_until_unix_seconds
                .saturating_add(max_staleness_seconds);
            if now_unix_seconds < authority_until {
                return seal_snapshot(EgressInternetSnapshot {
                    schema_version: EGRESS_INTERNET_CLASSIFICATION_SCHEMA_VERSION,
                    algorithm: EGRESS_INTERNET_CLASSIFICATION_ALGORITHM_AUTHORITY_CARVING_V1,
                    compiled_at_unix_seconds: now_unix_seconds,
                    authority_until_unix_seconds: authority_until,
                    policy,
                    classification: Some(classification),
                    authority: EgressInternetAuthority::LastKnownGood {
                        previous_snapshot_digest: prior.digest,
                    },
                    digest: EgressInternetSnapshotDigest([0; 32]),
                });
            }
        }
    }
    seal_snapshot(EgressInternetSnapshot {
        schema_version: EGRESS_INTERNET_CLASSIFICATION_SCHEMA_VERSION,
        algorithm: EGRESS_INTERNET_CLASSIFICATION_ALGORITHM_AUTHORITY_CARVING_V1,
        compiled_at_unix_seconds: now_unix_seconds,
        authority_until_unix_seconds: now_unix_seconds,
        policy,
        classification: None,
        authority: EgressInternetAuthority::DenyClosed,
        digest: EgressInternetSnapshotDigest([0; 32]),
    })
}

/// Independently verifies policy, evidence, fallback bounds, and digest.
///
/// # Errors
///
/// Rejects unsupported/noncanonical snapshots, invalid embedded evidence, and
/// digest mismatch.
pub fn verify_egress_internet_snapshot(
    snapshot: EgressInternetSnapshot,
) -> Result<VerifiedEgressInternetSnapshot, EgressInternetError> {
    let expected = snapshot.digest;
    let spec = normalize_egress_internet_destination_spec(EgressInternetDestinationSpec {
        classifier: snapshot.policy.classifier.clone(),
        exceptions: snapshot.policy.exceptions.clone(),
        fallback: snapshot.policy.fallback,
    })?;
    if snapshot.schema_version != EGRESS_INTERNET_CLASSIFICATION_SCHEMA_VERSION
        || snapshot.algorithm != EGRESS_INTERNET_CLASSIFICATION_ALGORITHM_AUTHORITY_CARVING_V1
        || snapshot.policy.revision == Revision::INITIAL
        || spec.classifier != snapshot.policy.classifier
        || spec.exceptions != snapshot.policy.exceptions
        || spec.fallback != snapshot.policy.fallback
    {
        return Err(EgressInternetError::NoncanonicalSnapshot);
    }
    match (&snapshot.authority, &snapshot.classification) {
        (EgressInternetAuthority::Current, Some(classification)) => {
            let classification = verify_egress_internet_classification(classification.clone())?;
            if classification.source != snapshot.policy.classifier
                || snapshot.authority_until_unix_seconds != classification.valid_until_unix_seconds
                || classification.observed_at_unix_seconds
                    > snapshot
                        .compiled_at_unix_seconds
                        .saturating_add(MAX_EGRESS_INTERNET_FUTURE_SKEW_SECONDS)
                || snapshot.compiled_at_unix_seconds >= snapshot.authority_until_unix_seconds
            {
                return Err(EgressInternetError::NoncanonicalSnapshot);
            }
        }
        (EgressInternetAuthority::LastKnownGood { .. }, Some(classification)) => {
            let classification = verify_egress_internet_classification(classification.clone())?;
            let EgressInternetFallback::LastKnownGood {
                max_staleness_seconds,
            } = snapshot.policy.fallback
            else {
                return Err(EgressInternetError::NoncanonicalSnapshot);
            };
            if classification.source != snapshot.policy.classifier
                || snapshot.authority_until_unix_seconds
                    != classification
                        .valid_until_unix_seconds
                        .saturating_add(max_staleness_seconds)
                || snapshot.compiled_at_unix_seconds < classification.valid_until_unix_seconds
                || snapshot.compiled_at_unix_seconds >= snapshot.authority_until_unix_seconds
            {
                return Err(EgressInternetError::NoncanonicalSnapshot);
            }
        }
        (EgressInternetAuthority::DenyClosed, None)
            if snapshot.authority_until_unix_seconds == snapshot.compiled_at_unix_seconds => {}
        _ => return Err(EgressInternetError::NoncanonicalSnapshot),
    }
    if snapshot_digest(&snapshot)? != expected {
        return Err(EgressInternetError::SnapshotDigestMismatch);
    }
    Ok(VerifiedEgressInternetSnapshot(snapshot))
}

/// Replays the last-known-good link against the exact preceding snapshot.
/// Standalone verification checks the embedded classification; this check also
/// proves that the fallback actually descended from retained authority.
///
/// # Errors
///
/// Rejects invalid snapshots and fallback links that do not match the exact
/// preceding snapshot.
pub fn verify_egress_internet_fallback_chain(
    snapshot: EgressInternetSnapshot,
    previous: &VerifiedEgressInternetSnapshot,
) -> Result<VerifiedEgressInternetSnapshot, EgressInternetError> {
    let verified = verify_egress_internet_snapshot(snapshot)?;
    if let EgressInternetAuthority::LastKnownGood {
        previous_snapshot_digest,
    } = verified.snapshot().authority
        && (previous_snapshot_digest != previous.snapshot().digest
            || verified.snapshot().classification != previous.snapshot().classification
            || verified.snapshot().policy.owner != previous.snapshot().policy.owner
            || verified.snapshot().policy.classifier != previous.snapshot().policy.classifier
            || verified.snapshot().policy.exceptions != previous.snapshot().policy.exceptions
            || verified.snapshot().compiled_at_unix_seconds
                < previous.snapshot().compiled_at_unix_seconds)
    {
        return Err(EgressInternetError::NoncanonicalSnapshot);
    }
    Ok(verified)
}

/// Evaluates one address using most-specific provider authority followed by
/// policy subtraction. Unknown or expired space is never internet.
#[must_use]
pub fn classify_egress_internet_destination(
    snapshot: &VerifiedEgressInternetSnapshot,
    address: IpAddr,
    now_unix_seconds: u64,
) -> EgressInternetDecision {
    let snapshot = snapshot.snapshot();
    if !matches!(snapshot.authority, EgressInternetAuthority::DenyClosed)
        && now_unix_seconds >= snapshot.authority_until_unix_seconds
    {
        return EgressInternetDecision::AuthorityExpired;
    }
    if snapshot
        .policy
        .exceptions
        .iter()
        .any(|prefix| prefix.contains(address))
    {
        return EgressInternetDecision::PolicyException;
    }
    let Some(classification) = &snapshot.classification else {
        return EgressInternetDecision::Unclassified;
    };
    classification
        .rules
        .iter()
        .filter(|rule| rule.prefix.contains(address))
        .max_by_key(|rule| rule.prefix.prefix_len)
        .map_or(EgressInternetDecision::Unclassified, |rule| {
            match rule.class {
                EgressInternetClass::Internet => EgressInternetDecision::Internet,
                EgressInternetClass::NonInternet => EgressInternetDecision::NonInternet,
            }
        })
}

fn seal_snapshot(
    mut snapshot: EgressInternetSnapshot,
) -> Result<VerifiedEgressInternetSnapshot, EgressInternetError> {
    snapshot.digest = snapshot_digest(&snapshot)?;
    verify_egress_internet_snapshot(snapshot)
}

fn canonicalize_prefixes(prefixes: &mut [IpPrefix], limit: usize) -> Result<(), &'static str> {
    if prefixes.len() > limit || prefixes.iter().any(|prefix| !prefix.is_canonical()) {
        return Err("prefix set is invalid or exceeds its bound");
    }
    prefixes.sort_unstable();
    if prefixes.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err("duplicate prefixes are forbidden");
    }
    Ok(())
}

fn valid_provider(provider: &EgressProviderRef) -> bool {
    !provider.name.is_empty()
        && provider.name.len() <= 253
        && !provider.instance.is_empty()
        && provider.instance.len() <= 128
}

fn classification_digest(
    classification: &EgressInternetClassification,
) -> Result<EgressInternetClassificationDigest, EgressInternetError> {
    #[derive(Serialize)]
    struct DigestInput<'a> {
        schema_version: u16,
        algorithm: u16,
        revision: Revision,
        source: &'a EgressProviderRef,
        source_epoch: u64,
        observed_at_unix_seconds: u64,
        valid_until_unix_seconds: u64,
        rules: &'a [EgressInternetClassificationRule],
    }
    let bytes = serde_json::to_vec(&DigestInput {
        schema_version: classification.schema_version,
        algorithm: classification.algorithm,
        revision: classification.revision,
        source: &classification.source,
        source_epoch: classification.source_epoch,
        observed_at_unix_seconds: classification.observed_at_unix_seconds,
        valid_until_unix_seconds: classification.valid_until_unix_seconds,
        rules: &classification.rules,
    })
    .map_err(|_| EgressInternetError::InvalidClassification("classification cannot serialize"))?;
    let mut digest = Sha256::new();
    digest.update(CLASSIFICATION_DIGEST_DOMAIN);
    digest.update(bytes);
    Ok(EgressInternetClassificationDigest(digest.finalize().into()))
}

fn snapshot_digest(
    snapshot: &EgressInternetSnapshot,
) -> Result<EgressInternetSnapshotDigest, EgressInternetError> {
    #[derive(Serialize)]
    struct DigestInput<'a> {
        schema_version: u16,
        algorithm: u16,
        compiled_at_unix_seconds: u64,
        authority_until_unix_seconds: u64,
        policy: &'a EgressInternetPolicy,
        classification: &'a Option<EgressInternetClassification>,
        authority: EgressInternetAuthority,
    }
    let bytes = serde_json::to_vec(&DigestInput {
        schema_version: snapshot.schema_version,
        algorithm: snapshot.algorithm,
        compiled_at_unix_seconds: snapshot.compiled_at_unix_seconds,
        authority_until_unix_seconds: snapshot.authority_until_unix_seconds,
        policy: &snapshot.policy,
        classification: &snapshot.classification,
        authority: snapshot.authority,
    })
    .map_err(|_| EgressInternetError::NoncanonicalSnapshot)?;
    let mut digest = Sha256::new();
    digest.update(SNAPSHOT_DIGEST_DOMAIN);
    digest.update(bytes);
    Ok(EgressInternetSnapshotDigest(digest.finalize().into()))
}

#[must_use]
pub const fn internet_family(address: IpAddr) -> AddressFamily {
    match address {
        IpAddr::V4(_) => AddressFamily::Ipv4,
        IpAddr::V6(_) => AddressFamily::Ipv6,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use super::*;
    use crate::EgressIntentScope;

    fn prefix(address: IpAddr, prefix_len: u8) -> IpPrefix {
        IpPrefix {
            address,
            prefix_len,
        }
    }

    fn owner() -> EgressIntentOwner {
        EgressIntentOwner {
            scope: EgressIntentScope::Cluster,
            name: "internet".to_owned(),
            uid: "internet-uid".to_owned(),
        }
    }

    fn spec(fallback: EgressInternetFallback) -> EgressInternetDestinationSpec {
        EgressInternetDestinationSpec {
            classifier: EgressProviderRef {
                name: "route-authority".to_owned(),
                instance: "global-v1".to_owned(),
            },
            exceptions: vec![prefix(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 0)), 24)],
            fallback,
        }
    }

    fn classification() -> EgressInternetClassification {
        seal_egress_internet_classification(EgressInternetClassification {
            schema_version: EGRESS_INTERNET_CLASSIFICATION_SCHEMA_VERSION,
            algorithm: EGRESS_INTERNET_CLASSIFICATION_ALGORITHM_AUTHORITY_CARVING_V1,
            revision: Revision::new(7),
            source: spec(EgressInternetFallback::Deny).classifier,
            source_epoch: 4,
            observed_at_unix_seconds: 1_000,
            valid_until_unix_seconds: 1_100,
            rules: vec![
                EgressInternetClassificationRule {
                    prefix: prefix(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
                    class: EgressInternetClass::Internet,
                    provenance: "rpki-snapshot:42".to_owned(),
                },
                EgressInternetClassificationRule {
                    prefix: prefix(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 8),
                    class: EgressInternetClass::NonInternet,
                    provenance: "cluster-private:v3".to_owned(),
                },
                EgressInternetClassificationRule {
                    prefix: prefix(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
                    class: EgressInternetClass::Internet,
                    provenance: "rpki-snapshot:42".to_owned(),
                },
                EgressInternetClassificationRule {
                    prefix: prefix("fd00::".parse().unwrap(), 8),
                    class: EgressInternetClass::NonInternet,
                    provenance: "cluster-private:v3".to_owned(),
                },
            ],
            digest: EgressInternetClassificationDigest([0; 32]),
        })
        .unwrap()
    }

    #[test]
    fn authority_carving_is_dual_stack_specific_and_subtractive() {
        let snapshot = materialize_egress_internet_snapshot(
            Revision::new(3),
            owner(),
            spec(EgressInternetFallback::Deny),
            Some(classification()),
            None,
            1_010,
        )
        .unwrap();
        assert_eq!(
            classify_egress_internet_destination(
                &snapshot,
                IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
                1_020
            ),
            EgressInternetDecision::Internet
        );
        assert_eq!(
            classify_egress_internet_destination(
                &snapshot,
                IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3)),
                1_020
            ),
            EgressInternetDecision::NonInternet
        );
        assert_eq!(
            classify_egress_internet_destination(
                &snapshot,
                IpAddr::V4(Ipv4Addr::new(203, 0, 113, 8)),
                1_020
            ),
            EgressInternetDecision::PolicyException
        );
        assert_eq!(
            classify_egress_internet_destination(
                &snapshot,
                "2606:4700:4700::1111".parse().unwrap(),
                1_020
            ),
            EgressInternetDecision::Internet
        );
        assert_eq!(
            classify_egress_internet_destination(&snapshot, "fd00::1".parse().unwrap(), 1_020),
            EgressInternetDecision::NonInternet
        );
    }

    #[test]
    fn explicit_fallback_is_bounded_digest_linked_and_then_denies() {
        let fallback = EgressInternetFallback::LastKnownGood {
            max_staleness_seconds: 60,
        };
        let current = materialize_egress_internet_snapshot(
            Revision::new(3),
            owner(),
            spec(fallback),
            Some(classification()),
            None,
            1_010,
        )
        .unwrap();
        let retained = materialize_egress_internet_snapshot(
            Revision::new(4),
            owner(),
            spec(fallback),
            None,
            Some(&current),
            1_120,
        )
        .unwrap();
        assert_eq!(retained.snapshot().authority_until_unix_seconds, 1_160);
        assert!(matches!(
            retained.snapshot().authority,
            EgressInternetAuthority::LastKnownGood {
                previous_snapshot_digest
            } if previous_snapshot_digest == current.snapshot().digest
        ));
        verify_egress_internet_fallback_chain(retained.snapshot().clone(), &current).unwrap();
        assert_eq!(
            classify_egress_internet_destination(
                &retained,
                IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4)),
                1_159
            ),
            EgressInternetDecision::Internet
        );
        assert_eq!(
            classify_egress_internet_destination(
                &retained,
                IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4)),
                1_160
            ),
            EgressInternetDecision::AuthorityExpired
        );
        let denied = materialize_egress_internet_snapshot(
            Revision::new(5),
            owner(),
            spec(fallback),
            None,
            Some(&retained),
            1_160,
        )
        .unwrap();
        assert_eq!(
            denied.snapshot().authority,
            EgressInternetAuthority::DenyClosed
        );
        assert!(denied.snapshot().classification.is_none());

        let mut forged = retained.snapshot().clone();
        forged.authority = EgressInternetAuthority::LastKnownGood {
            previous_snapshot_digest: EgressInternetSnapshotDigest([9; 32]),
        };
        let forged = seal_snapshot(forged).unwrap();
        assert_eq!(
            verify_egress_internet_fallback_chain(forged.snapshot().clone(), &current).unwrap_err(),
            EgressInternetError::NoncanonicalSnapshot
        );
    }

    #[test]
    fn replay_rejects_mutation_foreign_sources_and_implicit_fallback() {
        let mut classification = classification();
        classification.rules[0].provenance.push_str("-mutated");
        assert_eq!(
            verify_egress_internet_classification(classification).unwrap_err(),
            EgressInternetError::ClassificationDigestMismatch
        );

        let mut foreign = super::tests::classification();
        foreign.source.instance = "foreign".to_owned();
        foreign = seal_egress_internet_classification(foreign).unwrap();
        assert_eq!(
            materialize_egress_internet_snapshot(
                Revision::new(2),
                owner(),
                spec(EgressInternetFallback::Deny),
                Some(foreign),
                None,
                1_010,
            )
            .unwrap_err(),
            EgressInternetError::ForeignClassifier
        );

        let denied = materialize_egress_internet_snapshot(
            Revision::new(2),
            owner(),
            spec(EgressInternetFallback::Deny),
            None,
            None,
            1_010,
        )
        .unwrap();
        assert_eq!(
            denied.snapshot().authority,
            EgressInternetAuthority::DenyClosed
        );
        assert_eq!(
            classify_egress_internet_destination(
                &denied,
                IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
                1_010
            ),
            EgressInternetDecision::Unclassified
        );

        let prior = materialize_egress_internet_snapshot(
            Revision::new(2),
            owner(),
            spec(EgressInternetFallback::Deny),
            Some(super::tests::classification()),
            None,
            1_010,
        )
        .unwrap();
        let mut regressed = super::tests::classification();
        regressed.revision = Revision::new(6);
        regressed = seal_egress_internet_classification(regressed).unwrap();
        assert_eq!(
            materialize_egress_internet_snapshot(
                Revision::new(3),
                owner(),
                spec(EgressInternetFallback::Deny),
                Some(regressed),
                Some(&prior),
                1_010,
            )
            .unwrap_err(),
            EgressInternetError::ClassificationRegression
        );
    }

    #[test]
    fn classifier_rotation_starts_an_independent_replay_domain() {
        let prior = materialize_egress_internet_snapshot(
            Revision::new(3),
            owner(),
            spec(EgressInternetFallback::Deny),
            Some(classification()),
            None,
            1_010,
        )
        .unwrap();
        let mut rotated_spec = spec(EgressInternetFallback::LastKnownGood {
            max_staleness_seconds: 60,
        });
        rotated_spec.classifier.instance = "regional-v2".to_owned();
        let mut rotated = classification();
        rotated.source = rotated_spec.classifier.clone();
        rotated.source_epoch = 1;
        rotated.revision = Revision::new(1);
        rotated = seal_egress_internet_classification(rotated).unwrap();

        let current = materialize_egress_internet_snapshot(
            Revision::new(4),
            owner(),
            rotated_spec.clone(),
            Some(rotated),
            Some(&prior),
            1_020,
        )
        .unwrap();
        assert_eq!(
            current.snapshot().authority,
            EgressInternetAuthority::Current
        );
        assert_eq!(current.snapshot().policy.classifier.instance, "regional-v2");

        let denied = materialize_egress_internet_snapshot(
            Revision::new(4),
            owner(),
            rotated_spec,
            None,
            Some(&prior),
            1_020,
        )
        .unwrap();
        assert_eq!(
            denied.snapshot().authority,
            EgressInternetAuthority::DenyClosed
        );
    }

    #[test]
    fn model_materialization_is_explicit_and_reports_deny_closed_loss() {
        let internet = spec(EgressInternetFallback::Deny);
        let model = crate::normalize_model(
            Vec::new(),
            vec![crate::EgressIntent {
                owner: owner(),
                priority: crate::DEFAULT_EGRESS_INTENT_PRIORITY,
                source: crate::EgressSourceSelector::default(),
                destinations: crate::EgressDestinations::DenyAll,
                fqdn: None,
                internet: Some(internet.clone()),
                addresses: crate::EgressAddressRequest::Explicit {
                    addresses: vec!["192.0.2.10".parse().unwrap()],
                },
            }],
        )
        .unwrap();
        let mut classifications = BTreeMap::new();
        classifications.insert(internet.classifier.clone(), classification());
        let (materialized, reports) = materialize_egress_internet_model(
            model.clone(),
            &classifications,
            &BTreeMap::new(),
            Revision::new(4),
            1_010,
        )
        .unwrap();
        assert!(matches!(
            materialized.intents[0].destinations,
            crate::EgressDestinations::Internet(_)
        ));
        let report = reports.get(&owner()).unwrap();
        assert_eq!(report.classification_revision, Some(Revision::new(7)));
        assert_eq!(report.internet_rules, 2);
        assert_eq!(report.non_internet_rules, 2);

        let (denied, reports) = materialize_egress_internet_model(
            model,
            &BTreeMap::new(),
            &BTreeMap::new(),
            Revision::new(5),
            1_020,
        )
        .unwrap();
        let crate::EgressDestinations::Internet(snapshot) = &denied.intents[0].destinations else {
            panic!("internet intent must be materialized");
        };
        assert_eq!(snapshot.authority, EgressInternetAuthority::DenyClosed);
        assert_eq!(
            reports.get(&owner()).unwrap().authority,
            EgressInternetAuthority::DenyClosed
        );
    }
}
