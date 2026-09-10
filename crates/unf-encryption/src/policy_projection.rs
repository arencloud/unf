//! Lossless projection from L4 policy outcomes to L3 encryption demand.
//!
//! Encryption transport availability is monotonic: if any policy-authorized
//! L4 class may use an identity pair, the pair needs transport. This does not
//! authorize packets; the original L4 policy lookup remains the first gate.

use std::collections::{BTreeMap, BTreeSet};

use thiserror::Error;
use unf_common::{IdentityId, PolicyId, PolicyReason};

use crate::{EncryptionPolicyFact, MAX_ENCRYPTION_PATHS};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct EncryptionIdentityPair {
    pub source: IdentityId,
    pub destination: IdentityId,
}

/// One effective outcome from any protocol/port class for an identity pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncryptionPolicyObservation {
    pub pair: EncryptionIdentityPair,
    pub allowed: bool,
    pub reason: PolicyReason,
    pub policy_id: Option<PolicyId>,
}

/// Projects one exact fact per requested identity pair.
///
/// Absence is represented truthfully as `NoApplicablePolicy` with no invented
/// policy ID. Any allowed L4 class requests transport, while an all-denied pair
/// remains denied. The output is not packet authorization.
///
/// # Errors
///
/// Rejects zero/duplicate pairs, foreign observations, invalid provenance, or
/// capacity overflow.
pub fn project_encryption_policy_facts(
    pairs: impl IntoIterator<Item = EncryptionIdentityPair>,
    observations: impl IntoIterator<Item = EncryptionPolicyObservation>,
) -> Result<Vec<EncryptionPolicyFact>, EncryptionPolicyProjectionError> {
    let mut canonical_pairs = BTreeSet::new();
    for pair in pairs {
        if !canonical_pairs.insert(pair) {
            return Err(EncryptionPolicyProjectionError::InvalidPairSet);
        }
    }
    let pairs = canonical_pairs;
    if pairs.is_empty()
        || pairs.len() > MAX_ENCRYPTION_PATHS
        || pairs
            .iter()
            .any(|pair| pair.source.get() == 0 || pair.destination.get() == 0)
    {
        return Err(EncryptionPolicyProjectionError::InvalidPairSet);
    }
    let mut grouped = BTreeMap::<EncryptionIdentityPair, Vec<EncryptionPolicyObservation>>::new();
    for observation in observations {
        if !pairs.contains(&observation.pair)
            || observation
                .policy_id
                .is_some_and(|policy| policy.get() == 0)
            || matches!(observation.reason, PolicyReason::NoApplicablePolicy)
                && observation.policy_id.is_some()
            || !matches!(observation.reason, PolicyReason::NoApplicablePolicy)
                && observation.policy_id.is_none()
        {
            return Err(EncryptionPolicyProjectionError::InvalidObservation);
        }
        grouped
            .entry(observation.pair)
            .or_default()
            .push(observation);
    }

    pairs
        .into_iter()
        .map(|pair| {
            let observations = grouped.remove(&pair).unwrap_or_default();
            project_pair(pair, &observations)
        })
        .collect()
}

fn project_pair(
    pair: EncryptionIdentityPair,
    observations: &[EncryptionPolicyObservation],
) -> Result<EncryptionPolicyFact, EncryptionPolicyProjectionError> {
    if observations.is_empty() {
        return Ok(EncryptionPolicyFact {
            source: pair.source,
            destination: pair.destination,
            allowed: true,
            reason: PolicyReason::NoApplicablePolicy,
            policy_ids: Vec::new(),
        });
    }
    let allowed = observations.iter().any(|observation| observation.allowed);
    let relevant = observations
        .iter()
        .filter(|observation| observation.allowed == allowed)
        .collect::<Vec<_>>();
    let reason = if relevant
        .iter()
        .any(|observation| observation.reason == PolicyReason::ExplicitRule)
    {
        PolicyReason::ExplicitRule
    } else if relevant
        .iter()
        .any(|observation| observation.reason == PolicyReason::DefaultAction)
    {
        PolicyReason::DefaultAction
    } else {
        PolicyReason::NoApplicablePolicy
    };
    let policy_ids = relevant
        .iter()
        .filter_map(|observation| observation.policy_id)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    if matches!(reason, PolicyReason::NoApplicablePolicy) != policy_ids.is_empty() {
        return Err(EncryptionPolicyProjectionError::InvalidObservation);
    }
    Ok(EncryptionPolicyFact {
        source: pair.source,
        destination: pair.destination,
        allowed,
        reason,
        policy_ids,
    })
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum EncryptionPolicyProjectionError {
    #[error("encryption policy projection pair set is empty, invalid, or oversized")]
    InvalidPairSet,
    #[error("encryption policy observation is foreign or has invalid provenance")]
    InvalidObservation,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair(source: u32, destination: u32) -> EncryptionIdentityPair {
        EncryptionIdentityPair {
            source: IdentityId::new(source),
            destination: IdentityId::new(destination),
        }
    }

    #[test]
    fn policy_truth_quotient_preserves_default_allow_without_fake_identity() {
        let facts = project_encryption_policy_facts([pair(1, 2)], []).unwrap();
        assert!(facts[0].allowed);
        assert_eq!(facts[0].reason, PolicyReason::NoApplicablePolicy);
        assert!(facts[0].policy_ids.is_empty());
    }

    #[test]
    fn policy_truth_quotient_needs_transport_for_any_allowed_l4_class() {
        let pair = pair(1, 2);
        let facts = project_encryption_policy_facts(
            [pair],
            [
                EncryptionPolicyObservation {
                    pair,
                    allowed: false,
                    reason: PolicyReason::DefaultAction,
                    policy_id: Some(PolicyId::new(7)),
                },
                EncryptionPolicyObservation {
                    pair,
                    allowed: true,
                    reason: PolicyReason::ExplicitRule,
                    policy_id: Some(PolicyId::new(9)),
                },
                EncryptionPolicyObservation {
                    pair,
                    allowed: true,
                    reason: PolicyReason::ExplicitRule,
                    policy_id: Some(PolicyId::new(9)),
                },
            ],
        )
        .unwrap();
        assert!(facts[0].allowed);
        assert_eq!(facts[0].reason, PolicyReason::ExplicitRule);
        assert_eq!(facts[0].policy_ids, [PolicyId::new(9)]);
    }

    #[test]
    fn policy_truth_quotient_keeps_all_denied_pairs_out_of_plans() {
        let pair = pair(1, 2);
        let facts = project_encryption_policy_facts(
            [pair],
            [EncryptionPolicyObservation {
                pair,
                allowed: false,
                reason: PolicyReason::DefaultAction,
                policy_id: Some(PolicyId::new(7)),
            }],
        )
        .unwrap();
        assert!(!facts[0].allowed);
        assert_eq!(facts[0].policy_ids, [PolicyId::new(7)]);
    }
}
