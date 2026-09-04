//! Durable ownership for DQR plans, observer publications, and assessments.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use unf_common::Revision;

use crate::{
    EgressIntentOwner, EgressReachabilityAssessment, EgressReachabilityError,
    EgressReachabilityObservation, EgressReachabilityPlan, MAX_EGRESS_INTENTS,
    MAX_EGRESS_REACHABILITY_FUTURE_SKEW_SECONDS, MAX_EGRESS_REACHABILITY_OBSERVERS,
    VerifiedEgressReachabilityAssessment, assess_egress_reachability,
    egress_reachability_verdict_at, verify_egress_reachability_assessment,
    verify_egress_reachability_observation, verify_egress_reachability_plan,
};

pub const EGRESS_REACHABILITY_STORE_SCHEMA_VERSION: u16 = 1;
pub const MAX_EGRESS_REACHABILITY_SOURCE_KEY_BYTES: usize = 512;

const STORE_DIGEST_DOMAIN: &[u8] = b"unf.egress.reachability.store.v1\0";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EgressReachabilityPlanRecord {
    pub source_key: String,
    pub plan: EgressReachabilityPlan,
}

/// One authenticated Kubernetes status publication. The embedded plan makes
/// ingestion order-independent; it becomes authority only if it exactly
/// matches the current controller-owned plan at `plan_source_key`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EgressReachabilityObservationRecord {
    pub source_key: String,
    pub plan_source_key: String,
    pub plan: EgressReachabilityPlan,
    pub observation: EgressReachabilityObservation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EgressReachabilityStoreDigest(pub [u8; 32]);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EgressReachabilityStoreCheckpoint {
    pub schema_version: u16,
    pub revision: Revision,
    pub persisted_at_unix_seconds: u64,
    pub current_plans: Vec<EgressReachabilityPlanRecord>,
    pub current_observations: Vec<EgressReachabilityObservationRecord>,
    pub latest_plans: Vec<EgressReachabilityPlanRecord>,
    pub latest_observations: Vec<EgressReachabilityObservationRecord>,
    pub assessments: Vec<EgressReachabilityAssessment>,
    pub digest: EgressReachabilityStoreDigest,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum EgressReachabilityStoreError {
    #[error("invalid reachability source key")]
    InvalidSourceKey,
    #[error("reachability store capacity is exhausted")]
    CapacityExceeded,
    #[error("more than one current plan owns the same egress intent")]
    DuplicateOwner,
    #[error("more than one current object claims the same observer")]
    DuplicateObserver,
    #[error("reachability plan or observation position regressed")]
    Regression,
    #[error("reachability plan or observation mutated at the same position")]
    SamePositionMutation,
    #[error("unsupported reachability store checkpoint schema")]
    UnsupportedSchema,
    #[error("reachability store checkpoint is noncanonical")]
    NoncanonicalCheckpoint,
    #[error("reachability store revision is exhausted")]
    RevisionExhausted,
    #[error("reachability store encoding failed: {0}")]
    Encoding(String),
    #[error(transparent)]
    Reachability(#[from] EgressReachabilityError),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EgressReachabilityEvidenceStore {
    revision: Revision,
    current_plans: BTreeMap<String, EgressReachabilityPlan>,
    current_observations: BTreeMap<String, EgressReachabilityObservationRecord>,
    latest_plans: BTreeMap<String, EgressReachabilityPlan>,
    latest_observations: BTreeMap<String, EgressReachabilityObservationRecord>,
    assessments: BTreeMap<EgressIntentOwner, EgressReachabilityAssessment>,
}

impl Default for EgressReachabilityEvidenceStore {
    fn default() -> Self {
        Self {
            revision: Revision::INITIAL,
            current_plans: BTreeMap::new(),
            current_observations: BTreeMap::new(),
            latest_plans: BTreeMap::new(),
            latest_observations: BTreeMap::new(),
            assessments: BTreeMap::new(),
        }
    }
}

impl EgressReachabilityEvidenceStore {
    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    #[must_use]
    pub fn plan(&self, source_key: &str) -> Option<&EgressReachabilityPlan> {
        self.current_plans.get(source_key)
    }

    #[must_use]
    pub fn current_plan_records(&self) -> Vec<EgressReachabilityPlanRecord> {
        plan_records(&self.current_plans)
    }

    /// Revalidates the retained assessments without advancing time or store
    /// revision. Consumers independently enforce each absolute authority
    /// deadline when compiling an acknowledgement.
    ///
    /// # Errors
    ///
    /// Rejects any internally inconsistent retained plan, observation, or
    /// assessment.
    pub fn verified_assessments(
        &self,
    ) -> Result<
        BTreeMap<EgressIntentOwner, VerifiedEgressReachabilityAssessment>,
        EgressReachabilityStoreError,
    > {
        let mut verified = BTreeMap::new();
        for (source_key, plan) in &self.current_plans {
            let Some(assessment) = self.assessments.get(&plan.owner) else {
                continue;
            };
            let observations = self
                .current_observations
                .values()
                .filter(|record| {
                    record.plan_source_key == *source_key && record.plan.digest == plan.digest
                })
                .map(|record| record.observation.clone())
                .collect::<Vec<_>>();
            verified.insert(
                plan.owner.clone(),
                verify_egress_reachability_assessment(plan.clone(), observations, assessment)?,
            );
        }
        Ok(verified)
    }

    #[must_use]
    pub fn next_refresh_at_unix_seconds(&self) -> Option<u64> {
        self.assessments
            .values()
            .filter(|assessment| assessment.verdict != crate::EgressReachabilityVerdict::DenyClosed)
            .map(|assessment| assessment.authority_until_unix_seconds)
            .min()
    }

    /// Applies one controller-owned plan publication atomically.
    ///
    /// # Errors
    ///
    /// Rejects invalid keys/plans, ambiguous owner control, replay, mutation,
    /// capacity, or revision exhaustion.
    pub fn apply_plan(
        &mut self,
        source_key: String,
        plan: EgressReachabilityPlan,
    ) -> Result<bool, EgressReachabilityStoreError> {
        validate_source_key(&source_key)?;
        let plan = verify_egress_reachability_plan(plan)?;
        if self.current_plans.get(&source_key) == Some(&plan) {
            return Ok(false);
        }
        if self
            .current_plans
            .iter()
            .any(|(key, candidate)| key != &source_key && candidate.owner == plan.owner)
        {
            return Err(EgressReachabilityStoreError::DuplicateOwner);
        }
        if let Some(previous) = self.latest_plans.get(&source_key) {
            verify_plan_position(previous, &plan)?;
        }
        if !self.current_plans.contains_key(&source_key)
            && self.current_plans.len() >= MAX_EGRESS_INTENTS
        {
            return Err(EgressReachabilityStoreError::CapacityExceeded);
        }
        self.revision = checked_next(self.revision)?;
        self.current_plans.insert(source_key.clone(), plan.clone());
        self.latest_plans.insert(source_key, plan);
        self.assessments.clear();
        Ok(true)
    }

    /// Removes current plan authority while retaining its replay position.
    ///
    /// # Errors
    ///
    /// Rejects invalid keys or revision exhaustion.
    pub fn remove_plan(&mut self, source_key: &str) -> Result<bool, EgressReachabilityStoreError> {
        validate_source_key(source_key)?;
        if self.current_plans.remove(source_key).is_none() {
            return Ok(false);
        }
        self.revision = checked_next(self.revision)?;
        self.assessments.clear();
        Ok(true)
    }

    /// Atomically replaces the complete controller-owned plan set after a
    /// Kubernetes relist while retaining replay positions for absent plans.
    ///
    /// # Errors
    ///
    /// Rejects any invalid, duplicate, regressed, mutated, or oversized set.
    pub fn replace_plans(
        &mut self,
        replacement: BTreeMap<String, EgressReachabilityPlan>,
    ) -> Result<bool, EgressReachabilityStoreError> {
        if replacement == self.current_plans {
            return Ok(false);
        }
        if replacement.len() > MAX_EGRESS_INTENTS {
            return Err(EgressReachabilityStoreError::CapacityExceeded);
        }
        let mut owners = BTreeMap::new();
        let mut verified = BTreeMap::new();
        let mut latest = self.latest_plans.clone();
        for (source_key, plan) in replacement {
            validate_source_key(&source_key)?;
            let plan = verify_egress_reachability_plan(plan)?;
            if owners
                .insert(plan.owner.clone(), source_key.clone())
                .is_some()
            {
                return Err(EgressReachabilityStoreError::DuplicateOwner);
            }
            if let Some(previous) = latest.get(&source_key) {
                verify_plan_position(previous, &plan)?;
            }
            latest.insert(source_key.clone(), plan.clone());
            verified.insert(source_key, plan);
        }
        self.revision = checked_next(self.revision)?;
        self.current_plans = verified;
        self.latest_plans = latest;
        self.assessments.clear();
        Ok(true)
    }

    /// Applies one observer status publication. Its embedded plan is validated
    /// immediately but may arrive before the matching controller plan.
    ///
    /// # Errors
    ///
    /// Rejects malformed input, observer aliasing, replay, mutation, capacity,
    /// or revision exhaustion.
    pub fn apply_observation(
        &mut self,
        mut record: EgressReachabilityObservationRecord,
    ) -> Result<bool, EgressReachabilityStoreError> {
        validate_source_key(&record.source_key)?;
        validate_source_key(&record.plan_source_key)?;
        record.plan = verify_egress_reachability_plan(record.plan)?;
        record.observation =
            verify_egress_reachability_observation(&record.plan, record.observation)?;
        if self.current_observations.get(&record.source_key) == Some(&record) {
            return Ok(false);
        }
        let observer = record.observation.observer.name.clone();
        if self.current_observations.iter().any(|(key, candidate)| {
            key != &record.source_key && candidate.observation.observer.name == observer
        }) {
            return Err(EgressReachabilityStoreError::DuplicateObserver);
        }
        if let Some(previous) = self.latest_observations.get(&observer) {
            verify_observation_position(previous, &record)?;
        }
        if !self.current_observations.contains_key(&record.source_key)
            && self.current_observations.len() >= MAX_EGRESS_REACHABILITY_OBSERVERS
        {
            return Err(EgressReachabilityStoreError::CapacityExceeded);
        }
        self.revision = checked_next(self.revision)?;
        self.current_observations
            .insert(record.source_key.clone(), record.clone());
        self.latest_observations.insert(observer, record);
        self.assessments.clear();
        Ok(true)
    }

    /// Removes current observer authority while retaining replay evidence.
    ///
    /// # Errors
    ///
    /// Rejects invalid keys or revision exhaustion.
    pub fn remove_observation(
        &mut self,
        source_key: &str,
    ) -> Result<bool, EgressReachabilityStoreError> {
        validate_source_key(source_key)?;
        if self.current_observations.remove(source_key).is_none() {
            return Ok(false);
        }
        self.revision = checked_next(self.revision)?;
        self.assessments.clear();
        Ok(true)
    }

    /// Atomically replaces the complete observation set after a Kubernetes
    /// relist while retaining per-observer replay positions.
    ///
    /// # Errors
    ///
    /// Rejects any invalid, aliased, regressed, mutated, or oversized set.
    pub fn replace_observations(
        &mut self,
        replacement: BTreeMap<String, EgressReachabilityObservationRecord>,
    ) -> Result<bool, EgressReachabilityStoreError> {
        if replacement == self.current_observations {
            return Ok(false);
        }
        if replacement.len() > MAX_EGRESS_REACHABILITY_OBSERVERS {
            return Err(EgressReachabilityStoreError::CapacityExceeded);
        }
        let mut observers = BTreeMap::new();
        let mut verified = BTreeMap::new();
        let mut latest = self.latest_observations.clone();
        for (source_key, mut record) in replacement {
            if record.source_key != source_key {
                return Err(EgressReachabilityStoreError::InvalidSourceKey);
            }
            record = verify_record(record)?;
            let observer = record.observation.observer.name.clone();
            if observers
                .insert(observer.clone(), source_key.clone())
                .is_some()
            {
                return Err(EgressReachabilityStoreError::DuplicateObserver);
            }
            if let Some(previous) = latest.get(&observer) {
                verify_observation_position(previous, &record)?;
            }
            latest.insert(observer, record.clone());
            verified.insert(source_key, record);
        }
        self.revision = checked_next(self.revision)?;
        self.current_observations = verified;
        self.latest_observations = latest;
        self.assessments.clear();
        Ok(true)
    }

    /// Recompiles every current controller plan from only matching observer
    /// publications and retains the exact assessments for durable replay.
    ///
    /// # Errors
    ///
    /// Rejects invalid stored evidence, assessment compilation, or revision
    /// exhaustion without partially replacing retained assessments.
    pub fn materialize(
        &mut self,
        now_unix_seconds: u64,
    ) -> Result<
        BTreeMap<EgressIntentOwner, VerifiedEgressReachabilityAssessment>,
        EgressReachabilityStoreError,
    > {
        let mut verified = BTreeMap::new();
        let mut assessments = BTreeMap::new();
        for (source_key, plan) in &self.current_plans {
            let observations = self
                .current_observations
                .values()
                .filter(|record| {
                    record.plan_source_key == *source_key && record.plan.digest == plan.digest
                })
                .map(|record| record.observation.clone())
                .collect::<Vec<_>>();
            let assessment = if let Some(previous) = self.assessments.get(&plan.owner) {
                let previous = verify_egress_reachability_assessment(
                    plan.clone(),
                    observations.clone(),
                    previous,
                )?;
                if previous.verdict == crate::EgressReachabilityVerdict::DenyClosed
                    || egress_reachability_verdict_at(plan, &previous, now_unix_seconds)?
                        != crate::EgressReachabilityVerdict::DenyClosed
                {
                    previous
                } else {
                    assess_egress_reachability(plan.clone(), observations, now_unix_seconds)?
                }
            } else {
                assess_egress_reachability(plan.clone(), observations, now_unix_seconds)?
            };
            assessments.insert(plan.owner.clone(), assessment.assessment().clone());
            verified.insert(plan.owner.clone(), assessment);
        }
        if assessments != self.assessments {
            self.revision = checked_next(self.revision)?;
            self.assessments = assessments;
        }
        Ok(verified)
    }

    /// Produces one canonical, domain-separated durable checkpoint.
    ///
    /// # Errors
    ///
    /// Returns an encoding error if canonical serialization fails.
    pub fn checkpoint(
        &self,
        persisted_at_unix_seconds: u64,
    ) -> Result<EgressReachabilityStoreCheckpoint, EgressReachabilityStoreError> {
        let mut checkpoint = EgressReachabilityStoreCheckpoint {
            schema_version: EGRESS_REACHABILITY_STORE_SCHEMA_VERSION,
            revision: self.revision,
            persisted_at_unix_seconds,
            current_plans: plan_records(&self.current_plans),
            current_observations: self.current_observations.values().cloned().collect(),
            latest_plans: plan_records(&self.latest_plans),
            latest_observations: self.latest_observations.values().cloned().collect(),
            assessments: self.assessments.values().cloned().collect(),
            digest: EgressReachabilityStoreDigest([0; 32]),
        };
        checkpoint.digest = checkpoint_digest(&checkpoint)?;
        Ok(checkpoint)
    }

    /// Restores a checkpoint only after complete semantic and digest replay.
    ///
    /// # Errors
    ///
    /// Rejects version, clock, ordering, duplication, capacity, evidence,
    /// assessment, or digest drift without partial adoption.
    #[allow(clippy::too_many_lines)]
    pub fn restore(
        checkpoint: &EgressReachabilityStoreCheckpoint,
        now_unix_seconds: u64,
    ) -> Result<Self, EgressReachabilityStoreError> {
        if checkpoint.schema_version != EGRESS_REACHABILITY_STORE_SCHEMA_VERSION {
            return Err(EgressReachabilityStoreError::UnsupportedSchema);
        }
        if checkpoint.persisted_at_unix_seconds
            > now_unix_seconds.saturating_add(MAX_EGRESS_REACHABILITY_FUTURE_SKEW_SECONDS)
            || checkpoint.current_plans.len() > MAX_EGRESS_INTENTS
            || checkpoint.latest_plans.len() > MAX_EGRESS_INTENTS
            || checkpoint.current_observations.len() > MAX_EGRESS_REACHABILITY_OBSERVERS
            || checkpoint.latest_observations.len() > MAX_EGRESS_REACHABILITY_OBSERVERS
            || checkpoint.assessments.len() > MAX_EGRESS_INTENTS
            || checkpoint_digest(checkpoint)? != checkpoint.digest
        {
            return Err(EgressReachabilityStoreError::NoncanonicalCheckpoint);
        }
        let mut store = Self {
            revision: checkpoint.revision,
            ..Self::default()
        };
        for record in &checkpoint.latest_plans {
            validate_source_key(&record.source_key)?;
            let plan = verify_egress_reachability_plan(record.plan.clone())?;
            if store
                .latest_plans
                .insert(record.source_key.clone(), plan)
                .is_some()
            {
                return Err(EgressReachabilityStoreError::NoncanonicalCheckpoint);
            }
        }
        for record in &checkpoint.current_plans {
            validate_source_key(&record.source_key)?;
            let plan = verify_egress_reachability_plan(record.plan.clone())?;
            if store
                .latest_plans
                .get(&record.source_key)
                .is_none_or(|latest| latest != &plan)
                || store
                    .current_plans
                    .values()
                    .any(|candidate| candidate.owner == plan.owner)
                || store
                    .current_plans
                    .insert(record.source_key.clone(), plan)
                    .is_some()
            {
                return Err(EgressReachabilityStoreError::NoncanonicalCheckpoint);
            }
        }
        for record in &checkpoint.latest_observations {
            let record = verify_record(record.clone())?;
            let observer = record.observation.observer.name.clone();
            if store.latest_observations.insert(observer, record).is_some() {
                return Err(EgressReachabilityStoreError::NoncanonicalCheckpoint);
            }
        }
        for record in &checkpoint.current_observations {
            let record = verify_record(record.clone())?;
            let observer = record.observation.observer.name.clone();
            if store
                .latest_observations
                .get(&observer)
                .is_none_or(|latest| latest != &record)
                || store
                    .current_observations
                    .values()
                    .any(|candidate| candidate.observation.observer.name == observer)
                || store
                    .current_observations
                    .insert(record.source_key.clone(), record)
                    .is_some()
            {
                return Err(EgressReachabilityStoreError::NoncanonicalCheckpoint);
            }
        }
        for assessment in &checkpoint.assessments {
            if assessment.compiled_at_unix_seconds
                > now_unix_seconds.saturating_add(MAX_EGRESS_REACHABILITY_FUTURE_SKEW_SECONDS)
            {
                return Err(EgressReachabilityStoreError::NoncanonicalCheckpoint);
            }
            let (plan_source_key, plan) = store
                .current_plans
                .iter()
                .find(|(_, plan)| plan.digest == assessment.plan_digest)
                .ok_or(EgressReachabilityStoreError::NoncanonicalCheckpoint)?;
            let observations = store
                .current_observations
                .values()
                .filter(|record| {
                    record.plan_source_key == *plan_source_key && record.plan.digest == plan.digest
                })
                .map(|record| record.observation.clone())
                .collect::<Vec<_>>();
            let verified =
                verify_egress_reachability_assessment(plan.clone(), observations, assessment)?;
            if store
                .assessments
                .insert(plan.owner.clone(), verified.assessment().clone())
                .is_some()
            {
                return Err(EgressReachabilityStoreError::NoncanonicalCheckpoint);
            }
        }
        if store.checkpoint(checkpoint.persisted_at_unix_seconds)? != *checkpoint
            || (store.revision == Revision::INITIAL
                && (!store.current_plans.is_empty()
                    || !store.current_observations.is_empty()
                    || !store.latest_plans.is_empty()
                    || !store.latest_observations.is_empty()
                    || !store.assessments.is_empty()))
        {
            return Err(EgressReachabilityStoreError::NoncanonicalCheckpoint);
        }
        Ok(store)
    }
}

fn verify_record(
    mut record: EgressReachabilityObservationRecord,
) -> Result<EgressReachabilityObservationRecord, EgressReachabilityStoreError> {
    validate_source_key(&record.source_key)?;
    validate_source_key(&record.plan_source_key)?;
    record.plan = verify_egress_reachability_plan(record.plan)?;
    record.observation = verify_egress_reachability_observation(&record.plan, record.observation)?;
    Ok(record)
}

fn verify_plan_position(
    previous: &EgressReachabilityPlan,
    current: &EgressReachabilityPlan,
) -> Result<(), EgressReachabilityStoreError> {
    if current.revision < previous.revision {
        return Err(EgressReachabilityStoreError::Regression);
    }
    if current.revision == previous.revision && current.digest != previous.digest {
        return Err(EgressReachabilityStoreError::SamePositionMutation);
    }
    Ok(())
}

fn verify_observation_position(
    previous: &EgressReachabilityObservationRecord,
    current: &EgressReachabilityObservationRecord,
) -> Result<(), EgressReachabilityStoreError> {
    let old = (
        previous.observation.source_epoch,
        previous.observation.revision,
    );
    let new = (
        current.observation.source_epoch,
        current.observation.revision,
    );
    if new < old {
        return Err(EgressReachabilityStoreError::Regression);
    }
    if new == old && current != previous {
        return Err(EgressReachabilityStoreError::SamePositionMutation);
    }
    Ok(())
}

fn plan_records(
    plans: &BTreeMap<String, EgressReachabilityPlan>,
) -> Vec<EgressReachabilityPlanRecord> {
    plans
        .iter()
        .map(|(source_key, plan)| EgressReachabilityPlanRecord {
            source_key: source_key.clone(),
            plan: plan.clone(),
        })
        .collect()
}

fn validate_source_key(source_key: &str) -> Result<(), EgressReachabilityStoreError> {
    if source_key.is_empty()
        || source_key.len() > MAX_EGRESS_REACHABILITY_SOURCE_KEY_BYTES
        || source_key.chars().any(char::is_control)
    {
        return Err(EgressReachabilityStoreError::InvalidSourceKey);
    }
    Ok(())
}

fn checked_next(revision: Revision) -> Result<Revision, EgressReachabilityStoreError> {
    revision
        .get()
        .checked_add(1)
        .map(Revision::new)
        .ok_or(EgressReachabilityStoreError::RevisionExhausted)
}

fn checkpoint_digest(
    checkpoint: &EgressReachabilityStoreCheckpoint,
) -> Result<EgressReachabilityStoreDigest, EgressReachabilityStoreError> {
    let material = (
        checkpoint.schema_version,
        checkpoint.revision,
        checkpoint.persisted_at_unix_seconds,
        &checkpoint.current_plans,
        &checkpoint.current_observations,
        &checkpoint.latest_plans,
        &checkpoint.latest_observations,
        &checkpoint.assessments,
    );
    let encoded = serde_json::to_vec(&material)
        .map_err(|error| EgressReachabilityStoreError::Encoding(error.to_string()))?;
    let mut digest = Sha256::new();
    digest.update(STORE_DIGEST_DOMAIN);
    digest.update(encoded);
    Ok(EgressReachabilityStoreDigest(digest.finalize().into()))
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use super::*;
    use crate::{
        EGRESS_REACHABILITY_ALGORITHM_DIVERSITY_QUORUM_V1, EGRESS_REACHABILITY_SCHEMA_VERSION,
        EgressGatewayAction, EgressIntentScope, EgressProviderRef,
        EgressReachabilityObservationDigest, EgressReachabilityObserver, EgressReachabilityPath,
        EgressReachabilityPlanDigest, EgressReachabilityRouteObservation,
        EgressReachabilityVantage, EgressReachabilityVerdict, seal_egress_reachability_observation,
        seal_egress_reachability_plan,
    };

    const NOW: u64 = 30_000;

    fn plan(revision: u64) -> EgressReachabilityPlan {
        seal_egress_reachability_plan(EgressReachabilityPlan {
            schema_version: EGRESS_REACHABILITY_SCHEMA_VERSION,
            algorithm: EGRESS_REACHABILITY_ALGORITHM_DIVERSITY_QUORUM_V1.to_owned(),
            revision: Revision::new(revision),
            desired_revision: Revision::new(8),
            allocation_revision: Revision::new(7),
            owner: EgressIntentOwner {
                scope: EgressIntentScope::Cluster,
                name: "finance".to_owned(),
                uid: "finance-uid".to_owned(),
            },
            provider: EgressProviderRef {
                name: "bgp".to_owned(),
                instance: "edge".to_owned(),
            },
            lease_epoch: 4,
            action: EgressGatewayAction::Ensure,
            addresses: vec![
                "192.0.2.10".parse().unwrap(),
                "2001:db8::10".parse().unwrap(),
            ],
            expected_paths: vec![EgressReachabilityPath {
                gateway_uid: "gateway-a".to_owned(),
                forwarding_identity: "edge-a".to_owned(),
            }],
            minimum_paths_per_address: 1,
            maximum_paths_per_address: 1,
            vantages: vec![EgressReachabilityVantage {
                name: "outside".to_owned(),
                minimum_failure_domains: 2,
            }],
            max_observation_age_seconds: 60,
            digest: EgressReachabilityPlanDigest([0; 32]),
        })
        .unwrap()
    }

    fn record(
        plan: &EgressReachabilityPlan,
        observer: &str,
        domain: &str,
        revision: u64,
    ) -> EgressReachabilityObservationRecord {
        let observation = seal_egress_reachability_observation(
            plan,
            EgressReachabilityObservation {
                schema_version: EGRESS_REACHABILITY_SCHEMA_VERSION,
                algorithm: EGRESS_REACHABILITY_ALGORITHM_DIVERSITY_QUORUM_V1.to_owned(),
                plan_digest: plan.digest,
                observer: EgressReachabilityObserver {
                    name: observer.to_owned(),
                    failure_domain: domain.to_owned(),
                    vantage: "outside".to_owned(),
                },
                source_epoch: 2,
                revision: Revision::new(revision),
                observed_at_unix_seconds: NOW,
                valid_until_unix_seconds: NOW + 50,
                routes: plan
                    .addresses
                    .iter()
                    .map(|address| EgressReachabilityRouteObservation {
                        address: *address,
                        paths: plan.expected_paths.clone(),
                    })
                    .collect(),
                digest: EgressReachabilityObservationDigest([0; 32]),
            },
        )
        .unwrap();
        EgressReachabilityObservationRecord {
            source_key: format!("native:observation/{observer}"),
            plan_source_key: "native:plan/finance".to_owned(),
            plan: plan.clone(),
            observation,
        }
    }

    #[test]
    fn observations_can_arrive_before_plan_but_never_create_authority() {
        let plan = plan(3);
        let mut store = EgressReachabilityEvidenceStore::default();
        store
            .apply_observation(record(&plan, "a", "rack-a", 1))
            .unwrap();
        store
            .apply_observation(record(&plan, "b", "rack-b", 1))
            .unwrap();
        assert!(store.materialize(NOW + 1).unwrap().is_empty());
        store
            .apply_plan("native:plan/finance".to_owned(), plan.clone())
            .unwrap();
        let assessments = store.materialize(NOW + 1).unwrap();
        assert_eq!(
            assessments[&plan.owner].verdict,
            EgressReachabilityVerdict::Ready
        );
    }

    #[test]
    fn deletion_retains_replay_positions_and_revokes_quorum() {
        let plan = plan(3);
        let mut store = EgressReachabilityEvidenceStore::default();
        store
            .apply_plan("native:plan/finance".to_owned(), plan.clone())
            .unwrap();
        store
            .apply_observation(record(&plan, "a", "rack-a", 4))
            .unwrap();
        store
            .apply_observation(record(&plan, "b", "rack-b", 4))
            .unwrap();
        store.materialize(NOW + 1).unwrap();
        store.remove_observation("native:observation/b").unwrap();
        assert_eq!(
            store.materialize(NOW + 2).unwrap()[&plan.owner].verdict,
            EgressReachabilityVerdict::DenyClosed
        );
        assert_eq!(
            store
                .apply_observation(record(&plan, "b", "rack-b", 3))
                .unwrap_err(),
            EgressReachabilityStoreError::Regression
        );
    }

    #[test]
    fn checkpoint_replays_exact_assessment_and_rejects_inner_mutation() {
        let plan = plan(3);
        let mut store = EgressReachabilityEvidenceStore::default();
        store
            .apply_plan("native:plan/finance".to_owned(), plan.clone())
            .unwrap();
        store
            .apply_observation(record(&plan, "a", "rack-a", 1))
            .unwrap();
        store
            .apply_observation(record(&plan, "b", "rack-b", 1))
            .unwrap();
        store.materialize(NOW + 1).unwrap();
        let checkpoint = store.checkpoint(NOW + 2).unwrap();
        let restored = EgressReachabilityEvidenceStore::restore(&checkpoint, NOW + 3).unwrap();
        assert_eq!(restored.checkpoint(NOW + 2).unwrap(), checkpoint);

        let mut mutation = checkpoint;
        mutation.current_observations[0].observation.routes[0].address =
            "198.51.100.1".parse::<IpAddr>().unwrap();
        assert!(EgressReachabilityEvidenceStore::restore(&mutation, NOW + 3).is_err());
    }
}
