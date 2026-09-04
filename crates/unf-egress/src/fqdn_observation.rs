//! Authenticated, monotonic, restart-safe DNS observation ownership.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use unf_common::Revision;

use crate::{
    AuthenticatedEgressAgent, EGRESS_AGENT_SERVICE_ACCOUNT, EGRESS_AGENT_TOKEN_AUDIENCE,
    EgressDnsObservation, MAX_EGRESS_FQDN_FUTURE_SKEW_SECONDS, MAX_EGRESS_FQDN_OBSERVATIONS,
    MAX_EGRESS_FQDN_TTL_SECONDS, normalize_observation,
};

pub const EGRESS_FQDN_OBSERVATION_BATCH_SCHEMA_VERSION: u16 = 1;
pub const EGRESS_FQDN_OBSERVATION_CHECKPOINT_SCHEMA_VERSION: u16 = 1;
pub const MAX_EGRESS_FQDN_OBSERVATION_BATCHES: usize = 256;

const OBSERVATION_DIGEST_DOMAIN: &[u8] = b"unf.egress.fqdn.observation-ledger.v1\0";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EgressFqdnObservationBatch {
    pub schema_version: u16,
    pub observer_node_uid: String,
    pub source_epoch: u64,
    pub batch_revision: Revision,
    pub view: String,
    pub collected_at_unix_seconds: u64,
    /// A complete replacement for this observer/view. An empty batch is an
    /// authoritative empty result; no received batch is observation loss.
    pub observations: Vec<EgressDnsObservation>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EgressFqdnObservationDigest(pub [u8; 32]);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EgressFqdnObservationCheckpoint {
    pub schema_version: u16,
    pub revision: Revision,
    pub persisted_at_unix_seconds: u64,
    pub batches: Vec<EgressFqdnObservationBatch>,
    pub digest: EgressFqdnObservationDigest,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum EgressFqdnObservationError {
    #[error("FQDN observation principal is not a current UNF agent")]
    InvalidPrincipal,
    #[error("FQDN observation batch is not owned by the authenticated Node")]
    ForeignBatch,
    #[error("invalid FQDN observation batch: {0}")]
    InvalidBatch(&'static str),
    #[error("FQDN observation epoch or revision regressed")]
    Regression,
    #[error("FQDN observation replay mutated at the same epoch and revision")]
    SameRevisionMutation,
    #[error("FQDN observation ledger capacity is exhausted")]
    CapacityExceeded,
    #[error("unsupported FQDN observation checkpoint schema")]
    UnsupportedCheckpoint,
    #[error("FQDN observation checkpoint is noncanonical")]
    NoncanonicalCheckpoint,
    #[error("FQDN observation ledger revision is exhausted")]
    RevisionExhausted,
    #[error("FQDN observation digest encoding failed: {0}")]
    Encoding(String),
}

/// Complete last-known observation state, keyed by authenticated Node UID and
/// explicit resolver view. Only a received complete batch replaces state;
/// silence never manufactures an empty answer or renews prior TTLs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EgressFqdnObservationLedger {
    revision: Revision,
    batches: BTreeMap<(String, String), EgressFqdnObservationBatch>,
}

impl Default for EgressFqdnObservationLedger {
    fn default() -> Self {
        Self {
            revision: Revision::INITIAL,
            batches: BTreeMap::new(),
        }
    }
}

impl EgressFqdnObservationLedger {
    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    #[must_use]
    pub fn observations_for_view(&self, view: &str) -> Vec<EgressDnsObservation> {
        self.batches
            .iter()
            .filter(|((_, candidate_view), _)| candidate_view == view)
            .flat_map(|(_, batch)| batch.observations.iter().cloned())
            .collect()
    }

    /// Atomically adopts one complete authenticated observer/view batch.
    ///
    /// # Errors
    ///
    /// Rejects foreign principals, malformed/noncanonical state, replay,
    /// regression, mutation, capacity, or revision exhaustion.
    pub fn apply(
        &mut self,
        principal: &AuthenticatedEgressAgent,
        batch: EgressFqdnObservationBatch,
        now_unix_seconds: u64,
    ) -> Result<bool, EgressFqdnObservationError> {
        validate_principal(principal)?;
        if batch.observer_node_uid != principal.node_uid {
            return Err(EgressFqdnObservationError::ForeignBatch);
        }
        let batch = normalize_batch(batch, now_unix_seconds)?;
        let key = (batch.observer_node_uid.clone(), batch.view.clone());
        if let Some(previous) = self.batches.get(&key) {
            let old_position = (previous.source_epoch, previous.batch_revision);
            let new_position = (batch.source_epoch, batch.batch_revision);
            if new_position < old_position {
                return Err(EgressFqdnObservationError::Regression);
            }
            if new_position == old_position {
                return if previous == &batch {
                    Ok(false)
                } else {
                    Err(EgressFqdnObservationError::SameRevisionMutation)
                };
            }
        } else if self.batches.len() >= MAX_EGRESS_FQDN_OBSERVATION_BATCHES {
            return Err(EgressFqdnObservationError::CapacityExceeded);
        }
        let previous_len = self
            .batches
            .get(&key)
            .map_or(0, |previous| previous.observations.len());
        let total_observations = self
            .batches
            .values()
            .map(|candidate| candidate.observations.len())
            .sum::<usize>()
            .saturating_sub(previous_len)
            .saturating_add(batch.observations.len());
        if total_observations > MAX_EGRESS_FQDN_OBSERVATIONS {
            return Err(EgressFqdnObservationError::CapacityExceeded);
        }
        self.revision = checked_next(self.revision)?;
        self.batches.insert(key, batch);
        Ok(true)
    }

    /// Produces a canonical, domain-separated durable checkpoint.
    ///
    /// # Errors
    ///
    /// Returns an encoding error only if canonical serialization fails.
    pub fn checkpoint(
        &self,
        persisted_at_unix_seconds: u64,
    ) -> Result<EgressFqdnObservationCheckpoint, EgressFqdnObservationError> {
        let mut checkpoint = EgressFqdnObservationCheckpoint {
            schema_version: EGRESS_FQDN_OBSERVATION_CHECKPOINT_SCHEMA_VERSION,
            revision: self.revision,
            persisted_at_unix_seconds,
            batches: self.batches.values().cloned().collect(),
            digest: EgressFqdnObservationDigest([0; 32]),
        };
        checkpoint.digest = checkpoint_digest(&checkpoint)?;
        Ok(checkpoint)
    }

    /// Restores a complete checkpoint only after canonical replay.
    ///
    /// # Errors
    ///
    /// Rejects schema, clock, ordering, duplicate keys, batch, revision, or
    /// digest drift without partially adopting state.
    pub fn restore(
        checkpoint: EgressFqdnObservationCheckpoint,
        now_unix_seconds: u64,
    ) -> Result<Self, EgressFqdnObservationError> {
        if checkpoint.schema_version != EGRESS_FQDN_OBSERVATION_CHECKPOINT_SCHEMA_VERSION {
            return Err(EgressFqdnObservationError::UnsupportedCheckpoint);
        }
        if checkpoint.persisted_at_unix_seconds
            > now_unix_seconds.saturating_add(MAX_EGRESS_FQDN_FUTURE_SKEW_SECONDS)
            || checkpoint.batches.len() > MAX_EGRESS_FQDN_OBSERVATION_BATCHES
            || (checkpoint.revision == Revision::INITIAL && !checkpoint.batches.is_empty())
            || checkpoint_digest(&checkpoint)? != checkpoint.digest
        {
            return Err(EgressFqdnObservationError::NoncanonicalCheckpoint);
        }
        let mut batches = BTreeMap::new();
        let mut total_observations = 0usize;
        let original_batches = checkpoint.batches;
        for raw in &original_batches {
            let batch = normalize_batch(raw.clone(), checkpoint.persisted_at_unix_seconds)?;
            if &batch != raw {
                return Err(EgressFqdnObservationError::NoncanonicalCheckpoint);
            }
            total_observations = total_observations
                .checked_add(batch.observations.len())
                .ok_or(EgressFqdnObservationError::CapacityExceeded)?;
            let key = (batch.observer_node_uid.clone(), batch.view.clone());
            if batches.insert(key, batch).is_some() {
                return Err(EgressFqdnObservationError::NoncanonicalCheckpoint);
            }
        }
        if total_observations > MAX_EGRESS_FQDN_OBSERVATIONS
            || batches.values().cloned().collect::<Vec<_>>() != original_batches
        {
            return Err(EgressFqdnObservationError::NoncanonicalCheckpoint);
        }
        Ok(Self {
            revision: checkpoint.revision,
            batches,
        })
    }
}

fn normalize_batch(
    mut batch: EgressFqdnObservationBatch,
    now_unix_seconds: u64,
) -> Result<EgressFqdnObservationBatch, EgressFqdnObservationError> {
    if batch.schema_version != EGRESS_FQDN_OBSERVATION_BATCH_SCHEMA_VERSION
        || batch.observer_node_uid.is_empty()
        || batch.observer_node_uid.len() > 253
        || batch.source_epoch == 0
        || batch.batch_revision == Revision::INITIAL
        || batch.view.is_empty()
        || batch.view.len() > 253
        || batch.observations.len() > MAX_EGRESS_FQDN_OBSERVATIONS
        || batch.collected_at_unix_seconds
            > now_unix_seconds.saturating_add(MAX_EGRESS_FQDN_FUTURE_SKEW_SECONDS)
    {
        return Err(EgressFqdnObservationError::InvalidBatch(
            "schema, identity, position, view, size, or collection time is invalid",
        ));
    }
    let mut names = BTreeSet::new();
    let mut normalized = Vec::with_capacity(batch.observations.len());
    for observation in batch.observations {
        if observation.source.observer_uid != batch.observer_node_uid
            || observation.source.source_epoch != batch.source_epoch
            || observation.source.view != batch.view
            || observation.observation_revision != batch.batch_revision
            || observation.observed_at_unix_seconds > batch.collected_at_unix_seconds
        {
            return Err(EgressFqdnObservationError::InvalidBatch(
                "observation is not bound to its complete batch",
            ));
        }
        let observation =
            normalize_observation(observation, MAX_EGRESS_FQDN_TTL_SECONDS, now_unix_seconds)
                .map_err(|_| EgressFqdnObservationError::InvalidBatch("observation is invalid"))?;
        if !names.insert(observation.query_name.clone()) {
            return Err(EgressFqdnObservationError::InvalidBatch(
                "query names must be unique",
            ));
        }
        normalized.push(observation);
    }
    normalized.sort_by(|left, right| left.query_name.cmp(&right.query_name));
    batch.observations = normalized;
    Ok(batch)
}

fn validate_principal(
    principal: &AuthenticatedEgressAgent,
) -> Result<(), EgressFqdnObservationError> {
    if principal.namespace != "unf-system"
        || principal.service_account != EGRESS_AGENT_SERVICE_ACCOUNT
        || principal.audience != EGRESS_AGENT_TOKEN_AUDIENCE
        || principal.pod_name.is_empty()
        || principal.pod_uid.is_empty()
        || principal.node_name.is_empty()
        || principal.node_uid.is_empty()
    {
        return Err(EgressFqdnObservationError::InvalidPrincipal);
    }
    Ok(())
}

fn checked_next(revision: Revision) -> Result<Revision, EgressFqdnObservationError> {
    revision
        .get()
        .checked_add(1)
        .map(Revision::new)
        .ok_or(EgressFqdnObservationError::RevisionExhausted)
}

fn checkpoint_digest(
    checkpoint: &EgressFqdnObservationCheckpoint,
) -> Result<EgressFqdnObservationDigest, EgressFqdnObservationError> {
    let material = (
        checkpoint.schema_version,
        checkpoint.revision,
        checkpoint.persisted_at_unix_seconds,
        &checkpoint.batches,
    );
    let encoded = serde_json::to_vec(&material)
        .map_err(|error| EgressFqdnObservationError::Encoding(error.to_string()))?;
    let mut hasher = Sha256::new();
    hasher.update(OBSERVATION_DIGEST_DOMAIN);
    hasher.update(encoded);
    Ok(EgressFqdnObservationDigest(hasher.finalize().into()))
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::*;
    use crate::{EgressDnsAnswer, EgressDnsObservationSource};

    const NOW: u64 = 2_000_000;

    fn principal(node: &str) -> AuthenticatedEgressAgent {
        AuthenticatedEgressAgent {
            namespace: "unf-system".to_owned(),
            service_account: EGRESS_AGENT_SERVICE_ACCOUNT.to_owned(),
            pod_name: format!("unf-agent-{node}"),
            pod_uid: format!("pod-{node}"),
            node_name: node.to_owned(),
            node_uid: format!("uid-{node}"),
            audience: EGRESS_AGENT_TOKEN_AUDIENCE.to_owned(),
        }
    }

    fn batch(
        principal: &AuthenticatedEgressAgent,
        epoch: u64,
        revision: u64,
        names: &[&str],
    ) -> EgressFqdnObservationBatch {
        EgressFqdnObservationBatch {
            schema_version: EGRESS_FQDN_OBSERVATION_BATCH_SCHEMA_VERSION,
            observer_node_uid: principal.node_uid.clone(),
            source_epoch: epoch,
            batch_revision: Revision(revision),
            view: "cluster-default".to_owned(),
            collected_at_unix_seconds: NOW,
            observations: names
                .iter()
                .map(|name| EgressDnsObservation {
                    source: EgressDnsObservationSource {
                        observer_uid: principal.node_uid.clone(),
                        resolver: IpAddr::V4(Ipv4Addr::new(10, 96, 0, 10)),
                        view: "cluster-default".to_owned(),
                        source_epoch: epoch,
                    },
                    observation_revision: Revision(revision),
                    query_name: (*name).to_owned(),
                    canonical_chain: vec![(*name).to_owned()],
                    answers: vec![EgressDnsAnswer {
                        address: IpAddr::V4(Ipv4Addr::new(
                            203,
                            0,
                            113,
                            u8::try_from(revision).unwrap(),
                        )),
                        ttl_seconds: 60,
                    }],
                    observed_at_unix_seconds: NOW,
                })
                .collect(),
        }
    }

    #[test]
    fn authenticated_batches_are_monotonic_idempotent_and_node_bound() {
        let agent = principal("worker-a");
        let mut ledger = EgressFqdnObservationLedger::default();
        let first = batch(&agent, 1, 1, &["B.example", "a.example"]);
        assert!(ledger.apply(&agent, first.clone(), NOW).unwrap());
        assert!(!ledger.apply(&agent, first.clone(), NOW).unwrap());
        let mut mutation = first.clone();
        mutation.collected_at_unix_seconds += 1;
        assert_eq!(
            ledger.apply(&agent, mutation, NOW + 1),
            Err(EgressFqdnObservationError::SameRevisionMutation)
        );
        assert_eq!(
            ledger.apply(&principal("worker-b"), first, NOW),
            Err(EgressFqdnObservationError::ForeignBatch)
        );
        assert_eq!(ledger.observations_for_view("cluster-default").len(), 2);
        assert_eq!(
            ledger.observations_for_view("cluster-default")[0].query_name,
            "a.example"
        );
    }

    #[test]
    fn authoritative_empty_replaces_answers_but_missing_batch_does_not() {
        let agent = principal("worker-a");
        let mut ledger = EgressFqdnObservationLedger::default();
        ledger
            .apply(&agent, batch(&agent, 4, 8, &["api.example"]), NOW)
            .unwrap();
        assert_eq!(ledger.observations_for_view("cluster-default").len(), 1);

        let empty = batch(&agent, 4, 9, &[]);
        ledger.apply(&agent, empty, NOW).unwrap();
        assert!(ledger.observations_for_view("cluster-default").is_empty());
        assert_eq!(ledger.revision(), Revision(2));
    }

    #[test]
    fn epoch_revision_regression_and_noncanonical_batches_fail_closed() {
        let agent = principal("worker-a");
        let mut ledger = EgressFqdnObservationLedger::default();
        ledger
            .apply(&agent, batch(&agent, 3, 8, &["api.example"]), NOW)
            .unwrap();
        assert_eq!(
            ledger.apply(&agent, batch(&agent, 3, 7, &[]), NOW),
            Err(EgressFqdnObservationError::Regression)
        );
        assert_eq!(
            ledger.apply(&agent, batch(&agent, 2, 99, &[]), NOW),
            Err(EgressFqdnObservationError::Regression)
        );
        let duplicate = batch(&agent, 4, 1, &["same.example", "same.example"]);
        assert!(matches!(
            ledger.apply(&agent, duplicate, NOW),
            Err(EgressFqdnObservationError::InvalidBatch(_))
        ));
    }

    #[test]
    fn checkpoint_round_trip_and_inner_mutation_are_replay_checked() {
        let agent = principal("worker-a");
        let mut ledger = EgressFqdnObservationLedger::default();
        ledger
            .apply(&agent, batch(&agent, 1, 1, &["api.example"]), NOW)
            .unwrap();
        let checkpoint = ledger.checkpoint(NOW).unwrap();
        assert_eq!(
            EgressFqdnObservationLedger::restore(checkpoint.clone(), NOW).unwrap(),
            ledger
        );
        let mut mutation = checkpoint;
        mutation.batches[0].source_epoch += 1;
        mutation.digest = checkpoint_digest(&mutation).unwrap();
        assert!(matches!(
            EgressFqdnObservationLedger::restore(mutation, NOW),
            Err(EgressFqdnObservationError::InvalidBatch(_)
                | EgressFqdnObservationError::NoncanonicalCheckpoint)
        ));
    }
}
