//! Durable ownership for authenticated internet-classifier publications.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use unf_common::Revision;

use crate::{
    EgressIntentOwner, EgressInternetClassification, EgressInternetCompilationReport,
    EgressInternetError, EgressInternetSnapshot, EgressModel, EgressProviderRef,
    MAX_EGRESS_INTENTS, materialize_egress_internet_model, verify_egress_internet_classification,
    verify_egress_internet_snapshot,
};

pub const EGRESS_INTERNET_STORE_SCHEMA_VERSION: u16 = 1;
pub const MAX_EGRESS_INTERNET_CLASSIFIERS: usize = 64;
pub const MAX_EGRESS_INTERNET_SOURCE_KEY_BYTES: usize = 512;
pub const MAX_EGRESS_INTERNET_STORE_FUTURE_SKEW_SECONDS: u64 = 30;

const STORE_DIGEST_DOMAIN: &[u8] = b"unf.egress.internet.classifier-store.v1\0";

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EgressInternetCurrentRecord {
    pub source_key: String,
    pub classification: EgressInternetClassification,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EgressInternetStoreDigest(pub [u8; 32]);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EgressInternetStoreCheckpoint {
    pub schema_version: u16,
    pub revision: Revision,
    pub persisted_at_unix_seconds: u64,
    pub current: Vec<EgressInternetCurrentRecord>,
    pub latest: Vec<EgressInternetClassification>,
    pub snapshots: Vec<EgressInternetSnapshot>,
    pub digest: EgressInternetStoreDigest,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum EgressInternetStoreError {
    #[error("unsupported internet-classifier store schema")]
    UnsupportedSchema,
    #[error("invalid internet-classifier source key")]
    InvalidSourceKey,
    #[error("internet-classifier capacity is exhausted")]
    CapacityExceeded,
    #[error("more than one source claims the same classifier")]
    DuplicateClassifier,
    #[error("internet-classifier position regressed")]
    Regression,
    #[error("internet-classifier content changed at the same position")]
    SamePositionMutation,
    #[error("internet-classifier store checkpoint is noncanonical")]
    NoncanonicalCheckpoint,
    #[error("internet-classifier store revision is exhausted")]
    RevisionExhausted,
    #[error("internet-classifier store encoding failed: {0}")]
    Encoding(String),
    #[error(transparent)]
    Classification(#[from] EgressInternetError),
}

/// Current publications, retained replay positions, and the exact most recent
/// per-intent materialization. Removing a current source never erases the
/// evidence required to enforce replay ordering or bounded LKG behavior.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EgressInternetClassificationStore {
    revision: Revision,
    current: BTreeMap<String, EgressInternetClassification>,
    latest: BTreeMap<EgressProviderRef, EgressInternetClassification>,
    snapshots: BTreeMap<EgressIntentOwner, EgressInternetSnapshot>,
}

impl Default for EgressInternetClassificationStore {
    fn default() -> Self {
        Self {
            revision: Revision::INITIAL,
            current: BTreeMap::new(),
            latest: BTreeMap::new(),
            snapshots: BTreeMap::new(),
        }
    }
}

impl EgressInternetClassificationStore {
    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    #[must_use]
    pub fn current_classifications(
        &self,
    ) -> BTreeMap<EgressProviderRef, EgressInternetClassification> {
        self.current
            .values()
            .cloned()
            .map(|classification| (classification.source.clone(), classification))
            .collect()
    }

    /// Applies one authenticated Kubernetes object publication atomically.
    ///
    /// # Errors
    ///
    /// Rejects malformed evidence, ambiguous ownership, replay, mutation,
    /// capacity, source-key, or store-revision violations.
    pub fn apply(
        &mut self,
        source_key: String,
        classification: EgressInternetClassification,
    ) -> Result<bool, EgressInternetStoreError> {
        validate_source_key(&source_key)?;
        let classification = verify_egress_internet_classification(classification)?;
        if self.current.get(&source_key) == Some(&classification) {
            return Ok(false);
        }
        if self
            .current
            .iter()
            .any(|(key, candidate)| key != &source_key && candidate.source == classification.source)
        {
            return Err(EgressInternetStoreError::DuplicateClassifier);
        }
        verify_position(self.latest.get(&classification.source), &classification)?;
        if !self.current.contains_key(&source_key)
            && self.current.len() >= MAX_EGRESS_INTERNET_CLASSIFIERS
        {
            return Err(EgressInternetStoreError::CapacityExceeded);
        }
        self.revision = checked_next(self.revision)?;
        self.current.insert(source_key, classification.clone());
        self.latest
            .insert(classification.source.clone(), classification);
        Ok(true)
    }

    /// Withdraws current authority while preserving its replay/LKG evidence.
    ///
    /// # Errors
    ///
    /// Rejects invalid source keys or revision exhaustion.
    pub fn remove(&mut self, source_key: &str) -> Result<bool, EgressInternetStoreError> {
        validate_source_key(source_key)?;
        if self.current.remove(source_key).is_none() {
            return Ok(false);
        }
        self.revision = checked_next(self.revision)?;
        Ok(true)
    }

    /// Atomically replaces the complete watched publication set after a relist.
    ///
    /// # Errors
    ///
    /// Rejects malformed, duplicate, regressed, mutated, or oversized state.
    pub fn replace_current(
        &mut self,
        replacement: BTreeMap<String, EgressInternetClassification>,
    ) -> Result<bool, EgressInternetStoreError> {
        if replacement.len() > MAX_EGRESS_INTERNET_CLASSIFIERS {
            return Err(EgressInternetStoreError::CapacityExceeded);
        }
        let mut providers = BTreeSet::new();
        let mut verified = BTreeMap::new();
        for (source_key, classification) in replacement {
            validate_source_key(&source_key)?;
            let classification = verify_egress_internet_classification(classification)?;
            if !providers.insert(classification.source.clone()) {
                return Err(EgressInternetStoreError::DuplicateClassifier);
            }
            verify_position(self.latest.get(&classification.source), &classification)?;
            verified.insert(source_key, classification);
        }
        if verified == self.current {
            return Ok(false);
        }
        let revision = checked_next(self.revision)?;
        let mut latest = self.latest.clone();
        for classification in verified.values() {
            latest.insert(classification.source.clone(), classification.clone());
        }
        self.current = verified;
        self.latest = latest;
        self.revision = revision;
        Ok(true)
    }

    /// Materializes current, retained, or deny-closed authority and retains the
    /// exact resulting snapshots for restart-safe fallback.
    ///
    /// # Errors
    ///
    /// Rejects invalid model, classification, snapshot, or replay state.
    pub fn materialize(
        &mut self,
        model: EgressModel,
        policy_revision: Revision,
        now_unix_seconds: u64,
    ) -> Result<
        (
            EgressModel,
            BTreeMap<EgressIntentOwner, EgressInternetCompilationReport>,
            bool,
        ),
        EgressInternetStoreError,
    > {
        let (model, reports) = materialize_egress_internet_model(
            model,
            &self.current_classifications(),
            &self.snapshots,
            policy_revision,
            now_unix_seconds,
        )?;
        let snapshots = model
            .intents
            .iter()
            .filter_map(|intent| match &intent.destinations {
                crate::EgressDestinations::Internet(snapshot) => {
                    Some((intent.owner.clone(), snapshot.as_ref().clone()))
                }
                _ => None,
            })
            .collect::<BTreeMap<_, _>>();
        let changed = snapshots != self.snapshots;
        if changed {
            self.revision = checked_next(self.revision)?;
            self.snapshots = snapshots;
        }
        Ok((model, reports, changed))
    }

    /// Produces a canonical domain-separated durable checkpoint.
    ///
    /// # Errors
    ///
    /// Returns an encoding error if canonical serialization fails.
    pub fn checkpoint(
        &self,
        persisted_at_unix_seconds: u64,
    ) -> Result<EgressInternetStoreCheckpoint, EgressInternetStoreError> {
        let mut checkpoint = EgressInternetStoreCheckpoint {
            schema_version: EGRESS_INTERNET_STORE_SCHEMA_VERSION,
            revision: self.revision,
            persisted_at_unix_seconds,
            current: self
                .current
                .iter()
                .map(|(source_key, classification)| EgressInternetCurrentRecord {
                    source_key: source_key.clone(),
                    classification: classification.clone(),
                })
                .collect(),
            latest: self.latest.values().cloned().collect(),
            snapshots: self.snapshots.values().cloned().collect(),
            digest: EgressInternetStoreDigest([0; 32]),
        };
        checkpoint.digest = checkpoint_digest(&checkpoint)?;
        Ok(checkpoint)
    }

    /// Restores a checkpoint only after complete canonical replay.
    ///
    /// # Errors
    ///
    /// Rejects version, clock, ordering, duplication, bounds, evidence, or
    /// digest drift without partial adoption.
    pub fn restore(
        checkpoint: &EgressInternetStoreCheckpoint,
        now_unix_seconds: u64,
    ) -> Result<Self, EgressInternetStoreError> {
        if checkpoint.schema_version != EGRESS_INTERNET_STORE_SCHEMA_VERSION {
            return Err(EgressInternetStoreError::UnsupportedSchema);
        }
        if checkpoint.persisted_at_unix_seconds
            > now_unix_seconds.saturating_add(MAX_EGRESS_INTERNET_STORE_FUTURE_SKEW_SECONDS)
            || checkpoint.current.len() > MAX_EGRESS_INTERNET_CLASSIFIERS
            || checkpoint.latest.len() > MAX_EGRESS_INTERNET_CLASSIFIERS
            || checkpoint.snapshots.len() > MAX_EGRESS_INTENTS
            || checkpoint_digest(checkpoint)? != checkpoint.digest
        {
            return Err(EgressInternetStoreError::NoncanonicalCheckpoint);
        }
        let mut store = Self {
            revision: checkpoint.revision,
            ..Self::default()
        };
        for classification in &checkpoint.latest {
            let classification = verify_egress_internet_classification(classification.clone())?;
            if store
                .latest
                .insert(classification.source.clone(), classification)
                .is_some()
            {
                return Err(EgressInternetStoreError::NoncanonicalCheckpoint);
            }
        }
        for record in &checkpoint.current {
            validate_source_key(&record.source_key)?;
            let classification =
                verify_egress_internet_classification(record.classification.clone())?;
            if store
                .current
                .insert(record.source_key.clone(), classification.clone())
                .is_some()
                || store
                    .latest
                    .get(&classification.source)
                    .is_none_or(|latest| latest != &classification)
                || store
                    .current
                    .values()
                    .filter(|candidate| candidate.source == classification.source)
                    .count()
                    != 1
            {
                return Err(EgressInternetStoreError::NoncanonicalCheckpoint);
            }
        }
        for snapshot in &checkpoint.snapshots {
            let snapshot = verify_egress_internet_snapshot(snapshot.clone())?;
            if store
                .snapshots
                .insert(
                    snapshot.snapshot().policy.owner.clone(),
                    snapshot.snapshot().clone(),
                )
                .is_some()
            {
                return Err(EgressInternetStoreError::NoncanonicalCheckpoint);
            }
        }
        if store.checkpoint(checkpoint.persisted_at_unix_seconds)? != *checkpoint
            || (store.revision == Revision::INITIAL
                && (!store.current.is_empty()
                    || !store.latest.is_empty()
                    || !store.snapshots.is_empty()))
        {
            return Err(EgressInternetStoreError::NoncanonicalCheckpoint);
        }
        Ok(store)
    }
}

fn verify_position(
    previous: Option<&EgressInternetClassification>,
    current: &EgressInternetClassification,
) -> Result<(), EgressInternetStoreError> {
    let Some(previous) = previous else {
        return Ok(());
    };
    let old = (previous.source_epoch, previous.revision);
    let new = (current.source_epoch, current.revision);
    if new < old {
        return Err(EgressInternetStoreError::Regression);
    }
    if new == old && current.digest != previous.digest {
        return Err(EgressInternetStoreError::SamePositionMutation);
    }
    Ok(())
}

fn validate_source_key(source_key: &str) -> Result<(), EgressInternetStoreError> {
    if source_key.is_empty()
        || source_key.len() > MAX_EGRESS_INTERNET_SOURCE_KEY_BYTES
        || source_key.chars().any(char::is_control)
    {
        return Err(EgressInternetStoreError::InvalidSourceKey);
    }
    Ok(())
}

fn checked_next(revision: Revision) -> Result<Revision, EgressInternetStoreError> {
    revision
        .get()
        .checked_add(1)
        .map(Revision::new)
        .ok_or(EgressInternetStoreError::RevisionExhausted)
}

fn checkpoint_digest(
    checkpoint: &EgressInternetStoreCheckpoint,
) -> Result<EgressInternetStoreDigest, EgressInternetStoreError> {
    let material = (
        checkpoint.schema_version,
        checkpoint.revision,
        checkpoint.persisted_at_unix_seconds,
        &checkpoint.current,
        &checkpoint.latest,
        &checkpoint.snapshots,
    );
    let encoded = serde_json::to_vec(&material)
        .map_err(|error| EgressInternetStoreError::Encoding(error.to_string()))?;
    let mut digest = Sha256::new();
    digest.update(STORE_DIGEST_DOMAIN);
    digest.update(encoded);
    Ok(EgressInternetStoreDigest(digest.finalize().into()))
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::*;
    use crate::{
        EGRESS_INTERNET_CLASSIFICATION_ALGORITHM_AUTHORITY_CARVING_V1,
        EGRESS_INTERNET_CLASSIFICATION_SCHEMA_VERSION, EgressAddressRequest, EgressDestinations,
        EgressIntent, EgressIntentScope, EgressInternetAuthority, EgressInternetClass,
        EgressInternetClassificationDigest, EgressInternetClassificationRule,
        EgressInternetDestinationSpec, EgressInternetFallback, EgressSourceSelector, IpPrefix,
        seal_egress_internet_classification,
    };

    const NOW: u64 = 10_000;

    fn provider() -> EgressProviderRef {
        EgressProviderRef {
            name: "route-authority".to_owned(),
            instance: "global-v1".to_owned(),
        }
    }

    fn classification(revision: u64, valid_until: u64) -> EgressInternetClassification {
        seal_egress_internet_classification(EgressInternetClassification {
            schema_version: EGRESS_INTERNET_CLASSIFICATION_SCHEMA_VERSION,
            algorithm: EGRESS_INTERNET_CLASSIFICATION_ALGORITHM_AUTHORITY_CARVING_V1,
            revision: Revision::new(revision),
            source: provider(),
            source_epoch: 7,
            observed_at_unix_seconds: NOW,
            valid_until_unix_seconds: valid_until,
            rules: vec![EgressInternetClassificationRule {
                prefix: IpPrefix {
                    address: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                    prefix_len: 0,
                },
                class: EgressInternetClass::Internet,
                provenance: format!("fixture:{revision}"),
            }],
            digest: EgressInternetClassificationDigest([0; 32]),
        })
        .unwrap()
    }

    fn owner() -> EgressIntentOwner {
        EgressIntentOwner {
            scope: EgressIntentScope::Cluster,
            name: "public-access".to_owned(),
            uid: "public-access-uid".to_owned(),
        }
    }

    fn model() -> EgressModel {
        crate::normalize_model(
            Vec::new(),
            vec![EgressIntent {
                owner: owner(),
                priority: crate::DEFAULT_EGRESS_INTENT_PRIORITY,
                source: EgressSourceSelector::default(),
                destinations: EgressDestinations::DenyAll,
                fqdn: None,
                internet: Some(EgressInternetDestinationSpec {
                    classifier: provider(),
                    exceptions: Vec::new(),
                    fallback: EgressInternetFallback::LastKnownGood {
                        max_staleness_seconds: 60,
                    },
                }),
                addresses: EgressAddressRequest::Explicit {
                    addresses: vec!["192.0.2.10".parse().unwrap()],
                },
            }],
        )
        .unwrap()
    }

    #[test]
    fn publication_loss_restart_and_bounded_fallback_are_exact() {
        let mut store = EgressInternetClassificationStore::default();
        assert!(
            store
                .apply(
                    "native:classifier/global".to_owned(),
                    classification(3, NOW + 30)
                )
                .unwrap()
        );
        let (materialized, _, changed) = store
            .materialize(model(), Revision::new(5), NOW + 1)
            .unwrap();
        assert!(changed);
        assert!(matches!(
            materialized.intents[0].destinations,
            EgressDestinations::Internet(_)
        ));
        assert!(store.remove("native:classifier/global").unwrap());
        let (fallback, _, _) = store
            .materialize(model(), Revision::new(5), NOW + 40)
            .unwrap();
        let EgressDestinations::Internet(snapshot) = &fallback.intents[0].destinations else {
            panic!("internet authority must be materialized");
        };
        assert!(matches!(
            snapshot.authority,
            EgressInternetAuthority::LastKnownGood { .. }
        ));

        let checkpoint = store.checkpoint(NOW + 40).unwrap();
        let mut restored =
            EgressInternetClassificationStore::restore(&checkpoint, NOW + 41).unwrap();
        let (denied, _, _) = restored
            .materialize(model(), Revision::new(5), NOW + 90)
            .unwrap();
        let EgressDestinations::Internet(snapshot) = &denied.intents[0].destinations else {
            panic!("internet authority must be materialized");
        };
        assert_eq!(snapshot.authority, EgressInternetAuthority::DenyClosed);
    }

    #[test]
    fn relist_and_replay_never_erase_latest_position() {
        let mut store = EgressInternetClassificationStore::default();
        let current = classification(4, NOW + 30);
        store
            .apply("native:classifier/global".to_owned(), current.clone())
            .unwrap();
        store.remove("native:classifier/global").unwrap();
        assert_eq!(
            store
                .apply(
                    "native:classifier/global".to_owned(),
                    classification(3, NOW + 30)
                )
                .unwrap_err(),
            EgressInternetStoreError::Regression
        );
        let mut mutation = current;
        mutation.rules[0].provenance = "mutated".to_owned();
        mutation = seal_egress_internet_classification(mutation).unwrap();
        assert_eq!(
            store
                .apply("native:classifier/global".to_owned(), mutation)
                .unwrap_err(),
            EgressInternetStoreError::SamePositionMutation
        );
        assert!(!store.replace_current(BTreeMap::new()).unwrap());
    }

    #[test]
    fn checkpoint_rejects_mutation_and_duplicate_classifier_ownership() {
        let mut store = EgressInternetClassificationStore::default();
        store
            .apply(
                "native:classifier/a".to_owned(),
                classification(1, NOW + 30),
            )
            .unwrap();
        assert_eq!(
            store
                .apply(
                    "native:classifier/b".to_owned(),
                    classification(2, NOW + 30)
                )
                .unwrap_err(),
            EgressInternetStoreError::DuplicateClassifier
        );
        let mut checkpoint = store.checkpoint(NOW + 1).unwrap();
        checkpoint.latest[0].rules[0].provenance = "forged".to_owned();
        assert!(EgressInternetClassificationStore::restore(&checkpoint, NOW + 2).is_err());
    }
}
