//! Canonical, revisioned desired-state ownership shared by native and
//! compatibility Kubernetes adapters.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use unf_common::Revision;

use crate::{
    EgressAddressPool, EgressIntent, EgressIntentOwner, EgressModel, EgressModelError,
    EgressProviderRef, MAX_EGRESS_INTENTS, MAX_EGRESS_POOLS, normalize_model,
};

pub const EGRESS_DESIRED_CHECKPOINT_SCHEMA_VERSION: u16 = 1;
pub const MAX_EGRESS_SOURCE_KEY_BYTES: usize = 512;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EgressDesiredPoolRecord {
    pub source_key: String,
    pub pool: EgressAddressPool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EgressDesiredIntentRecord {
    pub source_key: String,
    pub intent: EgressIntent,
    pub explicit_provider: Option<EgressProviderRef>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EgressDesiredCheckpoint {
    pub schema_version: u16,
    pub revision: Revision,
    pub pools: Vec<EgressDesiredPoolRecord>,
    pub intents: Vec<EgressDesiredIntentRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum EgressDesiredError {
    #[error("unsupported egress desired-state schema {actual}; expected {expected}")]
    UnsupportedSchema { actual: u16, expected: u16 },
    #[error("invalid egress desired-state source key")]
    InvalidSourceKey,
    #[error("egress desired-state checkpoint is noncanonical")]
    NoncanonicalCheckpoint,
    #[error("egress desired-state revision is exhausted")]
    RevisionExhausted,
    #[error(transparent)]
    InvalidModel(#[from] EgressModelError),
}

/// Complete last-known-good desired model. Updates are compiled on a clone and
/// become visible only when the entire cross-resource model normalizes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EgressDesiredStore {
    revision: Revision,
    pools: BTreeMap<String, EgressAddressPool>,
    intents: BTreeMap<String, (EgressIntent, Option<EgressProviderRef>)>,
    model: EgressModel,
}

impl Default for EgressDesiredStore {
    fn default() -> Self {
        Self {
            revision: Revision::INITIAL,
            pools: BTreeMap::new(),
            intents: BTreeMap::new(),
            model: EgressModel {
                pools: Vec::new(),
                intents: Vec::new(),
            },
        }
    }
}

impl EgressDesiredStore {
    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    #[must_use]
    pub const fn model(&self) -> &EgressModel {
        &self.model
    }

    #[must_use]
    pub fn explicit_provider(&self, owner: &EgressIntentOwner) -> Option<&EgressProviderRef> {
        self.intents
            .values()
            .find(|(intent, _)| &intent.owner == owner)
            .and_then(|(_, provider)| provider.as_ref())
    }

    /// Restores one complete exact checkpoint without partial adoption.
    ///
    /// # Errors
    ///
    /// Rejects versions, bounds, keys, ordering, duplicate/model drift, or an
    /// impossible revision tuple.
    pub fn restore(checkpoint: EgressDesiredCheckpoint) -> Result<Self, EgressDesiredError> {
        if checkpoint.schema_version != EGRESS_DESIRED_CHECKPOINT_SCHEMA_VERSION {
            return Err(EgressDesiredError::UnsupportedSchema {
                actual: checkpoint.schema_version,
                expected: EGRESS_DESIRED_CHECKPOINT_SCHEMA_VERSION,
            });
        }
        if checkpoint.pools.len() > MAX_EGRESS_POOLS
            || checkpoint.intents.len() > MAX_EGRESS_INTENTS
            || (!checkpoint.pools.is_empty() || !checkpoint.intents.is_empty())
                && checkpoint.revision == Revision::INITIAL
        {
            return Err(EgressDesiredError::NoncanonicalCheckpoint);
        }
        let mut pools = BTreeMap::new();
        let mut intents = BTreeMap::new();
        let mut previous: Option<String> = None;
        for record in checkpoint.pools {
            validate_source_key(&record.source_key)?;
            if previous
                .as_deref()
                .is_some_and(|key| key >= record.source_key.as_str())
                || pools
                    .insert(record.source_key.clone(), record.pool)
                    .is_some()
            {
                return Err(EgressDesiredError::NoncanonicalCheckpoint);
            }
            previous = Some(record.source_key);
        }
        previous = None;
        for record in checkpoint.intents {
            validate_source_key(&record.source_key)?;
            if previous
                .as_deref()
                .is_some_and(|key| key >= record.source_key.as_str())
                || intents
                    .insert(
                        record.source_key.clone(),
                        (record.intent, record.explicit_provider),
                    )
                    .is_some()
            {
                return Err(EgressDesiredError::NoncanonicalCheckpoint);
            }
            previous = Some(record.source_key);
        }
        let model = compile(&pools, &intents)?;
        Ok(Self {
            revision: checkpoint.revision,
            pools,
            intents,
            model,
        })
    }

    /// Applies one normalized pool source transactionally.
    ///
    /// # Errors
    ///
    /// Rejects invalid keys, a noncanonical complete model, or revision exhaustion.
    pub fn apply_pool(
        &mut self,
        source_key: String,
        pool: EgressAddressPool,
    ) -> Result<bool, EgressDesiredError> {
        validate_source_key(&source_key)?;
        if self.pools.get(&source_key) == Some(&pool) {
            return Ok(false);
        }
        let mut pools = self.pools.clone();
        pools.insert(source_key, pool);
        self.replace(pools, self.intents.clone())
    }

    /// Removes one pool only if the complete remaining model is valid.
    ///
    /// # Errors
    ///
    /// Rejects invalid keys, referenced-pool removal, or revision exhaustion.
    pub fn remove_pool(&mut self, source_key: &str) -> Result<bool, EgressDesiredError> {
        validate_source_key(source_key)?;
        if !self.pools.contains_key(source_key) {
            return Ok(false);
        }
        let mut pools = self.pools.clone();
        pools.remove(source_key);
        self.replace(pools, self.intents.clone())
    }

    /// Atomically replaces every pool owned by one adapter prefix. This is the
    /// relist boundary: stale entries disappear only if the complete resulting
    /// cross-resource model remains valid.
    ///
    /// # Errors
    ///
    /// Rejects foreign keys, a noncanonical complete model, or revision exhaustion.
    pub fn replace_pools(
        &mut self,
        source_prefix: &str,
        replacement: BTreeMap<String, EgressAddressPool>,
    ) -> Result<bool, EgressDesiredError> {
        validate_source_key(source_prefix)?;
        if replacement
            .keys()
            .any(|key| !key.starts_with(source_prefix) || validate_source_key(key).is_err())
        {
            return Err(EgressDesiredError::InvalidSourceKey);
        }
        let mut pools = self.pools.clone();
        pools.retain(|key, _| !key.starts_with(source_prefix));
        pools.extend(replacement);
        if pools == self.pools {
            return Ok(false);
        }
        self.replace(pools, self.intents.clone())
    }

    /// Applies one normalized intent plus explicit-address provider ownership.
    ///
    /// # Errors
    ///
    /// Rejects invalid keys, provider mismatch, model conflicts, or revision exhaustion.
    pub fn apply_intent(
        &mut self,
        source_key: String,
        intent: EgressIntent,
        explicit_provider: Option<EgressProviderRef>,
    ) -> Result<bool, EgressDesiredError> {
        validate_source_key(&source_key)?;
        let value = (intent, explicit_provider);
        if self.intents.get(&source_key) == Some(&value) {
            return Ok(false);
        }
        let mut intents = self.intents.clone();
        intents.insert(source_key, value);
        self.replace(self.pools.clone(), intents)
    }

    /// Removes one intent transactionally.
    ///
    /// # Errors
    ///
    /// Rejects invalid keys, an invalid resulting model, or revision exhaustion.
    pub fn remove_intent(&mut self, source_key: &str) -> Result<bool, EgressDesiredError> {
        validate_source_key(source_key)?;
        if !self.intents.contains_key(source_key) {
            return Ok(false);
        }
        let mut intents = self.intents.clone();
        intents.remove(source_key);
        self.replace(self.pools.clone(), intents)
    }

    /// Atomically replaces every intent owned by one adapter prefix.
    ///
    /// # Errors
    ///
    /// Rejects foreign keys, provider/model conflicts, or revision exhaustion.
    pub fn replace_intents(
        &mut self,
        source_prefix: &str,
        replacement: BTreeMap<String, (EgressIntent, Option<EgressProviderRef>)>,
    ) -> Result<bool, EgressDesiredError> {
        validate_source_key(source_prefix)?;
        if replacement
            .keys()
            .any(|key| !key.starts_with(source_prefix) || validate_source_key(key).is_err())
        {
            return Err(EgressDesiredError::InvalidSourceKey);
        }
        let mut intents = self.intents.clone();
        intents.retain(|key, _| !key.starts_with(source_prefix));
        intents.extend(replacement);
        if intents == self.intents {
            return Ok(false);
        }
        self.replace(self.pools.clone(), intents)
    }

    #[must_use]
    pub fn checkpoint(&self) -> EgressDesiredCheckpoint {
        EgressDesiredCheckpoint {
            schema_version: EGRESS_DESIRED_CHECKPOINT_SCHEMA_VERSION,
            revision: self.revision,
            pools: self
                .pools
                .iter()
                .map(|(source_key, pool)| EgressDesiredPoolRecord {
                    source_key: source_key.clone(),
                    pool: pool.clone(),
                })
                .collect(),
            intents: self
                .intents
                .iter()
                .map(
                    |(source_key, (intent, explicit_provider))| EgressDesiredIntentRecord {
                        source_key: source_key.clone(),
                        intent: intent.clone(),
                        explicit_provider: explicit_provider.clone(),
                    },
                )
                .collect(),
        }
    }

    fn replace(
        &mut self,
        pools: BTreeMap<String, EgressAddressPool>,
        intents: BTreeMap<String, (EgressIntent, Option<EgressProviderRef>)>,
    ) -> Result<bool, EgressDesiredError> {
        let model = compile(&pools, &intents)?;
        let revision = checked_next(self.revision)?;
        self.pools = pools;
        self.intents = intents;
        self.model = model;
        self.revision = revision;
        Ok(true)
    }
}

fn compile(
    pools: &BTreeMap<String, EgressAddressPool>,
    intents: &BTreeMap<String, (EgressIntent, Option<EgressProviderRef>)>,
) -> Result<EgressModel, EgressDesiredError> {
    if pools.len() > MAX_EGRESS_POOLS || intents.len() > MAX_EGRESS_INTENTS {
        return Err(EgressDesiredError::NoncanonicalCheckpoint);
    }
    for (intent, provider) in intents.values() {
        let explicit = matches!(
            intent.addresses,
            crate::EgressAddressRequest::Explicit { .. }
        );
        if explicit != provider.is_some() {
            return Err(EgressDesiredError::NoncanonicalCheckpoint);
        }
    }
    normalize_model(
        pools.values().cloned().collect(),
        intents.values().map(|(intent, _)| intent.clone()).collect(),
    )
    .map_err(EgressDesiredError::from)
}

fn validate_source_key(source_key: &str) -> Result<(), EgressDesiredError> {
    if source_key.is_empty()
        || source_key.len() > MAX_EGRESS_SOURCE_KEY_BYTES
        || source_key.chars().any(char::is_control)
    {
        return Err(EgressDesiredError::InvalidSourceKey);
    }
    Ok(())
}

fn checked_next(revision: Revision) -> Result<Revision, EgressDesiredError> {
    revision
        .get()
        .checked_add(1)
        .map(Revision::new)
        .ok_or(EgressDesiredError::RevisionExhausted)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::net::IpAddr;

    use super::*;
    use crate::{
        AddressFamily, EgressAddressRequest, EgressDestinations, EgressIntentScope,
        EgressSourceSelector, IpPrefix,
    };

    fn pool() -> EgressAddressPool {
        EgressAddressPool {
            name: "finance".to_owned(),
            uid: "pool-uid".to_owned(),
            provider: EgressProviderRef {
                name: "static".to_owned(),
                instance: "lab".to_owned(),
            },
            prefixes: vec![IpPrefix {
                address: "192.0.2.0".parse().unwrap(),
                prefix_len: 24,
            }],
        }
    }

    fn intent() -> EgressIntent {
        EgressIntent {
            owner: EgressIntentOwner {
                scope: EgressIntentScope::Cluster,
                name: "finance".to_owned(),
                uid: "intent-uid".to_owned(),
            },
            priority: 1_000,
            source: EgressSourceSelector::default(),
            destinations: EgressDestinations::Any,
            addresses: EgressAddressRequest::Pool {
                name: "finance".to_owned(),
                families: vec![AddressFamily::Ipv4],
                addresses_per_family: 2,
            },
        }
    }

    #[test]
    fn complete_model_updates_are_atomic_revisioned_and_idempotent() {
        let mut store = EgressDesiredStore::default();
        assert!(store.apply_pool("native/pool".to_owned(), pool()).unwrap());
        assert_eq!(store.revision(), Revision::new(1));
        assert!(!store.apply_pool("native/pool".to_owned(), pool()).unwrap());
        assert!(
            store
                .apply_intent("native/policy".to_owned(), intent(), None)
                .unwrap()
        );
        assert_eq!(store.revision(), Revision::new(2));
        assert_eq!(store.model().intents.len(), 1);

        let before = store.clone();
        assert!(store.remove_pool("native/pool").is_err());
        assert_eq!(store, before);
        assert!(store.remove_intent("native/policy").unwrap());
        assert!(store.remove_pool("native/pool").unwrap());
        assert_eq!(store.revision(), Revision::new(4));
    }

    #[test]
    fn explicit_provider_and_checkpoint_replay_are_exact() {
        let mut explicit = intent();
        explicit.addresses = EgressAddressRequest::Explicit {
            addresses: vec!["192.0.2.40".parse::<IpAddr>().unwrap()],
        };
        let provider = EgressProviderRef {
            name: "openshift-egressip".to_owned(),
            instance: "cluster-a".to_owned(),
        };
        let mut store = EgressDesiredStore::default();
        store
            .apply_intent(
                "openshift/finance".to_owned(),
                explicit.clone(),
                Some(provider.clone()),
            )
            .unwrap();
        assert_eq!(store.explicit_provider(&explicit.owner), Some(&provider));
        let checkpoint = store.checkpoint();
        assert_eq!(EgressDesiredStore::restore(checkpoint).unwrap(), store);

        let mut malformed = store.checkpoint();
        malformed.intents[0].explicit_provider = None;
        assert_eq!(
            EgressDesiredStore::restore(malformed),
            Err(EgressDesiredError::NoncanonicalCheckpoint)
        );
    }

    #[test]
    fn duplicate_owners_and_noncanonical_checkpoint_order_fail_closed() {
        let mut store = EgressDesiredStore::default();
        store.apply_pool("native/pool".to_owned(), pool()).unwrap();
        store
            .apply_intent("native/a".to_owned(), intent(), None)
            .unwrap();
        assert!(
            store
                .apply_intent("native/b".to_owned(), intent(), None)
                .is_err()
        );
        assert_eq!(store.model().intents.len(), 1);

        let mut checkpoint = store.checkpoint();
        checkpoint.pools.push(checkpoint.pools[0].clone());
        assert!(EgressDesiredStore::restore(checkpoint).is_err());
        assert!(BTreeSet::from([store.model().pools[0].name.clone()]).contains("finance"));
    }
}
