//! Transactional, crash-repairable userspace gateway host state.
//!
//! This is the Phase 8.4 admission/state boundary. It deliberately does not
//! define BPF maps or packet processing; the next milestone lowers an active
//! verified bank into a consumable dataplane ABI.

use std::fmt::Display;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use unf_common::Revision;

use crate::{
    AdmittedEgressProjection, EGRESS_HOST_STATE_SCHEMA_VERSION, EgressBehaviorContract,
    EgressHaPlan, MAX_EGRESS_CONTRACT_PLANS,
};

pub const EGRESS_HOST_STATE_ABI_VERSION: u16 = 1;
pub const EGRESS_HOST_CHECKPOINT_SCHEMA_VERSION: u16 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EgressHostStateDigest(pub [u8; 32]);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EgressGatewayHostBank {
    pub schema_version: u16,
    pub abi_version: u16,
    pub controller_epoch: u64,
    pub projection_revision: Revision,
    pub contract: EgressBehaviorContract,
    pub ha_plans: Vec<EgressHaPlan>,
    pub state_digest: EgressHostStateDigest,
}

impl EgressGatewayHostBank {
    /// Lowers only an independently admitted exact-Node projection.
    ///
    /// # Errors
    ///
    /// Returns an encoding error if canonical host-state commitment fails.
    pub fn compile(projection: &AdmittedEgressProjection) -> Result<Self, EgressHostStateError> {
        let projection = projection.projection();
        let mut bank = Self {
            schema_version: EGRESS_HOST_STATE_SCHEMA_VERSION,
            abi_version: EGRESS_HOST_STATE_ABI_VERSION,
            controller_epoch: projection.controller_epoch,
            projection_revision: projection.revision,
            contract: projection.contract.clone(),
            ha_plans: projection.ha_plans.clone(),
            state_digest: EgressHostStateDigest([0; 32]),
        };
        bank.state_digest = bank.digest()?;
        Ok(bank)
    }

    /// Validates schema, bounds, exact Node ownership, ordering, lease fencing,
    /// and the self-contained durable commitment.
    ///
    /// # Errors
    ///
    /// Rejects corrupted, noncanonical, unsupported, or unbounded state.
    pub fn verify_integrity(&self) -> Result<(), EgressHostStateError> {
        if self.schema_version != EGRESS_HOST_STATE_SCHEMA_VERSION
            || self.abi_version != EGRESS_HOST_STATE_ABI_VERSION
        {
            return Err(EgressHostStateError::UnsupportedVersion {
                schema: self.schema_version,
                abi: self.abi_version,
            });
        }
        if self.controller_epoch == 0
            || self.projection_revision == Revision::INITIAL
            || self.contract.contract_revision == Revision::INITIAL
            || self.contract.node.name.is_empty()
            || self.contract.node.uid.is_empty()
            || self.contract.plans.len() > MAX_EGRESS_CONTRACT_PLANS
        {
            return Err(EgressHostStateError::InvalidBank);
        }
        self.contract
            .verify_integrity()
            .map_err(|_| EgressHostStateError::DigestMismatch)?;
        for plan in &self.ha_plans {
            plan.verify_integrity()
                .map_err(|_| EgressHostStateError::DigestMismatch)?;
        }
        let mut previous = None;
        for plan in &self.contract.plans {
            if plan.source.node != self.contract.node
                || plan.allocation.lease_epoch == 0
                || plan.gateways.is_empty()
                || !plan
                    .required_capabilities
                    .is_subset(&self.contract.node.capabilities)
                || plan.gateways.iter().any(|gateway| {
                    gateway.lease_epoch != plan.allocation.lease_epoch
                        || !plan
                            .required_capabilities
                            .is_subset(&gateway.node.capabilities)
                })
                || previous.is_some_and(|identity| identity >= plan.source.identity)
            {
                return Err(EgressHostStateError::InvalidBank);
            }
            previous = Some(plan.source.identity);
        }
        if self.state_digest != self.digest()? {
            return Err(EgressHostStateError::DigestMismatch);
        }
        Ok(())
    }

    fn digest(&self) -> Result<EgressHostStateDigest, EgressHostStateError> {
        let material = serde_json::to_vec(&(
            self.schema_version,
            self.abi_version,
            self.controller_epoch,
            self.projection_revision,
            &self.contract,
            &self.ha_plans,
        ))
        .map_err(|error| EgressHostStateError::Encoding(error.to_string()))?;
        let mut hasher = Sha256::new();
        hasher.update(b"unf.egress-gateway-host-bank.v1\0");
        hasher.update(material);
        Ok(EgressHostStateDigest(hasher.finalize().into()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EgressHostCheckpoint {
    pub schema_version: u16,
    pub abi_version: u16,
    pub active_bank: u8,
    pub bank: EgressGatewayHostBank,
}

impl EgressHostCheckpoint {
    fn new(active_bank: u8, bank: EgressGatewayHostBank) -> Self {
        Self {
            schema_version: EGRESS_HOST_CHECKPOINT_SCHEMA_VERSION,
            abi_version: EGRESS_HOST_STATE_ABI_VERSION,
            active_bank,
            bank,
        }
    }

    /// Parses and validates a strict schema-v1 checkpoint.
    ///
    /// # Errors
    ///
    /// Rejects malformed JSON, unknown fields, unsupported versions, invalid
    /// bank selection, or a mutated host-bank commitment.
    pub fn from_json(bytes: &[u8]) -> Result<Self, EgressHostStateError> {
        let checkpoint: Self = serde_json::from_slice(bytes)
            .map_err(|error| EgressHostStateError::Encoding(error.to_string()))?;
        checkpoint.verify_integrity()?;
        Ok(checkpoint)
    }

    /// Encodes the validated checkpoint for an owner-only durable store.
    ///
    /// # Errors
    ///
    /// Rejects invalid state or an encoding failure.
    pub fn to_json(&self) -> Result<Vec<u8>, EgressHostStateError> {
        self.verify_integrity()?;
        serde_json::to_vec(self).map_err(|error| EgressHostStateError::Encoding(error.to_string()))
    }

    /// Validates the checkpoint envelope and its committed bank.
    ///
    /// # Errors
    ///
    /// Rejects unsupported versions, invalid bank selection, or corrupt state.
    pub fn verify_integrity(&self) -> Result<(), EgressHostStateError> {
        if self.schema_version != EGRESS_HOST_CHECKPOINT_SCHEMA_VERSION
            || self.abi_version != EGRESS_HOST_STATE_ABI_VERSION
        {
            return Err(EgressHostStateError::UnsupportedVersion {
                schema: self.schema_version,
                abi: self.abi_version,
            });
        }
        validate_bank_index(self.active_bank)?;
        self.bank.verify_integrity()
    }
}

/// Storage boundary implemented by the agent's persistent maps and owner-only
/// checkpoint files. Each method must affect only Phase 8's exact ABI version.
#[allow(clippy::missing_errors_doc)]
pub trait EgressHostStateStore {
    type Error: Display;

    fn active_bank(&self) -> Result<u8, Self::Error>;
    fn write_bank(&mut self, bank: u8, state: &EgressGatewayHostBank) -> Result<(), Self::Error>;
    fn read_bank(&self, bank: u8) -> Result<Option<EgressGatewayHostBank>, Self::Error>;
    fn activate_bank(&mut self, bank: u8) -> Result<(), Self::Error>;
    fn clear_bank(&mut self, bank: u8) -> Result<(), Self::Error>;
    fn current_checkpoint(&self) -> Result<Option<EgressHostCheckpoint>, Self::Error>;
    fn pending_checkpoint(&self) -> Result<Option<EgressHostCheckpoint>, Self::Error>;
    fn prepare_checkpoint(&mut self, checkpoint: &EgressHostCheckpoint) -> Result<(), Self::Error>;
    fn commit_pending_checkpoint(&mut self) -> Result<(), Self::Error>;
    fn discard_pending_checkpoint(&mut self) -> Result<(), Self::Error>;
    fn clear_current_checkpoint(&mut self) -> Result<(), Self::Error>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EgressHostApplyOutcome {
    pub checkpoint: EgressHostCheckpoint,
    pub changed: bool,
    pub retired_previous_bank: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum EgressHostStateError {
    #[error("unsupported egress host state schema {schema} or ABI {abi}")]
    UnsupportedVersion { schema: u16, abi: u16 },
    #[error("invalid egress host-state bank")]
    InvalidBank,
    #[error("invalid egress host-state bank index {0}")]
    InvalidBankIndex(u8),
    #[error("egress host-state digest mismatch")]
    DigestMismatch,
    #[error("egress host-state epoch or revision regressed")]
    RevisionRegression,
    #[error("egress host state mutated at the same epoch and revision")]
    SameRevisionMutation,
    #[error("egress host-state inactive-bank readback mismatch")]
    ReadbackMismatch,
    #[error("egress host-state recovery evidence is ambiguous")]
    AmbiguousRecovery,
    #[error("egress host-state rollback failed after activation")]
    RecoveryRequired,
    #[error("egress host-state backend failed during {action}: {message}")]
    Backend {
        action: &'static str,
        message: String,
    },
    #[error("egress host-state encoding failed: {0}")]
    Encoding(String),
}

pub struct EgressHostStateManager<S> {
    store: S,
}

impl<S: EgressHostStateStore> EgressHostStateManager<S> {
    #[must_use]
    pub const fn new(store: S) -> Self {
        Self { store }
    }

    #[must_use]
    pub fn store(&self) -> &S {
        &self.store
    }

    #[must_use]
    pub fn store_mut(&mut self) -> &mut S {
        &mut self.store
    }

    #[must_use]
    pub fn into_store(self) -> S {
        self.store
    }

    /// Stages, reads back, prepares, activates, commits, and retires one exact
    /// bank. Any pre-activation failure preserves the last-known-good bank; a
    /// post-activation checkpoint failure rolls the pointer back.
    ///
    /// # Errors
    ///
    /// Rejects invalid/regressing state and returns bounded backend failures.
    pub fn apply(
        &mut self,
        desired: EgressGatewayHostBank,
    ) -> Result<EgressHostApplyOutcome, EgressHostStateError> {
        desired.verify_integrity()?;
        let (active, replay) = self.validate_apply_base(&desired)?;
        if let Some(replay) = replay {
            return Ok(replay);
        }
        let inactive = 1 - active;
        let pending = self.stage_and_prepare(inactive, desired)?;
        self.activate_and_commit(active, inactive, &pending)?;
        let retired_previous_bank = self.store.clear_bank(active).is_ok();
        Ok(EgressHostApplyOutcome {
            checkpoint: pending,
            changed: true,
            retired_previous_bank,
        })
    }

    fn validate_apply_base(
        &mut self,
        desired: &EgressGatewayHostBank,
    ) -> Result<(u8, Option<EgressHostApplyOutcome>), EgressHostStateError> {
        let active = self.backend("read active bank", |store| store.active_bank())?;
        validate_bank_index(active)?;
        let current = self.backend("read current checkpoint", |store| {
            store.current_checkpoint()
        })?;
        if self
            .backend("inspect pending checkpoint", |store| {
                store.pending_checkpoint()
            })?
            .is_some()
        {
            return Err(EgressHostStateError::AmbiguousRecovery);
        }
        if let Some(checkpoint) = &current {
            checkpoint.verify_integrity()?;
            if checkpoint.active_bank != active {
                return Err(EgressHostStateError::AmbiguousRecovery);
            }
            let active_state = self.backend("verify current active state", |store| {
                store.read_bank(active)
            })?;
            if active_state.as_ref() != Some(&checkpoint.bank) {
                return Err(EgressHostStateError::AmbiguousRecovery);
            }
            validate_transition(&checkpoint.bank, desired)?;
            if checkpoint.bank == *desired {
                return Ok((
                    active,
                    Some(EgressHostApplyOutcome {
                        checkpoint: checkpoint.clone(),
                        changed: false,
                        retired_previous_bank: true,
                    }),
                ));
            }
        } else if self
            .backend("inspect unowned active state", |store| {
                store.read_bank(active)
            })?
            .is_some()
        {
            return Err(EgressHostStateError::AmbiguousRecovery);
        }
        Ok((active, None))
    }

    fn stage_and_prepare(
        &mut self,
        inactive: u8,
        desired: EgressGatewayHostBank,
    ) -> Result<EgressHostCheckpoint, EgressHostStateError> {
        if let Err(error) = self.store.write_bank(inactive, &desired) {
            let _ = self.store.clear_bank(inactive);
            return Err(backend_error("stage inactive bank", error));
        }
        let readback = match self.store.read_bank(inactive) {
            Ok(readback) => readback,
            Err(error) => {
                let _ = self.store.clear_bank(inactive);
                return Err(backend_error("read back inactive bank", error));
            }
        };
        if readback.as_ref() != Some(&desired) {
            let _ = self.store.clear_bank(inactive);
            return Err(EgressHostStateError::ReadbackMismatch);
        }
        let pending = EgressHostCheckpoint::new(inactive, desired);
        if let Err(error) = self.store.prepare_checkpoint(&pending) {
            let _ = self.store.discard_pending_checkpoint();
            let _ = self.store.clear_bank(inactive);
            return Err(backend_error("prepare checkpoint", error));
        }
        let prepared = match self.store.pending_checkpoint() {
            Ok(prepared) => prepared,
            Err(error) => {
                let _ = self.store.discard_pending_checkpoint();
                let _ = self.store.clear_bank(inactive);
                return Err(backend_error("read prepared checkpoint", error));
            }
        };
        if prepared.as_ref() != Some(&pending) {
            let _ = self.store.discard_pending_checkpoint();
            let _ = self.store.clear_bank(inactive);
            return Err(EgressHostStateError::ReadbackMismatch);
        }
        Ok(pending)
    }

    fn activate_and_commit(
        &mut self,
        active: u8,
        inactive: u8,
        pending: &EgressHostCheckpoint,
    ) -> Result<(), EgressHostStateError> {
        if let Err(error) = self.store.activate_bank(inactive) {
            let pointer_rollback = match self.store.active_bank() {
                Ok(observed) if observed == inactive => self.store.activate_bank(active),
                Ok(observed) if observed == active => Ok(()),
                _ => return Err(EgressHostStateError::RecoveryRequired),
            };
            let pending_cleanup = self.store.discard_pending_checkpoint();
            let bank_cleanup = self.store.clear_bank(inactive);
            if pointer_rollback.is_err() || pending_cleanup.is_err() || bank_cleanup.is_err() {
                return Err(EgressHostStateError::RecoveryRequired);
            }
            return Err(backend_error("activate prepared bank", error));
        }
        if self.store.commit_pending_checkpoint().is_err() {
            match self.store.current_checkpoint() {
                Ok(Some(committed)) if committed == *pending => {}
                Ok(_) => {
                    let pointer_rollback = self.store.activate_bank(active);
                    let pending_cleanup = self.store.discard_pending_checkpoint();
                    let bank_cleanup = self.store.clear_bank(inactive);
                    if pointer_rollback.is_err()
                        || pending_cleanup.is_err()
                        || bank_cleanup.is_err()
                    {
                        return Err(EgressHostStateError::RecoveryRequired);
                    }
                    return Err(EgressHostStateError::Backend {
                        action: "commit prepared checkpoint",
                        message: "commit failed; active pointer was rolled back".to_owned(),
                    });
                }
                Err(_) => return Err(EgressHostStateError::RecoveryRequired),
            }
        }
        let committed = self.backend("read committed checkpoint", |store| {
            store.current_checkpoint()
        })?;
        if committed.as_ref() != Some(pending) {
            return Err(EgressHostStateError::RecoveryRequired);
        }
        Ok(())
    }

    /// Repairs an interrupted transaction from the active pointer plus exact
    /// current/pending checkpoints. The active pointer is authoritative; no
    /// revision is guessed.
    ///
    /// # Errors
    ///
    /// Rejects mutated checkpoints or evidence matching neither current nor
    /// prepared state.
    pub fn recover(&mut self) -> Result<Option<EgressHostCheckpoint>, EgressHostStateError> {
        let active = self.backend("read recovery active bank", |store| store.active_bank())?;
        validate_bank_index(active)?;
        let current = self.backend("read recovery current checkpoint", |store| {
            store.current_checkpoint()
        })?;
        let pending = self.backend("read recovery pending checkpoint", |store| {
            store.pending_checkpoint()
        })?;
        for checkpoint in current.iter().chain(pending.iter()) {
            checkpoint.verify_integrity()?;
        }
        if current
            .as_ref()
            .zip(pending.as_ref())
            .is_some_and(|(stable, prepared)| {
                stable.active_bank == active && prepared.active_bank == active && stable != prepared
            })
        {
            return Err(EgressHostStateError::AmbiguousRecovery);
        }
        if current.is_none() && pending.is_none() {
            return Ok(None);
        }
        let observed = self.backend("read recovery active state", |store| {
            store.read_bank(active)
        })?;

        if let Some(prepared) = pending.filter(|candidate| candidate.active_bank == active) {
            if observed.as_ref().is_some_and(|bank| bank != &prepared.bank) {
                return Err(EgressHostStateError::AmbiguousRecovery);
            }
            if observed.is_none() {
                self.backend("reconstruct prepared bank", |store| {
                    store.write_bank(active, &prepared.bank)
                })?;
                let readback = self.backend("read reconstructed prepared bank", |store| {
                    store.read_bank(active)
                })?;
                if readback.as_ref() != Some(&prepared.bank) {
                    return Err(EgressHostStateError::ReadbackMismatch);
                }
            }
            self.backend("commit recovered prepared checkpoint", |store| {
                store.commit_pending_checkpoint()
            })?;
            let _ = self.store.clear_bank(1 - active);
            return Ok(Some(prepared));
        }

        if let Some(stable) = current.filter(|candidate| candidate.active_bank == active) {
            if observed.as_ref().is_some_and(|bank| bank != &stable.bank) {
                return Err(EgressHostStateError::AmbiguousRecovery);
            }
            if observed.is_none() {
                self.backend("reconstruct current bank", |store| {
                    store.write_bank(active, &stable.bank)
                })?;
                let readback = self.backend("read reconstructed current bank", |store| {
                    store.read_bank(active)
                })?;
                if readback.as_ref() != Some(&stable.bank) {
                    return Err(EgressHostStateError::ReadbackMismatch);
                }
            }
            self.backend("discard stale prepared checkpoint", |store| {
                store.discard_pending_checkpoint()
            })?;
            let _ = self.store.clear_bank(1 - active);
            return Ok(Some(stable));
        }
        Err(EgressHostStateError::AmbiguousRecovery)
    }

    /// Removes only the exact Phase 8.4 ABI-owned banks and checkpoints.
    ///
    /// # Errors
    ///
    /// Refuses every unknown ABI version and surfaces scoped backend failures.
    pub fn cleanup(&mut self, abi_version: u16) -> Result<(), EgressHostStateError> {
        if abi_version != EGRESS_HOST_STATE_ABI_VERSION {
            return Err(EgressHostStateError::UnsupportedVersion {
                schema: EGRESS_HOST_STATE_SCHEMA_VERSION,
                abi: abi_version,
            });
        }
        for bank in [0, 1] {
            self.backend("clear owned bank", |store| store.clear_bank(bank))?;
        }
        self.backend("clear pending checkpoint", |store| {
            store.discard_pending_checkpoint()
        })?;
        self.backend("clear current checkpoint", |store| {
            store.clear_current_checkpoint()
        })?;
        self.backend("reset owned active pointer", |store| store.activate_bank(0))
    }

    fn backend<T>(
        &mut self,
        action: &'static str,
        operation: impl FnOnce(&mut S) -> Result<T, S::Error>,
    ) -> Result<T, EgressHostStateError> {
        operation(&mut self.store).map_err(|error| backend_error(action, error))
    }
}

fn validate_transition(
    current: &EgressGatewayHostBank,
    desired: &EgressGatewayHostBank,
) -> Result<(), EgressHostStateError> {
    if desired.controller_epoch < current.controller_epoch
        || (desired.controller_epoch == current.controller_epoch
            && (desired.projection_revision < current.projection_revision
                || desired.contract.contract_revision < current.contract.contract_revision))
    {
        return Err(EgressHostStateError::RevisionRegression);
    }
    if desired.controller_epoch == current.controller_epoch
        && desired.projection_revision == current.projection_revision
        && desired != current
    {
        return Err(EgressHostStateError::SameRevisionMutation);
    }
    Ok(())
}

fn validate_bank_index(bank: u8) -> Result<(), EgressHostStateError> {
    if bank > 1 {
        return Err(EgressHostStateError::InvalidBankIndex(bank));
    }
    Ok(())
}

fn backend_error(error_action: &'static str, error: impl Display) -> EgressHostStateError {
    EgressHostStateError::Backend {
        action: error_action,
        message: error.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::distribution::test_support::{admitted, admitted_variant};

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Failure {
        Write,
        Prepare,
        Activate,
        Commit,
    }

    #[derive(Debug, Clone, Default)]
    struct TestStore {
        active: u8,
        banks: [Option<EgressGatewayHostBank>; 2],
        current: Option<EgressHostCheckpoint>,
        pending: Option<EgressHostCheckpoint>,
        failure: Option<Failure>,
        corrupt_bank: Option<u8>,
    }

    impl EgressHostStateStore for TestStore {
        type Error = &'static str;

        fn active_bank(&self) -> Result<u8, Self::Error> {
            Ok(self.active)
        }

        fn write_bank(
            &mut self,
            bank: u8,
            state: &EgressGatewayHostBank,
        ) -> Result<(), Self::Error> {
            if self.failure == Some(Failure::Write) {
                self.failure = None;
                return Err("injected write failure");
            }
            self.banks[usize::from(bank)] = Some(state.clone());
            Ok(())
        }

        fn read_bank(&self, bank: u8) -> Result<Option<EgressGatewayHostBank>, Self::Error> {
            let mut value = self.banks[usize::from(bank)].clone();
            if self.corrupt_bank == Some(bank)
                && let Some(value) = &mut value
            {
                value.state_digest.0[0] ^= 0xff;
            }
            Ok(value)
        }

        fn activate_bank(&mut self, bank: u8) -> Result<(), Self::Error> {
            if self.failure == Some(Failure::Activate) {
                self.failure = None;
                return Err("injected activation failure");
            }
            self.active = bank;
            Ok(())
        }

        fn clear_bank(&mut self, bank: u8) -> Result<(), Self::Error> {
            self.banks[usize::from(bank)] = None;
            Ok(())
        }

        fn current_checkpoint(&self) -> Result<Option<EgressHostCheckpoint>, Self::Error> {
            Ok(self.current.clone())
        }

        fn pending_checkpoint(&self) -> Result<Option<EgressHostCheckpoint>, Self::Error> {
            Ok(self.pending.clone())
        }

        fn prepare_checkpoint(
            &mut self,
            checkpoint: &EgressHostCheckpoint,
        ) -> Result<(), Self::Error> {
            if self.failure == Some(Failure::Prepare) {
                self.failure = None;
                return Err("injected prepare failure");
            }
            self.pending = Some(checkpoint.clone());
            Ok(())
        }

        fn commit_pending_checkpoint(&mut self) -> Result<(), Self::Error> {
            if self.failure == Some(Failure::Commit) {
                self.failure = None;
                return Err("injected commit failure");
            }
            self.current = self.pending.take();
            Ok(())
        }

        fn discard_pending_checkpoint(&mut self) -> Result<(), Self::Error> {
            self.pending = None;
            Ok(())
        }

        fn clear_current_checkpoint(&mut self) -> Result<(), Self::Error> {
            self.current = None;
            Ok(())
        }
    }

    fn bank(revision: u64) -> EgressGatewayHostBank {
        EgressGatewayHostBank::compile(&admitted(revision)).expect("compile host bank")
    }

    fn reseal(bank: &mut EgressGatewayHostBank) {
        bank.state_digest = bank.digest().expect("seal host bank");
    }

    #[test]
    fn admitted_projection_compiles_digest_bound_checkpoint_json() {
        let bank = bank(4);
        bank.verify_integrity().expect("valid bank");
        let checkpoint = EgressHostCheckpoint::new(1, bank);
        let json = checkpoint.to_json().expect("encode checkpoint");
        assert_eq!(
            EgressHostCheckpoint::from_json(&json).expect("decode checkpoint"),
            checkpoint
        );
        let mut mutation: serde_json::Value = serde_json::from_slice(&json).expect("JSON value");
        mutation["bank"]["projectionRevision"] = serde_json::json!(99);
        assert_eq!(
            EgressHostCheckpoint::from_json(
                &serde_json::to_vec(&mutation).expect("encode mutation")
            ),
            Err(EgressHostStateError::DigestMismatch)
        );
    }

    #[test]
    fn apply_stages_reads_back_activates_and_is_idempotent() {
        let mut manager = EgressHostStateManager::new(TestStore::default());
        let first = manager.apply(bank(4)).expect("apply first bank");
        assert!(first.changed);
        assert_eq!(first.checkpoint.active_bank, 1);
        assert!(first.retired_previous_bank);
        let replay = manager.apply(bank(4)).expect("idempotent replay");
        assert!(!replay.changed);

        let second = manager.apply(bank(5)).expect("advance bank");
        assert_eq!(second.checkpoint.active_bank, 0);
        assert!(manager.store().banks[1].is_none());
    }

    #[test]
    fn transition_fences_regression_and_same_revision_mutation() {
        let mut manager = EgressHostStateManager::new(TestStore::default());
        manager.apply(bank(4)).expect("apply first bank");

        let mutation =
            EgressGatewayHostBank::compile(&admitted_variant(4)).expect("compile valid mutation");
        assert_eq!(
            manager.apply(mutation),
            Err(EgressHostStateError::SameRevisionMutation)
        );
        let regression = bank(3);
        assert_eq!(
            manager.apply(regression),
            Err(EgressHostStateError::RevisionRegression)
        );
    }

    #[test]
    fn stage_readback_and_activation_failure_preserve_last_known_good() {
        let mut manager = EgressHostStateManager::new(TestStore::default());
        let first = manager.apply(bank(4)).expect("apply first").checkpoint;

        manager.store_mut().corrupt_bank = Some(0);
        assert_eq!(
            manager.apply(bank(5)),
            Err(EgressHostStateError::ReadbackMismatch)
        );
        manager.store_mut().corrupt_bank = None;
        assert_eq!(manager.store().current.as_ref(), Some(&first));
        assert_eq!(manager.store().active, first.active_bank);

        manager.store_mut().failure = Some(Failure::Prepare);
        assert!(matches!(
            manager.apply(bank(5)),
            Err(EgressHostStateError::Backend {
                action: "prepare checkpoint",
                ..
            })
        ));
        assert!(manager.store().banks[0].is_none());
        assert!(manager.store().pending.is_none());

        manager.store_mut().failure = Some(Failure::Activate);
        assert!(matches!(
            manager.apply(bank(5)),
            Err(EgressHostStateError::Backend {
                action: "activate prepared bank",
                ..
            })
        ));
        assert_eq!(manager.store().current.as_ref(), Some(&first));
        assert_eq!(manager.store().active, first.active_bank);
    }

    #[test]
    fn checkpoint_commit_failure_rolls_activation_pointer_back() {
        let mut manager = EgressHostStateManager::new(TestStore::default());
        let first = manager.apply(bank(4)).expect("apply first").checkpoint;
        manager.store_mut().failure = Some(Failure::Commit);
        assert!(matches!(
            manager.apply(bank(5)),
            Err(EgressHostStateError::Backend {
                action: "commit prepared checkpoint",
                ..
            })
        ));
        assert_eq!(manager.store().active, first.active_bank);
        assert_eq!(manager.store().current.as_ref(), Some(&first));
        assert!(manager.store().pending.is_none());
    }

    #[test]
    fn recovery_commits_winning_pending_or_reconstructs_current_state() {
        let mut manager = EgressHostStateManager::new(TestStore::default());
        manager.apply(bank(4)).expect("apply first");
        let candidate = bank(5);
        let pending = EgressHostCheckpoint::new(0, candidate.clone());
        manager.store_mut().banks[0] = Some(candidate);
        manager.store_mut().pending = Some(pending.clone());
        manager.store_mut().active = 0;
        assert_eq!(
            manager.apply(bank(6)),
            Err(EgressHostStateError::AmbiguousRecovery)
        );
        assert_eq!(
            manager.recover().expect("recover pending"),
            Some(pending.clone())
        );
        assert_eq!(manager.store().current.as_ref(), Some(&pending));

        manager.store_mut().banks[0] = None;
        assert_eq!(manager.recover().expect("cold reconstruct"), Some(pending));
        assert!(manager.store().banks[0].is_some());
    }

    #[test]
    fn ambiguous_recovery_fails_closed_and_cleanup_is_version_scoped() {
        let stable_bank = bank(4);
        let stable = EgressHostCheckpoint::new(1, stable_bank.clone());
        let mut store = TestStore {
            active: 1,
            current: Some(stable),
            ..TestStore::default()
        };
        let mut foreign = bank(5);
        foreign.controller_epoch += 1;
        reseal(&mut foreign);
        store.banks[1] = Some(foreign);
        let mut manager = EgressHostStateManager::new(store);
        assert_eq!(
            manager.recover(),
            Err(EgressHostStateError::AmbiguousRecovery)
        );
        assert!(matches!(
            manager.cleanup(EGRESS_HOST_STATE_ABI_VERSION + 1),
            Err(EgressHostStateError::UnsupportedVersion { .. })
        ));
        manager
            .cleanup(EGRESS_HOST_STATE_ABI_VERSION)
            .expect("scoped cleanup");
        assert!(manager.store().banks.iter().all(Option::is_none));
        assert!(manager.store().current.is_none());
        assert!(manager.store().pending.is_none());
    }

    #[test]
    fn write_failure_never_creates_pending_or_changes_active_state() {
        let mut manager = EgressHostStateManager::new(TestStore {
            failure: Some(Failure::Write),
            ..TestStore::default()
        });
        assert!(matches!(
            manager.apply(bank(4)),
            Err(EgressHostStateError::Backend {
                action: "stage inactive bank",
                ..
            })
        ));
        assert_eq!(manager.store().active, 0);
        assert!(manager.store().current.is_none());
        assert!(manager.store().pending.is_none());
    }
}
