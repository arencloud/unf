//! Secret-free, loss-explicit operational evidence for the encryption fabric.
//!
//! Metrics use one closed stage/outcome matrix: their cardinality cannot grow
//! with Nodes, peers, policies, contracts, or epochs. A bounded hash-chained
//! history carries exact diagnostic provenance separately and makes both local
//! retention eviction and upstream observation loss explicit.

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use unf_common::Revision;

use crate::{
    AttestedEncryptionContractDigest, EncryptionFastPathDigest, EncryptionGenerationRecipient,
    EncryptionPathActivationDigest, EncryptionPathActivationReceipt,
};

pub const ENCRYPTION_OPERATIONS_SCHEMA_VERSION: u16 = 1;
pub const ENCRYPTION_OPERATIONS_HISTORY_CAPACITY: usize = 512;
pub const ENCRYPTION_OPERATIONAL_STAGE_COUNT: usize = 6;
pub const ENCRYPTION_OPERATIONAL_OUTCOME_COUNT: usize = 9;
const HISTORY_DOMAIN: &[u8] = b"unf.encryption.operations.history.v1\0";
const ACTIVATION_REPORT_DOMAIN: &[u8] = b"unf.encryption.operations.activation-report.v1\0";
pub const MAX_ENCRYPTION_ACTIVATION_REPORT_PATHS: usize = 4_096;

/// Strict, non-authoritative controller request for active-generation
/// testimony. A fleet-wide incomplete cut keeps every endpoint available for
/// reciprocal proofs, while only a Node whose cursor is missing must report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EncryptionActivationTestimonyRequest {
    pub schema_version: u16,
    pub recipient: EncryptionGenerationRecipient,
    pub generation: Revision,
    pub state_digest: EncryptionFastPathDigest,
    pub report_required: bool,
}

impl EncryptionActivationTestimonyRequest {
    /// Creates a request bound to one exact prepared generation.
    ///
    /// # Errors
    ///
    /// Rejects an empty identity, initial generation, or empty state digest.
    pub fn issue(
        recipient: EncryptionGenerationRecipient,
        generation: Revision,
        state_digest: EncryptionFastPathDigest,
        report_required: bool,
    ) -> Result<Self, EncryptionOperationsError> {
        let request = Self {
            schema_version: ENCRYPTION_OPERATIONS_SCHEMA_VERSION,
            recipient,
            generation,
            state_digest,
            report_required,
        };
        request.verify()?;
        Ok(request)
    }

    /// Validates the strict wire shape. This request deliberately carries no
    /// activation capability and cannot authorize local state mutation.
    ///
    /// # Errors
    ///
    /// Rejects unsupported or malformed coordinates.
    pub fn verify(&self) -> Result<(), EncryptionOperationsError> {
        if self.schema_version != ENCRYPTION_OPERATIONS_SCHEMA_VERSION
            || self.recipient.node_name.is_empty()
            || self.recipient.node_uid.is_empty()
            || self.generation == Revision::INITIAL
            || self.state_digest.0 == [0; 32]
        {
            return Err(EncryptionOperationsError::InvalidActivationTestimonyRequest);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum EncryptionOperationalStage {
    Requirement,
    Assignment,
    LocalExchange,
    RemoteQuorum,
    Activation,
    Lifecycle,
}

impl EncryptionOperationalStage {
    pub const ALL: [Self; ENCRYPTION_OPERATIONAL_STAGE_COUNT] = [
        Self::Requirement,
        Self::Assignment,
        Self::LocalExchange,
        Self::RemoteQuorum,
        Self::Activation,
        Self::Lifecycle,
    ];

    const fn index(self) -> usize {
        match self {
            Self::Requirement => 0,
            Self::Assignment => 1,
            Self::LocalExchange => 2,
            Self::RemoteQuorum => 3,
            Self::Activation => 4,
            Self::Lifecycle => 5,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum EncryptionOperationalOutcome {
    Native,
    Required,
    Pending,
    Proven,
    Activated,
    Denied,
    Expired,
    Collision,
    Loss,
}

impl EncryptionOperationalOutcome {
    pub const ALL: [Self; ENCRYPTION_OPERATIONAL_OUTCOME_COUNT] = [
        Self::Native,
        Self::Required,
        Self::Pending,
        Self::Proven,
        Self::Activated,
        Self::Denied,
        Self::Expired,
        Self::Collision,
        Self::Loss,
    ];

    const fn index(self) -> usize {
        match self {
            Self::Native => 0,
            Self::Required => 1,
            Self::Pending => 2,
            Self::Proven => 3,
            Self::Activated => 4,
            Self::Denied => 5,
            Self::Expired => 6,
            Self::Collision => 7,
            Self::Loss => 8,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum EncryptionObservationLossReason {
    QueuePressure,
    SourceUnavailable,
    DecodeRejected,
    ClockRejected,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EncryptionOperationsHistoryDigest(pub [u8; 32]);

/// One bounded, non-authoritative observation. It deliberately contains no
/// Node name, address, public/private key, nonce, challenge, or activation
/// permit. Exact contract digests are safe correlators, not capabilities.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EncryptionOperationalObservation {
    pub observed_at_unix_ms: u64,
    pub generation: Revision,
    pub stage: EncryptionOperationalStage,
    pub outcome: EncryptionOperationalOutcome,
    pub contract_digest: Option<AttestedEncryptionContractDigest>,
    pub epoch: Option<u64>,
}

impl EncryptionOperationalObservation {
    /// Creates a structurally valid, secret-free observation.
    ///
    /// # Errors
    ///
    /// Rejects zero timestamps/generations, semantically invalid stage/outcome
    /// pairs, or proof-plane observations without contract and epoch binding.
    pub fn issue(
        observed_at_unix_ms: u64,
        generation: Revision,
        stage: EncryptionOperationalStage,
        outcome: EncryptionOperationalOutcome,
        contract_digest: Option<AttestedEncryptionContractDigest>,
        epoch: Option<u64>,
    ) -> Result<Self, EncryptionOperationsError> {
        let observation = Self {
            observed_at_unix_ms,
            generation,
            stage,
            outcome,
            contract_digest,
            epoch,
        };
        observation.validate()?;
        Ok(observation)
    }

    fn validate(&self) -> Result<(), EncryptionOperationsError> {
        let requirement = self.stage == EncryptionOperationalStage::Requirement;
        let lifecycle = self.stage == EncryptionOperationalStage::Lifecycle;
        let valid_outcome = match self.stage {
            EncryptionOperationalStage::Requirement => matches!(
                self.outcome,
                EncryptionOperationalOutcome::Native
                    | EncryptionOperationalOutcome::Required
                    | EncryptionOperationalOutcome::Denied
            ),
            EncryptionOperationalStage::Assignment
            | EncryptionOperationalStage::LocalExchange
            | EncryptionOperationalStage::RemoteQuorum => matches!(
                self.outcome,
                EncryptionOperationalOutcome::Pending
                    | EncryptionOperationalOutcome::Proven
                    | EncryptionOperationalOutcome::Denied
                    | EncryptionOperationalOutcome::Expired
                    | EncryptionOperationalOutcome::Collision
            ),
            EncryptionOperationalStage::Activation => matches!(
                self.outcome,
                EncryptionOperationalOutcome::Pending
                    | EncryptionOperationalOutcome::Activated
                    | EncryptionOperationalOutcome::Denied
                    | EncryptionOperationalOutcome::Expired
            ),
            EncryptionOperationalStage::Lifecycle => matches!(
                self.outcome,
                EncryptionOperationalOutcome::Activated
                    | EncryptionOperationalOutcome::Denied
                    | EncryptionOperationalOutcome::Expired
                    | EncryptionOperationalOutcome::Collision
            ),
        };
        if self.observed_at_unix_ms == 0
            || self.generation == Revision::INITIAL
            || !valid_outcome
            || requirement && self.epoch.is_some()
            || requirement && self.contract_digest.is_some()
            || !requirement
                && (!lifecycle
                    || !matches!(
                        self.outcome,
                        EncryptionOperationalOutcome::Activated
                            | EncryptionOperationalOutcome::Collision
                    ))
                && (self.contract_digest.is_none() || self.epoch.is_none_or(|epoch| epoch == 0))
        {
            return Err(EncryptionOperationsError::InvalidObservation);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", deny_unknown_fields, rename_all = "camelCase")]
pub enum EncryptionOperationsHistoryEntry {
    Observation {
        observation: EncryptionOperationalObservation,
    },
    ObservationLoss {
        observed_at_unix_ms: u64,
        generation: Revision,
        reason: EncryptionObservationLossReason,
        omitted_observations: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EncryptionOperationsHistoryRecord {
    pub sequence: u64,
    pub entry: EncryptionOperationsHistoryEntry,
    pub previous_record_digest: EncryptionOperationsHistoryDigest,
    pub record_digest: EncryptionOperationsHistoryDigest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EncryptionOperationsHistoryCheckpoint {
    pub schema_version: u16,
    pub revision: u64,
    pub generation: Revision,
    pub counters: EncryptionOperationalCounters,
    pub evicted_records: u64,
    pub evicted_observations: u64,
    pub reported_lost_observations: u64,
    pub anchor_digest: EncryptionOperationsHistoryDigest,
    pub records: Vec<EncryptionOperationsHistoryRecord>,
}

impl Default for EncryptionOperationsHistoryCheckpoint {
    fn default() -> Self {
        Self {
            schema_version: ENCRYPTION_OPERATIONS_SCHEMA_VERSION,
            revision: 0,
            generation: Revision::INITIAL,
            counters: EncryptionOperationalCounters::default(),
            evicted_records: 0,
            evicted_observations: 0,
            reported_lost_observations: 0,
            anchor_digest: EncryptionOperationsHistoryDigest::default(),
            records: Vec::new(),
        }
    }
}

/// Fixed 54-cell metric matrix. Exporters may attach only the closed `stage`
/// and `outcome` values, never a contract, Node, peer, policy, or epoch label.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EncryptionOperationalCounters {
    cells: [[u64; ENCRYPTION_OPERATIONAL_OUTCOME_COUNT]; ENCRYPTION_OPERATIONAL_STAGE_COUNT],
}

impl Default for EncryptionOperationalCounters {
    fn default() -> Self {
        Self {
            cells: [[0; ENCRYPTION_OPERATIONAL_OUTCOME_COUNT]; ENCRYPTION_OPERATIONAL_STAGE_COUNT],
        }
    }
}

impl EncryptionOperationalCounters {
    #[must_use]
    pub fn get(
        &self,
        stage: EncryptionOperationalStage,
        outcome: EncryptionOperationalOutcome,
    ) -> u64 {
        self.cells[stage.index()][outcome.index()]
    }

    fn increment(
        &mut self,
        stage: EncryptionOperationalStage,
        outcome: EncryptionOperationalOutcome,
        amount: u64,
    ) -> Result<(), EncryptionOperationsError> {
        let cell = &mut self.cells[stage.index()][outcome.index()];
        *cell = cell
            .checked_add(amount)
            .ok_or(EncryptionOperationsError::CounterExhausted)?;
        Ok(())
    }
}

/// Compact status with a causal evidence watermark. `complete_through_sequence`
/// identifies the newest retained, digest-verified record. Loss and eviction
/// counters prevent an empty window from being mistaken for healthy silence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EncryptionOperationsStatus {
    pub schema_version: u16,
    pub generated_at_unix_ms: u64,
    pub generation: Revision,
    pub counters: EncryptionOperationalCounters,
    pub complete_through_sequence: u64,
    pub retained_records: u32,
    pub evicted_records: u64,
    pub evicted_observations: u64,
    pub reported_lost_observations: u64,
    pub loss_affected: bool,
    pub history_head_digest: EncryptionOperationsHistoryDigest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EncryptionActivationPathEvidence {
    pub contract_digest: AttestedEncryptionContractDigest,
    pub epoch: u64,
    pub activation_digest: EncryptionPathActivationDigest,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EncryptionActivationReportDigest(pub [u8; 32]);

/// Retry-stable, non-authoritative acknowledgement emitted only after the
/// agent has published and read back one exact fast-path generation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EncryptionActivationReport {
    pub schema_version: u16,
    pub recipient: EncryptionGenerationRecipient,
    pub generation: Revision,
    pub state_digest: EncryptionFastPathDigest,
    pub activated_at_unix_ms: u64,
    pub paths: Vec<EncryptionActivationPathEvidence>,
    pub report_digest: EncryptionActivationReportDigest,
}

impl EncryptionActivationReport {
    /// Seals the exact set of duplex receipts consumed by a published map cut.
    /// Empty paths are valid only for an authority-free dormant generation.
    ///
    /// # Errors
    ///
    /// Rejects malformed identity/generation/state, duplicate or oversized
    /// paths, receipt generation mismatch, or canonical encoding failure.
    pub fn issue(
        recipient: EncryptionGenerationRecipient,
        generation: Revision,
        state_digest: EncryptionFastPathDigest,
        activated_at_unix_ms: u64,
        receipts: &[EncryptionPathActivationReceipt],
    ) -> Result<Self, EncryptionOperationsError> {
        let mut paths = receipts
            .iter()
            .map(|receipt| EncryptionActivationPathEvidence {
                contract_digest: receipt.round.contract_digest,
                epoch: receipt.round.epoch,
                activation_digest: receipt.activation_digest,
            })
            .collect::<Vec<_>>();
        paths.sort_unstable_by_key(|path| {
            (path.contract_digest.0, path.epoch, path.activation_digest.0)
        });
        let mut report = Self {
            schema_version: ENCRYPTION_OPERATIONS_SCHEMA_VERSION,
            recipient,
            generation,
            state_digest,
            activated_at_unix_ms,
            paths,
            report_digest: EncryptionActivationReportDigest::default(),
        };
        report.validate_fields()?;
        report.report_digest = report.calculate_digest()?;
        Ok(report)
    }

    /// Replays the strict wire shape and digest.
    ///
    /// # Errors
    ///
    /// Rejects malformed, noncanonical, or mutated reports.
    pub fn verify(&self) -> Result<(), EncryptionOperationsError> {
        self.validate_fields()?;
        if self.report_digest == EncryptionActivationReportDigest::default()
            || self.report_digest != self.calculate_digest()?
        {
            return Err(EncryptionOperationsError::InvalidActivationReport);
        }
        Ok(())
    }

    fn validate_fields(&self) -> Result<(), EncryptionOperationsError> {
        if self.schema_version != ENCRYPTION_OPERATIONS_SCHEMA_VERSION
            || self.recipient.node_name.is_empty()
            || self.recipient.node_uid.is_empty()
            || self.generation == Revision::INITIAL
            || self.state_digest.0 == [0; 32]
            || self.activated_at_unix_ms == 0
            || self.paths.len() > MAX_ENCRYPTION_ACTIVATION_REPORT_PATHS
            || self.paths.windows(2).any(|pair| {
                (
                    pair[0].contract_digest.0,
                    pair[0].epoch,
                    pair[0].activation_digest.0,
                ) >= (
                    pair[1].contract_digest.0,
                    pair[1].epoch,
                    pair[1].activation_digest.0,
                )
            })
            || self.paths.iter().any(|path| {
                path.contract_digest.0 == [0; 32]
                    || path.epoch == 0
                    || path.activation_digest.0 == [0; 32]
            })
        {
            return Err(EncryptionOperationsError::InvalidActivationReport);
        }
        Ok(())
    }

    fn calculate_digest(
        &self,
    ) -> Result<EncryptionActivationReportDigest, EncryptionOperationsError> {
        #[derive(Serialize)]
        struct Seal<'a> {
            domain: &'a [u8],
            schema_version: u16,
            recipient: &'a EncryptionGenerationRecipient,
            generation: Revision,
            state_digest: EncryptionFastPathDigest,
            activated_at_unix_ms: u64,
            paths: &'a [EncryptionActivationPathEvidence],
        }
        let encoded = serde_json::to_vec(&Seal {
            domain: ACTIVATION_REPORT_DOMAIN,
            schema_version: self.schema_version,
            recipient: &self.recipient,
            generation: self.generation,
            state_digest: self.state_digest,
            activated_at_unix_ms: self.activated_at_unix_ms,
            paths: &self.paths,
        })
        .map_err(|error| EncryptionOperationsError::Encoding(error.to_string()))?;
        let mut hasher = Sha256::new();
        hasher.update(encoded);
        Ok(EncryptionActivationReportDigest(hasher.finalize().into()))
    }
}

#[derive(Debug, Clone, Default)]
pub struct EncryptionOperationsLedger {
    generation: Revision,
    counters: EncryptionOperationalCounters,
    history: EncryptionOperationsHistoryCheckpoint,
}

impl EncryptionOperationsLedger {
    /// Restores a complete bounded checkpoint after validating its chain and
    /// recomputing all retained/loss counters.
    ///
    /// # Errors
    ///
    /// Rejects unsupported, oversized, discontinuous, digest-invalid, or
    /// internally inconsistent checkpoints without returning partial state.
    pub fn restore(
        checkpoint: EncryptionOperationsHistoryCheckpoint,
    ) -> Result<Self, EncryptionOperationsError> {
        validate_checkpoint(&checkpoint)?;
        Ok(Self {
            generation: checkpoint.generation,
            counters: checkpoint.counters.clone(),
            history: checkpoint,
        })
    }

    /// Appends one validated observation and advances the fixed metric matrix.
    ///
    /// # Errors
    ///
    /// Rejects invalid or regressing evidence and counter exhaustion.
    pub fn observe(
        &mut self,
        observation: EncryptionOperationalObservation,
    ) -> Result<(), EncryptionOperationsError> {
        observation.validate()?;
        self.append(EncryptionOperationsHistoryEntry::Observation { observation })
    }

    /// Records known upstream loss. A loss marker consumes one history slot but
    /// represents the exact number of unavailable observations.
    ///
    /// # Errors
    ///
    /// Rejects zero/regressing inputs and counter exhaustion.
    pub fn record_loss(
        &mut self,
        observed_at_unix_ms: u64,
        generation: Revision,
        reason: EncryptionObservationLossReason,
        omitted_observations: u64,
    ) -> Result<(), EncryptionOperationsError> {
        if observed_at_unix_ms == 0
            || generation == Revision::INITIAL
            || generation < self.generation
            || omitted_observations == 0
        {
            return Err(EncryptionOperationsError::InvalidLoss);
        }
        self.append(EncryptionOperationsHistoryEntry::ObservationLoss {
            observed_at_unix_ms,
            generation,
            reason,
            omitted_observations,
        })
    }

    #[must_use]
    pub fn checkpoint(&self) -> EncryptionOperationsHistoryCheckpoint {
        self.history.clone()
    }

    /// Produces a fixed-cardinality, secret-free status snapshot.
    ///
    /// # Errors
    ///
    /// Rejects a zero timestamp or one preceding the newest retained evidence.
    pub fn status(
        &self,
        generated_at_unix_ms: u64,
    ) -> Result<EncryptionOperationsStatus, EncryptionOperationsError> {
        let newest_time = self
            .history
            .records
            .last()
            .map_or(0, |record| entry_time(&record.entry));
        if generated_at_unix_ms == 0 || generated_at_unix_ms < newest_time {
            return Err(EncryptionOperationsError::InvalidStatusTime);
        }
        let head = self
            .history
            .records
            .last()
            .map_or(self.history.anchor_digest, |record| record.record_digest);
        Ok(EncryptionOperationsStatus {
            schema_version: ENCRYPTION_OPERATIONS_SCHEMA_VERSION,
            generated_at_unix_ms,
            generation: self.generation,
            counters: self.counters.clone(),
            complete_through_sequence: self.history.revision,
            retained_records: u32::try_from(self.history.records.len())
                .map_err(|_| EncryptionOperationsError::CounterExhausted)?,
            evicted_records: self.history.evicted_records,
            evicted_observations: self.history.evicted_observations,
            reported_lost_observations: self.history.reported_lost_observations,
            loss_affected: self.history.evicted_observations != 0
                || self.history.reported_lost_observations != 0,
            history_head_digest: head,
        })
    }

    fn append(
        &mut self,
        entry: EncryptionOperationsHistoryEntry,
    ) -> Result<(), EncryptionOperationsError> {
        let generation = entry_generation(&entry);
        if generation < self.generation {
            return Err(EncryptionOperationsError::GenerationRegression);
        }
        let sequence = self
            .history
            .revision
            .checked_add(1)
            .ok_or(EncryptionOperationsError::CounterExhausted)?;
        let previous = self
            .history
            .records
            .last()
            .map_or(self.history.anchor_digest, |record| record.record_digest);
        let mut record = EncryptionOperationsHistoryRecord {
            sequence,
            entry,
            previous_record_digest: previous,
            record_digest: EncryptionOperationsHistoryDigest::default(),
        };
        record.record_digest = record_digest(&record)?;
        self.account_entry(&record.entry)?;
        self.history.records.push(record);
        self.history.revision = sequence;
        self.generation = generation;
        self.history.generation = generation;
        self.history.counters = self.counters.clone();
        if self.history.records.len() > ENCRYPTION_OPERATIONS_HISTORY_CAPACITY {
            let evicted = self.history.records.remove(0);
            self.history.anchor_digest = evicted.record_digest;
            self.history.evicted_records = self
                .history
                .evicted_records
                .checked_add(1)
                .ok_or(EncryptionOperationsError::CounterExhausted)?;
            self.history.evicted_observations = self
                .history
                .evicted_observations
                .checked_add(entry_observation_count(&evicted.entry))
                .ok_or(EncryptionOperationsError::CounterExhausted)?;
        }
        Ok(())
    }

    fn account_entry(
        &mut self,
        entry: &EncryptionOperationsHistoryEntry,
    ) -> Result<(), EncryptionOperationsError> {
        self.generation = self.generation.max(entry_generation(entry));
        match entry {
            EncryptionOperationsHistoryEntry::Observation { observation } => self
                .counters
                .increment(observation.stage, observation.outcome, 1),
            EncryptionOperationsHistoryEntry::ObservationLoss {
                omitted_observations,
                ..
            } => {
                self.counters.increment(
                    EncryptionOperationalStage::Lifecycle,
                    EncryptionOperationalOutcome::Loss,
                    *omitted_observations,
                )?;
                self.history.reported_lost_observations = self
                    .history
                    .reported_lost_observations
                    .checked_add(*omitted_observations)
                    .ok_or(EncryptionOperationsError::CounterExhausted)?;
                Ok(())
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum EncryptionOperationsError {
    #[error("invalid encryption operational observation")]
    InvalidObservation,
    #[error("invalid encryption observation-loss marker")]
    InvalidLoss,
    #[error("encryption operational generation regressed")]
    GenerationRegression,
    #[error("unsupported encryption operations schema")]
    UnsupportedSchema,
    #[error("encryption operations checkpoint is noncanonical")]
    NoncanonicalCheckpoint,
    #[error("encryption operations history digest is invalid")]
    InvalidDigest,
    #[error("encryption operations counter exhausted")]
    CounterExhausted,
    #[error("invalid encryption operations status timestamp")]
    InvalidStatusTime,
    #[error("invalid encryption activation report")]
    InvalidActivationReport,
    #[error("invalid encryption activation testimony request")]
    InvalidActivationTestimonyRequest,
    #[error("encryption operations encoding failed: {0}")]
    Encoding(String),
}

fn validate_checkpoint(
    checkpoint: &EncryptionOperationsHistoryCheckpoint,
) -> Result<(), EncryptionOperationsError> {
    if checkpoint.schema_version != ENCRYPTION_OPERATIONS_SCHEMA_VERSION {
        return Err(EncryptionOperationsError::UnsupportedSchema);
    }
    if checkpoint.records.len() > ENCRYPTION_OPERATIONS_HISTORY_CAPACITY
        || checkpoint.revision
            != checkpoint
                .evicted_records
                .checked_add(checkpoint.records.len() as u64)
                .ok_or(EncryptionOperationsError::CounterExhausted)?
        || checkpoint.evicted_records == 0
            && (checkpoint.evicted_observations != 0
                || checkpoint.anchor_digest != EncryptionOperationsHistoryDigest::default())
        || checkpoint.evicted_records != 0 && checkpoint.records.is_empty()
    {
        return Err(EncryptionOperationsError::NoncanonicalCheckpoint);
    }
    let mut previous = checkpoint.anchor_digest;
    let mut lost = 0_u64;
    let mut retained_counters = EncryptionOperationalCounters::default();
    let mut latest_generation = Revision::INITIAL;
    for (offset, record) in checkpoint.records.iter().enumerate() {
        let sequence = checkpoint
            .evicted_records
            .checked_add(offset as u64)
            .and_then(|value| value.checked_add(1))
            .ok_or(EncryptionOperationsError::CounterExhausted)?;
        validate_entry(&record.entry)?;
        latest_generation = latest_generation.max(entry_generation(&record.entry));
        if record.sequence != sequence || record.previous_record_digest != previous {
            return Err(EncryptionOperationsError::NoncanonicalCheckpoint);
        }
        if record.record_digest != record_digest(record)? {
            return Err(EncryptionOperationsError::InvalidDigest);
        }
        if let EncryptionOperationsHistoryEntry::ObservationLoss {
            omitted_observations,
            ..
        } = record.entry
        {
            lost = lost
                .checked_add(omitted_observations)
                .ok_or(EncryptionOperationsError::CounterExhausted)?;
            retained_counters.increment(
                EncryptionOperationalStage::Lifecycle,
                EncryptionOperationalOutcome::Loss,
                omitted_observations,
            )?;
        } else if let EncryptionOperationsHistoryEntry::Observation { observation } = &record.entry
        {
            retained_counters.increment(observation.stage, observation.outcome, 1)?;
        }
        previous = record.record_digest;
    }
    if latest_generation != checkpoint.generation
        || lost > checkpoint.reported_lost_observations
        || checkpoint.counters.get(
            EncryptionOperationalStage::Lifecycle,
            EncryptionOperationalOutcome::Loss,
        ) != checkpoint.reported_lost_observations
        || EncryptionOperationalStage::ALL.into_iter().any(|stage| {
            EncryptionOperationalOutcome::ALL
                .into_iter()
                .any(|outcome| {
                    retained_counters.get(stage, outcome) > checkpoint.counters.get(stage, outcome)
                })
        })
    {
        return Err(EncryptionOperationsError::NoncanonicalCheckpoint);
    }
    Ok(())
}

fn validate_entry(
    entry: &EncryptionOperationsHistoryEntry,
) -> Result<(), EncryptionOperationsError> {
    match entry {
        EncryptionOperationsHistoryEntry::Observation { observation } => observation.validate(),
        EncryptionOperationsHistoryEntry::ObservationLoss {
            observed_at_unix_ms,
            generation,
            omitted_observations,
            ..
        } if *observed_at_unix_ms != 0
            && *generation != Revision::INITIAL
            && *omitted_observations != 0 =>
        {
            Ok(())
        }
        EncryptionOperationsHistoryEntry::ObservationLoss { .. } => {
            Err(EncryptionOperationsError::InvalidLoss)
        }
    }
}

fn entry_generation(entry: &EncryptionOperationsHistoryEntry) -> Revision {
    match entry {
        EncryptionOperationsHistoryEntry::Observation { observation } => observation.generation,
        EncryptionOperationsHistoryEntry::ObservationLoss { generation, .. } => *generation,
    }
}

fn entry_time(entry: &EncryptionOperationsHistoryEntry) -> u64 {
    match entry {
        EncryptionOperationsHistoryEntry::Observation { observation } => {
            observation.observed_at_unix_ms
        }
        EncryptionOperationsHistoryEntry::ObservationLoss {
            observed_at_unix_ms,
            ..
        } => *observed_at_unix_ms,
    }
}

const fn entry_observation_count(entry: &EncryptionOperationsHistoryEntry) -> u64 {
    match entry {
        EncryptionOperationsHistoryEntry::Observation { .. } => 1,
        EncryptionOperationsHistoryEntry::ObservationLoss {
            omitted_observations,
            ..
        } => *omitted_observations,
    }
}

fn record_digest(
    record: &EncryptionOperationsHistoryRecord,
) -> Result<EncryptionOperationsHistoryDigest, EncryptionOperationsError> {
    #[derive(Serialize)]
    struct Seal<'a> {
        domain: &'a [u8],
        sequence: u64,
        entry: &'a EncryptionOperationsHistoryEntry,
        previous_record_digest: EncryptionOperationsHistoryDigest,
    }
    let bytes = serde_json::to_vec(&Seal {
        domain: HISTORY_DOMAIN,
        sequence: record.sequence,
        entry: &record.entry,
        previous_record_digest: record.previous_record_digest,
    })
    .map_err(|error| EncryptionOperationsError::Encoding(error.to_string()))?;
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    Ok(EncryptionOperationsHistoryDigest(hasher.finalize().into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(value: u8) -> AttestedEncryptionContractDigest {
        AttestedEncryptionContractDigest([value; 32])
    }

    fn observation(
        generation: u64,
        stage: EncryptionOperationalStage,
        outcome: EncryptionOperationalOutcome,
    ) -> EncryptionOperationalObservation {
        let requirement = stage == EncryptionOperationalStage::Requirement;
        EncryptionOperationalObservation::issue(
            10_000 + generation,
            Revision::new(generation),
            stage,
            outcome,
            (!requirement).then(|| digest(generation.to_le_bytes()[0])),
            (!requirement).then_some(generation),
        )
        .expect("fixture observation is valid")
    }

    #[test]
    fn fixed_cardinality_watermark_is_loss_explicit_and_secret_free() {
        let mut ledger = EncryptionOperationsLedger::default();
        ledger
            .observe(observation(
                1,
                EncryptionOperationalStage::Requirement,
                EncryptionOperationalOutcome::Required,
            ))
            .unwrap();
        ledger
            .observe(observation(
                1,
                EncryptionOperationalStage::Assignment,
                EncryptionOperationalOutcome::Pending,
            ))
            .unwrap();
        ledger
            .record_loss(
                10_002,
                Revision::new(2),
                EncryptionObservationLossReason::QueuePressure,
                7,
            )
            .unwrap();

        let status = ledger.status(10_003).unwrap();
        assert_eq!(
            status.counters.get(
                EncryptionOperationalStage::Requirement,
                EncryptionOperationalOutcome::Required
            ),
            1
        );
        assert_eq!(
            status.counters.get(
                EncryptionOperationalStage::Lifecycle,
                EncryptionOperationalOutcome::Loss
            ),
            7
        );
        assert!(status.loss_affected);
        assert_eq!(status.complete_through_sequence, 3);
        let encoded = serde_json::to_string(&ledger.checkpoint()).unwrap();
        for forbidden in [
            "privateKey",
            "publicKey",
            "nonce",
            "challenge",
            "permit",
            "nodeName",
            "address",
        ] {
            assert!(!encoded.contains(forbidden));
        }
        assert_eq!(
            ENCRYPTION_OPERATIONAL_STAGE_COUNT * ENCRYPTION_OPERATIONAL_OUTCOME_COUNT,
            54
        );
    }

    #[test]
    fn bounded_history_preserves_a_verifiable_eviction_anchor() {
        let mut ledger = EncryptionOperationsLedger::default();
        for generation in 1..=(ENCRYPTION_OPERATIONS_HISTORY_CAPACITY as u64 + 2) {
            ledger
                .observe(observation(
                    generation,
                    EncryptionOperationalStage::Requirement,
                    EncryptionOperationalOutcome::Required,
                ))
                .unwrap();
        }
        let checkpoint = ledger.checkpoint();
        assert_eq!(
            checkpoint.records.len(),
            ENCRYPTION_OPERATIONS_HISTORY_CAPACITY
        );
        assert_eq!(checkpoint.evicted_records, 2);
        assert_eq!(checkpoint.evicted_observations, 2);
        assert_ne!(
            checkpoint.anchor_digest,
            EncryptionOperationsHistoryDigest::default()
        );
        let restored = EncryptionOperationsLedger::restore(checkpoint.clone()).unwrap();
        let status = restored.status(20_000).unwrap();
        assert!(status.loss_affected);
        assert_eq!(status.evicted_observations, 2);
        assert_eq!(restored.checkpoint(), checkpoint);
    }

    #[test]
    fn mutation_regression_and_invalid_stage_outcome_fail_closed() {
        assert!(
            EncryptionOperationalObservation::issue(
                1,
                Revision::new(1),
                EncryptionOperationalStage::Activation,
                EncryptionOperationalOutcome::Native,
                Some(digest(1)),
                Some(1),
            )
            .is_err()
        );

        let mut ledger = EncryptionOperationsLedger::default();
        ledger
            .observe(observation(
                2,
                EncryptionOperationalStage::Activation,
                EncryptionOperationalOutcome::Activated,
            ))
            .unwrap();
        assert_eq!(
            ledger.observe(observation(
                1,
                EncryptionOperationalStage::Requirement,
                EncryptionOperationalOutcome::Required,
            )),
            Err(EncryptionOperationsError::GenerationRegression)
        );

        let mut checkpoint = ledger.checkpoint();
        checkpoint.records[0].entry = EncryptionOperationsHistoryEntry::ObservationLoss {
            observed_at_unix_ms: 1,
            generation: Revision::new(2),
            reason: EncryptionObservationLossReason::DecodeRejected,
            omitted_observations: 1,
        };
        assert_eq!(
            EncryptionOperationsLedger::restore(checkpoint).unwrap_err(),
            EncryptionOperationsError::InvalidDigest
        );
    }

    #[test]
    fn strict_wire_contract_rejects_unknown_fields() {
        let observation = observation(
            1,
            EncryptionOperationalStage::Assignment,
            EncryptionOperationalOutcome::Pending,
        );
        let mut value = serde_json::to_value(observation).unwrap();
        value["privateKey"] = serde_json::json!("must-not-be-accepted");
        assert!(serde_json::from_value::<EncryptionOperationalObservation>(value).is_err());
    }

    #[test]
    fn activation_report_is_retry_stable_strict_and_non_authoritative() {
        let recipient = EncryptionGenerationRecipient {
            node_name: "worker-a".to_owned(),
            node_uid: "worker-a-uid".to_owned(),
        };
        let report = EncryptionActivationReport::issue(
            recipient,
            Revision::new(7),
            EncryptionFastPathDigest([9; 32]),
            12_000,
            &[],
        )
        .unwrap();
        report.verify().unwrap();
        let replay = EncryptionActivationReport::issue(
            report.recipient.clone(),
            report.generation,
            report.state_digest,
            report.activated_at_unix_ms,
            &[],
        )
        .unwrap();
        assert_eq!(replay.report_digest, report.report_digest);
        let mut mutation = report.clone();
        mutation.activated_at_unix_ms += 1;
        assert_eq!(
            mutation.verify(),
            Err(EncryptionOperationsError::InvalidActivationReport)
        );
        let encoded = serde_json::to_string(&report).unwrap();
        for forbidden in ["privateKey", "publicKey", "nonce", "challenge", "permit"] {
            assert!(!encoded.contains(forbidden));
        }
        let mut unknown = serde_json::to_value(report).unwrap();
        unknown["activationPermit"] = serde_json::json!("forbidden");
        assert!(serde_json::from_value::<EncryptionActivationReport>(unknown).is_err());
    }

    #[test]
    fn activation_testimony_request_is_strict_and_carries_no_authority() {
        let request = EncryptionActivationTestimonyRequest::issue(
            EncryptionGenerationRecipient {
                node_name: "worker-a".to_owned(),
                node_uid: "worker-a-uid".to_owned(),
            },
            Revision::new(7),
            EncryptionFastPathDigest([9; 32]),
            true,
        )
        .unwrap();
        request.verify().unwrap();
        let encoded = serde_json::to_string(&request).unwrap();
        for forbidden in ["privateKey", "publicKey", "permit", "witness", "receipt"] {
            assert!(!encoded.contains(forbidden));
        }
        let mut unknown = serde_json::to_value(request).unwrap();
        unknown["activationPermit"] = serde_json::json!("forbidden");
        assert!(serde_json::from_value::<EncryptionActivationTestimonyRequest>(unknown).is_err());
    }
}
