//! Read-only, loss-explicit operations evidence for the egress fabric.

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use unf_common::Revision;

use crate::{
    EgressHaControlPlanePromotion, EgressHaDigest, EgressHaOldOwnerFenceEvidence, EgressHaPlan,
    EgressHaPromotionDigest, EgressIntentOwner, EgressNode,
};

pub const EGRESS_HA_HISTORY_SCHEMA_VERSION: u16 = 1;
pub const EGRESS_HA_HISTORY_CAPACITY: usize = 256;
const EGRESS_HA_HISTORY_DOMAIN: &[u8] = b"unf.egress.ha.history.v1\0";

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EgressHaHistoryDigest(pub [u8; 32]);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum EgressHaFenceKind {
    KernelRevocation,
    Infrastructure,
}

/// Compact terminal proof for one completed failover. It intentionally carries
/// no activation or ownership capability.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EgressHaHistoryRecord {
    pub sequence: u64,
    pub completed_unix_ms: u64,
    pub owner: EgressIntentOwner,
    pub controller_epoch: u64,
    pub promotion_epoch: u64,
    pub authority_revision: Revision,
    pub allocation_revision: Revision,
    pub lease_epoch: u64,
    pub failed_gateway: EgressNode,
    pub manifest_digest: EgressHaPromotionDigest,
    pub previous_plan_digest: EgressHaDigest,
    pub replacement_plan_digest: Option<EgressHaDigest>,
    pub authority_digest: EgressHaPromotionDigest,
    pub fence_kind: EgressHaFenceKind,
    pub source_count: u32,
    pub activated_source_count: u32,
    pub moved_shards: u16,
    pub flow_stream_count: u16,
    pub acknowledged_flow_twins: u64,
    pub previous_record_digest: EgressHaHistoryDigest,
    pub record_digest: EgressHaHistoryDigest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EgressHaHistoryCheckpoint {
    pub schema_version: u16,
    pub revision: u64,
    pub evicted_records: u64,
    pub anchor_digest: EgressHaHistoryDigest,
    pub records: Vec<EgressHaHistoryRecord>,
}

impl Default for EgressHaHistoryCheckpoint {
    fn default() -> Self {
        Self {
            schema_version: EGRESS_HA_HISTORY_SCHEMA_VERSION,
            revision: 0,
            evicted_records: 0,
            anchor_digest: EgressHaHistoryDigest::default(),
            records: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum EgressHaHistoryError {
    #[error("unsupported egress HA history schema")]
    UnsupportedSchema,
    #[error("egress HA history checkpoint is oversized or noncanonical")]
    NoncanonicalCheckpoint,
    #[error("egress HA history record is incomplete or digest-invalid")]
    InvalidRecord,
    #[error("egress HA history counter is exhausted")]
    CounterExhausted,
    #[error("egress HA history encoding failed: {0}")]
    Encoding(String),
}

#[derive(Debug, Clone, Default)]
pub struct EgressHaHistory {
    revision: u64,
    evicted_records: u64,
    anchor_digest: EgressHaHistoryDigest,
    records: Vec<EgressHaHistoryRecord>,
}

impl EgressHaHistory {
    /// Replays a complete bounded terminal-history checkpoint and verifies its
    /// sequence, eviction anchor, and every chained record digest.
    ///
    /// # Errors
    ///
    /// Rejects unsupported, oversized, discontinuous, overflowed, or
    /// digest-invalid history without returning partial state.
    pub fn restore(checkpoint: EgressHaHistoryCheckpoint) -> Result<Self, EgressHaHistoryError> {
        if checkpoint.schema_version != EGRESS_HA_HISTORY_SCHEMA_VERSION {
            return Err(EgressHaHistoryError::UnsupportedSchema);
        }
        if checkpoint.records.len() > EGRESS_HA_HISTORY_CAPACITY
            || checkpoint.revision
                != checkpoint
                    .evicted_records
                    .saturating_add(checkpoint.records.len() as u64)
            || checkpoint.evicted_records == 0
                && checkpoint.anchor_digest != EgressHaHistoryDigest::default()
            || checkpoint.evicted_records != 0 && checkpoint.records.is_empty()
        {
            return Err(EgressHaHistoryError::NoncanonicalCheckpoint);
        }
        let mut previous = checkpoint.anchor_digest;
        for (offset, record) in checkpoint.records.iter().enumerate() {
            let expected_sequence = checkpoint
                .evicted_records
                .checked_add(offset as u64)
                .and_then(|value| value.checked_add(1))
                .ok_or(EgressHaHistoryError::CounterExhausted)?;
            if record.sequence != expected_sequence || record.previous_record_digest != previous {
                return Err(EgressHaHistoryError::NoncanonicalCheckpoint);
            }
            record.verify()?;
            previous = record.record_digest;
        }
        Ok(Self {
            revision: checkpoint.revision,
            evicted_records: checkpoint.evicted_records,
            anchor_digest: checkpoint.anchor_digest,
            records: checkpoint.records,
        })
    }

    /// Appends one terminal promotion proof and advances bounded history.
    ///
    /// # Errors
    ///
    /// Rejects a non-terminal promotion, missing fence/activation evidence,
    /// invalid timestamp, counter exhaustion, or canonical encoding failure.
    pub fn append_completed(
        &mut self,
        promotion: &EgressHaControlPlanePromotion,
        replacement_plan: Option<&EgressHaPlan>,
        completed_unix_ms: u64,
    ) -> Result<EgressHaHistoryRecord, EgressHaHistoryError> {
        let sequence = self
            .revision
            .checked_add(1)
            .ok_or(EgressHaHistoryError::CounterExhausted)?;
        let previous = self
            .records
            .last()
            .map_or(self.anchor_digest, |record| record.record_digest);
        let record = EgressHaHistoryRecord::issue(
            sequence,
            completed_unix_ms,
            previous,
            promotion,
            replacement_plan,
        )?;
        self.records.push(record.clone());
        self.revision = sequence;
        if self.records.len() > EGRESS_HA_HISTORY_CAPACITY {
            let evicted = self.records.remove(0);
            self.anchor_digest = evicted.record_digest;
            self.evicted_records = self
                .evicted_records
                .checked_add(1)
                .ok_or(EgressHaHistoryError::CounterExhausted)?;
        }
        Ok(record)
    }

    #[must_use]
    pub fn checkpoint(&self) -> EgressHaHistoryCheckpoint {
        EgressHaHistoryCheckpoint {
            schema_version: EGRESS_HA_HISTORY_SCHEMA_VERSION,
            revision: self.revision,
            evicted_records: self.evicted_records,
            anchor_digest: self.anchor_digest,
            records: self.records.clone(),
        }
    }
}

impl EgressHaHistoryRecord {
    fn issue(
        sequence: u64,
        completed_unix_ms: u64,
        previous_record_digest: EgressHaHistoryDigest,
        promotion: &EgressHaControlPlanePromotion,
        replacement_plan: Option<&EgressHaPlan>,
    ) -> Result<Self, EgressHaHistoryError> {
        let manifest = &promotion.coordinator.manifest;
        let authority_digest = promotion
            .source_activations
            .first()
            .map(|evidence| evidence.authority_digest)
            .ok_or(EgressHaHistoryError::InvalidRecord)?;
        let fence_kind = match promotion.coordinator.old_owner_fence.as_ref() {
            Some(EgressHaOldOwnerFenceEvidence::Revocation(_)) => {
                EgressHaFenceKind::KernelRevocation
            }
            Some(EgressHaOldOwnerFenceEvidence::Infrastructure(_)) => {
                EgressHaFenceKind::Infrastructure
            }
            None => return Err(EgressHaHistoryError::InvalidRecord),
        };
        let source_count = u32::try_from(manifest.sources.len())
            .map_err(|_| EgressHaHistoryError::InvalidRecord)?;
        let activated_source_count = u32::try_from(promotion.source_activations.len())
            .map_err(|_| EgressHaHistoryError::InvalidRecord)?;
        let moved_shards = u16::try_from(manifest.handoffs.len())
            .map_err(|_| EgressHaHistoryError::InvalidRecord)?;
        let flow_stream_count = u16::try_from(promotion.flow_streams.len())
            .map_err(|_| EgressHaHistoryError::InvalidRecord)?;
        if completed_unix_ms == 0
            || source_count == 0
            || activated_source_count != source_count
            || promotion.cutovers.len() != manifest.sources.len()
        {
            return Err(EgressHaHistoryError::InvalidRecord);
        }
        let mut record = Self {
            sequence,
            completed_unix_ms,
            owner: manifest.owner.clone(),
            controller_epoch: manifest.controller_epoch,
            promotion_epoch: manifest.promotion_epoch,
            authority_revision: manifest.authority_revision,
            allocation_revision: manifest.allocation_revision,
            lease_epoch: manifest.lease_epoch,
            failed_gateway: manifest.failed_gateway.clone(),
            manifest_digest: manifest.manifest_digest,
            previous_plan_digest: promotion.previous_plan.plan_digest,
            replacement_plan_digest: replacement_plan.map(|plan| plan.plan_digest),
            authority_digest,
            fence_kind,
            source_count,
            activated_source_count,
            moved_shards,
            flow_stream_count,
            acknowledged_flow_twins: promotion
                .flow_acknowledgements
                .iter()
                .map(|acknowledgement| u64::from(acknowledgement.record_count))
                .fold(0_u64, u64::saturating_add),
            previous_record_digest,
            record_digest: EgressHaHistoryDigest::default(),
        };
        record.record_digest = record.calculate_digest()?;
        Ok(record)
    }

    fn verify(&self) -> Result<(), EgressHaHistoryError> {
        if self.sequence == 0
            || self.completed_unix_ms == 0
            || self.controller_epoch == 0
            || self.promotion_epoch == 0
            || self.authority_revision == Revision::INITIAL
            || self.allocation_revision == Revision::INITIAL
            || self.lease_epoch == 0
            || self.failed_gateway.name.is_empty()
            || self.failed_gateway.uid.is_empty()
            || self.source_count == 0
            || self.activated_source_count != self.source_count
            || self.moved_shards == 0
            || self.record_digest != self.calculate_digest()?
        {
            return Err(EgressHaHistoryError::InvalidRecord);
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Result<EgressHaHistoryDigest, EgressHaHistoryError> {
        #[derive(Serialize)]
        struct Seal<'a> {
            domain: &'a [u8],
            sequence: u64,
            completed_unix_ms: u64,
            owner: &'a EgressIntentOwner,
            controller_epoch: u64,
            promotion_epoch: u64,
            authority_revision: Revision,
            allocation_revision: Revision,
            lease_epoch: u64,
            failed_gateway: &'a EgressNode,
            manifest_digest: EgressHaPromotionDigest,
            previous_plan_digest: EgressHaDigest,
            replacement_plan_digest: Option<EgressHaDigest>,
            authority_digest: EgressHaPromotionDigest,
            fence_kind: EgressHaFenceKind,
            source_count: u32,
            activated_source_count: u32,
            moved_shards: u16,
            flow_stream_count: u16,
            acknowledged_flow_twins: u64,
            previous_record_digest: EgressHaHistoryDigest,
        }
        let encoded = serde_json::to_vec(&Seal {
            domain: EGRESS_HA_HISTORY_DOMAIN,
            sequence: self.sequence,
            completed_unix_ms: self.completed_unix_ms,
            owner: &self.owner,
            controller_epoch: self.controller_epoch,
            promotion_epoch: self.promotion_epoch,
            authority_revision: self.authority_revision,
            allocation_revision: self.allocation_revision,
            lease_epoch: self.lease_epoch,
            failed_gateway: &self.failed_gateway,
            manifest_digest: self.manifest_digest,
            previous_plan_digest: self.previous_plan_digest,
            replacement_plan_digest: self.replacement_plan_digest,
            authority_digest: self.authority_digest,
            fence_kind: self.fence_kind,
            source_count: self.source_count,
            activated_source_count: self.activated_source_count,
            moved_shards: self.moved_shards,
            flow_stream_count: self.flow_stream_count,
            acknowledged_flow_twins: self.acknowledged_flow_twins,
            previous_record_digest: self.previous_record_digest,
        })
        .map_err(|error| EgressHaHistoryError::Encoding(error.to_string()))?;
        let mut hasher = Sha256::new();
        hasher.update(encoded);
        Ok(EgressHaHistoryDigest(hasher.finalize().into()))
    }
}
