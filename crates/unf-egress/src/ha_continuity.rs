//! Acknowledged flow-twin ledgers for bounded established-flow continuity.
//!
//! Each primary-to-standby stream is an ordered hash chain. A promotion imports
//! only complete, live, acknowledged NAT mappings whose immutable tuple and
//! lease provenance match an exact CCR shard handoff.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use unf_common::{IdentityId, Revision};
use unf_ebpf_common::{CONNECTION_TCP_TIMEOUT_NS, CONNECTION_UDP_TIMEOUT_NS};

use crate::{
    EGRESS_HA_PROMOTION_SCHEMA_VERSION, EgressContractDigest, EgressHaActivationAuthority,
    EgressHaDigest, EgressHaPromotionDigest, EgressHaPromotionManifest, EgressNode,
};

pub const EGRESS_HA_CONTINUITY_SCHEMA_VERSION: u16 = 2;
pub const MAX_EGRESS_HA_TWIN_RECORDS: usize = 262_144 / 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EgressHaFlowId(pub [u8; 32]);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EgressHaContinuityDigest(pub [u8; 32]);

/// Immutable NAT mapping plus the only mutable liveness timestamp. Forward and
/// reverse entries are represented together, so a half-pair cannot transfer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EgressHaFlowTwin {
    pub flow_id: EgressHaFlowId,
    pub shard_index: u16,
    pub source_identity: IdentityId,
    pub protocol: u8,
    pub original_source_address: IpAddr,
    pub original_destination_address: IpAddr,
    pub original_source_port: u16,
    pub original_destination_port: u16,
    pub egress_address: IpAddr,
    pub translated_source_port: u16,
    pub contract_revision: Revision,
    pub contract_digest: EgressContractDigest,
    pub proof_witness: [u8; 16],
    pub lease_epoch: u64,
    pub last_seen_ns: u64,
    /// Portable wall-clock deadline converted conservatively from the source
    /// Node's monotonic ABI value and re-anchored by the standby Node.
    pub established_flows_until_unix_seconds: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase", tag = "operation")]
pub enum EgressHaFlowTwinOperation {
    Upsert(EgressHaFlowTwin),
    Remove { flow_id: EgressHaFlowId },
}

/// One strictly ordered primary delta. Hash chaining makes loss, reordering,
/// replay, and divergent standby state explicit at the acknowledgement point.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EgressHaFlowTwinDelta {
    pub schema_version: u16,
    pub sequence: u64,
    pub previous_digest: EgressHaContinuityDigest,
    pub operation: EgressHaFlowTwinOperation,
    pub delta_digest: EgressHaContinuityDigest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EgressHaFlowTwinStream {
    pub schema_version: u16,
    pub controller_epoch: u64,
    pub stream_epoch: u64,
    pub owner_plan_digest: EgressHaDigest,
    pub primary_gateway: EgressNode,
    pub standby_gateway: EgressNode,
    pub shard_indexes: Vec<u16>,
    pub sequence: u64,
    pub chain_digest: EgressHaContinuityDigest,
    pub records: Vec<EgressHaFlowTwin>,
    pub snapshot_digest: EgressHaContinuityDigest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EgressHaFlowTwinAcknowledgement {
    pub schema_version: u16,
    pub controller_epoch: u64,
    pub stream_epoch: u64,
    pub owner_plan_digest: EgressHaDigest,
    pub primary_gateway: EgressNode,
    pub standby_gateway: EgressNode,
    pub sequence: u64,
    pub chain_digest: EgressHaContinuityDigest,
    pub record_count: u32,
    pub snapshot_digest: EgressHaContinuityDigest,
    pub replica_revision: Revision,
    pub acknowledgement_digest: EgressHaContinuityDigest,
}

/// Import capability for the replacement gateway. Only these complete records
/// may receive `STANDBY_ACTIVE` before the source bank switches.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EgressHaContinuityCutover {
    pub schema_version: u16,
    pub promotion_digest: EgressHaPromotionDigest,
    pub activation_authority_digest: EgressHaPromotionDigest,
    pub active_plan_digest: EgressHaDigest,
    pub contingency_digest: EgressHaDigest,
    pub cutoff_ns: u64,
    pub target_source_bank: u8,
    pub streams: Vec<EgressHaFlowTwinStream>,
    pub acknowledgements: Vec<EgressHaFlowTwinAcknowledgement>,
    pub import_records: Vec<EgressHaFlowTwin>,
    pub cutover_digest: EgressHaContinuityDigest,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum EgressHaContinuityError {
    #[error("HA flow twin stream authority is invalid")]
    InvalidAuthority,
    #[error("HA flow twin delta is stale, reordered, duplicated, or mutated")]
    InvalidDelta,
    #[error("HA flow twin record is invalid or outside its exact shard handoff")]
    InvalidRecord,
    #[error("HA flow twin acknowledgement is incomplete or does not match replica state")]
    AcknowledgementMismatch,
    #[error("HA continuity cutover is incomplete, ambiguous, or expired")]
    CutoverMismatch,
    #[error("HA continuity encoding failed: {0}")]
    Encoding(String),
}

impl EgressHaFlowTwin {
    /// Constructs and seals the immutable flow identity.
    ///
    /// # Errors
    ///
    /// Rejects malformed tuples, protocols, revisions, ports, or timestamps.
    #[allow(clippy::too_many_arguments)]
    pub fn issue(
        shard_index: u16,
        source_identity: IdentityId,
        protocol: u8,
        original_source_address: IpAddr,
        original_destination_address: IpAddr,
        original_source_port: u16,
        original_destination_port: u16,
        egress_address: IpAddr,
        translated_source_port: u16,
        contract_revision: Revision,
        contract_digest: EgressContractDigest,
        proof_witness: [u8; 16],
        lease_epoch: u64,
        last_seen_ns: u64,
        established_flows_until_unix_seconds: u64,
    ) -> Result<Self, EgressHaContinuityError> {
        let mut record = Self {
            flow_id: EgressHaFlowId([0; 32]),
            shard_index,
            source_identity,
            protocol,
            original_source_address,
            original_destination_address,
            original_source_port,
            original_destination_port,
            egress_address,
            translated_source_port,
            contract_revision,
            contract_digest,
            proof_witness,
            lease_epoch,
            last_seen_ns,
            established_flows_until_unix_seconds,
        };
        record.validate_fields()?;
        record.flow_id = record.compute_flow_id()?;
        Ok(record)
    }

    /// Replays field and immutable flow-ID validation.
    ///
    /// # Errors
    ///
    /// Rejects mutated or malformed records.
    pub fn verify(&self) -> Result<(), EgressHaContinuityError> {
        self.validate_fields()?;
        if self.flow_id != self.compute_flow_id()? {
            return Err(EgressHaContinuityError::InvalidRecord);
        }
        Ok(())
    }

    #[must_use]
    pub const fn timeout_ns(&self) -> u64 {
        match self.protocol {
            6 => CONNECTION_TCP_TIMEOUT_NS,
            17 => CONNECTION_UDP_TIMEOUT_NS,
            _ => 0,
        }
    }

    #[must_use]
    pub const fn is_live_at(&self, cutoff_ns: u64) -> bool {
        cutoff_ns.saturating_sub(self.last_seen_ns) <= self.timeout_ns()
    }

    fn validate_fields(&self) -> Result<(), EgressHaContinuityError> {
        if self.source_identity.get() == 0
            || !matches!(self.protocol, 6 | 17)
            || self.original_source_address.is_ipv4() != self.original_destination_address.is_ipv4()
            || self.original_source_address.is_ipv4() != self.egress_address.is_ipv4()
            || self.original_source_address.is_unspecified()
            || self.original_destination_address.is_unspecified()
            || self.egress_address.is_unspecified()
            || self.original_source_port == 0
            || self.original_destination_port == 0
            || self.translated_source_port < unf_ebpf_common::EGRESS_SNAT_PORT_BASE
            || self.contract_revision == Revision::INITIAL
            || self.contract_digest.0 == [0; 32]
            || self.proof_witness == [0; 16]
            || self.lease_epoch == 0
            || self.last_seen_ns == 0
            || self.established_flows_until_unix_seconds == 0
        {
            return Err(EgressHaContinuityError::InvalidRecord);
        }
        Ok(())
    }

    fn compute_flow_id(&self) -> Result<EgressHaFlowId, EgressHaContinuityError> {
        Ok(EgressHaFlowId(digest_bytes(
            b"unf.egress-ha-flow-twin-id.v1\0",
            &(
                self.shard_index,
                self.source_identity,
                self.protocol,
                self.original_source_address,
                self.original_destination_address,
                self.original_source_port,
                self.original_destination_port,
                self.egress_address,
                self.translated_source_port,
                self.contract_revision,
                self.contract_digest,
                self.proof_witness,
                self.lease_epoch,
                self.established_flows_until_unix_seconds,
            ),
        )?))
    }
}

impl EgressHaFlowTwinDelta {
    /// Seals the next ordered operation for a stream.
    ///
    /// # Errors
    ///
    /// Rejects sequence overflow or an invalid flow record.
    pub fn issue(
        sequence: u64,
        previous_digest: EgressHaContinuityDigest,
        operation: EgressHaFlowTwinOperation,
    ) -> Result<Self, EgressHaContinuityError> {
        if sequence == 0 {
            return Err(EgressHaContinuityError::InvalidDelta);
        }
        if let EgressHaFlowTwinOperation::Upsert(record) = &operation {
            record.verify()?;
        }
        let mut delta = Self {
            schema_version: EGRESS_HA_CONTINUITY_SCHEMA_VERSION,
            sequence,
            previous_digest,
            operation,
            delta_digest: EgressHaContinuityDigest([0; 32]),
        };
        delta.delta_digest = continuity_digest(&(
            delta.schema_version,
            delta.sequence,
            delta.previous_digest,
            &delta.operation,
        ))?;
        Ok(delta)
    }
}

impl EgressHaFlowTwinStream {
    /// Starts an empty, exact handoff stream.
    ///
    /// # Errors
    ///
    /// Rejects invalid epochs, gateways, plans, or shard ordering.
    pub fn issue(
        manifest: &EgressHaPromotionManifest,
        primary_gateway: EgressNode,
        standby_gateway: EgressNode,
        mut shard_indexes: Vec<u16>,
        stream_epoch: u64,
    ) -> Result<Self, EgressHaContinuityError> {
        shard_indexes.sort_unstable();
        if manifest.schema_version != EGRESS_HA_PROMOTION_SCHEMA_VERSION
            || manifest.controller_epoch == 0
            || stream_epoch == 0
            || primary_gateway == standby_gateway
            || shard_indexes.is_empty()
            || shard_indexes.windows(2).any(|pair| pair[0] == pair[1])
            || !exact_stream_handoff(manifest, &primary_gateway, &standby_gateway, &shard_indexes)
        {
            return Err(EgressHaContinuityError::InvalidAuthority);
        }
        let mut stream = Self {
            schema_version: EGRESS_HA_CONTINUITY_SCHEMA_VERSION,
            controller_epoch: manifest.controller_epoch,
            stream_epoch,
            owner_plan_digest: manifest.active_plan_digest,
            primary_gateway,
            standby_gateway,
            shard_indexes,
            sequence: 0,
            chain_digest: EgressHaContinuityDigest([0; 32]),
            records: Vec::new(),
            snapshot_digest: EgressHaContinuityDigest([0; 32]),
        };
        stream.reseal()?;
        Ok(stream)
    }

    /// Issues the next operation against the current chain head.
    ///
    /// # Errors
    ///
    /// Rejects sequence overflow or invalid record content.
    pub fn next_delta(
        &self,
        operation: EgressHaFlowTwinOperation,
    ) -> Result<EgressHaFlowTwinDelta, EgressHaContinuityError> {
        EgressHaFlowTwinDelta::issue(
            self.sequence
                .checked_add(1)
                .ok_or(EgressHaContinuityError::InvalidDelta)?,
            self.chain_digest,
            operation,
        )
    }

    /// Applies one exact ordered delta. Primary and standby run this same code.
    ///
    /// # Errors
    ///
    /// Rejects loss, replay, mutation, invalid shard/lease state, or capacity.
    pub fn apply(
        &mut self,
        manifest: &EgressHaPromotionManifest,
        delta: &EgressHaFlowTwinDelta,
    ) -> Result<(), EgressHaContinuityError> {
        self.verify(manifest)?;
        let expected = EgressHaFlowTwinDelta::issue(
            self.sequence
                .checked_add(1)
                .ok_or(EgressHaContinuityError::InvalidDelta)?,
            self.chain_digest,
            delta.operation.clone(),
        )?;
        if &expected != delta {
            return Err(EgressHaContinuityError::InvalidDelta);
        }
        let mut records = self
            .records
            .iter()
            .cloned()
            .map(|record| (record.flow_id, record))
            .collect::<BTreeMap<_, _>>();
        match &delta.operation {
            EgressHaFlowTwinOperation::Upsert(record) => {
                validate_record_for_stream(record, self, manifest)?;
                if let Some(current) = records.get(&record.flow_id)
                    && record.last_seen_ns < current.last_seen_ns
                {
                    return Err(EgressHaContinuityError::InvalidRecord);
                }
                records.insert(record.flow_id, record.clone());
            }
            EgressHaFlowTwinOperation::Remove { flow_id } => {
                if records.remove(flow_id).is_none() {
                    return Err(EgressHaContinuityError::InvalidDelta);
                }
            }
        }
        if records.len() > MAX_EGRESS_HA_TWIN_RECORDS {
            return Err(EgressHaContinuityError::InvalidRecord);
        }
        self.records = records.into_values().collect();
        self.sequence = delta.sequence;
        self.chain_digest = delta.delta_digest;
        self.reseal()?;
        Ok(())
    }

    /// Verifies authority, canonical records, and the snapshot seal.
    ///
    /// # Errors
    ///
    /// Rejects foreign handoffs, records, ordering, or mutation.
    pub fn verify(
        &self,
        manifest: &EgressHaPromotionManifest,
    ) -> Result<(), EgressHaContinuityError> {
        if self.schema_version != EGRESS_HA_CONTINUITY_SCHEMA_VERSION
            || self.controller_epoch != manifest.controller_epoch
            || self.stream_epoch == 0
            || self.owner_plan_digest != manifest.active_plan_digest
            || self.primary_gateway == self.standby_gateway
            || self.shard_indexes.is_empty()
            || self.shard_indexes.windows(2).any(|pair| pair[0] >= pair[1])
            || self.records.len() > MAX_EGRESS_HA_TWIN_RECORDS
            || self
                .records
                .windows(2)
                .any(|pair| pair[0].flow_id >= pair[1].flow_id)
            || !exact_stream_handoff(
                manifest,
                &self.primary_gateway,
                &self.standby_gateway,
                &self.shard_indexes,
            )
        {
            return Err(EgressHaContinuityError::InvalidAuthority);
        }
        for record in &self.records {
            validate_record_for_stream(record, self, manifest)?;
        }
        if self.snapshot_digest != stream_digest(self)? {
            return Err(EgressHaContinuityError::InvalidAuthority);
        }
        Ok(())
    }

    /// Produces exact standby readback for the current watermark.
    ///
    /// # Errors
    ///
    /// Rejects invalid stream state or zero replica revision.
    pub fn acknowledge(
        &self,
        manifest: &EgressHaPromotionManifest,
        replica_revision: Revision,
    ) -> Result<EgressHaFlowTwinAcknowledgement, EgressHaContinuityError> {
        self.verify(manifest)?;
        if replica_revision == Revision::INITIAL {
            return Err(EgressHaContinuityError::AcknowledgementMismatch);
        }
        let mut ack = EgressHaFlowTwinAcknowledgement {
            schema_version: EGRESS_HA_CONTINUITY_SCHEMA_VERSION,
            controller_epoch: self.controller_epoch,
            stream_epoch: self.stream_epoch,
            owner_plan_digest: self.owner_plan_digest,
            primary_gateway: self.primary_gateway.clone(),
            standby_gateway: self.standby_gateway.clone(),
            sequence: self.sequence,
            chain_digest: self.chain_digest,
            record_count: u32::try_from(self.records.len())
                .map_err(|_| EgressHaContinuityError::AcknowledgementMismatch)?,
            snapshot_digest: self.snapshot_digest,
            replica_revision,
            acknowledgement_digest: EgressHaContinuityDigest([0; 32]),
        };
        ack.acknowledgement_digest = acknowledgement_digest(&ack)?;
        Ok(ack)
    }

    fn reseal(&mut self) -> Result<(), EgressHaContinuityError> {
        self.snapshot_digest = stream_digest(self)?;
        Ok(())
    }
}

impl EgressHaFlowTwinAcknowledgement {
    /// Checks this acknowledgement against exact replica readback.
    ///
    /// # Errors
    ///
    /// Rejects stale, forged, partial, or mismatched state.
    pub fn verify(
        &self,
        stream: &EgressHaFlowTwinStream,
        manifest: &EgressHaPromotionManifest,
    ) -> Result<(), EgressHaContinuityError> {
        stream.verify(manifest)?;
        if self.schema_version != EGRESS_HA_CONTINUITY_SCHEMA_VERSION
            || self.controller_epoch != stream.controller_epoch
            || self.stream_epoch != stream.stream_epoch
            || self.owner_plan_digest != stream.owner_plan_digest
            || self.primary_gateway != stream.primary_gateway
            || self.standby_gateway != stream.standby_gateway
            || self.sequence != stream.sequence
            || self.chain_digest != stream.chain_digest
            || usize::try_from(self.record_count).ok() != Some(stream.records.len())
            || self.snapshot_digest != stream.snapshot_digest
            || self.replica_revision == Revision::INITIAL
            || self.acknowledgement_digest != acknowledgement_digest(self)?
        {
            return Err(EgressHaContinuityError::AcknowledgementMismatch);
        }
        Ok(())
    }
}

impl EgressHaContinuityCutover {
    /// Builds a continuity import bound to a complete promotion authority.
    ///
    /// # Errors
    ///
    /// Rejects missing/mismatched streams or acknowledgements, duplicate flow
    /// identity, expired state resurrection, and invalid target banks.
    pub fn issue(
        authority: &EgressHaActivationAuthority,
        mut streams: Vec<EgressHaFlowTwinStream>,
        mut acknowledgements: Vec<EgressHaFlowTwinAcknowledgement>,
        cutoff_ns: u64,
        target_source_bank: u8,
    ) -> Result<Self, EgressHaContinuityError> {
        authority
            .verify()
            .map_err(|_| EgressHaContinuityError::InvalidAuthority)?;
        if cutoff_ns == 0 || target_source_bank > 1 {
            return Err(EgressHaContinuityError::CutoverMismatch);
        }
        streams.sort_by_key(stream_key);
        acknowledgements.sort_by_key(acknowledgement_key);
        let expected_pairs = handoff_pairs(&authority.manifest);
        if streams.len() != expected_pairs.len()
            || acknowledgements.len() != expected_pairs.len()
            || streams.iter().map(stream_key).collect::<BTreeSet<_>>() != expected_pairs
            || acknowledgements
                .iter()
                .map(acknowledgement_key)
                .collect::<BTreeSet<_>>()
                != expected_pairs
        {
            return Err(EgressHaContinuityError::CutoverMismatch);
        }
        let mut records = BTreeMap::new();
        for (stream, acknowledgement) in streams.iter().zip(&acknowledgements) {
            if stream_key(stream) != acknowledgement_key(acknowledgement) {
                return Err(EgressHaContinuityError::CutoverMismatch);
            }
            acknowledgement.verify(stream, &authority.manifest)?;
            for record in &stream.records {
                if record.is_live_at(cutoff_ns)
                    && records.insert(record.flow_id, record.clone()).is_some()
                {
                    return Err(EgressHaContinuityError::CutoverMismatch);
                }
            }
        }
        let import_records = records.into_values().collect::<Vec<_>>();
        let mut cutover = Self {
            schema_version: EGRESS_HA_CONTINUITY_SCHEMA_VERSION,
            promotion_digest: authority.manifest.manifest_digest,
            activation_authority_digest: authority.authority_digest,
            active_plan_digest: authority.manifest.active_plan_digest,
            contingency_digest: authority.manifest.contingency_digest,
            cutoff_ns,
            target_source_bank,
            streams,
            acknowledgements,
            import_records,
            cutover_digest: EgressHaContinuityDigest([0; 32]),
        };
        cutover.cutover_digest = cutover_material_digest(&cutover)?;
        Ok(cutover)
    }

    /// Replays the complete cutover and compares every field.
    ///
    /// # Errors
    ///
    /// Rejects any mutation or authority mismatch.
    pub fn verify(
        &self,
        authority: &EgressHaActivationAuthority,
    ) -> Result<(), EgressHaContinuityError> {
        if self.schema_version != EGRESS_HA_CONTINUITY_SCHEMA_VERSION
            || self.promotion_digest != authority.manifest.manifest_digest
            || self.activation_authority_digest != authority.authority_digest
            || self.active_plan_digest != authority.manifest.active_plan_digest
            || self.contingency_digest != authority.manifest.contingency_digest
            || self.cutoff_ns == 0
            || self.target_source_bank > 1
        {
            return Err(EgressHaContinuityError::CutoverMismatch);
        }
        let expected = Self::issue(
            authority,
            self.streams.clone(),
            self.acknowledgements.clone(),
            self.cutoff_ns,
            self.target_source_bank,
        )?;
        if &expected == self {
            Ok(())
        } else {
            Err(EgressHaContinuityError::CutoverMismatch)
        }
    }
}

fn validate_record_for_stream(
    record: &EgressHaFlowTwin,
    stream: &EgressHaFlowTwinStream,
    manifest: &EgressHaPromotionManifest,
) -> Result<(), EgressHaContinuityError> {
    record.verify()?;
    let valid_handoff = manifest.handoffs.iter().any(|handoff| {
        handoff.shard_index == record.shard_index
            && handoff.old_gateway == stream.primary_gateway
            && handoff.new_gateway == stream.standby_gateway
            && handoff.addresses.contains(&record.egress_address)
    });
    if record.lease_epoch != manifest.lease_epoch
        || !stream.shard_indexes.contains(&record.shard_index)
        || !valid_handoff
    {
        return Err(EgressHaContinuityError::InvalidRecord);
    }
    Ok(())
}

fn exact_stream_handoff(
    manifest: &EgressHaPromotionManifest,
    primary: &EgressNode,
    standby: &EgressNode,
    shards: &[u16],
) -> bool {
    let expected = manifest
        .handoffs
        .iter()
        .filter(|handoff| handoff.old_gateway == *primary && handoff.new_gateway == *standby)
        .map(|handoff| handoff.shard_index)
        .collect::<Vec<_>>();
    expected == shards
}

fn stream_key(stream: &EgressHaFlowTwinStream) -> (EgressNode, EgressNode) {
    (
        stream.primary_gateway.clone(),
        stream.standby_gateway.clone(),
    )
}

fn acknowledgement_key(ack: &EgressHaFlowTwinAcknowledgement) -> (EgressNode, EgressNode) {
    (ack.primary_gateway.clone(), ack.standby_gateway.clone())
}

fn handoff_pairs(manifest: &EgressHaPromotionManifest) -> BTreeSet<(EgressNode, EgressNode)> {
    manifest
        .handoffs
        .iter()
        .map(|handoff| (handoff.old_gateway.clone(), handoff.new_gateway.clone()))
        .collect()
}

fn stream_digest(
    stream: &EgressHaFlowTwinStream,
) -> Result<EgressHaContinuityDigest, EgressHaContinuityError> {
    continuity_digest(&(
        stream.schema_version,
        stream.controller_epoch,
        stream.stream_epoch,
        stream.owner_plan_digest,
        &stream.primary_gateway,
        &stream.standby_gateway,
        &stream.shard_indexes,
        stream.sequence,
        stream.chain_digest,
        &stream.records,
    ))
}

fn acknowledgement_digest(
    ack: &EgressHaFlowTwinAcknowledgement,
) -> Result<EgressHaContinuityDigest, EgressHaContinuityError> {
    continuity_digest(&(
        ack.schema_version,
        ack.controller_epoch,
        ack.stream_epoch,
        ack.owner_plan_digest,
        &ack.primary_gateway,
        &ack.standby_gateway,
        ack.sequence,
        ack.chain_digest,
        ack.record_count,
        ack.snapshot_digest,
        ack.replica_revision,
    ))
}

fn cutover_material_digest(
    cutover: &EgressHaContinuityCutover,
) -> Result<EgressHaContinuityDigest, EgressHaContinuityError> {
    continuity_digest(&(
        cutover.schema_version,
        cutover.promotion_digest,
        cutover.activation_authority_digest,
        cutover.active_plan_digest,
        cutover.contingency_digest,
        cutover.cutoff_ns,
        cutover.target_source_bank,
        &cutover.streams,
        &cutover.acknowledgements,
        &cutover.import_records,
    ))
}

fn continuity_digest<T: Serialize>(
    value: &T,
) -> Result<EgressHaContinuityDigest, EgressHaContinuityError> {
    Ok(EgressHaContinuityDigest(digest_bytes(
        b"unf.egress-ha-flow-twin.v1\0",
        value,
    )?))
}

fn digest_bytes<T: Serialize>(
    domain: &[u8],
    value: &T,
) -> Result<[u8; 32], EgressHaContinuityError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| EgressHaContinuityError::Encoding(error.to_string()))?;
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(bytes);
    Ok(hasher.finalize().into())
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use super::*;
    use crate::{
        AddressFamily, DEFAULT_EGRESS_INTENT_PRIORITY, EgressAddressLease, EgressAddressRequest,
        EgressCapability, EgressDestinations, EgressHaCandidate,
        EgressHaGatewayAcquisitionEvidence, EgressHaInfrastructureFenceEvidence,
        EgressHaPromotionCoordinator, EgressHaReachabilityHandoffEvidence,
        EgressHaSourceFenceEvidence, EgressIntent, EgressIntentOwner, EgressIntentScope,
        EgressProjectionRecipient, EgressProviderRef, EgressSourceSelector, compile_egress_ha_plan,
    };

    // The promotion fixture intentionally uses one source and enough shards to
    // produce at least one old->new stream regardless of rendezvous ordering.
    #[allow(clippy::too_many_lines)]
    fn authority() -> EgressHaActivationAuthority {
        let owner = EgressIntentOwner {
            scope: EgressIntentScope::Cluster,
            name: "payments".to_owned(),
            uid: "uid-payments".to_owned(),
        };
        let lease = EgressAddressLease {
            intent: EgressIntent {
                owner,
                priority: DEFAULT_EGRESS_INTENT_PRIORITY,
                source: EgressSourceSelector::default(),
                destinations: EgressDestinations::Any,
                fqdn: None,
                addresses: EgressAddressRequest::Pool {
                    name: "public".to_owned(),
                    families: vec![AddressFamily::Ipv4, AddressFamily::Ipv6],
                    addresses_per_family: 4,
                },
            },
            pool: None,
            provider: EgressProviderRef {
                name: "static".to_owned(),
                instance: "lab".to_owned(),
            },
            addresses: vec![
                "192.0.2.20".parse().unwrap(),
                "192.0.2.21".parse().unwrap(),
                "192.0.2.22".parse().unwrap(),
                "192.0.2.23".parse().unwrap(),
                "2001:db8::20".parse().unwrap(),
                "2001:db8::21".parse().unwrap(),
                "2001:db8::22".parse().unwrap(),
                "2001:db8::23".parse().unwrap(),
            ],
            lease_epoch: 7,
            intent_epoch: 1,
            intent_revision: Revision::new(2),
            allocation_revision: Revision::new(3),
        };
        let candidates = ["a", "b", "c"]
            .into_iter()
            .map(|name| EgressHaCandidate {
                node: EgressNode {
                    name: format!("gateway-{name}"),
                    uid: format!("uid-{name}"),
                    capabilities: BTreeSet::from([EgressCapability::LeaseEpochFencing]),
                },
                capacity_units: 1,
                failure_domains: BTreeMap::from([("zone".to_owned(), name.to_owned())]),
            })
            .collect();
        let plan = compile_egress_ha_plan(&lease, candidates, None, Revision::new(9)).unwrap();
        let failed = plan.assignments[0].gateway.uid.clone();
        let source = EgressProjectionRecipient {
            node_name: "worker-a".to_owned(),
            node_uid: "worker-uid-a".to_owned(),
        };
        let manifest = EgressHaPromotionManifest::issue(
            &plan,
            &failed,
            vec![source.clone()],
            41,
            12,
            Revision::new(19),
        )
        .unwrap();
        let mut coordinator = EgressHaPromotionCoordinator::new(manifest.clone());
        coordinator
            .admit_source_fence(EgressHaSourceFenceEvidence {
                schema_version: EGRESS_HA_PROMOTION_SCHEMA_VERSION,
                controller_epoch: 41,
                promotion_epoch: 12,
                recipient: source,
                manifest_digest: manifest.manifest_digest,
                active_plan_digest: manifest.active_plan_digest,
                fenced_shards: manifest
                    .handoffs
                    .iter()
                    .map(|item| item.shard_index)
                    .collect(),
                inactive_bank: 1,
            })
            .unwrap();
        coordinator
            .admit_infrastructure_fence(EgressHaInfrastructureFenceEvidence {
                schema_version: EGRESS_HA_PROMOTION_SCHEMA_VERSION,
                controller_epoch: 41,
                promotion_epoch: 12,
                gateway: manifest.failed_gateway.clone(),
                manifest_digest: manifest.manifest_digest,
                provider: "redfish".to_owned(),
                fence_token: "off-12".to_owned(),
                provider_revision: 12,
                isolated: true,
            })
            .unwrap();
        for gateway in manifest
            .handoffs
            .iter()
            .map(|item| item.new_gateway.clone())
            .collect::<BTreeSet<_>>()
        {
            let addresses = manifest
                .handoffs
                .iter()
                .filter(|item| item.new_gateway == gateway)
                .flat_map(|item| item.addresses.iter().copied())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect();
            coordinator
                .admit_gateway_acquisition(EgressHaGatewayAcquisitionEvidence {
                    schema_version: EGRESS_HA_PROMOTION_SCHEMA_VERSION,
                    controller_epoch: 41,
                    promotion_epoch: 12,
                    gateway,
                    manifest_digest: manifest.manifest_digest,
                    owned_addresses: addresses,
                    kernel_revision: Revision::new(22),
                })
                .unwrap();
        }
        coordinator
            .admit_reachability_handoff(EgressHaReachabilityHandoffEvidence {
                schema_version: EGRESS_HA_PROMOTION_SCHEMA_VERSION,
                controller_epoch: 41,
                promotion_epoch: 12,
                manifest_digest: manifest.manifest_digest,
                expected_plan_digest: manifest.active_plan_digest,
                installed_plan_digest: manifest.contingency_digest,
                handoffs: manifest.handoffs.clone(),
                provider: "static-l2-cas".to_owned(),
                provider_revision: 30,
                compare_and_swap_applied: true,
            })
            .unwrap();
        coordinator.activation_authority().unwrap()
    }

    fn stream(authority: &EgressHaActivationAuthority) -> EgressHaFlowTwinStream {
        let first = &authority.manifest.handoffs[0];
        let shards = authority
            .manifest
            .handoffs
            .iter()
            .filter(|item| {
                item.old_gateway == first.old_gateway && item.new_gateway == first.new_gateway
            })
            .map(|item| item.shard_index)
            .collect();
        EgressHaFlowTwinStream::issue(
            &authority.manifest,
            first.old_gateway.clone(),
            first.new_gateway.clone(),
            shards,
            5,
        )
        .unwrap()
    }

    fn record(authority: &EgressHaActivationAuthority, last_seen_ns: u64) -> EgressHaFlowTwin {
        let handoff = &authority.manifest.handoffs[0];
        let egress_address = *handoff
            .addresses
            .iter()
            .find(|item| item.is_ipv4())
            .unwrap();
        EgressHaFlowTwin::issue(
            handoff.shard_index,
            IdentityId::new(77),
            6,
            "10.0.0.10".parse().unwrap(),
            "198.51.100.10".parse().unwrap(),
            41000,
            443,
            egress_address,
            52000,
            Revision::new(8),
            EgressContractDigest([7; 32]),
            [8; 16],
            authority.manifest.lease_epoch,
            last_seen_ns,
            u64::MAX,
        )
        .unwrap()
    }

    #[test]
    fn ordered_twin_stream_converges_to_exact_acknowledged_snapshot() {
        let authority = authority();
        let mut primary = stream(&authority);
        let mut standby = primary.clone();
        let delta = primary
            .next_delta(EgressHaFlowTwinOperation::Upsert(record(&authority, 1_000)))
            .unwrap();
        primary.apply(&authority.manifest, &delta).unwrap();
        standby.apply(&authority.manifest, &delta).unwrap();
        assert_eq!(primary, standby);
        standby
            .acknowledge(&authority.manifest, Revision::new(4))
            .unwrap()
            .verify(&primary, &authority.manifest)
            .unwrap();
    }

    #[test]
    fn loss_reorder_replay_and_immutable_mapping_change_fail_closed() {
        let authority = authority();
        let mut stream = stream(&authority);
        let first = stream
            .next_delta(EgressHaFlowTwinOperation::Upsert(record(&authority, 1_000)))
            .unwrap();
        stream.apply(&authority.manifest, &first).unwrap();
        assert_eq!(
            stream.apply(&authority.manifest, &first),
            Err(EgressHaContinuityError::InvalidDelta)
        );
        let mut changed = record(&authority, 2_000);
        changed.translated_source_port += 1;
        changed.flow_id = changed.compute_flow_id().unwrap();
        let delta = stream
            .next_delta(EgressHaFlowTwinOperation::Upsert(changed))
            .unwrap();
        stream.apply(&authority.manifest, &delta).unwrap();
        assert_eq!(
            stream.records.len(),
            2,
            "port remap has a different immutable flow ID"
        );
    }

    #[test]
    fn cutover_imports_only_live_complete_acknowledged_pairs() {
        let authority = authority();
        let mut streams = Vec::new();
        let mut acks = Vec::new();
        for (old, new) in handoff_pairs(&authority.manifest) {
            let shards = authority
                .manifest
                .handoffs
                .iter()
                .filter(|item| item.old_gateway == old && item.new_gateway == new)
                .map(|item| item.shard_index)
                .collect();
            let mut item =
                EgressHaFlowTwinStream::issue(&authority.manifest, old, new, shards, 5).unwrap();
            if item
                .shard_indexes
                .contains(&authority.manifest.handoffs[0].shard_index)
            {
                let live = item
                    .next_delta(EgressHaFlowTwinOperation::Upsert(record(&authority, 1_000)))
                    .unwrap();
                item.apply(&authority.manifest, &live).unwrap();
                let expired = item
                    .next_delta(EgressHaFlowTwinOperation::Upsert(record(&authority, 1)))
                    .unwrap();
                let mut expired_record = match expired.operation {
                    EgressHaFlowTwinOperation::Upsert(record) => record,
                    EgressHaFlowTwinOperation::Remove { .. } => unreachable!(),
                };
                expired_record.original_source_port += 1;
                expired_record.flow_id = expired_record.compute_flow_id().unwrap();
                let expired = item
                    .next_delta(EgressHaFlowTwinOperation::Upsert(expired_record))
                    .unwrap();
                item.apply(&authority.manifest, &expired).unwrap();
            }
            acks.push(
                item.acknowledge(&authority.manifest, Revision::new(7))
                    .unwrap(),
            );
            streams.push(item);
        }
        let cutoff = 1_000 + CONNECTION_TCP_TIMEOUT_NS;
        let cutover =
            EgressHaContinuityCutover::issue(&authority, streams, acks, cutoff, 1).unwrap();
        assert_eq!(cutover.import_records.len(), 1);
        cutover.verify(&authority).unwrap();
    }

    #[test]
    fn stale_ack_and_foreign_shard_never_authorize_cutover() {
        let authority = authority();
        let item = stream(&authority);
        let mut ack = item
            .acknowledge(&authority.manifest, Revision::new(7))
            .unwrap();
        ack.sequence += 1;
        assert_eq!(
            ack.verify(&item, &authority.manifest),
            Err(EgressHaContinuityError::AcknowledgementMismatch)
        );
        let mut foreign = record(&authority, 1_000);
        foreign.shard_index = u16::MAX;
        foreign.flow_id = foreign.compute_flow_id().unwrap();
        let delta = item
            .next_delta(EgressHaFlowTwinOperation::Upsert(foreign))
            .unwrap();
        let mut replica = item.clone();
        assert_eq!(
            replica.apply(&authority.manifest, &delta),
            Err(EgressHaContinuityError::InvalidRecord)
        );
    }

    #[test]
    fn inner_snapshot_mutation_cannot_hide_behind_recomputed_outer_digest() {
        let authority = authority();
        let mut streams = Vec::new();
        let mut acks = Vec::new();
        for (old, new) in handoff_pairs(&authority.manifest) {
            let shards = authority
                .manifest
                .handoffs
                .iter()
                .filter(|item| item.old_gateway == old && item.new_gateway == new)
                .map(|item| item.shard_index)
                .collect();
            let item =
                EgressHaFlowTwinStream::issue(&authority.manifest, old, new, shards, 5).unwrap();
            acks.push(
                item.acknowledge(&authority.manifest, Revision::new(7))
                    .unwrap(),
            );
            streams.push(item);
        }
        let mut cutover =
            EgressHaContinuityCutover::issue(&authority, streams, acks, 100, 1).unwrap();
        cutover.streams[0].stream_epoch += 1;
        cutover.cutover_digest = cutover_material_digest(&cutover).unwrap();
        assert!(cutover.verify(&authority).is_err());
    }
}
