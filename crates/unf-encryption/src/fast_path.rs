//! Intent-coalesced encryption transport compiler and packet-decision mirror.
//!
//! Identity authority remains exact while identical Node/epoch transports are
//! shared. The compiler is pure: callers stage its fixed-width output into an
//! inactive BPF bank and publish only [`EncryptionMapConfig`] atomically.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use unf_common::{IdentityId, Revision};
use unf_ebpf_common::{
    ENCRYPTION_BANK_COUNT, ENCRYPTION_DECISION_FLAG_POLICY_AUTHORIZED,
    ENCRYPTION_DECISION_FLAG_SELECTION_BOUND, ENCRYPTION_DECISION_MAP_CAPACITY,
    ENCRYPTION_DISPOSITION_NATIVE, ENCRYPTION_DISPOSITION_REQUIRED,
    ENCRYPTION_FLOW_FLAG_ESTABLISHED_LEASE, ENCRYPTION_MAP_ABI_VERSION, ENCRYPTION_ROUTE_MARK_MASK,
    ENCRYPTION_TRANSPORT_ACTIVE, ENCRYPTION_TRANSPORT_DRAINING,
    ENCRYPTION_TRANSPORT_FLAG_KERNEL_READBACK, ENCRYPTION_TRANSPORT_MAP_CAPACITY,
    EncryptionDecisionKey, EncryptionDecisionValue, EncryptionFlowValue, EncryptionMapConfig,
    EncryptionTransportKey, EncryptionTransportValue, apply_encryption_route_mark,
    clear_encryption_route_mark, encryption_route_mark, encryption_transport_is_usable,
};

use crate::{
    AttestedEncryptionPathContract, EncryptionDisposition, EncryptionPathClass,
    KernelTransactionPhase, ProofCarryingKernelTransaction, WireGuardKernelSnapshot,
};

pub const MAX_FAST_PATH_DECISIONS: usize = ENCRYPTION_DECISION_MAP_CAPACITY as usize;
pub const MAX_FAST_PATH_TRANSPORTS: usize = ENCRYPTION_TRANSPORT_MAP_CAPACITY as usize;
pub const MAX_FAST_PATH_EPOCHS: usize = 2;

const FAST_PATH_DIGEST_DOMAIN: &[u8] = b"unf.encryption-fast-path.v1\0";
const TRANSPORT_ID_DOMAIN: &[u8] = b"unf.encryption-transport-id.v1\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum FastPathEpochState {
    Active,
    Draining,
}

/// A committed kernel transaction plus exact readback is the admission token
/// for one epoch. It is not a claim of live packet delivery; milestone 9.6
/// will strengthen `readiness_digest` with bidirectional challenge evidence.
#[derive(Clone, Copy)]
pub struct FastPathEpochAdmission<'a> {
    pub contract: &'a AttestedEncryptionPathContract,
    pub transaction: &'a ProofCarryingKernelTransaction,
    pub readback: &'a WireGuardKernelSnapshot,
    pub readiness_digest: [u8; 32],
    pub state: FastPathEpochState,
    pub drain_until_monotonic_ns: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FastPathDecisionInput {
    pub source_identity: IdentityId,
    pub destination_identity: IdentityId,
    pub disposition: EncryptionDisposition,
    /// Required decisions reference one admitted epoch and exact plan.
    pub contract_epoch: Option<u64>,
    pub plan_index: Option<usize>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FastPathCompileContext {
    pub generation: Revision,
    pub policy_revision: Revision,
    pub service_revision: Revision,
    pub egress_revision: Revision,
    pub bank: u8,
    pub now_unix_ms: u64,
    pub now_monotonic_ns: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EncryptionTransportAuthority {
    pub transport_id: u64,
    pub trust_domain: String,
    pub local_node_uid: String,
    pub destination_node_uid: String,
    pub key_epoch: u64,
    pub path_class: EncryptionPathClass,
    pub interface_name: String,
    pub interface_index: u32,
    pub route_table: u32,
    pub fwmark: u32,
    pub mtu: u32,
    pub kernel_configuration_digest: [u8; 32],
    pub readiness_digest: [u8; 32],
    pub contract_revision: Revision,
    pub state: FastPathEpochState,
    pub drain_until_monotonic_ns: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct FastPathDecisionAuthority {
    pub source_identity: IdentityId,
    pub destination_identity: IdentityId,
    pub disposition: EncryptionDisposition,
    pub transport_id: Option<u64>,
    pub contract_revision: Option<Revision>,
    pub key_epoch: Option<u64>,
    pub decision_witness: [u8; 16],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EncryptionFastPathDigest(pub [u8; 32]);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptionFastPathState {
    pub config: EncryptionMapConfig,
    pub decisions: Vec<(EncryptionDecisionKey, EncryptionDecisionValue)>,
    pub transports: Vec<(EncryptionTransportKey, EncryptionTransportValue)>,
    pub decision_authority: Vec<FastPathDecisionAuthority>,
    pub transport_authority: Vec<EncryptionTransportAuthority>,
    pub state_digest: EncryptionFastPathDigest,
}

impl EncryptionFastPathState {
    /// Replays fixed-width lowering and the canonical digest before a staged
    /// bank is recovered or published.
    ///
    /// # Errors
    ///
    /// Rejects any config, authority, transport-ID, lowered-record, count, or
    /// digest mutation.
    pub fn verify_integrity(&self) -> Result<(), FastPathError> {
        if self.config.schema_version != ENCRYPTION_MAP_ABI_VERSION
            || self.config.active_bank >= ENCRYPTION_BANK_COUNT
            || self.config.generation == 0
            || self.config.policy_revision == 0
            || self.config.service_revision == 0
            || self.config.egress_revision == 0
            || self.config.epoch_count == 0
            || usize::from(self.config.epoch_count) > MAX_FAST_PATH_EPOCHS
        {
            return Err(FastPathError::IntegrityMismatch);
        }
        let context = FastPathCompileContext {
            generation: Revision::new(self.config.generation),
            policy_revision: Revision::new(self.config.policy_revision),
            service_revision: Revision::new(self.config.service_revision),
            egress_revision: Revision::new(self.config.egress_revision),
            bank: self.config.active_bank,
            now_unix_ms: 1,
            now_monotonic_ns: 1,
        };
        let expected_config = map_config(
            context,
            usize::from(self.config.epoch_count),
            &self.decision_authority,
            &self.transport_authority,
        )?;
        if self.config != expected_config
            || self.decisions != lower_decisions(context, &self.decision_authority)
            || self.transports
                != lower_transports(self.config.active_bank, &self.transport_authority)
            || self.state_digest
                != state_digest(
                    context,
                    usize::from(self.config.epoch_count),
                    &self.decision_authority,
                    &self.transport_authority,
                )?
            || !transport_ids_are_valid(&self.transport_authority)
            || !route_marks_are_unambiguous(&self.transport_authority)
        {
            return Err(FastPathError::IntegrityMismatch);
        }
        Ok(())
    }
}

pub(crate) struct FastPathRestoreAuthority {
    pub generation: Revision,
    pub policy_revision: Revision,
    pub service_revision: Revision,
    pub egress_revision: Revision,
    pub bank: u8,
    pub epoch_count: u8,
    pub decisions: Vec<FastPathDecisionAuthority>,
    pub transports: Vec<EncryptionTransportAuthority>,
    pub expected_digest: EncryptionFastPathDigest,
}

pub(crate) fn restore_encryption_fast_path_state(
    authority: FastPathRestoreAuthority,
) -> Result<EncryptionFastPathState, FastPathError> {
    let context = FastPathCompileContext {
        generation: authority.generation,
        policy_revision: authority.policy_revision,
        service_revision: authority.service_revision,
        egress_revision: authority.egress_revision,
        bank: authority.bank,
        now_unix_ms: 1,
        now_monotonic_ns: 1,
    };
    let config = map_config(
        context,
        usize::from(authority.epoch_count),
        &authority.decisions,
        &authority.transports,
    )?;
    let decisions = lower_decisions(context, &authority.decisions);
    let transports = lower_transports(authority.bank, &authority.transports);
    let state_digest = state_digest(
        context,
        usize::from(authority.epoch_count),
        &authority.decisions,
        &authority.transports,
    )?;
    if state_digest != authority.expected_digest {
        return Err(FastPathError::IntegrityMismatch);
    }
    let state = EncryptionFastPathState {
        config,
        decisions,
        transports,
        decision_authority: authority.decisions,
        transport_authority: authority.transports,
        state_digest,
    };
    state.verify_integrity()?;
    Ok(state)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CausalEpochLease {
    pub source_identity: IdentityId,
    pub destination_identity: IdentityId,
    pub transport_id: u64,
    pub key_epoch: u64,
    pub contract_revision: u64,
    pub decision_witness: [u8; 16],
    pub last_seen_monotonic_ns: u64,
    pub drain_until_monotonic_ns: u64,
}

impl CausalEpochLease {
    #[must_use]
    pub const fn lower(self) -> EncryptionFlowValue {
        EncryptionFlowValue {
            last_seen_monotonic_ns: self.last_seen_monotonic_ns,
            transport_id: self.transport_id,
            key_epoch: self.key_epoch,
            contract_revision: self.contract_revision,
            drain_until_monotonic_ns: self.drain_until_monotonic_ns,
            decision_witness: self.decision_witness,
            schema_version: ENCRYPTION_MAP_ABI_VERSION,
            flags: ENCRYPTION_FLOW_FLAG_ESTABLISHED_LEASE,
            reserved: [0; 5],
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FastPathPacketContext {
    pub source_identity: IdentityId,
    pub destination_identity: IdentityId,
    pub policy_authorized: bool,
    pub policy_revision: Revision,
    pub service_revision: Revision,
    pub egress_revision: Revision,
    pub now_monotonic_ns: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FastPathDropReason {
    PolicyDenied,
    AuthorityMissing,
    RevisionMismatch,
    TransportUnavailable,
    LeaseExpiredOrRevoked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FastPathPacketDecision {
    Native,
    Encrypt {
        /// Kernel `WireGuard` applies this mark to its outer UDP packet. It is
        /// evidence only and must never be copied directly onto plaintext.
        outer_fwmark: u32,
        /// Complementary selector placed only in UNF's leased skb-mark field.
        route_mark: u32,
        route_mark_mask: u32,
        route_table: u32,
        interface_index: u32,
        mtu: u32,
        lease: CausalEpochLease,
    },
    Drop(FastPathDropReason),
}

impl FastPathPacketDecision {
    /// Applies a selected route lease without disturbing marks owned by a
    /// Service, another dataplane, or the application. Drops have no mark.
    #[must_use]
    pub const fn apply_to_mark(self, existing: u32) -> Option<u32> {
        match self {
            Self::Native => Some(clear_encryption_route_mark(existing)),
            Self::Encrypt { route_mark, .. } => apply_encryption_route_mark(existing, route_mark),
            Self::Drop(_) => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum FastPathError {
    #[error("invalid encryption fast-path bank or revision context")]
    InvalidContext,
    #[error("encryption fast path requires exactly one active epoch and at most two epochs")]
    InvalidEpochSet,
    #[error("encryption contract is invalid, stale, or does not match its kernel authority")]
    InvalidContract,
    #[error("kernel transaction is not a committed exact readback")]
    KernelAuthorityUnavailable,
    #[error("invalid or duplicate encryption decision")]
    InvalidDecision,
    #[error("required encryption decision does not resolve to an exact active plan")]
    RequiredAuthorityUnavailable,
    #[error("encryption fast-path {kind} capacity exceeded: {actual} > {limit}")]
    Capacity {
        kind: &'static str,
        actual: usize,
        limit: usize,
    },
    #[error("content-derived encryption transport ID collision")]
    TransportIdCollision,
    #[error("encryption route mark resolves to conflicting policy-route tables")]
    RouteMarkCollision,
    #[error("encryption fast-path state differs from canonical replay")]
    IntegrityMismatch,
    #[error("encryption fast-path canonical encoding failed: {0}")]
    CanonicalEncoding(String),
}

/// Compiles a complete inactive generation. No caller-visible state is
/// mutated on failure, including capacity or ID-collision failure.
///
/// # Errors
///
/// Rejects invalid banks/revisions, malformed or stale contracts, noncommitted
/// kernel readback, ambiguous decisions, missing required authority, bounds,
/// or a content-derived ID collision.
pub fn compile_encryption_fast_path(
    context: FastPathCompileContext,
    epochs: &[FastPathEpochAdmission<'_>],
    inputs: &[FastPathDecisionInput],
) -> Result<EncryptionFastPathState, FastPathError> {
    validate_context(context, epochs, inputs)?;
    let admitted = admit_epochs(context, epochs)?;
    let mut transport_by_key = BTreeMap::new();
    let mut decision_authority =
        compile_decisions(context, inputs, &admitted, &mut transport_by_key)?;
    add_draining_transports(epochs, &mut transport_by_key)?;
    decision_authority.sort_by_key(|entry| (entry.source_identity, entry.destination_identity));
    let transport_authority = materialize_transports(transport_by_key)?;
    if !route_marks_are_unambiguous(&transport_authority) {
        return Err(FastPathError::RouteMarkCollision);
    }
    let config = map_config(
        context,
        epochs.len(),
        &decision_authority,
        &transport_authority,
    )?;
    let decisions = lower_decisions(context, &decision_authority);
    let transports = lower_transports(context.bank, &transport_authority);
    let state_digest = state_digest(
        context,
        epochs.len(),
        &decision_authority,
        &transport_authority,
    )?;
    let state = EncryptionFastPathState {
        config,
        decisions,
        transports,
        decision_authority,
        transport_authority,
        state_digest,
    };
    state.verify_integrity()?;
    Ok(state)
}

type TransportIndex<'a> = BTreeMap<CoalescingKey, (u64, &'a FastPathEpochAdmission<'a>)>;

fn admit_epochs<'a>(
    context: FastPathCompileContext,
    epochs: &'a [FastPathEpochAdmission<'a>],
) -> Result<BTreeMap<u64, &'a FastPathEpochAdmission<'a>>, FastPathError> {
    let mut admitted = BTreeMap::new();
    for epoch in epochs {
        validate_epoch(context, epoch)?;
        if admitted
            .insert(epoch.contract.plans[0].source_key.epoch, epoch)
            .is_some()
        {
            return Err(FastPathError::InvalidEpochSet);
        }
    }
    Ok(admitted)
}

fn compile_decisions<'a>(
    context: FastPathCompileContext,
    inputs: &[FastPathDecisionInput],
    admitted: &BTreeMap<u64, &'a FastPathEpochAdmission<'a>>,
    transports: &mut TransportIndex<'a>,
) -> Result<Vec<FastPathDecisionAuthority>, FastPathError> {
    let mut decisions = Vec::with_capacity(inputs.len());
    let mut seen = BTreeSet::new();
    for input in inputs {
        if input.source_identity.get() == 0
            || input.destination_identity.get() == 0
            || !seen.insert((input.source_identity, input.destination_identity))
        {
            return Err(FastPathError::InvalidDecision);
        }
        let decision = match input.disposition {
            EncryptionDisposition::Native => native_decision(context, *input)?,
            EncryptionDisposition::Required => {
                required_decision(context, *input, admitted, transports)?
            }
        };
        decisions.push(decision);
    }
    Ok(decisions)
}

fn native_decision(
    context: FastPathCompileContext,
    input: FastPathDecisionInput,
) -> Result<FastPathDecisionAuthority, FastPathError> {
    if input.contract_epoch.is_some() || input.plan_index.is_some() {
        return Err(FastPathError::InvalidDecision);
    }
    Ok(FastPathDecisionAuthority {
        source_identity: input.source_identity,
        destination_identity: input.destination_identity,
        disposition: input.disposition,
        transport_id: None,
        contract_revision: None,
        key_epoch: None,
        decision_witness: native_witness(context, input),
    })
}

fn required_decision<'a>(
    context: FastPathCompileContext,
    input: FastPathDecisionInput,
    admitted: &BTreeMap<u64, &'a FastPathEpochAdmission<'a>>,
    transports: &mut TransportIndex<'a>,
) -> Result<FastPathDecisionAuthority, FastPathError> {
    let epoch_number = input
        .contract_epoch
        .ok_or(FastPathError::RequiredAuthorityUnavailable)?;
    let epoch = admitted
        .get(&epoch_number)
        .ok_or(FastPathError::RequiredAuthorityUnavailable)?;
    let plan_index = input
        .plan_index
        .ok_or(FastPathError::RequiredAuthorityUnavailable)?;
    let plan = epoch
        .contract
        .plans
        .get(plan_index)
        .ok_or(FastPathError::RequiredAuthorityUnavailable)?;
    if epoch.state != FastPathEpochState::Active
        || plan.source.identity != input.source_identity
        || plan.destination.identity != input.destination_identity
        || plan.policy.revision != context.policy_revision
        || plan.disposition != EncryptionDisposition::Required
    {
        return Err(FastPathError::RequiredAuthorityUnavailable);
    }
    let key = transport_key(epoch, plan_index)?;
    let id = transport_id(&key)?;
    if let Some(existing) = transports.insert(key, (id, epoch))
        && existing.0 != id
    {
        return Err(FastPathError::TransportIdCollision);
    }
    Ok(FastPathDecisionAuthority {
        source_identity: input.source_identity,
        destination_identity: input.destination_identity,
        disposition: input.disposition,
        transport_id: Some(id),
        contract_revision: Some(epoch.contract.contract_revision),
        key_epoch: Some(epoch_number),
        decision_witness: epoch
            .contract
            .decision_witness(plan_index)
            .map_err(|_| FastPathError::InvalidContract)?
            .0,
    })
}

fn add_draining_transports<'a>(
    epochs: &'a [FastPathEpochAdmission<'a>],
    transports: &mut TransportIndex<'a>,
) -> Result<(), FastPathError> {
    for epoch in epochs
        .iter()
        .filter(|epoch| epoch.state == FastPathEpochState::Draining)
    {
        for plan_index in 0..epoch.contract.plans.len() {
            let key = transport_key(epoch, plan_index)?;
            let id = transport_id(&key)?;
            transports.entry(key).or_insert((id, epoch));
        }
    }
    if transports.len() > MAX_FAST_PATH_TRANSPORTS {
        return Err(FastPathError::Capacity {
            kind: "transport",
            actual: transports.len(),
            limit: MAX_FAST_PATH_TRANSPORTS,
        });
    }
    Ok(())
}

fn materialize_transports(
    transports: TransportIndex<'_>,
) -> Result<Vec<EncryptionTransportAuthority>, FastPathError> {
    let mut authority = Vec::with_capacity(transports.len());
    for (key, (id, epoch)) in transports {
        let candidate = authority_from_key(id, key, epoch);
        if authority
            .iter()
            .any(|existing: &EncryptionTransportAuthority| {
                existing.transport_id == candidate.transport_id && existing != &candidate
            })
        {
            return Err(FastPathError::TransportIdCollision);
        }
        authority.push(candidate);
    }
    authority.sort_by_key(|entry| entry.transport_id);
    Ok(authority)
}

fn map_config(
    context: FastPathCompileContext,
    epoch_count: usize,
    decisions: &[FastPathDecisionAuthority],
    transports: &[EncryptionTransportAuthority],
) -> Result<EncryptionMapConfig, FastPathError> {
    Ok(EncryptionMapConfig {
        generation: context.generation.get(),
        policy_revision: context.policy_revision.get(),
        service_revision: context.service_revision.get(),
        egress_revision: context.egress_revision.get(),
        decision_count: u32::try_from(decisions.len()).map_err(|_| FastPathError::Capacity {
            kind: "decision",
            actual: decisions.len(),
            limit: MAX_FAST_PATH_DECISIONS,
        })?,
        transport_count: u32::try_from(transports.len()).map_err(|_| FastPathError::Capacity {
            kind: "transport",
            actual: transports.len(),
            limit: MAX_FAST_PATH_TRANSPORTS,
        })?,
        schema_version: ENCRYPTION_MAP_ABI_VERSION,
        active_bank: context.bank,
        epoch_count: u8::try_from(epoch_count).map_err(|_| FastPathError::InvalidEpochSet)?,
    })
}

/// Mirrors the bounded packet path: policy always wins; established leases may
/// use a draining epoch; new required flows may use only current active state.
#[must_use]
pub fn select_encryption_transport(
    state: &EncryptionFastPathState,
    packet: FastPathPacketContext,
    established: Option<CausalEpochLease>,
) -> FastPathPacketDecision {
    if !packet.policy_authorized {
        return FastPathPacketDecision::Drop(FastPathDropReason::PolicyDenied);
    }
    if state.config.schema_version != ENCRYPTION_MAP_ABI_VERSION
        || state.config.active_bank >= ENCRYPTION_BANK_COUNT
        || state.config.epoch_count == 0
        || usize::from(state.config.epoch_count) > MAX_FAST_PATH_EPOCHS
        || packet.policy_revision.get() != state.config.policy_revision
        || packet.service_revision.get() != state.config.service_revision
        || packet.egress_revision.get() != state.config.egress_revision
    {
        return FastPathPacketDecision::Drop(FastPathDropReason::RevisionMismatch);
    }
    if let Some(mut lease) = established {
        if lease.source_identity != packet.source_identity
            || lease.destination_identity != packet.destination_identity
        {
            return FastPathPacketDecision::Drop(FastPathDropReason::LeaseExpiredOrRevoked);
        }
        let Some((_, transport)) = state
            .transports
            .iter()
            .find(|(key, _)| key.transport_id == lease.transport_id)
        else {
            return FastPathPacketDecision::Drop(FastPathDropReason::LeaseExpiredOrRevoked);
        };
        if lease.key_epoch != transport.key_epoch
            || lease.contract_revision != transport.contract_revision
            || !encryption_transport_is_usable(transport, true, packet.now_monotonic_ns)
        {
            return FastPathPacketDecision::Drop(FastPathDropReason::LeaseExpiredOrRevoked);
        }
        lease.last_seen_monotonic_ns = packet.now_monotonic_ns;
        lease.drain_until_monotonic_ns = transport.drain_until_monotonic_ns;
        return encrypted(transport, lease);
    }
    let Some((_, decision)) = state.decisions.iter().find(|(key, _)| {
        key.bank == state.config.active_bank
            && key.source_identity == packet.source_identity
            && key.destination_identity == packet.destination_identity
    }) else {
        return FastPathPacketDecision::Drop(FastPathDropReason::AuthorityMissing);
    };
    if decision.schema_version != ENCRYPTION_MAP_ABI_VERSION
        || decision.decision_witness == [0; 16]
        || decision.flags
            != ENCRYPTION_DECISION_FLAG_POLICY_AUTHORIZED | ENCRYPTION_DECISION_FLAG_SELECTION_BOUND
        || decision.policy_revision != packet.policy_revision.get()
        || decision.service_revision != packet.service_revision.get()
        || decision.egress_revision != packet.egress_revision.get()
    {
        return FastPathPacketDecision::Drop(FastPathDropReason::RevisionMismatch);
    }
    if decision.disposition == ENCRYPTION_DISPOSITION_NATIVE {
        return if decision.transport_id == 0
            && decision.contract_revision == 0
            && decision.key_epoch == 0
        {
            FastPathPacketDecision::Native
        } else {
            FastPathPacketDecision::Drop(FastPathDropReason::RevisionMismatch)
        };
    }
    if decision.disposition != ENCRYPTION_DISPOSITION_REQUIRED
        || decision.transport_id == 0
        || decision.contract_revision == 0
        || decision.key_epoch == 0
    {
        return FastPathPacketDecision::Drop(FastPathDropReason::RevisionMismatch);
    }
    let Some((_, transport)) = state.transports.iter().find(|(key, _)| {
        key.bank == state.config.active_bank && key.transport_id == decision.transport_id
    }) else {
        return FastPathPacketDecision::Drop(FastPathDropReason::TransportUnavailable);
    };
    if decision.key_epoch != transport.key_epoch
        || decision.contract_revision != transport.contract_revision
        || !encryption_transport_is_usable(transport, false, packet.now_monotonic_ns)
    {
        return FastPathPacketDecision::Drop(FastPathDropReason::TransportUnavailable);
    }
    encrypted(
        transport,
        CausalEpochLease {
            source_identity: packet.source_identity,
            destination_identity: packet.destination_identity,
            transport_id: decision.transport_id,
            key_epoch: decision.key_epoch,
            contract_revision: decision.contract_revision,
            decision_witness: decision.decision_witness,
            last_seen_monotonic_ns: packet.now_monotonic_ns,
            drain_until_monotonic_ns: transport.drain_until_monotonic_ns,
        },
    )
}

fn validate_context(
    context: FastPathCompileContext,
    epochs: &[FastPathEpochAdmission<'_>],
    inputs: &[FastPathDecisionInput],
) -> Result<(), FastPathError> {
    if context.bank >= ENCRYPTION_BANK_COUNT
        || context.generation == Revision::INITIAL
        || context.policy_revision == Revision::INITIAL
        || context.service_revision == Revision::INITIAL
        || context.egress_revision == Revision::INITIAL
        || context.now_unix_ms == 0
        || context.now_monotonic_ns == 0
    {
        return Err(FastPathError::InvalidContext);
    }
    if epochs.is_empty()
        || epochs.len() > MAX_FAST_PATH_EPOCHS
        || epochs
            .iter()
            .filter(|epoch| epoch.state == FastPathEpochState::Active)
            .count()
            != 1
    {
        return Err(FastPathError::InvalidEpochSet);
    }
    if inputs.len() > MAX_FAST_PATH_DECISIONS {
        return Err(FastPathError::Capacity {
            kind: "decision",
            actual: inputs.len(),
            limit: MAX_FAST_PATH_DECISIONS,
        });
    }
    Ok(())
}

fn validate_epoch(
    context: FastPathCompileContext,
    epoch: &FastPathEpochAdmission<'_>,
) -> Result<(), FastPathError> {
    epoch
        .contract
        .verify_integrity()
        .map_err(|_| FastPathError::InvalidContract)?;
    epoch
        .transaction
        .verify()
        .map_err(|_| FastPathError::KernelAuthorityUnavailable)?;
    epoch
        .readback
        .verify_against(&epoch.transaction.plan)
        .map_err(|_| FastPathError::KernelAuthorityUnavailable)?;
    if epoch.transaction.phase != KernelTransactionPhase::Committed
        || epoch.transaction.readback_configuration_digest
            != Some(epoch.readback.configuration_digest)
        || epoch.readiness_digest == [0; 32]
        || epoch.contract.plans.is_empty()
        || context.now_unix_ms < epoch.contract.valid_from_unix_ms
        || context.now_unix_ms > epoch.contract.valid_until_unix_ms
        || epoch.transaction.plan.cluster_id != epoch.contract.local_node.cluster_id
        || epoch.transaction.plan.local_node_uid != epoch.contract.local_node.uid
        || epoch.transaction.plan.epoch != epoch.contract.plans[0].source_key.epoch
        || encryption_route_mark(epoch.transaction.plan.fwmark).is_none()
        || (epoch.state == FastPathEpochState::Draining
            && epoch.drain_until_monotonic_ns <= context.now_monotonic_ns)
        || (epoch.state == FastPathEpochState::Active && epoch.drain_until_monotonic_ns != 0)
    {
        return Err(FastPathError::KernelAuthorityUnavailable);
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
struct CoalescingKey {
    trust_domain: String,
    local_node_uid: String,
    destination_node_uid: String,
    key_epoch: u64,
    path_class: EncryptionPathClass,
    interface_name: String,
    interface_index: u32,
    route_table: u32,
    fwmark: u32,
    mtu: u32,
    kernel_configuration_digest: [u8; 32],
    readiness_digest: [u8; 32],
    contract_revision: Revision,
}

fn transport_key(
    epoch: &FastPathEpochAdmission<'_>,
    plan_index: usize,
) -> Result<CoalescingKey, FastPathError> {
    let plan = epoch
        .contract
        .plans
        .get(plan_index)
        .ok_or(FastPathError::RequiredAuthorityUnavailable)?;
    let kernel = &epoch.transaction.plan;
    let path = &plan.transport.forward;
    let peer = kernel
        .peers
        .iter()
        .find(|peer| peer.node_uid == plan.destination.node.uid)
        .ok_or(FastPathError::KernelAuthorityUnavailable)?;
    if path.source_node_uid != kernel.local_node_uid
        || path.destination_node_uid != peer.node_uid
        || path.epoch != kernel.epoch
        || path.interface_name != kernel.interface_name
        || path.route_table != kernel.route_table
        || path.fwmark != kernel.fwmark
        || path.mtu != kernel.mtu_envelope.interface_mtu
        || path.peer_endpoint != peer.endpoint
        || path.allowed_ips != peer.allowed_ips
        || plan.destination_key.public_key != peer.public_key
    {
        return Err(FastPathError::KernelAuthorityUnavailable);
    }
    Ok(CoalescingKey {
        trust_domain: kernel.cluster_id.clone(),
        local_node_uid: kernel.local_node_uid.clone(),
        destination_node_uid: peer.node_uid.clone(),
        key_epoch: kernel.epoch,
        path_class: path.path_class,
        interface_name: kernel.interface_name.clone(),
        interface_index: epoch.readback.interface_index,
        route_table: kernel.route_table,
        fwmark: kernel.fwmark,
        mtu: kernel.mtu_envelope.interface_mtu,
        kernel_configuration_digest: epoch.readback.configuration_digest.0,
        readiness_digest: epoch.readiness_digest,
        contract_revision: epoch.contract.contract_revision,
    })
}

fn transport_id(key: &CoalescingKey) -> Result<u64, FastPathError> {
    let material = serde_json::to_vec(key)
        .map_err(|error| FastPathError::CanonicalEncoding(error.to_string()))?;
    let mut hasher = Sha256::new();
    hasher.update(TRANSPORT_ID_DOMAIN);
    hasher.update(material);
    let digest = hasher.finalize();
    let mut bytes = [0; 8];
    bytes.copy_from_slice(&digest[..8]);
    let id = u64::from_be_bytes(bytes);
    Ok(if id == 0 { 1 } else { id })
}

fn authority_from_key(
    transport_id: u64,
    key: CoalescingKey,
    epoch: &FastPathEpochAdmission<'_>,
) -> EncryptionTransportAuthority {
    EncryptionTransportAuthority {
        transport_id,
        trust_domain: key.trust_domain,
        local_node_uid: key.local_node_uid,
        destination_node_uid: key.destination_node_uid,
        key_epoch: key.key_epoch,
        path_class: key.path_class,
        interface_name: key.interface_name,
        interface_index: key.interface_index,
        route_table: key.route_table,
        fwmark: key.fwmark,
        mtu: key.mtu,
        kernel_configuration_digest: key.kernel_configuration_digest,
        readiness_digest: key.readiness_digest,
        contract_revision: key.contract_revision,
        state: epoch.state,
        drain_until_monotonic_ns: epoch.drain_until_monotonic_ns,
    }
}

fn transport_ids_are_valid(transports: &[EncryptionTransportAuthority]) -> bool {
    let mut ids = BTreeSet::new();
    transports.iter().all(|transport| {
        let key = CoalescingKey {
            trust_domain: transport.trust_domain.clone(),
            local_node_uid: transport.local_node_uid.clone(),
            destination_node_uid: transport.destination_node_uid.clone(),
            key_epoch: transport.key_epoch,
            path_class: transport.path_class,
            interface_name: transport.interface_name.clone(),
            interface_index: transport.interface_index,
            route_table: transport.route_table,
            fwmark: transport.fwmark,
            mtu: transport.mtu,
            kernel_configuration_digest: transport.kernel_configuration_digest,
            readiness_digest: transport.readiness_digest,
            contract_revision: transport.contract_revision,
        };
        transport_id(&key).is_ok_and(|id| id == transport.transport_id && ids.insert(id))
    })
}

fn route_marks_are_unambiguous(transports: &[EncryptionTransportAuthority]) -> bool {
    let mut tables = BTreeMap::new();
    transports.iter().all(|transport| {
        let Some(mark) = encryption_route_mark(transport.fwmark) else {
            return false;
        };
        tables
            .insert(mark, transport.route_table)
            .is_none_or(|existing| existing == transport.route_table)
    })
}

fn native_witness(context: FastPathCompileContext, input: FastPathDecisionInput) -> [u8; 16] {
    let mut hasher = Sha256::new();
    hasher.update(b"unf.encryption-native-decision.v1\0");
    hasher.update(context.generation.get().to_be_bytes());
    hasher.update(input.source_identity.get().to_be_bytes());
    hasher.update(input.destination_identity.get().to_be_bytes());
    let digest = hasher.finalize();
    let mut witness = [0; 16];
    witness.copy_from_slice(&digest[..16]);
    witness
}

fn lower_decisions(
    context: FastPathCompileContext,
    authority: &[FastPathDecisionAuthority],
) -> Vec<(EncryptionDecisionKey, EncryptionDecisionValue)> {
    authority
        .iter()
        .map(|entry| {
            let required = entry.disposition == EncryptionDisposition::Required;
            (
                EncryptionDecisionKey {
                    source_identity: entry.source_identity,
                    destination_identity: entry.destination_identity,
                    bank: context.bank,
                    reserved: [0; 3],
                },
                EncryptionDecisionValue {
                    transport_id: entry.transport_id.unwrap_or_default(),
                    contract_revision: entry.contract_revision.map_or(0, Revision::get),
                    policy_revision: context.policy_revision.get(),
                    service_revision: context.service_revision.get(),
                    egress_revision: context.egress_revision.get(),
                    key_epoch: entry.key_epoch.unwrap_or_default(),
                    decision_witness: entry.decision_witness,
                    schema_version: ENCRYPTION_MAP_ABI_VERSION,
                    disposition: if required {
                        ENCRYPTION_DISPOSITION_REQUIRED
                    } else {
                        ENCRYPTION_DISPOSITION_NATIVE
                    },
                    flags: ENCRYPTION_DECISION_FLAG_POLICY_AUTHORIZED
                        | ENCRYPTION_DECISION_FLAG_SELECTION_BOUND,
                },
            )
        })
        .collect()
}

fn lower_transports(
    bank: u8,
    authority: &[EncryptionTransportAuthority],
) -> Vec<(EncryptionTransportKey, EncryptionTransportValue)> {
    authority
        .iter()
        .map(|entry| {
            let mut kernel_digest = [0; 16];
            kernel_digest.copy_from_slice(&entry.kernel_configuration_digest[..16]);
            let mut readiness_digest = [0; 16];
            readiness_digest.copy_from_slice(&entry.readiness_digest[..16]);
            (
                EncryptionTransportKey {
                    transport_id: entry.transport_id,
                    bank,
                    reserved: [0; 7],
                },
                EncryptionTransportValue {
                    key_epoch: entry.key_epoch,
                    contract_revision: entry.contract_revision.get(),
                    drain_until_monotonic_ns: entry.drain_until_monotonic_ns,
                    fwmark: entry.fwmark,
                    route_table: entry.route_table,
                    interface_index: entry.interface_index,
                    mtu: entry.mtu,
                    kernel_configuration_digest: kernel_digest,
                    readiness_digest,
                    schema_version: ENCRYPTION_MAP_ABI_VERSION,
                    state: match entry.state {
                        FastPathEpochState::Active => ENCRYPTION_TRANSPORT_ACTIVE,
                        FastPathEpochState::Draining => ENCRYPTION_TRANSPORT_DRAINING,
                    },
                    flags: ENCRYPTION_TRANSPORT_FLAG_KERNEL_READBACK,
                    reserved: [0; 4],
                },
            )
        })
        .collect()
}

fn state_digest(
    context: FastPathCompileContext,
    epoch_count: usize,
    decisions: &[FastPathDecisionAuthority],
    transports: &[EncryptionTransportAuthority],
) -> Result<EncryptionFastPathDigest, FastPathError> {
    let material = serde_json::to_vec(&(
        context.generation,
        context.policy_revision,
        context.service_revision,
        context.egress_revision,
        context.bank,
        epoch_count,
        decisions,
        transports,
    ))
    .map_err(|error| FastPathError::CanonicalEncoding(error.to_string()))?;
    let mut hasher = Sha256::new();
    hasher.update(FAST_PATH_DIGEST_DOMAIN);
    hasher.update(material);
    Ok(EncryptionFastPathDigest(hasher.finalize().into()))
}

fn encrypted(
    transport: &EncryptionTransportValue,
    lease: CausalEpochLease,
) -> FastPathPacketDecision {
    let Some(route_mark) = encryption_route_mark(transport.fwmark) else {
        return FastPathPacketDecision::Drop(FastPathDropReason::TransportUnavailable);
    };
    FastPathPacketDecision::Encrypt {
        outer_fwmark: transport.fwmark,
        route_mark,
        route_mark_mask: ENCRYPTION_ROUTE_MARK_MASK,
        route_table: transport.route_table,
        interface_index: transport.interface_index,
        mtu: transport.mtu,
        lease,
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    use unf_common::PolicyId;

    use super::*;
    use crate::{
        CausalCommitVector, EncryptionBaseline, EncryptionCapability, EncryptionContractFacts,
        EncryptionContractRevisions, EncryptionEndpointFact, EncryptionIntent, EncryptionKeyFact,
        EncryptionKeyPhase, EncryptionModel, EncryptionNode, EncryptionPathFact,
        EncryptionPolicyFact, EncryptionRouteAuthority, EncryptionRouteAuthorityError,
        EncryptionRouteFamily, FastPathMapCheckpoint, FastPathMapRecoveryAction,
        FastPathMapTransaction, FastPathTransactionError, IpPrefix, ManagedIdentitySelector,
        UNF_ENCRYPTION_RULE_PRIORITY_BASE, UNF_WIREGUARD_ROUTE_PROTOCOL, UnderlayAddressFamily,
        UnderlayMtuObservation, WireGuardEpochActivation, WireGuardKernelPlan,
        WireGuardKernelPlanInput, WireGuardKernelSnapshotInput, WireGuardMtuEnvelope,
        WireGuardPeerPlan, WireGuardPeerReadback, WireGuardPublicKey, WireGuardRouteReadback,
        WireGuardRouteScope,
    };

    struct Fixture {
        contract: AttestedEncryptionPathContract,
        transaction: ProofCarryingKernelTransaction,
        snapshot: WireGuardKernelSnapshot,
    }

    fn prefix(address: IpAddr, prefix_len: u8) -> IpPrefix {
        IpPrefix {
            address,
            prefix_len,
        }
    }

    fn node(name: &str, ordinal: u8) -> EncryptionNode {
        EncryptionNode {
            cluster_id: "cluster-a".to_owned(),
            name: name.to_owned(),
            uid: format!("uid-{name}"),
            pod_cidrs: vec![
                prefix(IpAddr::V4(Ipv4Addr::new(10, 42, ordinal, 0)), 24),
                prefix(
                    IpAddr::V6(Ipv6Addr::new(0xfd42, u16::from(ordinal), 0, 0, 0, 0, 0, 0)),
                    64,
                ),
            ],
            underlay_addresses: vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, ordinal))],
            capabilities: [
                EncryptionCapability::KernelWireGuard,
                EncryptionCapability::DualStackUnderlay,
                EncryptionCapability::PolicyRouting,
                EncryptionCapability::TwoEpochRotation,
                EncryptionCapability::EncryptedPathChallenge,
            ]
            .into_iter()
            .collect(),
        }
    }

    #[allow(clippy::too_many_lines)]
    fn fixture(epoch: u64) -> Fixture {
        let source_node = node("worker-a", 1);
        let destination_node = node("worker-b", 2);
        let source_identities = [IdentityId::new(11), IdentityId::new(12)];
        let destination_identities = [IdentityId::new(21), IdentityId::new(22)];
        let model = EncryptionModel::normalize(
            "cluster-a".to_owned(),
            EncryptionBaseline::Native,
            vec![EncryptionIntent {
                name: "required".to_owned(),
                uid: "uid-required".to_owned(),
                priority: 100,
                sources: ManagedIdentitySelector::Identities(
                    source_identities.into_iter().collect(),
                ),
                destinations: ManagedIdentitySelector::Identities(
                    destination_identities.into_iter().collect(),
                ),
            }],
        )
        .unwrap();
        let endpoints = source_identities
            .into_iter()
            .map(|identity| EncryptionEndpointFact {
                identity,
                workload_uid: format!("source-{}", identity.get()),
                node: source_node.clone(),
            })
            .chain(
                destination_identities
                    .into_iter()
                    .map(|identity| EncryptionEndpointFact {
                        identity,
                        workload_uid: format!("destination-{}", identity.get()),
                        node: destination_node.clone(),
                    }),
            )
            .collect::<Vec<_>>();
        let policies = source_identities
            .into_iter()
            .flat_map(|source| {
                destination_identities
                    .into_iter()
                    .map(move |destination| EncryptionPolicyFact {
                        source,
                        destination,
                        allowed: true,
                        policy_ids: vec![PolicyId::new(9)],
                    })
            })
            .collect();
        let path = |source: &EncryptionNode, destination: &EncryptionNode| EncryptionPathFact {
            source_node_uid: source.uid.clone(),
            destination_node_uid: destination.uid.clone(),
            epoch,
            path_class: EncryptionPathClass::ManagedPod,
            peer_endpoint: SocketAddr::new(destination.underlay_addresses[0], 51_820),
            allowed_ips: destination.pod_cidrs.clone(),
            interface_name: format!("unfwg{epoch:09}"),
            route_table: 20_000 + u32::try_from(epoch).unwrap(),
            fwmark: 0x0055_0000 + (u32::try_from(epoch).unwrap() << 8),
            mtu: 1_420,
        };
        let facts = EncryptionContractFacts {
            revisions: EncryptionContractRevisions {
                intent: Revision::new(1),
                identity: Revision::new(2),
                policy: Revision::new(3),
                routing: Revision::new(4),
                key: Revision::new(5),
            },
            active_epoch: epoch,
            endpoints,
            policies,
            keys: vec![
                EncryptionKeyFact {
                    node_uid: source_node.uid.clone(),
                    epoch,
                    public_key: WireGuardPublicKey([1; 32]),
                    phase: EncryptionKeyPhase::Active,
                    valid_from_unix_ms: 900,
                    valid_until_unix_ms: 3_000,
                },
                EncryptionKeyFact {
                    node_uid: destination_node.uid.clone(),
                    epoch,
                    public_key: WireGuardPublicKey([2; 32]),
                    phase: EncryptionKeyPhase::Active,
                    valid_from_unix_ms: 900,
                    valid_until_unix_ms: 3_000,
                },
            ],
            paths: vec![
                path(&source_node, &destination_node),
                path(&destination_node, &source_node),
            ],
        };
        let contract = AttestedEncryptionPathContract::issue(
            &model,
            &facts,
            source_node.clone(),
            Revision::new(8),
            950,
            2_500,
        )
        .unwrap();
        let mtu_envelope = WireGuardMtuEnvelope::derive(&[UnderlayMtuObservation {
            peer_node_uid: destination_node.uid.clone(),
            family: UnderlayAddressFamily::Ipv4,
            underlay_mtu: 1_480,
        }])
        .unwrap();
        let plan = WireGuardKernelPlan::new(WireGuardKernelPlanInput {
            cluster_id: "cluster-a".to_owned(),
            local_node_uid: source_node.uid,
            epoch,
            revision: Revision::new(9),
            interface_name: format!("unfwg{epoch:09}"),
            local_public_key: WireGuardPublicKey([1; 32]),
            listen_port: 51_820,
            fwmark: 0x0055_0000 + (u32::try_from(epoch).unwrap() << 8),
            route_table: 20_000 + u32::try_from(epoch).unwrap(),
            mtu_envelope,
            activation: WireGuardEpochActivation::Active,
            peers: vec![WireGuardPeerPlan {
                node_uid: destination_node.uid,
                public_key: WireGuardPublicKey([2; 32]),
                endpoint: SocketAddr::new(destination_node.underlay_addresses[0], 51_820),
                persistent_keepalive_seconds: 25,
                allowed_ips: destination_node.pod_cidrs.clone(),
            }],
        })
        .unwrap();
        let interface_index = 17;
        let snapshot = WireGuardKernelSnapshot::issue(WireGuardKernelSnapshotInput {
            interface_name: plan.interface_name.clone(),
            interface_index,
            owner_alias: plan.owner_alias.clone(),
            is_up: true,
            mtu: plan.mtu_envelope.interface_mtu,
            public_key: plan.local_public_key,
            listen_port: plan.listen_port,
            fwmark: plan.fwmark,
            peers: plan
                .peers
                .iter()
                .map(|peer| WireGuardPeerReadback {
                    public_key: peer.public_key,
                    endpoint: peer.endpoint,
                    persistent_keepalive_seconds: peer.persistent_keepalive_seconds,
                    allowed_ips: peer.allowed_ips.clone(),
                    last_handshake_unix_seconds: 1,
                    received_bytes: 1,
                    transmitted_bytes: 1,
                })
                .collect(),
            routes: plan
                .route_prefixes()
                .into_iter()
                .map(|route_prefix| WireGuardRouteReadback {
                    prefix: route_prefix,
                    interface_index,
                    table: plan.route_table,
                    protocol: UNF_WIREGUARD_ROUTE_PROTOCOL,
                    scope: WireGuardRouteScope::for_prefix(route_prefix),
                })
                .collect(),
        })
        .unwrap();
        let mut transaction =
            ProofCarryingKernelTransaction::begin(Revision::new(10), plan, None).unwrap();
        transaction.commit(&snapshot).unwrap();
        Fixture {
            contract,
            transaction,
            snapshot,
        }
    }

    const fn context(bank: u8) -> FastPathCompileContext {
        context_at(bank, 20)
    }

    const fn context_at(bank: u8, generation: u64) -> FastPathCompileContext {
        FastPathCompileContext {
            generation: Revision::new(generation),
            policy_revision: Revision::new(3),
            service_revision: Revision::new(30),
            egress_revision: Revision::new(40),
            bank,
            now_unix_ms: 1_000,
            now_monotonic_ns: 10_000,
        }
    }

    fn packet() -> FastPathPacketContext {
        FastPathPacketContext {
            source_identity: IdentityId::new(11),
            destination_identity: IdentityId::new(21),
            policy_authorized: true,
            policy_revision: Revision::new(3),
            service_revision: Revision::new(30),
            egress_revision: Revision::new(40),
            now_monotonic_ns: 11_000,
        }
    }

    fn required_state(
        fixture: &Fixture,
        compile_context: FastPathCompileContext,
    ) -> EncryptionFastPathState {
        compile_encryption_fast_path(
            compile_context,
            &[FastPathEpochAdmission {
                contract: &fixture.contract,
                transaction: &fixture.transaction,
                readback: &fixture.snapshot,
                readiness_digest: [7; 32],
                state: FastPathEpochState::Active,
                drain_until_monotonic_ns: 0,
            }],
            &[FastPathDecisionInput {
                source_identity: IdentityId::new(11),
                destination_identity: IdentityId::new(21),
                disposition: EncryptionDisposition::Required,
                contract_epoch: Some(7),
                plan_index: Some(0),
            }],
        )
        .unwrap()
    }

    #[test]
    fn identities_coalesce_without_losing_exact_decisions() {
        let fixture = fixture(7);
        let epoch = FastPathEpochAdmission {
            contract: &fixture.contract,
            transaction: &fixture.transaction,
            readback: &fixture.snapshot,
            readiness_digest: [7; 32],
            state: FastPathEpochState::Active,
            drain_until_monotonic_ns: 0,
        };
        let state = compile_encryption_fast_path(
            context(1),
            &[epoch],
            &[
                FastPathDecisionInput {
                    source_identity: IdentityId::new(11),
                    destination_identity: IdentityId::new(21),
                    disposition: EncryptionDisposition::Required,
                    contract_epoch: Some(7),
                    plan_index: Some(0),
                },
                FastPathDecisionInput {
                    source_identity: IdentityId::new(12),
                    destination_identity: IdentityId::new(22),
                    disposition: EncryptionDisposition::Required,
                    contract_epoch: Some(7),
                    plan_index: Some(3),
                },
            ],
        )
        .unwrap();
        assert_eq!(state.decisions.len(), 2);
        assert_eq!(state.transports.len(), 1);
        assert_eq!(
            state.decisions[0].1.transport_id,
            state.decisions[1].1.transport_id
        );
        assert!(matches!(
            select_encryption_transport(&state, packet(), None),
            FastPathPacketDecision::Encrypt { .. }
        ));

        let reversed = compile_encryption_fast_path(
            context(1),
            &[epoch],
            &[
                FastPathDecisionInput {
                    source_identity: IdentityId::new(12),
                    destination_identity: IdentityId::new(22),
                    disposition: EncryptionDisposition::Required,
                    contract_epoch: Some(7),
                    plan_index: Some(3),
                },
                FastPathDecisionInput {
                    source_identity: IdentityId::new(11),
                    destination_identity: IdentityId::new(21),
                    disposition: EncryptionDisposition::Required,
                    contract_epoch: Some(7),
                    plan_index: Some(0),
                },
            ],
        )
        .unwrap();
        assert_eq!(state.state_digest, reversed.state_digest);
        let mut mutated = state.clone();
        mutated.transports[0].1.mtu -= 1;
        assert_eq!(
            mutated.verify_integrity(),
            Err(FastPathError::IntegrityMismatch)
        );
    }

    #[test]
    fn policy_and_selection_revisions_fail_before_transport() {
        let fixture = fixture(7);
        let epoch = FastPathEpochAdmission {
            contract: &fixture.contract,
            transaction: &fixture.transaction,
            readback: &fixture.snapshot,
            readiness_digest: [7; 32],
            state: FastPathEpochState::Active,
            drain_until_monotonic_ns: 0,
        };
        let state = compile_encryption_fast_path(
            context(0),
            &[epoch],
            &[FastPathDecisionInput {
                source_identity: IdentityId::new(11),
                destination_identity: IdentityId::new(21),
                disposition: EncryptionDisposition::Required,
                contract_epoch: Some(7),
                plan_index: Some(0),
            }],
        )
        .unwrap();
        let mut denied = packet();
        denied.policy_authorized = false;
        assert_eq!(
            select_encryption_transport(&state, denied, None),
            FastPathPacketDecision::Drop(FastPathDropReason::PolicyDenied)
        );
        let mut stale_packet = packet();
        stale_packet.service_revision = Revision::new(31);
        assert_eq!(
            select_encryption_transport(&state, stale_packet, None),
            FastPathPacketDecision::Drop(FastPathDropReason::RevisionMismatch)
        );
    }

    #[test]
    fn cooperative_mark_lease_separates_inner_outer_and_preserves_foreign_bits() {
        let fixture = fixture(7);
        let state = compile_encryption_fast_path(
            context(0),
            &[FastPathEpochAdmission {
                contract: &fixture.contract,
                transaction: &fixture.transaction,
                readback: &fixture.snapshot,
                readiness_digest: [7; 32],
                state: FastPathEpochState::Active,
                drain_until_monotonic_ns: 0,
            }],
            &[FastPathDecisionInput {
                source_identity: IdentityId::new(11),
                destination_identity: IdentityId::new(21),
                disposition: EncryptionDisposition::Required,
                contract_epoch: Some(7),
                plan_index: Some(0),
            }],
        )
        .unwrap();
        let selection = select_encryption_transport(&state, packet(), None);
        let FastPathPacketDecision::Encrypt {
            outer_fwmark,
            route_mark,
            route_mark_mask,
            ..
        } = selection
        else {
            panic!("required flow must receive a cooperative mark lease");
        };
        assert_eq!(outer_fwmark, 0x0055_0700);
        assert_eq!(route_mark, 0x00aa_f800);
        assert_eq!(route_mark_mask, ENCRYPTION_ROUTE_MARK_MASK);
        assert_ne!(outer_fwmark & route_mark_mask, route_mark);

        let preexisting = 0x8100_005a;
        let marked = selection
            .apply_to_mark(preexisting)
            .expect("encrypt decision owns a valid mark lease");
        assert_eq!(marked, 0x81aa_f85a);
        assert_eq!(
            marked & !route_mark_mask,
            preexisting & !route_mark_mask,
            "neighboring skb mark fields must survive"
        );
        assert_eq!(
            FastPathPacketDecision::Native.apply_to_mark(marked),
            Some(preexisting),
            "native selection must release only UNF's mark lease"
        );
        assert_eq!(
            FastPathPacketDecision::Drop(FastPathDropReason::PolicyDenied)
                .apply_to_mark(preexisting),
            None,
            "a drop must never publish route metadata"
        );
    }

    #[test]
    fn cooperative_mark_lease_rejects_conflicting_route_table_authority() {
        let fixture = fixture(7);
        let state = compile_encryption_fast_path(
            context(0),
            &[FastPathEpochAdmission {
                contract: &fixture.contract,
                transaction: &fixture.transaction,
                readback: &fixture.snapshot,
                readiness_digest: [7; 32],
                state: FastPathEpochState::Active,
                drain_until_monotonic_ns: 0,
            }],
            &[FastPathDecisionInput {
                source_identity: IdentityId::new(11),
                destination_identity: IdentityId::new(21),
                disposition: EncryptionDisposition::Required,
                contract_epoch: Some(7),
                plan_index: Some(0),
            }],
        )
        .unwrap();
        let mut authority = state.transport_authority;
        let mut conflict = authority[0].clone();
        conflict.transport_id ^= 1;
        conflict.route_table += 1;
        authority.push(conflict);
        assert!(!route_marks_are_unambiguous(&authority));

        authority[1].route_table = authority[0].route_table;
        assert!(route_marks_are_unambiguous(&authority));
    }

    #[test]
    fn route_before_authority_binds_dual_stack_rules_to_exact_kernel_evidence() {
        let fixture = fixture(7);
        let state = required_state(&fixture, context_at(1, 21));
        let authority =
            EncryptionRouteAuthority::issue(&state, std::slice::from_ref(&fixture.snapshot))
                .unwrap();
        authority.verify().unwrap();

        assert_eq!(authority.generation, Revision::new(21));
        assert_eq!(authority.fast_path_digest, state.state_digest);
        assert_eq!(authority.rules.len(), 2);
        assert_eq!(authority.routes.len(), 2);
        assert_eq!(authority.rules[0].family, EncryptionRouteFamily::Ipv4);
        assert_eq!(authority.rules[1].family, EncryptionRouteFamily::Ipv6);
        assert_eq!(authority.rules[0].route_mark, 0x00aa_f800);
        assert_eq!(authority.rules[0].outer_fwmark, 0x0055_0700);
        assert_eq!(authority.rules[0].route_table, 20_007);
        assert_eq!(
            authority.rules[0].priority,
            UNF_ENCRYPTION_RULE_PRIORITY_BASE + 0xaaf8
        );
        let permit = authority.authorize_publication(&authority.rules).unwrap();
        permit.verify_for(&state).unwrap();

        let mut wrong_generation = required_state(&fixture, context_at(0, 22));
        assert!(matches!(
            permit.verify_for(&wrong_generation),
            Err(EncryptionRouteAuthorityError::InvalidPublicationPermit)
        ));
        wrong_generation.state_digest = state.state_digest;
        assert!(permit.verify_for(&wrong_generation).is_err());
    }

    #[test]
    fn route_before_authority_refuses_missing_mutated_or_partial_readback() {
        let fixture = fixture(7);
        let state = required_state(&fixture, context_at(1, 21));
        assert!(matches!(
            EncryptionRouteAuthority::issue(&state, &[]),
            Err(EncryptionRouteAuthorityError::KernelEvidenceMismatch)
        ));

        let mut mutated_snapshot = fixture.snapshot.clone();
        mutated_snapshot.routes[0].interface_index += 1;
        assert!(matches!(
            EncryptionRouteAuthority::issue(&state, &[mutated_snapshot]),
            Err(EncryptionRouteAuthorityError::InvalidKernelSnapshot(_))
        ));

        let mut authority =
            EncryptionRouteAuthority::issue(&state, std::slice::from_ref(&fixture.snapshot))
                .unwrap();
        let partial = &authority.rules[..1];
        assert!(matches!(
            authority.authorize_publication(partial),
            Err(EncryptionRouteAuthorityError::RuleReadbackMismatch)
        ));
        authority.rules[0].route_table += 1;
        assert!(matches!(
            authority.verify(),
            Err(EncryptionRouteAuthorityError::InvalidAuthority
                | EncryptionRouteAuthorityError::InvalidRule)
        ));
    }

    #[test]
    fn causal_epoch_lease_drains_then_denies_without_plaintext() {
        let old = fixture(6);
        let old_active = FastPathEpochAdmission {
            contract: &old.contract,
            transaction: &old.transaction,
            readback: &old.snapshot,
            readiness_digest: [6; 32],
            state: FastPathEpochState::Active,
            drain_until_monotonic_ns: 0,
        };
        let old_state = compile_encryption_fast_path(
            context(0),
            &[old_active],
            &[FastPathDecisionInput {
                source_identity: IdentityId::new(11),
                destination_identity: IdentityId::new(21),
                disposition: EncryptionDisposition::Required,
                contract_epoch: Some(6),
                plan_index: Some(0),
            }],
        )
        .unwrap();
        let FastPathPacketDecision::Encrypt { lease, .. } =
            select_encryption_transport(&old_state, packet(), None)
        else {
            panic!("old epoch must admit the flow");
        };

        let new = fixture(7);
        let rotating = compile_encryption_fast_path(
            context(1),
            &[
                FastPathEpochAdmission {
                    contract: &old.contract,
                    transaction: &old.transaction,
                    readback: &old.snapshot,
                    readiness_digest: [6; 32],
                    state: FastPathEpochState::Draining,
                    drain_until_monotonic_ns: 20_000,
                },
                FastPathEpochAdmission {
                    contract: &new.contract,
                    transaction: &new.transaction,
                    readback: &new.snapshot,
                    readiness_digest: [7; 32],
                    state: FastPathEpochState::Active,
                    drain_until_monotonic_ns: 0,
                },
            ],
            &[FastPathDecisionInput {
                source_identity: IdentityId::new(11),
                destination_identity: IdentityId::new(21),
                disposition: EncryptionDisposition::Required,
                contract_epoch: Some(7),
                plan_index: Some(0),
            }],
        )
        .unwrap();
        assert!(matches!(
            select_encryption_transport(&rotating, packet(), Some(lease)),
            FastPathPacketDecision::Encrypt { lease, .. } if lease.key_epoch == 6
        ));
        let mut wrong_identity = packet();
        wrong_identity.source_identity = IdentityId::new(12);
        assert_eq!(
            select_encryption_transport(&rotating, wrong_identity, Some(lease)),
            FastPathPacketDecision::Drop(FastPathDropReason::LeaseExpiredOrRevoked)
        );
        let mut expired = packet();
        expired.now_monotonic_ns = 20_001;
        assert_eq!(
            select_encryption_transport(&rotating, expired, Some(lease)),
            FastPathPacketDecision::Drop(FastPathDropReason::LeaseExpiredOrRevoked)
        );
        let FastPathPacketDecision::Encrypt {
            lease: new_lease, ..
        } = select_encryption_transport(&rotating, packet(), None)
        else {
            panic!("new flow must use the active epoch");
        };
        assert_eq!(new_lease.key_epoch, 7);

        let mut revoked = rotating.clone();
        revoked
            .transports
            .retain(|(key, _)| key.transport_id != lease.transport_id);
        assert_eq!(
            select_encryption_transport(&revoked, packet(), Some(lease)),
            FastPathPacketDecision::Drop(FastPathDropReason::LeaseExpiredOrRevoked)
        );
    }

    #[test]
    fn explicit_native_is_distinct_from_missing_authority() {
        let fixture = fixture(7);
        let state = compile_encryption_fast_path(
            context(0),
            &[FastPathEpochAdmission {
                contract: &fixture.contract,
                transaction: &fixture.transaction,
                readback: &fixture.snapshot,
                readiness_digest: [7; 32],
                state: FastPathEpochState::Active,
                drain_until_monotonic_ns: 0,
            }],
            &[FastPathDecisionInput {
                source_identity: IdentityId::new(11),
                destination_identity: IdentityId::new(21),
                disposition: EncryptionDisposition::Native,
                contract_epoch: None,
                plan_index: None,
            }],
        )
        .unwrap();
        assert_eq!(
            select_encryption_transport(&state, packet(), None),
            FastPathPacketDecision::Native
        );
        let mut corrupt = state.clone();
        corrupt.decisions[0].1.transport_id = 99;
        assert_eq!(
            select_encryption_transport(&corrupt, packet(), None),
            FastPathPacketDecision::Drop(FastPathDropReason::RevisionMismatch)
        );
        let mut unknown = packet();
        unknown.destination_identity = IdentityId::new(99);
        assert_eq!(
            select_encryption_transport(&state, unknown, None),
            FastPathPacketDecision::Drop(FastPathDropReason::AuthorityMissing)
        );
    }

    #[test]
    fn noncommitted_kernel_state_never_becomes_packet_authority() {
        let fixture = fixture(7);
        let prepared = ProofCarryingKernelTransaction::begin(
            Revision::new(11),
            fixture.transaction.plan.clone(),
            None,
        )
        .unwrap();
        assert_eq!(
            compile_encryption_fast_path(
                context(0),
                &[FastPathEpochAdmission {
                    contract: &fixture.contract,
                    transaction: &prepared,
                    readback: &fixture.snapshot,
                    readiness_digest: [7; 32],
                    state: FastPathEpochState::Active,
                    drain_until_monotonic_ns: 0,
                }],
                &[FastPathDecisionInput {
                    source_identity: IdentityId::new(11),
                    destination_identity: IdentityId::new(21),
                    disposition: EncryptionDisposition::Required,
                    contract_epoch: Some(7),
                    plan_index: Some(0),
                }],
            ),
            Err(FastPathError::KernelAuthorityUnavailable)
        );
    }

    #[test]
    fn causal_commit_vector_makes_every_crash_boundary_total() {
        let fixture = fixture(7);
        let prior_state = required_state(&fixture, context_at(0, 20));
        let desired_state = required_state(&fixture, context_at(1, 21));
        let prior = crate::FastPathPublishedGeneration::issue(&prior_state).unwrap();
        let vector = CausalCommitVector::issue(&desired_state).unwrap();
        vector.verify().unwrap();
        assert_eq!(vector.active_epoch, 7);
        assert_eq!(vector.kernel_configuration_digests.len(), 1);

        let mut transaction =
            FastPathMapTransaction::begin(Revision::new(22), vector, Some(prior)).unwrap();
        assert_eq!(
            transaction.recover(Some(prior), None).unwrap(),
            FastPathMapRecoveryAction::ClearAndRestageInactive
        );
        transaction.record_staged(&desired_state).unwrap();
        assert_eq!(
            transaction
                .recover(Some(prior), Some(desired_state.state_digest))
                .unwrap(),
            FastPathMapRecoveryAction::ActivateDesired
        );
        let desired = transaction.desired.published;
        assert_eq!(
            transaction
                .recover(Some(desired), Some(desired_state.state_digest))
                .unwrap(),
            FastPathMapRecoveryAction::CommitObservedDesired
        );
        transaction.commit(&desired_state).unwrap();
        assert_eq!(
            transaction
                .recover(Some(desired), Some(desired_state.state_digest))
                .unwrap(),
            FastPathMapRecoveryAction::ReuseCommitted
        );

        let mut mutated = transaction.clone();
        mutated.desired.active_epoch += 1;
        assert_eq!(
            mutated.verify(),
            Err(FastPathTransactionError::InvalidCommitVector)
        );
        let json = serde_json::to_string(&transaction).unwrap();
        assert!(!json.contains("private"));
        assert!(
            serde_json::from_str::<FastPathMapTransaction>(&json.replacen(
                '{',
                "{\"unknown\":true,",
                1
            ))
            .is_err()
        );
    }

    #[test]
    fn proof_carrying_map_mirror_reconstructs_exact_restart_bytes() {
        let fixture = fixture(7);
        let desired = required_state(&fixture, context_at(1, 21));
        let mut checkpoint =
            FastPathMapCheckpoint::begin(Revision::new(22), &desired, None).unwrap();
        let encoded = serde_json::to_vec(&checkpoint).unwrap();
        let restored: FastPathMapCheckpoint = serde_json::from_slice(&encoded).unwrap();
        restored.verify().unwrap();
        assert_eq!(restored.desired_state().unwrap(), desired);
        let mut unknown: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
        unknown["unexpected"] = serde_json::json!(true);
        assert!(serde_json::from_value::<FastPathMapCheckpoint>(unknown).is_err());

        checkpoint.record_staged(&desired).unwrap();
        checkpoint.commit(&desired).unwrap();
        checkpoint.verify().unwrap();
        assert_eq!(
            checkpoint.transaction.phase,
            crate::FastPathMapTransactionPhase::Committed
        );

        let mut mutated = restored;
        mutated.transport_authority[0].fwmark ^= 1;
        assert_eq!(
            mutated.verify(),
            Err(FastPathTransactionError::InvalidFastPath(
                FastPathError::IntegrityMismatch
            ))
        );
    }

    #[test]
    fn causal_commit_rollback_requires_prior_and_positive_absence() {
        let fixture = fixture(7);
        let desired_state = required_state(&fixture, context_at(1, 21));
        let vector = CausalCommitVector::issue(&desired_state).unwrap();
        let mut transaction =
            FastPathMapTransaction::begin(Revision::new(22), vector, None).unwrap();
        assert!(transaction.record_rollback(None, false).is_err());
        transaction.record_rollback(None, true).unwrap();
        assert_eq!(
            transaction.recover(None, None).unwrap(),
            FastPathMapRecoveryAction::RollbackComplete
        );
        assert_eq!(
            transaction
                .recover(None, Some(EncryptionFastPathDigest([9; 32])))
                .unwrap(),
            FastPathMapRecoveryAction::RefuseUnknownState
        );
    }
}
