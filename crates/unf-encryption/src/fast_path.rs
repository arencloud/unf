//! Intent-coalesced encryption transport compiler and packet-decision mirror.
//!
//! Identity authority remains exact while identical Node/epoch transports are
//! shared. The compiler is pure: callers stage its fixed-width output into an
//! inactive BPF bank and publish only [`EncryptionMapConfig`] atomically.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use unf_common::{IdentityId, Revision};
use unf_ebpf_common::{
    ENCRYPTION_BANK_COUNT, ENCRYPTION_DECISION_FLAG_ADDRESS_BOUND,
    ENCRYPTION_DECISION_FLAG_POLICY_AUTHORIZED, ENCRYPTION_DECISION_FLAG_SELECTION_BOUND,
    ENCRYPTION_DECISION_MAP_CAPACITY, ENCRYPTION_DISPOSITION_NATIVE,
    ENCRYPTION_DISPOSITION_REQUIRED, ENCRYPTION_FLOW_FLAG_ESTABLISHED_LEASE,
    ENCRYPTION_MAP_ABI_VERSION, ENCRYPTION_PATH_MAP_CAPACITY, ENCRYPTION_ROUTE_MARK_MASK,
    ENCRYPTION_TRANSPORT_ACTIVE, ENCRYPTION_TRANSPORT_DRAINING,
    ENCRYPTION_TRANSPORT_FLAG_KERNEL_READBACK, ENCRYPTION_TRANSPORT_MAP_CAPACITY,
    EncryptionDecisionKey, EncryptionDecisionValue, EncryptionFlowValue, EncryptionIpv4PathData,
    EncryptionIpv6PathData, EncryptionMapConfig, EncryptionPathValue, EncryptionTransportKey,
    EncryptionTransportValue, apply_encryption_route_mark, clear_encryption_route_mark,
    encryption_route_mark, encryption_transport_is_usable,
};

use crate::{
    AttestedEncryptionPathContract, EncryptionDisposition, EncryptionPathClass,
    KernelTransactionPhase, ProofCarryingKernelTransaction, WireGuardKernelSnapshot,
};

pub const MAX_FAST_PATH_DECISIONS: usize = ENCRYPTION_DECISION_MAP_CAPACITY as usize;
pub const MAX_FAST_PATH_TRANSPORTS: usize = ENCRYPTION_TRANSPORT_MAP_CAPACITY as usize;
pub const MAX_FAST_PATH_PATHS: usize = ENCRYPTION_PATH_MAP_CAPACITY as usize;
pub const MAX_FAST_PATH_EPOCHS: usize = 2;

const FAST_PATH_DIGEST_DOMAIN: &[u8] = b"unf.encryption-fast-path.v2\0";
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

/// One destination-prefix-to-transport binding used only when an identity
/// pair can land on multiple remote Nodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EncryptionPathAuthority {
    pub prefix: crate::IpPrefix,
    pub transport_id: u64,
    pub contract_revision: Revision,
    pub key_epoch: u64,
    pub binding_witness: [u8; 16],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EncryptionFastPathDigest(pub [u8; 32]);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptionFastPathState {
    pub config: EncryptionMapConfig,
    pub decisions: Vec<(EncryptionDecisionKey, EncryptionDecisionValue)>,
    pub transports: Vec<(EncryptionTransportKey, EncryptionTransportValue)>,
    pub ipv4_paths: Vec<(u32, EncryptionIpv4PathData, EncryptionPathValue)>,
    pub ipv6_paths: Vec<(u32, EncryptionIpv6PathData, EncryptionPathValue)>,
    pub decision_authority: Vec<FastPathDecisionAuthority>,
    pub transport_authority: Vec<EncryptionTransportAuthority>,
    pub path_authority: Vec<EncryptionPathAuthority>,
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
            || usize::from(self.config.epoch_count) > MAX_FAST_PATH_EPOCHS
            || self.config.epoch_count == 0
                && (!self.decision_authority.is_empty()
                    || !self.transport_authority.is_empty()
                    || !self.path_authority.is_empty())
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
            &self.path_authority,
        )?;
        if self.config != expected_config
            || self.decisions != lower_decisions(context, &self.decision_authority)
            || self.transports
                != lower_transports(self.config.active_bank, &self.transport_authority)
            || self.ipv4_paths != lower_ipv4_paths(self.config.active_bank, &self.path_authority)
            || self.ipv6_paths != lower_ipv6_paths(self.config.active_bank, &self.path_authority)
            || self.state_digest
                != state_digest(
                    context,
                    usize::from(self.config.epoch_count),
                    &self.decision_authority,
                    &self.transport_authority,
                    &self.path_authority,
                )?
            || !transport_ids_are_valid(&self.transport_authority)
            || !route_marks_are_unambiguous(&self.transport_authority)
            || !paths_are_valid(&self.path_authority, &self.transport_authority)
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
    pub paths: Vec<EncryptionPathAuthority>,
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
        &authority.paths,
    )?;
    let decisions = lower_decisions(context, &authority.decisions);
    let transports = lower_transports(authority.bank, &authority.transports);
    let ipv4_paths = lower_ipv4_paths(authority.bank, &authority.paths);
    let ipv6_paths = lower_ipv6_paths(authority.bank, &authority.paths);
    let state_digest = state_digest(
        context,
        usize::from(authority.epoch_count),
        &authority.decisions,
        &authority.transports,
        &authority.paths,
    )?;
    if state_digest != authority.expected_digest {
        return Err(FastPathError::IntegrityMismatch);
    }
    let state = EncryptionFastPathState {
        config,
        decisions,
        transports,
        ipv4_paths,
        ipv6_paths,
        decision_authority: authority.decisions,
        transport_authority: authority.transports,
        path_authority: authority.paths,
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
    /// Final backend or egress address after Service and egress resolution.
    pub destination_address: IpAddr,
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
    let (mut decision_authority, path_authority) =
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
        &path_authority,
    )?;
    let decisions = lower_decisions(context, &decision_authority);
    let transports = lower_transports(context.bank, &transport_authority);
    let ipv4_paths = lower_ipv4_paths(context.bank, &path_authority);
    let ipv6_paths = lower_ipv6_paths(context.bank, &path_authority);
    let state_digest = state_digest(
        context,
        epochs.len(),
        &decision_authority,
        &transport_authority,
        &path_authority,
    )?;
    let state = EncryptionFastPathState {
        config,
        decisions,
        transports,
        ipv4_paths,
        ipv6_paths,
        decision_authority,
        transport_authority,
        path_authority,
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
) -> Result<(Vec<FastPathDecisionAuthority>, Vec<EncryptionPathAuthority>), FastPathError> {
    let mut grouped = BTreeMap::<(IdentityId, IdentityId), Vec<FastPathDecisionInput>>::new();
    for input in inputs {
        if input.source_identity.get() == 0 || input.destination_identity.get() == 0 {
            return Err(FastPathError::InvalidDecision);
        }
        grouped
            .entry((input.source_identity, input.destination_identity))
            .or_default()
            .push(*input);
    }
    let mut decisions = Vec::with_capacity(grouped.len());
    let mut paths = BTreeMap::<crate::IpPrefix, EncryptionPathAuthority>::new();
    for ((source, destination), group) in grouped {
        if group.len() == 1 {
            let input = group[0];
            decisions.push(match input.disposition {
                EncryptionDisposition::Native => native_decision(context, input)?,
                EncryptionDisposition::Required => {
                    required_decision(context, input, admitted, transports)?.0
                }
            });
            continue;
        }
        decisions.push(compile_replicated_decision(
            context,
            source,
            destination,
            group,
            admitted,
            transports,
            &mut paths,
        )?);
    }
    let paths = paths.into_values().collect::<Vec<_>>();
    if paths.len() > MAX_FAST_PATH_PATHS {
        return Err(FastPathError::Capacity {
            kind: "path",
            actual: paths.len(),
            limit: MAX_FAST_PATH_PATHS,
        });
    }
    Ok((decisions, paths))
}

fn compile_replicated_decision<'a>(
    context: FastPathCompileContext,
    source: IdentityId,
    destination: IdentityId,
    group: Vec<FastPathDecisionInput>,
    admitted: &BTreeMap<u64, &'a FastPathEpochAdmission<'a>>,
    transports: &mut TransportIndex<'a>,
    paths: &mut BTreeMap<crate::IpPrefix, EncryptionPathAuthority>,
) -> Result<FastPathDecisionAuthority, FastPathError> {
    if group
        .iter()
        .any(|input| input.disposition != EncryptionDisposition::Required)
    {
        return Err(FastPathError::InvalidDecision);
    }
    let mut references = BTreeSet::new();
    let mut bindings = Vec::with_capacity(group.len());
    for input in group {
        if !references.insert((input.contract_epoch, input.plan_index)) {
            return Err(FastPathError::InvalidDecision);
        }
        bindings.push(required_decision(context, input, admitted, transports)?);
    }
    let contract_revision = bindings[0]
        .0
        .contract_revision
        .ok_or(FastPathError::RequiredAuthorityUnavailable)?;
    let key_epoch = bindings[0]
        .0
        .key_epoch
        .ok_or(FastPathError::RequiredAuthorityUnavailable)?;
    if bindings.iter().any(|(decision, _)| {
        decision.contract_revision != Some(contract_revision)
            || decision.key_epoch != Some(key_epoch)
    }) {
        return Err(FastPathError::RequiredAuthorityUnavailable);
    }
    let mut plan_witnesses = Vec::with_capacity(bindings.len());
    for (decision, prefixes) in bindings {
        let transport_id = decision
            .transport_id
            .ok_or(FastPathError::RequiredAuthorityUnavailable)?;
        plan_witnesses.push(decision.decision_witness);
        insert_path_bindings(paths, prefixes, transport_id, contract_revision, key_epoch)?;
    }
    plan_witnesses.sort_unstable();
    Ok(FastPathDecisionAuthority {
        source_identity: source,
        destination_identity: destination,
        disposition: EncryptionDisposition::Required,
        transport_id: None,
        contract_revision: Some(contract_revision),
        key_epoch: Some(key_epoch),
        decision_witness: aggregate_decision_witness(context, source, destination, &plan_witnesses),
    })
}

fn insert_path_bindings(
    paths: &mut BTreeMap<crate::IpPrefix, EncryptionPathAuthority>,
    prefixes: Vec<crate::IpPrefix>,
    transport_id: u64,
    contract_revision: Revision,
    key_epoch: u64,
) -> Result<(), FastPathError> {
    for prefix in prefixes {
        let candidate = EncryptionPathAuthority {
            prefix,
            transport_id,
            contract_revision,
            key_epoch,
            binding_witness: path_binding_witness(
                prefix,
                transport_id,
                contract_revision,
                key_epoch,
            )?,
        };
        if let Some(existing) = paths.insert(prefix, candidate)
            && existing != candidate
        {
            return Err(FastPathError::RequiredAuthorityUnavailable);
        }
    }
    Ok(())
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
) -> Result<(FastPathDecisionAuthority, Vec<crate::IpPrefix>), FastPathError> {
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
    Ok((
        FastPathDecisionAuthority {
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
        },
        plan.transport.forward.allowed_ips.clone(),
    ))
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
    paths: &[EncryptionPathAuthority],
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
        path_count: u32::try_from(paths.len()).map_err(|_| FastPathError::Capacity {
            kind: "path",
            actual: paths.len(),
            limit: MAX_FAST_PATH_PATHS,
        })?,
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
    if let Some(lease) = established {
        return select_established_transport(state, packet, lease);
    }
    let Some((_, decision)) = state.decisions.iter().find(|(key, _)| {
        key.bank == state.config.active_bank
            && key.source_identity == packet.source_identity
            && key.destination_identity == packet.destination_identity
    }) else {
        return FastPathPacketDecision::Drop(FastPathDropReason::AuthorityMissing);
    };
    let base_flags =
        ENCRYPTION_DECISION_FLAG_POLICY_AUTHORIZED | ENCRYPTION_DECISION_FLAG_SELECTION_BOUND;
    let address_bound = decision.flags == base_flags | ENCRYPTION_DECISION_FLAG_ADDRESS_BOUND;
    if decision.schema_version != ENCRYPTION_MAP_ABI_VERSION
        || decision.decision_witness == [0; 16]
        || decision.flags != base_flags && !address_bound
        || decision.policy_revision != packet.policy_revision.get()
        || decision.service_revision != packet.service_revision.get()
        || decision.egress_revision != packet.egress_revision.get()
    {
        return FastPathPacketDecision::Drop(FastPathDropReason::RevisionMismatch);
    }
    if decision.disposition == ENCRYPTION_DISPOSITION_NATIVE {
        return if !address_bound
            && decision.transport_id == 0
            && decision.contract_revision == 0
            && decision.key_epoch == 0
        {
            FastPathPacketDecision::Native
        } else {
            FastPathPacketDecision::Drop(FastPathDropReason::RevisionMismatch)
        };
    }
    if decision.disposition != ENCRYPTION_DISPOSITION_REQUIRED
        || decision.contract_revision == 0
        || decision.key_epoch == 0
    {
        return FastPathPacketDecision::Drop(FastPathDropReason::RevisionMismatch);
    }
    let transport_id = match resolve_new_transport_id(state, packet, decision, address_bound) {
        Ok(transport_id) => transport_id,
        Err(reason) => return FastPathPacketDecision::Drop(reason),
    };
    let Some((_, transport)) = state
        .transports
        .iter()
        .find(|(key, _)| key.bank == state.config.active_bank && key.transport_id == transport_id)
    else {
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
            transport_id,
            key_epoch: decision.key_epoch,
            contract_revision: decision.contract_revision,
            decision_witness: decision.decision_witness,
            last_seen_monotonic_ns: packet.now_monotonic_ns,
            drain_until_monotonic_ns: transport.drain_until_monotonic_ns,
        },
    )
}

fn resolve_new_transport_id(
    state: &EncryptionFastPathState,
    packet: FastPathPacketContext,
    decision: &EncryptionDecisionValue,
    address_bound: bool,
) -> Result<u64, FastPathDropReason> {
    if !address_bound {
        return (decision.transport_id != 0)
            .then_some(decision.transport_id)
            .ok_or(FastPathDropReason::RevisionMismatch);
    }
    if decision.transport_id != 0 {
        return Err(FastPathDropReason::RevisionMismatch);
    }
    let path = state
        .path_authority
        .iter()
        .filter(|path| path.prefix.contains(packet.destination_address))
        .max_by_key(|path| path.prefix.prefix_len)
        .ok_or(FastPathDropReason::TransportUnavailable)?;
    if path.contract_revision.get() != decision.contract_revision
        || path.key_epoch != decision.key_epoch
        || path.binding_witness == [0; 16]
    {
        return Err(FastPathDropReason::RevisionMismatch);
    }
    Ok(path.transport_id)
}

fn select_established_transport(
    state: &EncryptionFastPathState,
    packet: FastPathPacketContext,
    mut lease: CausalEpochLease,
) -> FastPathPacketDecision {
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
    encrypted(transport, lease)
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
    if epochs.len() > MAX_FAST_PATH_EPOCHS
        || epochs.is_empty() && !inputs.is_empty()
        || !epochs.is_empty()
            && epochs
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

fn paths_are_valid(
    paths: &[EncryptionPathAuthority],
    transports: &[EncryptionTransportAuthority],
) -> bool {
    let mut seen = BTreeSet::new();
    paths.iter().enumerate().all(|(index, path)| {
        path.prefix.is_canonical()
            && seen.insert(path.prefix)
            && !paths
                .iter()
                .skip(index + 1)
                .any(|other| path.prefix.overlaps(other.prefix))
            && path.binding_witness
                == path_binding_witness(
                    path.prefix,
                    path.transport_id,
                    path.contract_revision,
                    path.key_epoch,
                )
                .unwrap_or_default()
            && transports.iter().any(|transport| {
                transport.transport_id == path.transport_id
                    && transport.contract_revision == path.contract_revision
                    && transport.key_epoch == path.key_epoch
                    && transport.state == FastPathEpochState::Active
            })
    })
}

fn path_binding_witness(
    prefix: crate::IpPrefix,
    transport_id: u64,
    contract_revision: Revision,
    key_epoch: u64,
) -> Result<[u8; 16], FastPathError> {
    let material = serde_json::to_vec(&(prefix, transport_id, contract_revision, key_epoch))
        .map_err(|error| FastPathError::CanonicalEncoding(error.to_string()))?;
    let mut hasher = Sha256::new();
    hasher.update(b"unf.encryption-address-path.v1\0");
    hasher.update(material);
    let digest = hasher.finalize();
    let mut witness = [0; 16];
    witness.copy_from_slice(&digest[..16]);
    Ok(witness)
}

fn aggregate_decision_witness(
    context: FastPathCompileContext,
    source: IdentityId,
    destination: IdentityId,
    plan_witnesses: &[[u8; 16]],
) -> [u8; 16] {
    let mut hasher = Sha256::new();
    hasher.update(b"unf.encryption-replica-decision.v1\0");
    hasher.update(context.generation.get().to_be_bytes());
    hasher.update(source.get().to_be_bytes());
    hasher.update(destination.get().to_be_bytes());
    for witness in plan_witnesses {
        hasher.update(witness);
    }
    let digest = hasher.finalize();
    let mut witness = [0; 16];
    witness.copy_from_slice(&digest[..16]);
    witness
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
                        | ENCRYPTION_DECISION_FLAG_SELECTION_BOUND
                        | if required && entry.transport_id.is_none() {
                            ENCRYPTION_DECISION_FLAG_ADDRESS_BOUND
                        } else {
                            0
                        },
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

fn lower_ipv4_paths(
    bank: u8,
    authority: &[EncryptionPathAuthority],
) -> Vec<(u32, EncryptionIpv4PathData, EncryptionPathValue)> {
    authority
        .iter()
        .filter_map(|entry| match entry.prefix.address {
            IpAddr::V4(address) => Some((
                u32::from(entry.prefix.prefix_len),
                EncryptionIpv4PathData {
                    bank,
                    reserved: [0; 3],
                    destination_address: address.octets(),
                },
                lower_path_value(entry),
            )),
            IpAddr::V6(_) => None,
        })
        .collect()
}

fn lower_ipv6_paths(
    bank: u8,
    authority: &[EncryptionPathAuthority],
) -> Vec<(u32, EncryptionIpv6PathData, EncryptionPathValue)> {
    authority
        .iter()
        .filter_map(|entry| match entry.prefix.address {
            IpAddr::V4(_) => None,
            IpAddr::V6(address) => Some((
                u32::from(entry.prefix.prefix_len),
                EncryptionIpv6PathData {
                    bank,
                    reserved: [0; 3],
                    destination_address: address.octets(),
                },
                lower_path_value(entry),
            )),
        })
        .collect()
}

fn lower_path_value(entry: &EncryptionPathAuthority) -> EncryptionPathValue {
    EncryptionPathValue {
        transport_id: entry.transport_id,
        contract_revision: entry.contract_revision.get(),
        key_epoch: entry.key_epoch,
        binding_witness: entry.binding_witness,
        schema_version: ENCRYPTION_MAP_ABI_VERSION,
        flags: 0,
        reserved: [0; 5],
    }
}

fn state_digest(
    context: FastPathCompileContext,
    epoch_count: usize,
    decisions: &[FastPathDecisionAuthority],
    transports: &[EncryptionTransportAuthority],
    paths: &[EncryptionPathAuthority],
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
        paths,
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

    use unf_common::{PolicyId, PolicyReason};

    use super::*;
    use crate::{
        AuthenticatedNodeIdentity, CausalCommitVector, EncryptionActivationLatch,
        EncryptionActivationLatchError, EncryptionActivationMode, EncryptionBaseline,
        EncryptionCapability, EncryptionContractFacts, EncryptionContractRevisions,
        EncryptionEndpointFact, EncryptionEndpointPathProof, EncryptionFrontierPublishOutcome,
        EncryptionGenerationDistributionError, EncryptionGenerationFact,
        EncryptionGenerationFactError, EncryptionGenerationFactOutcome,
        EncryptionGenerationFactReconciler, EncryptionGenerationFrontier,
        EncryptionGenerationFrontierError, EncryptionGenerationPathProofPermit,
        EncryptionGenerationProducer, EncryptionGenerationRecipient, EncryptionGenerationRequest,
        EncryptionIntent, EncryptionKeyFact, EncryptionKeyPhase, EncryptionModel, EncryptionNode,
        EncryptionPathActivationReceipt, EncryptionPathEndpointRole, EncryptionPathFact,
        EncryptionPathProofError, EncryptionPathProofLedger, EncryptionPathProofRound,
        EncryptionPolicyFact, EncryptionRouteAuthority, EncryptionRouteAuthorityError,
        EncryptionRouteFamily, FastPathMapCheckpoint, FastPathMapRecoveryAction,
        FastPathMapTransaction, FastPathPublishedGeneration, FastPathTransactionError, IpPrefix,
        LinuxPreparedLocalGeneration, ManagedIdentitySelector, NodeLocalGenerationProposal,
        NodeLocalOrchestratorError, NodeLocalRecoveryPlan, NodeSealedGenerationCapsule,
        PreparedNodeEncryptionGeneration, UNF_ENCRYPTION_RULE_PRIORITY_BASE,
        UNF_WIREGUARD_ROUTE_PROTOCOL, UnderlayAddressFamily, UnderlayMtuObservation,
        WireGuardEpochActivation, WireGuardKernelPlan, WireGuardKernelPlanInput,
        WireGuardKernelSnapshotInput, WireGuardMtuEnvelope, WireGuardPeerPlan,
        WireGuardPeerReadback, WireGuardPublicKey, WireGuardRouteReadback, WireGuardRouteScope,
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
        fixture_with_replica(epoch, false)
    }

    #[allow(clippy::too_many_lines)]
    fn fixture_with_replica(epoch: u64, replicated: bool) -> Fixture {
        let source_node = node("worker-a", 1);
        let destination_node = node("worker-b", 2);
        let replica_node = node("worker-c", 3);
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
        let mut endpoints = source_identities
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
        if replicated {
            endpoints.extend(destination_identities.into_iter().map(|identity| {
                EncryptionEndpointFact {
                    identity,
                    workload_uid: format!("replica-{}", identity.get()),
                    node: replica_node.clone(),
                }
            }));
        }
        let policies = source_identities
            .into_iter()
            .flat_map(|source| {
                destination_identities
                    .into_iter()
                    .map(move |destination| EncryptionPolicyFact {
                        source,
                        destination,
                        allowed: true,
                        reason: PolicyReason::ExplicitRule,
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
        let mut keys = vec![
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
        ];
        let mut paths = vec![
            path(&source_node, &destination_node),
            path(&destination_node, &source_node),
        ];
        if replicated {
            keys.push(EncryptionKeyFact {
                node_uid: replica_node.uid.clone(),
                epoch,
                public_key: WireGuardPublicKey([3; 32]),
                phase: EncryptionKeyPhase::Active,
                valid_from_unix_ms: 900,
                valid_until_unix_ms: 3_000,
            });
            paths.push(path(&source_node, &replica_node));
            paths.push(path(&replica_node, &source_node));
        }
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
            keys,
            paths,
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
        let mut mtu_observations = vec![UnderlayMtuObservation {
            peer_node_uid: destination_node.uid.clone(),
            family: UnderlayAddressFamily::Ipv4,
            underlay_mtu: 1_480,
        }];
        if replicated {
            mtu_observations.push(UnderlayMtuObservation {
                peer_node_uid: replica_node.uid.clone(),
                family: UnderlayAddressFamily::Ipv4,
                underlay_mtu: 1_480,
            });
        }
        let mtu_envelope = WireGuardMtuEnvelope::derive(&mtu_observations).unwrap();
        let mut peers = vec![WireGuardPeerPlan {
            node_uid: destination_node.uid.clone(),
            public_key: WireGuardPublicKey([2; 32]),
            endpoint: SocketAddr::new(destination_node.underlay_addresses[0], 51_820),
            persistent_keepalive_seconds: 25,
            allowed_ips: destination_node.pod_cidrs.clone(),
        }];
        if replicated {
            peers.push(WireGuardPeerPlan {
                node_uid: replica_node.uid.clone(),
                public_key: WireGuardPublicKey([3; 32]),
                endpoint: SocketAddr::new(replica_node.underlay_addresses[0], 51_820),
                persistent_keepalive_seconds: 25,
                allowed_ips: replica_node.pod_cidrs.clone(),
            });
        }
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
            peers,
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
            destination_address: "10.2.0.8".parse().unwrap(),
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

    fn path_snapshot(
        fixture: &Fixture,
        role: EncryptionPathEndpointRole,
        received_bytes: u64,
        transmitted_bytes: u64,
    ) -> WireGuardKernelSnapshot {
        let plan = &fixture.contract.plans[0];
        let (path, local_key, peer_key, interface_index) = match role {
            EncryptionPathEndpointRole::Source => (
                &plan.transport.forward,
                plan.source_key.public_key,
                plan.destination_key.public_key,
                fixture.snapshot.interface_index,
            ),
            EncryptionPathEndpointRole::Destination => (
                &plan.transport.reverse,
                plan.destination_key.public_key,
                plan.source_key.public_key,
                fixture.snapshot.interface_index + 1,
            ),
        };
        let owner_alias = match role {
            EncryptionPathEndpointRole::Source => fixture.snapshot.owner_alias.clone(),
            EncryptionPathEndpointRole::Destination => {
                format!(
                    "unf:encryption:v1:fixture:destination:{}",
                    plan.source_key.epoch
                )
            }
        };
        WireGuardKernelSnapshot::issue(WireGuardKernelSnapshotInput {
            interface_name: path.interface_name.clone(),
            interface_index,
            owner_alias,
            is_up: true,
            mtu: path.mtu,
            public_key: local_key,
            listen_port: 51_820,
            fwmark: path.fwmark,
            peers: vec![WireGuardPeerReadback {
                public_key: peer_key,
                endpoint: path.peer_endpoint,
                persistent_keepalive_seconds: 25,
                allowed_ips: path.allowed_ips.clone(),
                last_handshake_unix_seconds: 1,
                received_bytes,
                transmitted_bytes,
            }],
            routes: path
                .allowed_ips
                .iter()
                .map(|prefix| WireGuardRouteReadback {
                    prefix: *prefix,
                    interface_index,
                    table: path.route_table,
                    protocol: UNF_WIREGUARD_ROUTE_PROTOCOL,
                    scope: WireGuardRouteScope::for_prefix(*prefix),
                })
                .collect(),
        })
        .unwrap()
    }

    fn path_receipt(fixture: &Fixture) -> EncryptionPathActivationReceipt {
        let round =
            EncryptionPathProofRound::issue(&fixture.contract, 0, [19; 32], 1_100, 2_000).unwrap();
        let mut ledger = EncryptionPathProofLedger::new(round.clone()).unwrap();
        for role in [
            EncryptionPathEndpointRole::Source,
            EncryptionPathEndpointRole::Destination,
        ] {
            let node = match role {
                EncryptionPathEndpointRole::Source => &fixture.contract.plans[0].source.node,
                EncryptionPathEndpointRole::Destination => {
                    &fixture.contract.plans[0].destination.node
                }
            };
            let authenticated = AuthenticatedNodeIdentity {
                cluster_id: node.cluster_id.clone(),
                node_name: node.name.clone(),
                node_uid: node.uid.clone(),
            };
            let proof = EncryptionEndpointPathProof::issue(
                &round,
                &fixture.contract,
                0,
                role,
                &authenticated,
                &path_snapshot(fixture, role, 1, 1),
                &path_snapshot(fixture, role, 2, 2),
                round.family_mask,
                1_200,
            )
            .unwrap();
            ledger.observe(&authenticated, proof, 1_200).unwrap();
        }
        ledger.activation_receipt(1_300).unwrap()
    }

    fn inactive_plan(fixture: &Fixture) -> WireGuardKernelPlan {
        let plan = &fixture.transaction.plan;
        WireGuardKernelPlan::new(WireGuardKernelPlanInput {
            cluster_id: plan.cluster_id.clone(),
            local_node_uid: plan.local_node_uid.clone(),
            epoch: plan.epoch,
            revision: plan.revision,
            interface_name: plan.interface_name.clone(),
            local_public_key: plan.local_public_key,
            listen_port: plan.listen_port,
            fwmark: plan.fwmark,
            route_table: plan.route_table,
            mtu_envelope: plan.mtu_envelope.clone(),
            activation: WireGuardEpochActivation::InactiveStaged,
            peers: plan.peers.clone(),
        })
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
    fn replicated_identity_late_binds_the_final_dual_stack_destination() {
        let fixture = fixture_with_replica(7, true);
        let epoch = FastPathEpochAdmission {
            contract: &fixture.contract,
            transaction: &fixture.transaction,
            readback: &fixture.snapshot,
            readiness_digest: [7; 32],
            state: FastPathEpochState::Active,
            drain_until_monotonic_ns: 0,
        };
        let inputs = fixture
            .contract
            .plans
            .iter()
            .enumerate()
            .filter(|(_, plan)| {
                plan.source.identity == IdentityId::new(11)
                    && plan.destination.identity == IdentityId::new(21)
            })
            .map(|(plan_index, _)| FastPathDecisionInput {
                source_identity: IdentityId::new(11),
                destination_identity: IdentityId::new(21),
                disposition: EncryptionDisposition::Required,
                contract_epoch: Some(7),
                plan_index: Some(plan_index),
            })
            .collect::<Vec<_>>();
        assert_eq!(inputs.len(), 2);
        let state = compile_encryption_fast_path(context(1), &[epoch], &inputs).unwrap();
        assert_eq!(state.decisions.len(), 1);
        assert_eq!(state.transports.len(), 2);
        assert_eq!(state.path_authority.len(), 4);
        assert_eq!(state.config.path_count, 4);
        assert_eq!(state.decisions[0].1.transport_id, 0);
        assert_ne!(
            state.decisions[0].1.flags & ENCRYPTION_DECISION_FLAG_ADDRESS_BOUND,
            0
        );

        let mut first = packet();
        first.destination_address = "10.42.2.8".parse().unwrap();
        let FastPathPacketDecision::Encrypt {
            lease: first_lease, ..
        } = select_encryption_transport(&state, first, None)
        else {
            panic!("first replica must resolve");
        };
        let mut second = packet();
        second.destination_address = "fd42:3::8".parse().unwrap();
        let FastPathPacketDecision::Encrypt {
            lease: second_lease,
            ..
        } = select_encryption_transport(&state, second, None)
        else {
            panic!("second replica must resolve");
        };
        assert_ne!(first_lease.transport_id, second_lease.transport_id);

        second.destination_address = "10.42.99.8".parse().unwrap();
        assert_eq!(
            select_encryption_transport(&state, second, None),
            FastPathPacketDecision::Drop(FastPathDropReason::TransportUnavailable)
        );
        let mut corrupt = state.clone();
        corrupt.path_authority[0].binding_witness[0] ^= 1;
        assert_eq!(
            corrupt.verify_integrity(),
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
    fn node_sealed_generation_capsule_admits_only_the_exact_causal_successor() {
        let fixture = fixture(7);
        let first_state = required_state(&fixture, context_at(1, 21));
        let first_checkpoint =
            FastPathMapCheckpoint::begin(Revision::new(22), &first_state, None).unwrap();
        let recipient = EncryptionGenerationRecipient {
            node_name: "worker-a".to_owned(),
            node_uid: "uid-worker-a".to_owned(),
        };
        let first_request =
            EncryptionGenerationRequest::issue("worker-a".to_owned(), None, [1; 32]).unwrap();
        let first_capsule = NodeSealedGenerationCapsule::issue(
            100,
            recipient.clone(),
            &first_request,
            first_checkpoint,
        )
        .unwrap();
        let first = first_capsule.admit(&first_request, None).unwrap();
        first.verify().unwrap();

        let second_state = required_state(&fixture, context_at(0, 23));
        let second_checkpoint =
            FastPathMapCheckpoint::begin(Revision::new(24), &second_state, Some(first.published()))
                .unwrap();
        let second_request =
            EncryptionGenerationRequest::issue("worker-a".to_owned(), Some(&first), [2; 32])
                .unwrap();
        let mut out_of_bounds = second_request.clone();
        out_of_bounds.current.as_mut().unwrap().published.bank =
            unf_ebpf_common::ENCRYPTION_BANK_COUNT;
        assert!(out_of_bounds.verify().is_err());
        let mut out_of_capacity = second_request.clone();
        out_of_capacity
            .current
            .as_mut()
            .unwrap()
            .published
            .decision_count = unf_ebpf_common::ENCRYPTION_DECISION_MAP_CAPACITY + 1;
        assert!(out_of_capacity.verify().is_err());
        // Controller epochs identify incarnations; generation/predecessor
        // authority is monotonic, but the opaque epoch number need not be.
        let second_capsule =
            NodeSealedGenerationCapsule::issue(99, recipient, &second_request, second_checkpoint)
                .unwrap();
        let second = second_capsule.admit(&second_request, Some(&first)).unwrap();
        assert_eq!(second.controller_epoch, 99);
        assert_eq!(second.published().generation, Revision::new(23));
        assert_eq!(second.published().bank, 0);
        assert!(!serde_json::to_string(&second).unwrap().contains("private"));
    }

    #[test]
    fn node_sealed_generation_capsule_rejects_replay_uid_swap_and_mutation() {
        let fixture = fixture(7);
        let state = required_state(&fixture, context_at(1, 21));
        let checkpoint = FastPathMapCheckpoint::begin(Revision::new(22), &state, None).unwrap();
        let request =
            EncryptionGenerationRequest::issue("worker-a".to_owned(), None, [3; 32]).unwrap();
        let capsule = NodeSealedGenerationCapsule::issue(
            100,
            EncryptionGenerationRecipient {
                node_name: "worker-a".to_owned(),
                node_uid: "uid-worker-a".to_owned(),
            },
            &request,
            checkpoint,
        )
        .unwrap();

        let replay_request =
            EncryptionGenerationRequest::issue("worker-a".to_owned(), None, [4; 32]).unwrap();
        assert!(matches!(
            capsule.admit(&replay_request, None),
            Err(EncryptionGenerationDistributionError::RequestMismatch)
        ));
        let mut swapped = capsule.clone();
        swapped.recipient.node_uid = "replacement-uid".to_owned();
        assert!(matches!(
            swapped.admit(&request, None),
            Err(EncryptionGenerationDistributionError::InvalidCapsule)
        ));
        let mut mutated = capsule.clone();
        mutated
            .checkpoint
            .transport_authority
            .first_mut()
            .unwrap()
            .route_table += 1;
        assert!(matches!(
            mutated.admit(&request, None),
            Err(EncryptionGenerationDistributionError::InvalidCheckpoint(_))
        ));
        let encoded = serde_json::to_string(&capsule).unwrap();
        assert!(
            serde_json::from_str::<NodeSealedGenerationCapsule>(&encoded.replacen(
                '{',
                "{\"unknown\":true,",
                1
            ))
            .is_err()
        );
    }

    #[test]
    fn tri_plane_activation_latch_joins_distribution_routes_and_exact_predecessor() {
        let fixture = fixture(7);
        let state = required_state(&fixture, context_at(1, 21));
        let checkpoint = FastPathMapCheckpoint::begin(Revision::new(22), &state, None).unwrap();
        let recipient = EncryptionGenerationRecipient {
            node_name: "worker-a".to_owned(),
            node_uid: "uid-worker-a".to_owned(),
        };
        let request =
            EncryptionGenerationRequest::issue("worker-a".to_owned(), None, [5; 32]).unwrap();
        let admitted = NodeSealedGenerationCapsule::issue(
            100,
            recipient.clone(),
            &request,
            checkpoint.clone(),
        )
        .unwrap()
        .admit(&request, None)
        .unwrap();
        let authority =
            EncryptionRouteAuthority::issue(&state, std::slice::from_ref(&fixture.snapshot))
                .unwrap();
        let permit = authority.authorize_publication(&authority.rules).unwrap();
        let latch = EncryptionActivationLatch::issue(&admitted, &recipient, None, permit).unwrap();
        let witness = latch.witness();
        assert_ne!(witness.0, [0; 32]);
        let material = latch.open(None, None).unwrap();
        assert_eq!(material.witness(), witness);
        let (opened_checkpoint, opened_state, opened_permit, mode) = material.into_parts();
        assert_eq!(mode, EncryptionActivationMode::PublishSuccessor);
        assert_eq!(opened_checkpoint, checkpoint);
        assert_eq!(opened_state, state);
        opened_permit.verify_for(&opened_state).unwrap();

        let mut quarantined = checkpoint;
        quarantined.record_staged(&state).unwrap();
        let resumed = EncryptionActivationLatch::issue(
            &admitted,
            &recipient,
            None,
            authority.authorize_publication(&authority.rules).unwrap(),
        )
        .unwrap()
        .open(None, Some(&quarantined))
        .unwrap();
        assert_eq!(resumed.into_parts().0, quarantined);

        let revalidated = EncryptionActivationLatch::issue(
            &admitted,
            &recipient,
            Some(admitted.published()),
            authority.authorize_publication(&authority.rules).unwrap(),
        )
        .unwrap()
        .open(Some(admitted.published()), None)
        .unwrap();
        assert_eq!(
            revalidated.mode(),
            EncryptionActivationMode::RevalidateCurrent
        );
    }

    #[test]
    fn tri_plane_activation_latch_refuses_cross_plane_or_predecessor_drift() {
        let fixture = fixture(7);
        let state = required_state(&fixture, context_at(1, 21));
        let checkpoint = FastPathMapCheckpoint::begin(Revision::new(22), &state, None).unwrap();
        let recipient = EncryptionGenerationRecipient {
            node_name: "worker-a".to_owned(),
            node_uid: "uid-worker-a".to_owned(),
        };
        let request =
            EncryptionGenerationRequest::issue("worker-a".to_owned(), None, [6; 32]).unwrap();
        let admitted =
            NodeSealedGenerationCapsule::issue(100, recipient.clone(), &request, checkpoint)
                .unwrap()
                .admit(&request, None)
                .unwrap();
        let authority =
            EncryptionRouteAuthority::issue(&state, std::slice::from_ref(&fixture.snapshot))
                .unwrap();
        let replacement = EncryptionGenerationRecipient {
            node_name: "worker-a".to_owned(),
            node_uid: "replacement-uid".to_owned(),
        };
        assert!(matches!(
            EncryptionActivationLatch::issue(
                &admitted,
                &replacement,
                None,
                authority.authorize_publication(&authority.rules).unwrap()
            ),
            Err(EncryptionActivationLatchError::RecipientMismatch)
        ));
        let mut wrong_applied = admitted.published();
        wrong_applied.generation = Revision::new(100);
        assert!(matches!(
            EncryptionActivationLatch::issue(
                &admitted,
                &recipient,
                Some(wrong_applied),
                authority.authorize_publication(&authority.rules).unwrap()
            ),
            Err(EncryptionActivationLatchError::PredecessorMismatch)
        ));

        let other_state = required_state(&fixture, context_at(0, 23));
        let other_checkpoint =
            FastPathMapCheckpoint::begin(Revision::new(24), &other_state, None).unwrap();
        let other_authority =
            EncryptionRouteAuthority::issue(&other_state, std::slice::from_ref(&fixture.snapshot))
                .unwrap();
        let other_permit = other_authority
            .authorize_publication(&other_authority.rules)
            .unwrap();
        assert!(matches!(
            EncryptionActivationLatch::issue(&admitted, &recipient, None, other_permit),
            Err(EncryptionActivationLatchError::InvalidRoutePermit(_))
        ));
        let renewed = EncryptionActivationLatch::issue(
            &admitted,
            &recipient,
            None,
            authority.authorize_publication(&authority.rules).unwrap(),
        )
        .unwrap();
        assert!(matches!(
            renewed.open(None, Some(&other_checkpoint)),
            Err(EncryptionActivationLatchError::PendingTransactionMismatch)
        ));
    }

    #[test]
    fn causal_generation_frontier_backpressures_every_exact_predecessor() {
        let fixture = fixture(7);
        let recipient = EncryptionGenerationRecipient {
            node_name: "worker-a".to_owned(),
            node_uid: "uid-worker-a".to_owned(),
        };
        let first_state = required_state(&fixture, context_at(1, 21));
        let first_checkpoint =
            FastPathMapCheckpoint::begin(Revision::new(21), &first_state, None).unwrap();
        let first_published = first_checkpoint.transaction.desired.published;
        let first = EncryptionGenerationFrontier::issue(
            Revision::new(21),
            vec![recipient.clone()],
            vec![PreparedNodeEncryptionGeneration {
                recipient: recipient.clone(),
                checkpoint: first_checkpoint,
            }],
        )
        .unwrap();
        first.verify().unwrap();
        let mut tampered = first.clone();
        tampered.frontier_digest.0[0] ^= 1;
        assert!(matches!(
            tampered.verify(),
            Err(EncryptionGenerationFrontierError::DigestMismatch)
        ));

        let second_state = required_state(&fixture, context_at(0, 22));
        let second_checkpoint =
            FastPathMapCheckpoint::begin(Revision::new(22), &second_state, Some(first_published))
                .unwrap();
        let second = EncryptionGenerationFrontier::issue(
            Revision::new(22),
            vec![recipient.clone()],
            vec![PreparedNodeEncryptionGeneration {
                recipient: recipient.clone(),
                checkpoint: second_checkpoint,
            }],
        )
        .unwrap();

        let mut producer = EncryptionGenerationProducer::default();
        assert_eq!(
            producer.publish(first.clone()).unwrap(),
            EncryptionFrontierPublishOutcome::Published
        );
        assert_eq!(
            producer.publish(first).unwrap(),
            EncryptionFrontierPublishOutcome::Unchanged
        );
        assert!(!producer.is_fully_acknowledged());
        assert!(matches!(
            producer.publish(second.clone()),
            Err(EncryptionGenerationFrontierError::PredecessorNotAcknowledged)
        ));

        let mut wrong = first_published;
        wrong.state_digest.0[0] ^= 1;
        assert!(matches!(
            producer.acknowledge(&recipient, wrong),
            Err(EncryptionGenerationFrontierError::AcknowledgementMismatch)
        ));
        assert!(producer.acknowledge(&recipient, first_published).unwrap());
        assert!(!producer.acknowledge(&recipient, first_published).unwrap());
        assert!(producer.is_fully_acknowledged());
        let durable = producer.checkpoint().unwrap();
        durable.verify().unwrap();
        let mut cross_frontier_receipt = durable.clone();
        cross_frontier_receipt.acknowledgements[0].frontier_digest.0[0] ^= 1;
        assert!(matches!(
            EncryptionGenerationProducer::restore(cross_frontier_receipt),
            Err(EncryptionGenerationFrontierError::InvalidProducerCheckpoint)
        ));
        let mut encoded = serde_json::to_value(&durable).unwrap();
        encoded
            .as_object_mut()
            .unwrap()
            .insert("unexpected".to_owned(), serde_json::json!(true));
        assert!(
            serde_json::from_value::<crate::EncryptionGenerationProducerCheckpoint>(encoded)
                .is_err()
        );
        producer = EncryptionGenerationProducer::restore(durable).unwrap();
        assert!(producer.is_fully_acknowledged());
        assert_eq!(
            producer.publish(second).unwrap(),
            EncryptionFrontierPublishOutcome::Published
        );
        assert_eq!(
            producer.desired_for(&recipient).unwrap().transaction.prior,
            Some(first_published)
        );

        let empty = EncryptionGenerationProducer::default()
            .checkpoint()
            .unwrap();
        let restored_empty = EncryptionGenerationProducer::restore(empty).unwrap();
        assert!(restored_empty.active().is_none());
        assert!(restored_empty.is_fully_acknowledged());
    }

    #[test]
    fn complete_cut_fact_reconciler_never_mixes_membership_truth() {
        let fixture = fixture(7);
        let recipient = EncryptionGenerationRecipient {
            node_name: "worker-a".to_owned(),
            node_uid: "uid-worker-a".to_owned(),
        };
        let state = required_state(&fixture, context_at(1, 21));
        let checkpoint = FastPathMapCheckpoint::begin(Revision::new(21), &state, None).unwrap();
        let fact = EncryptionGenerationFact::issue(Revision::new(9), recipient.clone(), checkpoint)
            .unwrap();
        fact.verify().unwrap();

        let mut reconciler = EncryptionGenerationFactReconciler::default();
        let alias = EncryptionGenerationRecipient {
            node_name: "worker-alias".to_owned(),
            node_uid: recipient.node_uid.clone(),
        };
        assert!(matches!(
            reconciler.replace_membership(Revision::new(9), vec![recipient.clone(), alias]),
            Err(EncryptionGenerationFactError::InvalidMembership)
        ));
        assert!(
            reconciler
                .replace_membership(Revision::new(9), vec![recipient.clone()])
                .unwrap()
        );
        assert_eq!(reconciler.expected(), 1);
        assert_eq!(reconciler.observed(), 0);
        assert_eq!(
            reconciler.observe(fact.clone()).unwrap(),
            EncryptionGenerationFactOutcome::Accepted
        );
        assert_eq!(
            reconciler.observe(fact.clone()).unwrap(),
            EncryptionGenerationFactOutcome::Unchanged
        );
        let frontier = reconciler.candidate().unwrap().unwrap();
        assert_eq!(frontier.members, vec![recipient.clone()]);
        assert_eq!(frontier.revision, Revision::new(21));

        let mut mutated = fact.clone();
        mutated.fact_digest.0[0] ^= 1;
        assert!(matches!(
            mutated.verify(),
            Err(EncryptionGenerationFactError::DigestMismatch)
        ));
        let mut unknown = serde_json::to_value(&fact).unwrap();
        unknown
            .as_object_mut()
            .unwrap()
            .insert("unexpected".to_owned(), serde_json::json!(true));
        assert!(serde_json::from_value::<EncryptionGenerationFact>(unknown).is_err());

        assert!(
            reconciler
                .replace_membership(Revision::new(10), vec![recipient])
                .unwrap()
        );
        assert_eq!(reconciler.observed(), 0);
        assert!(reconciler.candidate().unwrap().is_none());
        assert!(matches!(
            reconciler.observe(fact),
            Err(EncryptionGenerationFactError::ForeignMembership)
        ));
    }

    #[test]
    fn causal_proof_ladder_refuses_controller_substitution_and_reuse() {
        let fixture = fixture(7);
        let recipient = EncryptionGenerationRecipient {
            node_name: "worker-a".to_owned(),
            node_uid: "uid-worker-a".to_owned(),
        };
        let state = required_state(&fixture, context_at(1, 21));
        let checkpoint = FastPathMapCheckpoint::begin(Revision::new(21), &state, None).unwrap();
        let proposal = NodeLocalGenerationProposal::issue(
            Revision::new(9),
            recipient.clone(),
            checkpoint.clone(),
        )
        .unwrap();
        proposal.fact().verify().unwrap();
        let request =
            EncryptionGenerationRequest::issue(recipient.node_name.clone(), None, [9; 32]).unwrap();
        let admitted =
            NodeSealedGenerationCapsule::issue(100, recipient.clone(), &request, checkpoint)
                .unwrap()
                .admit(&request, None)
                .unwrap();

        let substituted_state = required_state(&fixture, context_at(0, 22));
        let substituted_checkpoint =
            FastPathMapCheckpoint::begin(Revision::new(22), &substituted_state, None).unwrap();
        let substituted = NodeSealedGenerationCapsule::issue(
            100,
            recipient.clone(),
            &request,
            substituted_checkpoint,
        )
        .unwrap()
        .admit(&request, None)
        .unwrap();
        assert!(matches!(
            proposal.clone().bind_controller_admission(substituted),
            Err(NodeLocalOrchestratorError::ControllerSubstitution)
        ));

        let proven_bound = proposal
            .clone()
            .bind_controller_admission(admitted.clone())
            .unwrap();
        let controller_bound = proposal.bind_controller_admission(admitted).unwrap();
        assert!(matches!(
            EncryptionGenerationPathProofPermit::issue(
                &state,
                recipient.clone(),
                Vec::new(),
                1_000,
            ),
            Err(EncryptionPathProofError::InvalidGenerationProof)
        ));
        let authority =
            EncryptionRouteAuthority::issue(&state, std::slice::from_ref(&fixture.snapshot))
                .unwrap();
        let permit = authority.authorize_publication(&authority.rules).unwrap();
        assert!(matches!(
            controller_bound.authorize_map_activation(None, permit),
            Err(NodeLocalOrchestratorError::InvalidActivation(
                EncryptionActivationLatchError::MissingPathProof
            ))
        ));

        let path_permit = EncryptionGenerationPathProofPermit::issue(
            &state,
            recipient,
            vec![path_receipt(&fixture)],
            1_300,
        )
        .unwrap();
        let route_permit = authority.authorize_publication(&authority.rules).unwrap();
        let latch = proven_bound
            .authorize_path_proven_map_activation(None, route_permit, path_permit, 1_300)
            .unwrap();
        let material = latch.open(None, None, 1_300).unwrap();
        assert_eq!(
            material.into_parts().0.transaction.desired.published,
            FastPathPublishedGeneration::issue(&state).unwrap()
        );
    }

    #[test]
    fn linux_convergence_capsule_binds_the_complete_exact_kernel_cut() {
        let current_fixture = fixture(7);
        let state = required_state(&current_fixture, context_at(1, 21));
        let checkpoint = FastPathMapCheckpoint::begin(Revision::new(21), &state, None).unwrap();
        let recipient = EncryptionGenerationRecipient {
            node_name: "worker-a".to_owned(),
            node_uid: "uid-worker-a".to_owned(),
        };
        let prepared = LinuxPreparedLocalGeneration::bind_exact_readback(
            Revision::new(9),
            recipient.clone(),
            checkpoint.clone(),
            &[inactive_plan(&current_fixture)],
            std::slice::from_ref(&current_fixture.snapshot),
        )
        .unwrap();
        assert_ne!(prepared.witness().0, [0; 32]);
        assert_eq!(prepared.fact().recipient, recipient);
        assert_eq!(prepared.fact().checkpoint, checkpoint);

        let replay = LinuxPreparedLocalGeneration::bind_exact_readback(
            Revision::new(9),
            prepared.fact().recipient.clone(),
            prepared.fact().checkpoint.clone(),
            &[inactive_plan(&current_fixture)],
            std::slice::from_ref(&current_fixture.snapshot),
        )
        .unwrap();
        assert_eq!(replay.witness(), prepared.witness());

        let old = fixture(6);
        let new = fixture(7);
        let rotating = compile_encryption_fast_path(
            context_at(1, 22),
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
        let rotating_checkpoint =
            FastPathMapCheckpoint::begin(Revision::new(22), &rotating, None).unwrap();
        let first = LinuxPreparedLocalGeneration::bind_exact_readback(
            Revision::new(9),
            EncryptionGenerationRecipient {
                node_name: "worker-a".to_owned(),
                node_uid: "uid-worker-a".to_owned(),
            },
            rotating_checkpoint.clone(),
            &[inactive_plan(&old), inactive_plan(&new)],
            &[new.snapshot.clone(), old.snapshot.clone()],
        )
        .unwrap();
        let reordered = LinuxPreparedLocalGeneration::bind_exact_readback(
            Revision::new(9),
            first.fact().recipient.clone(),
            rotating_checkpoint,
            &[inactive_plan(&new), inactive_plan(&old)],
            &[old.snapshot, new.snapshot],
        )
        .unwrap();
        assert_eq!(first.witness(), reordered.witness());
    }

    #[test]
    fn linux_convergence_capsule_accepts_only_its_exact_controller_echo() {
        let fixture = fixture(7);
        let state = required_state(&fixture, context_at(1, 21));
        let checkpoint = FastPathMapCheckpoint::begin(Revision::new(21), &state, None).unwrap();
        let recipient = EncryptionGenerationRecipient {
            node_name: "worker-a".to_owned(),
            node_uid: "uid-worker-a".to_owned(),
        };
        let prepared = LinuxPreparedLocalGeneration::bind_exact_readback(
            Revision::new(9),
            recipient.clone(),
            checkpoint.clone(),
            &[inactive_plan(&fixture)],
            std::slice::from_ref(&fixture.snapshot),
        )
        .unwrap();
        let request =
            EncryptionGenerationRequest::issue(recipient.node_name.clone(), None, [9; 32]).unwrap();
        let admitted =
            NodeSealedGenerationCapsule::issue(100, recipient.clone(), &request, checkpoint)
                .unwrap()
                .admit(&request, None)
                .unwrap();
        prepared.verify_controller_admission(&admitted).unwrap();

        let substituted_state = required_state(&fixture, context_at(0, 22));
        let substituted_checkpoint =
            FastPathMapCheckpoint::begin(Revision::new(22), &substituted_state, None).unwrap();
        let substituted =
            NodeSealedGenerationCapsule::issue(100, recipient, &request, substituted_checkpoint)
                .unwrap()
                .admit(&request, None)
                .unwrap();
        assert!(matches!(
            prepared.verify_controller_admission(&substituted),
            Err(NodeLocalOrchestratorError::ControllerSubstitution)
        ));
    }

    #[test]
    fn recovery_plan_rehydrates_fresh_capability_and_rejects_serialized_authority() {
        let fixture = fixture(7);
        let state = required_state(&fixture, context_at(1, 21));
        let checkpoint = FastPathMapCheckpoint::begin(Revision::new(21), &state, None).unwrap();
        let prepared = LinuxPreparedLocalGeneration::bind_exact_readback(
            Revision::new(9),
            EncryptionGenerationRecipient {
                node_name: "worker-a".to_owned(),
                node_uid: "uid-worker-a".to_owned(),
            },
            checkpoint,
            &[inactive_plan(&fixture)],
            std::slice::from_ref(&fixture.snapshot),
        )
        .unwrap();
        let recovery = prepared.recovery_plan().clone();
        recovery.verify().unwrap();
        let rehydrated = recovery
            .rehydrate_exact_readback(std::slice::from_ref(&fixture.snapshot))
            .unwrap();
        assert_eq!(rehydrated.fact(), prepared.fact());
        assert_eq!(rehydrated.witness(), prepared.witness());
        assert!(recovery.rehydrate_exact_readback(&[]).is_err());

        let mut mutated = recovery.clone();
        mutated.plans[0].plan_digest.0[0] ^= 1;
        assert!(mutated.verify().is_err());
        let mut encoded = serde_json::to_value(recovery).unwrap();
        encoded
            .as_object_mut()
            .unwrap()
            .insert("serializedLatch".to_owned(), serde_json::json!(vec![7; 32]));
        assert!(serde_json::from_value::<NodeLocalRecoveryPlan>(encoded).is_err());
    }

    #[test]
    fn linux_convergence_capsule_refuses_partial_foreign_or_active_staging() {
        let fixture = fixture(7);
        let state = required_state(&fixture, context_at(1, 21));
        let checkpoint = FastPathMapCheckpoint::begin(Revision::new(21), &state, None).unwrap();
        let recipient = EncryptionGenerationRecipient {
            node_name: "worker-a".to_owned(),
            node_uid: "uid-worker-a".to_owned(),
        };
        assert!(matches!(
            LinuxPreparedLocalGeneration::bind_exact_readback(
                Revision::new(9),
                recipient.clone(),
                checkpoint.clone(),
                &[inactive_plan(&fixture)],
                &[],
            ),
            Err(NodeLocalOrchestratorError::KernelCommitmentMismatch)
        ));
        assert!(matches!(
            LinuxPreparedLocalGeneration::bind_exact_readback(
                Revision::new(9),
                EncryptionGenerationRecipient {
                    node_name: recipient.node_name.clone(),
                    node_uid: "replacement-uid".to_owned(),
                },
                checkpoint.clone(),
                &[inactive_plan(&fixture)],
                std::slice::from_ref(&fixture.snapshot),
            ),
            Err(NodeLocalOrchestratorError::KernelCommitmentMismatch)
        ));
        assert!(matches!(
            LinuxPreparedLocalGeneration::bind_exact_readback(
                Revision::new(9),
                recipient,
                checkpoint,
                std::slice::from_ref(&fixture.transaction.plan),
                std::slice::from_ref(&fixture.snapshot),
            ),
            Err(NodeLocalOrchestratorError::KernelCommitmentMismatch)
        ));
    }

    #[test]
    fn causal_generation_frontier_refuses_partial_or_cross_node_cuts() {
        let fixture = fixture(7);
        let recipient = EncryptionGenerationRecipient {
            node_name: "worker-a".to_owned(),
            node_uid: "uid-worker-a".to_owned(),
        };
        let state = required_state(&fixture, context_at(1, 21));
        let checkpoint = FastPathMapCheckpoint::begin(Revision::new(21), &state, None).unwrap();
        let replacement = EncryptionGenerationRecipient {
            node_name: "worker-a".to_owned(),
            node_uid: "replacement-uid".to_owned(),
        };
        assert!(matches!(
            EncryptionGenerationFrontier::issue(
                Revision::new(21),
                vec![replacement.clone()],
                vec![PreparedNodeEncryptionGeneration {
                    recipient: replacement,
                    checkpoint: checkpoint.clone(),
                }],
            ),
            Err(EncryptionGenerationFrontierError::CrossDomainAuthority)
        ));

        let second_member = EncryptionGenerationRecipient {
            node_name: "worker-b".to_owned(),
            node_uid: "uid-worker-b".to_owned(),
        };
        assert!(matches!(
            EncryptionGenerationFrontier::issue(
                Revision::new(21),
                vec![recipient.clone(), second_member],
                vec![PreparedNodeEncryptionGeneration {
                    recipient,
                    checkpoint,
                }],
            ),
            Err(EncryptionGenerationFrontierError::IncompleteMembership)
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
