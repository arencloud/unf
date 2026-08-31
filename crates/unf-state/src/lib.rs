//! Revisioned control-plane state and stable identity metadata.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use unf_common::{
    BackendId, IdentityId, LOAD_BALANCER_REACHABILITY_SCHEMA_VERSION, PolicyDirection, PolicyId,
    PolicyReason, Revision, RuleId, SERVICE_SNAPSHOT_SCHEMA_VERSION, ServiceId, Verdict,
};

pub const IDENTITY_SNAPSHOT_SCHEMA_VERSION: u16 = 2;
pub const POLICY_SNAPSHOT_SCHEMA_VERSION: u16 = 4;
pub const TOPOLOGY_SNAPSHOT_SCHEMA_VERSION: u16 = 3;
pub const TOPOLOGY_HISTORY_SCHEMA_VERSION: u16 = 1;
pub const TOPOLOGY_HISTORY_CHECKPOINT_SCHEMA_VERSION: u16 = 1;
pub const TOPOLOGY_HISTORY_CAPACITY: usize = 32;
pub const FLOW_EXPORT_SCHEMA_VERSION: u16 = 5;
pub const FLOW_HISTORY_SNAPSHOT_SCHEMA_VERSION: u16 = 6;
pub const FLOW_HISTORY_CHECKPOINT_SCHEMA_VERSION: u16 = 5;
pub const SHADOW_IMPACT_SCHEMA_VERSION: u16 = 1;
pub const AGENT_STATUS_SCHEMA_VERSION: u16 = 6;
pub const COMPONENT_COMPATIBILITY_SCHEMA_VERSION: u16 = 2;
pub const PERSISTENT_BPF_STATE_ABI_VERSION: u16 = 6;
pub const FLOW_EXPORT_BATCH_LIMIT: usize = 512;
pub const FLOW_HISTORY_CAPACITY: usize = 4_096;
const FLOW_HISTORY_LEGACY_MAX_CLOCK_REGRESSION_MILLIS: u64 = 1_000;
/// One half of the dual-bank eBPF policy map's 262,144-entry capacity.
pub const POLICY_MAP_BANK_ENTRY_LIMIT: usize = 131_072;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComponentCompatibility {
    pub schema_version: u16,
    pub component: String,
    pub software_version: String,
    pub build_revision: String,
    pub persistent_bpf_state_abi_version: u16,
    pub identity_snapshot_schema_version: u16,
    pub policy_snapshot_schema_version: u16,
    pub service_snapshot_schema_version: u16,
    #[serde(default)]
    pub load_balancer_reachability_schema_version: u16,
    pub agent_status_schema_version: u16,
    pub flow_export_schema_version: u16,
}

impl ComponentCompatibility {
    #[must_use]
    pub fn current(component: &str, software_version: &str, build_revision: &str) -> Self {
        Self {
            schema_version: COMPONENT_COMPATIBILITY_SCHEMA_VERSION,
            component: component.to_owned(),
            software_version: software_version.to_owned(),
            build_revision: build_revision.to_owned(),
            persistent_bpf_state_abi_version: PERSISTENT_BPF_STATE_ABI_VERSION,
            identity_snapshot_schema_version: IDENTITY_SNAPSHOT_SCHEMA_VERSION,
            policy_snapshot_schema_version: POLICY_SNAPSHOT_SCHEMA_VERSION,
            service_snapshot_schema_version: SERVICE_SNAPSHOT_SCHEMA_VERSION,
            load_balancer_reachability_schema_version: LOAD_BALANCER_REACHABILITY_SCHEMA_VERSION,
            agent_status_schema_version: AGENT_STATUS_SCHEMA_VERSION,
            flow_export_schema_version: FLOW_EXPORT_SCHEMA_VERSION,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevisionSet {
    pub identity: Revision,
    pub policy: Revision,
    pub service: Revision,
    pub routing: Revision,
    pub topology: Revision,
    pub telemetry: Revision,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VersionTransition {
    #[default]
    Normal,
    CompatibleRollback,
    BlockedRollback,
    Recovery,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentStateReport {
    pub schema_version: u16,
    pub node_name: String,
    pub pod_name: String,
    pub pod_uid: String,
    #[serde(default)]
    pub version_transition: VersionTransition,
    pub ready: bool,
    pub bpf_loaded: bool,
    pub desired_identity_revision: u64,
    pub applied_identity_revision: u64,
    pub desired_identity_epoch: u64,
    pub applied_identity_epoch: u64,
    pub identity_map_entries: u64,
    pub ipv4_identity_map_entries: u64,
    pub ipv6_identity_map_entries: u64,
    pub desired_policy_revision: u64,
    pub applied_policy_revision: u64,
    pub desired_policy_epoch: u64,
    pub applied_policy_epoch: u64,
    pub policy_map_entries: u64,
    pub active_policy_bank: u64,
    #[serde(default)]
    pub desired_service_epoch: u64,
    #[serde(default)]
    pub desired_service_revision: u64,
    #[serde(default)]
    pub applied_service_epoch: u64,
    #[serde(default)]
    pub applied_service_revision: u64,
    #[serde(default)]
    pub service_snapshot_schema_version: u16,
    #[serde(default)]
    pub failed_service_epoch: u64,
    #[serde(default)]
    pub failed_service_revision: u64,
    #[serde(default)]
    pub service_count: u64,
    #[serde(default)]
    pub service_frontend_count: u64,
    #[serde(default)]
    pub service_backend_count: u64,
    #[serde(default)]
    pub desired_node_port_frontend_count: u64,
    #[serde(default)]
    pub applied_node_port_frontend_count: u64,
    #[serde(default)]
    pub node_port_cluster_frontend_count: u64,
    #[serde(default)]
    pub node_port_local_frontend_count: u64,
    #[serde(default)]
    pub load_balancer_reachability_schema_version: u16,
    #[serde(default)]
    pub desired_load_balancer_epoch: u64,
    #[serde(default)]
    pub desired_load_balancer_revision: u64,
    #[serde(default)]
    pub desired_load_balancer_allocation_revision: u64,
    #[serde(default)]
    pub applied_load_balancer_epoch: u64,
    #[serde(default)]
    pub applied_load_balancer_revision: u64,
    #[serde(default)]
    pub applied_load_balancer_allocation_revision: u64,
    #[serde(default)]
    pub load_balancer_frontend_count: u64,
    #[serde(default)]
    pub active_load_balancer_bank: u64,
    #[serde(default)]
    pub load_balancer_reconcile_errors: u64,
    #[serde(default)]
    pub load_balancer_last_error: Option<String>,
    #[serde(default)]
    pub service_reconcile_errors: u64,
    #[serde(default)]
    pub service_last_error: Option<String>,
    #[serde(default)]
    pub service_dataplane_events: u64,
    #[serde(default)]
    pub service_translations: u64,
    #[serde(default)]
    pub service_drops: u64,
    #[serde(default)]
    pub service_expirations: u64,
    #[serde(default)]
    pub node_port_cluster_translations: u64,
    #[serde(default)]
    pub node_port_local_translations: u64,
    #[serde(default)]
    pub node_port_no_backend_drops: u64,
    #[serde(default)]
    pub invalid_service_events: u64,
    #[serde(default)]
    pub last_service_id: u32,
    #[serde(default)]
    pub last_backend_id: u32,
    #[serde(default)]
    pub last_service_revision: u64,
    #[serde(default)]
    pub last_service_action: u8,
    #[serde(default)]
    pub last_service_reason: u8,
    #[serde(default)]
    pub desired_node_block_revision: u64,
    #[serde(default)]
    pub applied_node_block_revision: u64,
    #[serde(default)]
    pub desired_remote_route_epoch: u64,
    #[serde(default)]
    pub applied_remote_route_epoch: u64,
    #[serde(default)]
    pub desired_remote_route_revision: u64,
    #[serde(default)]
    pub applied_remote_route_revision: u64,
    #[serde(default)]
    pub remote_route_entries: u64,
    #[serde(default)]
    pub remote_route_reconcile_errors: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentConvergenceEntry {
    pub node_name: String,
    pub fresh: bool,
    pub converged: bool,
    pub last_received_unix_ms: Option<u64>,
    pub report: Option<AgentStateReport>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentConvergenceSnapshot {
    pub schema_version: u16,
    pub expected_agents: usize,
    pub reporting_agents: usize,
    pub missing_agents: usize,
    pub stale_agents: usize,
    pub converged_agents: usize,
    pub unexpected_agents: usize,
    pub all_converged: bool,
    pub nodes: Vec<AgentConvergenceEntry>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceFrontendKind {
    #[default]
    ClusterIp,
    NodePortCluster,
    NodePortLocal,
    LoadBalancerCluster,
    LoadBalancerLocal,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ServiceFlowKey {
    pub service_id: ServiceId,
    pub backend_id: Option<BackendId>,
    pub service_revision: Revision,
    pub action: u8,
    pub reason: u8,
    #[serde(default)]
    pub frontend_kind: ServiceFrontendKind,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct FlowHistoryKey {
    #[serde(default)]
    pub direction: PolicyDirection,
    pub source_identity: IdentityId,
    pub destination_identity: IdentityId,
    pub source_ipv4: Option<Ipv4Addr>,
    pub destination_ipv4: Option<Ipv4Addr>,
    pub source_ipv6: Option<Ipv6Addr>,
    pub destination_ipv6: Option<Ipv6Addr>,
    pub protocol: u8,
    pub destination_port: u16,
    #[serde(default)]
    pub service: Option<ServiceFlowKey>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlowExportDecision {
    pub verdict: Verdict,
    pub reason: u8,
    pub policy_id: Option<PolicyId>,
    pub rule_id: Option<RuleId>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlowExportRecord {
    pub key: FlowHistoryKey,
    pub policy_revision: Revision,
    pub decision: FlowExportDecision,
    pub shadow: Option<FlowExportDecision>,
    #[serde(default)]
    pub service: Option<ServiceFlowOutcome>,
    pub observed_events: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceFlowOutcome {
    pub service_id: ServiceId,
    pub backend_id: Option<BackendId>,
    pub service_revision: Revision,
    pub backend_ipv4: Option<Ipv4Addr>,
    pub backend_ipv6: Option<Ipv6Addr>,
    pub frontend_port: u16,
    pub backend_port: Option<u16>,
    pub action: u8,
    pub reason: u8,
    #[serde(default)]
    pub frontend_kind: ServiceFrontendKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlowExportBatch {
    pub schema_version: u16,
    pub node_name: String,
    pub dropped_events: u64,
    pub entries: Vec<FlowExportRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlowHistoryEntry {
    pub key: FlowHistoryKey,
    pub source_workloads: Vec<String>,
    pub destination_workloads: Vec<String>,
    pub policy_revision: Revision,
    pub decision: FlowExportDecision,
    pub shadow: Option<FlowExportDecision>,
    #[serde(default)]
    pub service: Option<ServiceFlowOutcome>,
    pub observed_events: u64,
    pub first_received_unix_ms: u64,
    pub last_received_unix_ms: u64,
    pub reporting_nodes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlowHistorySnapshot {
    pub schema_version: u16,
    pub source_epoch: u64,
    pub revision: Revision,
    pub capacity: usize,
    pub retained_flows: usize,
    pub retained_observations: u64,
    pub evicted_flows: u64,
    pub evicted_observations: u64,
    pub agent_dropped_events: u64,
    pub durable_checkpointed_flows: usize,
    pub durable_omitted_flows: usize,
    pub durable_omitted_observations: u64,
    pub query: FlowHistoryQuerySummary,
    pub entries: Vec<FlowHistoryEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlowHistoryQuerySummary {
    pub since_unix_ms: Option<u64>,
    pub until_unix_ms: Option<u64>,
    pub limit: usize,
    pub matched_flows: usize,
    pub matched_observations: u64,
    pub returned_flows: usize,
    pub truncated: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShadowImpactClassification {
    WouldDeny,
    WouldAllow,
    SameVerdict,
    OtherVerdictChange,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShadowImpactSummary {
    pub selected_flows: usize,
    pub selected_observations: u64,
    pub shadowed_flows: usize,
    pub shadowed_observations: u64,
    pub would_deny_flows: usize,
    pub would_deny_observations: u64,
    pub would_allow_flows: usize,
    pub would_allow_observations: u64,
    pub same_verdict_flows: usize,
    pub same_verdict_observations: u64,
    pub other_verdict_change_flows: usize,
    pub other_verdict_change_observations: u64,
    pub decision_change_flows: usize,
    pub decision_change_observations: u64,
    pub affected_workloads: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShadowImpactChange {
    pub classification: ShadowImpactClassification,
    pub flow: FlowHistoryEntry,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShadowImpactReport {
    pub schema_version: u16,
    pub analysis: String,
    pub analysis_source: String,
    pub flow_history_schema_version: u16,
    pub source_epoch: u64,
    pub flow_history_revision: Revision,
    pub query: FlowHistoryQuerySummary,
    pub retained_flows: usize,
    pub retained_observations: u64,
    pub shadow_policy_ids: Vec<u32>,
    pub summary: ShadowImpactSummary,
    pub changes: Vec<ShadowImpactChange>,
    pub note: String,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ShadowImpactError {
    #[error("unsupported flow-history snapshot schema {actual}; expected {expected}")]
    UnsupportedSchema { actual: u16, expected: u16 },
    #[error("flow-history query reports {reported} returned flows but contains {actual} entries")]
    InconsistentReturnedFlows { reported: usize, actual: usize },
    #[error("flow-history entry has zero observations")]
    ZeroObservations,
    #[error("flow-history entry has invalid receive timestamps")]
    InvalidTimestamps,
}

/// Builds a bounded, observation-weighted report from one history snapshot.
///
/// # Errors
///
/// Returns [`ShadowImpactError`] when the snapshot schema is unsupported, its
/// query metadata does not match its entries, or an entry has invalid counts or
/// timestamps.
pub fn analyze_shadow_impact(
    snapshot: &FlowHistorySnapshot,
    analysis_source: impl Into<String>,
) -> Result<ShadowImpactReport, ShadowImpactError> {
    if snapshot.schema_version != FLOW_HISTORY_SNAPSHOT_SCHEMA_VERSION {
        return Err(ShadowImpactError::UnsupportedSchema {
            actual: snapshot.schema_version,
            expected: FLOW_HISTORY_SNAPSHOT_SCHEMA_VERSION,
        });
    }
    if snapshot.query.returned_flows != snapshot.entries.len() {
        return Err(ShadowImpactError::InconsistentReturnedFlows {
            reported: snapshot.query.returned_flows,
            actual: snapshot.entries.len(),
        });
    }

    let mut summary = ShadowImpactSummary {
        selected_flows: snapshot.entries.len(),
        selected_observations: snapshot
            .entries
            .iter()
            .map(|entry| entry.observed_events)
            .fold(0_u64, u64::saturating_add),
        ..ShadowImpactSummary::default()
    };
    let mut affected_workloads = BTreeSet::new();
    let mut shadow_policy_ids = BTreeSet::new();
    let mut changes = Vec::new();
    for entry in &snapshot.entries {
        if entry.observed_events == 0 {
            return Err(ShadowImpactError::ZeroObservations);
        }
        if entry.first_received_unix_ms > entry.last_received_unix_ms {
            return Err(ShadowImpactError::InvalidTimestamps);
        }
        let Some(shadow) = entry.shadow else {
            continue;
        };
        summary.shadowed_flows += 1;
        summary.shadowed_observations = summary
            .shadowed_observations
            .saturating_add(entry.observed_events);
        if let Some(policy_id) = shadow.policy_id {
            shadow_policy_ids.insert(policy_id.get());
        }
        for workload in entry
            .source_workloads
            .iter()
            .chain(&entry.destination_workloads)
        {
            affected_workloads.insert(workload.clone());
        }
        if entry.source_workloads.is_empty() {
            affected_workloads.insert(format!("identity:{}", entry.key.source_identity.get()));
        }
        if entry.destination_workloads.is_empty() {
            affected_workloads.insert(format!("identity:{}", entry.key.destination_identity.get()));
        }

        let classification = record_shadow_classification(
            &mut summary,
            entry.decision.verdict,
            shadow.verdict,
            entry.observed_events,
        );
        if entry.decision != shadow {
            summary.decision_change_flows += 1;
            summary.decision_change_observations = summary
                .decision_change_observations
                .saturating_add(entry.observed_events);
        }
        changes.push(ShadowImpactChange {
            classification,
            flow: entry.clone(),
        });
    }
    summary.affected_workloads = affected_workloads.len();

    Ok(ShadowImpactReport {
        schema_version: SHADOW_IMPACT_SCHEMA_VERSION,
        analysis: "shadow_impact".to_owned(),
        analysis_source: analysis_source.into(),
        flow_history_schema_version: snapshot.schema_version,
        source_epoch: snapshot.source_epoch,
        flow_history_revision: snapshot.revision,
        query: snapshot.query.clone(),
        retained_flows: snapshot.retained_flows,
        retained_observations: snapshot.retained_observations,
        shadow_policy_ids: shadow_policy_ids.into_iter().collect(),
        summary,
        changes,
        note: "observation-weighted counterfactuals from recorded shadow decisions; no policy or dataplane state was changed".to_owned(),
    })
}

fn record_shadow_classification(
    summary: &mut ShadowImpactSummary,
    actual: Verdict,
    shadow: Verdict,
    observations: u64,
) -> ShadowImpactClassification {
    match (actual, shadow) {
        (Verdict::Allow, Verdict::Deny) => {
            summary.would_deny_flows += 1;
            summary.would_deny_observations =
                summary.would_deny_observations.saturating_add(observations);
            ShadowImpactClassification::WouldDeny
        }
        (Verdict::Deny, Verdict::Allow) => {
            summary.would_allow_flows += 1;
            summary.would_allow_observations = summary
                .would_allow_observations
                .saturating_add(observations);
            ShadowImpactClassification::WouldAllow
        }
        (actual, proposed) if actual == proposed => {
            summary.same_verdict_flows += 1;
            summary.same_verdict_observations = summary
                .same_verdict_observations
                .saturating_add(observations);
            ShadowImpactClassification::SameVerdict
        }
        _ => {
            summary.other_verdict_change_flows += 1;
            summary.other_verdict_change_observations = summary
                .other_verdict_change_observations
                .saturating_add(observations);
            ShadowImpactClassification::OtherVerdictChange
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlowHistoryCheckpoint {
    pub schema_version: u16,
    pub revision: Revision,
    pub evicted_flows: u64,
    pub evicted_observations: u64,
    pub agent_dropped_events: u64,
    pub agent_last_dropped_events: BTreeMap<String, u64>,
    pub omitted_flows: usize,
    pub omitted_observations: u64,
    pub entries: Vec<FlowHistoryEntry>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum FlowHistoryCheckpointError {
    #[error("unsupported flow-history checkpoint schema {actual}; expected {expected}")]
    UnsupportedSchema { actual: u16, expected: u16 },
    #[error("flow-history checkpoint contains {actual} entries; capacity is {capacity}")]
    CapacityExceeded { actual: usize, capacity: usize },
    #[error("flow-history checkpoint contains duplicate key")]
    DuplicateKey,
    #[error("flow-history checkpoint entry has invalid receive timestamps")]
    InvalidTimestamps,
    #[error("flow-history checkpoint entry has zero observations")]
    ZeroObservations,
    #[error("flow-history checkpoint entry has no reporting nodes")]
    MissingReportingNode,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RetainedFlow {
    record: FlowExportRecord,
    first_received_unix_ms: u64,
    last_received_unix_ms: u64,
    reporting_nodes: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowHistoryStore {
    capacity: usize,
    revision: Revision,
    entries: BTreeMap<FlowHistoryKey, RetainedFlow>,
    evicted_flows: u64,
    evicted_observations: u64,
    agent_dropped_events: u64,
    agent_last_dropped_events: BTreeMap<String, u64>,
    durable_omitted_flows: usize,
    durable_omitted_observations: u64,
}

impl Default for FlowHistoryStore {
    fn default() -> Self {
        Self::with_capacity(FLOW_HISTORY_CAPACITY)
    }
}

impl FlowHistoryStore {
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            capacity,
            revision: Revision::default(),
            entries: BTreeMap::new(),
            evicted_flows: 0,
            evicted_observations: 0,
            agent_dropped_events: 0,
            agent_last_dropped_events: BTreeMap::new(),
            durable_omitted_flows: 0,
            durable_omitted_observations: 0,
        }
    }

    pub fn ingest(&mut self, batch: FlowExportBatch, received_unix_ms: u64) -> bool {
        let FlowExportBatch {
            node_name,
            dropped_events,
            entries,
            ..
        } = batch;
        let previous_dropped = self
            .agent_last_dropped_events
            .insert(node_name.clone(), dropped_events)
            .unwrap_or(0);
        let new_drops = if dropped_events >= previous_dropped {
            dropped_events - previous_dropped
        } else {
            dropped_events
        };
        self.agent_dropped_events = self.agent_dropped_events.saturating_add(new_drops);
        let mut changed = new_drops != 0;
        for record in entries {
            changed = true;
            if let Some(retained) = self.entries.get_mut(&record.key) {
                retained.record.policy_revision = record.policy_revision;
                retained.record.decision = record.decision;
                retained.record.shadow = record.shadow;
                retained.record.service = record.service;
                retained.record.observed_events = retained
                    .record
                    .observed_events
                    .saturating_add(record.observed_events);
                retained.last_received_unix_ms =
                    retained.last_received_unix_ms.max(received_unix_ms);
                retained.reporting_nodes.insert(node_name.clone());
                continue;
            }
            if self.capacity == 0 {
                self.evicted_flows = self.evicted_flows.saturating_add(1);
                self.evicted_observations = self
                    .evicted_observations
                    .saturating_add(record.observed_events);
                continue;
            }
            if self.entries.len() == self.capacity
                && let Some(eviction_key) = self
                    .entries
                    .iter()
                    .min_by_key(|(key, retained)| (retained.last_received_unix_ms, *key))
                    .map(|(key, _)| key.clone())
                && let Some(evicted) = self.entries.remove(&eviction_key)
            {
                self.evicted_flows = self.evicted_flows.saturating_add(1);
                self.evicted_observations = self
                    .evicted_observations
                    .saturating_add(evicted.record.observed_events);
            }
            self.entries.insert(
                record.key.clone(),
                RetainedFlow {
                    record,
                    first_received_unix_ms: received_unix_ms,
                    last_received_unix_ms: received_unix_ms,
                    reporting_nodes: BTreeSet::from([node_name.clone()]),
                },
            );
        }
        if changed {
            self.revision = self.revision.next();
        }
        changed
    }

    #[must_use]
    pub fn snapshot(&self, source_epoch: u64) -> FlowHistorySnapshot {
        self.snapshot_window(source_epoch, None, None, self.capacity)
    }

    #[must_use]
    pub fn snapshot_window(
        &self,
        source_epoch: u64,
        since_unix_ms: Option<u64>,
        until_unix_ms: Option<u64>,
        limit: usize,
    ) -> FlowHistorySnapshot {
        let retained_observations = self
            .entries
            .values()
            .map(|retained| retained.record.observed_events)
            .fold(0_u64, u64::saturating_add);
        let mut matched: Vec<_> = self
            .entries
            .values()
            .filter(|retained| {
                since_unix_ms.is_none_or(|since| retained.last_received_unix_ms >= since)
                    && until_unix_ms.is_none_or(|until| retained.last_received_unix_ms <= until)
            })
            .collect();
        matched.sort_by(|left, right| {
            right
                .last_received_unix_ms
                .cmp(&left.last_received_unix_ms)
                .then_with(|| left.record.key.cmp(&right.record.key))
        });
        let matched_flows = matched.len();
        let matched_observations = matched
            .iter()
            .map(|retained| retained.record.observed_events)
            .fold(0_u64, u64::saturating_add);
        let entries: Vec<_> = matched
            .into_iter()
            .take(limit)
            .map(|retained| FlowHistoryEntry {
                key: retained.record.key.clone(),
                source_workloads: Vec::new(),
                destination_workloads: Vec::new(),
                policy_revision: retained.record.policy_revision,
                decision: retained.record.decision,
                shadow: retained.record.shadow,
                service: retained.record.service,
                observed_events: retained.record.observed_events,
                first_received_unix_ms: retained.first_received_unix_ms,
                last_received_unix_ms: retained.last_received_unix_ms,
                reporting_nodes: retained.reporting_nodes.iter().cloned().collect(),
            })
            .collect();
        FlowHistorySnapshot {
            schema_version: FLOW_HISTORY_SNAPSHOT_SCHEMA_VERSION,
            source_epoch,
            revision: self.revision,
            capacity: self.capacity,
            retained_flows: self.entries.len(),
            retained_observations,
            evicted_flows: self.evicted_flows,
            evicted_observations: self.evicted_observations,
            agent_dropped_events: self.agent_dropped_events,
            durable_checkpointed_flows: 0,
            durable_omitted_flows: self.durable_omitted_flows,
            durable_omitted_observations: self.durable_omitted_observations,
            query: FlowHistoryQuerySummary {
                since_unix_ms,
                until_unix_ms,
                limit,
                matched_flows,
                matched_observations,
                returned_flows: entries.len(),
                truncated: entries.len() < matched_flows,
            },
            entries,
        }
    }

    #[must_use]
    pub fn checkpoint(&self, entry_limit: usize) -> FlowHistoryCheckpoint {
        let snapshot = self.snapshot_window(0, None, None, entry_limit);
        let checkpointed_observations = snapshot
            .entries
            .iter()
            .map(|entry| entry.observed_events)
            .fold(0_u64, u64::saturating_add);
        FlowHistoryCheckpoint {
            schema_version: FLOW_HISTORY_CHECKPOINT_SCHEMA_VERSION,
            revision: self.revision,
            evicted_flows: self.evicted_flows,
            evicted_observations: self.evicted_observations,
            agent_dropped_events: self.agent_dropped_events,
            agent_last_dropped_events: self.agent_last_dropped_events.clone(),
            omitted_flows: self
                .durable_omitted_flows
                .saturating_add(self.entries.len().saturating_sub(snapshot.entries.len())),
            omitted_observations: self.durable_omitted_observations.saturating_add(
                snapshot
                    .retained_observations
                    .saturating_sub(checkpointed_observations),
            ),
            entries: snapshot.entries,
        }
    }

    /// Reconstructs bounded flow history from a validated persistence checkpoint.
    ///
    /// # Errors
    ///
    /// Returns [`FlowHistoryCheckpointError`] when the schema, entry count,
    /// timestamps, observation counts, reporting nodes, or logical keys are invalid.
    pub fn from_checkpoint(
        checkpoint: FlowHistoryCheckpoint,
        capacity: usize,
    ) -> Result<Self, FlowHistoryCheckpointError> {
        if !(1..=FLOW_HISTORY_CHECKPOINT_SCHEMA_VERSION).contains(&checkpoint.schema_version) {
            return Err(FlowHistoryCheckpointError::UnsupportedSchema {
                actual: checkpoint.schema_version,
                expected: FLOW_HISTORY_CHECKPOINT_SCHEMA_VERSION,
            });
        }
        let migrate_legacy_clock_regression =
            checkpoint.schema_version < FLOW_HISTORY_CHECKPOINT_SCHEMA_VERSION;
        if checkpoint.entries.len() > capacity {
            return Err(FlowHistoryCheckpointError::CapacityExceeded {
                actual: checkpoint.entries.len(),
                capacity,
            });
        }
        let mut entries = BTreeMap::new();
        for mut entry in checkpoint.entries {
            if entry.first_received_unix_ms == 0 {
                return Err(FlowHistoryCheckpointError::InvalidTimestamps);
            }
            if entry.last_received_unix_ms < entry.first_received_unix_ms {
                let regression = entry
                    .first_received_unix_ms
                    .saturating_sub(entry.last_received_unix_ms);
                if !migrate_legacy_clock_regression
                    || regression > FLOW_HISTORY_LEGACY_MAX_CLOCK_REGRESSION_MILLIS
                {
                    return Err(FlowHistoryCheckpointError::InvalidTimestamps);
                }
                entry.last_received_unix_ms = entry.first_received_unix_ms;
            }
            if entry.observed_events == 0 {
                return Err(FlowHistoryCheckpointError::ZeroObservations);
            }
            if entry.reporting_nodes.is_empty() {
                return Err(FlowHistoryCheckpointError::MissingReportingNode);
            }
            let retained = RetainedFlow {
                record: FlowExportRecord {
                    key: entry.key.clone(),
                    policy_revision: entry.policy_revision,
                    decision: entry.decision,
                    shadow: entry.shadow,
                    service: entry.service,
                    observed_events: entry.observed_events,
                },
                first_received_unix_ms: entry.first_received_unix_ms,
                last_received_unix_ms: entry.last_received_unix_ms,
                reporting_nodes: entry.reporting_nodes.into_iter().collect(),
            };
            if entries.insert(entry.key, retained).is_some() {
                return Err(FlowHistoryCheckpointError::DuplicateKey);
            }
        }
        Ok(Self {
            capacity,
            revision: checkpoint.revision,
            entries,
            evicted_flows: checkpoint.evicted_flows,
            evicted_observations: checkpoint.evicted_observations,
            agent_dropped_events: checkpoint.agent_dropped_events,
            agent_last_dropped_events: checkpoint.agent_last_dropped_events,
            durable_omitted_flows: checkpoint.omitted_flows,
            durable_omitted_observations: checkpoint.omitted_observations,
        })
    }

    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TopologyNode {
    pub name: String,
    pub ready: bool,
    pub labels: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TopologyWorkload {
    pub reference: String,
    pub identity_id: IdentityId,
    pub namespace: String,
    pub name: String,
    pub node_name: Option<String>,
    pub service_account: String,
    pub application: Option<String>,
    pub labels: BTreeMap<String, String>,
    pub ipv4_addresses: Vec<Ipv4Addr>,
    pub ipv6_addresses: Vec<Ipv6Addr>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct TopologyServicePort {
    pub name: Option<String>,
    pub protocol: String,
    pub port: u16,
    pub target_port: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct TopologyServiceBackendPort {
    pub name: Option<String>,
    pub protocol: String,
    pub port: Option<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct TopologyServiceBackend {
    pub endpoint_slice: String,
    pub address_type: String,
    pub addresses: Vec<String>,
    pub target_workload: Option<String>,
    pub node_name: Option<String>,
    pub zone: Option<String>,
    pub ready: bool,
    pub serving: bool,
    pub terminating: bool,
    pub ports: Vec<TopologyServiceBackendPort>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TopologyService {
    pub reference: String,
    pub namespace: String,
    pub name: String,
    pub service_type: String,
    pub cluster_ips: Vec<IpAddr>,
    pub selector: BTreeMap<String, String>,
    pub ports: Vec<TopologyServicePort>,
    pub selected_workloads: Vec<String>,
    pub backends: Vec<TopologyServiceBackend>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TopologyStateSnapshot {
    pub schema_version: u16,
    pub source_epoch: u64,
    pub revision: Revision,
    pub identity_revision: Revision,
    pub nodes: Vec<TopologyNode>,
    pub workloads: Vec<TopologyWorkload>,
    pub services: Vec<TopologyService>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TopologyHistoryEntry {
    pub captured_at_unix_ms: u64,
    pub snapshot: TopologyStateSnapshot,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TopologyHistoryQuerySummary {
    pub since_revision: Option<u64>,
    pub until_revision: Option<u64>,
    pub since_unix_ms: Option<u64>,
    pub until_unix_ms: Option<u64>,
    pub limit: usize,
    pub matched_snapshots: usize,
    pub returned_snapshots: usize,
    pub truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TopologyHistorySnapshot {
    pub schema_version: u16,
    pub capacity: usize,
    pub retained_snapshots: usize,
    pub evicted_snapshots: u64,
    pub durable_checkpointed_snapshots: usize,
    pub durable_omitted_snapshots: u64,
    pub query: TopologyHistoryQuerySummary,
    pub entries: Vec<TopologyHistoryEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TopologyHistoryCheckpoint {
    pub schema_version: u16,
    pub evicted_snapshots: u64,
    pub omitted_snapshots: u64,
    pub entries: Vec<TopologyHistoryEntry>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum TopologyHistoryCheckpointError {
    #[error("unsupported topology-history checkpoint schema {actual}; expected {expected}")]
    UnsupportedSchema { actual: u16, expected: u16 },
    #[error("topology-history checkpoint contains {actual} entries; capacity is {capacity}")]
    CapacityExceeded { actual: usize, capacity: usize },
    #[error("topology-history checkpoint entry has an invalid capture timestamp")]
    InvalidTimestamp,
    #[error("topology-history checkpoint contains unsupported topology schema {actual}")]
    UnsupportedTopologySchema { actual: u16 },
    #[error("topology-history checkpoint revisions are not strictly increasing")]
    InvalidRevisionOrder,
    #[error("topology-history checkpoint contains a duplicate epoch/revision fence")]
    DuplicateFence,
}

#[derive(Debug, PartialEq, Eq)]
pub struct TopologyHistoryStore {
    capacity: usize,
    entries: VecDeque<TopologyHistoryEntry>,
    evicted_snapshots: u64,
    durable_omitted_snapshots: u64,
}

impl Default for TopologyHistoryStore {
    fn default() -> Self {
        Self::with_capacity(TOPOLOGY_HISTORY_CAPACITY)
    }
}

impl TopologyHistoryStore {
    #[must_use]
    pub const fn with_capacity(capacity: usize) -> Self {
        Self {
            capacity,
            entries: VecDeque::new(),
            evicted_snapshots: 0,
            durable_omitted_snapshots: 0,
        }
    }

    pub fn record(&mut self, snapshot: TopologyStateSnapshot, captured_at_unix_ms: u64) {
        if self.capacity == 0 {
            self.evicted_snapshots = self.evicted_snapshots.saturating_add(1);
            return;
        }
        if let Some(latest) = self.entries.back_mut()
            && latest.snapshot.source_epoch == snapshot.source_epoch
            && latest.snapshot.revision == snapshot.revision
        {
            *latest = TopologyHistoryEntry {
                captured_at_unix_ms,
                snapshot,
            };
            return;
        }
        if self.entries.len() == self.capacity {
            self.entries.pop_front();
            self.evicted_snapshots = self.evicted_snapshots.saturating_add(1);
        }
        self.entries.push_back(TopologyHistoryEntry {
            captured_at_unix_ms,
            snapshot,
        });
    }

    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn snapshot_window(
        &self,
        since_revision: Option<u64>,
        until_revision: Option<u64>,
        since_unix_ms: Option<u64>,
        until_unix_ms: Option<u64>,
        limit: usize,
        durable_checkpointed_snapshots: usize,
    ) -> TopologyHistorySnapshot {
        let matched: Vec<_> = self
            .entries
            .iter()
            .rev()
            .filter(|entry| {
                let revision = entry.snapshot.revision.get();
                since_revision.is_none_or(|since| revision >= since)
                    && until_revision.is_none_or(|until| revision <= until)
                    && since_unix_ms.is_none_or(|since| entry.captured_at_unix_ms >= since)
                    && until_unix_ms.is_none_or(|until| entry.captured_at_unix_ms <= until)
            })
            .collect();
        let matched_snapshots = matched.len();
        let entries = matched.into_iter().take(limit).cloned().collect::<Vec<_>>();
        TopologyHistorySnapshot {
            schema_version: TOPOLOGY_HISTORY_SCHEMA_VERSION,
            capacity: self.capacity,
            retained_snapshots: self.entries.len(),
            evicted_snapshots: self.evicted_snapshots,
            durable_checkpointed_snapshots,
            durable_omitted_snapshots: self.durable_omitted_snapshots,
            query: TopologyHistoryQuerySummary {
                since_revision,
                until_revision,
                since_unix_ms,
                until_unix_ms,
                limit,
                matched_snapshots,
                returned_snapshots: entries.len(),
                truncated: entries.len() < matched_snapshots,
            },
            entries,
        }
    }

    #[must_use]
    pub fn checkpoint(&self, entry_limit: usize) -> TopologyHistoryCheckpoint {
        let retained = self.entries.len().min(entry_limit);
        TopologyHistoryCheckpoint {
            schema_version: TOPOLOGY_HISTORY_CHECKPOINT_SCHEMA_VERSION,
            evicted_snapshots: self.evicted_snapshots,
            omitted_snapshots: self
                .durable_omitted_snapshots
                .saturating_add(self.entries.len().saturating_sub(retained) as u64),
            entries: self
                .entries
                .iter()
                .skip(self.entries.len().saturating_sub(retained))
                .cloned()
                .collect(),
        }
    }

    /// Reconstructs bounded topology history from a validated checkpoint.
    ///
    /// # Errors
    ///
    /// Returns [`TopologyHistoryCheckpointError`] when the checkpoint schema,
    /// bounds, timestamps, topology schemas, or revision ordering are invalid.
    pub fn from_checkpoint(
        checkpoint: TopologyHistoryCheckpoint,
        capacity: usize,
    ) -> Result<Self, TopologyHistoryCheckpointError> {
        if checkpoint.schema_version != TOPOLOGY_HISTORY_CHECKPOINT_SCHEMA_VERSION {
            return Err(TopologyHistoryCheckpointError::UnsupportedSchema {
                actual: checkpoint.schema_version,
                expected: TOPOLOGY_HISTORY_CHECKPOINT_SCHEMA_VERSION,
            });
        }
        if checkpoint.entries.len() > capacity {
            return Err(TopologyHistoryCheckpointError::CapacityExceeded {
                actual: checkpoint.entries.len(),
                capacity,
            });
        }
        let mut fences = BTreeSet::new();
        let mut previous_revision = None;
        for entry in &checkpoint.entries {
            if entry.captured_at_unix_ms == 0 {
                return Err(TopologyHistoryCheckpointError::InvalidTimestamp);
            }
            if entry.snapshot.schema_version != TOPOLOGY_SNAPSHOT_SCHEMA_VERSION {
                return Err(TopologyHistoryCheckpointError::UnsupportedTopologySchema {
                    actual: entry.snapshot.schema_version,
                });
            }
            let revision = entry.snapshot.revision.get();
            if !fences.insert((entry.snapshot.source_epoch, revision)) {
                return Err(TopologyHistoryCheckpointError::DuplicateFence);
            }
            if revision == 0 || previous_revision.is_some_and(|previous| revision <= previous) {
                return Err(TopologyHistoryCheckpointError::InvalidRevisionOrder);
            }
            previous_revision = Some(revision);
        }
        Ok(Self {
            capacity,
            entries: checkpoint.entries.into(),
            evicted_snapshots: checkpoint.evicted_snapshots,
            durable_omitted_snapshots: checkpoint.omitted_snapshots,
        })
    }

    #[must_use]
    pub fn latest_revision(&self) -> Revision {
        self.entries
            .back()
            .map_or(Revision::INITIAL, |entry| entry.snapshot.revision)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkIdentity {
    pub id: IdentityId,
    pub cluster: String,
    pub namespace: String,
    pub workload: String,
    pub service_account: String,
    pub application: Option<String>,
    pub labels: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct IdentityEntry {
    canonical_key: String,
    identity: NetworkIdentity,
    pod_references: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PodIdentityBinding {
    identity_id: IdentityId,
    addresses: BTreeSet<IpAddr>,
}

/// Collision-checking identity authority and Pod-IP lookup index.
///
/// An IP address is only an index to an admitted identity. The canonical
/// metadata key remains the authority used to detect numeric-ID collisions.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IdentityRegistry {
    revision: Revision,
    identities: BTreeMap<IdentityId, IdentityEntry>,
    pods: BTreeMap<String, PodIdentityBinding>,
    addresses: BTreeMap<IpAddr, (String, IdentityId)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ipv4IdentityMapping {
    pub address: Ipv4Addr,
    pub identity_id: IdentityId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ipv6IdentityMapping {
    pub address: Ipv6Addr,
    pub identity_id: IdentityId,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityStateSnapshot {
    pub schema_version: u16,
    pub source_epoch: u64,
    pub revision: Revision,
    pub ipv4_entries: Vec<Ipv4IdentityMapping>,
    pub ipv6_entries: Vec<Ipv6IdentityMapping>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct PolicyMapKey {
    pub source_identity: IdentityId,
    pub destination_identity: IdentityId,
    /// IP protocol number, or zero for a global wildcard fallback.
    pub protocol: u8,
    /// Destination port, or zero for a protocol-specific or global wildcard.
    pub destination_port: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyDecisionRecord {
    pub verdict: Verdict,
    pub reason: PolicyReason,
    pub policy_id: Option<PolicyId>,
    pub rule_id: Option<RuleId>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyMapEntry {
    pub key: PolicyMapKey,
    pub decision: PolicyDecisionRecord,
    pub shadow: Option<PolicyDecisionRecord>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Ipv4PolicyMapKey {
    /// Exact source address, or `0.0.0.0` for an external-source fallback.
    pub source_address: Ipv4Addr,
    pub destination_identity: IdentityId,
    /// IP protocol number, or zero for a global wildcard fallback.
    pub protocol: u8,
    /// Destination port, or zero for a protocol-specific or global wildcard.
    pub destination_port: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ipv4PolicyMapEntry {
    pub key: Ipv4PolicyMapKey,
    pub decision: PolicyDecisionRecord,
    pub shadow: Option<PolicyDecisionRecord>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Ipv6PolicyMapKey {
    pub source_network: Ipv6Addr,
    pub source_prefix_len: u8,
    pub destination_identity: IdentityId,
    /// IP protocol number, or zero for a global wildcard fallback.
    pub protocol: u8,
    /// Destination port, or zero for a protocol-specific or global wildcard.
    pub destination_port: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ipv6PolicyMapEntry {
    pub key: Ipv6PolicyMapKey,
    pub decision: PolicyDecisionRecord,
    pub shadow: Option<PolicyDecisionRecord>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct EgressIpv4PolicyMapKey {
    pub source_identity: IdentityId,
    /// Exact destination address, or `0.0.0.0` for an arbitrary-destination fallback.
    pub destination_address: Ipv4Addr,
    /// IP protocol number, or zero for a global wildcard fallback.
    pub protocol: u8,
    /// Destination port, or zero for a protocol-specific or global wildcard.
    pub destination_port: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct EgressIpv4PolicyMapEntry {
    pub key: EgressIpv4PolicyMapKey,
    pub decision: PolicyDecisionRecord,
    pub shadow: Option<PolicyDecisionRecord>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct EgressIpv6PolicyMapKey {
    pub source_identity: IdentityId,
    pub destination_network: Ipv6Addr,
    pub destination_prefix_len: u8,
    /// IP protocol number, or zero for a global wildcard fallback.
    pub protocol: u8,
    /// Destination port, or zero for a protocol-specific or global wildcard.
    pub destination_port: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct EgressIpv6PolicyMapEntry {
    pub key: EgressIpv6PolicyMapKey,
    pub decision: PolicyDecisionRecord,
    pub shadow: Option<PolicyDecisionRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyStateSnapshot {
    pub schema_version: u16,
    pub source_epoch: u64,
    pub revision: Revision,
    pub entries: Vec<PolicyMapEntry>,
    pub ipv4_entries: Vec<Ipv4PolicyMapEntry>,
    pub ipv6_entries: Vec<Ipv6PolicyMapEntry>,
    #[serde(default)]
    pub egress_ipv4_entries: Vec<EgressIpv4PolicyMapEntry>,
    #[serde(default)]
    pub egress_ipv6_entries: Vec<EgressIpv6PolicyMapEntry>,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum IdentityAdmissionError {
    #[error("identity ID zero is reserved for unknown identity")]
    ReservedIdentity,
    #[error(
        "identity ID {identity_id:?} collision between canonical keys {existing_key:?} and {requested_key:?}"
    )]
    IdentityCollision {
        identity_id: IdentityId,
        existing_key: String,
        requested_key: String,
    },
    #[error(
        "Pod IP {address} is already assigned to {existing_pod}, cannot assign it to {requested_pod}"
    )]
    AddressConflict {
        address: IpAddr,
        existing_pod: String,
        requested_pod: String,
    },
}

impl IdentityRegistry {
    /// Atomically admits or updates one Pod's identity and IP indexes.
    ///
    /// # Errors
    ///
    /// Returns an error without changing the registry when the numeric identity
    /// collides with another canonical key, the ID is reserved, or a Pod IP is
    /// already owned by another Pod.
    pub fn admit_pod(
        &mut self,
        pod_key: String,
        canonical_key: String,
        identity: &NetworkIdentity,
        addresses: impl IntoIterator<Item = IpAddr>,
    ) -> Result<(), IdentityAdmissionError> {
        if identity.id.get() == 0 {
            return Err(IdentityAdmissionError::ReservedIdentity);
        }
        if let Some(existing) = self.identities.get(&identity.id)
            && existing.canonical_key != canonical_key
        {
            return Err(IdentityAdmissionError::IdentityCollision {
                identity_id: identity.id,
                existing_key: existing.canonical_key.clone(),
                requested_key: canonical_key,
            });
        }

        let addresses: BTreeSet<_> = addresses.into_iter().collect();
        for address in &addresses {
            if let Some((existing_pod, _)) = self.addresses.get(address)
                && existing_pod != &pod_key
            {
                return Err(IdentityAdmissionError::AddressConflict {
                    address: *address,
                    existing_pod: existing_pod.clone(),
                    requested_pod: pod_key,
                });
            }
        }

        let previous = self.clone();
        self.remove_pod_binding(&pod_key);
        self.identities
            .entry(identity.id)
            .and_modify(|entry| {
                entry.identity.clone_from(identity);
                entry.pod_references += 1;
            })
            .or_insert(IdentityEntry {
                canonical_key,
                identity: identity.clone(),
                pod_references: 1,
            });
        for address in &addresses {
            self.addresses
                .insert(*address, (pod_key.clone(), identity.id));
        }
        self.pods.insert(
            pod_key,
            PodIdentityBinding {
                identity_id: identity.id,
                addresses,
            },
        );
        if self.identities != previous.identities
            || self.pods != previous.pods
            || self.addresses != previous.addresses
        {
            self.revision = previous.revision.next();
        }
        Ok(())
    }

    pub fn remove_pod(&mut self, pod_key: &str) -> bool {
        let removed = self.remove_pod_binding(pod_key);
        if removed {
            self.revision = self.revision.next();
        }
        removed
    }

    fn remove_pod_binding(&mut self, pod_key: &str) -> bool {
        let Some(binding) = self.pods.remove(pod_key) else {
            return false;
        };
        for address in binding.addresses {
            self.addresses.remove(&address);
        }
        if let Some(entry) = self.identities.get_mut(&binding.identity_id) {
            entry.pod_references = entry.pod_references.saturating_sub(1);
            if entry.pod_references == 0 {
                self.identities.remove(&binding.identity_id);
            }
        }
        true
    }

    pub fn clear(&mut self) {
        if self.pods.is_empty() && self.identities.is_empty() && self.addresses.is_empty() {
            return;
        }
        self.pods.clear();
        self.identities.clear();
        self.addresses.clear();
        self.revision = self.revision.next();
    }

    #[must_use]
    pub fn identity_for_ip(&self, address: IpAddr) -> Option<IdentityId> {
        self.addresses.get(&address).map(|(_, identity)| *identity)
    }

    #[must_use]
    pub fn identity(&self, id: IdentityId) -> Option<&NetworkIdentity> {
        self.identities.get(&id).map(|entry| &entry.identity)
    }

    #[must_use]
    pub fn identity_count(&self) -> usize {
        self.identities.len()
    }

    #[must_use]
    pub fn address_count(&self) -> usize {
        self.addresses.len()
    }

    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    #[must_use]
    pub fn identity_snapshot(&self, source_epoch: u64) -> IdentityStateSnapshot {
        let ipv4_entries = self
            .addresses
            .iter()
            .filter_map(|(address, (_, identity_id))| match address {
                IpAddr::V4(address) => Some(Ipv4IdentityMapping {
                    address: *address,
                    identity_id: *identity_id,
                }),
                IpAddr::V6(_) => None,
            })
            .collect();
        let ipv6_entries = self
            .addresses
            .iter()
            .filter_map(|(address, (_, identity_id))| match address {
                IpAddr::V4(_) => None,
                IpAddr::V6(address) => Some(Ipv6IdentityMapping {
                    address: *address,
                    identity_id: *identity_id,
                }),
            })
            .collect();
        IdentityStateSnapshot {
            schema_version: IDENTITY_SNAPSHOT_SCHEMA_VERSION,
            source_epoch,
            revision: self.revision,
            ipv4_entries,
            ipv6_entries,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateSnapshot<T> {
    pub revision: Revision,
    pub value: T,
}

impl<T> StateSnapshot<T> {
    #[must_use]
    pub const fn new(revision: Revision, value: T) -> Self {
        Self { revision, value }
    }
}

/// FNV-1a provides a deterministic prototype ID. Collision detection is required
/// before an identity enters authoritative dataplane state.
#[must_use]
pub fn provisional_identity_id(identity_key: &str) -> IdentityId {
    let mut hash = 0x811c_9dc5_u32;
    for byte in identity_key.as_bytes() {
        hash ^= u32::from(*byte);
        hash = hash.wrapping_mul(0x0100_0193);
    }
    // Zero means "unknown" in the dataplane ABI.
    IdentityId::new(if hash == 0 { 1 } else { hash })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn component_compatibility_fixes_the_upgrade_contract() {
        let compatibility = ComponentCompatibility::current("unf-agent", "0.1.0", "revision-a");
        assert_eq!(
            compatibility.schema_version,
            COMPONENT_COMPATIBILITY_SCHEMA_VERSION
        );
        assert_eq!(compatibility.component, "unf-agent");
        assert_eq!(compatibility.software_version, "0.1.0");
        assert_eq!(compatibility.build_revision, "revision-a");
        assert_eq!(
            compatibility.persistent_bpf_state_abi_version,
            PERSISTENT_BPF_STATE_ABI_VERSION
        );
        assert_eq!(
            compatibility.identity_snapshot_schema_version,
            IDENTITY_SNAPSHOT_SCHEMA_VERSION
        );
        assert_eq!(
            compatibility.policy_snapshot_schema_version,
            POLICY_SNAPSHOT_SCHEMA_VERSION
        );
        assert_eq!(
            compatibility.agent_status_schema_version,
            AGENT_STATUS_SCHEMA_VERSION
        );
        assert_eq!(
            compatibility.service_snapshot_schema_version,
            SERVICE_SNAPSHOT_SCHEMA_VERSION
        );
        assert_eq!(
            compatibility.load_balancer_reachability_schema_version,
            LOAD_BALANCER_REACHABILITY_SCHEMA_VERSION
        );
        assert_eq!(
            compatibility.flow_export_schema_version,
            FLOW_EXPORT_SCHEMA_VERSION
        );
    }

    #[test]
    fn version_transition_uses_stable_wire_names() {
        assert_eq!(
            serde_json::to_string(&VersionTransition::CompatibleRollback)
                .expect("transition serializes"),
            "\"compatible_rollback\""
        );
        assert_eq!(
            serde_json::from_str::<VersionTransition>("\"blocked_rollback\"")
                .expect("transition deserializes"),
            VersionTransition::BlockedRollback
        );
    }

    #[test]
    fn provisional_ids_are_deterministic_and_nonzero() {
        let key = "cluster-a/backend/default/api";
        assert_eq!(provisional_identity_id(key), provisional_identity_id(key));
        assert_ne!(provisional_identity_id(key).get(), 0);
        assert_ne!(
            provisional_identity_id(key),
            provisional_identity_id("cluster-a/backend/default/worker")
        );
    }

    fn identity(id: u32, workload: &str) -> NetworkIdentity {
        NetworkIdentity {
            id: IdentityId::new(id),
            cluster: "local".to_owned(),
            namespace: "backend".to_owned(),
            workload: workload.to_owned(),
            service_account: "default".to_owned(),
            application: Some(workload.to_owned()),
            labels: BTreeMap::new(),
        }
    }

    #[test]
    fn registry_indexes_pod_ip_and_garbage_collects_identity() {
        let mut registry = IdentityRegistry::default();
        let address = "10.244.1.3".parse().expect("valid test address");
        registry
            .admit_pod(
                "backend/server-1".to_owned(),
                "local/backend/default/server".to_owned(),
                &identity(42, "server"),
                [address],
            )
            .expect("identity is admitted");

        assert_eq!(registry.identity_for_ip(address), Some(IdentityId::new(42)));
        assert_eq!(registry.identity_count(), 1);
        assert_eq!(registry.address_count(), 1);
        assert_eq!(registry.revision(), Revision::new(1));
        assert!(registry.remove_pod("backend/server-1"));
        assert_eq!(registry.identity_for_ip(address), None);
        assert_eq!(registry.identity_count(), 0);
        assert_eq!(registry.revision(), Revision::new(2));
    }

    #[test]
    fn registry_rejects_identity_hash_collision_without_mutation() {
        let mut registry = IdentityRegistry::default();
        registry
            .admit_pod(
                "backend/server-1".to_owned(),
                "local/backend/default/server".to_owned(),
                &identity(42, "server"),
                ["10.244.1.3".parse().expect("valid test address")],
            )
            .expect("first identity is admitted");

        let error = registry
            .admit_pod(
                "backend/other-1".to_owned(),
                "local/backend/default/other".to_owned(),
                &identity(42, "other"),
                ["10.244.1.4".parse().expect("valid test address")],
            )
            .expect_err("colliding identity is rejected");

        assert!(matches!(
            error,
            IdentityAdmissionError::IdentityCollision { .. }
        ));
        assert_eq!(registry.identity_count(), 1);
        assert_eq!(registry.address_count(), 1);
        assert_eq!(registry.revision(), Revision::new(1));
    }

    #[test]
    fn registry_rejects_reused_pod_ip_without_mutation() {
        let mut registry = IdentityRegistry::default();
        let address = "10.244.1.3".parse().expect("valid test address");
        registry
            .admit_pod(
                "backend/server-1".to_owned(),
                "local/backend/default/server".to_owned(),
                &identity(42, "server"),
                [address],
            )
            .expect("first identity is admitted");

        let error = registry
            .admit_pod(
                "frontend/client-1".to_owned(),
                "local/frontend/default/client".to_owned(),
                &identity(84, "client"),
                [address],
            )
            .expect_err("duplicate address is rejected");

        assert!(matches!(
            error,
            IdentityAdmissionError::AddressConflict { .. }
        ));
        assert_eq!(registry.identity_for_ip(address), Some(IdentityId::new(42)));
        assert_eq!(registry.identity_count(), 1);
        assert_eq!(registry.revision(), Revision::new(1));
    }

    #[test]
    fn registry_snapshot_is_revisioned_sorted_and_idempotent() {
        let mut registry = IdentityRegistry::default();
        let server = identity(42, "server");
        registry
            .admit_pod(
                "backend/server-1".to_owned(),
                "local/backend/default/server".to_owned(),
                &server,
                [
                    "10.244.1.4".parse().expect("valid test address"),
                    "10.244.1.3".parse().expect("valid test address"),
                    "fd00:10:244:1::4".parse().expect("valid test address"),
                    "fd00:10:244:1::3".parse().expect("valid test address"),
                ],
            )
            .expect("identity is admitted");
        let first = registry.identity_snapshot(7);
        assert_eq!(first.schema_version, IDENTITY_SNAPSHOT_SCHEMA_VERSION);
        assert_eq!(first.source_epoch, 7);
        assert_eq!(first.revision, Revision::new(1));
        assert_eq!(first.ipv4_entries[0].address, Ipv4Addr::new(10, 244, 1, 3));
        assert_eq!(
            first.ipv6_entries[0].address,
            "fd00:10:244:1::3".parse::<Ipv6Addr>().unwrap()
        );

        registry
            .admit_pod(
                "backend/server-1".to_owned(),
                "local/backend/default/server".to_owned(),
                &server,
                [
                    "10.244.1.4".parse().expect("valid test address"),
                    "10.244.1.3".parse().expect("valid test address"),
                    "fd00:10:244:1::4".parse().expect("valid test address"),
                    "fd00:10:244:1::3".parse().expect("valid test address"),
                ],
            )
            .expect("idempotent update succeeds");
        assert_eq!(registry.revision(), Revision::new(1));
    }

    fn topology_snapshot(revision: u64) -> TopologyStateSnapshot {
        TopologyStateSnapshot {
            schema_version: TOPOLOGY_SNAPSHOT_SCHEMA_VERSION,
            source_epoch: 17,
            revision: Revision::new(revision),
            identity_revision: Revision::new(3),
            nodes: vec![TopologyNode {
                name: "worker-a".to_owned(),
                ready: true,
                labels: BTreeMap::from([("zone".to_owned(), "a".to_owned())]),
            }],
            workloads: vec![TopologyWorkload {
                reference: "frontend/client".to_owned(),
                identity_id: IdentityId::new(42),
                namespace: "frontend".to_owned(),
                name: "client".to_owned(),
                node_name: Some("worker-a".to_owned()),
                service_account: "default".to_owned(),
                application: Some("client".to_owned()),
                labels: BTreeMap::from([("app".to_owned(), "client".to_owned())]),
                ipv4_addresses: vec![Ipv4Addr::new(10, 42, 0, 10)],
                ipv6_addresses: vec!["fd00:10:42::10".parse().unwrap()],
            }],
            services: vec![TopologyService {
                reference: "frontend/client".to_owned(),
                namespace: "frontend".to_owned(),
                name: "client".to_owned(),
                service_type: "ClusterIP".to_owned(),
                cluster_ips: vec!["10.43.0.10".parse().expect("valid test address")],
                selector: BTreeMap::from([("app".to_owned(), "client".to_owned())]),
                ports: vec![TopologyServicePort {
                    name: Some("http".to_owned()),
                    protocol: "TCP".to_owned(),
                    port: 80,
                    target_port: Some("8080".to_owned()),
                }],
                selected_workloads: vec!["frontend/client".to_owned()],
                backends: vec![TopologyServiceBackend {
                    endpoint_slice: "frontend/client-abc".to_owned(),
                    address_type: "IPv4".to_owned(),
                    addresses: vec!["10.42.0.10".to_owned()],
                    target_workload: Some("frontend/client".to_owned()),
                    node_name: Some("worker-a".to_owned()),
                    zone: Some("zone-a".to_owned()),
                    ready: true,
                    serving: true,
                    terminating: false,
                    ports: vec![TopologyServiceBackendPort {
                        name: Some("http".to_owned()),
                        protocol: "TCP".to_owned(),
                        port: Some(8080),
                    }],
                }],
            }],
        }
    }

    #[test]
    fn topology_snapshot_schema_round_trips() {
        let snapshot = topology_snapshot(4);
        let encoded = serde_json::to_vec(&snapshot).expect("topology snapshot serializes");
        let decoded: TopologyStateSnapshot =
            serde_json::from_slice(&encoded).expect("topology snapshot deserializes");
        assert_eq!(decoded, snapshot);
    }

    #[test]
    fn topology_history_is_bounded_queryable_and_restart_safe() {
        let mut store = TopologyHistoryStore::with_capacity(3);
        for (revision, captured_at) in [(1, 100), (2, 200), (3, 300), (4, 400)] {
            store.record(topology_snapshot(revision), captured_at);
        }

        let bounded = store.snapshot_window(Some(2), Some(4), Some(200), None, 2, 0);
        assert_eq!(bounded.schema_version, TOPOLOGY_HISTORY_SCHEMA_VERSION);
        assert_eq!(bounded.retained_snapshots, 3);
        assert_eq!(bounded.evicted_snapshots, 1);
        assert_eq!(bounded.query.matched_snapshots, 3);
        assert_eq!(bounded.query.returned_snapshots, 2);
        assert!(bounded.query.truncated);
        assert_eq!(bounded.entries[0].snapshot.revision, Revision::new(4));
        assert_eq!(bounded.entries[1].snapshot.revision, Revision::new(3));

        let checkpoint = store.checkpoint(2);
        assert_eq!(checkpoint.omitted_snapshots, 1);
        let restored = TopologyHistoryStore::from_checkpoint(checkpoint, 3)
            .expect("valid topology history restores");
        assert_eq!(restored.latest_revision(), Revision::new(4));
        let restored_snapshot = restored.snapshot_window(None, None, None, None, 3, 2);
        assert_eq!(restored_snapshot.retained_snapshots, 2);
        assert_eq!(restored_snapshot.durable_omitted_snapshots, 1);
        assert_eq!(restored_snapshot.durable_checkpointed_snapshots, 2);
    }

    #[test]
    fn topology_history_rejects_untrusted_checkpoints() {
        let mut store = TopologyHistoryStore::with_capacity(2);
        store.record(topology_snapshot(1), 100);
        store.record(topology_snapshot(2), 200);

        let mut checkpoint = store.checkpoint(2);
        checkpoint.entries[1].snapshot.revision = Revision::new(1);
        checkpoint.entries[1].snapshot.source_epoch = 18;
        assert_eq!(
            TopologyHistoryStore::from_checkpoint(checkpoint, 2),
            Err(TopologyHistoryCheckpointError::InvalidRevisionOrder)
        );

        let mut checkpoint = store.checkpoint(2);
        checkpoint.entries[1].snapshot.revision = Revision::new(1);
        assert_eq!(
            TopologyHistoryStore::from_checkpoint(checkpoint, 2),
            Err(TopologyHistoryCheckpointError::DuplicateFence)
        );

        let mut checkpoint = store.checkpoint(2);
        checkpoint.entries[0].snapshot.schema_version = TOPOLOGY_SNAPSHOT_SCHEMA_VERSION - 1;
        assert_eq!(
            TopologyHistoryStore::from_checkpoint(checkpoint, 2),
            Err(TopologyHistoryCheckpointError::UnsupportedTopologySchema {
                actual: TOPOLOGY_SNAPSHOT_SCHEMA_VERSION - 1,
            })
        );
    }

    fn flow_record(
        source: u32,
        destination: u32,
        port: u16,
        observations: u64,
    ) -> FlowExportRecord {
        FlowExportRecord {
            key: FlowHistoryKey {
                direction: PolicyDirection::Ingress,
                source_identity: IdentityId::new(source),
                destination_identity: IdentityId::new(destination),
                source_ipv4: None,
                destination_ipv4: None,
                source_ipv6: None,
                destination_ipv6: None,
                protocol: 6,
                destination_port: port,
                service: None,
            },
            policy_revision: Revision::new(7),
            decision: FlowExportDecision {
                verdict: Verdict::Allow,
                reason: 1,
                policy_id: Some(PolicyId::new(9)),
                rule_id: Some(RuleId::new(2)),
            },
            shadow: None,
            service: None,
            observed_events: observations,
        }
    }

    #[test]
    fn flow_history_aggregates_nodes_and_observations_deterministically() {
        let mut store = FlowHistoryStore::with_capacity(2);
        assert!(store.ingest(
            FlowExportBatch {
                schema_version: FLOW_EXPORT_SCHEMA_VERSION,
                node_name: "worker-a".to_owned(),
                dropped_events: 3,
                entries: vec![flow_record(1, 2, 8080, 4)],
            },
            100,
        ));
        assert!(store.ingest(
            FlowExportBatch {
                schema_version: FLOW_EXPORT_SCHEMA_VERSION,
                node_name: "worker-b".to_owned(),
                dropped_events: 1,
                entries: vec![flow_record(1, 2, 8080, 6)],
            },
            200,
        ));
        let snapshot = store.snapshot(17);
        assert_eq!(snapshot.revision, Revision::new(2));
        assert_eq!(snapshot.retained_flows, 1);
        assert_eq!(snapshot.retained_observations, 10);
        assert_eq!(snapshot.agent_dropped_events, 4);
        assert_eq!(
            snapshot.entries[0].reporting_nodes,
            ["worker-a", "worker-b"]
        );
        assert_eq!(snapshot.entries[0].first_received_unix_ms, 100);
        assert_eq!(snapshot.entries[0].last_received_unix_ms, 200);
    }

    #[test]
    fn flow_history_clamps_clock_regression_and_migrates_bounded_v3_checkpoint() {
        let mut store = FlowHistoryStore::with_capacity(1);
        let first = FlowExportBatch {
            schema_version: FLOW_EXPORT_SCHEMA_VERSION,
            node_name: "worker-a".to_owned(),
            dropped_events: 0,
            entries: vec![flow_record(1, 2, 8080, 1)],
        };
        assert!(store.ingest(first.clone(), 200));
        assert!(store.ingest(first, 199));
        let checkpoint = store.checkpoint(1);
        assert_eq!(
            checkpoint.schema_version,
            FLOW_HISTORY_CHECKPOINT_SCHEMA_VERSION
        );
        assert_eq!(checkpoint.entries[0].first_received_unix_ms, 200);
        assert_eq!(checkpoint.entries[0].last_received_unix_ms, 200);
        FlowHistoryStore::from_checkpoint(checkpoint.clone(), 1)
            .expect("current checkpoint remains restart-valid after clock regression");

        let mut legacy = checkpoint.clone();
        legacy.schema_version = 3;
        legacy.entries[0].first_received_unix_ms = 200;
        legacy.entries[0].last_received_unix_ms = 199;
        let migrated = FlowHistoryStore::from_checkpoint(legacy.clone(), 1)
            .expect("bounded schema-v3 clock regression is migrated");
        assert_eq!(migrated.snapshot(17).entries[0].last_received_unix_ms, 200);

        let mut current = legacy.clone();
        current.schema_version = FLOW_HISTORY_CHECKPOINT_SCHEMA_VERSION;
        assert_eq!(
            FlowHistoryStore::from_checkpoint(current, 1),
            Err(FlowHistoryCheckpointError::InvalidTimestamps)
        );

        legacy.entries[0].first_received_unix_ms = 1_200;
        legacy.entries[0].last_received_unix_ms = 199;
        assert_eq!(
            FlowHistoryStore::from_checkpoint(legacy, 1),
            Err(FlowHistoryCheckpointError::InvalidTimestamps)
        );
    }

    #[test]
    fn flow_history_retains_service_outcome_provenance() {
        let mut record = flow_record(0, 0, 80, 2);
        record.policy_revision = Revision::default();
        record.decision = FlowExportDecision {
            verdict: Verdict::Allow,
            reason: 1,
            policy_id: None,
            rule_id: None,
        };
        record.service = Some(ServiceFlowOutcome {
            service_id: ServiceId::new(11),
            backend_id: Some(BackendId::new(13)),
            service_revision: Revision::new(7),
            backend_ipv4: Some(Ipv4Addr::new(10, 42, 1, 20)),
            backend_ipv6: None,
            frontend_port: 80,
            backend_port: Some(8080),
            action: 1,
            reason: 1,
            frontend_kind: ServiceFrontendKind::NodePortCluster,
        });
        record.key.service = Some(ServiceFlowKey {
            service_id: ServiceId::new(11),
            backend_id: Some(BackendId::new(13)),
            service_revision: Revision::new(7),
            action: 1,
            reason: 1,
            frontend_kind: ServiceFrontendKind::NodePortCluster,
        });
        let mut failure = record.clone();
        failure.key.service = Some(ServiceFlowKey {
            service_id: ServiceId::new(11),
            backend_id: None,
            service_revision: Revision::new(8),
            action: 2,
            reason: 3,
            frontend_kind: ServiceFrontendKind::NodePortLocal,
        });
        failure.decision.verdict = Verdict::Deny;
        failure.decision.reason = 3;
        failure.service = Some(ServiceFlowOutcome {
            service_id: ServiceId::new(11),
            backend_id: None,
            service_revision: Revision::new(8),
            backend_ipv4: None,
            backend_ipv6: None,
            frontend_port: 80,
            backend_port: None,
            action: 2,
            reason: 3,
            frontend_kind: ServiceFrontendKind::NodePortLocal,
        });
        let mut store = FlowHistoryStore::with_capacity(2);
        store.ingest(
            FlowExportBatch {
                schema_version: FLOW_EXPORT_SCHEMA_VERSION,
                node_name: "worker-a".to_owned(),
                dropped_events: 0,
                entries: vec![record, failure],
            },
            100,
        );
        let checkpoint = store.checkpoint(2);
        let restored = FlowHistoryStore::from_checkpoint(checkpoint, 2)
            .expect("service history checkpoint is restorable");
        let snapshot = restored.snapshot(17);
        assert_eq!(snapshot.retained_flows, 2);
        assert!(snapshot.entries.iter().any(|entry| {
            entry.service.is_some_and(|outcome| {
                outcome.service_id == ServiceId::new(11)
                    && outcome.backend_id == Some(BackendId::new(13))
                    && outcome.backend_port == Some(8080)
            })
        }));
        assert!(snapshot.entries.iter().any(|entry| {
            entry
                .service
                .is_some_and(|outcome| outcome.action == 2 && outcome.reason == 3)
        }));
    }

    #[test]
    fn flow_history_migrates_pre_nodeport_classification_checkpoints() {
        let mut record = flow_record(0, 0, 80, 1);
        record.key.service = Some(ServiceFlowKey {
            service_id: ServiceId::new(11),
            backend_id: None,
            service_revision: Revision::new(7),
            action: 2,
            reason: 3,
            frontend_kind: ServiceFrontendKind::NodePortLocal,
        });
        record.policy_revision = Revision::default();
        record.decision = FlowExportDecision {
            verdict: Verdict::Deny,
            reason: 3,
            policy_id: None,
            rule_id: None,
        };
        record.service = Some(ServiceFlowOutcome {
            service_id: ServiceId::new(11),
            backend_id: None,
            service_revision: Revision::new(7),
            backend_ipv4: None,
            backend_ipv6: None,
            frontend_port: 80,
            backend_port: None,
            action: 2,
            reason: 3,
            frontend_kind: ServiceFrontendKind::NodePortLocal,
        });
        let mut store = FlowHistoryStore::with_capacity(1);
        store.ingest(
            FlowExportBatch {
                schema_version: FLOW_EXPORT_SCHEMA_VERSION,
                node_name: "worker-a".to_owned(),
                dropped_events: 0,
                entries: vec![record],
            },
            100,
        );
        let mut legacy = serde_json::to_value(store.checkpoint(1)).unwrap();
        legacy["schema_version"] = serde_json::json!(4);
        legacy["entries"][0]["key"]["service"]
            .as_object_mut()
            .unwrap()
            .remove("frontend_kind");
        legacy["entries"][0]["service"]
            .as_object_mut()
            .unwrap()
            .remove("frontend_kind");
        let checkpoint: FlowHistoryCheckpoint = serde_json::from_value(legacy).unwrap();
        let restored = FlowHistoryStore::from_checkpoint(checkpoint, 1)
            .expect("schema-v4 ClusterIP history remains restart compatible");
        let entry = &restored.snapshot(17).entries[0];
        assert_eq!(
            entry.service.unwrap().frontend_kind,
            ServiceFrontendKind::ClusterIp
        );
        assert_eq!(
            entry.key.service.as_ref().unwrap().frontend_kind,
            ServiceFrontendKind::ClusterIp
        );
    }

    #[test]
    fn flow_history_keeps_ingress_and_egress_decisions_separate() {
        let ingress = flow_record(1, 2, 8080, 2);
        let mut egress = ingress.clone();
        egress.key.direction = PolicyDirection::Egress;
        egress.observed_events = 3;
        let mut store = FlowHistoryStore::with_capacity(2);
        store.ingest(
            FlowExportBatch {
                schema_version: FLOW_EXPORT_SCHEMA_VERSION,
                node_name: "worker-a".to_owned(),
                dropped_events: 0,
                entries: vec![ingress, egress],
            },
            100,
        );

        let snapshot = store.snapshot(17);
        assert_eq!(snapshot.retained_flows, 2);
        assert_eq!(snapshot.retained_observations, 5);
        assert!(
            snapshot
                .entries
                .iter()
                .any(|entry| entry.key.direction == PolicyDirection::Ingress)
        );
        assert!(
            snapshot
                .entries
                .iter()
                .any(|entry| entry.key.direction == PolicyDirection::Egress)
        );
    }

    #[test]
    fn flow_history_evicts_the_oldest_entry_at_capacity() {
        let mut store = FlowHistoryStore::with_capacity(2);
        for (port, received) in [(8080, 100), (8081, 200), (8082, 300)] {
            store.ingest(
                FlowExportBatch {
                    schema_version: FLOW_EXPORT_SCHEMA_VERSION,
                    node_name: "worker-a".to_owned(),
                    dropped_events: 0,
                    entries: vec![flow_record(1, 2, port, u64::from(port - 8079))],
                },
                received,
            );
        }
        let snapshot = store.snapshot(17);
        assert_eq!(snapshot.retained_flows, 2);
        assert_eq!(snapshot.evicted_flows, 1);
        assert_eq!(snapshot.evicted_observations, 1);
        assert_eq!(snapshot.entries[0].key.destination_port, 8082);
        assert_eq!(snapshot.entries[1].key.destination_port, 8081);
    }

    #[test]
    fn flow_history_time_windows_use_last_received_time_and_bound_results() {
        let mut store = FlowHistoryStore::with_capacity(3);
        for (port, received) in [(8080, 100), (8081, 200), (8082, 300)] {
            store.ingest(
                FlowExportBatch {
                    schema_version: FLOW_EXPORT_SCHEMA_VERSION,
                    node_name: "worker-a".to_owned(),
                    dropped_events: 0,
                    entries: vec![flow_record(1, 2, port, u64::from(port - 8079))],
                },
                received,
            );
        }

        let window = store.snapshot_window(17, Some(150), Some(250), 3);
        assert_eq!(window.retained_flows, 3);
        assert_eq!(window.query.matched_flows, 1);
        assert_eq!(window.query.matched_observations, 2);
        assert_eq!(window.query.returned_flows, 1);
        assert!(!window.query.truncated);
        assert_eq!(window.entries[0].key.destination_port, 8081);

        let limited = store.snapshot_window(17, None, None, 1);
        assert_eq!(limited.query.matched_flows, 3);
        assert_eq!(limited.query.returned_flows, 1);
        assert!(limited.query.truncated);
        assert_eq!(limited.entries[0].key.destination_port, 8082);
    }

    #[test]
    fn shadow_impact_is_observation_weighted_and_offline_safe() {
        let mut would_deny = flow_record(1, 2, 9090, 7);
        would_deny.shadow = Some(FlowExportDecision {
            verdict: Verdict::Deny,
            reason: PolicyReason::ExplicitRule as u8,
            policy_id: Some(PolicyId::new(41)),
            rule_id: Some(RuleId::new(3)),
        });
        let unchanged = flow_record(1, 2, 8080, 5);
        let mut store = FlowHistoryStore::with_capacity(2);
        store.ingest(
            FlowExportBatch {
                schema_version: FLOW_EXPORT_SCHEMA_VERSION,
                node_name: "worker-a".to_owned(),
                dropped_events: 0,
                entries: vec![would_deny, unchanged],
            },
            100,
        );

        let report = analyze_shadow_impact(&store.snapshot(17), "offline:test.json")
            .expect("valid saved history produces a shadow-impact report");
        assert_eq!(report.schema_version, SHADOW_IMPACT_SCHEMA_VERSION);
        assert_eq!(report.analysis_source, "offline:test.json");
        assert_eq!(report.shadow_policy_ids, [41]);
        assert_eq!(report.summary.selected_flows, 2);
        assert_eq!(report.summary.selected_observations, 12);
        assert_eq!(report.summary.shadowed_flows, 1);
        assert_eq!(report.summary.shadowed_observations, 7);
        assert_eq!(report.summary.would_deny_flows, 1);
        assert_eq!(report.summary.would_deny_observations, 7);
        assert_eq!(report.summary.decision_change_flows, 1);
        assert_eq!(report.summary.affected_workloads, 2);
        assert_eq!(report.changes.len(), 1);
        assert_eq!(
            report.changes[0].classification,
            ShadowImpactClassification::WouldDeny
        );
    }

    #[test]
    fn shadow_impact_rejects_untrusted_snapshot_shape() {
        let store = FlowHistoryStore::with_capacity(1);
        let mut snapshot = store.snapshot(17);
        snapshot.schema_version = FLOW_HISTORY_SNAPSHOT_SCHEMA_VERSION - 1;
        assert_eq!(
            analyze_shadow_impact(&snapshot, "offline:legacy.json"),
            Err(ShadowImpactError::UnsupportedSchema {
                actual: FLOW_HISTORY_SNAPSHOT_SCHEMA_VERSION - 1,
                expected: FLOW_HISTORY_SNAPSHOT_SCHEMA_VERSION,
            })
        );

        let mut snapshot = store.snapshot(17);
        snapshot.query.returned_flows = 1;
        assert_eq!(
            analyze_shadow_impact(&snapshot, "offline:invalid.json"),
            Err(ShadowImpactError::InconsistentReturnedFlows {
                reported: 1,
                actual: 0,
            })
        );
    }

    #[test]
    fn flow_history_checkpoint_restores_newest_entries_and_drop_baselines() {
        let mut store = FlowHistoryStore::with_capacity(3);
        for (port, received) in [(8080, 100), (8081, 200), (8082, 300)] {
            store.ingest(
                FlowExportBatch {
                    schema_version: FLOW_EXPORT_SCHEMA_VERSION,
                    node_name: "worker-a".to_owned(),
                    dropped_events: 3,
                    entries: vec![flow_record(1, 2, port, u64::from(port - 8079))],
                },
                received,
            );
        }
        let checkpoint = store.checkpoint(2);
        assert_eq!(checkpoint.omitted_flows, 1);
        assert_eq!(checkpoint.omitted_observations, 1);

        let mut restored = FlowHistoryStore::from_checkpoint(checkpoint, 3)
            .expect("valid flow-history checkpoint restores");
        let restored_snapshot = restored.snapshot(99);
        assert_eq!(restored_snapshot.revision, Revision::new(3));
        assert_eq!(restored_snapshot.retained_flows, 2);
        assert_eq!(restored_snapshot.durable_omitted_flows, 1);
        assert_eq!(restored_snapshot.durable_omitted_observations, 1);
        assert_eq!(restored_snapshot.entries[0].key.destination_port, 8082);
        assert_eq!(restored_snapshot.entries[1].key.destination_port, 8081);

        restored.ingest(
            FlowExportBatch {
                schema_version: FLOW_EXPORT_SCHEMA_VERSION,
                node_name: "worker-a".to_owned(),
                dropped_events: 4,
                entries: Vec::new(),
            },
            400,
        );
        assert_eq!(restored.snapshot(99).agent_dropped_events, 4);

        let mut legacy = serde_json::to_value(store.checkpoint(1)).unwrap();
        legacy["schema_version"] = serde_json::json!(1);
        legacy["entries"][0]["key"]
            .as_object_mut()
            .expect("legacy key is an object")
            .remove("direction");
        let legacy: FlowHistoryCheckpoint = serde_json::from_value(legacy).unwrap();
        let migrated = FlowHistoryStore::from_checkpoint(legacy, 3)
            .expect("schema-v1 checkpoint defaults to ingress");
        assert_eq!(
            migrated.snapshot(99).entries[0].key.direction,
            PolicyDirection::Ingress
        );
    }

    #[test]
    fn zero_capacity_flow_history_drops_without_growing() {
        let mut store = FlowHistoryStore::with_capacity(0);
        store.ingest(
            FlowExportBatch {
                schema_version: FLOW_EXPORT_SCHEMA_VERSION,
                node_name: "worker-a".to_owned(),
                dropped_events: 0,
                entries: vec![flow_record(1, 2, 8080, 7)],
            },
            100,
        );
        let snapshot = store.snapshot(17);
        assert_eq!(snapshot.retained_flows, 0);
        assert_eq!(snapshot.evicted_flows, 1);
        assert_eq!(snapshot.evicted_observations, 7);
    }
}
