//! Revisioned control-plane state and stable identity metadata.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use unf_common::{IdentityId, PolicyId, PolicyReason, Revision, RuleId, Verdict};

pub const IDENTITY_SNAPSHOT_SCHEMA_VERSION: u16 = 2;
pub const POLICY_SNAPSHOT_SCHEMA_VERSION: u16 = 3;
pub const TOPOLOGY_SNAPSHOT_SCHEMA_VERSION: u16 = 3;
pub const FLOW_EXPORT_SCHEMA_VERSION: u16 = 2;
pub const AGENT_STATUS_SCHEMA_VERSION: u16 = 1;
pub const FLOW_EXPORT_BATCH_LIMIT: usize = 512;
pub const FLOW_HISTORY_CAPACITY: usize = 4_096;
/// One half of the dual-bank eBPF policy map's 262,144-entry capacity.
pub const POLICY_MAP_BANK_ENTRY_LIMIT: usize = 131_072;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevisionSet {
    pub identity: Revision,
    pub policy: Revision,
    pub service: Revision,
    pub routing: Revision,
    pub topology: Revision,
    pub telemetry: Revision,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentStateReport {
    pub schema_version: u16,
    pub node_name: String,
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

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct FlowHistoryKey {
    pub source_identity: IdentityId,
    pub destination_identity: IdentityId,
    pub source_ipv4: Option<Ipv4Addr>,
    pub destination_ipv4: Option<Ipv4Addr>,
    pub source_ipv6: Option<Ipv6Addr>,
    pub destination_ipv6: Option<Ipv6Addr>,
    pub protocol: u8,
    pub destination_port: u16,
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
    pub observed_events: u64,
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
    pub entries: Vec<FlowHistoryEntry>,
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
                retained.record.observed_events = retained
                    .record
                    .observed_events
                    .saturating_add(record.observed_events);
                retained.last_received_unix_ms = received_unix_ms;
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
        let entries: Vec<_> = self
            .entries
            .values()
            .map(|retained| FlowHistoryEntry {
                key: retained.record.key.clone(),
                source_workloads: Vec::new(),
                destination_workloads: Vec::new(),
                policy_revision: retained.record.policy_revision,
                decision: retained.record.decision,
                shadow: retained.record.shadow,
                observed_events: retained.record.observed_events,
                first_received_unix_ms: retained.first_received_unix_ms,
                last_received_unix_ms: retained.last_received_unix_ms,
                reporting_nodes: retained.reporting_nodes.iter().cloned().collect(),
            })
            .collect();
        FlowHistorySnapshot {
            schema_version: FLOW_EXPORT_SCHEMA_VERSION,
            source_epoch,
            revision: self.revision,
            capacity: self.capacity,
            retained_flows: entries.len(),
            retained_observations: entries
                .iter()
                .map(|entry| entry.observed_events)
                .fold(0_u64, u64::saturating_add),
            evicted_flows: self.evicted_flows,
            evicted_observations: self.evicted_observations,
            agent_dropped_events: self.agent_dropped_events,
            entries,
        }
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyStateSnapshot {
    pub schema_version: u16,
    pub source_epoch: u64,
    pub revision: Revision,
    pub entries: Vec<PolicyMapEntry>,
    pub ipv4_entries: Vec<Ipv4PolicyMapEntry>,
    pub ipv6_entries: Vec<Ipv6PolicyMapEntry>,
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

    #[test]
    fn topology_snapshot_schema_round_trips() {
        let snapshot = TopologyStateSnapshot {
            schema_version: TOPOLOGY_SNAPSHOT_SCHEMA_VERSION,
            source_epoch: 17,
            revision: Revision::new(4),
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
        };
        let encoded = serde_json::to_vec(&snapshot).expect("topology snapshot serializes");
        let decoded: TopologyStateSnapshot =
            serde_json::from_slice(&encoded).expect("topology snapshot deserializes");
        assert_eq!(decoded, snapshot);
    }

    fn flow_record(
        source: u32,
        destination: u32,
        port: u16,
        observations: u64,
    ) -> FlowExportRecord {
        FlowExportRecord {
            key: FlowHistoryKey {
                source_identity: IdentityId::new(source),
                destination_identity: IdentityId::new(destination),
                source_ipv4: None,
                destination_ipv4: None,
                source_ipv6: None,
                destination_ipv6: None,
                protocol: 6,
                destination_port: port,
            },
            policy_revision: Revision::new(7),
            decision: FlowExportDecision {
                verdict: Verdict::Allow,
                reason: 1,
                policy_id: Some(PolicyId::new(9)),
                rule_id: Some(RuleId::new(2)),
            },
            shadow: None,
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
        assert_eq!(snapshot.entries[0].key.destination_port, 8081);
        assert_eq!(snapshot.entries[1].key.destination_port, 8082);
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
