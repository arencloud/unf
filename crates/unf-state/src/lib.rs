//! Revisioned control-plane state and stable identity metadata.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use unf_common::{IdentityId, PolicyId, PolicyReason, Revision, RuleId, Verdict};

pub const IDENTITY_SNAPSHOT_SCHEMA_VERSION: u16 = 1;
pub const POLICY_SNAPSHOT_SCHEMA_VERSION: u16 = 2;
pub const TOPOLOGY_SNAPSHOT_SCHEMA_VERSION: u16 = 1;
/// One half of the dual-bank eBPF policy map's 262,144-entry capacity.
pub const POLICY_MAP_BANK_ENTRY_LIMIT: usize = 131_072;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevisionSet {
    pub identity: Revision,
    pub policy: Revision,
    pub service: Revision,
    pub routing: Revision,
    pub topology: Revision,
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
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct TopologyServicePort {
    pub name: Option<String>,
    pub protocol: String,
    pub port: u16,
    pub target_port: Option<String>,
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityStateSnapshot {
    pub schema_version: u16,
    pub source_epoch: u64,
    pub revision: Revision,
    pub entries: Vec<Ipv4IdentityMapping>,
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyStateSnapshot {
    pub schema_version: u16,
    pub source_epoch: u64,
    pub revision: Revision,
    pub entries: Vec<PolicyMapEntry>,
    pub ipv4_entries: Vec<Ipv4PolicyMapEntry>,
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
    pub fn ipv4_snapshot(&self, source_epoch: u64) -> IdentityStateSnapshot {
        let entries = self
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
        IdentityStateSnapshot {
            schema_version: IDENTITY_SNAPSHOT_SCHEMA_VERSION,
            source_epoch,
            revision: self.revision,
            entries,
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
                ],
            )
            .expect("identity is admitted");
        let first = registry.ipv4_snapshot(7);
        assert_eq!(first.schema_version, IDENTITY_SNAPSHOT_SCHEMA_VERSION);
        assert_eq!(first.source_epoch, 7);
        assert_eq!(first.revision, Revision::new(1));
        assert_eq!(first.entries[0].address, Ipv4Addr::new(10, 244, 1, 3));

        registry
            .admit_pod(
                "backend/server-1".to_owned(),
                "local/backend/default/server".to_owned(),
                &server,
                [
                    "10.244.1.4".parse().expect("valid test address"),
                    "10.244.1.3".parse().expect("valid test address"),
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
            }],
        };
        let encoded = serde_json::to_vec(&snapshot).expect("topology snapshot serializes");
        let decoded: TopologyStateSnapshot =
            serde_json::from_slice(&encoded).expect("topology snapshot deserializes");
        assert_eq!(decoded, snapshot);
    }
}
