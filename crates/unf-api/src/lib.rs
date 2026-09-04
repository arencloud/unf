//! Kubernetes-facing APIs. Domain policy evaluation lives in `unf-policy`.

use std::collections::BTreeMap;

use k8s_openapi::apimachinery::pkg::apis::meta::v1::LabelSelector;
use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(CustomResource, Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[kube(
    group = "network.unf.io",
    version = "v1alpha1",
    kind = "SecurityPolicy",
    plural = "securitypolicies",
    namespaced,
    status = "SecurityPolicyStatus",
    shortname = "unfsp"
)]
#[serde(rename_all = "camelCase")]
pub struct SecurityPolicySpec {
    pub target: WorkloadSelector,
    #[serde(default)]
    pub ingress: Vec<IngressRule>,
    #[serde(default = "default_priority")]
    pub priority: u32,
    #[serde(default)]
    pub default_action: Action,
    #[serde(default)]
    pub enforcement_mode: EnforcementMode,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SecurityPolicyStatus {
    #[serde(default)]
    pub observed_generation: Option<i64>,
    #[serde(default)]
    pub compiled_revision: Option<u64>,
    #[serde(default)]
    pub conditions: Vec<PolicyCondition>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct PolicyCondition {
    pub condition_type: String,
    pub status: String,
    pub reason: String,
    pub message: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct WorkloadSelector {
    #[serde(default)]
    pub namespace: Option<String>,
    #[serde(default)]
    pub service_account: Option<String>,
    #[serde(default)]
    pub application: Option<String>,
    #[serde(default)]
    pub match_labels: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct IngressRule {
    #[serde(default)]
    pub from: WorkloadSelector,
    #[serde(default)]
    pub protocols: Vec<ProtocolPort>,
    pub action: Action,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ProtocolPort {
    pub protocol: TransportProtocol,
    #[schemars(range(min = 1))]
    pub port: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "PascalCase")]
pub enum TransportProtocol {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "PascalCase")]
pub enum Action {
    Allow,
    #[default]
    Deny,
    Audit,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "PascalCase")]
pub enum EnforcementMode {
    #[default]
    Enforce,
    Shadow,
}

const fn default_priority() -> u32 {
    1_000
}

#[derive(CustomResource, Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[kube(
    group = "network.unf.io",
    version = "v1alpha1",
    kind = "EgressPool",
    plural = "egresspools",
    status = "EgressResourceStatus",
    shortname = "unfep"
)]
#[serde(rename_all = "camelCase")]
pub struct EgressPoolSpec {
    pub provider: EgressProvider,
    pub prefixes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct EgressProvider {
    pub name: String,
    pub instance: String,
}

#[derive(CustomResource, Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[kube(
    group = "network.unf.io",
    version = "v1alpha1",
    kind = "EgressPolicy",
    plural = "egresspolicies",
    status = "EgressResourceStatus",
    shortname = "unfeg"
)]
#[serde(rename_all = "camelCase")]
pub struct EgressPolicySpec {
    pub target: EgressTarget,
    #[serde(default)]
    pub destinations: EgressDestinations,
    pub egress: EgressAddressSelection,
    #[serde(default = "default_priority")]
    pub priority: u32,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct EgressTarget {
    #[serde(default)]
    pub namespace_selector: LabelSelector,
    #[serde(default)]
    pub workload_selector: LabelSelector,
    #[serde(default)]
    pub service_accounts: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct EgressDestinations {
    #[serde(default)]
    pub networks: Vec<String>,
    #[serde(default)]
    pub fqdn: Vec<String>,
    #[serde(default)]
    pub dns: EgressDnsControls,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct EgressDnsControls {
    #[serde(default = "default_egress_dns_view")]
    pub view: String,
    #[serde(default = "default_egress_dns_required_observers")]
    #[schemars(range(min = 1, max = 16))]
    pub required_observers: u16,
    #[serde(default = "default_egress_dns_max_addresses")]
    #[schemars(range(min = 1, max = 4096))]
    pub max_addresses: u16,
    #[serde(default = "default_egress_dns_max_ttl_seconds")]
    #[schemars(range(min = 1, max = 604_800))]
    pub max_ttl_seconds: u32,
    #[serde(default = "default_egress_dns_established_grace_seconds")]
    #[schemars(range(max = 3600))]
    pub established_flow_grace_seconds: u32,
}

impl Default for EgressDnsControls {
    fn default() -> Self {
        Self {
            view: default_egress_dns_view(),
            required_observers: default_egress_dns_required_observers(),
            max_addresses: default_egress_dns_max_addresses(),
            max_ttl_seconds: default_egress_dns_max_ttl_seconds(),
            established_flow_grace_seconds: default_egress_dns_established_grace_seconds(),
        }
    }
}

fn default_egress_dns_view() -> String {
    "cluster-default".to_owned()
}

const fn default_egress_dns_required_observers() -> u16 {
    1
}

const fn default_egress_dns_max_addresses() -> u16 {
    256
}

const fn default_egress_dns_max_ttl_seconds() -> u32 {
    300
}

const fn default_egress_dns_established_grace_seconds() -> u32 {
    30
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct EgressAddressSelection {
    #[serde(default)]
    pub pool: Option<String>,
    #[serde(default)]
    pub explicit_addresses: Vec<String>,
    #[serde(default)]
    pub families: Vec<EgressAddressFamily>,
    #[serde(default = "default_addresses_per_family")]
    #[schemars(range(min = 1))]
    pub addresses_per_family: u16,
    #[serde(default)]
    pub provider: Option<EgressProvider>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum EgressAddressFamily {
    IPv4,
    IPv6,
}

const fn default_addresses_per_family() -> u16 {
    1
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct EgressResourceStatus {
    #[serde(default)]
    pub observed_generation: Option<i64>,
    #[serde(default)]
    pub desired_revision: Option<u64>,
    #[serde(default)]
    pub conditions: Vec<PolicyCondition>,
}

#[cfg(test)]
mod tests {
    use kube::CustomResourceExt;

    use super::*;

    #[test]
    fn generated_crd_contains_structural_schema() {
        let value = serde_json::to_value(SecurityPolicy::crd()).expect("CRD serializes");
        assert_eq!(value["spec"]["group"], "network.unf.io");
        assert!(value["spec"]["versions"][0]["schema"]["openAPIV3Schema"].is_object());
    }

    #[test]
    fn generated_egress_crds_are_cluster_scoped_and_structural() {
        for crd in [EgressPool::crd(), EgressPolicy::crd()] {
            let value = serde_json::to_value(crd).expect("CRD serializes");
            assert_eq!(value["spec"]["group"], "network.unf.io");
            assert_eq!(value["spec"]["scope"], "Cluster");
            assert!(value["spec"]["versions"][0]["schema"]["openAPIV3Schema"].is_object());
        }
    }

    #[test]
    fn checked_in_crd_matches_rust_schema() {
        let checked_in: serde_json::Value = serde_yaml::from_str(include_str!(
            "../../../deploy/crds/network.unf.io_securitypolicies.yaml"
        ))
        .expect("checked-in CRD is valid YAML");
        let generated = serde_json::to_value(SecurityPolicy::crd()).expect("CRD serializes");
        assert_eq!(checked_in, generated, "run `make generate-crds`");
    }

    #[test]
    fn checked_in_egress_crds_match_rust_schema() {
        for (checked_in, generated) in [
            (
                include_str!("../../../deploy/crds/network.unf.io_egresspools.yaml"),
                EgressPool::crd(),
            ),
            (
                include_str!("../../../deploy/crds/network.unf.io_egresspolicies.yaml"),
                EgressPolicy::crd(),
            ),
        ] {
            let checked_in: serde_json::Value =
                serde_yaml::from_str(checked_in).expect("checked-in CRD is valid YAML");
            let generated = serde_json::to_value(generated).expect("CRD serializes");
            assert_eq!(checked_in, generated, "run `make generate-crds`");
        }
    }

    #[test]
    fn egress_policy_defaults_are_safe_and_explicit() {
        let yaml = r"
apiVersion: network.unf.io/v1alpha1
kind: EgressPolicy
metadata:
  name: finance
spec:
  target:
    namespaceSelector:
      matchLabels: {kubernetes.io/metadata.name: finance}
  egress:
    pool: finance-egress
    families: [IPv4, IPv6]
    addressesPerFamily: 2
";
        let policy: EgressPolicy = serde_yaml::from_str(yaml).expect("valid policy");
        assert_eq!(policy.spec.priority, 1_000);
        assert!(policy.spec.destinations.networks.is_empty());
        assert!(policy.spec.destinations.fqdn.is_empty());
        assert_eq!(policy.spec.destinations.dns, EgressDnsControls::default());
    }

    #[test]
    fn defaults_are_safe() {
        let yaml = r"
apiVersion: network.unf.io/v1alpha1
kind: SecurityPolicy
metadata:
  name: deny-by-default
  namespace: backend
spec:
  target:
    application: api
";
        let policy: SecurityPolicy = serde_yaml::from_str(yaml).expect("valid policy");
        assert_eq!(policy.spec.default_action, Action::Deny);
        assert_eq!(policy.spec.enforcement_mode, EnforcementMode::Enforce);
        assert_eq!(policy.spec.priority, 1_000);
    }
}
