//! Kubernetes-independent policy IR, compilation, and deterministic evaluation.

mod network_policy;

pub use network_policy::{
    KUBERNETES_NETWORK_POLICY_MAX_IP_BLOCK_ADDRESSES,
    KUBERNETES_NETWORK_POLICY_MAX_IPV6_IP_BLOCK_PREFIXES,
    KUBERNETES_NETWORK_POLICY_MAX_PORT_RANGE_WIDTH, KUBERNETES_NETWORK_POLICY_PRIORITY,
    NetworkPolicyCompileError, NetworkPolicyCompiler,
};

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::net::{Ipv4Addr, Ipv6Addr};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use unf_api::{
    Action, EnforcementMode, SecurityPolicy, TransportProtocol, WorkloadSelector as ApiSelector,
};
use unf_common::{IdentityId, PolicyAction, PolicyId, Protocol, RuleId, Verdict};
use unf_state::{
    Ipv4PolicyMapEntry, Ipv4PolicyMapKey, Ipv6PolicyMapEntry, Ipv6PolicyMapKey,
    POLICY_MAP_BANK_ENTRY_LIMIT, PolicyDecisionRecord, PolicyMapEntry, PolicyMapKey,
};

pub use unf_common::{PolicyDirection, PolicyReason as DecisionReason};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentitySelector {
    pub namespace: Option<String>,
    pub namespace_match_labels: BTreeMap<String, String>,
    pub namespace_match_expressions: Vec<LabelExpression>,
    pub service_account: Option<String>,
    pub application: Option<String>,
    pub match_labels: BTreeMap<String, String>,
    pub match_expressions: Vec<LabelExpression>,
    pub ipv4_blocks: Vec<Ipv4Block>,
    pub ipv6_blocks: Vec<Ipv6Block>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Ipv4Cidr {
    pub network: Ipv4Addr,
    pub prefix_len: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Ipv4Block {
    pub cidr: Ipv4Cidr,
    pub except: Vec<Ipv4Cidr>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Ipv6Cidr {
    pub network: Ipv6Addr,
    pub prefix_len: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Ipv6Block {
    pub cidr: Ipv6Cidr,
    pub except: Vec<Ipv6Cidr>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct LabelExpression {
    pub key: String,
    pub operator: LabelExpressionOperator,
    pub values: BTreeSet<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum LabelExpressionOperator {
    In,
    NotIn,
    Exists,
    DoesNotExist,
}

impl IdentitySelector {
    #[must_use]
    pub fn matches(&self, endpoint: &Endpoint) -> bool {
        self.namespace
            .as_ref()
            .is_none_or(|expected| expected == &endpoint.namespace)
            && self
                .namespace_match_labels
                .iter()
                .all(|(key, value)| endpoint.namespace_labels.get(key) == Some(value))
            && self
                .namespace_match_expressions
                .iter()
                .all(|expression| expression.matches(&endpoint.namespace_labels))
            && self
                .service_account
                .as_ref()
                .is_none_or(|expected| expected == &endpoint.service_account)
            && self
                .application
                .as_ref()
                .is_none_or(|expected| endpoint.application.as_ref() == Some(expected))
            && self
                .match_labels
                .iter()
                .all(|(key, value)| endpoint.labels.get(key) == Some(value))
            && self
                .match_expressions
                .iter()
                .all(|expression| expression.matches(&endpoint.labels))
    }

    fn matches_source(
        &self,
        endpoint: &Endpoint,
        source_ipv4: Option<Ipv4Addr>,
        source_ipv6: Option<Ipv6Addr>,
    ) -> bool {
        let external_source_matches = endpoint.identity.get() != 0
            || !self.ipv4_blocks.is_empty()
            || !self.ipv6_blocks.is_empty()
            || self.is_unconstrained();
        external_source_matches
            && self.matches(endpoint)
            && match (source_ipv4, source_ipv6) {
                (Some(address), None) => {
                    self.ipv6_blocks.is_empty()
                        && (self.ipv4_blocks.is_empty()
                            || self.ipv4_blocks.iter().any(|block| block.contains(address)))
                }
                (None, Some(address)) => {
                    self.ipv4_blocks.is_empty()
                        && (self.ipv6_blocks.is_empty()
                            || self.ipv6_blocks.iter().any(|block| block.contains(address)))
                }
                (None, None) => self.ipv4_blocks.is_empty() && self.ipv6_blocks.is_empty(),
                (Some(_), Some(_)) => false,
            }
    }

    fn is_unconstrained(&self) -> bool {
        self.namespace.is_none()
            && self.namespace_match_labels.is_empty()
            && self.namespace_match_expressions.is_empty()
            && self.service_account.is_none()
            && self.application.is_none()
            && self.match_labels.is_empty()
            && self.match_expressions.is_empty()
    }
}

impl Ipv4Cidr {
    #[must_use]
    pub fn contains(&self, address: Ipv4Addr) -> bool {
        if self.prefix_len > 32 {
            return false;
        }
        let mask = if self.prefix_len == 0 {
            0
        } else {
            u32::MAX << (32 - self.prefix_len)
        };
        u32::from(address) & mask == u32::from(self.network)
    }

    #[must_use]
    pub fn address_count(&self) -> u64 {
        if self.prefix_len > 32 {
            u64::MAX
        } else {
            1_u64 << (32 - self.prefix_len)
        }
    }

    #[must_use]
    pub fn contains_cidr(&self, other: &Self) -> bool {
        self.prefix_len <= other.prefix_len && self.contains(other.network)
    }

    fn addresses(&self) -> impl Iterator<Item = Ipv4Addr> {
        let start = u32::from(self.network);
        let count = u32::try_from(self.address_count()).unwrap_or(u32::MAX);
        (0..count).map(move |offset| Ipv4Addr::from(start + offset))
    }
}

impl Ipv4Block {
    #[must_use]
    pub fn contains(&self, address: Ipv4Addr) -> bool {
        self.cidr.contains(address) && !self.except.iter().any(|except| except.contains(address))
    }

    fn addresses(&self) -> impl Iterator<Item = Ipv4Addr> + '_ {
        self.cidr
            .addresses()
            .filter(|address| self.contains(*address))
    }
}

impl Ipv6Cidr {
    #[must_use]
    pub fn contains(&self, address: Ipv6Addr) -> bool {
        if self.prefix_len > 128 {
            return false;
        }
        let mask = if self.prefix_len == 0 {
            0
        } else {
            u128::MAX << (128 - self.prefix_len)
        };
        u128::from(address) & mask == u128::from(self.network)
    }

    #[must_use]
    pub fn contains_cidr(&self, other: &Self) -> bool {
        self.prefix_len <= other.prefix_len && self.contains(other.network)
    }
}

impl Ipv6Block {
    #[must_use]
    pub fn contains(&self, address: Ipv6Addr) -> bool {
        self.cidr.contains(address) && !self.except.iter().any(|except| except.contains(address))
    }
}

impl LabelExpression {
    fn matches(&self, labels: &BTreeMap<String, String>) -> bool {
        match self.operator {
            LabelExpressionOperator::In => labels
                .get(&self.key)
                .is_some_and(|value| self.values.contains(value)),
            LabelExpressionOperator::NotIn => labels
                .get(&self.key)
                .is_none_or(|value| !self.values.contains(value)),
            LabelExpressionOperator::Exists => labels.contains_key(&self.key),
            LabelExpressionOperator::DoesNotExist => !labels.contains_key(&self.key),
        }
    }
}

impl From<ApiSelector> for IdentitySelector {
    fn from(value: ApiSelector) -> Self {
        Self {
            namespace: value.namespace,
            namespace_match_labels: BTreeMap::new(),
            namespace_match_expressions: Vec::new(),
            service_account: value.service_account,
            application: value.application,
            match_labels: value.match_labels,
            match_expressions: Vec::new(),
            ipv4_blocks: Vec::new(),
            ipv6_blocks: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Endpoint {
    pub identity: IdentityId,
    pub namespace: String,
    pub namespace_labels: BTreeMap<String, String>,
    pub service_account: String,
    pub application: Option<String>,
    pub labels: BTreeMap<String, String>,
    pub named_ports: BTreeMap<NamedPort, u16>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv4Endpoint {
    pub address: Ipv4Addr,
    pub endpoint: Endpoint,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv6Endpoint {
    pub address: Ipv6Addr,
    pub endpoint: Endpoint,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct NamedPort {
    pub name: String,
    pub protocol: Protocol,
}

impl Endpoint {
    fn resolve_named_port(&self, name: &str, protocol: Protocol) -> Option<u16> {
        self.named_ports
            .iter()
            .find(|(named_port, _)| named_port.name == name && named_port.protocol == protocol)
            .map(|(_, port)| *port)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleProvenance {
    pub policy_id: PolicyId,
    pub policy_name: String,
    pub namespace: String,
    pub rule_index: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyRule {
    pub id: RuleId,
    pub source: IdentitySelector,
    pub destination: IdentitySelector,
    pub protocol: Option<Protocol>,
    pub destination_port: DestinationPort,
    pub action: PolicyAction,
    pub provenance: RuleProvenance,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DestinationPort {
    Any,
    Number(u16),
    Named(String),
    Range { start: u16, end: u16 },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyIr {
    pub id: PolicyId,
    pub name: String,
    pub namespace: String,
    pub priority: u32,
    pub origin: PolicyOrigin,
    #[serde(default)]
    pub direction: PolicyDirection,
    pub target: IdentitySelector,
    pub default_action: PolicyAction,
    pub enforcement_mode: PolicyEnforcementMode,
    pub rules: Vec<PolicyRule>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyOrigin {
    Native,
    KubernetesNetworkPolicy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyEnforcementMode {
    Enforce,
    Shadow,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Flow<'a> {
    pub source: &'a Endpoint,
    pub destination: &'a Endpoint,
    pub protocol: Protocol,
    pub destination_port: u16,
    pub source_ipv4: Option<Ipv4Addr>,
    pub source_ipv6: Option<Ipv6Addr>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyDecision {
    #[serde(default, skip_serializing_if = "policy_direction_is_ingress")]
    pub direction: PolicyDirection,
    pub verdict: Verdict,
    pub shadow_verdict: Option<Verdict>,
    pub shadow_reason: Option<DecisionReason>,
    pub shadow_policy_id: Option<PolicyId>,
    pub shadow_rule_id: Option<RuleId>,
    pub reason: DecisionReason,
    pub policy_id: Option<PolicyId>,
    pub rule_id: Option<RuleId>,
    pub audits: Vec<RuleProvenance>,
}

#[expect(
    clippy::trivially_copy_pass_by_ref,
    reason = "serde skip_serializing_if requires a predicate accepting a reference"
)]
fn policy_direction_is_ingress(direction: &PolicyDirection) -> bool {
    *direction == PolicyDirection::Ingress
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PolicyCompileError {
    #[error("SecurityPolicy metadata.name is required")]
    MissingName,
    #[error("SecurityPolicy metadata.namespace is required")]
    MissingNamespace,
    #[error("ingress rule {rule_index} contains invalid port 0")]
    InvalidPort { rule_index: usize },
    #[error("policy contains more rules than can be represented by RuleId")]
    TooManyRules,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum DataplaneCompileError {
    #[error("identity ID {identity_id:?} has conflicting endpoint metadata")]
    IdentityMetadataConflict { identity_id: IdentityId },
    #[error("compiled policy contains more than {limit} entries for one dataplane bank")]
    EntryLimitExceeded { limit: usize },
    #[error("source IPv4 address {address} has conflicting endpoint metadata")]
    Ipv4MetadataConflict { address: Ipv4Addr },
    #[error("IPv4 policy block contains {address_count} addresses, exceeding limit {limit}")]
    Ipv4BlockTooLarge { address_count: u64, limit: u64 },
    #[error("source IPv6 address {address} has conflicting endpoint metadata")]
    Ipv6MetadataConflict { address: Ipv6Addr },
    #[error("{direction:?} policy IR cannot be lowered by the ingress dataplane compiler")]
    UnsupportedPolicyDirection { direction: PolicyDirection },
}

pub struct PolicyCompiler;

impl PolicyCompiler {
    /// Converts an API object to a Kubernetes-independent, provenance-preserving IR.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyCompileError`] when required Kubernetes metadata is absent,
    /// a port is zero, or the rule count cannot fit the dataplane ID width.
    pub fn compile(
        policy_id: PolicyId,
        policy: SecurityPolicy,
    ) -> Result<PolicyIr, PolicyCompileError> {
        let name = policy
            .metadata
            .name
            .ok_or(PolicyCompileError::MissingName)?;
        let namespace = policy
            .metadata
            .namespace
            .ok_or(PolicyCompileError::MissingNamespace)?;
        let spec = policy.spec;
        let mut target: IdentitySelector = spec.target.into();
        // A namespaced policy defaults its target to its own namespace.
        target.namespace.get_or_insert_with(|| namespace.clone());

        let mut rules = Vec::new();
        for (source_index, rule) in spec.ingress.into_iter().enumerate() {
            if rule.protocols.iter().any(|item| item.port == 0) {
                return Err(PolicyCompileError::InvalidPort {
                    rule_index: source_index,
                });
            }

            let source: IdentitySelector = rule.from.into();
            let action = convert_action(rule.action);
            if rule.protocols.is_empty() {
                push_rule(
                    &mut rules,
                    policy_id,
                    &name,
                    &namespace,
                    source,
                    target.clone(),
                    None,
                    DestinationPort::Any,
                    action,
                    source_index,
                )?;
            } else {
                for protocol_port in rule.protocols {
                    let protocol = match protocol_port.protocol {
                        TransportProtocol::Tcp => Protocol::Tcp,
                        TransportProtocol::Udp => Protocol::Udp,
                    };
                    push_rule(
                        &mut rules,
                        policy_id,
                        &name,
                        &namespace,
                        source.clone(),
                        target.clone(),
                        Some(protocol),
                        DestinationPort::Number(protocol_port.port),
                        action,
                        source_index,
                    )?;
                }
            }
        }

        Ok(PolicyIr {
            id: policy_id,
            name,
            namespace,
            priority: spec.priority,
            origin: PolicyOrigin::Native,
            direction: PolicyDirection::Ingress,
            target,
            default_action: convert_action(spec.default_action),
            enforcement_mode: match spec.enforcement_mode {
                EnforcementMode::Enforce => PolicyEnforcementMode::Enforce,
                EnforcementMode::Shadow => PolicyEnforcementMode::Shadow,
            },
            rules,
        })
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn push_rule(
    rules: &mut Vec<PolicyRule>,
    policy_id: PolicyId,
    policy_name: &str,
    namespace: &str,
    source: IdentitySelector,
    destination: IdentitySelector,
    protocol: Option<Protocol>,
    destination_port: DestinationPort,
    action: PolicyAction,
    source_index: usize,
) -> Result<(), PolicyCompileError> {
    let id = u32::try_from(rules.len())
        .map(RuleId::new)
        .map_err(|_| PolicyCompileError::TooManyRules)?;
    let rule_index = u32::try_from(source_index).map_err(|_| PolicyCompileError::TooManyRules)?;
    rules.push(PolicyRule {
        id,
        source,
        destination,
        protocol,
        destination_port,
        action,
        provenance: RuleProvenance {
            policy_id,
            policy_name: policy_name.to_owned(),
            namespace: namespace.to_owned(),
            rule_index,
        },
    });
    Ok(())
}

const fn convert_action(action: Action) -> PolicyAction {
    match action {
        Action::Allow => PolicyAction::Allow,
        Action::Deny => PolicyAction::Deny,
        Action::Audit => PolicyAction::Audit,
    }
}

/// Evaluates ingress policy without depending on insertion or controller watch order.
///
/// This compatibility wrapper preserves the original ingress-only API. New
/// direction-aware callers should use [`evaluate_for_direction`].
#[must_use]
pub fn evaluate(policies: &[PolicyIr], flow: Flow<'_>) -> PolicyDecision {
    evaluate_for_direction(policies, PolicyDirection::Ingress, flow)
}

/// Evaluates policy for one explicit isolation direction.
///
/// Ingress policies select the destination workload. Egress policies select the
/// source workload. Policies in the opposite direction never affect the result.
#[must_use]
pub fn evaluate_for_direction(
    policies: &[PolicyIr],
    direction: PolicyDirection,
    flow: Flow<'_>,
) -> PolicyDecision {
    let selected_endpoint = match direction {
        PolicyDirection::Ingress => flow.destination,
        PolicyDirection::Egress => flow.source,
    };
    let applicable: Vec<&PolicyIr> = policies
        .iter()
        .filter(|policy| policy.direction == direction && policy.target.matches(selected_endpoint))
        .collect();

    let mut audits = matching_audits(&applicable, flow);
    audits.sort_by(|left, right| {
        left.policy_id
            .cmp(&right.policy_id)
            .then(left.rule_index.cmp(&right.rule_index))
    });

    let enforced = decide_for_mode(&applicable, flow, PolicyEnforcementMode::Enforce);
    let shadow = decide_for_mode(&applicable, flow, PolicyEnforcementMode::Shadow);

    let (verdict, reason, policy_id, rule_id) = enforced.unwrap_or((
        Verdict::Allow,
        DecisionReason::NoApplicablePolicy,
        None,
        None,
    ));
    let (shadow_verdict, shadow_reason, shadow_policy_id, shadow_rule_id) = shadow.map_or(
        (None, None, None, None),
        |(verdict, reason, policy_id, rule_id)| (Some(verdict), Some(reason), policy_id, rule_id),
    );

    PolicyDecision {
        direction,
        verdict,
        shadow_verdict,
        shadow_reason,
        shadow_policy_id,
        shadow_rule_id,
        reason,
        policy_id,
        rule_id,
        audits,
    }
}

/// Resolves selector-based policy IR into deterministic identity-tuple entries.
///
/// Port and protocol zero together represent the global fallback evaluated
/// without protocol-specific rules. A concrete protocol with port zero is a
/// protocol-specific wildcard. The eBPF fast path can therefore resolve exact,
/// protocol-wide, then global decisions without interpreting selectors or
/// policy priority.
///
/// # Errors
///
/// Returns [`DataplaneCompileError::IdentityMetadataConflict`] if one numeric
/// identity is associated with different endpoint metadata.
pub fn compile_dataplane_entries(
    policies: &[PolicyIr],
    endpoints: &[Endpoint],
) -> Result<Vec<PolicyMapEntry>, DataplaneCompileError> {
    ensure_ingress_dataplane_policies(policies)?;
    let global_policies = global_fallback_policies(policies);
    let mut unique_endpoints = BTreeMap::<IdentityId, &Endpoint>::new();
    for endpoint in endpoints {
        if let Some(existing) = unique_endpoints.insert(endpoint.identity, endpoint)
            && existing != endpoint
        {
            return Err(DataplaneCompileError::IdentityMetadataConflict {
                identity_id: endpoint.identity,
            });
        }
    }

    let mut entries = Vec::new();
    for source in unique_endpoints.values() {
        for destination in unique_endpoints.values() {
            let global_fallback = evaluate(
                &global_policies,
                Flow {
                    source,
                    destination,
                    protocol: Protocol::Tcp,
                    destination_port: 0,
                    source_ipv4: None,
                    source_ipv6: None,
                },
            );
            let global_entry = policy_map_entry(source, destination, 0, 0, &global_fallback);
            if has_policy_provenance(&global_fallback) {
                push_dataplane_entry(&mut entries, global_entry)?;
            }

            let wildcard_protocols: BTreeSet<_> = policies
                .iter()
                .filter(|policy| policy.target.matches(destination))
                .flat_map(|policy| &policy.rules)
                .filter(|rule| {
                    rule.source.matches_source(source, None, None)
                        && rule.destination.matches(destination)
                        && rule.destination_port == DestinationPort::Any
                })
                .filter_map(|rule| rule.protocol)
                .collect();
            let mut protocol_entries = BTreeMap::new();
            for protocol in wildcard_protocols {
                let decision = evaluate(
                    policies,
                    Flow {
                        source,
                        destination,
                        protocol,
                        destination_port: 0,
                        source_ipv4: None,
                        source_ipv6: None,
                    },
                );
                let entry = policy_map_entry(source, destination, protocol as u8, 0, &decision);
                if has_policy_provenance(&decision)
                    && (entry.decision != global_entry.decision
                        || entry.shadow != global_entry.shadow)
                {
                    push_dataplane_entry(&mut entries, entry)?;
                }
                protocol_entries.insert(protocol, entry);
            }

            let exact_tuples: BTreeSet<_> = policies
                .iter()
                .filter(|policy| policy.target.matches(destination))
                .flat_map(|policy| &policy.rules)
                .filter(|rule| {
                    rule.source.matches_source(source, None, None)
                        && rule.destination.matches(destination)
                })
                .flat_map(|rule| exact_rule_ports(rule, destination))
                .collect();
            for (protocol, port) in exact_tuples {
                let decision = evaluate(
                    policies,
                    Flow {
                        source,
                        destination,
                        protocol,
                        destination_port: port,
                        source_ipv4: None,
                        source_ipv6: None,
                    },
                );
                let entry = policy_map_entry(source, destination, protocol as u8, port, &decision);
                let inherited = protocol_entries.get(&protocol).unwrap_or(&global_entry);
                if has_policy_provenance(&decision)
                    && (entry.decision != inherited.decision || entry.shadow != inherited.shadow)
                {
                    push_dataplane_entry(&mut entries, entry)?;
                }
            }
        }
    }
    entries.sort_by_key(|entry| entry.key);
    Ok(entries)
}

/// Resolves IPv4-aware source rules into a second exact-source policy map.
///
/// Known Pod addresses retain their workload metadata. Addresses referenced only
/// by an `ipBlock` use an external endpoint with identity zero, while source
/// address zero is reserved as the arbitrary-external-source fallback.
///
/// # Errors
///
/// Returns an error for conflicting endpoint metadata or when exact-source
/// expansion exceeds one dataplane bank.
pub fn compile_ipv4_dataplane_entries(
    policies: &[PolicyIr],
    endpoints: &[Endpoint],
    ipv4_endpoints: &[Ipv4Endpoint],
) -> Result<Vec<Ipv4PolicyMapEntry>, DataplaneCompileError> {
    ensure_ingress_dataplane_policies(policies)?;
    let global_policies = global_fallback_policies(policies);
    let mut destinations = BTreeMap::<IdentityId, &Endpoint>::new();
    for endpoint in endpoints {
        if let Some(existing) = destinations.insert(endpoint.identity, endpoint)
            && existing != endpoint
        {
            return Err(DataplaneCompileError::IdentityMetadataConflict {
                identity_id: endpoint.identity,
            });
        }
    }

    let mut known_sources = BTreeMap::<Ipv4Addr, &Endpoint>::new();
    for source in ipv4_endpoints {
        if let Some(existing) = known_sources.insert(source.address, &source.endpoint)
            && existing != &source.endpoint
        {
            return Err(DataplaneCompileError::Ipv4MetadataConflict {
                address: source.address,
            });
        }
    }

    let ipv4_blocks: Vec<_> = policies
        .iter()
        .flat_map(|policy| &policy.rules)
        .flat_map(|rule| &rule.source.ipv4_blocks)
        .collect();
    for block in &ipv4_blocks {
        let address_count = block.cidr.address_count();
        if address_count > KUBERNETES_NETWORK_POLICY_MAX_IP_BLOCK_ADDRESSES {
            return Err(DataplaneCompileError::Ipv4BlockTooLarge {
                address_count,
                limit: KUBERNETES_NETWORK_POLICY_MAX_IP_BLOCK_ADDRESSES,
            });
        }
    }

    let mut source_addresses: BTreeSet<_> = known_sources.keys().copied().collect();
    for address in ipv4_blocks.into_iter().flat_map(Ipv4Block::addresses) {
        if address != Ipv4Addr::UNSPECIFIED
            && source_addresses.insert(address)
            && source_addresses.len() > POLICY_MAP_BANK_ENTRY_LIMIT
        {
            return Err(DataplaneCompileError::EntryLimitExceeded {
                limit: POLICY_MAP_BANK_ENTRY_LIMIT,
            });
        }
    }

    let external = external_endpoint();
    let mut entries = Vec::new();
    for address in source_addresses {
        let source = known_sources.get(&address).copied().unwrap_or(&external);
        for destination in destinations.values() {
            compile_ipv4_pair(
                policies,
                &global_policies,
                source,
                Some(address),
                address,
                destination,
                &mut entries,
            )?;
        }
    }

    for destination in destinations.values().filter(|destination| {
        policies.iter().any(|policy| {
            policy.origin == PolicyOrigin::KubernetesNetworkPolicy
                && policy.target.matches(destination)
        })
    }) {
        compile_ipv4_pair(
            policies,
            &global_policies,
            &external,
            None,
            Ipv4Addr::UNSPECIFIED,
            destination,
            &mut entries,
        )?;
    }

    entries.sort_by_key(|entry| entry.key);
    Ok(entries)
}

/// Resolves IPv6-aware source rules into bounded longest-prefix-match entries.
///
/// Policy boundaries, exceptions, and known Pod addresses are represented as
/// prefixes. A representative address outside all child boundaries determines
/// the decision inherited by the remainder of each prefix.
///
/// # Errors
///
/// Returns an error for conflicting endpoint metadata or when the bounded
/// prefix decisions exceed one dataplane bank.
pub fn compile_ipv6_dataplane_entries(
    policies: &[PolicyIr],
    endpoints: &[Endpoint],
    ipv6_endpoints: &[Ipv6Endpoint],
) -> Result<Vec<Ipv6PolicyMapEntry>, DataplaneCompileError> {
    ensure_ingress_dataplane_policies(policies)?;
    let global_policies = global_fallback_policies(policies);
    let mut destinations = BTreeMap::<IdentityId, &Endpoint>::new();
    for endpoint in endpoints {
        if let Some(existing) = destinations.insert(endpoint.identity, endpoint)
            && existing != endpoint
        {
            return Err(DataplaneCompileError::IdentityMetadataConflict {
                identity_id: endpoint.identity,
            });
        }
    }

    let mut known_sources = BTreeMap::<Ipv6Addr, &Endpoint>::new();
    for source in ipv6_endpoints {
        if let Some(existing) = known_sources.insert(source.address, &source.endpoint)
            && existing != &source.endpoint
        {
            return Err(DataplaneCompileError::Ipv6MetadataConflict {
                address: source.address,
            });
        }
    }

    let mut boundaries = BTreeSet::from([Ipv6Cidr {
        network: Ipv6Addr::UNSPECIFIED,
        prefix_len: 0,
    }]);
    for block in policies
        .iter()
        .flat_map(|policy| &policy.rules)
        .flat_map(|rule| &rule.source.ipv6_blocks)
    {
        boundaries.insert(block.cidr.clone());
        boundaries.extend(block.except.iter().cloned());
    }
    boundaries.extend(known_sources.keys().copied().map(|network| Ipv6Cidr {
        network,
        prefix_len: 128,
    }));
    if boundaries.len() > POLICY_MAP_BANK_ENTRY_LIMIT {
        return Err(DataplaneCompileError::EntryLimitExceeded {
            limit: POLICY_MAP_BANK_ENTRY_LIMIT,
        });
    }
    let boundaries: Vec<_> = boundaries.into_iter().collect();
    let external = external_endpoint();
    let mut entries = Vec::new();
    for destination in destinations.values() {
        for boundary in &boundaries {
            let excluded: Vec<_> = boundaries
                .iter()
                .filter(|candidate| {
                    candidate.prefix_len > boundary.prefix_len && boundary.contains_cidr(candidate)
                })
                .collect();
            let Some(address) = uncovered_ipv6_address(boundary, &excluded) else {
                continue;
            };
            let source = known_sources.get(&address).copied().unwrap_or(&external);
            compile_ipv6_pair(
                policies,
                &global_policies,
                source,
                address,
                boundary,
                destination,
                &mut entries,
            )?;
        }
    }
    entries.sort_by_key(|entry| entry.key);
    Ok(entries)
}

fn uncovered_ipv6_address(cidr: &Ipv6Cidr, excluded: &[&Ipv6Cidr]) -> Option<Ipv6Addr> {
    if excluded.contains(&cidr) {
        return None;
    }
    if excluded.iter().all(|item| !item.contains(cidr.network)) {
        return Some(cidr.network);
    }
    if cidr.prefix_len == 128 {
        return None;
    }
    let child_prefix = cidr.prefix_len + 1;
    let step = 1_u128 << (128 - child_prefix);
    for network in [u128::from(cidr.network), u128::from(cidr.network) + step] {
        let child = Ipv6Cidr {
            network: Ipv6Addr::from(network),
            prefix_len: child_prefix,
        };
        let child_excluded: Vec<_> = excluded
            .iter()
            .copied()
            .filter(|item| child.contains_cidr(item))
            .collect();
        if child_excluded.is_empty() {
            return Some(child.network);
        }
        if let Some(address) = uncovered_ipv6_address(&child, &child_excluded) {
            return Some(address);
        }
    }
    None
}

#[allow(clippy::too_many_arguments)]
fn compile_ipv6_pair(
    policies: &[PolicyIr],
    global_policies: &[PolicyIr],
    source: &Endpoint,
    source_address: Ipv6Addr,
    source_cidr: &Ipv6Cidr,
    destination: &Endpoint,
    entries: &mut Vec<Ipv6PolicyMapEntry>,
) -> Result<(), DataplaneCompileError> {
    let global_fallback = evaluate(
        global_policies,
        Flow {
            source,
            destination,
            protocol: Protocol::Tcp,
            destination_port: 0,
            source_ipv4: None,
            source_ipv6: Some(source_address),
        },
    );
    let global_entry = ipv6_policy_map_entry(source_cidr, destination, 0, 0, &global_fallback);
    if has_policy_provenance(&global_fallback) {
        push_ipv6_dataplane_entry(entries, global_entry)?;
    }

    let wildcard_protocols: BTreeSet<_> = policies
        .iter()
        .filter(|policy| policy.target.matches(destination))
        .flat_map(|policy| &policy.rules)
        .filter(|rule| {
            rule.destination.matches(destination) && rule.destination_port == DestinationPort::Any
        })
        .filter_map(|rule| rule.protocol)
        .collect();
    for protocol in wildcard_protocols {
        let decision = evaluate(
            policies,
            Flow {
                source,
                destination,
                protocol,
                destination_port: 0,
                source_ipv4: None,
                source_ipv6: Some(source_address),
            },
        );
        let entry = ipv6_policy_map_entry(source_cidr, destination, protocol as u8, 0, &decision);
        if has_policy_provenance(&decision) {
            push_ipv6_dataplane_entry(entries, entry)?;
        }
    }

    let exact_tuples: BTreeSet<_> = policies
        .iter()
        .filter(|policy| policy.target.matches(destination))
        .flat_map(|policy| &policy.rules)
        .filter(|rule| rule.destination.matches(destination))
        .flat_map(|rule| exact_rule_ports(rule, destination))
        .collect();
    for (protocol, port) in exact_tuples {
        let decision = evaluate(
            policies,
            Flow {
                source,
                destination,
                protocol,
                destination_port: port,
                source_ipv4: None,
                source_ipv6: Some(source_address),
            },
        );
        let entry =
            ipv6_policy_map_entry(source_cidr, destination, protocol as u8, port, &decision);
        if has_policy_provenance(&decision) {
            push_ipv6_dataplane_entry(entries, entry)?;
        }
    }
    Ok(())
}

fn compile_ipv4_pair(
    policies: &[PolicyIr],
    global_policies: &[PolicyIr],
    source: &Endpoint,
    source_ipv4: Option<Ipv4Addr>,
    source_address: Ipv4Addr,
    destination: &Endpoint,
    entries: &mut Vec<Ipv4PolicyMapEntry>,
) -> Result<(), DataplaneCompileError> {
    let global_fallback = evaluate(
        global_policies,
        Flow {
            source,
            destination,
            protocol: Protocol::Tcp,
            destination_port: 0,
            source_ipv4,
            source_ipv6: None,
        },
    );
    let global_entry = ipv4_policy_map_entry(source_address, destination, 0, 0, &global_fallback);
    if has_policy_provenance(&global_fallback) {
        push_ipv4_dataplane_entry(entries, global_entry)?;
    }

    let wildcard_protocols: BTreeSet<_> = policies
        .iter()
        .filter(|policy| policy.target.matches(destination))
        .flat_map(|policy| &policy.rules)
        .filter(|rule| {
            rule.source.matches_source(source, source_ipv4, None)
                && rule.destination.matches(destination)
                && rule.destination_port == DestinationPort::Any
        })
        .filter_map(|rule| rule.protocol)
        .collect();
    let mut protocol_entries = BTreeMap::new();
    for protocol in wildcard_protocols {
        let decision = evaluate(
            policies,
            Flow {
                source,
                destination,
                protocol,
                destination_port: 0,
                source_ipv4,
                source_ipv6: None,
            },
        );
        let entry =
            ipv4_policy_map_entry(source_address, destination, protocol as u8, 0, &decision);
        if has_policy_provenance(&decision)
            && (entry.decision != global_entry.decision || entry.shadow != global_entry.shadow)
        {
            push_ipv4_dataplane_entry(entries, entry)?;
        }
        protocol_entries.insert(protocol, entry);
    }

    let exact_tuples: BTreeSet<_> = policies
        .iter()
        .filter(|policy| policy.target.matches(destination))
        .flat_map(|policy| &policy.rules)
        .filter(|rule| {
            rule.source.matches_source(source, source_ipv4, None)
                && rule.destination.matches(destination)
        })
        .flat_map(|rule| exact_rule_ports(rule, destination))
        .collect();
    for (protocol, port) in exact_tuples {
        let decision = evaluate(
            policies,
            Flow {
                source,
                destination,
                protocol,
                destination_port: port,
                source_ipv4,
                source_ipv6: None,
            },
        );
        let entry =
            ipv4_policy_map_entry(source_address, destination, protocol as u8, port, &decision);
        let inherited = protocol_entries.get(&protocol).unwrap_or(&global_entry);
        if has_policy_provenance(&decision)
            && (entry.decision != inherited.decision || entry.shadow != inherited.shadow)
        {
            push_ipv4_dataplane_entry(entries, entry)?;
        }
    }
    Ok(())
}

fn global_fallback_policies(policies: &[PolicyIr]) -> Vec<PolicyIr> {
    policies
        .iter()
        .cloned()
        .map(|mut policy| {
            policy.rules.retain(|rule| rule.protocol.is_none());
            policy
        })
        .collect()
}

fn ensure_ingress_dataplane_policies(policies: &[PolicyIr]) -> Result<(), DataplaneCompileError> {
    if let Some(policy) = policies
        .iter()
        .find(|policy| policy.direction != PolicyDirection::Ingress)
    {
        return Err(DataplaneCompileError::UnsupportedPolicyDirection {
            direction: policy.direction,
        });
    }
    Ok(())
}

fn external_endpoint() -> Endpoint {
    Endpoint {
        identity: IdentityId::new(0),
        namespace: String::new(),
        namespace_labels: BTreeMap::new(),
        service_account: String::new(),
        application: None,
        labels: BTreeMap::new(),
        named_ports: BTreeMap::new(),
    }
}

fn exact_rule_ports(rule: &PolicyRule, destination: &Endpoint) -> Vec<(Protocol, u16)> {
    let Some(protocol) = rule.protocol else {
        return Vec::new();
    };
    match &rule.destination_port {
        DestinationPort::Any => Vec::new(),
        DestinationPort::Number(port) => vec![(protocol, *port)],
        DestinationPort::Named(name) => destination
            .resolve_named_port(name, protocol)
            .map_or_else(Vec::new, |port| vec![(protocol, port)]),
        DestinationPort::Range { start, end } => {
            (*start..=*end).map(|port| (protocol, port)).collect()
        }
    }
}

fn push_dataplane_entry(
    entries: &mut Vec<PolicyMapEntry>,
    entry: PolicyMapEntry,
) -> Result<(), DataplaneCompileError> {
    ensure_dataplane_capacity(entries.len())?;
    entries.push(entry);
    Ok(())
}

fn push_ipv4_dataplane_entry(
    entries: &mut Vec<Ipv4PolicyMapEntry>,
    entry: Ipv4PolicyMapEntry,
) -> Result<(), DataplaneCompileError> {
    ensure_dataplane_capacity(entries.len())?;
    entries.push(entry);
    Ok(())
}

fn push_ipv6_dataplane_entry(
    entries: &mut Vec<Ipv6PolicyMapEntry>,
    entry: Ipv6PolicyMapEntry,
) -> Result<(), DataplaneCompileError> {
    ensure_dataplane_capacity(entries.len())?;
    entries.push(entry);
    Ok(())
}

fn ensure_dataplane_capacity(entry_count: usize) -> Result<(), DataplaneCompileError> {
    if entry_count >= POLICY_MAP_BANK_ENTRY_LIMIT {
        return Err(DataplaneCompileError::EntryLimitExceeded {
            limit: POLICY_MAP_BANK_ENTRY_LIMIT,
        });
    }
    Ok(())
}

fn has_policy_provenance(decision: &PolicyDecision) -> bool {
    decision.policy_id.is_some() || decision.shadow_policy_id.is_some()
}

fn policy_map_entry(
    source: &Endpoint,
    destination: &Endpoint,
    protocol: u8,
    destination_port: u16,
    decision: &PolicyDecision,
) -> PolicyMapEntry {
    PolicyMapEntry {
        key: PolicyMapKey {
            source_identity: source.identity,
            destination_identity: destination.identity,
            protocol,
            destination_port,
        },
        decision: PolicyDecisionRecord {
            verdict: decision.verdict,
            reason: decision.reason,
            policy_id: decision.policy_id,
            rule_id: decision.rule_id,
        },
        shadow: decision
            .shadow_verdict
            .zip(decision.shadow_reason)
            .map(|(verdict, reason)| PolicyDecisionRecord {
                verdict,
                reason,
                policy_id: decision.shadow_policy_id,
                rule_id: decision.shadow_rule_id,
            }),
    }
}

fn ipv4_policy_map_entry(
    source_address: Ipv4Addr,
    destination: &Endpoint,
    protocol: u8,
    destination_port: u16,
    decision: &PolicyDecision,
) -> Ipv4PolicyMapEntry {
    Ipv4PolicyMapEntry {
        key: Ipv4PolicyMapKey {
            source_address,
            destination_identity: destination.identity,
            protocol,
            destination_port,
        },
        decision: PolicyDecisionRecord {
            verdict: decision.verdict,
            reason: decision.reason,
            policy_id: decision.policy_id,
            rule_id: decision.rule_id,
        },
        shadow: decision
            .shadow_verdict
            .zip(decision.shadow_reason)
            .map(|(verdict, reason)| PolicyDecisionRecord {
                verdict,
                reason,
                policy_id: decision.shadow_policy_id,
                rule_id: decision.shadow_rule_id,
            }),
    }
}

fn ipv6_policy_map_entry(
    source: &Ipv6Cidr,
    destination: &Endpoint,
    protocol: u8,
    destination_port: u16,
    decision: &PolicyDecision,
) -> Ipv6PolicyMapEntry {
    Ipv6PolicyMapEntry {
        key: Ipv6PolicyMapKey {
            source_network: source.network,
            source_prefix_len: source.prefix_len,
            destination_identity: destination.identity,
            protocol,
            destination_port,
        },
        decision: PolicyDecisionRecord {
            verdict: decision.verdict,
            reason: decision.reason,
            policy_id: decision.policy_id,
            rule_id: decision.rule_id,
        },
        shadow: decision
            .shadow_verdict
            .zip(decision.shadow_reason)
            .map(|(verdict, reason)| PolicyDecisionRecord {
                verdict,
                reason,
                policy_id: decision.shadow_policy_id,
                rule_id: decision.shadow_rule_id,
            }),
    }
}

type RankedDecision = (u32, PolicyAction, PolicyId, Option<RuleId>, DecisionReason);

fn decide_for_mode(
    policies: &[&PolicyIr],
    flow: Flow<'_>,
    mode: PolicyEnforcementMode,
) -> Option<(Verdict, DecisionReason, Option<PolicyId>, Option<RuleId>)> {
    let mut candidates = Vec::new();
    let policies_for_mode: Vec<_> = policies
        .iter()
        .copied()
        .filter(|policy| policy.enforcement_mode == mode)
        .collect();
    for policy in policies_for_mode
        .iter()
        .copied()
        .filter(|policy| policy.origin == PolicyOrigin::Native)
    {
        let matched = policy.rules.iter().filter(|rule| rule_matches(rule, flow));
        let mut enforcing_rules = matched
            .filter(|rule| rule.action != PolicyAction::Audit)
            .peekable();
        if enforcing_rules.peek().is_some() {
            candidates.extend(enforcing_rules.map(|rule| {
                (
                    policy.priority,
                    rule.action,
                    policy.id,
                    Some(rule.id),
                    DecisionReason::ExplicitRule,
                )
            }));
        } else if policy.default_action != PolicyAction::Audit {
            candidates.push((
                policy.priority,
                policy.default_action,
                policy.id,
                None,
                DecisionReason::DefaultAction,
            ));
        }
    }

    let compatibility_policies: Vec<_> = policies_for_mode
        .iter()
        .copied()
        .filter(|policy| policy.origin == PolicyOrigin::KubernetesNetworkPolicy)
        .collect();
    let compatibility_rules: Vec<_> = compatibility_policies
        .iter()
        .flat_map(|policy| &policy.rules)
        .filter(|rule| rule_matches(rule, flow))
        .collect();
    if compatibility_rules.is_empty() {
        let mut defaults: Vec<_> = compatibility_policies
            .iter()
            .filter(|policy| policy.default_action != PolicyAction::Audit)
            .map(|policy| {
                (
                    policy.priority,
                    policy.default_action,
                    policy.id,
                    None,
                    DecisionReason::DefaultAction,
                )
            })
            .collect();
        defaults.sort_by(compare_decisions);
        if let Some(default) = defaults.first() {
            candidates.push(*default);
        }
    } else {
        candidates.extend(compatibility_rules.into_iter().map(|rule| {
            (
                KUBERNETES_NETWORK_POLICY_PRIORITY,
                rule.action,
                rule.provenance.policy_id,
                Some(rule.id),
                DecisionReason::ExplicitRule,
            )
        }));
    }

    candidates.sort_by(compare_decisions);
    candidates.first().map(|candidate| {
        (
            action_verdict(candidate.1),
            candidate.4,
            Some(candidate.2),
            candidate.3,
        )
    })
}

fn compare_decisions(left: &RankedDecision, right: &RankedDecision) -> Ordering {
    left.0
        .cmp(&right.0)
        .then(action_rank(left.1).cmp(&action_rank(right.1)))
        .then(left.2.cmp(&right.2))
        .then(left.3.cmp(&right.3))
}

const fn action_rank(action: PolicyAction) -> u8 {
    match action {
        PolicyAction::Deny => 0,
        PolicyAction::Allow => 1,
        PolicyAction::Audit => 2,
    }
}

const fn action_verdict(action: PolicyAction) -> Verdict {
    match action {
        PolicyAction::Allow => Verdict::Allow,
        PolicyAction::Deny => Verdict::Deny,
        PolicyAction::Audit => Verdict::Audit,
    }
}

fn matching_audits(policies: &[&PolicyIr], flow: Flow<'_>) -> Vec<RuleProvenance> {
    policies
        .iter()
        .flat_map(|policy| &policy.rules)
        .filter(|rule| rule.action == PolicyAction::Audit && rule_matches(rule, flow))
        .map(|rule| rule.provenance.clone())
        .collect()
}

fn rule_matches(rule: &PolicyRule, flow: Flow<'_>) -> bool {
    rule.source
        .matches_source(flow.source, flow.source_ipv4, flow.source_ipv6)
        && rule.destination.matches(flow.destination)
        && rule.protocol.is_none_or(|value| value == flow.protocol)
        && match &rule.destination_port {
            DestinationPort::Any => true,
            DestinationPort::Number(port) => *port == flow.destination_port,
            DestinationPort::Named(name) => flow
                .destination
                .resolve_named_port(name, flow.protocol)
                .is_some_and(|port| port == flow.destination_port),
            DestinationPort::Range { start, end } => {
                (*start..=*end).contains(&flow.destination_port)
            }
        }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use unf_api::{IngressRule, ProtocolPort, SecurityPolicySpec, WorkloadSelector};
    use unf_common::PolicyId;

    use super::*;

    fn endpoint_with_id(id: u32, namespace: &str, application: &str) -> Endpoint {
        Endpoint {
            identity: IdentityId::new(id),
            namespace: namespace.to_owned(),
            namespace_labels: BTreeMap::new(),
            service_account: "default".to_owned(),
            application: Some(application.to_owned()),
            labels: BTreeMap::new(),
            named_ports: BTreeMap::new(),
        }
    }

    fn endpoint(namespace: &str, application: &str) -> Endpoint {
        endpoint_with_id(1, namespace, application)
    }

    fn policy(
        id: u32,
        priority: u32,
        action: Action,
        default_action: Action,
        mode: EnforcementMode,
        port: Option<u16>,
    ) -> PolicyIr {
        let protocols = port.map_or_else(Vec::new, |port| {
            vec![ProtocolPort {
                protocol: TransportProtocol::Tcp,
                port,
            }]
        });
        let name = format!("policy-{id}");
        let api = SecurityPolicy::new(
            &name,
            SecurityPolicySpec {
                target: WorkloadSelector {
                    application: Some("server".to_owned()),
                    ..WorkloadSelector::default()
                },
                ingress: vec![IngressRule {
                    from: WorkloadSelector {
                        namespace: Some("frontend".to_owned()),
                        ..WorkloadSelector::default()
                    },
                    protocols,
                    action,
                }],
                priority,
                default_action,
                enforcement_mode: mode,
            },
        );
        let mut api = api;
        api.metadata.namespace = Some("backend".to_owned());
        PolicyCompiler::compile(PolicyId::new(id), api).expect("policy compiles")
    }

    fn test_flow<'a>(source: &'a Endpoint, destination: &'a Endpoint, port: u16) -> Flow<'a> {
        Flow {
            source,
            destination,
            protocol: Protocol::Tcp,
            destination_port: port,
            source_ipv4: None,
            source_ipv6: None,
        }
    }

    fn egress_policy() -> PolicyIr {
        let target = IdentitySelector {
            namespace: Some("frontend".to_owned()),
            application: Some("client".to_owned()),
            ..IdentitySelector::default()
        };
        PolicyIr {
            id: PolicyId::new(2),
            name: "allow-client-to-server".to_owned(),
            namespace: "frontend".to_owned(),
            priority: 100,
            origin: PolicyOrigin::Native,
            direction: PolicyDirection::Egress,
            target: target.clone(),
            default_action: PolicyAction::Deny,
            enforcement_mode: PolicyEnforcementMode::Enforce,
            rules: vec![PolicyRule {
                id: RuleId::new(0),
                source: target,
                destination: IdentitySelector {
                    namespace: Some("backend".to_owned()),
                    application: Some("server".to_owned()),
                    ..IdentitySelector::default()
                },
                protocol: Some(Protocol::Tcp),
                destination_port: DestinationPort::Number(8080),
                action: PolicyAction::Allow,
                provenance: RuleProvenance {
                    policy_id: PolicyId::new(2),
                    policy_name: "allow-client-to-server".to_owned(),
                    namespace: "frontend".to_owned(),
                    rule_index: 0,
                },
            }],
        }
    }

    #[test]
    fn evaluation_is_direction_aware_and_isolated() {
        let source = endpoint("frontend", "client");
        let destination = endpoint("backend", "server");
        let alternate_destination = endpoint("backend", "database");
        let alternate_source = endpoint("operations", "job");
        let ingress = policy(
            1,
            100,
            Action::Allow,
            Action::Deny,
            EnforcementMode::Enforce,
            Some(8080),
        );
        let egress = egress_policy();
        let policies = [ingress, egress];

        let ingress_decision = evaluate(&policies, test_flow(&source, &destination, 8080));
        assert_eq!(ingress_decision.direction, PolicyDirection::Ingress);
        assert_eq!(ingress_decision.verdict, Verdict::Allow);
        assert_eq!(ingress_decision.policy_id, Some(PolicyId::new(1)));

        let egress_decision = evaluate_for_direction(
            &policies,
            PolicyDirection::Egress,
            test_flow(&source, &destination, 8080),
        );
        assert_eq!(egress_decision.direction, PolicyDirection::Egress);
        assert_eq!(egress_decision.verdict, Verdict::Allow);
        assert_eq!(egress_decision.policy_id, Some(PolicyId::new(2)));

        let denied = evaluate_for_direction(
            &policies,
            PolicyDirection::Egress,
            test_flow(&source, &alternate_destination, 8080),
        );
        assert_eq!(denied.verdict, Verdict::Deny);
        assert_eq!(denied.reason, DecisionReason::DefaultAction);

        let unisolated = evaluate_for_direction(
            &policies,
            PolicyDirection::Egress,
            test_flow(&alternate_source, &destination, 8080),
        );
        assert_eq!(unisolated.verdict, Verdict::Allow);
        assert_eq!(unisolated.reason, DecisionReason::NoApplicablePolicy);
    }

    #[test]
    fn direction_serialization_is_explicit_and_backward_compatible() {
        let egress = egress_policy();
        let mut serialized = serde_json::to_value(&egress).expect("policy IR serializes");
        assert_eq!(serialized["direction"], "Egress");

        serialized
            .as_object_mut()
            .expect("policy IR is an object")
            .remove("direction");
        let legacy: PolicyIr =
            serde_json::from_value(serialized).expect("legacy policy IR deserializes");
        assert_eq!(legacy.direction, PolicyDirection::Ingress);

        let source = endpoint("frontend", "client");
        let destination = endpoint("backend", "server");
        let ingress_decision = evaluate(
            &[policy(
                1,
                100,
                Action::Allow,
                Action::Deny,
                EnforcementMode::Enforce,
                Some(8080),
            )],
            test_flow(&source, &destination, 8080),
        );
        assert!(
            serde_json::to_value(ingress_decision)
                .expect("ingress decision serializes")
                .get("direction")
                .is_none(),
            "the established ingress response shape remains unchanged"
        );

        let decision = evaluate_for_direction(
            &[egress],
            PolicyDirection::Egress,
            test_flow(&source, &destination, 8080),
        );
        assert_eq!(
            serde_json::to_value(decision).expect("decision serializes")["direction"],
            "Egress"
        );
    }

    #[test]
    fn ingress_dataplane_compilers_reject_egress_policy_ir() {
        let egress = egress_policy();
        let expected = DataplaneCompileError::UnsupportedPolicyDirection {
            direction: PolicyDirection::Egress,
        };

        assert_eq!(
            compile_dataplane_entries(std::slice::from_ref(&egress), &[])
                .expect_err("egress IR must not reach the ingress dataplane"),
            expected
        );
        assert_eq!(
            compile_ipv4_dataplane_entries(std::slice::from_ref(&egress), &[], &[])
                .expect_err("egress IR must not reach the IPv4 ingress dataplane"),
            expected
        );
        assert_eq!(
            compile_ipv6_dataplane_entries(&[egress], &[], &[])
                .expect_err("egress IR must not reach the IPv6 ingress dataplane"),
            expected
        );
    }

    #[test]
    fn explicit_allow_matches_protocol_and_port() {
        let source = endpoint("frontend", "client");
        let destination = endpoint("backend", "server");
        let decision = evaluate(
            &[policy(
                1,
                100,
                Action::Allow,
                Action::Deny,
                EnforcementMode::Enforce,
                Some(8080),
            )],
            test_flow(&source, &destination, 8080),
        );
        assert_eq!(decision.verdict, Verdict::Allow);
        assert_eq!(decision.reason, DecisionReason::ExplicitRule);
    }

    #[test]
    fn unmatched_port_uses_default_deny() {
        let source = endpoint("frontend", "client");
        let destination = endpoint("backend", "server");
        let decision = evaluate(
            &[policy(
                1,
                100,
                Action::Allow,
                Action::Deny,
                EnforcementMode::Enforce,
                Some(8080),
            )],
            test_flow(&source, &destination, 9090),
        );
        assert_eq!(decision.verdict, Verdict::Deny);
        assert_eq!(decision.reason, DecisionReason::DefaultAction);
    }

    #[test]
    fn lower_numeric_priority_wins() {
        let source = endpoint("frontend", "client");
        let destination = endpoint("backend", "server");
        let policies = vec![
            policy(
                1,
                200,
                Action::Allow,
                Action::Allow,
                EnforcementMode::Enforce,
                None,
            ),
            policy(
                2,
                100,
                Action::Deny,
                Action::Allow,
                EnforcementMode::Enforce,
                None,
            ),
        ];
        assert_eq!(
            evaluate(&policies, test_flow(&source, &destination, 8080)).verdict,
            Verdict::Deny
        );
    }

    #[test]
    fn deny_wins_same_priority_conflict() {
        let source = endpoint("frontend", "client");
        let destination = endpoint("backend", "server");
        let policies = vec![
            policy(
                1,
                100,
                Action::Allow,
                Action::Allow,
                EnforcementMode::Enforce,
                None,
            ),
            policy(
                2,
                100,
                Action::Deny,
                Action::Allow,
                EnforcementMode::Enforce,
                None,
            ),
        ];
        assert_eq!(
            evaluate(&policies, test_flow(&source, &destination, 8080)).verdict,
            Verdict::Deny
        );
    }

    #[test]
    fn wildcard_rule_matches_any_protocol_port() {
        let source = endpoint("frontend", "client");
        let destination = endpoint("backend", "server");
        let policy = policy(
            1,
            100,
            Action::Allow,
            Action::Deny,
            EnforcementMode::Enforce,
            None,
        );
        let flow = Flow {
            source: &source,
            destination: &destination,
            protocol: Protocol::Udp,
            destination_port: 53,
            source_ipv4: None,
            source_ipv6: None,
        };
        assert_eq!(evaluate(&[policy], flow).verdict, Verdict::Allow);
    }

    #[test]
    fn shadow_policy_reports_without_enforcing() {
        let source = endpoint("frontend", "client");
        let destination = endpoint("backend", "server");
        let policy = policy(
            1,
            100,
            Action::Deny,
            Action::Deny,
            EnforcementMode::Shadow,
            None,
        );
        let decision = evaluate(&[policy], test_flow(&source, &destination, 8080));
        assert_eq!(decision.verdict, Verdict::Allow);
        assert_eq!(decision.shadow_verdict, Some(Verdict::Deny));
        assert_eq!(decision.shadow_reason, Some(DecisionReason::ExplicitRule));
        assert_eq!(decision.shadow_policy_id, Some(PolicyId::new(1)));
        assert_eq!(decision.shadow_rule_id, Some(RuleId::new(0)));
    }

    #[test]
    fn dataplane_compilation_emits_exact_and_default_decisions() {
        let source = endpoint_with_id(11, "frontend", "client");
        let destination = endpoint_with_id(22, "backend", "server");
        let compiled_policy = policy(
            7,
            100,
            Action::Allow,
            Action::Deny,
            EnforcementMode::Enforce,
            Some(8080),
        );
        let entries = compile_dataplane_entries(
            std::slice::from_ref(&compiled_policy),
            &[source.clone(), destination.clone()],
        )
        .expect("dataplane policy compiles");
        assert_eq!(
            entries,
            compile_dataplane_entries(
                std::slice::from_ref(&compiled_policy),
                &[destination, source]
            )
            .expect("endpoint order does not affect output")
        );
        assert!(entries.windows(2).all(|pair| pair[0].key < pair[1].key));

        let exact = entries
            .iter()
            .find(|entry| {
                entry.key.source_identity == IdentityId::new(11)
                    && entry.key.destination_identity == IdentityId::new(22)
                    && entry.key.protocol == Protocol::Tcp as u8
                    && entry.key.destination_port == 8080
            })
            .expect("exact allow entry exists");
        assert_eq!(exact.decision.verdict, Verdict::Allow);
        assert_eq!(exact.decision.reason, DecisionReason::ExplicitRule);
        assert_eq!(exact.decision.policy_id, Some(PolicyId::new(7)));
        assert_eq!(exact.decision.rule_id, Some(RuleId::new(0)));

        let fallback = entries
            .iter()
            .find(|entry| {
                entry.key.source_identity == IdentityId::new(11)
                    && entry.key.destination_identity == IdentityId::new(22)
                    && entry.key.protocol == 0
                    && entry.key.destination_port == 0
            })
            .expect("default deny entry exists");
        assert_eq!(fallback.decision.verdict, Verdict::Deny);
        assert_eq!(fallback.decision.reason, DecisionReason::DefaultAction);
        assert_eq!(fallback.decision.rule_id, None);
    }

    #[test]
    fn dataplane_compilation_preserves_shadow_decision() {
        let source = endpoint_with_id(11, "frontend", "client");
        let destination = endpoint_with_id(22, "backend", "server");
        let entries = compile_dataplane_entries(
            &[policy(
                7,
                100,
                Action::Deny,
                Action::Deny,
                EnforcementMode::Shadow,
                None,
            )],
            &[source, destination],
        )
        .expect("shadow dataplane policy compiles");
        let entry = entries
            .iter()
            .find(|entry| {
                entry.key.source_identity == IdentityId::new(11)
                    && entry.key.destination_identity == IdentityId::new(22)
            })
            .expect("shadow entry exists");

        assert_eq!(entry.decision.verdict, Verdict::Allow);
        assert_eq!(entry.decision.policy_id, None);
        let shadow = entry.shadow.expect("shadow provenance is retained");
        assert_eq!(shadow.verdict, Verdict::Deny);
        assert_eq!(shadow.reason, DecisionReason::ExplicitRule);
        assert_eq!(shadow.policy_id, Some(PolicyId::new(7)));
    }

    #[test]
    fn dataplane_compilation_rejects_conflicting_identity_metadata() {
        let left = endpoint_with_id(11, "frontend", "client");
        let right = endpoint_with_id(11, "backend", "server");
        assert_eq!(
            compile_dataplane_entries(&[], &[left, right]),
            Err(DataplaneCompileError::IdentityMetadataConflict {
                identity_id: IdentityId::new(11),
            })
        );
    }

    #[test]
    fn dataplane_capacity_guard_rejects_a_full_bank() {
        assert_eq!(
            ensure_dataplane_capacity(POLICY_MAP_BANK_ENTRY_LIMIT),
            Err(DataplaneCompileError::EntryLimitExceeded {
                limit: POLICY_MAP_BANK_ENTRY_LIMIT,
            })
        );
        assert!(ensure_dataplane_capacity(POLICY_MAP_BANK_ENTRY_LIMIT - 1).is_ok());
    }

    #[test]
    fn ipv4_lowering_revalidates_block_expansion_limit() {
        let source = endpoint_with_id(1, "frontend", "client");
        let destination = endpoint_with_id(2, "backend", "server");
        let mut policy = policy(
            1,
            100,
            Action::Allow,
            Action::Deny,
            EnforcementMode::Enforce,
            Some(443),
        );
        policy.rules[0].source.ipv4_blocks.push(Ipv4Block {
            cidr: Ipv4Cidr {
                network: Ipv4Addr::new(10, 0, 0, 0),
                prefix_len: 21,
            },
            except: Vec::new(),
        });
        assert_eq!(
            compile_ipv4_dataplane_entries(&[policy], &[source, destination], &[]),
            Err(DataplaneCompileError::Ipv4BlockTooLarge {
                address_count: 2_048,
                limit: KUBERNETES_NETWORK_POLICY_MAX_IP_BLOCK_ADDRESSES,
            })
        );
    }

    proptest! {
        #[test]
        fn evaluation_does_not_depend_on_policy_order(mut ids in prop::collection::vec(1_u32..10_000, 1..20)) {
            ids.sort_unstable();
            ids.dedup();
            let source = endpoint("frontend", "client");
            let destination = endpoint("backend", "server");
            let mut policies: Vec<_> = ids.iter().map(|id| {
                let action = if id % 2 == 0 { Action::Deny } else { Action::Allow };
                policy(*id, id % 5, action, Action::Deny, EnforcementMode::Enforce, Some(8080))
            }).collect();
            let expected = evaluate(&policies, test_flow(&source, &destination, 8080));
            policies.reverse();
            prop_assert_eq!(evaluate(&policies, test_flow(&source, &destination, 8080)), expected);
        }
    }
}
