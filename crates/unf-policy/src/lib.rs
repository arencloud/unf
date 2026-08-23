//! Kubernetes-independent policy IR, compilation, and deterministic evaluation.

use std::cmp::Ordering;
use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use unf_api::{
    Action, EnforcementMode, SecurityPolicy, TransportProtocol, WorkloadSelector as ApiSelector,
};
use unf_common::{IdentityId, PolicyAction, PolicyId, Protocol, RuleId, Verdict};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentitySelector {
    pub namespace: Option<String>,
    pub service_account: Option<String>,
    pub application: Option<String>,
    pub match_labels: BTreeMap<String, String>,
}

impl IdentitySelector {
    #[must_use]
    pub fn matches(&self, endpoint: &Endpoint) -> bool {
        self.namespace
            .as_ref()
            .is_none_or(|expected| expected == &endpoint.namespace)
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
    }
}

impl From<ApiSelector> for IdentitySelector {
    fn from(value: ApiSelector) -> Self {
        Self {
            namespace: value.namespace,
            service_account: value.service_account,
            application: value.application,
            match_labels: value.match_labels,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Endpoint {
    pub identity: IdentityId,
    pub namespace: String,
    pub service_account: String,
    pub application: Option<String>,
    pub labels: BTreeMap<String, String>,
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
    pub port: Option<u16>,
    pub action: PolicyAction,
    pub provenance: RuleProvenance,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyIr {
    pub id: PolicyId,
    pub name: String,
    pub namespace: String,
    pub priority: u32,
    pub target: IdentitySelector,
    pub default_action: PolicyAction,
    pub enforcement_mode: PolicyEnforcementMode,
    pub rules: Vec<PolicyRule>,
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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DecisionReason {
    NoApplicablePolicy,
    ExplicitRule,
    DefaultAction,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyDecision {
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
                    None,
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
                        Some(protocol_port.port),
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
fn push_rule(
    rules: &mut Vec<PolicyRule>,
    policy_id: PolicyId,
    policy_name: &str,
    namespace: &str,
    source: IdentitySelector,
    destination: IdentitySelector,
    protocol: Option<Protocol>,
    port: Option<u16>,
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
        port,
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

/// Evaluates policy without depending on insertion or controller watch order.
#[must_use]
pub fn evaluate(policies: &[PolicyIr], flow: Flow<'_>) -> PolicyDecision {
    let applicable: Vec<&PolicyIr> = policies
        .iter()
        .filter(|policy| policy.target.matches(flow.destination))
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

type RankedDecision = (u32, PolicyAction, PolicyId, Option<RuleId>, DecisionReason);

fn decide_for_mode(
    policies: &[&PolicyIr],
    flow: Flow<'_>,
    mode: PolicyEnforcementMode,
) -> Option<(Verdict, DecisionReason, Option<PolicyId>, Option<RuleId>)> {
    let mut candidates = Vec::new();
    for policy in policies
        .iter()
        .copied()
        .filter(|policy| policy.enforcement_mode == mode)
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
    rule.source.matches(flow.source)
        && rule.destination.matches(flow.destination)
        && rule.protocol.is_none_or(|value| value == flow.protocol)
        && rule.port.is_none_or(|value| value == flow.destination_port)
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use unf_api::{IngressRule, ProtocolPort, SecurityPolicySpec, WorkloadSelector};
    use unf_common::PolicyId;

    use super::*;

    fn endpoint(namespace: &str, application: &str) -> Endpoint {
        Endpoint {
            identity: IdentityId::new(1),
            namespace: namespace.to_owned(),
            service_account: "default".to_owned(),
            application: Some(application.to_owned()),
            labels: BTreeMap::new(),
        }
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
        }
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
