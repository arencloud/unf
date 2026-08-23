use k8s_openapi::api::networking::v1::{NetworkPolicy, NetworkPolicyPeer, NetworkPolicyPort};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::LabelSelector;
use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;
use thiserror::Error;
use unf_common::{PolicyAction, PolicyId, Protocol};

use crate::{
    IdentitySelector, PolicyEnforcementMode, PolicyIr, PolicyOrigin, PolicyRule, push_rule,
};

/// Compatibility policies sit below the native policy priority range by
/// default. A native policy can deliberately override this baseline.
pub const KUBERNETES_NETWORK_POLICY_PRIORITY: u32 = 1_000_000;
const NAMESPACE_NAME_LABEL: &str = "kubernetes.io/metadata.name";

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum NetworkPolicyCompileError {
    #[error("NetworkPolicy metadata.name is required")]
    MissingName,
    #[error("NetworkPolicy metadata.namespace is required")]
    MissingNamespace,
    #[error("NetworkPolicy spec is required")]
    MissingSpec,
    #[error("NetworkPolicy spec.podSelector is required")]
    MissingPodSelector,
    #[error("NetworkPolicy egress semantics are not supported yet")]
    UnsupportedEgress,
    #[error("NetworkPolicy policyType {policy_type:?} is not supported")]
    UnsupportedPolicyType { policy_type: String },
    #[error("NetworkPolicy policyTypes must include Ingress")]
    MissingIngressPolicyType,
    #[error("{field} matchExpressions are not supported yet")]
    UnsupportedMatchExpressions { field: &'static str },
    #[error("ingress rule {rule_index} peer {peer_index} uses unsupported ipBlock")]
    UnsupportedIpBlock {
        rule_index: usize,
        peer_index: usize,
    },
    #[error(
        "ingress rule {rule_index} peer {peer_index} namespaceSelector currently supports only an empty selector or kubernetes.io/metadata.name"
    )]
    UnsupportedNamespaceSelector {
        rule_index: usize,
        peer_index: usize,
    },
    #[error("ingress rule {rule_index} port {port_index} uses unsupported named port {name:?}")]
    UnsupportedNamedPort {
        rule_index: usize,
        port_index: usize,
        name: String,
    },
    #[error(
        "ingress rule {rule_index} port {port_index} matches a protocol without a numeric port, which the current BPF key cannot represent"
    )]
    UnsupportedProtocolOnlyPort {
        rule_index: usize,
        port_index: usize,
    },
    #[error("ingress rule {rule_index} port {port_index} uses unsupported port range")]
    UnsupportedPortRange {
        rule_index: usize,
        port_index: usize,
    },
    #[error("ingress rule {rule_index} port {port_index} uses unsupported protocol {protocol:?}")]
    UnsupportedProtocol {
        rule_index: usize,
        port_index: usize,
        protocol: String,
    },
    #[error("ingress rule {rule_index} port {port_index} contains invalid port {port}")]
    InvalidPort {
        rule_index: usize,
        port_index: usize,
        port: i32,
    },
    #[error("NetworkPolicy contains more rules than can be represented by RuleId")]
    TooManyRules,
}

/// Translates the supported ingress subset of Kubernetes `NetworkPolicy` into the
/// same Kubernetes-independent IR used by native UNF policy.
pub struct NetworkPolicyCompiler;

impl NetworkPolicyCompiler {
    /// # Errors
    ///
    /// Returns an explicit error for missing metadata or semantics that cannot
    /// yet be represented faithfully by the UNF identity and L3/L4 model.
    pub fn compile(
        policy_id: PolicyId,
        policy: NetworkPolicy,
    ) -> Result<PolicyIr, NetworkPolicyCompileError> {
        let name = policy
            .metadata
            .name
            .ok_or(NetworkPolicyCompileError::MissingName)?;
        let namespace = policy
            .metadata
            .namespace
            .ok_or(NetworkPolicyCompileError::MissingNamespace)?;
        let spec = policy.spec.ok_or(NetworkPolicyCompileError::MissingSpec)?;
        validate_policy_types(spec.policy_types.as_deref(), spec.egress.as_deref())?;

        let pod_selector = spec
            .pod_selector
            .ok_or(NetworkPolicyCompileError::MissingPodSelector)?;
        let target = pod_identity_selector(pod_selector, Some(namespace.clone()), "podSelector")?;
        let mut rules = Vec::<PolicyRule>::new();
        for (rule_index, ingress) in spec.ingress.unwrap_or_default().into_iter().enumerate() {
            let sources = sources(ingress.from, &namespace, rule_index)?;
            let ports = ports(ingress.ports, rule_index)?;
            for source in sources {
                for (protocol, port) in &ports {
                    push_rule(
                        &mut rules,
                        policy_id,
                        &name,
                        &namespace,
                        source.clone(),
                        target.clone(),
                        *protocol,
                        *port,
                        PolicyAction::Allow,
                        rule_index,
                    )
                    .map_err(|_| NetworkPolicyCompileError::TooManyRules)?;
                }
            }
        }

        Ok(PolicyIr {
            id: policy_id,
            name,
            namespace,
            priority: KUBERNETES_NETWORK_POLICY_PRIORITY,
            origin: PolicyOrigin::KubernetesNetworkPolicy,
            target,
            default_action: PolicyAction::Deny,
            enforcement_mode: PolicyEnforcementMode::Enforce,
            rules,
        })
    }
}

fn validate_policy_types(
    policy_types: Option<&[String]>,
    egress: Option<&[k8s_openapi::api::networking::v1::NetworkPolicyEgressRule]>,
) -> Result<(), NetworkPolicyCompileError> {
    if egress.is_some() {
        return Err(NetworkPolicyCompileError::UnsupportedEgress);
    }
    if let Some(policy_types) = policy_types {
        if policy_types.is_empty() {
            return Err(NetworkPolicyCompileError::MissingIngressPolicyType);
        }
        for policy_type in policy_types {
            match policy_type.as_str() {
                "Ingress" => {}
                "Egress" => return Err(NetworkPolicyCompileError::UnsupportedEgress),
                _ => {
                    return Err(NetworkPolicyCompileError::UnsupportedPolicyType {
                        policy_type: policy_type.clone(),
                    });
                }
            }
        }
    }
    Ok(())
}

fn sources(
    peers: Option<Vec<NetworkPolicyPeer>>,
    policy_namespace: &str,
    rule_index: usize,
) -> Result<Vec<IdentitySelector>, NetworkPolicyCompileError> {
    let peers = peers.unwrap_or_default();
    if peers.is_empty() {
        return Ok(vec![IdentitySelector::default()]);
    }
    peers
        .into_iter()
        .enumerate()
        .map(|(peer_index, peer)| peer_selector(peer, policy_namespace, rule_index, peer_index))
        .collect()
}

fn peer_selector(
    peer: NetworkPolicyPeer,
    policy_namespace: &str,
    rule_index: usize,
    peer_index: usize,
) -> Result<IdentitySelector, NetworkPolicyCompileError> {
    if peer.ip_block.is_some() {
        return Err(NetworkPolicyCompileError::UnsupportedIpBlock {
            rule_index,
            peer_index,
        });
    }
    let namespace = match peer.namespace_selector {
        Some(selector) => namespace_from_selector(selector, rule_index, peer_index)?,
        None if peer.pod_selector.is_some() => Some(policy_namespace.to_owned()),
        None => None,
    };
    match peer.pod_selector {
        Some(selector) => pod_identity_selector(selector, namespace, "peer podSelector"),
        None => Ok(IdentitySelector {
            namespace,
            ..IdentitySelector::default()
        }),
    }
}

fn namespace_from_selector(
    selector: LabelSelector,
    rule_index: usize,
    peer_index: usize,
) -> Result<Option<String>, NetworkPolicyCompileError> {
    reject_expressions(&selector, "peer namespaceSelector")?;
    let labels = selector.match_labels.unwrap_or_default();
    if labels.is_empty() {
        return Ok(None);
    }
    if labels.len() == 1 {
        return labels.get(NAMESPACE_NAME_LABEL).cloned().map(Some).ok_or(
            NetworkPolicyCompileError::UnsupportedNamespaceSelector {
                rule_index,
                peer_index,
            },
        );
    }
    Err(NetworkPolicyCompileError::UnsupportedNamespaceSelector {
        rule_index,
        peer_index,
    })
}

fn pod_identity_selector(
    selector: LabelSelector,
    namespace: Option<String>,
    field: &'static str,
) -> Result<IdentitySelector, NetworkPolicyCompileError> {
    reject_expressions(&selector, field)?;
    Ok(IdentitySelector {
        namespace,
        match_labels: selector.match_labels.unwrap_or_default(),
        ..IdentitySelector::default()
    })
}

fn reject_expressions(
    selector: &LabelSelector,
    field: &'static str,
) -> Result<(), NetworkPolicyCompileError> {
    if selector
        .match_expressions
        .as_ref()
        .is_some_and(|requirements| !requirements.is_empty())
    {
        Err(NetworkPolicyCompileError::UnsupportedMatchExpressions { field })
    } else {
        Ok(())
    }
}

type PortTuple = (Option<Protocol>, Option<u16>);

fn ports(
    policy_ports: Option<Vec<NetworkPolicyPort>>,
    rule_index: usize,
) -> Result<Vec<PortTuple>, NetworkPolicyCompileError> {
    let policy_ports = policy_ports.unwrap_or_default();
    if policy_ports.is_empty() {
        return Ok(vec![(None, None)]);
    }
    policy_ports
        .into_iter()
        .enumerate()
        .map(|(port_index, port)| port_tuple(port, rule_index, port_index))
        .collect()
}

fn port_tuple(
    port: NetworkPolicyPort,
    rule_index: usize,
    port_index: usize,
) -> Result<(Option<Protocol>, Option<u16>), NetworkPolicyCompileError> {
    let protocol = match port.protocol.as_deref().unwrap_or("TCP") {
        "TCP" => Protocol::Tcp,
        "UDP" => Protocol::Udp,
        value => {
            return Err(NetworkPolicyCompileError::UnsupportedProtocol {
                rule_index,
                port_index,
                protocol: value.to_owned(),
            });
        }
    };
    let numeric_port = match port.port {
        Some(IntOrString::Int(value)) => {
            Some(
                u16::try_from(value).map_err(|_| NetworkPolicyCompileError::InvalidPort {
                    rule_index,
                    port_index,
                    port: value,
                })?,
            )
        }
        Some(IntOrString::String(name)) => {
            return Err(NetworkPolicyCompileError::UnsupportedNamedPort {
                rule_index,
                port_index,
                name,
            });
        }
        None => None,
    };
    if numeric_port == Some(0) {
        return Err(NetworkPolicyCompileError::InvalidPort {
            rule_index,
            port_index,
            port: 0,
        });
    }
    let numeric_port =
        numeric_port.ok_or(NetworkPolicyCompileError::UnsupportedProtocolOnlyPort {
            rule_index,
            port_index,
        })?;
    if port
        .end_port
        .is_some_and(|end_port| i32::from(numeric_port) != end_port)
    {
        return Err(NetworkPolicyCompileError::UnsupportedPortRange {
            rule_index,
            port_index,
        });
    }
    Ok((Some(protocol), Some(numeric_port)))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use k8s_openapi::api::networking::v1::{IPBlock, NetworkPolicyIngressRule, NetworkPolicySpec};
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::{LabelSelectorRequirement, ObjectMeta};
    use unf_common::{IdentityId, PolicyReason, Verdict};

    use super::*;
    use crate::{Endpoint, Flow, compile_dataplane_entries, evaluate};

    fn labels(values: &[(&str, &str)]) -> BTreeMap<String, String> {
        values
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
            .collect()
    }

    fn selector(values: &[(&str, &str)]) -> LabelSelector {
        LabelSelector {
            match_labels: Some(labels(values)),
            ..LabelSelector::default()
        }
    }

    fn policy(ingress: Vec<NetworkPolicyIngressRule>) -> NetworkPolicy {
        NetworkPolicy {
            metadata: ObjectMeta {
                name: Some("allow-client".to_owned()),
                namespace: Some("backend".to_owned()),
                ..ObjectMeta::default()
            },
            spec: Some(NetworkPolicySpec {
                pod_selector: Some(selector(&[("app", "server")])),
                ingress: Some(ingress),
                policy_types: Some(vec!["Ingress".to_owned()]),
                ..NetworkPolicySpec::default()
            }),
        }
    }

    fn endpoint(id: u32, namespace: &str, app: &str) -> Endpoint {
        Endpoint {
            identity: IdentityId::new(id),
            namespace: namespace.to_owned(),
            service_account: "default".to_owned(),
            application: Some(app.to_owned()),
            labels: labels(&[("app", app)]),
        }
    }

    #[test]
    fn ingress_policy_uses_the_existing_evaluator() {
        let peer = NetworkPolicyPeer {
            namespace_selector: Some(selector(&[(NAMESPACE_NAME_LABEL, "frontend")])),
            pod_selector: Some(selector(&[("app", "client")])),
            ..NetworkPolicyPeer::default()
        };
        let port = NetworkPolicyPort {
            port: Some(IntOrString::Int(8080)),
            protocol: Some("TCP".to_owned()),
            ..NetworkPolicyPort::default()
        };
        let compiled = NetworkPolicyCompiler::compile(
            PolicyId::new(41),
            policy(vec![NetworkPolicyIngressRule {
                from: Some(vec![peer]),
                ports: Some(vec![port]),
            }]),
        )
        .expect("supported NetworkPolicy compiles");
        let source = endpoint(1, "frontend", "client");
        let destination = endpoint(2, "backend", "server");
        let allowed = evaluate(
            std::slice::from_ref(&compiled),
            Flow {
                source: &source,
                destination: &destination,
                protocol: Protocol::Tcp,
                destination_port: 8080,
            },
        );
        assert_eq!(allowed.verdict, Verdict::Allow);
        assert_eq!(allowed.reason, PolicyReason::ExplicitRule);
        assert_eq!(allowed.policy_id, Some(PolicyId::new(41)));

        let denied = evaluate(
            &[compiled],
            Flow {
                source: &source,
                destination: &destination,
                protocol: Protocol::Tcp,
                destination_port: 9090,
            },
        );
        assert_eq!(denied.verdict, Verdict::Deny);
        assert_eq!(denied.reason, PolicyReason::DefaultAction);
    }

    #[test]
    fn empty_ingress_is_default_deny() {
        let compiled = NetworkPolicyCompiler::compile(PolicyId::new(7), policy(Vec::new()))
            .expect("isolation policy compiles");
        let source = endpoint(1, "frontend", "client");
        let destination = endpoint(2, "backend", "server");
        assert_eq!(
            evaluate(
                &[compiled],
                Flow {
                    source: &source,
                    destination: &destination,
                    protocol: Protocol::Tcp,
                    destination_port: 8080,
                }
            )
            .verdict,
            Verdict::Deny
        );
    }

    #[test]
    fn multiple_policies_combine_allows_additively() {
        let isolation = NetworkPolicyCompiler::compile(PolicyId::new(7), policy(Vec::new()))
            .expect("isolation policy compiles");
        let allow = NetworkPolicyCompiler::compile(
            PolicyId::new(8),
            policy(vec![NetworkPolicyIngressRule {
                from: None,
                ports: Some(vec![NetworkPolicyPort {
                    port: Some(IntOrString::Int(8080)),
                    ..NetworkPolicyPort::default()
                }]),
            }]),
        )
        .expect("allow policy compiles");
        let source = endpoint(1, "frontend", "client");
        let destination = endpoint(2, "backend", "server");
        let policies = [isolation, allow];
        let allowed_flow = Flow {
            source: &source,
            destination: &destination,
            protocol: Protocol::Tcp,
            destination_port: 8080,
        };
        let allowed = evaluate(&policies, allowed_flow);
        assert_eq!(allowed.verdict, Verdict::Allow);
        let mut reversed = policies.clone();
        reversed.reverse();
        assert_eq!(evaluate(&reversed, allowed_flow), allowed);
        assert_eq!(
            evaluate(
                &policies,
                Flow {
                    source: &source,
                    destination: &destination,
                    protocol: Protocol::Tcp,
                    destination_port: 9090,
                }
            )
            .verdict,
            Verdict::Deny
        );

        let entries = compile_dataplane_entries(&policies, &[source, destination])
            .expect("compatibility policy lowers through the shared dataplane compiler");
        let exact = entries
            .iter()
            .find(|entry| {
                entry.key.source_identity == IdentityId::new(1)
                    && entry.key.destination_identity == IdentityId::new(2)
                    && entry.key.protocol == Protocol::Tcp as u8
                    && entry.key.destination_port == 8080
            })
            .expect("additive allow is represented in the dataplane map");
        assert_eq!(exact.decision.verdict, Verdict::Allow);
    }

    #[test]
    fn omitted_sources_and_ports_are_wildcards() {
        let compiled = NetworkPolicyCompiler::compile(
            PolicyId::new(7),
            policy(vec![NetworkPolicyIngressRule::default()]),
        )
        .expect("wildcard rule compiles");
        assert_eq!(compiled.rules.len(), 1);
        assert_eq!(compiled.rules[0].source, IdentitySelector::default());
        assert_eq!(compiled.rules[0].protocol, None);
        assert_eq!(compiled.rules[0].port, None);
    }

    #[test]
    fn pod_selector_without_namespace_is_policy_local() {
        let compiled = NetworkPolicyCompiler::compile(
            PolicyId::new(7),
            policy(vec![NetworkPolicyIngressRule {
                from: Some(vec![NetworkPolicyPeer {
                    pod_selector: Some(selector(&[("app", "client")])),
                    ..NetworkPolicyPeer::default()
                }]),
                ports: None,
            }]),
        )
        .expect("local peer compiles");
        assert_eq!(
            compiled.rules[0].source.namespace.as_deref(),
            Some("backend")
        );
    }

    #[test]
    fn unsupported_features_fail_explicitly() {
        let ip_block_policy = policy(vec![NetworkPolicyIngressRule {
            from: Some(vec![NetworkPolicyPeer {
                ip_block: Some(IPBlock {
                    cidr: "10.0.0.0/8".to_owned(),
                    except: None,
                }),
                ..NetworkPolicyPeer::default()
            }]),
            ports: None,
        }]);
        assert!(matches!(
            NetworkPolicyCompiler::compile(PolicyId::new(7), ip_block_policy),
            Err(NetworkPolicyCompileError::UnsupportedIpBlock { .. })
        ));

        let mut expression_policy = policy(Vec::new());
        expression_policy
            .spec
            .as_mut()
            .expect("spec exists")
            .pod_selector = Some(LabelSelector {
            match_expressions: Some(vec![LabelSelectorRequirement {
                key: "app".to_owned(),
                operator: "In".to_owned(),
                values: Some(vec!["server".to_owned()]),
            }]),
            ..LabelSelector::default()
        });
        assert!(matches!(
            NetworkPolicyCompiler::compile(PolicyId::new(7), expression_policy),
            Err(NetworkPolicyCompileError::UnsupportedMatchExpressions { .. })
        ));

        let named_port_policy = policy(vec![NetworkPolicyIngressRule {
            from: None,
            ports: Some(vec![NetworkPolicyPort {
                port: Some(IntOrString::String("http".to_owned())),
                ..NetworkPolicyPort::default()
            }]),
        }]);
        assert!(matches!(
            NetworkPolicyCompiler::compile(PolicyId::new(7), named_port_policy),
            Err(NetworkPolicyCompileError::UnsupportedNamedPort { .. })
        ));

        let protocol_only_policy = policy(vec![NetworkPolicyIngressRule {
            from: None,
            ports: Some(vec![NetworkPolicyPort::default()]),
        }]);
        assert!(matches!(
            NetworkPolicyCompiler::compile(PolicyId::new(7), protocol_only_policy),
            Err(NetworkPolicyCompileError::UnsupportedProtocolOnlyPort { .. })
        ));

        let mut egress_policy = policy(Vec::new());
        egress_policy
            .spec
            .as_mut()
            .expect("spec exists")
            .policy_types = Some(vec!["Egress".to_owned()]);
        assert_eq!(
            NetworkPolicyCompiler::compile(PolicyId::new(7), egress_policy),
            Err(NetworkPolicyCompileError::UnsupportedEgress)
        );
    }
}
