use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv4Addr;

use k8s_openapi::api::networking::v1::{NetworkPolicy, NetworkPolicyPeer, NetworkPolicyPort};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{LabelSelector, LabelSelectorRequirement};
use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;
use thiserror::Error;
use unf_common::{PolicyAction, PolicyId, Protocol};

use crate::{
    DestinationPort, IdentitySelector, Ipv4Block, Ipv4Cidr, LabelExpression,
    LabelExpressionOperator, PolicyEnforcementMode, PolicyIr, PolicyOrigin, PolicyRule, push_rule,
};

/// Compatibility policies sit below the native policy priority range by
/// default. A native policy can deliberately override this baseline.
pub const KUBERNETES_NETWORK_POLICY_PRIORITY: u32 = 1_000_000;
/// Prevents one selector pair from expanding an unbounded number of exact BPF keys.
pub const KUBERNETES_NETWORK_POLICY_MAX_PORT_RANGE_WIDTH: u32 = 1_024;
/// Bounds exact-source expansion for one IPv4 `ipBlock`.
pub const KUBERNETES_NETWORK_POLICY_MAX_IP_BLOCK_ADDRESSES: u64 = 1_024;
const NAMESPACE_NAME_LABEL: &str = "kubernetes.io/metadata.name";

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum NetworkPolicyCompileError {
    #[error("NetworkPolicy metadata.name is required")]
    MissingName,
    #[error("NetworkPolicy metadata.namespace is required")]
    MissingNamespace,
    #[error("NetworkPolicy spec is required")]
    MissingSpec,
    #[error("NetworkPolicy egress semantics are not supported yet")]
    UnsupportedEgress,
    #[error("NetworkPolicy policyType {policy_type:?} is not supported")]
    UnsupportedPolicyType { policy_type: String },
    #[error("NetworkPolicy policyTypes must include Ingress")]
    MissingIngressPolicyType,
    #[error("{field} matchExpression for key {key:?} uses invalid operator {operator:?}")]
    InvalidMatchExpressionOperator {
        field: &'static str,
        key: String,
        operator: String,
    },
    #[error(
        "{field} matchExpression for key {key:?} with operator {operator:?} has invalid values"
    )]
    InvalidMatchExpressionValues {
        field: &'static str,
        key: String,
        operator: String,
    },
    #[error(
        "ingress rule {rule_index} peer {peer_index} combines ipBlock with pod/namespace selectors"
    )]
    InvalidIpBlockPeerCombination {
        rule_index: usize,
        peer_index: usize,
    },
    #[error("ingress rule {rule_index} peer {peer_index} contains invalid IPv4 CIDR {cidr:?}")]
    InvalidIpBlockCidr {
        rule_index: usize,
        peer_index: usize,
        cidr: String,
    },
    #[error(
        "ingress rule {rule_index} peer {peer_index} except CIDR {except:?} is outside {cidr:?}"
    )]
    IpBlockExceptOutsideCidr {
        rule_index: usize,
        peer_index: usize,
        cidr: String,
        except: String,
    },
    #[error(
        "ingress rule {rule_index} peer {peer_index} ipBlock contains {address_count} addresses, exceeding limit {limit}"
    )]
    IpBlockTooLarge {
        rule_index: usize,
        peer_index: usize,
        address_count: u64,
        limit: u64,
    },
    #[error(
        "ingress rule {rule_index} peer {peer_index} ipBlock contains reserved source address 0.0.0.0"
    )]
    IpBlockContainsReservedAddress {
        rule_index: usize,
        peer_index: usize,
    },
    #[error("ingress rule {rule_index} port {port_index} contains an empty named port")]
    InvalidNamedPort {
        rule_index: usize,
        port_index: usize,
    },
    #[error("ingress rule {rule_index} port {port_index} combines a named port with endPort")]
    InvalidNamedPortRange {
        rule_index: usize,
        port_index: usize,
    },
    #[error("ingress rule {rule_index} port {port_index} contains invalid range {start}..={end}")]
    InvalidPortRange {
        rule_index: usize,
        port_index: usize,
        start: i32,
        end: i32,
    },
    #[error(
        "ingress rule {rule_index} port {port_index} range width {width} exceeds limit {limit}"
    )]
    PortRangeTooLarge {
        rule_index: usize,
        port_index: usize,
        width: u32,
        limit: u32,
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

        let pod_selector = spec.pod_selector.unwrap_or_default();
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
                        port.clone(),
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
    let NetworkPolicyPeer {
        ip_block,
        namespace_selector,
        pod_selector,
    } = peer;
    if let Some(ip_block) = ip_block {
        if namespace_selector.is_some() || pod_selector.is_some() {
            return Err(NetworkPolicyCompileError::InvalidIpBlockPeerCombination {
                rule_index,
                peer_index,
            });
        }
        return ip_block_selector(ip_block, rule_index, peer_index);
    }
    let namespace_selector = match namespace_selector {
        Some(selector) => namespace_identity_selector(selector)?,
        None if pod_selector.is_some() => NamespaceIdentitySelector {
            namespace: Some(policy_namespace.to_owned()),
            ..NamespaceIdentitySelector::default()
        },
        None => NamespaceIdentitySelector::default(),
    };
    let mut identity_selector = pod_selector.map_or_else(
        || Ok(IdentitySelector::default()),
        |selector| pod_identity_selector(selector, None, "peer podSelector"),
    )?;
    identity_selector.namespace = namespace_selector.namespace;
    identity_selector.namespace_match_labels = namespace_selector.match_labels;
    identity_selector.namespace_match_expressions = namespace_selector.match_expressions;
    Ok(identity_selector)
}

fn ip_block_selector(
    ip_block: k8s_openapi::api::networking::v1::IPBlock,
    rule_index: usize,
    peer_index: usize,
) -> Result<IdentitySelector, NetworkPolicyCompileError> {
    let cidr_text = ip_block.cidr;
    let cidr = parse_ipv4_cidr(&cidr_text).ok_or_else(|| {
        NetworkPolicyCompileError::InvalidIpBlockCidr {
            rule_index,
            peer_index,
            cidr: cidr_text.clone(),
        }
    })?;
    let address_count = cidr.address_count();
    if cidr.contains(Ipv4Addr::UNSPECIFIED) {
        return Err(NetworkPolicyCompileError::IpBlockContainsReservedAddress {
            rule_index,
            peer_index,
        });
    }
    if address_count > KUBERNETES_NETWORK_POLICY_MAX_IP_BLOCK_ADDRESSES {
        return Err(NetworkPolicyCompileError::IpBlockTooLarge {
            rule_index,
            peer_index,
            address_count,
            limit: KUBERNETES_NETWORK_POLICY_MAX_IP_BLOCK_ADDRESSES,
        });
    }
    let mut except = ip_block
        .except
        .unwrap_or_default()
        .into_iter()
        .map(|except_text| {
            let except = parse_ipv4_cidr(&except_text).ok_or_else(|| {
                NetworkPolicyCompileError::InvalidIpBlockCidr {
                    rule_index,
                    peer_index,
                    cidr: except_text.clone(),
                }
            })?;
            if !cidr.contains_cidr(&except) {
                return Err(NetworkPolicyCompileError::IpBlockExceptOutsideCidr {
                    rule_index,
                    peer_index,
                    cidr: cidr_text.clone(),
                    except: except_text,
                });
            }
            Ok(except)
        })
        .collect::<Result<Vec<_>, _>>()?;
    except.sort();
    except.dedup();
    Ok(IdentitySelector {
        ipv4_blocks: vec![Ipv4Block { cidr, except }],
        ..IdentitySelector::default()
    })
}

fn parse_ipv4_cidr(value: &str) -> Option<Ipv4Cidr> {
    let (address, prefix_len) = value.split_once('/')?;
    let address: Ipv4Addr = address.parse().ok()?;
    let prefix_len: u8 = prefix_len.parse().ok()?;
    if prefix_len > 32 {
        return None;
    }
    let mask = if prefix_len == 0 {
        0
    } else {
        u32::MAX << (32 - prefix_len)
    };
    Some(Ipv4Cidr {
        network: Ipv4Addr::from(u32::from(address) & mask),
        prefix_len,
    })
}

#[derive(Default)]
struct NamespaceIdentitySelector {
    namespace: Option<String>,
    match_labels: BTreeMap<String, String>,
    match_expressions: Vec<LabelExpression>,
}

fn namespace_identity_selector(
    selector: LabelSelector,
) -> Result<NamespaceIdentitySelector, NetworkPolicyCompileError> {
    let mut match_labels = selector.match_labels.unwrap_or_default();
    let namespace = match_labels.remove(NAMESPACE_NAME_LABEL);
    let match_expressions = selector
        .match_expressions
        .unwrap_or_default()
        .into_iter()
        .map(|requirement| label_expression(requirement, "peer namespaceSelector"))
        .collect::<Result<BTreeSet<_>, _>>()?
        .into_iter()
        .collect();
    Ok(NamespaceIdentitySelector {
        namespace,
        match_labels,
        match_expressions,
    })
}

fn pod_identity_selector(
    selector: LabelSelector,
    namespace: Option<String>,
    field: &'static str,
) -> Result<IdentitySelector, NetworkPolicyCompileError> {
    let match_expressions = selector
        .match_expressions
        .unwrap_or_default()
        .into_iter()
        .map(|requirement| label_expression(requirement, field))
        .collect::<Result<BTreeSet<_>, _>>()?
        .into_iter()
        .collect();
    Ok(IdentitySelector {
        namespace,
        match_labels: selector.match_labels.unwrap_or_default(),
        match_expressions,
        ..IdentitySelector::default()
    })
}

fn label_expression(
    requirement: LabelSelectorRequirement,
    field: &'static str,
) -> Result<LabelExpression, NetworkPolicyCompileError> {
    let values: BTreeSet<_> = requirement.values.unwrap_or_default().into_iter().collect();
    let operator = match requirement.operator.as_str() {
        "In" if !values.is_empty() => LabelExpressionOperator::In,
        "NotIn" if !values.is_empty() => LabelExpressionOperator::NotIn,
        "Exists" if values.is_empty() => LabelExpressionOperator::Exists,
        "DoesNotExist" if values.is_empty() => LabelExpressionOperator::DoesNotExist,
        "In" | "NotIn" | "Exists" | "DoesNotExist" => {
            return Err(NetworkPolicyCompileError::InvalidMatchExpressionValues {
                field,
                key: requirement.key,
                operator: requirement.operator,
            });
        }
        _ => {
            return Err(NetworkPolicyCompileError::InvalidMatchExpressionOperator {
                field,
                key: requirement.key,
                operator: requirement.operator,
            });
        }
    };
    Ok(LabelExpression {
        key: requirement.key,
        operator,
        values,
    })
}

type PortTuple = (Option<Protocol>, DestinationPort);

fn ports(
    policy_ports: Option<Vec<NetworkPolicyPort>>,
    rule_index: usize,
) -> Result<Vec<PortTuple>, NetworkPolicyCompileError> {
    let policy_ports = policy_ports.unwrap_or_default();
    if policy_ports.is_empty() {
        return Ok(vec![(None, DestinationPort::Any)]);
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
) -> Result<PortTuple, NetworkPolicyCompileError> {
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
    let destination_port = match port.port {
        Some(IntOrString::Int(value)) => {
            let start =
                u16::try_from(value).map_err(|_| NetworkPolicyCompileError::InvalidPort {
                    rule_index,
                    port_index,
                    port: value,
                })?;
            if start == 0 {
                return Err(NetworkPolicyCompileError::InvalidPort {
                    rule_index,
                    port_index,
                    port: 0,
                });
            }
            match port.end_port {
                None => DestinationPort::Number(start),
                Some(end_value) => {
                    let end = u16::try_from(end_value).map_err(|_| {
                        NetworkPolicyCompileError::InvalidPortRange {
                            rule_index,
                            port_index,
                            start: value,
                            end: end_value,
                        }
                    })?;
                    if end < start {
                        return Err(NetworkPolicyCompileError::InvalidPortRange {
                            rule_index,
                            port_index,
                            start: value,
                            end: end_value,
                        });
                    }
                    let width = u32::from(end) - u32::from(start) + 1;
                    if width > KUBERNETES_NETWORK_POLICY_MAX_PORT_RANGE_WIDTH {
                        return Err(NetworkPolicyCompileError::PortRangeTooLarge {
                            rule_index,
                            port_index,
                            width,
                            limit: KUBERNETES_NETWORK_POLICY_MAX_PORT_RANGE_WIDTH,
                        });
                    }
                    if start == end {
                        DestinationPort::Number(start)
                    } else {
                        DestinationPort::Range { start, end }
                    }
                }
            }
        }
        Some(IntOrString::String(name)) if !name.is_empty() => {
            if port.end_port.is_some() {
                return Err(NetworkPolicyCompileError::InvalidNamedPortRange {
                    rule_index,
                    port_index,
                });
            }
            DestinationPort::Named(name)
        }
        Some(IntOrString::String(_)) => {
            return Err(NetworkPolicyCompileError::InvalidNamedPort {
                rule_index,
                port_index,
            });
        }
        None if port.end_port.is_none() => DestinationPort::Any,
        None => {
            return Err(NetworkPolicyCompileError::InvalidPortRange {
                rule_index,
                port_index,
                start: 0,
                end: port.end_port.unwrap_or_default(),
            });
        }
    };
    Ok((Some(protocol), destination_port))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use k8s_openapi::api::networking::v1::{IPBlock, NetworkPolicyIngressRule, NetworkPolicySpec};
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::{LabelSelectorRequirement, ObjectMeta};
    use unf_common::{IdentityId, PolicyReason, Verdict};

    use super::*;
    use crate::{
        Endpoint, Flow, Ipv4Endpoint, NamedPort, compile_dataplane_entries,
        compile_ipv4_dataplane_entries, evaluate,
    };

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

    fn expression(key: &str, operator: &str, values: &[&str]) -> LabelSelectorRequirement {
        LabelSelectorRequirement {
            key: key.to_owned(),
            operator: operator.to_owned(),
            values: Some(values.iter().map(|value| (*value).to_owned()).collect()),
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
            namespace_labels: labels(&[(NAMESPACE_NAME_LABEL, namespace)]),
            service_account: "default".to_owned(),
            application: Some(app.to_owned()),
            labels: labels(&[("app", app)]),
            named_ports: BTreeMap::new(),
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
                source_ipv4: None,
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
                source_ipv4: None,
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
                    source_ipv4: None,
                }
            )
            .verdict,
            Verdict::Deny
        );
    }

    #[test]
    fn omitted_target_selector_defaults_to_all_pods_in_the_policy_namespace() {
        let mut namespace_policy = policy(vec![NetworkPolicyIngressRule {
            from: None,
            ports: Some(vec![NetworkPolicyPort {
                port: Some(IntOrString::Int(8085)),
                ..NetworkPolicyPort::default()
            }]),
        }]);
        let spec = namespace_policy
            .spec
            .as_mut()
            .expect("test policy has spec");
        spec.pod_selector = None;
        spec.policy_types = None;
        let compiled = NetworkPolicyCompiler::compile(PolicyId::new(7), namespace_policy)
            .expect("omitted podSelector defaults to an empty selector");

        assert_eq!(compiled.target.namespace.as_deref(), Some("backend"));
        assert!(compiled.target.match_labels.is_empty());
        assert!(compiled.target.match_expressions.is_empty());
        assert_eq!(compiled.rules[0].protocol, Some(Protocol::Tcp));

        let source = endpoint(1, "frontend", "client");
        let selected = endpoint(2, "backend", "database");
        let non_selected = endpoint(3, "frontend", "database");
        assert_eq!(
            evaluate(
                std::slice::from_ref(&compiled),
                Flow {
                    source: &source,
                    destination: &selected,
                    protocol: Protocol::Tcp,
                    destination_port: 8085,
                    source_ipv4: None,
                },
            )
            .verdict,
            Verdict::Allow
        );
        assert_eq!(
            evaluate(
                std::slice::from_ref(&compiled),
                Flow {
                    source: &source,
                    destination: &selected,
                    protocol: Protocol::Udp,
                    destination_port: 8085,
                    source_ipv4: None,
                },
            )
            .verdict,
            Verdict::Deny,
            "an omitted protocol defaults to TCP"
        );
        assert_eq!(
            evaluate(
                &[compiled],
                Flow {
                    source: &source,
                    destination: &non_selected,
                    protocol: Protocol::Tcp,
                    destination_port: 9092,
                    source_ipv4: None,
                },
            )
            .reason,
            PolicyReason::NoApplicablePolicy
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
            source_ipv4: None,
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
                    source_ipv4: None,
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
        assert_eq!(compiled.rules[0].destination_port, DestinationPort::Any);
    }

    #[test]
    fn protocol_only_ports_lower_without_broadening_other_protocols() {
        let compiled = NetworkPolicyCompiler::compile(
            PolicyId::new(7),
            policy(vec![NetworkPolicyIngressRule {
                from: None,
                ports: Some(vec![NetworkPolicyPort::default()]),
            }]),
        )
        .expect("protocol-only TCP port compiles");
        assert_eq!(compiled.rules[0].protocol, Some(Protocol::Tcp));
        assert_eq!(compiled.rules[0].destination_port, DestinationPort::Any);

        let source = endpoint(1, "frontend", "client");
        let destination = endpoint(2, "backend", "server");
        for port in [1, 8080, u16::MAX] {
            assert_eq!(
                evaluate(
                    std::slice::from_ref(&compiled),
                    Flow {
                        source: &source,
                        destination: &destination,
                        protocol: Protocol::Tcp,
                        destination_port: port,
                        source_ipv4: None,
                    },
                )
                .verdict,
                Verdict::Allow
            );
        }
        assert_eq!(
            evaluate(
                std::slice::from_ref(&compiled),
                Flow {
                    source: &source,
                    destination: &destination,
                    protocol: Protocol::Udp,
                    destination_port: 8080,
                    source_ipv4: None,
                },
            )
            .verdict,
            Verdict::Deny
        );

        let identity_entries = compile_dataplane_entries(
            std::slice::from_ref(&compiled),
            &[source.clone(), destination.clone()],
        )
        .expect("protocol wildcard lowers into the identity policy map");
        assert!(identity_entries.iter().any(|entry| {
            entry.key.source_identity == source.identity
                && entry.key.destination_identity == destination.identity
                && entry.key.protocol == Protocol::Tcp as u8
                && entry.key.destination_port == 0
                && entry.decision.verdict == Verdict::Allow
        }));
        assert!(identity_entries.iter().any(|entry| {
            entry.key.source_identity == source.identity
                && entry.key.destination_identity == destination.identity
                && entry.key.protocol == 0
                && entry.key.destination_port == 0
                && entry.decision.verdict == Verdict::Deny
        }));

        let source_address = Ipv4Addr::new(10, 0, 0, 1);
        let ipv4_entries = compile_ipv4_dataplane_entries(
            &[compiled],
            &[source.clone(), destination.clone()],
            &[Ipv4Endpoint {
                address: source_address,
                endpoint: source,
            }],
        )
        .expect("protocol wildcard lowers into the IPv4 policy map");
        assert!(ipv4_entries.iter().any(|entry| {
            entry.key.source_address == source_address
                && entry.key.destination_identity == destination.identity
                && entry.key.protocol == Protocol::Tcp as u8
                && entry.key.destination_port == 0
                && entry.decision.verdict == Verdict::Allow
        }));
        assert!(!ipv4_entries.iter().any(|entry| {
            entry.key.protocol == Protocol::Udp as u8 && entry.key.destination_port == 0
        }));
    }

    #[test]
    fn udp_protocol_only_port_is_supported() {
        let compiled = NetworkPolicyCompiler::compile(
            PolicyId::new(7),
            policy(vec![NetworkPolicyIngressRule {
                from: None,
                ports: Some(vec![NetworkPolicyPort {
                    protocol: Some("UDP".to_owned()),
                    ..NetworkPolicyPort::default()
                }]),
            }]),
        )
        .expect("protocol-only UDP port compiles");
        assert_eq!(compiled.rules[0].protocol, Some(Protocol::Udp));
        assert_eq!(compiled.rules[0].destination_port, DestinationPort::Any);
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
    fn pod_match_expressions_follow_kubernetes_semantics() {
        let mut expression_policy = policy(vec![NetworkPolicyIngressRule {
            from: Some(vec![NetworkPolicyPeer {
                namespace_selector: Some(selector(&[(NAMESPACE_NAME_LABEL, "frontend")])),
                pod_selector: Some(LabelSelector {
                    match_expressions: Some(vec![
                        expression("app", "In", &["client", "worker"]),
                        expression("blocked", "NotIn", &["yes"]),
                        expression("managed", "Exists", &[]),
                    ]),
                    ..LabelSelector::default()
                }),
                ..NetworkPolicyPeer::default()
            }]),
            ports: None,
        }]);
        expression_policy
            .spec
            .as_mut()
            .expect("spec exists")
            .pod_selector = Some(LabelSelector {
            match_expressions: Some(vec![
                expression("app", "In", &["server"]),
                expression("tier", "NotIn", &["edge"]),
                expression("managed", "Exists", &[]),
                expression("skip", "DoesNotExist", &[]),
            ]),
            ..LabelSelector::default()
        });
        let compiled = NetworkPolicyCompiler::compile(PolicyId::new(7), expression_policy)
            .expect("pod matchExpressions compile");
        let mut source = endpoint(1, "frontend", "client");
        source
            .labels
            .insert("managed".to_owned(), "true".to_owned());
        let mut destination = endpoint(2, "backend", "server");
        destination
            .labels
            .insert("tier".to_owned(), "core".to_owned());
        destination
            .labels
            .insert("managed".to_owned(), "true".to_owned());
        assert_eq!(
            evaluate(
                std::slice::from_ref(&compiled),
                Flow {
                    source: &source,
                    destination: &destination,
                    protocol: Protocol::Tcp,
                    destination_port: 8080,
                    source_ipv4: None,
                }
            )
            .verdict,
            Verdict::Allow
        );

        source.labels.insert("blocked".to_owned(), "yes".to_owned());
        assert_eq!(
            evaluate(
                std::slice::from_ref(&compiled),
                Flow {
                    source: &source,
                    destination: &destination,
                    protocol: Protocol::Tcp,
                    destination_port: 8080,
                    source_ipv4: None,
                }
            )
            .verdict,
            Verdict::Deny
        );

        destination.labels.remove("managed");
        assert_eq!(
            evaluate(
                &[compiled],
                Flow {
                    source: &source,
                    destination: &destination,
                    protocol: Protocol::Tcp,
                    destination_port: 8080,
                    source_ipv4: None,
                }
            )
            .reason,
            PolicyReason::NoApplicablePolicy
        );
    }

    #[test]
    fn pod_match_expression_order_is_canonical() {
        let mut first = policy(Vec::new());
        first.spec.as_mut().expect("spec exists").pod_selector = Some(LabelSelector {
            match_expressions: Some(vec![
                expression("tier", "NotIn", &["edge"]),
                expression("app", "In", &["server", "api"]),
            ]),
            ..LabelSelector::default()
        });
        let mut second = first.clone();
        second
            .spec
            .as_mut()
            .expect("spec exists")
            .pod_selector
            .as_mut()
            .expect("selector exists")
            .match_expressions
            .as_mut()
            .expect("expressions exist")
            .reverse();
        assert_eq!(
            NetworkPolicyCompiler::compile(PolicyId::new(7), first),
            NetworkPolicyCompiler::compile(PolicyId::new(7), second)
        );
    }

    #[test]
    fn invalid_pod_match_expressions_fail_explicitly() {
        let mut invalid_values = policy(Vec::new());
        invalid_values
            .spec
            .as_mut()
            .expect("spec exists")
            .pod_selector = Some(LabelSelector {
            match_expressions: Some(vec![expression("app", "In", &[])]),
            ..LabelSelector::default()
        });
        assert!(matches!(
            NetworkPolicyCompiler::compile(PolicyId::new(7), invalid_values),
            Err(NetworkPolicyCompileError::InvalidMatchExpressionValues { .. })
        ));

        let mut invalid_operator = policy(Vec::new());
        invalid_operator
            .spec
            .as_mut()
            .expect("spec exists")
            .pod_selector = Some(LabelSelector {
            match_expressions: Some(vec![expression("app", "Equals", &["server"])]),
            ..LabelSelector::default()
        });
        assert!(matches!(
            NetworkPolicyCompiler::compile(PolicyId::new(7), invalid_operator),
            Err(NetworkPolicyCompileError::InvalidMatchExpressionOperator { .. })
        ));
    }

    #[test]
    fn namespace_label_selectors_match_source_namespace_metadata() {
        let compiled = NetworkPolicyCompiler::compile(
            PolicyId::new(7),
            policy(vec![NetworkPolicyIngressRule {
                from: Some(vec![NetworkPolicyPeer {
                    namespace_selector: Some(LabelSelector {
                        match_labels: Some(labels(&[("environment", "production")])),
                        match_expressions: Some(vec![
                            expression("team", "In", &["checkout", "platform"]),
                            expression("disabled", "DoesNotExist", &[]),
                        ]),
                    }),
                    pod_selector: Some(selector(&[("app", "client")])),
                    ..NetworkPolicyPeer::default()
                }]),
                ports: None,
            }]),
        )
        .expect("namespace label selector compiles");
        let mut source = endpoint(1, "frontend", "client");
        source.namespace_labels.extend(labels(&[
            ("environment", "production"),
            ("team", "checkout"),
        ]));
        let destination = endpoint(2, "backend", "server");
        assert_eq!(
            evaluate(
                std::slice::from_ref(&compiled),
                Flow {
                    source: &source,
                    destination: &destination,
                    protocol: Protocol::Tcp,
                    destination_port: 8080,
                    source_ipv4: None,
                },
            )
            .verdict,
            Verdict::Allow
        );

        source
            .namespace_labels
            .insert("environment".to_owned(), "staging".to_owned());
        assert_eq!(
            evaluate(
                std::slice::from_ref(&compiled),
                Flow {
                    source: &source,
                    destination: &destination,
                    protocol: Protocol::Tcp,
                    destination_port: 8080,
                    source_ipv4: None,
                },
            )
            .verdict,
            Verdict::Deny
        );
    }

    #[test]
    fn named_ports_resolve_against_each_destination() {
        let compiled = NetworkPolicyCompiler::compile(
            PolicyId::new(7),
            policy(vec![NetworkPolicyIngressRule {
                from: None,
                ports: Some(vec![NetworkPolicyPort {
                    port: Some(IntOrString::String("http".to_owned())),
                    protocol: Some("TCP".to_owned()),
                    ..NetworkPolicyPort::default()
                }]),
            }]),
        )
        .expect("named port policy compiles");
        assert_eq!(
            compiled.rules[0].destination_port,
            DestinationPort::Named("http".to_owned())
        );
        let source = endpoint(1, "frontend", "client");
        let mut destination = endpoint(2, "backend", "server");
        destination.named_ports.insert(
            NamedPort {
                name: "http".to_owned(),
                protocol: Protocol::Tcp,
            },
            8081,
        );
        let mut alternate = endpoint(3, "backend", "server");
        alternate.named_ports.insert(
            NamedPort {
                name: "http".to_owned(),
                protocol: Protocol::Tcp,
            },
            9090,
        );
        assert_eq!(
            evaluate(
                std::slice::from_ref(&compiled),
                Flow {
                    source: &source,
                    destination: &destination,
                    protocol: Protocol::Tcp,
                    destination_port: 8081,
                    source_ipv4: None,
                },
            )
            .verdict,
            Verdict::Allow
        );
        assert_eq!(
            evaluate(
                std::slice::from_ref(&compiled),
                Flow {
                    source: &source,
                    destination: &destination,
                    protocol: Protocol::Tcp,
                    destination_port: 8082,
                    source_ipv4: None,
                },
            )
            .verdict,
            Verdict::Deny
        );
        assert_eq!(
            evaluate(
                std::slice::from_ref(&compiled),
                Flow {
                    source: &source,
                    destination: &alternate,
                    protocol: Protocol::Tcp,
                    destination_port: 9090,
                    source_ipv4: None,
                },
            )
            .verdict,
            Verdict::Allow
        );
        let entries = compile_dataplane_entries(&[compiled], &[source, destination, alternate])
            .expect("named port lowers through the shared dataplane compiler");
        assert!(entries.iter().any(|entry| {
            entry.key.destination_identity == IdentityId::new(2)
                && entry.key.protocol == Protocol::Tcp as u8
                && entry.key.destination_port == 8081
                && entry.decision.verdict == Verdict::Allow
        }));
        assert!(entries.iter().any(|entry| {
            entry.key.destination_identity == IdentityId::new(3)
                && entry.key.protocol == Protocol::Tcp as u8
                && entry.key.destination_port == 9090
                && entry.decision.verdict == Verdict::Allow
        }));
    }

    #[test]
    fn bounded_port_ranges_evaluate_and_lower_to_exact_entries() {
        let compiled = NetworkPolicyCompiler::compile(
            PolicyId::new(7),
            policy(vec![NetworkPolicyIngressRule {
                from: None,
                ports: Some(vec![NetworkPolicyPort {
                    port: Some(IntOrString::Int(8082)),
                    end_port: Some(8084),
                    protocol: Some("TCP".to_owned()),
                }]),
            }]),
        )
        .expect("bounded port range compiles");
        assert_eq!(
            compiled.rules[0].destination_port,
            DestinationPort::Range {
                start: 8082,
                end: 8084,
            }
        );
        let source = endpoint(1, "frontend", "client");
        let destination = endpoint(2, "backend", "server");
        for port in 8082..=8084 {
            assert_eq!(
                evaluate(
                    std::slice::from_ref(&compiled),
                    Flow {
                        source: &source,
                        destination: &destination,
                        protocol: Protocol::Tcp,
                        destination_port: port,
                        source_ipv4: None,
                    },
                )
                .verdict,
                Verdict::Allow
            );
        }
        for port in [8081, 8085] {
            assert_eq!(
                evaluate(
                    std::slice::from_ref(&compiled),
                    Flow {
                        source: &source,
                        destination: &destination,
                        protocol: Protocol::Tcp,
                        destination_port: port,
                        source_ipv4: None,
                    },
                )
                .verdict,
                Verdict::Deny
            );
        }
        let entries = compile_dataplane_entries(&[compiled], &[source, destination])
            .expect("bounded range lowers to exact dataplane entries");
        let lowered_ports: BTreeSet<_> = entries
            .iter()
            .filter(|entry| {
                entry.key.destination_identity == IdentityId::new(2)
                    && entry.key.protocol == Protocol::Tcp as u8
            })
            .map(|entry| entry.key.destination_port)
            .collect();
        assert_eq!(lowered_ports, BTreeSet::from([8082, 8083, 8084]));
    }

    #[test]
    fn invalid_and_oversized_port_ranges_fail_explicitly() {
        let ranged_policy = |port, end_port| {
            policy(vec![NetworkPolicyIngressRule {
                from: None,
                ports: Some(vec![NetworkPolicyPort {
                    port: Some(port),
                    end_port: Some(end_port),
                    ..NetworkPolicyPort::default()
                }]),
            }])
        };
        let maximum_range = NetworkPolicyCompiler::compile(
            PolicyId::new(7),
            ranged_policy(IntOrString::Int(1), 1024),
        )
        .expect("a range at the inclusive width limit compiles");
        assert_eq!(
            maximum_range.rules[0].destination_port,
            DestinationPort::Range {
                start: 1,
                end: 1024,
            }
        );
        assert!(matches!(
            NetworkPolicyCompiler::compile(
                PolicyId::new(7),
                ranged_policy(IntOrString::Int(8084), 8082),
            ),
            Err(NetworkPolicyCompileError::InvalidPortRange { .. })
        ));
        assert!(matches!(
            NetworkPolicyCompiler::compile(
                PolicyId::new(7),
                ranged_policy(IntOrString::Int(1), 1025),
            ),
            Err(NetworkPolicyCompileError::PortRangeTooLarge { .. })
        ));
        assert!(matches!(
            NetworkPolicyCompiler::compile(
                PolicyId::new(7),
                ranged_policy(IntOrString::String("http".to_owned()), 8082),
            ),
            Err(NetworkPolicyCompileError::InvalidNamedPortRange { .. })
        ));
    }

    #[test]
    fn bounded_ip_blocks_apply_exceptions_and_lower_exact_sources() {
        let compiled = NetworkPolicyCompiler::compile(
            PolicyId::new(7),
            policy(vec![NetworkPolicyIngressRule {
                from: Some(vec![NetworkPolicyPeer {
                    ip_block: Some(IPBlock {
                        cidr: "10.0.0.0/30".to_owned(),
                        except: Some(vec!["10.0.0.2/32".to_owned()]),
                    }),
                    ..NetworkPolicyPeer::default()
                }]),
                ports: Some(vec![NetworkPolicyPort {
                    protocol: Some("TCP".to_owned()),
                    port: Some(IntOrString::Int(8080)),
                    ..NetworkPolicyPort::default()
                }]),
            }]),
        )
        .expect("bounded IPv4 ipBlock compiles");
        let source = endpoint(1, "frontend", "client");
        let destination = endpoint(2, "backend", "server");
        for (address, expected) in [
            (Ipv4Addr::new(10, 0, 0, 1), Verdict::Allow),
            (Ipv4Addr::new(10, 0, 0, 2), Verdict::Deny),
            (Ipv4Addr::new(10, 0, 0, 4), Verdict::Deny),
        ] {
            assert_eq!(
                evaluate(
                    std::slice::from_ref(&compiled),
                    Flow {
                        source: &source,
                        destination: &destination,
                        protocol: Protocol::Tcp,
                        destination_port: 8080,
                        source_ipv4: Some(address),
                    },
                )
                .verdict,
                expected
            );
        }

        let ipv4_sources = [
            Ipv4Endpoint {
                address: Ipv4Addr::new(10, 0, 0, 1),
                endpoint: source.clone(),
            },
            Ipv4Endpoint {
                address: Ipv4Addr::new(10, 0, 0, 2),
                endpoint: source.clone(),
            },
        ];
        let entries =
            compile_ipv4_dataplane_entries(&[compiled], &[source, destination], &ipv4_sources)
                .expect("ipBlock lowers into exact-source entries");
        let decision_for = |address| {
            entries
                .iter()
                .find(|entry| {
                    entry.key.source_address == address
                        && entry.key.destination_identity == IdentityId::new(2)
                        && entry.key.protocol == Protocol::Tcp as u8
                        && entry.key.destination_port == 8080
                })
                .map(|entry| entry.decision.verdict)
        };
        assert_eq!(
            decision_for(Ipv4Addr::new(10, 0, 0, 1)),
            Some(Verdict::Allow)
        );
        assert_eq!(decision_for(Ipv4Addr::new(10, 0, 0, 2)), None);
        assert!(entries.iter().any(|entry| {
            entry.key.source_address == Ipv4Addr::UNSPECIFIED
                && entry.key.destination_identity == IdentityId::new(2)
                && entry.key.protocol == 0
                && entry.key.destination_port == 0
                && entry.decision.verdict == Verdict::Deny
        }));
    }

    #[test]
    fn invalid_and_oversized_ip_blocks_fail_explicitly() {
        let policy_with_block = |cidr: &str, except: Option<&str>| {
            policy(vec![NetworkPolicyIngressRule {
                from: Some(vec![NetworkPolicyPeer {
                    ip_block: Some(IPBlock {
                        cidr: cidr.to_owned(),
                        except: except.map(|value| vec![value.to_owned()]),
                    }),
                    ..NetworkPolicyPeer::default()
                }]),
                ports: None,
            }])
        };
        NetworkPolicyCompiler::compile(PolicyId::new(7), policy_with_block("10.0.0.0/22", None))
            .expect("a block at the exact address limit compiles");
        assert!(matches!(
            NetworkPolicyCompiler::compile(
                PolicyId::new(7),
                policy_with_block("10.0.0.0/21", None),
            ),
            Err(NetworkPolicyCompileError::IpBlockTooLarge { .. })
        ));
        assert!(matches!(
            NetworkPolicyCompiler::compile(
                PolicyId::new(7),
                policy_with_block("2001:db8::/120", None),
            ),
            Err(NetworkPolicyCompileError::InvalidIpBlockCidr { .. })
        ));
        assert!(matches!(
            NetworkPolicyCompiler::compile(
                PolicyId::new(7),
                policy_with_block("10.0.0.0/24", Some("10.0.1.0/24")),
            ),
            Err(NetworkPolicyCompileError::IpBlockExceptOutsideCidr { .. })
        ));
        assert!(matches!(
            NetworkPolicyCompiler::compile(PolicyId::new(7), policy_with_block("0.0.0.0/32", None),),
            Err(NetworkPolicyCompileError::IpBlockContainsReservedAddress { .. })
        ));

        let mut combined_peer = policy_with_block("10.0.0.1/32", None);
        combined_peer
            .spec
            .as_mut()
            .unwrap()
            .ingress
            .as_mut()
            .unwrap()[0]
            .from
            .as_mut()
            .unwrap()[0]
            .pod_selector = Some(LabelSelector::default());
        assert!(matches!(
            NetworkPolicyCompiler::compile(PolicyId::new(7), combined_peer),
            Err(NetworkPolicyCompileError::InvalidIpBlockPeerCombination { .. })
        ));
    }

    #[test]
    fn unsupported_features_fail_explicitly() {
        let empty_named_port_policy = policy(vec![NetworkPolicyIngressRule {
            from: None,
            ports: Some(vec![NetworkPolicyPort {
                port: Some(IntOrString::String(String::new())),
                ..NetworkPolicyPort::default()
            }]),
        }]);
        assert!(matches!(
            NetworkPolicyCompiler::compile(PolicyId::new(7), empty_named_port_policy),
            Err(NetworkPolicyCompileError::InvalidNamedPort { .. })
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
