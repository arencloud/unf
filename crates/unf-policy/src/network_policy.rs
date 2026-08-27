use std::collections::{BTreeMap, BTreeSet};
use std::net::{Ipv4Addr, Ipv6Addr};

use k8s_openapi::api::networking::v1::{
    NetworkPolicy, NetworkPolicyEgressRule, NetworkPolicyPeer, NetworkPolicyPort,
};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{LabelSelector, LabelSelectorRequirement};
use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;
use thiserror::Error;
use unf_common::{PolicyAction, PolicyId, Protocol};

use crate::{
    DestinationPort, IdentitySelector, Ipv4Block, Ipv4Cidr, Ipv6Block, Ipv6Cidr, LabelExpression,
    LabelExpressionOperator, PolicyDirection, PolicyEnforcementMode, PolicyIr, PolicyOrigin,
    PolicyRule, push_rule,
};

/// Compatibility policies sit below the native policy priority range by
/// default. A native policy can deliberately override this baseline.
pub const KUBERNETES_NETWORK_POLICY_PRIORITY: u32 = 1_000_000;
/// Prevents one selector pair from expanding an unbounded number of exact BPF keys.
pub const KUBERNETES_NETWORK_POLICY_MAX_PORT_RANGE_WIDTH: u32 = 1_024;
/// Bounds exact-source expansion for one IPv4 `ipBlock`.
pub const KUBERNETES_NETWORK_POLICY_MAX_IP_BLOCK_ADDRESSES: u64 = 1_024;
/// Bounds the CIDR boundary count for one compact IPv6 `ipBlock`.
pub const KUBERNETES_NETWORK_POLICY_MAX_IPV6_IP_BLOCK_PREFIXES: usize = 1_024;
const NAMESPACE_NAME_LABEL: &str = "kubernetes.io/metadata.name";

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum NetworkPolicyCompileError {
    #[error("NetworkPolicy metadata.name is required")]
    MissingName,
    #[error("NetworkPolicy metadata.namespace is required")]
    MissingNamespace,
    #[error("NetworkPolicy spec is required")]
    MissingSpec,
    #[error("NetworkPolicy egress enforcement is not supported yet")]
    UnsupportedEgress,
    #[error("NetworkPolicy policyType {policy_type:?} is not supported")]
    UnsupportedPolicyType { policy_type: String },
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
        "policy rule {rule_index} peer {peer_index} combines ipBlock with pod/namespace selectors"
    )]
    InvalidIpBlockPeerCombination {
        rule_index: usize,
        peer_index: usize,
    },
    #[error("policy rule {rule_index} peer {peer_index} contains invalid IP CIDR {cidr:?}")]
    InvalidIpBlockCidr {
        rule_index: usize,
        peer_index: usize,
        cidr: String,
    },
    #[error(
        "policy rule {rule_index} peer {peer_index} except CIDR {except:?} is outside {cidr:?}"
    )]
    IpBlockExceptOutsideCidr {
        rule_index: usize,
        peer_index: usize,
        cidr: String,
        except: String,
    },
    #[error(
        "policy rule {rule_index} peer {peer_index} ipBlock contains {address_count} addresses, exceeding limit {limit}"
    )]
    IpBlockTooLarge {
        rule_index: usize,
        peer_index: usize,
        address_count: u64,
        limit: u64,
    },
    #[error(
        "policy rule {rule_index} peer {peer_index} IPv6 ipBlock contains {prefix_count} CIDR boundaries, exceeding limit {limit}"
    )]
    Ipv6IpBlockTooManyPrefixes {
        rule_index: usize,
        peer_index: usize,
        prefix_count: usize,
        limit: usize,
    },
    #[error("policy rule {rule_index} peer {peer_index} ipBlock contains reserved address 0.0.0.0")]
    IpBlockContainsReservedAddress {
        rule_index: usize,
        peer_index: usize,
    },
    #[error("policy rule {rule_index} port {port_index} contains an empty named port")]
    InvalidNamedPort {
        rule_index: usize,
        port_index: usize,
    },
    #[error("policy rule {rule_index} port {port_index} combines a named port with endPort")]
    InvalidNamedPortRange {
        rule_index: usize,
        port_index: usize,
    },
    #[error("policy rule {rule_index} port {port_index} contains invalid range {start}..={end}")]
    InvalidPortRange {
        rule_index: usize,
        port_index: usize,
        start: i32,
        end: i32,
    },
    #[error("policy rule {rule_index} port {port_index} range width {width} exceeds limit {limit}")]
    PortRangeTooLarge {
        rule_index: usize,
        port_index: usize,
        width: u32,
        limit: u32,
    },
    #[error("policy rule {rule_index} port {port_index} uses unsupported protocol {protocol:?}")]
    UnsupportedProtocol {
        rule_index: usize,
        port_index: usize,
        protocol: String,
    },
    #[error("policy rule {rule_index} port {port_index} contains invalid port {port}")]
    InvalidPort {
        rule_index: usize,
        port_index: usize,
        port: i32,
    },
    #[error("NetworkPolicy contains more rules than can be represented by RuleId")]
    TooManyRules,
}

/// Translates supported Kubernetes `NetworkPolicy` directions into the same
/// Kubernetes-independent IR used by native UNF policy.
pub struct NetworkPolicyCompiler;

impl NetworkPolicyCompiler {
    /// Translates the ingress-only shape currently admitted by the controller.
    ///
    /// Use [`Self::compile_directions`] for userspace translation of effective
    /// ingress and egress directions. This enforcement entry point rejects every
    /// object whose effective directions include egress.
    ///
    /// # Errors
    ///
    /// Returns an explicit error for missing metadata or semantics that cannot
    /// yet be represented faithfully by the UNF identity and L3/L4 model.
    pub fn compile(
        policy_id: PolicyId,
        policy: NetworkPolicy,
    ) -> Result<PolicyIr, NetworkPolicyCompileError> {
        let mut policies = Self::compile_directions(policy_id, policy)?;
        if policies.len() == 1 && policies[0].direction == PolicyDirection::Ingress {
            return Ok(policies.remove(0));
        }
        Err(NetworkPolicyCompileError::UnsupportedEgress)
    }

    /// Translates every effective policy direction into one independent IR.
    ///
    /// Omitted or empty `policyTypes` follows Kubernetes API defaulting: ingress
    /// is always selected, and egress is additionally selected when at least one
    /// egress rule exists. Explicit policy types select only the named directions.
    ///
    /// # Errors
    ///
    /// Returns an explicit error for missing metadata, invalid selectors and
    /// ports, unknown policy types, or invalid/beyond-limit address blocks.
    pub fn compile_directions(
        policy_id: PolicyId,
        policy: NetworkPolicy,
    ) -> Result<Vec<PolicyIr>, NetworkPolicyCompileError> {
        let name = policy
            .metadata
            .name
            .ok_or(NetworkPolicyCompileError::MissingName)?;
        let namespace = policy
            .metadata
            .namespace
            .ok_or(NetworkPolicyCompileError::MissingNamespace)?;
        let spec = policy.spec.ok_or(NetworkPolicyCompileError::MissingSpec)?;
        let directions = policy_directions(spec.policy_types.as_deref(), spec.egress.as_deref())?;

        let pod_selector = spec.pod_selector.unwrap_or_default();
        let target = pod_identity_selector(pod_selector, Some(namespace.clone()), "podSelector")?;
        let mut policies = Vec::with_capacity(2);

        if directions.ingress {
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
            policies.push(compatibility_policy_ir(
                policy_id,
                &name,
                &namespace,
                PolicyDirection::Ingress,
                target.clone(),
                rules,
            ));
        }

        if directions.egress {
            let mut rules = Vec::<PolicyRule>::new();
            for (rule_index, egress) in spec.egress.unwrap_or_default().into_iter().enumerate() {
                let destinations = destinations(egress.to, &namespace, rule_index)?;
                let ports = ports(egress.ports, rule_index)?;
                for destination in destinations {
                    for (protocol, port) in &ports {
                        push_rule(
                            &mut rules,
                            policy_id,
                            &name,
                            &namespace,
                            target.clone(),
                            destination.clone(),
                            *protocol,
                            port.clone(),
                            PolicyAction::Allow,
                            rule_index,
                        )
                        .map_err(|_| NetworkPolicyCompileError::TooManyRules)?;
                    }
                }
            }
            policies.push(compatibility_policy_ir(
                policy_id,
                &name,
                &namespace,
                PolicyDirection::Egress,
                target,
                rules,
            ));
        }

        Ok(policies)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PolicyDirections {
    ingress: bool,
    egress: bool,
}

fn policy_directions(
    policy_types: Option<&[String]>,
    egress: Option<&[NetworkPolicyEgressRule]>,
) -> Result<PolicyDirections, NetworkPolicyCompileError> {
    if policy_types.is_none_or(<[String]>::is_empty) {
        return Ok(PolicyDirections {
            ingress: true,
            egress: egress.is_some_and(|rules| !rules.is_empty()),
        });
    }

    let mut directions = PolicyDirections {
        ingress: false,
        egress: false,
    };
    if let Some(policy_types) = policy_types {
        for policy_type in policy_types {
            match policy_type.as_str() {
                "Ingress" => directions.ingress = true,
                "Egress" => directions.egress = true,
                _ => {
                    return Err(NetworkPolicyCompileError::UnsupportedPolicyType {
                        policy_type: policy_type.clone(),
                    });
                }
            }
        }
    }
    Ok(directions)
}

fn compatibility_policy_ir(
    policy_id: PolicyId,
    name: &str,
    namespace: &str,
    direction: PolicyDirection,
    target: IdentitySelector,
    rules: Vec<PolicyRule>,
) -> PolicyIr {
    PolicyIr {
        id: policy_id,
        name: name.to_owned(),
        namespace: namespace.to_owned(),
        priority: KUBERNETES_NETWORK_POLICY_PRIORITY,
        origin: PolicyOrigin::KubernetesNetworkPolicy,
        direction,
        target,
        default_action: PolicyAction::Deny,
        enforcement_mode: PolicyEnforcementMode::Enforce,
        rules,
    }
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

fn destinations(
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
    if let Some(cidr) = parse_ipv6_cidr(&cidr_text) {
        let mut except = ip_block
            .except
            .unwrap_or_default()
            .into_iter()
            .map(|except_text| {
                let except = parse_ipv6_cidr(&except_text).ok_or_else(|| {
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
        let prefix_count = 1 + except.len();
        if prefix_count > KUBERNETES_NETWORK_POLICY_MAX_IPV6_IP_BLOCK_PREFIXES {
            return Err(NetworkPolicyCompileError::Ipv6IpBlockTooManyPrefixes {
                rule_index,
                peer_index,
                prefix_count,
                limit: KUBERNETES_NETWORK_POLICY_MAX_IPV6_IP_BLOCK_PREFIXES,
            });
        }
        return Ok(IdentitySelector {
            ipv6_blocks: vec![Ipv6Block { cidr, except }],
            ..IdentitySelector::default()
        });
    }
    let cidr = parse_ipv4_cidr(&cidr_text).ok_or_else(|| {
        NetworkPolicyCompileError::InvalidIpBlockCidr {
            rule_index,
            peer_index,
            cidr: cidr_text.clone(),
        }
    })?;
    let address_count = cidr.address_count();
    if cidr.prefix_len != 0 && cidr.contains(Ipv4Addr::UNSPECIFIED) {
        return Err(NetworkPolicyCompileError::IpBlockContainsReservedAddress {
            rule_index,
            peer_index,
        });
    }
    if cidr.prefix_len != 0 && address_count > KUBERNETES_NETWORK_POLICY_MAX_IP_BLOCK_ADDRESSES {
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
    validate_global_ipv4_exceptions(&cidr, &except, rule_index, peer_index)?;
    Ok(IdentitySelector {
        ipv4_blocks: vec![Ipv4Block { cidr, except }],
        ..IdentitySelector::default()
    })
}

fn validate_global_ipv4_exceptions(
    cidr: &Ipv4Cidr,
    except: &[Ipv4Cidr],
    rule_index: usize,
    peer_index: usize,
) -> Result<(), NetworkPolicyCompileError> {
    if cidr.prefix_len != 0 {
        return Ok(());
    }
    let address_count = except
        .iter()
        .try_fold(0_u64, |total, item| total.checked_add(item.address_count()));
    if address_count.is_some_and(|count| count <= KUBERNETES_NETWORK_POLICY_MAX_IP_BLOCK_ADDRESSES)
    {
        return Ok(());
    }
    Err(NetworkPolicyCompileError::IpBlockTooLarge {
        rule_index,
        peer_index,
        address_count: address_count.unwrap_or(u64::MAX),
        limit: KUBERNETES_NETWORK_POLICY_MAX_IP_BLOCK_ADDRESSES,
    })
}

fn parse_ipv6_cidr(value: &str) -> Option<Ipv6Cidr> {
    let (address, prefix_len) = value.split_once('/')?;
    let address: Ipv6Addr = address.parse().ok()?;
    let prefix_len: u8 = prefix_len.parse().ok()?;
    if prefix_len > 128 {
        return None;
    }
    let mask = if prefix_len == 0 {
        0
    } else {
        u128::MAX << (128 - prefix_len)
    };
    Some(Ipv6Cidr {
        network: Ipv6Addr::from(u128::from(address) & mask),
        prefix_len,
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
        "SCTP" => Protocol::Sctp,
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
                    if start == 1 && end == u16::MAX {
                        return Ok((Some(protocol), DestinationPort::Any));
                    }
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

    use k8s_openapi::api::networking::v1::{
        IPBlock, NetworkPolicyEgressRule, NetworkPolicyIngressRule, NetworkPolicySpec,
    };
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::{LabelSelectorRequirement, ObjectMeta};
    use unf_common::{IdentityId, PolicyReason, Verdict};

    use super::*;
    use crate::{
        DestinationAddresses, Endpoint, Flow, Ipv4Endpoint, Ipv6Endpoint, NamedPort,
        PolicyDecision, compile_dataplane_entries, compile_egress_ipv4_dataplane_entries,
        compile_egress_ipv6_dataplane_entries, compile_ipv4_dataplane_entries,
        compile_ipv6_dataplane_entries, evaluate, evaluate_for_direction,
        evaluate_for_direction_with_addresses,
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

    fn egress_policy(
        egress: Option<Vec<NetworkPolicyEgressRule>>,
        policy_types: Option<Vec<&str>>,
    ) -> NetworkPolicy {
        NetworkPolicy {
            metadata: ObjectMeta {
                name: Some("allow-server".to_owned()),
                namespace: Some("frontend".to_owned()),
                ..ObjectMeta::default()
            },
            spec: Some(NetworkPolicySpec {
                pod_selector: Some(selector(&[("app", "client")])),
                egress,
                policy_types: policy_types
                    .map(|types| types.into_iter().map(str::to_owned).collect::<Vec<_>>()),
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

    fn evaluate_egress_with_addresses(
        policies: &[PolicyIr],
        source: &Endpoint,
        destination: &Endpoint,
        destination_addresses: DestinationAddresses,
    ) -> PolicyDecision {
        evaluate_for_direction_with_addresses(
            policies,
            PolicyDirection::Egress,
            Flow {
                source,
                destination,
                protocol: Protocol::Tcp,
                destination_port: 443,
                source_ipv4: None,
                source_ipv6: None,
            },
            destination_addresses,
        )
    }

    #[test]
    fn egress_translation_selects_source_and_preserves_peer_port_pairing() {
        let peer = NetworkPolicyPeer {
            namespace_selector: Some(selector(&[(NAMESPACE_NAME_LABEL, "backend")])),
            pod_selector: Some(selector(&[("app", "server")])),
            ..NetworkPolicyPeer::default()
        };
        let translated = NetworkPolicyCompiler::compile_directions(
            PolicyId::new(51),
            egress_policy(
                Some(vec![NetworkPolicyEgressRule {
                    to: Some(vec![peer]),
                    ports: Some(vec![NetworkPolicyPort {
                        port: Some(IntOrString::Int(8080)),
                        protocol: Some("TCP".to_owned()),
                        ..NetworkPolicyPort::default()
                    }]),
                }]),
                Some(vec!["Egress"]),
            ),
        )
        .expect("supported egress policy translates");
        assert_eq!(translated.len(), 1);
        let compiled = &translated[0];
        assert_eq!(compiled.direction, PolicyDirection::Egress);
        assert_eq!(compiled.target.namespace.as_deref(), Some("frontend"));
        assert_eq!(compiled.target.match_labels, labels(&[("app", "client")]));
        assert_eq!(compiled.rules.len(), 1);
        assert_eq!(
            compiled.rules[0].destination.namespace.as_deref(),
            Some("backend")
        );
        assert_eq!(
            compiled.rules[0].destination.match_labels,
            labels(&[("app", "server")])
        );

        let source = endpoint(1, "frontend", "client");
        let destination = endpoint(2, "backend", "server");
        let database = endpoint(3, "backend", "database");
        let allowed = evaluate_for_direction(
            &translated,
            PolicyDirection::Egress,
            Flow {
                source: &source,
                destination: &destination,
                protocol: Protocol::Tcp,
                destination_port: 8080,
                source_ipv4: None,
                source_ipv6: None,
            },
        );
        assert_eq!(allowed.verdict, Verdict::Allow);
        assert_eq!(allowed.policy_id, Some(PolicyId::new(51)));
        let denied = evaluate_for_direction(
            &translated,
            PolicyDirection::Egress,
            Flow {
                source: &source,
                destination: &database,
                protocol: Protocol::Tcp,
                destination_port: 8080,
                source_ipv4: None,
                source_ipv6: None,
            },
        );
        assert_eq!(denied.verdict, Verdict::Deny);
        assert_eq!(denied.reason, PolicyReason::DefaultAction);
    }

    #[test]
    fn policy_type_defaulting_matches_kubernetes_api_behavior() {
        let no_egress =
            NetworkPolicyCompiler::compile_directions(PolicyId::new(52), egress_policy(None, None))
                .expect("omitted types default to ingress");
        assert_eq!(
            no_egress
                .iter()
                .map(|policy| policy.direction)
                .collect::<Vec<_>>(),
            vec![PolicyDirection::Ingress]
        );

        let empty_types = NetworkPolicyCompiler::compile_directions(
            PolicyId::new(52),
            egress_policy(None, Some(Vec::new())),
        )
        .expect("empty types receive API defaults");
        assert_eq!(empty_types[0].direction, PolicyDirection::Ingress);

        let empty_egress = NetworkPolicyCompiler::compile_directions(
            PolicyId::new(52),
            egress_policy(Some(Vec::new()), None),
        )
        .expect("empty egress list does not imply egress");
        assert_eq!(empty_egress.len(), 1);
        assert_eq!(empty_egress[0].direction, PolicyDirection::Ingress);

        let defaulted_both = NetworkPolicyCompiler::compile_directions(
            PolicyId::new(52),
            egress_policy(Some(vec![NetworkPolicyEgressRule::default()]), None),
        )
        .expect("non-empty egress defaults both directions");
        assert_eq!(
            defaulted_both
                .iter()
                .map(|policy| policy.direction)
                .collect::<Vec<_>>(),
            vec![PolicyDirection::Ingress, PolicyDirection::Egress]
        );
        assert!(defaulted_both[0].rules.is_empty());
        assert_eq!(defaulted_both[1].rules.len(), 1);
        assert_eq!(
            defaulted_both[1].rules[0].destination,
            IdentitySelector::default()
        );
        assert_eq!(defaulted_both[1].rules[0].protocol, None);
        assert_eq!(
            defaulted_both[1].rules[0].destination_port,
            DestinationPort::Any
        );

        let explicit_egress_deny = NetworkPolicyCompiler::compile_directions(
            PolicyId::new(52),
            egress_policy(None, Some(vec!["Egress"])),
        )
        .expect("explicit egress with no rules is default deny");
        assert_eq!(explicit_egress_deny.len(), 1);
        assert_eq!(explicit_egress_deny[0].direction, PolicyDirection::Egress);
        assert!(explicit_egress_deny[0].rules.is_empty());

        let explicit_both = NetworkPolicyCompiler::compile_directions(
            PolicyId::new(52),
            egress_policy(None, Some(vec!["Ingress", "Egress"])),
        )
        .expect("explicit types isolate both directions without rules");
        assert_eq!(
            explicit_both
                .iter()
                .map(|policy| policy.direction)
                .collect::<Vec<_>>(),
            vec![PolicyDirection::Ingress, PolicyDirection::Egress]
        );
        assert!(explicit_both.iter().all(|policy| policy.rules.is_empty()));

        let ingress_only = NetworkPolicyCompiler::compile_directions(
            PolicyId::new(52),
            egress_policy(
                Some(vec![NetworkPolicyEgressRule::default()]),
                Some(vec!["Ingress"]),
            ),
        )
        .expect("explicit ingress ignores egress rules");
        assert_eq!(ingress_only.len(), 1);
        assert_eq!(ingress_only[0].direction, PolicyDirection::Ingress);

        assert_eq!(
            NetworkPolicyCompiler::compile_directions(
                PolicyId::new(52),
                egress_policy(None, Some(vec!["Audit"])),
            ),
            Err(NetworkPolicyCompileError::UnsupportedPolicyType {
                policy_type: "Audit".to_owned(),
            })
        );
    }

    #[test]
    fn egress_ipv4_ipblock_applies_destination_exceptions_and_address_invariants() {
        let ipv4_policy = egress_policy(
            Some(vec![NetworkPolicyEgressRule {
                to: Some(vec![NetworkPolicyPeer {
                    ip_block: Some(IPBlock {
                        cidr: "10.0.0.0/29".to_owned(),
                        except: Some(vec!["10.0.0.4/32".to_owned()]),
                    }),
                    ..NetworkPolicyPeer::default()
                }]),
                ports: None,
            }]),
            Some(vec!["Egress"]),
        );
        let ipv4 = NetworkPolicyCompiler::compile_directions(PolicyId::new(53), ipv4_policy)
            .expect("bounded IPv4 destination block translates");
        let source = endpoint(1, "frontend", "client");
        let destination = endpoint(0, "external", "external");

        assert_eq!(
            evaluate_egress_with_addresses(
                &ipv4,
                &source,
                &destination,
                DestinationAddresses {
                    ipv4: Some("10.0.0.3".parse().expect("valid IPv4 address")),
                    ipv6: None,
                },
            )
            .verdict,
            Verdict::Allow
        );
        for address in ["10.0.0.4", "10.0.1.1"] {
            let decision = evaluate_egress_with_addresses(
                &ipv4,
                &source,
                &destination,
                DestinationAddresses {
                    ipv4: Some(address.parse().expect("valid IPv4 address")),
                    ipv6: None,
                },
            );
            assert_eq!(decision.verdict, Verdict::Deny);
            assert_eq!(decision.reason, PolicyReason::DefaultAction);
        }
        for destination_addresses in [
            DestinationAddresses::default(),
            DestinationAddresses {
                ipv4: Some("10.0.0.3".parse().expect("valid IPv4 address")),
                ipv6: Some("2001:db8::3".parse().expect("valid IPv6 address")),
            },
        ] {
            assert_eq!(
                evaluate_egress_with_addresses(
                    &ipv4,
                    &source,
                    &destination,
                    destination_addresses,
                )
                .verdict,
                Verdict::Deny
            );
        }
    }

    #[test]
    fn egress_ipv6_ipblock_applies_destination_exceptions() {
        let ipv6_policy = egress_policy(
            Some(vec![NetworkPolicyEgressRule {
                to: Some(vec![NetworkPolicyPeer {
                    ip_block: Some(IPBlock {
                        cidr: "2001:db8::/64".to_owned(),
                        except: Some(vec!["2001:db8::5/128".to_owned()]),
                    }),
                    ..NetworkPolicyPeer::default()
                }]),
                ports: None,
            }]),
            Some(vec!["Egress"]),
        );
        let ipv6 = NetworkPolicyCompiler::compile_directions(PolicyId::new(54), ipv6_policy)
            .expect("bounded IPv6 destination block translates");
        let source = endpoint(1, "frontend", "client");
        let destination = endpoint(0, "external", "external");
        assert_eq!(
            evaluate_egress_with_addresses(
                &ipv6,
                &source,
                &destination,
                DestinationAddresses {
                    ipv4: None,
                    ipv6: Some("2001:db8::4".parse().expect("valid IPv6 address")),
                },
            )
            .verdict,
            Verdict::Allow
        );
        assert_eq!(
            evaluate_egress_with_addresses(
                &ipv6,
                &source,
                &destination,
                DestinationAddresses {
                    ipv4: None,
                    ipv6: Some("2001:db8::5".parse().expect("valid IPv6 address")),
                },
            )
            .verdict,
            Verdict::Deny
        );
    }

    #[test]
    fn egress_allow_all_and_overlapping_cidrs_are_additive() {
        let deny = NetworkPolicyCompiler::compile_directions(
            PolicyId::new(60),
            egress_policy(None, Some(vec!["Egress"])),
        )
        .expect("empty egress policy isolates its selected source");
        let allow_all = NetworkPolicyCompiler::compile_directions(
            PolicyId::new(61),
            egress_policy(
                Some(vec![NetworkPolicyEgressRule::default()]),
                Some(vec!["Egress"]),
            ),
        )
        .expect("empty egress rule allows every destination");
        let source = endpoint(1, "frontend", "client");
        let destination = endpoint(0, "external", "external");
        let allow_all_policies = [deny[0].clone(), allow_all[0].clone()];
        assert_eq!(
            evaluate_egress_with_addresses(
                &allow_all_policies,
                &source,
                &destination,
                DestinationAddresses {
                    ipv4: Some("203.0.113.20".parse().expect("valid IPv4 address")),
                    ipv6: None,
                },
            )
            .verdict,
            Verdict::Allow
        );

        let cidr_policy = |id, cidr: &str| {
            NetworkPolicyCompiler::compile_directions(
                PolicyId::new(id),
                egress_policy(
                    Some(vec![NetworkPolicyEgressRule {
                        to: Some(vec![NetworkPolicyPeer {
                            ip_block: Some(IPBlock {
                                cidr: cidr.to_owned(),
                                except: None,
                            }),
                            ..NetworkPolicyPeer::default()
                        }]),
                        ports: None,
                    }]),
                    Some(vec!["Egress"]),
                ),
            )
            .expect("bounded egress CIDR policy translates")
            .remove(0)
        };
        let overlapping = [
            cidr_policy(62, "10.0.0.0/24"),
            cidr_policy(63, "10.0.0.0/25"),
        ];
        assert_eq!(
            evaluate_egress_with_addresses(
                &overlapping,
                &source,
                &destination,
                DestinationAddresses {
                    ipv4: Some("10.0.0.20".parse().expect("valid IPv4 address")),
                    ipv6: None,
                },
            )
            .verdict,
            Verdict::Allow
        );
        assert_eq!(
            evaluate_egress_with_addresses(
                &overlapping,
                &source,
                &destination,
                DestinationAddresses {
                    ipv4: Some("10.0.1.20".parse().expect("valid IPv4 address")),
                    ipv6: None,
                },
            )
            .verdict,
            Verdict::Deny
        );
    }

    #[test]
    fn egress_ipv4_lowering_is_source_selected_and_preserves_exceptions() {
        let policy = egress_policy(
            Some(vec![NetworkPolicyEgressRule {
                to: Some(vec![NetworkPolicyPeer {
                    ip_block: Some(IPBlock {
                        cidr: "10.0.0.0/30".to_owned(),
                        except: Some(vec!["10.0.0.2/32".to_owned()]),
                    }),
                    ..NetworkPolicyPeer::default()
                }]),
                ports: Some(vec![NetworkPolicyPort {
                    protocol: Some("TCP".to_owned()),
                    port: Some(IntOrString::Int(443)),
                    ..NetworkPolicyPort::default()
                }]),
            }]),
            Some(vec!["Egress"]),
        );
        let policies = NetworkPolicyCompiler::compile_directions(PolicyId::new(55), policy)
            .expect("egress IPv4 policy translates");
        let source = endpoint(1, "frontend", "client");
        let unselected = endpoint(2, "frontend", "job");
        let entries = compile_egress_ipv4_dataplane_entries(&policies, &[source, unselected], &[])
            .expect("egress IPv4 policy lowers");

        assert!(
            entries
                .iter()
                .all(|entry| entry.key.source_identity == IdentityId::new(1))
        );
        assert!(entries.iter().any(|entry| {
            entry.key.destination_address == "10.0.0.1".parse::<Ipv4Addr>().expect("valid IPv4")
                && entry.key.protocol == Protocol::Tcp as u8
                && entry.key.destination_port == 443
                && entry.decision.verdict == Verdict::Allow
        }));
        assert!(entries.iter().any(|entry| {
            entry.key.destination_address == Ipv4Addr::UNSPECIFIED
                && entry.key.protocol == 0
                && entry.key.destination_port == 0
                && entry.decision.verdict == Verdict::Deny
                && entry.decision.reason == PolicyReason::DefaultAction
        }));
        assert!(entries.iter().all(|entry| {
            entry.key.destination_address != "10.0.0.2".parse::<Ipv4Addr>().expect("valid IPv4")
                || entry.decision.verdict != Verdict::Allow
        }));
    }

    #[test]
    fn egress_ipv4_global_block_uses_fallback_and_exact_exceptions() {
        let policy = egress_policy(
            Some(vec![NetworkPolicyEgressRule {
                to: Some(vec![NetworkPolicyPeer {
                    ip_block: Some(IPBlock {
                        cidr: "0.0.0.0/0".to_owned(),
                        except: Some(vec!["203.0.113.7/32".to_owned()]),
                    }),
                    ..NetworkPolicyPeer::default()
                }]),
                ports: Some(vec![NetworkPolicyPort {
                    protocol: Some("TCP".to_owned()),
                    port: Some(IntOrString::Int(1)),
                    end_port: Some(i32::from(u16::MAX)),
                }]),
            }]),
            Some(vec!["Egress"]),
        );
        let policies = NetworkPolicyCompiler::compile_directions(PolicyId::new(58), policy)
            .expect("global IPv4 block and full transport range translate");
        assert_eq!(policies[0].rules[0].destination_port, DestinationPort::Any);

        let source = endpoint(1, "frontend", "client");
        let entries = compile_egress_ipv4_dataplane_entries(&policies, &[source], &[])
            .expect("global IPv4 block lowers without address expansion");
        assert!(entries.iter().any(|entry| {
            entry.key.destination_address == Ipv4Addr::UNSPECIFIED
                && entry.key.protocol == Protocol::Tcp as u8
                && entry.key.destination_port == 0
                && entry.decision.verdict == Verdict::Allow
        }));
        assert!(entries.iter().any(|entry| {
            entry.key.destination_address
                == "203.0.113.7".parse::<Ipv4Addr>().expect("valid exception")
                && entry.key.protocol == 0
                && entry.key.destination_port == 0
                && entry.decision.verdict == Verdict::Deny
        }));
    }

    #[test]
    fn egress_named_port_lowering_uses_destination_metadata() {
        let policy = egress_policy(
            Some(vec![NetworkPolicyEgressRule {
                to: Some(vec![NetworkPolicyPeer {
                    namespace_selector: Some(selector(&[(NAMESPACE_NAME_LABEL, "backend")])),
                    pod_selector: Some(selector(&[("app", "server")])),
                    ..NetworkPolicyPeer::default()
                }]),
                ports: Some(vec![NetworkPolicyPort {
                    protocol: Some("TCP".to_owned()),
                    port: Some(IntOrString::String("https".to_owned())),
                    ..NetworkPolicyPort::default()
                }]),
            }]),
            Some(vec!["Egress"]),
        );
        let policies = NetworkPolicyCompiler::compile_directions(PolicyId::new(56), policy)
            .expect("named-port egress policy translates");
        let source = endpoint(1, "frontend", "client");
        let mut destination = endpoint(2, "backend", "server");
        destination.named_ports.insert(
            NamedPort {
                name: "https".to_owned(),
                protocol: Protocol::Tcp,
            },
            8443,
        );
        let entries = compile_egress_ipv4_dataplane_entries(
            &policies,
            &[source.clone(), destination.clone()],
            &[Ipv4Endpoint {
                address: "10.244.1.10".parse().expect("valid Pod IPv4"),
                endpoint: destination,
            }],
        )
        .expect("named-port egress policy lowers");

        assert!(entries.iter().any(|entry| {
            entry.key.source_identity == source.identity
                && entry.key.destination_address
                    == "10.244.1.10".parse::<Ipv4Addr>().expect("valid Pod IPv4")
                && entry.key.protocol == Protocol::Tcp as u8
                && entry.key.destination_port == 8443
                && entry.decision.verdict == Verdict::Allow
        }));
    }

    #[test]
    fn egress_ipv6_lowering_uses_destination_prefixes_and_exceptions() {
        let policy = egress_policy(
            Some(vec![NetworkPolicyEgressRule {
                to: Some(vec![NetworkPolicyPeer {
                    ip_block: Some(IPBlock {
                        cidr: "2001:db8::/126".to_owned(),
                        except: Some(vec!["2001:db8::2/128".to_owned()]),
                    }),
                    ..NetworkPolicyPeer::default()
                }]),
                ports: Some(vec![NetworkPolicyPort {
                    protocol: Some("TCP".to_owned()),
                    port: Some(IntOrString::Int(443)),
                    ..NetworkPolicyPort::default()
                }]),
            }]),
            Some(vec!["Egress"]),
        );
        let policies = NetworkPolicyCompiler::compile_directions(PolicyId::new(57), policy)
            .expect("egress IPv6 policy translates");
        let source = endpoint(1, "frontend", "client");
        let entries = compile_egress_ipv6_dataplane_entries(&policies, &[source], &[])
            .expect("egress IPv6 policy lowers");

        assert!(entries.iter().any(|entry| {
            entry.key.destination_network == "2001:db8::".parse::<Ipv6Addr>().expect("valid IPv6")
                && entry.key.destination_prefix_len == 126
                && entry.key.protocol == Protocol::Tcp as u8
                && entry.key.destination_port == 443
                && entry.decision.verdict == Verdict::Allow
        }));
        assert!(entries.iter().any(|entry| {
            entry.key.destination_network == "2001:db8::2".parse::<Ipv6Addr>().expect("valid IPv6")
                && entry.key.destination_prefix_len == 128
                && entry.key.protocol == 0
                && entry.key.destination_port == 0
                && entry.decision.verdict == Verdict::Deny
        }));
        assert!(entries.iter().any(|entry| {
            entry.key.destination_network == Ipv6Addr::UNSPECIFIED
                && entry.key.destination_prefix_len == 0
                && entry.decision.verdict == Verdict::Deny
        }));
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
                source_ipv6: None,
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
                source_ipv6: None,
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
                    source_ipv6: None,
                }
            )
            .verdict,
            Verdict::Deny
        );
    }

    #[test]
    fn policy_update_replaces_allow_all_with_default_deny_and_recovers() {
        let source = endpoint(1, "frontend", "client");
        let destination = endpoint(2, "backend", "server");
        let decision = |compiled: &PolicyIr| {
            evaluate(
                std::slice::from_ref(compiled),
                Flow {
                    source: &source,
                    destination: &destination,
                    protocol: Protocol::Tcp,
                    destination_port: 8080,
                    source_ipv4: None,
                    source_ipv6: None,
                },
            )
        };
        let mut updated_policy = policy(vec![NetworkPolicyIngressRule::default()]);
        updated_policy.metadata.name = Some("allow-all-mutate-to-deny-all".to_owned());

        let allow_all = NetworkPolicyCompiler::compile(PolicyId::new(8), updated_policy.clone())
            .expect("allow-all policy compiles");
        assert_eq!(decision(&allow_all).verdict, Verdict::Allow);
        assert_eq!(decision(&allow_all).reason, PolicyReason::ExplicitRule);

        updated_policy
            .spec
            .as_mut()
            .expect("updated policy has spec")
            .ingress = Some(Vec::new());
        let default_deny = NetworkPolicyCompiler::compile(PolicyId::new(8), updated_policy.clone())
            .expect("updated default-deny policy compiles");
        assert_eq!(decision(&default_deny).verdict, Verdict::Deny);
        assert_eq!(decision(&default_deny).reason, PolicyReason::DefaultAction);

        updated_policy
            .spec
            .as_mut()
            .expect("updated policy has spec")
            .ingress = Some(vec![NetworkPolicyIngressRule::default()]);
        let recovered = NetworkPolicyCompiler::compile(PolicyId::new(8), updated_policy)
            .expect("restored allow-all policy compiles");
        assert_eq!(decision(&recovered).verdict, Verdict::Allow);
        assert_eq!(decision(&recovered).policy_id, Some(PolicyId::new(8)));
    }

    #[test]
    fn target_label_lifecycle_changes_policy_applicability() {
        let mut lifecycle_policy = policy(Vec::new());
        lifecycle_policy
            .spec
            .as_mut()
            .expect("test policy has spec")
            .pod_selector = Some(selector(&[("conformance-target", "isolated")]));
        let compiled = NetworkPolicyCompiler::compile(PolicyId::new(8), lifecycle_policy)
            .expect("target-label policy compiles");
        let source = endpoint(1, "frontend", "client");
        let mut destination = endpoint(2, "backend", "server");
        let decision = |destination: &Endpoint| {
            evaluate(
                std::slice::from_ref(&compiled),
                Flow {
                    source: &source,
                    destination,
                    protocol: Protocol::Tcp,
                    destination_port: 8087,
                    source_ipv4: None,
                    source_ipv6: None,
                },
            )
        };

        let unselected = decision(&destination);
        assert_eq!(unselected.verdict, Verdict::Allow);
        assert_eq!(unselected.reason, PolicyReason::NoApplicablePolicy);

        destination
            .labels
            .insert("conformance-target".to_owned(), "isolated".to_owned());
        let selected = decision(&destination);
        assert_eq!(selected.verdict, Verdict::Deny);
        assert_eq!(selected.reason, PolicyReason::DefaultAction);

        destination.labels.remove("conformance-target");
        let recovered = decision(&destination);
        assert_eq!(recovered.verdict, Verdict::Allow);
        assert_eq!(recovered.reason, PolicyReason::NoApplicablePolicy);
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
                    source_ipv6: None,
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
                    source_ipv6: None,
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
                    source_ipv6: None,
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
            source_ipv6: None,
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
                    source_ipv6: None,
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
    fn target_specific_allow_overrides_broad_default_deny_only_for_its_target() {
        let mut broad_policy = policy(Vec::new());
        broad_policy.metadata.name = Some("broad-default-deny".to_owned());
        broad_policy
            .spec
            .as_mut()
            .expect("broad policy has spec")
            .pod_selector = Some(LabelSelector::default());
        let broad = NetworkPolicyCompiler::compile(PolicyId::new(9), broad_policy)
            .expect("broad default-deny policy compiles");

        let mut narrow_policy = policy(vec![NetworkPolicyIngressRule {
            from: Some(vec![NetworkPolicyPeer {
                pod_selector: Some(LabelSelector::default()),
                namespace_selector: Some(LabelSelector::default()),
                ..NetworkPolicyPeer::default()
            }]),
            ports: None,
        }]);
        narrow_policy.metadata.name = Some("target-specific-allow".to_owned());
        let narrow = NetworkPolicyCompiler::compile(PolicyId::new(10), narrow_policy)
            .expect("target-specific allow policy compiles");

        let remote_source = endpoint(1, "frontend", "client");
        let same_namespace_source = endpoint(4, "backend", "client");
        let server = endpoint(2, "backend", "server");
        let alternate = endpoint(3, "backend", "alternate");
        let policies = [broad, narrow];
        let decision = |source: &Endpoint, destination: &Endpoint| {
            evaluate(
                &policies,
                Flow {
                    source,
                    destination,
                    protocol: Protocol::Tcp,
                    destination_port: 8080,
                    source_ipv4: None,
                    source_ipv6: None,
                },
            )
        };

        for source in [&remote_source, &same_namespace_source] {
            let allowed = decision(source, &server);
            assert_eq!(allowed.verdict, Verdict::Allow);
            assert_eq!(allowed.reason, PolicyReason::ExplicitRule);
            let denied = decision(source, &alternate);
            assert_eq!(denied.verdict, Verdict::Deny);
            assert_eq!(denied.reason, PolicyReason::DefaultAction);
        }

        let entries = compile_dataplane_entries(
            &policies,
            &[remote_source, same_namespace_source, server, alternate],
        )
        .expect("target-specific exception lowers into destination-specific entries");
        assert!(entries.iter().any(|entry| {
            entry.key.source_identity == IdentityId::new(1)
                && entry.key.destination_identity == IdentityId::new(2)
                && entry.key.protocol == 0
                && entry.key.destination_port == 0
                && entry.decision.verdict == Verdict::Allow
        }));
        assert!(entries.iter().any(|entry| {
            entry.key.source_identity == IdentityId::new(1)
                && entry.key.destination_identity == IdentityId::new(3)
                && entry.key.protocol == 0
                && entry.key.destination_port == 0
                && entry.decision.verdict == Verdict::Deny
        }));
    }

    #[test]
    fn overlapping_target_selectors_combine_only_on_their_intersection() {
        let rule = |port| NetworkPolicyIngressRule {
            from: None,
            ports: Some(vec![NetworkPolicyPort {
                port: Some(IntOrString::Int(port)),
                ..NetworkPolicyPort::default()
            }]),
        };
        let mut broad_policy = policy(vec![rule(8080)]);
        broad_policy.metadata.name = Some("broad-target".to_owned());
        broad_policy
            .spec
            .as_mut()
            .expect("broad policy has spec")
            .pod_selector = Some(LabelSelector {
            match_expressions: Some(vec![expression("app", "Exists", &[])]),
            ..LabelSelector::default()
        });
        let broad = NetworkPolicyCompiler::compile(PolicyId::new(9), broad_policy)
            .expect("broad target policy compiles");

        let mut narrow_policy = policy(vec![rule(8081)]);
        narrow_policy.metadata.name = Some("narrow-target".to_owned());
        let narrow = NetworkPolicyCompiler::compile(PolicyId::new(10), narrow_policy)
            .expect("narrow target policy compiles");

        let source = endpoint(1, "frontend", "client");
        let server = endpoint(2, "backend", "server");
        let alternate = endpoint(3, "backend", "alternate");
        let policies = [broad, narrow];
        let verdict = |destination: &Endpoint, port| {
            evaluate(
                &policies,
                Flow {
                    source: &source,
                    destination,
                    protocol: Protocol::Tcp,
                    destination_port: port,
                    source_ipv4: None,
                    source_ipv6: None,
                },
            )
            .verdict
        };

        assert_eq!(verdict(&server, 8080), Verdict::Allow);
        assert_eq!(verdict(&server, 8081), Verdict::Allow);
        assert_eq!(verdict(&alternate, 8080), Verdict::Allow);
        assert_eq!(verdict(&alternate, 8081), Verdict::Deny);

        let entries = compile_dataplane_entries(&policies, &[source, server, alternate])
            .expect("overlapping target policies lower into destination-specific entries");
        assert!(entries.iter().any(|entry| {
            entry.key.destination_identity == IdentityId::new(2)
                && entry.key.destination_port == 8081
                && entry.decision.verdict == Verdict::Allow
        }));
        assert!(!entries.iter().any(|entry| {
            entry.key.destination_identity == IdentityId::new(3)
                && entry.key.destination_port == 8081
                && entry.decision.verdict == Verdict::Allow
        }));
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
    fn explicit_empty_sources_and_ports_are_wildcards() {
        let compiled = NetworkPolicyCompiler::compile(
            PolicyId::new(7),
            policy(vec![NetworkPolicyIngressRule {
                from: Some(Vec::new()),
                ports: Some(Vec::new()),
            }]),
        )
        .expect("explicit empty source and port lists compile");
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
                        source_ipv6: None,
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
                    source_ipv6: None,
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
    fn sctp_named_and_protocol_only_ports_evaluate_and_lower() {
        let named = NetworkPolicyCompiler::compile(
            PolicyId::new(7),
            policy(vec![NetworkPolicyIngressRule {
                from: None,
                ports: Some(vec![NetworkPolicyPort {
                    protocol: Some("SCTP".to_owned()),
                    port: Some(IntOrString::String("association".to_owned())),
                    ..NetworkPolicyPort::default()
                }]),
            }]),
        )
        .expect("named SCTP port compiles");
        let source = endpoint(1, "frontend", "client");
        let mut destination = endpoint(2, "backend", "server");
        destination.named_ports.insert(
            NamedPort {
                name: "association".to_owned(),
                protocol: Protocol::Sctp,
            },
            8086,
        );
        assert_eq!(
            evaluate(
                std::slice::from_ref(&named),
                Flow {
                    source: &source,
                    destination: &destination,
                    protocol: Protocol::Sctp,
                    destination_port: 8086,
                    source_ipv4: None,
                    source_ipv6: None,
                },
            )
            .verdict,
            Verdict::Allow
        );
        assert_eq!(
            evaluate(
                std::slice::from_ref(&named),
                Flow {
                    source: &source,
                    destination: &destination,
                    protocol: Protocol::Tcp,
                    destination_port: 8086,
                    source_ipv4: None,
                    source_ipv6: None,
                },
            )
            .verdict,
            Verdict::Deny
        );
        let entries = compile_dataplane_entries(&[named], &[source, destination])
            .expect("named SCTP port lowers into the identity policy map");
        assert!(entries.iter().any(|entry| {
            entry.key.protocol == Protocol::Sctp as u8
                && entry.key.destination_port == 8086
                && entry.decision.verdict == Verdict::Allow
        }));

        let protocol_only = NetworkPolicyCompiler::compile(
            PolicyId::new(8),
            policy(vec![NetworkPolicyIngressRule {
                from: None,
                ports: Some(vec![NetworkPolicyPort {
                    protocol: Some("SCTP".to_owned()),
                    ..NetworkPolicyPort::default()
                }]),
            }]),
        )
        .expect("protocol-only SCTP port compiles");
        assert_eq!(protocol_only.rules[0].protocol, Some(Protocol::Sctp));
        assert_eq!(
            protocol_only.rules[0].destination_port,
            DestinationPort::Any
        );
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
        let decision = |source: &Endpoint, destination: &Endpoint| {
            evaluate(
                std::slice::from_ref(&compiled),
                Flow {
                    source,
                    destination,
                    protocol: Protocol::Tcp,
                    destination_port: 8080,
                    source_ipv4: None,
                    source_ipv6: None,
                },
            )
        };
        assert_eq!(decision(&source, &destination).verdict, Verdict::Allow);

        destination
            .labels
            .insert("app".to_owned(), "database".to_owned());
        assert_eq!(
            decision(&source, &destination).reason,
            PolicyReason::NoApplicablePolicy
        );
        destination
            .labels
            .insert("app".to_owned(), "server".to_owned());

        destination
            .labels
            .insert("tier".to_owned(), "edge".to_owned());
        assert_eq!(
            decision(&source, &destination).reason,
            PolicyReason::NoApplicablePolicy
        );
        destination
            .labels
            .insert("tier".to_owned(), "core".to_owned());

        destination.labels.remove("managed");
        assert_eq!(
            decision(&source, &destination).reason,
            PolicyReason::NoApplicablePolicy
        );
        destination
            .labels
            .insert("managed".to_owned(), "true".to_owned());

        destination
            .labels
            .insert("skip".to_owned(), "true".to_owned());
        assert_eq!(
            decision(&source, &destination).reason,
            PolicyReason::NoApplicablePolicy
        );
        destination.labels.remove("skip");

        source.labels.insert("blocked".to_owned(), "yes".to_owned());
        assert_eq!(decision(&source, &destination).verdict, Verdict::Deny);
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
                    source_ipv6: None,
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
                    source_ipv6: None,
                },
            )
            .verdict,
            Verdict::Deny
        );
    }

    #[test]
    fn namespace_name_selectors_support_exact_and_not_in_matching() {
        let same_namespace = endpoint(1, "backend", "same-client");
        let source_a = endpoint(2, "source-a", "client");
        let source_b = endpoint(3, "source-b", "client");
        let destination = endpoint(4, "backend", "server");
        let verdict = |compiled: &PolicyIr, source: &Endpoint| {
            evaluate(
                std::slice::from_ref(compiled),
                Flow {
                    source,
                    destination: &destination,
                    protocol: Protocol::Tcp,
                    destination_port: 8087,
                    source_ipv4: None,
                    source_ipv6: None,
                },
            )
            .verdict
        };
        let compile = |selector| {
            NetworkPolicyCompiler::compile(
                PolicyId::new(15),
                policy(vec![NetworkPolicyIngressRule {
                    from: Some(vec![NetworkPolicyPeer {
                        namespace_selector: Some(selector),
                        ..NetworkPolicyPeer::default()
                    }]),
                    ports: None,
                }]),
            )
            .expect("Namespace selector compiles")
        };

        let exact_namespace = compile(selector(&[(NAMESPACE_NAME_LABEL, "source-a")]));
        assert_eq!(verdict(&exact_namespace, &source_a), Verdict::Allow);
        assert_eq!(verdict(&exact_namespace, &source_b), Verdict::Deny);
        assert_eq!(verdict(&exact_namespace, &same_namespace), Verdict::Deny);

        let namespace_not_in = compile(LabelSelector {
            match_expressions: Some(vec![expression(
                NAMESPACE_NAME_LABEL,
                "NotIn",
                &["backend", "source-b"],
            )]),
            ..LabelSelector::default()
        });
        assert_eq!(verdict(&namespace_not_in, &source_a), Verdict::Allow);
        assert_eq!(verdict(&namespace_not_in, &source_b), Verdict::Deny);
        assert_eq!(verdict(&namespace_not_in, &same_namespace), Verdict::Deny);
    }

    #[test]
    fn upstream_peer_matrix_preserves_namespace_scope_and_boolean_semantics() {
        let mut same_namespace = endpoint(1, "backend", "same-client");
        same_namespace.labels.extend(labels(&[("source", "same")]));
        let mut source_a = endpoint(2, "source-a", "client");
        source_a.labels.extend(labels(&[("source", "selected")]));
        source_a
            .namespace_labels
            .extend(labels(&[("conformance-group", "a")]));
        let mut source_b = endpoint(3, "source-b", "client");
        source_b.labels.extend(labels(&[("source", "selected")]));
        source_b
            .namespace_labels
            .extend(labels(&[("conformance-group", "b")]));
        let destination = endpoint(4, "backend", "server");
        let verdict = |compiled: &PolicyIr, source: &Endpoint| {
            evaluate(
                std::slice::from_ref(compiled),
                Flow {
                    source,
                    destination: &destination,
                    protocol: Protocol::Tcp,
                    destination_port: 8087,
                    source_ipv4: None,
                    source_ipv6: None,
                },
            )
            .verdict
        };

        let same_namespace_only = NetworkPolicyCompiler::compile(
            PolicyId::new(10),
            policy(vec![NetworkPolicyIngressRule {
                from: Some(vec![NetworkPolicyPeer {
                    pod_selector: Some(selector(&[("source", "same")])),
                    ..NetworkPolicyPeer::default()
                }]),
                ports: None,
            }]),
        )
        .expect("same-namespace PodSelector compiles");
        assert_eq!(
            verdict(&same_namespace_only, &same_namespace),
            Verdict::Allow
        );
        assert_eq!(verdict(&same_namespace_only, &source_a), Verdict::Deny);

        let every_namespace = NetworkPolicyCompiler::compile(
            PolicyId::new(11),
            policy(vec![NetworkPolicyIngressRule {
                from: Some(vec![NetworkPolicyPeer {
                    namespace_selector: Some(LabelSelector::default()),
                    ..NetworkPolicyPeer::default()
                }]),
                ports: None,
            }]),
        )
        .expect("empty NamespaceSelector compiles");
        for source in [&same_namespace, &source_a, &source_b] {
            assert_eq!(verdict(&every_namespace, source), Verdict::Allow);
        }

        let selectors_and = NetworkPolicyCompiler::compile(
            PolicyId::new(12),
            policy(vec![NetworkPolicyIngressRule {
                from: Some(vec![NetworkPolicyPeer {
                    namespace_selector: Some(selector(&[("conformance-group", "a")])),
                    pod_selector: Some(selector(&[("source", "selected")])),
                    ..NetworkPolicyPeer::default()
                }]),
                ports: None,
            }]),
        )
        .expect("combined PodSelector and NamespaceSelector compiles");
        assert_eq!(verdict(&selectors_and, &source_a), Verdict::Allow);
        assert_eq!(verdict(&selectors_and, &source_b), Verdict::Deny);
        assert_eq!(verdict(&selectors_and, &same_namespace), Verdict::Deny);

        let peers_or = NetworkPolicyCompiler::compile(
            PolicyId::new(13),
            policy(vec![NetworkPolicyIngressRule {
                from: Some(vec![
                    NetworkPolicyPeer {
                        pod_selector: Some(selector(&[("source", "same")])),
                        ..NetworkPolicyPeer::default()
                    },
                    NetworkPolicyPeer {
                        namespace_selector: Some(selector(&[("conformance-group", "b")])),
                        ..NetworkPolicyPeer::default()
                    },
                ]),
                ports: None,
            }]),
        )
        .expect("multiple peers compile as alternatives");
        assert_eq!(verdict(&peers_or, &same_namespace), Verdict::Allow);
        assert_eq!(verdict(&peers_or, &source_b), Verdict::Allow);
        assert_eq!(verdict(&peers_or, &source_a), Verdict::Deny);
    }

    #[test]
    fn multiple_pod_selector_peers_are_ored_within_the_policy_namespace() {
        let mut first_local_source = endpoint(1, "backend", "client-a");
        first_local_source
            .labels
            .extend(labels(&[("conformance-source", "same")]));
        let second_local_source = endpoint(2, "backend", "alternate-server");
        let third_local_source = endpoint(3, "backend", "client-c");
        let mut remote_matching_source = endpoint(4, "frontend", "client-a");
        remote_matching_source
            .labels
            .extend(labels(&[("conformance-source", "same")]));
        let destination = endpoint(5, "backend", "server");

        let compiled = NetworkPolicyCompiler::compile(
            PolicyId::new(15),
            policy(vec![NetworkPolicyIngressRule {
                from: Some(vec![
                    NetworkPolicyPeer {
                        pod_selector: Some(selector(&[("conformance-source", "same")])),
                        ..NetworkPolicyPeer::default()
                    },
                    NetworkPolicyPeer {
                        pod_selector: Some(selector(&[("app", "alternate-server")])),
                        ..NetworkPolicyPeer::default()
                    },
                ]),
                ports: Some(vec![NetworkPolicyPort {
                    port: Some(IntOrString::Int(8087)),
                    protocol: Some("TCP".to_owned()),
                    ..NetworkPolicyPort::default()
                }]),
            }]),
        )
        .expect("multiple PodSelector peers compile as same-Namespace alternatives");
        let decision = |source: &Endpoint, port| {
            evaluate(
                std::slice::from_ref(&compiled),
                Flow {
                    source,
                    destination: &destination,
                    protocol: Protocol::Tcp,
                    destination_port: port,
                    source_ipv4: None,
                    source_ipv6: None,
                },
            )
        };

        for source in [&first_local_source, &second_local_source] {
            let allowed = decision(source, 8087);
            assert_eq!(allowed.verdict, Verdict::Allow);
            assert_eq!(allowed.reason, PolicyReason::ExplicitRule);
            assert_eq!(decision(source, 8088).verdict, Verdict::Deny);
        }
        for source in [&third_local_source, &remote_matching_source] {
            let denied = decision(source, 8087);
            assert_eq!(denied.verdict, Verdict::Deny);
            assert_eq!(denied.reason, PolicyReason::DefaultAction);
        }

        let entries = compile_dataplane_entries(
            std::slice::from_ref(&compiled),
            &[
                first_local_source,
                second_local_source,
                third_local_source,
                remote_matching_source,
                destination,
            ],
        )
        .expect("both same-Namespace peer alternatives lower into dataplane entries");
        let exact_allow = |source_identity| {
            entries.iter().any(|entry| {
                entry.key.source_identity == IdentityId::new(source_identity)
                    && entry.key.destination_identity == IdentityId::new(5)
                    && entry.key.protocol == Protocol::Tcp as u8
                    && entry.key.destination_port == 8087
                    && entry.decision.verdict == Verdict::Allow
            })
        };
        assert!(exact_allow(1));
        assert!(exact_allow(2));
        assert!(!exact_allow(3));
        assert!(!exact_allow(4));
    }

    #[test]
    fn multiple_pod_values_and_namespace_exclusion_are_anded() {
        let mut same_namespace_b = endpoint(1, "backend", "client-b");
        same_namespace_b.labels.extend(labels(&[("pod", "b")]));
        let mut remote_a = endpoint(2, "frontend", "client-a");
        remote_a.labels.extend(labels(&[("pod", "a")]));
        let mut remote_b = endpoint(3, "frontend", "client-b");
        remote_b.labels.extend(labels(&[("pod", "b")]));
        let mut remote_c = endpoint(4, "edge", "client-c");
        remote_c.labels.extend(labels(&[("pod", "c")]));
        let destination = endpoint(5, "backend", "server");

        let compiled = NetworkPolicyCompiler::compile(
            PolicyId::new(16),
            policy(vec![NetworkPolicyIngressRule {
                from: Some(vec![NetworkPolicyPeer {
                    namespace_selector: Some(LabelSelector {
                        match_expressions: Some(vec![expression(
                            NAMESPACE_NAME_LABEL,
                            "NotIn",
                            &["backend"],
                        )]),
                        ..LabelSelector::default()
                    }),
                    pod_selector: Some(LabelSelector {
                        match_expressions: Some(vec![expression("pod", "In", &["b", "c"])]),
                        ..LabelSelector::default()
                    }),
                    ..NetworkPolicyPeer::default()
                }]),
                ports: Some(vec![NetworkPolicyPort {
                    port: Some(IntOrString::Int(8087)),
                    protocol: Some("TCP".to_owned()),
                    ..NetworkPolicyPort::default()
                }]),
            }]),
        )
        .expect("multi-value Pod and Namespace selectors compile together");
        let decision = |source: &Endpoint, port| {
            evaluate(
                std::slice::from_ref(&compiled),
                Flow {
                    source,
                    destination: &destination,
                    protocol: Protocol::Tcp,
                    destination_port: port,
                    source_ipv4: None,
                    source_ipv6: None,
                },
            )
        };

        for source in [&remote_b, &remote_c] {
            let allowed = decision(source, 8087);
            assert_eq!(allowed.verdict, Verdict::Allow);
            assert_eq!(allowed.reason, PolicyReason::ExplicitRule);
            assert_eq!(decision(source, 8088).verdict, Verdict::Deny);
        }
        for source in [&same_namespace_b, &remote_a] {
            let denied = decision(source, 8087);
            assert_eq!(denied.verdict, Verdict::Deny);
            assert_eq!(denied.reason, PolicyReason::DefaultAction);
        }

        let entries = compile_dataplane_entries(
            std::slice::from_ref(&compiled),
            &[same_namespace_b, remote_a, remote_b, remote_c, destination],
        )
        .expect("only the remote b and c alternatives lower into allow entries");
        let exact_allow = |source_identity| {
            entries.iter().any(|entry| {
                entry.key.source_identity == IdentityId::new(source_identity)
                    && entry.key.destination_identity == IdentityId::new(5)
                    && entry.key.protocol == Protocol::Tcp as u8
                    && entry.key.destination_port == 8087
                    && entry.decision.verdict == Verdict::Allow
            })
        };
        assert!(!exact_allow(1));
        assert!(!exact_allow(2));
        assert!(exact_allow(3));
        assert!(exact_allow(4));
    }

    #[test]
    fn upstream_expression_rules_preserve_source_port_pairing() {
        let mut same_namespace = endpoint(1, "backend", "same-client");
        same_namespace
            .labels
            .extend(labels(&[("conformance-source", "same")]));
        let mut source_a = endpoint(2, "source-a", "client");
        source_a
            .labels
            .extend(labels(&[("conformance-source", "selected")]));
        source_a
            .namespace_labels
            .extend(labels(&[("conformance-group", "a")]));
        let mut source_b = endpoint(3, "source-b", "client");
        source_b
            .labels
            .extend(labels(&[("conformance-source", "selected")]));
        source_b
            .namespace_labels
            .extend(labels(&[("conformance-group", "b")]));
        let destination = endpoint(4, "backend", "server");

        let expression_selector = |group: &str| LabelSelector {
            match_expressions: Some(vec![expression("conformance-group", "In", &[group])]),
            ..LabelSelector::default()
        };
        let selected_source = LabelSelector {
            match_expressions: Some(vec![
                expression("conformance-source", "In", &["selected"]),
                expression("blocked", "DoesNotExist", &[]),
            ]),
            ..LabelSelector::default()
        };
        let rule = |group: &str, port: i32| NetworkPolicyIngressRule {
            from: Some(vec![NetworkPolicyPeer {
                namespace_selector: Some(expression_selector(group)),
                pod_selector: Some(selected_source.clone()),
                ..NetworkPolicyPeer::default()
            }]),
            ports: Some(vec![NetworkPolicyPort {
                port: Some(IntOrString::Int(port)),
                protocol: Some("TCP".to_owned()),
                ..NetworkPolicyPort::default()
            }]),
        };
        let compiled = NetworkPolicyCompiler::compile(
            PolicyId::new(14),
            policy(vec![rule("a", 8087), rule("b", 8088)]),
        )
        .expect("multiple expression-based ingress rules compile");
        let verdict = |source: &Endpoint, port| {
            evaluate(
                std::slice::from_ref(&compiled),
                Flow {
                    source,
                    destination: &destination,
                    protocol: Protocol::Tcp,
                    destination_port: port,
                    source_ipv4: None,
                    source_ipv6: None,
                },
            )
            .verdict
        };

        assert_eq!(verdict(&source_a, 8087), Verdict::Allow);
        assert_eq!(verdict(&source_a, 8088), Verdict::Deny);
        assert_eq!(verdict(&source_b, 8087), Verdict::Deny);
        assert_eq!(verdict(&source_b, 8088), Verdict::Allow);
        assert_eq!(verdict(&same_namespace, 8087), Verdict::Deny);
        assert_eq!(verdict(&same_namespace, 8088), Verdict::Deny);

        source_b
            .labels
            .insert("blocked".to_owned(), "true".to_owned());
        assert_eq!(verdict(&source_b, 8088), Verdict::Deny);
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
                    source_ipv6: None,
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
                    source_ipv6: None,
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
                    source_ipv6: None,
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
    fn unresolved_named_port_fails_closed() {
        let compiled = NetworkPolicyCompiler::compile(
            PolicyId::new(7),
            policy(vec![NetworkPolicyIngressRule {
                from: None,
                ports: Some(vec![NetworkPolicyPort {
                    port: Some(IntOrString::String("no-such-port".to_owned())),
                    protocol: Some("TCP".to_owned()),
                    ..NetworkPolicyPort::default()
                }]),
            }]),
        )
        .expect("unresolved named port policy compiles");
        let source = endpoint(1, "frontend", "client");
        let destination = endpoint(2, "backend", "server");

        let decision = evaluate(
            std::slice::from_ref(&compiled),
            Flow {
                source: &source,
                destination: &destination,
                protocol: Protocol::Tcp,
                destination_port: 8081,
                source_ipv4: None,
                source_ipv6: None,
            },
        );
        assert_eq!(decision.verdict, Verdict::Deny);
        assert_eq!(decision.reason, PolicyReason::DefaultAction);

        let entries = compile_dataplane_entries(&[compiled], &[source, destination])
            .expect("unresolved named port lowers to isolation without an allow");
        assert!(entries.iter().any(|entry| {
            entry.key.destination_identity == IdentityId::new(2)
                && entry.key.protocol == 0
                && entry.key.destination_port == 0
                && entry.decision.verdict == Verdict::Deny
        }));
        assert!(!entries.iter().any(|entry| {
            entry.key.destination_identity == IdentityId::new(2)
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
                        source_ipv6: None,
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
                        source_ipv6: None,
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
                        source_ipv6: None,
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
    fn ipv6_ip_blocks_lower_prefixes_and_exception_overrides() {
        let compiled = NetworkPolicyCompiler::compile(
            PolicyId::new(8),
            policy(vec![NetworkPolicyIngressRule {
                from: Some(vec![NetworkPolicyPeer {
                    ip_block: Some(IPBlock {
                        cidr: "2001:db8:1::/64".to_owned(),
                        except: Some(vec!["2001:db8:1:0:8000::/65".to_owned()]),
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
        .expect("IPv6 ipBlock compiles without address expansion");
        let source = endpoint(1, "frontend", "client");
        let destination = endpoint(2, "backend", "server");
        for (address, expected) in [
            ("2001:db8:1::1", Verdict::Allow),
            ("2001:db8:1:0:8000::1", Verdict::Deny),
            ("2001:db8:2::1", Verdict::Deny),
        ] {
            assert_eq!(
                evaluate(
                    std::slice::from_ref(&compiled),
                    Flow {
                        source: &source,
                        destination: &destination,
                        protocol: Protocol::Tcp,
                        destination_port: 8080,
                        source_ipv4: None,
                        source_ipv6: Some(address.parse().unwrap()),
                    },
                )
                .verdict,
                expected
            );
        }

        let entries = compile_ipv6_dataplane_entries(
            &[compiled],
            &[source.clone(), destination.clone()],
            &[Ipv6Endpoint {
                address: "2001:db8:1::1".parse().unwrap(),
                endpoint: source,
            }],
        )
        .expect("IPv6 ipBlock lowers to bounded prefixes");
        let decision = |prefix_len, protocol, port| {
            entries
                .iter()
                .find(|entry| {
                    entry.key.source_prefix_len == prefix_len
                        && entry.key.destination_identity == destination.identity
                        && entry.key.protocol == protocol
                        && entry.key.destination_port == port
                })
                .map(|entry| entry.decision.verdict)
        };
        assert_eq!(
            decision(64, Protocol::Tcp as u8, 8080),
            Some(Verdict::Allow)
        );
        assert_eq!(decision(65, Protocol::Tcp as u8, 8080), Some(Verdict::Deny));
        assert_eq!(decision(0, 0, 0), Some(Verdict::Deny));
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
        let too_many_ipv6_exceptions = (0..KUBERNETES_NETWORK_POLICY_MAX_IPV6_IP_BLOCK_PREFIXES)
            .map(|index| format!("2001:db8::{index:x}/128"))
            .collect();
        let oversized_ipv6 = policy(vec![NetworkPolicyIngressRule {
            from: Some(vec![NetworkPolicyPeer {
                ip_block: Some(IPBlock {
                    cidr: "2001:db8::/64".to_owned(),
                    except: Some(too_many_ipv6_exceptions),
                }),
                ..NetworkPolicyPeer::default()
            }]),
            ports: None,
        }]);
        assert!(matches!(
            NetworkPolicyCompiler::compile(PolicyId::new(7), oversized_ipv6),
            Err(NetworkPolicyCompileError::Ipv6IpBlockTooManyPrefixes { .. })
        ));
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
