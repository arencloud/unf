//! Native Kubernetes API translation into the provider-neutral egress model.

use std::collections::BTreeSet;
use std::net::IpAddr;

use k8s_openapi::apimachinery::pkg::apis::meta::v1::LabelSelector as KubernetesLabelSelector;
use kube::ResourceExt;
use thiserror::Error;
use unf_api::{
    EgressAddressFamily as ApiAddressFamily, EgressDestinations as ApiEgressDestinations,
    EgressInternetClass as ApiInternetClass, EgressInternetClassification,
    EgressInternetFallback as ApiInternetFallback, EgressPolicy, EgressPool,
};
use unf_common::Revision;
use unf_egress::{
    AddressFamily, EgressAddressPool, EgressAddressRequest,
    EgressDestinations as DomainDestinations, EgressFqdnDestinationSpec, EgressFqdnPattern,
    EgressIntent, EgressIntentOwner, EgressIntentScope, EgressInternetClass,
    EgressInternetClassification as DomainInternetClassification,
    EgressInternetClassificationDigest, EgressInternetClassificationRule,
    EgressInternetDestinationSpec, EgressInternetFallback, EgressModelError, EgressProviderRef,
    EgressSourceSelector, IpPrefix, LabelExpression, LabelExpressionOperator, LabelSelector,
    normalize_intent, normalize_pools, seal_egress_internet_classification,
};

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum NativeEgressApiError {
    #[error("{kind} {name:?} has no stable UID")]
    MissingUid { kind: &'static str, name: String },
    #[error("{kind} {name:?} has invalid CIDR {value:?}")]
    InvalidCidr {
        kind: &'static str,
        name: String,
        value: String,
    },
    #[error("EgressPolicy {name:?} uses unsupported selector operator {operator:?}")]
    UnsupportedSelectorOperator { name: String, operator: String },
    #[error("EgressPolicy {0:?} must select exactly one pool or explicit address set")]
    InvalidAddressSelection(String),
    #[error("EgressPolicy {0:?} must choose only one network, FQDN, or internet destination kind")]
    AmbiguousDestinations(String),
    #[error("EgressPolicy {0:?} has an invalid internet fallback configuration")]
    InvalidInternetFallback(String),
    #[error("EgressPolicy {name:?} has invalid FQDN pattern {value:?}")]
    InvalidFqdn { name: String, value: String },
    #[error("EgressPolicy {name:?} has invalid DNS resolver address {value:?}")]
    InvalidDnsResolver { name: String, value: String },
    #[error("native egress resource cannot be normalized: {0}")]
    InvalidModel(String),
}

pub fn translate_egress_pool(pool: &EgressPool) -> Result<EgressAddressPool, NativeEgressApiError> {
    let name = pool.name_any();
    let uid = pool
        .metadata
        .uid
        .clone()
        .filter(|uid| !uid.is_empty())
        .ok_or_else(|| NativeEgressApiError::MissingUid {
            kind: "EgressPool",
            name: name.clone(),
        })?;
    let prefixes = pool
        .spec
        .prefixes
        .iter()
        .map(|value| parse_prefix("EgressPool", &name, value))
        .collect::<Result<Vec<_>, _>>()?;
    let translated = EgressAddressPool {
        name,
        uid,
        provider: EgressProviderRef {
            name: pool.spec.provider.name.clone(),
            instance: pool.spec.provider.instance.clone(),
        },
        prefixes,
    };
    normalize_pools(vec![translated])
        .map_err(|error| model_error(&error))?
        .pop()
        .ok_or_else(|| NativeEgressApiError::InvalidModel("pool disappeared".to_owned()))
}

pub fn translate_egress_internet_classification(
    publication: &EgressInternetClassification,
) -> Result<DomainInternetClassification, NativeEgressApiError> {
    let name = publication.name_any();
    let rules = publication
        .spec
        .rules
        .iter()
        .map(|rule| {
            Ok(EgressInternetClassificationRule {
                prefix: parse_prefix("EgressInternetClassification", &name, &rule.prefix)?,
                class: match rule.class {
                    ApiInternetClass::Internet => EgressInternetClass::Internet,
                    ApiInternetClass::NonInternet => EgressInternetClass::NonInternet,
                },
                provenance: rule.provenance.clone(),
            })
        })
        .collect::<Result<Vec<_>, NativeEgressApiError>>()?;
    seal_egress_internet_classification(DomainInternetClassification {
        schema_version: unf_egress::EGRESS_INTERNET_CLASSIFICATION_SCHEMA_VERSION,
        algorithm: unf_egress::EGRESS_INTERNET_CLASSIFICATION_ALGORITHM_AUTHORITY_CARVING_V1,
        revision: Revision::new(publication.spec.revision),
        source: EgressProviderRef {
            name: publication.spec.classifier.name.clone(),
            instance: publication.spec.classifier.instance.clone(),
        },
        source_epoch: publication.spec.source_epoch,
        observed_at_unix_seconds: publication.spec.observed_at_unix_seconds,
        valid_until_unix_seconds: publication.spec.valid_until_unix_seconds,
        rules,
        digest: EgressInternetClassificationDigest([0; 32]),
    })
    .map_err(|error| NativeEgressApiError::InvalidModel(error.to_string()))
}

pub fn translate_egress_policy(
    policy: &EgressPolicy,
) -> Result<(EgressIntent, Option<EgressProviderRef>), NativeEgressApiError> {
    let name = policy.name_any();
    let uid = policy
        .metadata
        .uid
        .clone()
        .filter(|uid| !uid.is_empty())
        .ok_or_else(|| NativeEgressApiError::MissingUid {
            kind: "EgressPolicy",
            name: name.clone(),
        })?;
    let (destinations, fqdn, internet) = translate_destinations(&name, &policy.spec.destinations)?;
    let selection = &policy.spec.egress;
    let (addresses, provider) = match (
        selection.pool.as_deref(),
        selection.explicit_addresses.is_empty(),
    ) {
        (Some(pool), true) if selection.provider.is_none() && !selection.families.is_empty() => (
            EgressAddressRequest::Pool {
                name: pool.to_owned(),
                families: selection
                    .families
                    .iter()
                    .map(|family| match family {
                        ApiAddressFamily::IPv4 => AddressFamily::Ipv4,
                        ApiAddressFamily::IPv6 => AddressFamily::Ipv6,
                    })
                    .collect(),
                addresses_per_family: selection.addresses_per_family,
            },
            None,
        ),
        (None, false) if selection.families.is_empty() && selection.provider.is_some() => {
            let addresses = selection
                .explicit_addresses
                .iter()
                .map(|value| {
                    value
                        .parse::<IpAddr>()
                        .map_err(|_| NativeEgressApiError::InvalidCidr {
                            kind: "EgressPolicy",
                            name: name.clone(),
                            value: value.clone(),
                        })
                })
                .collect::<Result<Vec<_>, _>>()?;
            let provider = selection
                .provider
                .as_ref()
                .map(|provider| EgressProviderRef {
                    name: provider.name.clone(),
                    instance: provider.instance.clone(),
                });
            (EgressAddressRequest::Explicit { addresses }, provider)
        }
        _ => return Err(NativeEgressApiError::InvalidAddressSelection(name)),
    };
    let intent = normalize_intent(EgressIntent {
        owner: EgressIntentOwner {
            scope: EgressIntentScope::Cluster,
            name: name.clone(),
            uid,
        },
        priority: policy.spec.priority,
        source: EgressSourceSelector {
            namespace: translate_selector(&name, &policy.spec.target.namespace_selector)?,
            workload: translate_selector(&name, &policy.spec.target.workload_selector)?,
            service_accounts: policy
                .spec
                .target
                .service_accounts
                .iter()
                .cloned()
                .collect::<BTreeSet<_>>(),
        },
        destinations,
        fqdn,
        internet,
        addresses,
    })
    .map_err(|error| model_error(&error))?;
    Ok((intent, provider))
}

fn translate_destinations(
    name: &str,
    destinations: &ApiEgressDestinations,
) -> Result<
    (
        DomainDestinations,
        Option<EgressFqdnDestinationSpec>,
        Option<EgressInternetDestinationSpec>,
    ),
    NativeEgressApiError,
> {
    let translated = match (
        destinations.networks.is_empty(),
        destinations.fqdn.is_empty(),
        destinations.internet.as_ref(),
    ) {
        (true, true, None) => (DomainDestinations::Any, None, None),
        (false, true, None) => (
            DomainDestinations::Networks(
                destinations
                    .networks
                    .iter()
                    .map(|value| parse_prefix("EgressPolicy", name, value))
                    .collect::<Result<Vec<_>, _>>()?,
            ),
            None,
            None,
        ),
        (true, false, None) => {
            let controls = &destinations.dns;
            let patterns = destinations
                .fqdn
                .iter()
                .map(|value| {
                    EgressFqdnPattern::parse(value).map_err(|_| NativeEgressApiError::InvalidFqdn {
                        name: name.to_owned(),
                        value: value.clone(),
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;
            let resolver_addresses = controls
                .resolver_addresses
                .iter()
                .map(|value| {
                    value
                        .parse::<IpAddr>()
                        .map_err(|_| NativeEgressApiError::InvalidDnsResolver {
                            name: name.to_owned(),
                            value: value.clone(),
                        })
                })
                .collect::<Result<Vec<_>, _>>()?;
            (
                DomainDestinations::DenyAll,
                Some(EgressFqdnDestinationSpec {
                    patterns,
                    view: controls.view.clone(),
                    discovery_names: controls.discovery_names.clone(),
                    resolver_addresses,
                    required_observers: controls.required_observers,
                    max_addresses: controls.max_addresses,
                    max_ttl_seconds: controls.max_ttl_seconds,
                    established_flow_grace_seconds: controls.established_flow_grace_seconds,
                }),
                None,
            )
        }
        (true, true, Some(internet)) => {
            let exceptions = internet
                .exceptions
                .iter()
                .map(|value| parse_prefix("EgressPolicy", name, value))
                .collect::<Result<Vec<_>, _>>()?;
            let fallback = match (internet.fallback, internet.max_staleness_seconds) {
                (ApiInternetFallback::Deny, 0) => EgressInternetFallback::Deny,
                (ApiInternetFallback::LastKnownGood, seconds) if seconds > 0 => {
                    EgressInternetFallback::LastKnownGood {
                        max_staleness_seconds: seconds,
                    }
                }
                _ => {
                    return Err(NativeEgressApiError::InvalidInternetFallback(
                        name.to_owned(),
                    ));
                }
            };
            (
                DomainDestinations::DenyAll,
                None,
                Some(EgressInternetDestinationSpec {
                    classifier: EgressProviderRef {
                        name: internet.classifier.name.clone(),
                        instance: internet.classifier.instance.clone(),
                    },
                    exceptions,
                    fallback,
                }),
            )
        }
        _ => {
            return Err(NativeEgressApiError::AmbiguousDestinations(name.to_owned()));
        }
    };
    Ok(translated)
}

fn translate_selector(
    name: &str,
    selector: &KubernetesLabelSelector,
) -> Result<LabelSelector, NativeEgressApiError> {
    let expressions = selector
        .match_expressions
        .as_deref()
        .unwrap_or_default()
        .iter()
        .map(|requirement| {
            let operator = match requirement.operator.as_str() {
                "In" => LabelExpressionOperator::In,
                "NotIn" => LabelExpressionOperator::NotIn,
                "Exists" => LabelExpressionOperator::Exists,
                "DoesNotExist" => LabelExpressionOperator::DoesNotExist,
                operator => {
                    return Err(NativeEgressApiError::UnsupportedSelectorOperator {
                        name: name.to_owned(),
                        operator: operator.to_owned(),
                    });
                }
            };
            Ok(LabelExpression {
                key: requirement.key.clone(),
                operator,
                values: requirement
                    .values
                    .clone()
                    .unwrap_or_default()
                    .into_iter()
                    .collect(),
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(LabelSelector {
        match_labels: selector.match_labels.clone().unwrap_or_default(),
        match_expressions: expressions,
    })
}

fn parse_prefix(
    kind: &'static str,
    name: &str,
    value: &str,
) -> Result<IpPrefix, NativeEgressApiError> {
    let (address, prefix_len) = value
        .split_once('/')
        .ok_or_else(|| invalid_cidr(kind, name, value))?;
    let address = address
        .parse::<IpAddr>()
        .map_err(|_| invalid_cidr(kind, name, value))?;
    let prefix_len = prefix_len
        .parse::<u8>()
        .map_err(|_| invalid_cidr(kind, name, value))?;
    let prefix = IpPrefix {
        address,
        prefix_len,
    };
    if !prefix.is_canonical() {
        return Err(invalid_cidr(kind, name, value));
    }
    Ok(prefix)
}

fn invalid_cidr(kind: &'static str, name: &str, value: &str) -> NativeEgressApiError {
    NativeEgressApiError::InvalidCidr {
        kind,
        name: name.to_owned(),
        value: value.to_owned(),
    }
}

fn model_error(error: &EgressModelError) -> NativeEgressApiError {
    NativeEgressApiError::InvalidModel(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_pool_and_policy_translate_to_one_exact_domain_model() {
        let pool: EgressPool = serde_json::from_value(serde_json::json!({
            "apiVersion": "network.unf.io/v1alpha1",
            "kind": "EgressPool",
            "metadata": {"name": "finance", "uid": "pool-uid"},
            "spec": {
                "provider": {"name": "static", "instance": "rack-a"},
                "prefixes": ["192.0.2.0/24", "2001:db8::/64"]
            }
        }))
        .unwrap();
        let policy: EgressPolicy = serde_json::from_value(serde_json::json!({
            "apiVersion": "network.unf.io/v1alpha1",
            "kind": "EgressPolicy",
            "metadata": {"name": "finance", "uid": "policy-uid"},
            "spec": {
                "target": {
                    "namespaceSelector": {"matchLabels": {"team": "finance"}},
                    "workloadSelector": {"matchLabels": {"app": "ledger"}},
                    "serviceAccounts": ["settlement"]
                },
                "destinations": {"networks": ["198.51.100.0/24", "2001:db8:ffff::/48"]},
                "egress": {
                    "pool": "finance",
                    "families": ["IPv4", "IPv6"],
                    "addressesPerFamily": 2
                },
                "priority": 900
            }
        }))
        .unwrap();
        let pool = translate_egress_pool(&pool).unwrap();
        let (intent, provider) = translate_egress_policy(&policy).unwrap();
        assert!(provider.is_none());
        let model = unf_egress::normalize_model(vec![pool], vec![intent]).unwrap();
        assert_eq!(model.pools.len(), 1);
        assert_eq!(model.intents.len(), 1);
    }

    #[test]
    fn native_translation_rejects_ambiguous_address_ownership_and_bad_cidr() {
        let ambiguous: EgressPolicy = serde_json::from_value(serde_json::json!({
            "apiVersion": "network.unf.io/v1alpha1",
            "kind": "EgressPolicy",
            "metadata": {"name": "bad", "uid": "bad-uid"},
            "spec": {
                "target": {},
                "egress": {
                    "pool": "finance",
                    "explicitAddresses": ["192.0.2.40"],
                    "families": ["IPv4"]
                }
            }
        }))
        .unwrap();
        assert!(matches!(
            translate_egress_policy(&ambiguous),
            Err(NativeEgressApiError::InvalidAddressSelection(_))
        ));

        let pool: EgressPool = serde_json::from_value(serde_json::json!({
            "apiVersion": "network.unf.io/v1alpha1",
            "kind": "EgressPool",
            "metadata": {"name": "bad", "uid": "pool-uid"},
            "spec": {
                "provider": {"name": "static", "instance": "rack-a"},
                "prefixes": ["192.0.2.4/24"]
            }
        }))
        .unwrap();
        assert!(matches!(
            translate_egress_pool(&pool),
            Err(NativeEgressApiError::InvalidCidr { .. })
        ));
    }

    #[test]
    fn native_fqdn_translation_is_canonical_bounded_and_initially_deny_all() {
        let policy: EgressPolicy = serde_json::from_value(serde_json::json!({
            "apiVersion": "network.unf.io/v1alpha1",
            "kind": "EgressPolicy",
            "metadata": {"name": "bank-access", "uid": "policy-uid"},
            "spec": {
                "target": {"namespaceSelector": {"matchLabels": {"team": "finance"}}},
                "destinations": {
                    "fqdn": ["API.PARTNER.TEST.", "*.bank.example"],
                    "dns": {
                        "view": "finance/production",
                        "discoveryNames": ["payments.bank.example"],
                        "resolverAddresses": ["10.96.0.53", "2001:db8::53"],
                        "requiredObservers": 2,
                        "maxAddresses": 128,
                        "maxTtlSeconds": 120,
                        "establishedFlowGraceSeconds": 15
                    }
                },
                "egress": {"pool": "finance", "families": ["IPv4", "IPv6"]}
            }
        }))
        .unwrap();
        let (intent, provider) = translate_egress_policy(&policy).unwrap();
        assert!(provider.is_none());
        assert_eq!(intent.destinations, DomainDestinations::DenyAll);
        let fqdn = intent.fqdn.unwrap();
        assert_eq!(
            fqdn.patterns[0],
            EgressFqdnPattern::Exact("api.partner.test".to_owned())
        );
        assert_eq!(fqdn.required_observers, 2);
        assert_eq!(fqdn.max_ttl_seconds, 120);
        assert_eq!(fqdn.discovery_names, ["payments.bank.example"]);
        assert_eq!(
            fqdn.resolver_addresses,
            [
                "10.96.0.53".parse::<IpAddr>().unwrap(),
                "2001:db8::53".parse::<IpAddr>().unwrap()
            ]
        );

        let ambiguous: EgressPolicy = serde_json::from_value(serde_json::json!({
            "apiVersion": "network.unf.io/v1alpha1",
            "kind": "EgressPolicy",
            "metadata": {"name": "ambiguous", "uid": "ambiguous-uid"},
            "spec": {
                "target": {},
                "destinations": {
                    "networks": ["198.51.100.0/24"],
                    "fqdn": ["api.example"]
                },
                "egress": {"pool": "finance", "families": ["IPv4"]}
            }
        }))
        .unwrap();
        assert!(matches!(
            translate_egress_policy(&ambiguous),
            Err(NativeEgressApiError::AmbiguousDestinations(_))
        ));
    }

    #[test]
    fn native_internet_translation_requires_explicit_bounded_fallback() {
        let policy: EgressPolicy = serde_json::from_value(serde_json::json!({
            "apiVersion": "network.unf.io/v1alpha1",
            "kind": "EgressPolicy",
            "metadata": {"name": "public-access", "uid": "internet-uid"},
            "spec": {
                "target": {"namespaceSelector": {"matchLabels": {"team": "finance"}}},
                "destinations": {
                    "internet": {
                        "classifier": {"name": "route-authority", "instance": "global-v1"},
                        "exceptions": ["203.0.113.0/24", "2001:db8:42::/48"],
                        "fallback": "LastKnownGood",
                        "maxStalenessSeconds": 300
                    }
                },
                "egress": {"pool": "finance", "families": ["IPv4", "IPv6"]}
            }
        }))
        .unwrap();
        let (intent, provider) = translate_egress_policy(&policy).unwrap();
        assert!(provider.is_none());
        assert_eq!(intent.destinations, DomainDestinations::DenyAll);
        let internet = intent.internet.unwrap();
        assert_eq!(internet.classifier.name, "route-authority");
        assert_eq!(internet.exceptions[0].prefix_len, 24);
        assert_eq!(
            internet.fallback,
            EgressInternetFallback::LastKnownGood {
                max_staleness_seconds: 300
            }
        );

        let mut invalid = policy;
        invalid
            .spec
            .destinations
            .internet
            .as_mut()
            .unwrap()
            .max_staleness_seconds = 0;
        assert!(matches!(
            translate_egress_policy(&invalid),
            Err(NativeEgressApiError::InvalidInternetFallback(_))
        ));
    }

    #[test]
    fn authenticated_classifier_publication_is_sealed_and_canonical() {
        let publication: EgressInternetClassification = serde_json::from_value(serde_json::json!({
            "apiVersion": "network.unf.io/v1alpha1",
            "kind": "EgressInternetClassification",
            "metadata": {"name": "global-routes"},
            "spec": {
                "classifier": {"name": "route-authority", "instance": "global-v1"},
                "sourceEpoch": 9,
                "revision": 17,
                "observedAtUnixSeconds": 1000,
                "validUntilUnixSeconds": 1100,
                "rules": [
                    {"prefix": "2001:db8::/32", "class": "NonInternet", "provenance": "tenant:v4"},
                    {"prefix": "0.0.0.0/0", "class": "Internet", "provenance": "rpki:42"}
                ]
            }
        }))
        .unwrap();
        let translated = translate_egress_internet_classification(&publication).unwrap();
        assert_eq!(translated.revision, Revision::new(17));
        assert_eq!(translated.source_epoch, 9);
        assert_eq!(translated.rules[0].prefix.address.to_string(), "0.0.0.0");
        assert_ne!(translated.digest.0, [0; 32]);

        let mut invalid = publication;
        invalid.spec.rules[0].prefix = "2001:db8::1/32".to_owned();
        assert!(matches!(
            translate_egress_internet_classification(&invalid),
            Err(NativeEgressApiError::InvalidCidr { .. })
        ));
    }
}
