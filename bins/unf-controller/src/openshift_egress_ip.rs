//! Strict `OpenShift` `EgressIP` compatibility translation.
//!
//! The adapter intentionally does not watch resources or mutate status yet.
//! It converts the platform API edge into `unf-egress` and provides a
//! foreign-preserving status merge for the later ownership transaction.

use std::collections::BTreeSet;
use std::net::IpAddr;

use k8s_openapi::apimachinery::pkg::apis::meta::v1::LabelSelector as KubernetesLabelSelector;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use unf_egress::{
    DEFAULT_EGRESS_INTENT_PRIORITY, EgressAddressRequest, EgressDestinations, EgressIntent,
    EgressIntentOwner, EgressIntentScope, EgressModelError, EgressSourceSelector, LabelExpression,
    LabelExpressionOperator, LabelSelector, MAX_EGRESS_ADDRESSES_PER_INTENT, normalize_intent,
};

pub const MAX_OPENSHIFT_EGRESS_STATUS_ITEMS: usize = 64;

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct OpenShiftEgressIpSpec {
    #[serde(rename = "egressIPs")]
    pub egress_ips: Vec<String>,
    pub namespace_selector: KubernetesLabelSelector,
    #[serde(default)]
    pub pod_selector: Option<KubernetesLabelSelector>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct OpenShiftEgressIpStatusItem {
    #[serde(rename = "egressIP")]
    pub egress_ip: String,
    pub node: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum OpenShiftEgressIpError {
    #[error("OpenShift EgressIP {name:?} has an invalid requested address {address:?}")]
    InvalidAddress { name: String, address: String },
    #[error("OpenShift EgressIP {name:?} uses unsupported selector operator {operator:?}")]
    UnsupportedSelectorOperator { name: String, operator: String },
    #[error("OpenShift EgressIP {name:?} cannot be normalized: {source}")]
    InvalidModel {
        name: String,
        #[source]
        source: EgressModelError,
    },
    #[error("OpenShift EgressIP status has {actual} items; limit is {limit}")]
    TooManyStatusItems { actual: usize, limit: usize },
    #[error("OpenShift EgressIP desired status contains invalid assignment {address:?}/{node:?}")]
    InvalidStatusAssignment { address: IpAddr, node: String },
    #[error("OpenShift EgressIP desired status address {0} is already foreign-owned")]
    ForeignStatusAddress(IpAddr),
}

/// Translates the `OpenShift` 4.22 `k8s.ovn.org/v1` spec into one normalized
/// provider-neutral egress intent.
///
/// A missing pod selector defaults to an empty selector (all Pods in matching
/// Namespaces). Requested addresses remain explicit intent; they do not imply
/// allocation, gateway readiness, reachability, or dataplane acknowledgement.
///
/// # Errors
///
/// Rejects malformed addresses, unsupported label operators, and any core
/// model validation failure.
pub fn translate_openshift_egress_ip(
    name: &str,
    uid: &str,
    spec: OpenShiftEgressIpSpec,
) -> Result<EgressIntent, OpenShiftEgressIpError> {
    let addresses = spec
        .egress_ips
        .into_iter()
        .map(|address| {
            address
                .parse::<IpAddr>()
                .map_err(|_| OpenShiftEgressIpError::InvalidAddress {
                    name: name.to_owned(),
                    address,
                })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let namespace = translate_selector(name, spec.namespace_selector)?;
    let workload = translate_selector(name, spec.pod_selector.unwrap_or_default())?;
    normalize_intent(EgressIntent {
        owner: EgressIntentOwner {
            scope: EgressIntentScope::Cluster,
            name: name.to_owned(),
            uid: uid.to_owned(),
        },
        priority: DEFAULT_EGRESS_INTENT_PRIORITY,
        source: EgressSourceSelector {
            namespace,
            workload,
            service_accounts: BTreeSet::new(),
        },
        destinations: EgressDestinations::Any,
        fqdn: None,
        addresses: EgressAddressRequest::Explicit { addresses },
    })
    .map_err(|source| OpenShiftEgressIpError::InvalidModel {
        name: name.to_owned(),
        source,
    })
}

/// Replaces only assignments previously published by UNF while retaining every
/// foreign or unparseable status item in its observed order.
///
/// # Errors
///
/// Rejects unbounded status, invalid/duplicate desired state, or collisions
/// with an address not present in `previously_owned`.
pub fn reconcile_openshift_egress_ip_status(
    existing: &[OpenShiftEgressIpStatusItem],
    previously_owned: &[IpAddr],
    desired: &[(IpAddr, String)],
) -> Result<Vec<OpenShiftEgressIpStatusItem>, OpenShiftEgressIpError> {
    if existing.len() > MAX_OPENSHIFT_EGRESS_STATUS_ITEMS {
        return Err(OpenShiftEgressIpError::TooManyStatusItems {
            actual: existing.len(),
            limit: MAX_OPENSHIFT_EGRESS_STATUS_ITEMS,
        });
    }
    if desired.len() > MAX_EGRESS_ADDRESSES_PER_INTENT {
        return Err(OpenShiftEgressIpError::TooManyStatusItems {
            actual: desired.len(),
            limit: MAX_EGRESS_ADDRESSES_PER_INTENT,
        });
    }
    let owned = previously_owned.iter().copied().collect::<BTreeSet<_>>();
    let mut foreign_addresses = BTreeSet::new();
    let mut reconciled = Vec::with_capacity(existing.len() + desired.len());
    for item in existing {
        let parsed = item.egress_ip.parse::<IpAddr>().ok();
        if parsed.is_some_and(|address| owned.contains(&address)) {
            continue;
        }
        if let Some(address) = parsed {
            foreign_addresses.insert(address);
        }
        reconciled.push(item.clone());
    }

    let mut desired = desired.to_vec();
    desired.sort_unstable();
    for pair in desired.windows(2) {
        if pair[0].0 == pair[1].0 {
            return Err(OpenShiftEgressIpError::InvalidStatusAssignment {
                address: pair[1].0,
                node: pair[1].1.clone(),
            });
        }
    }
    for (address, node) in desired {
        if address.is_unspecified() || node.is_empty() || node.len() > 253 {
            return Err(OpenShiftEgressIpError::InvalidStatusAssignment { address, node });
        }
        if foreign_addresses.contains(&address) {
            return Err(OpenShiftEgressIpError::ForeignStatusAddress(address));
        }
        reconciled.push(OpenShiftEgressIpStatusItem {
            egress_ip: address.to_string(),
            node,
        });
    }
    if reconciled.len() > MAX_OPENSHIFT_EGRESS_STATUS_ITEMS {
        return Err(OpenShiftEgressIpError::TooManyStatusItems {
            actual: reconciled.len(),
            limit: MAX_OPENSHIFT_EGRESS_STATUS_ITEMS,
        });
    }
    Ok(reconciled)
}

fn translate_selector(
    name: &str,
    selector: KubernetesLabelSelector,
) -> Result<LabelSelector, OpenShiftEgressIpError> {
    let match_expressions = selector
        .match_expressions
        .unwrap_or_default()
        .into_iter()
        .map(|requirement| {
            let operator = match requirement.operator.as_str() {
                "In" => LabelExpressionOperator::In,
                "NotIn" => LabelExpressionOperator::NotIn,
                "Exists" => LabelExpressionOperator::Exists,
                "DoesNotExist" => LabelExpressionOperator::DoesNotExist,
                operator => {
                    return Err(OpenShiftEgressIpError::UnsupportedSelectorOperator {
                        name: name.to_owned(),
                        operator: operator.to_owned(),
                    });
                }
            };
            Ok(LabelExpression {
                key: requirement.key,
                operator,
                values: requirement.values.unwrap_or_default().into_iter().collect(),
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(LabelSelector {
        match_labels: selector.match_labels.unwrap_or_default(),
        match_expressions,
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use k8s_openapi::apimachinery::pkg::apis::meta::v1::LabelSelectorRequirement;
    use unf_egress::{EgressAddressRequest, EgressDestinations, EgressIntentScope};

    use super::*;

    #[test]
    fn translates_dual_stack_and_intersects_platform_selectors() {
        let translated = translate_openshift_egress_ip(
            "finance",
            "uid-finance",
            OpenShiftEgressIpSpec {
                egress_ips: vec!["2001:db8::20".to_owned(), "192.0.2.20".to_owned()],
                namespace_selector: KubernetesLabelSelector {
                    match_labels: Some(BTreeMap::from([("team".to_owned(), "finance".to_owned())])),
                    ..KubernetesLabelSelector::default()
                },
                pod_selector: Some(KubernetesLabelSelector {
                    match_labels: Some(BTreeMap::from([("app".to_owned(), "ledger".to_owned())])),
                    ..KubernetesLabelSelector::default()
                }),
            },
        )
        .expect("valid OpenShift compatibility input");

        assert_eq!(translated.owner.scope, EgressIntentScope::Cluster);
        assert_eq!(translated.destinations, EgressDestinations::Any);
        let EgressAddressRequest::Explicit { addresses } = translated.addresses else {
            panic!("expected explicit addresses")
        };
        assert!(matches!(
            addresses.as_slice(),
            [IpAddr::V4(_), IpAddr::V6(_)]
        ));
        assert!(translated.source.matches(
            &BTreeMap::from([("team".to_owned(), "finance".to_owned())]),
            &BTreeMap::from([("app".to_owned(), "ledger".to_owned())]),
            "any-service-account"
        ));
        assert!(!translated.source.matches(
            &BTreeMap::from([("team".to_owned(), "other".to_owned())]),
            &BTreeMap::from([("app".to_owned(), "ledger".to_owned())]),
            "any-service-account"
        ));
    }

    #[test]
    fn absent_pod_selector_defaults_to_all_pods() {
        let translated = translate_openshift_egress_ip(
            "all-pods",
            "uid-all-pods",
            OpenShiftEgressIpSpec {
                egress_ips: vec!["192.0.2.30".to_owned()],
                namespace_selector: KubernetesLabelSelector::default(),
                pod_selector: None,
            },
        )
        .expect("valid defaulting");
        assert!(translated.source.workload.matches(&BTreeMap::from([(
            "arbitrary".to_owned(),
            "label".to_owned()
        )])));
    }

    #[test]
    fn rejects_unknown_operator_and_bad_address() {
        let bad_selector = OpenShiftEgressIpSpec {
            egress_ips: vec!["192.0.2.30".to_owned()],
            namespace_selector: KubernetesLabelSelector {
                match_expressions: Some(vec![LabelSelectorRequirement {
                    key: "team".to_owned(),
                    operator: "GreaterThan".to_owned(),
                    values: Some(vec!["1".to_owned()]),
                }]),
                ..KubernetesLabelSelector::default()
            },
            pod_selector: None,
        };
        assert!(matches!(
            translate_openshift_egress_ip("bad", "uid-bad", bad_selector),
            Err(OpenShiftEgressIpError::UnsupportedSelectorOperator { .. })
        ));

        let bad_address = OpenShiftEgressIpSpec {
            egress_ips: vec!["not-an-ip".to_owned()],
            namespace_selector: KubernetesLabelSelector::default(),
            pod_selector: None,
        };
        assert!(matches!(
            translate_openshift_egress_ip("bad", "uid-bad", bad_address),
            Err(OpenShiftEgressIpError::InvalidAddress { .. })
        ));
    }

    #[test]
    fn status_merge_preserves_foreign_bytes_and_replaces_only_owned_entries() {
        let existing = vec![
            OpenShiftEgressIpStatusItem {
                egress_ip: "192.0.2.20".to_owned(),
                node: "old-node".to_owned(),
            },
            OpenShiftEgressIpStatusItem {
                egress_ip: "2001:0db8::99".to_owned(),
                node: "foreign-node".to_owned(),
            },
            OpenShiftEgressIpStatusItem {
                egress_ip: "future-provider-value".to_owned(),
                node: "future-node".to_owned(),
            },
        ];
        let reconciled = reconcile_openshift_egress_ip_status(
            &existing,
            &["192.0.2.20".parse().expect("valid")],
            &[("192.0.2.30".parse().expect("valid"), "new-node".to_owned())],
        )
        .expect("safe merge");
        assert_eq!(&reconciled[..2], &existing[1..]);
        assert_eq!(reconciled[2].egress_ip, "192.0.2.30");
        assert_eq!(reconciled[2].node, "new-node");
    }

    #[test]
    fn status_merge_rejects_foreign_address_adoption() {
        let existing = vec![OpenShiftEgressIpStatusItem {
            egress_ip: "192.0.2.40".to_owned(),
            node: "foreign-node".to_owned(),
        }];
        assert!(matches!(
            reconcile_openshift_egress_ip_status(
                &existing,
                &[],
                &[("192.0.2.40".parse().expect("valid"), "ours".to_owned())]
            ),
            Err(OpenShiftEgressIpError::ForeignStatusAddress(_))
        ));
    }
}
