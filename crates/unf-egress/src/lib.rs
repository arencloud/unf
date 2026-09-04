//! Kubernetes-independent identity-aware egress domain.
//!
//! Intent, allocation, provider ownership, verified exact-Node contracts, and
//! transactional userspace host state live here. Platform adapters translate
//! their APIs into these types; packet processing remains a later boundary.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
#[cfg(test)]
use std::net::{Ipv4Addr, Ipv6Addr};

use serde::{Deserialize, Serialize};
use thiserror::Error;

mod allocation;
mod contract;
mod control_plane;
mod dataplane;
mod desired;
mod distribution;
mod fqdn;
mod gateway;
mod gateway_address;
mod ha;
mod ha_continuity;
mod ha_promotion;
mod host_state;
mod proof;
mod safe_forgetting;

pub use allocation::*;
pub use contract::*;
pub use control_plane::*;
pub use dataplane::*;
pub use desired::*;
pub use distribution::*;
pub use fqdn::*;
pub use gateway::*;
pub use gateway_address::*;
pub use ha::*;
pub use ha_continuity::*;
pub use ha_promotion::*;
pub use host_state::*;
pub use proof::*;
pub use safe_forgetting::*;

pub const DEFAULT_EGRESS_INTENT_PRIORITY: u32 = 1_000;
pub const MAX_EGRESS_POOLS: usize = 64;
pub const MAX_EGRESS_POOL_PREFIXES: usize = 256;
pub const MAX_EGRESS_INTENTS: usize = 4_096;
pub const MAX_EGRESS_DESTINATIONS: usize = 256;
pub const MAX_EGRESS_ADDRESSES_PER_INTENT: usize = 16;
pub const MAX_EGRESS_LABELS: usize = 64;
pub const MAX_EGRESS_EXPRESSIONS: usize = 64;
pub const MAX_EGRESS_EXPRESSION_VALUES: usize = 64;
pub const MAX_EGRESS_SERVICE_ACCOUNTS: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum AddressFamily {
    Ipv4,
    Ipv6,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct IpPrefix {
    pub address: IpAddr,
    pub prefix_len: u8,
}

impl IpPrefix {
    #[must_use]
    pub const fn family(self) -> AddressFamily {
        match self.address {
            IpAddr::V4(_) => AddressFamily::Ipv4,
            IpAddr::V6(_) => AddressFamily::Ipv6,
        }
    }

    #[must_use]
    pub fn is_canonical(self) -> bool {
        match self.address {
            IpAddr::V4(address) => {
                self.prefix_len <= 32
                    && (u32::from(address) & ipv4_mask(self.prefix_len)) == u32::from(address)
            }
            IpAddr::V6(address) => {
                self.prefix_len <= 128
                    && (u128::from(address) & ipv6_mask(self.prefix_len)) == u128::from(address)
            }
        }
    }

    #[must_use]
    pub fn contains(self, address: IpAddr) -> bool {
        match (self.address, address) {
            (IpAddr::V4(network), IpAddr::V4(candidate)) if self.prefix_len <= 32 => {
                u32::from(candidate) & ipv4_mask(self.prefix_len) == u32::from(network)
            }
            (IpAddr::V6(network), IpAddr::V6(candidate)) if self.prefix_len <= 128 => {
                u128::from(candidate) & ipv6_mask(self.prefix_len) == u128::from(network)
            }
            _ => false,
        }
    }

    #[must_use]
    pub fn overlaps(self, other: Self) -> bool {
        self.family() == other.family()
            && (self.contains(other.address) || other.contains(self.address))
    }
}

const fn ipv4_mask(prefix_len: u8) -> u32 {
    if prefix_len == 0 {
        0
    } else if prefix_len <= 32 {
        u32::MAX << (32 - prefix_len)
    } else {
        0
    }
}

const fn ipv6_mask(prefix_len: u8) -> u128 {
    if prefix_len == 0 {
        0
    } else if prefix_len <= 128 {
        u128::MAX << (128 - prefix_len)
    } else {
        0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum LabelExpressionOperator {
    In,
    NotIn,
    Exists,
    DoesNotExist,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct LabelExpression {
    pub key: String,
    pub operator: LabelExpressionOperator,
    pub values: BTreeSet<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct LabelSelector {
    pub match_labels: BTreeMap<String, String>,
    pub match_expressions: Vec<LabelExpression>,
}

impl LabelSelector {
    #[must_use]
    pub fn matches(&self, labels: &BTreeMap<String, String>) -> bool {
        self.match_labels
            .iter()
            .all(|(key, value)| labels.get(key) == Some(value))
            && self.match_expressions.iter().all(|expression| {
                let value = labels.get(&expression.key);
                match expression.operator {
                    LabelExpressionOperator::In => {
                        value.is_some_and(|value| expression.values.contains(value))
                    }
                    LabelExpressionOperator::NotIn => {
                        value.is_none_or(|value| !expression.values.contains(value))
                    }
                    LabelExpressionOperator::Exists => value.is_some(),
                    LabelExpressionOperator::DoesNotExist => value.is_none(),
                }
            })
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EgressSourceSelector {
    pub namespace: LabelSelector,
    pub workload: LabelSelector,
    pub service_accounts: BTreeSet<String>,
}

impl EgressSourceSelector {
    #[must_use]
    pub fn matches(
        &self,
        namespace_labels: &BTreeMap<String, String>,
        workload_labels: &BTreeMap<String, String>,
        service_account: &str,
    ) -> bool {
        self.namespace.matches(namespace_labels)
            && self.workload.matches(workload_labels)
            && (self.service_accounts.is_empty() || self.service_accounts.contains(service_account))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(
    deny_unknown_fields,
    rename_all = "camelCase",
    tag = "kind",
    content = "networks"
)]
pub enum EgressDestinations {
    Any,
    Networks(Vec<IpPrefix>),
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EgressProviderRef {
    pub name: String,
    pub instance: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EgressAddressPool {
    pub name: String,
    pub uid: String,
    pub provider: EgressProviderRef,
    pub prefixes: Vec<IpPrefix>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub enum EgressIntentScope {
    Cluster,
    Namespace(String),
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EgressIntentOwner {
    pub scope: EgressIntentScope,
    pub name: String,
    pub uid: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase", tag = "kind")]
pub enum EgressAddressRequest {
    Pool {
        name: String,
        families: Vec<AddressFamily>,
        addresses_per_family: u16,
    },
    Explicit {
        addresses: Vec<IpAddr>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EgressIntent {
    pub owner: EgressIntentOwner,
    pub priority: u32,
    pub source: EgressSourceSelector,
    pub destinations: EgressDestinations,
    pub addresses: EgressAddressRequest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EgressModel {
    pub pools: Vec<EgressAddressPool>,
    pub intents: Vec<EgressIntent>,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum EgressModelError {
    #[error("egress model has {actual} pools; limit is {limit}")]
    TooManyPools { actual: usize, limit: usize },
    #[error("egress model has {actual} intents; limit is {limit}")]
    TooManyIntents { actual: usize, limit: usize },
    #[error("invalid egress pool {pool:?}: {reason}")]
    InvalidPool { pool: String, reason: &'static str },
    #[error("duplicate egress pool name {0:?}")]
    DuplicatePoolName(String),
    #[error("duplicate egress pool UID {0:?}")]
    DuplicatePoolUid(String),
    #[error("egress pools {left:?} and {right:?} overlap at {left_prefix:?}/{right_prefix:?}")]
    OverlappingPools {
        left: String,
        right: String,
        left_prefix: IpPrefix,
        right_prefix: IpPrefix,
    },
    #[error("invalid egress intent {intent:?}: {reason}")]
    InvalidIntent {
        intent: String,
        reason: &'static str,
    },
    #[error("duplicate egress intent owner {0:?}")]
    DuplicateIntentOwner(EgressIntentOwner),
    #[error("duplicate egress intent UID {0:?}")]
    DuplicateIntentUid(String),
    #[error("egress intent {intent:?} refers to unknown pool {pool:?}")]
    UnknownPool { intent: String, pool: String },
    #[error("egress intent {intent:?} requests {family:?}, absent from pool {pool:?}")]
    MissingPoolFamily {
        intent: String,
        pool: String,
        family: AddressFamily,
    },
    #[error("invalid {selector} selector for intent {intent:?}: {reason}")]
    InvalidSelector {
        intent: String,
        selector: &'static str,
        reason: &'static str,
    },
}

/// Validates and deterministically orders a complete pool set.
///
/// # Errors
///
/// Rejects unbounded, duplicate, non-canonical, or overlapping pool state.
pub fn normalize_pools(
    mut pools: Vec<EgressAddressPool>,
) -> Result<Vec<EgressAddressPool>, EgressModelError> {
    if pools.len() > MAX_EGRESS_POOLS {
        return Err(EgressModelError::TooManyPools {
            actual: pools.len(),
            limit: MAX_EGRESS_POOLS,
        });
    }
    for pool in &mut pools {
        validate_pool(pool)?;
        pool.prefixes.sort_unstable();
    }
    pools.sort_by(|left, right| left.name.cmp(&right.name));
    let mut names = BTreeSet::new();
    let mut uids = BTreeSet::new();
    for pool in &pools {
        if !names.insert(pool.name.clone()) {
            return Err(EgressModelError::DuplicatePoolName(pool.name.clone()));
        }
        if !uids.insert(pool.uid.clone()) {
            return Err(EgressModelError::DuplicatePoolUid(pool.uid.clone()));
        }
    }
    for (index, left) in pools.iter().enumerate() {
        for right in pools.iter().skip(index + 1) {
            for left_prefix in &left.prefixes {
                if let Some(right_prefix) = right
                    .prefixes
                    .iter()
                    .find(|candidate| left_prefix.overlaps(**candidate))
                {
                    return Err(EgressModelError::OverlappingPools {
                        left: left.name.clone(),
                        right: right.name.clone(),
                        left_prefix: *left_prefix,
                        right_prefix: *right_prefix,
                    });
                }
            }
        }
    }
    Ok(pools)
}

/// Validates and deterministically orders one normalized egress intent.
///
/// # Errors
///
/// Rejects invalid ownership, selectors, destinations, or address requests.
pub fn normalize_intent(mut intent: EgressIntent) -> Result<EgressIntent, EgressModelError> {
    validate_owner(&intent.owner)?;
    if intent.priority == 0 {
        return Err(invalid_intent(&intent, "priority zero is reserved"));
    }
    validate_selector(
        &intent.owner.name,
        "namespace",
        &mut intent.source.namespace,
    )?;
    validate_selector(&intent.owner.name, "workload", &mut intent.source.workload)?;
    if intent.source.service_accounts.len() > MAX_EGRESS_SERVICE_ACCOUNTS
        || intent
            .source
            .service_accounts
            .iter()
            .any(|name| !valid_name(name))
    {
        return Err(invalid_intent(
            &intent,
            "service-account selector is invalid or exceeds its bound",
        ));
    }
    normalize_destinations(&intent.owner.name, &mut intent.destinations)?;
    normalize_address_request(&intent.owner.name, &mut intent.addresses)?;
    Ok(intent)
}

/// Validates and deterministically orders a complete intent set.
///
/// # Errors
///
/// Rejects invalid or duplicate owner identity.
pub fn normalize_intents(
    intents: Vec<EgressIntent>,
) -> Result<Vec<EgressIntent>, EgressModelError> {
    if intents.len() > MAX_EGRESS_INTENTS {
        return Err(EgressModelError::TooManyIntents {
            actual: intents.len(),
            limit: MAX_EGRESS_INTENTS,
        });
    }
    let mut normalized = intents
        .into_iter()
        .map(normalize_intent)
        .collect::<Result<Vec<_>, _>>()?;
    normalized
        .sort_by(|left, right| (left.priority, &left.owner).cmp(&(right.priority, &right.owner)));
    let mut owners = BTreeSet::new();
    let mut uids = BTreeSet::new();
    for intent in &normalized {
        if !owners.insert((intent.owner.scope.clone(), intent.owner.name.clone())) {
            return Err(EgressModelError::DuplicateIntentOwner(intent.owner.clone()));
        }
        if !uids.insert(intent.owner.uid.clone()) {
            return Err(EgressModelError::DuplicateIntentUid(
                intent.owner.uid.clone(),
            ));
        }
    }
    Ok(normalized)
}

/// Validates a coherent model, including intent references to pool families.
///
/// # Errors
///
/// Rejects any invalid set, unknown pool, or unavailable requested family.
pub fn normalize_model(
    pools: Vec<EgressAddressPool>,
    intents: Vec<EgressIntent>,
) -> Result<EgressModel, EgressModelError> {
    let pools = normalize_pools(pools)?;
    let intents = normalize_intents(intents)?;
    let pools_by_name = pools
        .iter()
        .map(|pool| (pool.name.as_str(), pool))
        .collect::<BTreeMap<_, _>>();
    for intent in &intents {
        let EgressAddressRequest::Pool { name, families, .. } = &intent.addresses else {
            continue;
        };
        let Some(pool) = pools_by_name.get(name.as_str()) else {
            return Err(EgressModelError::UnknownPool {
                intent: intent.owner.name.clone(),
                pool: name.clone(),
            });
        };
        for family in families {
            if !pool
                .prefixes
                .iter()
                .any(|prefix| prefix.family() == *family)
            {
                return Err(EgressModelError::MissingPoolFamily {
                    intent: intent.owner.name.clone(),
                    pool: name.clone(),
                    family: *family,
                });
            }
        }
    }
    Ok(EgressModel { pools, intents })
}

fn validate_pool(pool: &EgressAddressPool) -> Result<(), EgressModelError> {
    let invalid = |reason| EgressModelError::InvalidPool {
        pool: pool.name.clone(),
        reason,
    };
    if !valid_name(&pool.name) || !valid_uid(&pool.uid) {
        return Err(invalid("name and UID must be nonempty and bounded"));
    }
    if !valid_name(&pool.provider.name) || !valid_uid(&pool.provider.instance) {
        return Err(invalid(
            "provider name and instance must be nonempty and bounded",
        ));
    }
    if pool.prefixes.is_empty() || pool.prefixes.len() > MAX_EGRESS_POOL_PREFIXES {
        return Err(invalid("prefix set must be nonempty and bounded"));
    }
    if pool.prefixes.iter().any(|prefix| !prefix.is_canonical()) {
        return Err(invalid("prefixes must be family-valid and canonical"));
    }
    let unique = pool.prefixes.iter().copied().collect::<BTreeSet<_>>();
    if unique.len() != pool.prefixes.len() {
        return Err(invalid("duplicate prefixes are forbidden"));
    }
    for (index, left) in pool.prefixes.iter().enumerate() {
        if pool
            .prefixes
            .iter()
            .skip(index + 1)
            .any(|right| left.overlaps(*right))
        {
            return Err(invalid("prefixes within a pool must not overlap"));
        }
    }
    Ok(())
}

fn validate_owner(owner: &EgressIntentOwner) -> Result<(), EgressModelError> {
    let invalid = |reason| EgressModelError::InvalidIntent {
        intent: owner.name.clone(),
        reason,
    };
    if !valid_name(&owner.name) || !valid_uid(&owner.uid) {
        return Err(invalid("owner name and UID must be nonempty and bounded"));
    }
    if matches!(&owner.scope, EgressIntentScope::Namespace(namespace) if !valid_name(namespace)) {
        return Err(invalid("owner namespace must be nonempty and bounded"));
    }
    Ok(())
}

fn validate_selector(
    intent: &str,
    selector_name: &'static str,
    selector: &mut LabelSelector,
) -> Result<(), EgressModelError> {
    let invalid = |reason| EgressModelError::InvalidSelector {
        intent: intent.to_owned(),
        selector: selector_name,
        reason,
    };
    if selector.match_labels.len() > MAX_EGRESS_LABELS
        || selector
            .match_labels
            .iter()
            .any(|(key, value)| !valid_label_key(key) || !valid_label_value(value))
    {
        return Err(invalid("matchLabels is invalid or exceeds its bound"));
    }
    if selector.match_expressions.len() > MAX_EGRESS_EXPRESSIONS {
        return Err(invalid("matchExpressions exceeds its bound"));
    }
    for expression in &selector.match_expressions {
        if !valid_label_key(&expression.key)
            || expression.values.len() > MAX_EGRESS_EXPRESSION_VALUES
        {
            return Err(invalid("expression key or values are invalid or unbounded"));
        }
        let values_required = matches!(
            expression.operator,
            LabelExpressionOperator::In | LabelExpressionOperator::NotIn
        );
        if values_required == expression.values.is_empty()
            || expression
                .values
                .iter()
                .any(|value| !valid_label_value(value))
        {
            return Err(invalid("expression operator has invalid value cardinality"));
        }
    }
    selector.match_expressions.sort_unstable();
    if selector
        .match_expressions
        .windows(2)
        .any(|pair| pair[0] == pair[1])
    {
        return Err(invalid("duplicate matchExpressions are forbidden"));
    }
    Ok(())
}

fn normalize_destinations(
    intent: &str,
    destinations: &mut EgressDestinations,
) -> Result<(), EgressModelError> {
    let EgressDestinations::Networks(networks) = destinations else {
        return Ok(());
    };
    if networks.is_empty() || networks.len() > MAX_EGRESS_DESTINATIONS {
        return Err(EgressModelError::InvalidIntent {
            intent: intent.to_owned(),
            reason: "destination network set must be nonempty and bounded",
        });
    }
    if networks.iter().any(|prefix| !prefix.is_canonical()) {
        return Err(EgressModelError::InvalidIntent {
            intent: intent.to_owned(),
            reason: "destination prefixes must be family-valid and canonical",
        });
    }
    networks.sort_unstable();
    if networks.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(EgressModelError::InvalidIntent {
            intent: intent.to_owned(),
            reason: "duplicate destination prefixes are forbidden",
        });
    }
    Ok(())
}

fn normalize_address_request(
    intent: &str,
    request: &mut EgressAddressRequest,
) -> Result<(), EgressModelError> {
    let invalid = |reason| EgressModelError::InvalidIntent {
        intent: intent.to_owned(),
        reason,
    };
    match request {
        EgressAddressRequest::Pool {
            name,
            families,
            addresses_per_family,
        } => {
            if !valid_name(name) {
                return Err(invalid("pool reference must be nonempty and bounded"));
            }
            families.sort_unstable();
            families.dedup();
            if families.is_empty() {
                return Err(invalid("at least one address family is required"));
            }
            if *addresses_per_family == 0
                || usize::from(*addresses_per_family) > MAX_EGRESS_ADDRESSES_PER_INTENT
            {
                return Err(invalid("address count is zero or exceeds its bound"));
            }
        }
        EgressAddressRequest::Explicit { addresses } => {
            if addresses.is_empty() || addresses.len() > MAX_EGRESS_ADDRESSES_PER_INTENT {
                return Err(invalid("explicit address set must be nonempty and bounded"));
            }
            addresses.sort_unstable();
            if addresses.windows(2).any(|pair| pair[0] == pair[1]) {
                return Err(invalid("duplicate explicit addresses are forbidden"));
            }
            if addresses.iter().any(IpAddr::is_unspecified) {
                return Err(invalid("unspecified explicit addresses are forbidden"));
            }
        }
    }
    Ok(())
}

fn invalid_intent(intent: &EgressIntent, reason: &'static str) -> EgressModelError {
    EgressModelError::InvalidIntent {
        intent: intent.owner.name.clone(),
        reason,
    }
}

fn valid_name(value: &str) -> bool {
    !value.is_empty() && value.len() <= 253
}

fn valid_uid(value: &str) -> bool {
    !value.is_empty() && value.len() <= 128
}

fn valid_label_key(value: &str) -> bool {
    let Some((prefix, name)) = value.split_once('/') else {
        return valid_label_name(value);
    };
    !prefix.contains('/') && valid_dns_subdomain(prefix) && valid_label_name(name)
}

fn valid_label_value(value: &str) -> bool {
    value.is_empty() || valid_label_name(value)
}

fn valid_label_name(value: &str) -> bool {
    value.len() <= 63
        && value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && value
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn valid_dns_subdomain(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value.split('.').all(|label| {
            label.len() <= 63
                && label
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .as_bytes()
                    .last()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn prefix(address: &str, prefix_len: u8) -> IpPrefix {
        IpPrefix {
            address: address.parse().expect("valid test address"),
            prefix_len,
        }
    }

    fn pool(name: &str, uid: &str, prefixes: Vec<IpPrefix>) -> EgressAddressPool {
        EgressAddressPool {
            name: name.to_owned(),
            uid: uid.to_owned(),
            provider: EgressProviderRef {
                name: "static".to_owned(),
                instance: "lab".to_owned(),
            },
            prefixes,
        }
    }

    fn intent(name: &str) -> EgressIntent {
        EgressIntent {
            owner: EgressIntentOwner {
                scope: EgressIntentScope::Namespace("finance".to_owned()),
                name: name.to_owned(),
                uid: format!("uid-{name}"),
            },
            priority: DEFAULT_EGRESS_INTENT_PRIORITY,
            source: EgressSourceSelector::default(),
            destinations: EgressDestinations::Any,
            addresses: EgressAddressRequest::Pool {
                name: "finance".to_owned(),
                families: vec![AddressFamily::Ipv6, AddressFamily::Ipv4],
                addresses_per_family: 2,
            },
        }
    }

    #[test]
    fn dual_stack_pools_and_intents_are_canonical() {
        let pools = normalize_pools(vec![
            pool("z", "uid-z", vec![prefix("2001:db8:2::", 64)]),
            pool(
                "a",
                "uid-a",
                vec![prefix("2001:db8:1::", 64), prefix("192.0.2.0", 24)],
            ),
        ])
        .expect("valid pools");
        assert_eq!(pools[0].name, "a");
        assert_eq!(pools[0].prefixes[0], prefix("192.0.2.0", 24));

        let normalized = normalize_intent(intent("payments")).expect("valid intent");
        let EgressAddressRequest::Pool { families, .. } = normalized.addresses else {
            panic!("expected pool request")
        };
        assert_eq!(families, vec![AddressFamily::Ipv4, AddressFamily::Ipv6]);
    }

    #[test]
    fn rejects_noncanonical_and_overlapping_pool_state() {
        assert!(matches!(
            normalize_pools(vec![pool("bad", "uid-bad", vec![prefix("192.0.2.1", 24)])]),
            Err(EgressModelError::InvalidPool { .. })
        ));
        assert!(matches!(
            normalize_pools(vec![
                pool("a", "uid-a", vec![prefix("192.0.2.0", 24)]),
                pool("b", "uid-b", vec![prefix("192.0.2.128", 25)]),
            ]),
            Err(EgressModelError::OverlappingPools { .. })
        ));
    }

    #[test]
    fn selector_intersects_namespace_workload_and_service_account() {
        let selector = EgressSourceSelector {
            namespace: LabelSelector {
                match_labels: BTreeMap::from([("team".to_owned(), "finance".to_owned())]),
                match_expressions: Vec::new(),
            },
            workload: LabelSelector {
                match_labels: BTreeMap::from([("app".to_owned(), "ledger".to_owned())]),
                match_expressions: Vec::new(),
            },
            service_accounts: BTreeSet::from(["settlement".to_owned()]),
        };
        let namespace = BTreeMap::from([("team".to_owned(), "finance".to_owned())]);
        let workload = BTreeMap::from([("app".to_owned(), "ledger".to_owned())]);
        assert!(selector.matches(&namespace, &workload, "settlement"));
        assert!(!selector.matches(&namespace, &workload, "default"));
    }

    #[test]
    fn empty_selectors_mean_all_but_empty_explicit_addresses_mean_invalid() {
        assert!(EgressSourceSelector::default().matches(
            &BTreeMap::new(),
            &BTreeMap::new(),
            "default"
        ));
        let mut candidate = intent("empty");
        candidate.addresses = EgressAddressRequest::Explicit {
            addresses: Vec::new(),
        };
        assert!(matches!(
            normalize_intent(candidate),
            Err(EgressModelError::InvalidIntent { .. })
        ));
    }

    #[test]
    fn expression_value_contract_is_strict() {
        let mut candidate = intent("expression");
        candidate.source.workload.match_expressions = vec![LabelExpression {
            key: "app".to_owned(),
            operator: LabelExpressionOperator::Exists,
            values: BTreeSet::from(["illegal".to_owned()]),
        }];
        assert!(matches!(
            normalize_intent(candidate),
            Err(EgressModelError::InvalidSelector { .. })
        ));
    }

    #[test]
    fn explicit_addresses_are_sorted_and_unspecified_is_rejected() {
        let mut candidate = intent("explicit");
        candidate.addresses = EgressAddressRequest::Explicit {
            addresses: vec![
                "2001:db8::20".parse().expect("valid"),
                "192.0.2.20".parse().expect("valid"),
            ],
        };
        let normalized = normalize_intent(candidate).expect("valid explicit intent");
        let EgressAddressRequest::Explicit { addresses } = normalized.addresses else {
            panic!("expected explicit request")
        };
        assert_eq!(addresses[0], IpAddr::V4(Ipv4Addr::new(192, 0, 2, 20)));

        let mut invalid = intent("unspecified");
        invalid.addresses = EgressAddressRequest::Explicit {
            addresses: vec![IpAddr::V6(Ipv6Addr::UNSPECIFIED)],
        };
        assert!(normalize_intent(invalid).is_err());
    }

    #[test]
    fn complete_intent_set_uses_priority_then_owner_order() {
        let mut later = intent("later");
        later.priority = 2_000;
        let earlier = intent("earlier");
        let normalized = normalize_intents(vec![later, earlier]).expect("valid set");
        assert_eq!(normalized[0].owner.name, "earlier");
    }

    #[test]
    fn coherent_model_checks_pool_references_and_families() {
        let ipv4_pool = pool("finance", "uid-pool", vec![prefix("192.0.2.0", 24)]);
        let mut candidate = intent("payments");
        candidate.addresses = EgressAddressRequest::Pool {
            name: "finance".to_owned(),
            families: vec![AddressFamily::Ipv6],
            addresses_per_family: 1,
        };
        assert!(matches!(
            normalize_model(vec![ipv4_pool], vec![candidate]),
            Err(EgressModelError::MissingPoolFamily {
                family: AddressFamily::Ipv6,
                ..
            })
        ));
    }

    #[test]
    fn rejects_malformed_label_syntax() {
        let mut candidate = intent("labels");
        candidate.source.workload.match_labels =
            BTreeMap::from([("not a key".to_owned(), "valid".to_owned())]);
        assert!(matches!(
            normalize_intent(candidate),
            Err(EgressModelError::InvalidSelector { .. })
        ));
    }

    #[test]
    fn serialized_model_rejects_unknown_fields() {
        let json = serde_json::json!({
            "address": "192.0.2.0",
            "prefixLen": 24,
            "provider": "foreign"
        });
        assert!(serde_json::from_value::<IpPrefix>(json).is_err());
    }
}
