use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use futures::TryStreamExt as _;
use rtnetlink::packet_route::AddressFamily;
use rtnetlink::packet_route::route::{
    RouteAddress, RouteAttribute, RouteMessage, RouteProtocol, RouteScope,
};
use rtnetlink::packet_route::rule::{RuleAction, RuleAttribute, RuleMessage};
use rtnetlink::{Handle, IpVersion, RouteMessageBuilder};
use unf_ebpf_common::{ENCRYPTION_ROUTE_MARK_MASK, encryption_route_mark};

use super::{
    EncryptionPolicyRouteRule, EncryptionRouteAuthority, EncryptionRouteAuthorityError,
    EncryptionRouteFamily, EncryptionRoutePublicationPermit, EncryptionRouteWitness, rule_priority,
};
use crate::{IpPrefix, UNF_WIREGUARD_ROUTE_PROTOCOL, WireGuardKernelPlan, WireGuardRouteScope};

const MAX_KERNEL_RULE_READBACK: usize = 262_144;
const MAX_KERNEL_ROUTE_READBACK: usize = 262_144;
// Linux's built-in `main` rule normally starts at 32_766. UNF's two
// alternating table-lookup slots are 30_000 and 30_001, so this common tier
// is evaluated after either successful lookup but before `main`. Rules at this
// tier have disjoint masked marks; sharing a priority is therefore unambiguous.
const UNF_ENCRYPTION_TERMINAL_RULE_PRIORITY: u32 = 30_002;

#[derive(Debug, Clone, Copy)]
enum CreatedRuleKind {
    Lookup,
    Terminal,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct LinuxEncryptionRouteProvider;

impl LinuxEncryptionRouteProvider {
    /// Installs exact masked rules only after every referenced route passes
    /// independent rtnetlink readback. A permit is returned only after a
    /// second exact rule readback; partial new rules are rolled back.
    ///
    /// # Errors
    ///
    /// Refuses missing/mutated routes, conflicting priorities/selectors,
    /// foreign attributes, kernel errors, or incomplete rollback.
    pub async fn activate(
        &self,
        authority: &EncryptionRouteAuthority,
    ) -> Result<EncryptionRoutePublicationPermit, EncryptionRouteAuthorityError> {
        authority.verify()?;
        let handle = connect_route("open encryption policy-route connection")?;
        require_exact_routes(&handle, &authority.routes).await?;
        let before = list_rules(&handle).await?;
        preflight_rules(&before, &authority.rules)?;

        let mut created = Vec::new();
        for rule in &authority.rules {
            if find_exact_terminal_rule(&before, rule).is_none() {
                if let Err(cause) = add_terminal_rule(&handle, rule).await {
                    return rollback_or_error(&handle, &created, cause).await;
                }
                created.push((rule.clone(), CreatedRuleKind::Terminal));
            }
            if find_exact_rule(&before, rule).is_some() {
                continue;
            }
            if let Err(cause) = add_rule(&handle, rule).await {
                return rollback_or_error(&handle, &created, cause).await;
            }
            created.push((rule.clone(), CreatedRuleKind::Lookup));
        }
        let observed = match exact_desired_rules(&handle, &authority.rules).await {
            Ok(observed) => observed,
            Err(cause) => return rollback_or_error(&handle, &created, cause).await,
        };
        authority.authorize_publication(&observed)
    }

    /// Removes only exact rules described by a verified authority and proves
    /// their absence. Routes and interfaces are deliberately untouched.
    ///
    /// # Errors
    ///
    /// Refuses foreign or partially matching state instead of broad deletion.
    pub async fn deactivate(
        &self,
        authority: &EncryptionRouteAuthority,
    ) -> Result<(), EncryptionRouteAuthorityError> {
        authority.verify()?;
        let handle = connect_route("open encryption policy-route cleanup connection")?;
        let observed = list_rules(&handle).await?;
        preflight_rules(&observed, &authority.rules)?;
        for rule in authority.rules.iter().rev() {
            if let Some(message) = find_exact_rule(&observed, rule) {
                handle
                    .rule()
                    .del(message.clone())
                    .execute()
                    .await
                    .map_err(|error| kernel("delete encryption policy rule", &error))?;
            }
            if let Some(message) = find_exact_terminal_rule(&observed, rule) {
                handle
                    .rule()
                    .del(message.clone())
                    .execute()
                    .await
                    .map_err(|error| kernel("delete encryption terminal rule", &error))?;
            }
        }
        let remaining = list_rules(&handle).await?;
        if authority.rules.iter().any(|rule| {
            find_exact_rule(&remaining, rule).is_some()
                || find_exact_terminal_rule(&remaining, rule).is_some()
        }) {
            return Err(EncryptionRouteAuthorityError::RuleReadbackMismatch);
        }
        Ok(())
    }

    /// Removes the exact policy rules owned by one retiring `WireGuard` plan.
    /// This deliberately derives the ownership key from the digest-verified
    /// plan, so restart recovery never needs a broad priority/table sweep.
    ///
    /// # Errors
    ///
    /// Refuses a malformed plan or any priority/selector collision that is
    /// not byte-exact UNF state. Success includes positive rule absence.
    pub async fn deactivate_plan(
        &self,
        plan: &WireGuardKernelPlan,
    ) -> Result<(), EncryptionRouteAuthorityError> {
        plan.verify()
            .map_err(EncryptionRouteAuthorityError::InvalidKernelSnapshot)?;
        let route_mark =
            encryption_route_mark(plan.fwmark).ok_or(EncryptionRouteAuthorityError::InvalidRule)?;
        let priority = rule_priority(route_mark)?;
        let rules = plan
            .route_prefixes()
            .into_iter()
            .map(|prefix| EncryptionPolicyRouteRule {
                family: EncryptionRouteFamily::for_address(prefix.address),
                priority,
                route_mark,
                route_mark_mask: ENCRYPTION_ROUTE_MARK_MASK,
                route_table: plan.route_table,
                outer_fwmark: plan.fwmark,
            })
            .collect::<BTreeSet<_>>();
        let handle = connect_route("open retiring encryption policy-route connection")?;
        let observed = list_rules(&handle).await?;
        let rules = rules.into_iter().collect::<Vec<_>>();
        preflight_rules(&observed, &rules)?;
        for rule in rules.iter().rev() {
            if let Some(message) = find_exact_rule(&observed, rule) {
                handle
                    .rule()
                    .del(message.clone())
                    .execute()
                    .await
                    .map_err(|error| kernel("delete retiring encryption policy rule", &error))?;
            }
            if let Some(message) = find_exact_terminal_rule(&observed, rule) {
                handle
                    .rule()
                    .del(message.clone())
                    .execute()
                    .await
                    .map_err(|error| kernel("delete retiring encryption terminal rule", &error))?;
            }
        }
        let remaining = list_rules(&handle).await?;
        if rules.iter().any(|rule| {
            find_exact_rule(&remaining, rule).is_some()
                || find_exact_terminal_rule(&remaining, rule).is_some()
        }) {
            return Err(EncryptionRouteAuthorityError::RuleReadbackMismatch);
        }
        Ok(())
    }
}

fn connect_route(operation: &'static str) -> Result<Handle, EncryptionRouteAuthorityError> {
    let (connection, handle, _) =
        rtnetlink::new_connection().map_err(|error| EncryptionRouteAuthorityError::Kernel {
            operation,
            message: error.to_string(),
        })?;
    tokio::spawn(connection);
    Ok(handle)
}

async fn add_rule(
    handle: &Handle,
    rule: &EncryptionPolicyRouteRule,
) -> Result<(), EncryptionRouteAuthorityError> {
    let request = handle
        .rule()
        .add()
        .table_id(rule.route_table)
        .priority(rule.priority)
        .fw_mark(rule.route_mark)
        .action(RuleAction::ToTable);
    match rule.family {
        EncryptionRouteFamily::Ipv4 => {
            let mut request = request.v4();
            request
                .message_mut()
                .attributes
                .push(RuleAttribute::FwMask(rule.route_mark_mask));
            request
                .message_mut()
                .attributes
                .push(RuleAttribute::Protocol(RouteProtocol::from(
                    UNF_WIREGUARD_ROUTE_PROTOCOL,
                )));
            request
                .execute()
                .await
                .map_err(|error| kernel("add IPv4 encryption policy rule", &error))
        }
        EncryptionRouteFamily::Ipv6 => {
            let mut request = request.v6();
            request
                .message_mut()
                .attributes
                .push(RuleAttribute::FwMask(rule.route_mark_mask));
            request
                .message_mut()
                .attributes
                .push(RuleAttribute::Protocol(RouteProtocol::from(
                    UNF_WIREGUARD_ROUTE_PROTOCOL,
                )));
            request
                .execute()
                .await
                .map_err(|error| kernel("add IPv6 encryption policy rule", &error))
        }
    }
}

async fn add_terminal_rule(
    handle: &Handle,
    rule: &EncryptionPolicyRouteRule,
) -> Result<(), EncryptionRouteAuthorityError> {
    let request = handle
        .rule()
        .add()
        .table_id(0)
        .priority(UNF_ENCRYPTION_TERMINAL_RULE_PRIORITY)
        .fw_mark(rule.route_mark)
        .action(RuleAction::Unreachable);
    match rule.family {
        EncryptionRouteFamily::Ipv4 => {
            let mut request = request.v4();
            request
                .message_mut()
                .attributes
                .push(RuleAttribute::FwMask(rule.route_mark_mask));
            request
                .message_mut()
                .attributes
                .push(RuleAttribute::Protocol(RouteProtocol::from(
                    UNF_WIREGUARD_ROUTE_PROTOCOL,
                )));
            request
                .execute()
                .await
                .map_err(|error| kernel("add IPv4 encryption terminal rule", &error))
        }
        EncryptionRouteFamily::Ipv6 => {
            let mut request = request.v6();
            request
                .message_mut()
                .attributes
                .push(RuleAttribute::FwMask(rule.route_mark_mask));
            request
                .message_mut()
                .attributes
                .push(RuleAttribute::Protocol(RouteProtocol::from(
                    UNF_WIREGUARD_ROUTE_PROTOCOL,
                )));
            request
                .execute()
                .await
                .map_err(|error| kernel("add IPv6 encryption terminal rule", &error))
        }
    }
}

async fn rollback_or_error<T>(
    handle: &Handle,
    created: &[(EncryptionPolicyRouteRule, CreatedRuleKind)],
    cause: EncryptionRouteAuthorityError,
) -> Result<T, EncryptionRouteAuthorityError> {
    match rollback_created(handle, created).await {
        Ok(()) => Err(cause),
        Err(rollback) => Err(EncryptionRouteAuthorityError::Rollback {
            cause: cause.to_string(),
            rollback: rollback.to_string(),
        }),
    }
}

async fn rollback_created(
    handle: &Handle,
    created: &[(EncryptionPolicyRouteRule, CreatedRuleKind)],
) -> Result<(), EncryptionRouteAuthorityError> {
    let observed = list_rules(handle).await?;
    for (rule, kind) in created.iter().rev() {
        let message = match kind {
            CreatedRuleKind::Lookup => find_exact_rule(&observed, rule),
            CreatedRuleKind::Terminal => find_exact_terminal_rule(&observed, rule),
        }
        .ok_or_else(|| {
            EncryptionRouteAuthorityError::ForeignState(
                "new policy rule changed before rollback".to_owned(),
            )
        })?;
        handle
            .rule()
            .del(message.clone())
            .execute()
            .await
            .map_err(|error| kernel("rollback encryption policy rule", &error))?;
    }
    let remaining = list_rules(handle).await?;
    if created.iter().any(|(rule, kind)| match kind {
        CreatedRuleKind::Lookup => find_exact_rule(&remaining, rule).is_some(),
        CreatedRuleKind::Terminal => find_exact_terminal_rule(&remaining, rule).is_some(),
    }) {
        return Err(EncryptionRouteAuthorityError::RuleReadbackMismatch);
    }
    Ok(())
}

async fn exact_desired_rules(
    handle: &Handle,
    desired: &[EncryptionPolicyRouteRule],
) -> Result<Vec<EncryptionPolicyRouteRule>, EncryptionRouteAuthorityError> {
    let observed = list_rules(handle).await?;
    preflight_rules(&observed, desired)?;
    if desired.iter().any(|rule| {
        find_exact_rule(&observed, rule).is_none()
            || find_exact_terminal_rule(&observed, rule).is_none()
    }) {
        return Err(EncryptionRouteAuthorityError::RuleReadbackMismatch);
    }
    Ok(desired.to_vec())
}

fn preflight_rules(
    observed: &BTreeMap<EncryptionRouteFamily, Vec<RuleMessage>>,
    desired: &[EncryptionPolicyRouteRule],
) -> Result<(), EncryptionRouteAuthorityError> {
    for rule in desired {
        let family = observed
            .get(&rule.family)
            .map(Vec::as_slice)
            .unwrap_or_default();
        let lookup_collisions = family
            .iter()
            .filter(|message| lookup_rule_key_collides(message, rule))
            .collect::<Vec<_>>();
        match lookup_collisions.as_slice() {
            [] => {}
            [message] if rule_is_exact(message, rule) => {}
            _ => {
                return Err(EncryptionRouteAuthorityError::ForeignState(format!(
                    "{:?} lookup rule priority {} or selector {:#010x}/{:#010x} is not exactly UNF-owned: {lookup_collisions:?}",
                    rule.family, rule.priority, rule.route_mark, rule.route_mark_mask,
                )));
            }
        }
        let terminal_collisions = family
            .iter()
            .filter(|message| terminal_rule_key_collides(message, rule))
            .collect::<Vec<_>>();
        match terminal_collisions.as_slice() {
            [] => {}
            [message] if terminal_rule_is_exact(message, rule) => {}
            _ => {
                return Err(EncryptionRouteAuthorityError::ForeignState(format!(
                    "{:?} terminal rule priority {} or selector {:#010x}/{:#010x} is not exactly UNF-owned: {terminal_collisions:?}",
                    rule.family,
                    UNF_ENCRYPTION_TERMINAL_RULE_PRIORITY,
                    rule.route_mark,
                    rule.route_mark_mask,
                )));
            }
        }
    }
    Ok(())
}

fn find_exact_rule<'a>(
    observed: &'a BTreeMap<EncryptionRouteFamily, Vec<RuleMessage>>,
    desired: &EncryptionPolicyRouteRule,
) -> Option<&'a RuleMessage> {
    observed
        .get(&desired.family)?
        .iter()
        .find(|message| rule_is_exact(message, desired))
}

fn find_exact_terminal_rule<'a>(
    observed: &'a BTreeMap<EncryptionRouteFamily, Vec<RuleMessage>>,
    desired: &EncryptionPolicyRouteRule,
) -> Option<&'a RuleMessage> {
    observed
        .get(&desired.family)?
        .iter()
        .find(|message| terminal_rule_is_exact(message, desired))
}

fn lookup_rule_key_collides(message: &RuleMessage, desired: &EncryptionPolicyRouteRule) -> bool {
    rule_priority_value(message) == Some(desired.priority)
        || (rule_fwmark(message) == Some(desired.route_mark)
            && rule_fwmask(message).unwrap_or(u32::MAX) == desired.route_mark_mask
            && !terminal_rule_is_exact(message, desired))
}

fn terminal_rule_key_collides(message: &RuleMessage, desired: &EncryptionPolicyRouteRule) -> bool {
    let same_selector = rule_fwmark(message) == Some(desired.route_mark)
        && rule_fwmask(message).unwrap_or(u32::MAX) == desired.route_mark_mask;
    same_selector
        && (rule_priority_value(message) == Some(UNF_ENCRYPTION_TERMINAL_RULE_PRIORITY)
            || !rule_is_exact(message, desired))
}

fn rule_is_exact(message: &RuleMessage, desired: &EncryptionPolicyRouteRule) -> bool {
    message.header.family
        == match desired.family {
            EncryptionRouteFamily::Ipv4 => AddressFamily::Inet,
            EncryptionRouteFamily::Ipv6 => AddressFamily::Inet6,
        }
        && message.header.dst_len == 0
        && message.header.src_len == 0
        && message.header.tos == 0
        && message.header.action == RuleAction::ToTable
        && message.header.flags.is_empty()
        && rule_table(message) == desired.route_table
        && rule_priority_value(message) == Some(desired.priority)
        && rule_fwmark(message) == Some(desired.route_mark)
        && rule_fwmask(message) == Some(desired.route_mark_mask)
        && rule_protocol(message) == Some(UNF_WIREGUARD_ROUTE_PROTOCOL)
        && rule_suppress_prefix_len(message).is_none_or(|value| value == u32::MAX)
        && message.attributes.iter().all(|attribute| {
            matches!(
                attribute,
                RuleAttribute::Table(_)
                    | RuleAttribute::Priority(_)
                    | RuleAttribute::FwMark(_)
                    | RuleAttribute::FwMask(_)
                    | RuleAttribute::Protocol(_)
                    | RuleAttribute::SuppressPrefixLen(_)
            )
        })
}

fn terminal_rule_is_exact(message: &RuleMessage, desired: &EncryptionPolicyRouteRule) -> bool {
    message.header.family
        == match desired.family {
            EncryptionRouteFamily::Ipv4 => AddressFamily::Inet,
            EncryptionRouteFamily::Ipv6 => AddressFamily::Inet6,
        }
        && message.header.dst_len == 0
        && message.header.src_len == 0
        && message.header.tos == 0
        && message.header.action == RuleAction::Unreachable
        && message.header.flags.is_empty()
        && rule_table(message) == 0
        && rule_priority_value(message) == Some(UNF_ENCRYPTION_TERMINAL_RULE_PRIORITY)
        && rule_fwmark(message) == Some(desired.route_mark)
        && rule_fwmask(message) == Some(desired.route_mark_mask)
        && rule_protocol(message) == Some(UNF_WIREGUARD_ROUTE_PROTOCOL)
        && rule_suppress_prefix_len(message).is_none_or(|value| value == u32::MAX)
        && message.attributes.iter().all(|attribute| {
            matches!(
                attribute,
                RuleAttribute::Table(_)
                    | RuleAttribute::Priority(_)
                    | RuleAttribute::FwMark(_)
                    | RuleAttribute::FwMask(_)
                    | RuleAttribute::Protocol(_)
                    | RuleAttribute::SuppressPrefixLen(_)
            )
        })
}

fn rule_table(message: &RuleMessage) -> u32 {
    message
        .attributes
        .iter()
        .find_map(|attribute| match attribute {
            RuleAttribute::Table(value) => Some(*value),
            _ => None,
        })
        .unwrap_or(u32::from(message.header.table))
}

fn rule_priority_value(message: &RuleMessage) -> Option<u32> {
    message
        .attributes
        .iter()
        .find_map(|attribute| match attribute {
            RuleAttribute::Priority(value) => Some(*value),
            _ => None,
        })
}

fn rule_fwmark(message: &RuleMessage) -> Option<u32> {
    message
        .attributes
        .iter()
        .find_map(|attribute| match attribute {
            RuleAttribute::FwMark(value) => Some(*value),
            _ => None,
        })
}

fn rule_fwmask(message: &RuleMessage) -> Option<u32> {
    message
        .attributes
        .iter()
        .find_map(|attribute| match attribute {
            RuleAttribute::FwMask(value) => Some(*value),
            _ => None,
        })
}

fn rule_protocol(message: &RuleMessage) -> Option<u8> {
    message
        .attributes
        .iter()
        .find_map(|attribute| match attribute {
            RuleAttribute::Protocol(value) => Some(u8::from(*value)),
            _ => None,
        })
}

fn rule_suppress_prefix_len(message: &RuleMessage) -> Option<u32> {
    message
        .attributes
        .iter()
        .find_map(|attribute| match attribute {
            RuleAttribute::SuppressPrefixLen(value) => Some(*value),
            _ => None,
        })
}

async fn list_rules(
    handle: &Handle,
) -> Result<BTreeMap<EncryptionRouteFamily, Vec<RuleMessage>>, EncryptionRouteAuthorityError> {
    let mut result = BTreeMap::new();
    for (family, version) in [
        (EncryptionRouteFamily::Ipv4, IpVersion::V4),
        (EncryptionRouteFamily::Ipv6, IpVersion::V6),
    ] {
        let mut rules = handle.rule().get(version).execute();
        let entries = result.entry(family).or_insert_with(Vec::new);
        while let Some(rule) = rules
            .try_next()
            .await
            .map_err(|error| kernel("list encryption policy rules", &error))?
        {
            entries.push(rule);
            if entries.len() > MAX_KERNEL_RULE_READBACK {
                return Err(EncryptionRouteAuthorityError::CapacityExceeded);
            }
        }
    }
    Ok(result)
}

async fn require_exact_routes(
    handle: &Handle,
    desired: &[EncryptionRouteWitness],
) -> Result<(), EncryptionRouteAuthorityError> {
    let messages = list_routes(handle).await?;
    let desired_keys = desired
        .iter()
        .map(|route| (route.prefix, route.route_table))
        .collect::<BTreeSet<_>>();
    let desired_tables = desired
        .iter()
        .map(|route| route.route_table)
        .collect::<BTreeSet<_>>();
    let mut keyed = BTreeMap::<(IpPrefix, u32), Vec<&RouteMessage>>::new();
    for message in &messages {
        if let Some(key) = route_key(message) {
            keyed.entry(key).or_default().push(message);
        }
    }
    for route in desired {
        match keyed
            .get(&(route.prefix, route.route_table))
            .map(Vec::as_slice)
        {
            Some([message]) if route_is_exact(message, route) => {}
            None => return Err(EncryptionRouteAuthorityError::RuleReadbackMismatch),
            _ => {
                return Err(EncryptionRouteAuthorityError::ForeignState(format!(
                    "route {}/{} table {} is not exact before authority",
                    route.prefix.address, route.prefix.prefix_len, route.route_table
                )));
            }
        }
    }
    if messages.iter().any(|message| {
        let table = route_table(message);
        desired_tables.contains(&table)
            && route_key(message).is_none_or(|key| !desired_keys.contains(&key))
            && !is_kernel_generated_multicast(message)
    }) {
        return Err(EncryptionRouteAuthorityError::ForeignState(
            "unexpected route shares an encryption table or interface".to_owned(),
        ));
    }
    Ok(())
}

async fn list_routes(handle: &Handle) -> Result<Vec<RouteMessage>, EncryptionRouteAuthorityError> {
    let mut messages = Vec::new();
    for request in [
        RouteMessageBuilder::<Ipv4Addr>::new().build(),
        RouteMessageBuilder::<Ipv6Addr>::new().build(),
    ] {
        let mut routes = handle.route().get(request).execute();
        while let Some(route) = routes
            .try_next()
            .await
            .map_err(|error| kernel("list encryption routes", &error))?
        {
            messages.push(route);
            if messages.len() > MAX_KERNEL_ROUTE_READBACK {
                return Err(EncryptionRouteAuthorityError::CapacityExceeded);
            }
        }
    }
    Ok(messages)
}

fn route_key(message: &RouteMessage) -> Option<(IpPrefix, u32)> {
    let address = message
        .attributes
        .iter()
        .find_map(|attribute| match attribute {
            RouteAttribute::Destination(RouteAddress::Inet(value)) => Some(IpAddr::V4(*value)),
            RouteAttribute::Destination(RouteAddress::Inet6(value)) => Some(IpAddr::V6(*value)),
            _ => None,
        })?;
    Some((
        IpPrefix {
            address,
            prefix_len: message.header.destination_prefix_length,
        },
        route_table(message),
    ))
}

fn route_table(message: &RouteMessage) -> u32 {
    message
        .attributes
        .iter()
        .find_map(|attribute| match attribute {
            RouteAttribute::Table(value) => Some(*value),
            _ => None,
        })
        .unwrap_or(u32::from(message.header.table))
}

fn is_kernel_generated_multicast(message: &RouteMessage) -> bool {
    route_key(message)
        == Some((
            IpPrefix {
                address: IpAddr::V6(Ipv6Addr::from(0xff00_u128 << 112)),
                prefix_len: 8,
            },
            255,
        ))
        && message.header.protocol == RouteProtocol::Kernel
        && message.header.scope == RouteScope::Universe
}

fn route_is_exact(message: &RouteMessage, desired: &EncryptionRouteWitness) -> bool {
    message.header.protocol == RouteProtocol::from(desired.protocol)
        && message.header.scope
            == match desired.scope {
                WireGuardRouteScope::Link => RouteScope::Link,
                WireGuardRouteScope::Universe => RouteScope::Universe,
            }
        && message.attributes.iter().any(|attribute| {
            matches!(attribute, RouteAttribute::Oif(value) if *value == desired.interface_index)
        })
}

fn kernel(operation: &'static str, error: &rtnetlink::Error) -> EncryptionRouteAuthorityError {
    EncryptionRouteAuthorityError::Kernel {
        operation,
        message: error.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use futures::TryStreamExt as _;
    use rtnetlink::LinkDummy;
    use unf_common::Revision;
    use unf_ebpf_common::{ENCRYPTION_ROUTE_MARK_MASK, encryption_route_mark};

    use super::*;
    use crate::{EncryptionFastPathDigest, EncryptionRouteAuthorityDigest};

    fn live_authority(interface_index: u32) -> EncryptionRouteAuthority {
        let outer_fwmark = 0x0055_0100;
        let route_mark = encryption_route_mark(outer_fwmark).unwrap();
        let priority = super::super::rule_priority(route_mark).unwrap();
        let table = 29_951;
        let mut authority = EncryptionRouteAuthority {
            schema_version: super::super::ENCRYPTION_ROUTE_AUTHORITY_SCHEMA_VERSION,
            generation: Revision::new(51),
            fast_path_digest: EncryptionFastPathDigest([5; 32]),
            rules: vec![
                EncryptionPolicyRouteRule {
                    family: EncryptionRouteFamily::Ipv4,
                    priority,
                    route_mark,
                    route_mark_mask: ENCRYPTION_ROUTE_MARK_MASK,
                    route_table: table,
                    outer_fwmark,
                },
                EncryptionPolicyRouteRule {
                    family: EncryptionRouteFamily::Ipv6,
                    priority,
                    route_mark,
                    route_mark_mask: ENCRYPTION_ROUTE_MARK_MASK,
                    route_table: table,
                    outer_fwmark,
                },
            ],
            routes: vec![
                EncryptionRouteWitness {
                    prefix: IpPrefix {
                        address: "198.51.100.0".parse().unwrap(),
                        prefix_len: 24,
                    },
                    interface_index,
                    route_table: table,
                    protocol: UNF_WIREGUARD_ROUTE_PROTOCOL,
                    scope: WireGuardRouteScope::Link,
                    kernel_configuration_digest: [7; 32],
                },
                EncryptionRouteWitness {
                    prefix: IpPrefix {
                        address: "2001:db8:51::".parse().unwrap(),
                        prefix_len: 64,
                    },
                    interface_index,
                    route_table: table,
                    protocol: UNF_WIREGUARD_ROUTE_PROTOCOL,
                    scope: WireGuardRouteScope::Universe,
                    kernel_configuration_digest: [7; 32],
                },
            ],
            authority_digest: EncryptionRouteAuthorityDigest([0; 32]),
        };
        authority.authority_digest = authority.calculate_digest().unwrap();
        authority.verify().unwrap();
        authority
    }

    fn build_live_route(route: &EncryptionRouteWitness) -> RouteMessage {
        match route.prefix.address {
            IpAddr::V4(address) => RouteMessageBuilder::<Ipv4Addr>::new()
                .destination_prefix(address, route.prefix.prefix_len)
                .output_interface(route.interface_index)
                .table_id(route.route_table)
                .protocol(RouteProtocol::from(route.protocol))
                .scope(RouteScope::Link)
                .build(),
            IpAddr::V6(address) => RouteMessageBuilder::<Ipv6Addr>::new()
                .destination_prefix(address, route.prefix.prefix_len)
                .output_interface(route.interface_index)
                .table_id(route.route_table)
                .protocol(RouteProtocol::from(route.protocol))
                .scope(RouteScope::Universe)
                .build(),
        }
    }

    fn build_rule_message(
        rule: &EncryptionPolicyRouteRule,
        action: RuleAction,
        priority: u32,
    ) -> RuleMessage {
        let mut message = RuleMessage::default();
        message.header.family = match rule.family {
            EncryptionRouteFamily::Ipv4 => AddressFamily::Inet,
            EncryptionRouteFamily::Ipv6 => AddressFamily::Inet6,
        };
        message.header.action = action;
        if action == RuleAction::ToTable {
            message
                .attributes
                .push(RuleAttribute::Table(rule.route_table));
        }
        message.attributes.push(RuleAttribute::Priority(priority));
        message
            .attributes
            .push(RuleAttribute::FwMark(rule.route_mark));
        message
            .attributes
            .push(RuleAttribute::FwMask(rule.route_mark_mask));
        message
            .attributes
            .push(RuleAttribute::Protocol(RouteProtocol::from(
                UNF_WIREGUARD_ROUTE_PROTOCOL,
            )));
        message
    }

    #[test]
    fn lookup_and_terminal_rules_are_exact_and_foreign_safe() {
        let authority = live_authority(51);
        let rule = &authority.rules[0];
        let lookup = build_rule_message(rule, RuleAction::ToTable, rule.priority);
        let terminal = build_rule_message(
            rule,
            RuleAction::Unreachable,
            UNF_ENCRYPTION_TERMINAL_RULE_PRIORITY,
        );
        let observed = BTreeMap::from([(rule.family, vec![lookup, terminal.clone()])]);

        preflight_rules(&observed, std::slice::from_ref(rule)).unwrap();
        assert!(find_exact_rule(&observed, rule).is_some());
        assert!(find_exact_terminal_rule(&observed, rule).is_some());

        let mut unsafe_fallback = terminal;
        unsafe_fallback.header.action = RuleAction::ToTable;
        let observed = BTreeMap::from([(rule.family, vec![unsafe_fallback])]);
        assert!(matches!(
            preflight_rules(&observed, std::slice::from_ref(rule)),
            Err(EncryptionRouteAuthorityError::ForeignState(_))
        ));
    }

    #[tokio::test]
    #[ignore = "requires an isolated network namespace with CAP_NET_ADMIN"]
    async fn privileged_route_before_authority_is_exact_replayable_and_foreign_safe() {
        let interface_name = "unfrtdummy51";
        let handle = connect_route("open route-authority live test").unwrap();
        handle
            .link()
            .add(LinkDummy::new(interface_name).up().build())
            .execute()
            .await
            .unwrap();
        let interface = handle
            .link()
            .get()
            .match_name(interface_name.to_owned())
            .execute()
            .try_next()
            .await
            .unwrap()
            .unwrap();
        let authority = live_authority(interface.header.index);
        let provider = LinuxEncryptionRouteProvider;
        handle
            .route()
            .add(build_live_route(&authority.routes[0]))
            .execute()
            .await
            .unwrap();
        assert!(provider.activate(&authority).await.is_err());
        let before_routes_complete = list_rules(&handle).await.unwrap();
        assert!(
            authority
                .rules
                .iter()
                .all(|rule| find_exact_rule(&before_routes_complete, rule).is_none()),
            "an incomplete route set must not install any authority rule"
        );
        handle
            .route()
            .add(build_live_route(&authority.routes[1]))
            .execute()
            .await
            .unwrap();
        let permit = provider.activate(&authority).await.unwrap();
        assert_eq!(permit.authority_digest(), authority.authority_digest);
        let active_rules = list_rules(&handle).await.unwrap();
        assert!(authority.rules.iter().all(|rule| {
            find_exact_rule(&active_rules, rule).is_some()
                && find_exact_terminal_rule(&active_rules, rule).is_some()
        }));
        assert_eq!(
            provider.activate(&authority).await.unwrap(),
            permit,
            "exact activation must be replayable"
        );
        provider.deactivate(&authority).await.unwrap();
        let deactivated_rules = list_rules(&handle).await.unwrap();
        assert!(authority.rules.iter().all(|rule| {
            find_exact_rule(&deactivated_rules, rule).is_none()
                && find_exact_terminal_rule(&deactivated_rules, rule).is_none()
        }));

        let mut foreign = authority.rules[0].clone();
        foreign.route_table += 1;
        add_rule(&handle, &foreign).await.unwrap();
        assert!(matches!(
            provider.activate(&authority).await,
            Err(EncryptionRouteAuthorityError::ForeignState(_))
        ));
        let observed = list_rules(&handle).await.unwrap();
        let message = find_exact_rule(&observed, &foreign).expect("foreign rule retained");
        handle.rule().del(message.clone()).execute().await.unwrap();
        handle
            .link()
            .del(interface.header.index)
            .execute()
            .await
            .unwrap();
    }
}
