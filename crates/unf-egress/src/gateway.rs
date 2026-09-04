//! Lease-fenced gateway and reachability provider transactions.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use unf_common::Revision;

use crate::{
    EgressAddressLease, EgressIntentOwner, EgressNode, EgressProviderRef, MAX_EGRESS_INTENTS,
};

pub const EGRESS_GATEWAY_DESIRED_SCHEMA_VERSION: u16 = 1;
pub const EGRESS_GATEWAY_ACK_SCHEMA_VERSION: u16 = 1;
pub const EGRESS_GATEWAY_CHECKPOINT_SCHEMA_VERSION: u16 = 1;
pub const MAX_EGRESS_GATEWAY_NODES: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum EgressGatewayAction {
    Ensure,
    Withdraw,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EgressGatewayDesired {
    pub schema_version: u16,
    pub revision: Revision,
    pub allocation_revision: Revision,
    pub owner: EgressIntentOwner,
    pub provider: EgressProviderRef,
    pub lease_epoch: u64,
    pub action: EgressGatewayAction,
    pub addresses: Vec<IpAddr>,
    pub nodes: Vec<EgressNode>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum EgressProviderOutcome {
    Ready,
    Withdrawn,
    Rejected,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EgressGatewayAcknowledgement {
    pub schema_version: u16,
    pub revision: Revision,
    pub desired_revision: Revision,
    pub allocation_revision: Revision,
    pub owner: EgressIntentOwner,
    pub provider: EgressProviderRef,
    pub lease_epoch: u64,
    pub outcome: EgressProviderOutcome,
    pub nodes: Vec<EgressNode>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EgressReachabilityAcknowledgement {
    pub schema_version: u16,
    pub revision: Revision,
    pub desired_revision: Revision,
    pub allocation_revision: Revision,
    pub owner: EgressIntentOwner,
    pub provider: EgressProviderRef,
    pub lease_epoch: u64,
    pub outcome: EgressProviderOutcome,
    pub addresses: Vec<IpAddr>,
    pub error: Option<String>,
}

/// Implemented by a gateway host-state provider without owning allocation or
/// reachability publication semantics.
pub trait EgressGatewayProvider {
    type Error;

    /// Applies exact desired host state and returns revision-bound observation.
    ///
    /// # Errors
    ///
    /// Provider implementations return their own bounded operational error.
    fn reconcile(
        &mut self,
        desired: &EgressGatewayDesired,
    ) -> Result<EgressGatewayAcknowledgement, Self::Error>;
}

/// Implemented independently by a provider that makes translated addresses
/// externally reachable.
pub trait EgressReachabilityProvider {
    type Error;

    /// Applies exact external reachability and returns its independent result.
    ///
    /// # Errors
    ///
    /// Provider implementations return their own bounded operational error.
    fn reconcile(
        &mut self,
        desired: &EgressGatewayDesired,
    ) -> Result<EgressReachabilityAcknowledgement, Self::Error>;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EgressGatewayRecord {
    pub desired: EgressGatewayDesired,
    pub gateway: Option<EgressGatewayAcknowledgement>,
    pub reachability: Option<EgressReachabilityAcknowledgement>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EgressGatewayCheckpoint {
    pub schema_version: u16,
    pub revision: Revision,
    pub records: Vec<EgressGatewayRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum EgressGatewayError {
    #[error("unsupported egress gateway schema {actual}; expected {expected}")]
    UnsupportedSchema { actual: u16, expected: u16 },
    #[error("invalid egress gateway desired state for {0:?}")]
    InvalidDesired(EgressIntentOwner),
    #[error("egress gateway has {actual} records; limit is {limit}")]
    TooManyRecords { actual: usize, limit: usize },
    #[error("egress gateway owner is unknown: {0:?}")]
    UnknownOwner(EgressIntentOwner),
    #[error("egress gateway lease epoch regressed or mutated for {0:?}")]
    LeaseEpochConflict(EgressIntentOwner),
    #[error("egress gateway address {address} remains fenced by {owner:?}")]
    AddressConflict {
        address: IpAddr,
        owner: EgressIntentOwner,
    },
    #[error("egress gateway acknowledgement does not match desired state for {0:?}")]
    AcknowledgementMismatch(EgressIntentOwner),
    #[error("egress gateway acknowledgement revision regressed or mutated for {0:?}")]
    AcknowledgementRevisionConflict(EgressIntentOwner),
    #[error("egress gateway rejection requires one bounded error")]
    InvalidOutcome,
    #[error("egress gateway withdrawal is not completely acknowledged for {0:?}")]
    WithdrawalIncomplete(EgressIntentOwner),
    #[error("egress gateway ownership is not ready for contract publication: {0:?}")]
    NotReady(EgressIntentOwner),
    #[error("egress gateway revision is exhausted")]
    CounterExhausted,
}

#[derive(Debug, Clone, Default)]
pub struct EgressGatewayRegistry {
    revision: Revision,
    records: BTreeMap<EgressIntentOwner, EgressGatewayRecord>,
}

impl EgressGatewayRegistry {
    /// Restores exact desired and acknowledged state after full validation.
    ///
    /// # Errors
    ///
    /// Rejects unsupported, noncanonical, duplicate, stale, or incoherent state.
    pub fn restore(checkpoint: EgressGatewayCheckpoint) -> Result<Self, EgressGatewayError> {
        if checkpoint.schema_version != EGRESS_GATEWAY_CHECKPOINT_SCHEMA_VERSION {
            return Err(EgressGatewayError::UnsupportedSchema {
                actual: checkpoint.schema_version,
                expected: EGRESS_GATEWAY_CHECKPOINT_SCHEMA_VERSION,
            });
        }
        if checkpoint.records.len() > MAX_EGRESS_INTENTS {
            return Err(EgressGatewayError::TooManyRecords {
                actual: checkpoint.records.len(),
                limit: MAX_EGRESS_INTENTS,
            });
        }
        let original = checkpoint.records.clone();
        let mut records = BTreeMap::new();
        let mut address_owners = BTreeMap::new();
        for record in checkpoint.records {
            validate_desired(&record.desired)?;
            if record.desired.revision > checkpoint.revision
                || records
                    .insert(record.desired.owner.clone(), record.clone())
                    .is_some()
            {
                return Err(EgressGatewayError::InvalidDesired(
                    record.desired.owner.clone(),
                ));
            }
            if let Some(ack) = &record.gateway {
                validate_gateway_ack(&record.desired, ack, None)?;
            }
            if let Some(ack) = &record.reachability {
                validate_reachability_ack(&record.desired, ack, None)?;
            }
            for address in &record.desired.addresses {
                if let Some(owner) = address_owners.insert(*address, record.desired.owner.clone()) {
                    return Err(EgressGatewayError::AddressConflict {
                        address: *address,
                        owner,
                    });
                }
            }
        }
        if records.values().cloned().collect::<Vec<_>>() != original {
            return Err(EgressGatewayError::InvalidDesired(
                original
                    .first()
                    .map_or_else(invalid_owner, |record| record.desired.owner.clone()),
            ));
        }
        Ok(Self {
            revision: checkpoint.revision,
            records,
        })
    }

    /// Creates or idempotently returns an exact lease-fenced ensure operation.
    ///
    /// # Errors
    ///
    /// Rejects malformed leases/Nodes, epoch regression or mutation, capacity,
    /// and revision exhaustion without partial mutation.
    pub fn ensure(
        &mut self,
        lease: &EgressAddressLease,
        mut nodes: Vec<EgressNode>,
    ) -> Result<EgressGatewayDesired, EgressGatewayError> {
        nodes.sort_unstable();
        let candidate = EgressGatewayDesired {
            schema_version: EGRESS_GATEWAY_DESIRED_SCHEMA_VERSION,
            revision: Revision::INITIAL,
            allocation_revision: lease.allocation_revision,
            owner: lease.intent.owner.clone(),
            provider: lease.provider.clone(),
            lease_epoch: lease.lease_epoch,
            action: EgressGatewayAction::Ensure,
            addresses: lease.addresses.clone(),
            nodes,
        };
        validate_desired_without_revision(&candidate)?;
        if let Some(existing) = self.records.get(&candidate.owner) {
            if candidate.lease_epoch < existing.desired.lease_epoch
                || existing.desired.action == EgressGatewayAction::Withdraw
            {
                return Err(EgressGatewayError::LeaseEpochConflict(candidate.owner));
            }
            if candidate.lease_epoch == existing.desired.lease_epoch {
                let mut expected = candidate.clone();
                expected.revision = existing.desired.revision;
                if existing.desired == expected {
                    return Ok(existing.desired.clone());
                }
                if candidate.provider != existing.desired.provider
                    || candidate.addresses != existing.desired.addresses
                    || candidate.allocation_revision < existing.desired.allocation_revision
                {
                    return Err(EgressGatewayError::LeaseEpochConflict(candidate.owner));
                }
            } else {
                return Err(EgressGatewayError::LeaseEpochConflict(candidate.owner));
            }
        } else if self.records.len() == MAX_EGRESS_INTENTS {
            return Err(EgressGatewayError::TooManyRecords {
                actual: self.records.len() + 1,
                limit: MAX_EGRESS_INTENTS,
            });
        }
        for record in self.records.values() {
            if record.desired.owner == candidate.owner {
                continue;
            }
            if let Some(address) = candidate
                .addresses
                .iter()
                .find(|address| record.desired.addresses.contains(address))
            {
                return Err(EgressGatewayError::AddressConflict {
                    address: *address,
                    owner: record.desired.owner.clone(),
                });
            }
        }
        self.replace_desired(candidate)
    }

    /// Produces an idempotent safe-withdraw operation for retained ownership.
    ///
    /// Withdrawal keeps the address and epoch fenced until both independent
    /// providers acknowledge removal.
    ///
    /// # Errors
    ///
    /// Rejects unknown owners and revision exhaustion without mutation.
    pub fn withdraw(
        &mut self,
        owner: &EgressIntentOwner,
    ) -> Result<EgressGatewayDesired, EgressGatewayError> {
        let record = self
            .records
            .get(owner)
            .ok_or_else(|| EgressGatewayError::UnknownOwner(owner.clone()))?;
        if record.desired.action == EgressGatewayAction::Withdraw {
            return Ok(record.desired.clone());
        }
        let mut desired = record.desired.clone();
        desired.revision = Revision::INITIAL;
        desired.action = EgressGatewayAction::Withdraw;
        self.replace_desired(desired)
    }

    /// Records one exact independently revisioned gateway-readiness result.
    ///
    /// # Errors
    ///
    /// Rejects unknown ownership, stale/mutated revision, provenance mismatch,
    /// or invalid outcome/error combinations.
    pub fn acknowledge_gateway(
        &mut self,
        acknowledgement: EgressGatewayAcknowledgement,
    ) -> Result<bool, EgressGatewayError> {
        let record = self
            .records
            .get_mut(&acknowledgement.owner)
            .ok_or_else(|| EgressGatewayError::UnknownOwner(acknowledgement.owner.clone()))?;
        let changed =
            validate_gateway_ack(&record.desired, &acknowledgement, record.gateway.as_ref())?;
        if changed {
            record.gateway = Some(acknowledgement);
        }
        Ok(changed)
    }

    /// Records one exact independently revisioned reachability result.
    ///
    /// # Errors
    ///
    /// Uses the same strict replay and provenance rules as gateway readiness.
    pub fn acknowledge_reachability(
        &mut self,
        acknowledgement: EgressReachabilityAcknowledgement,
    ) -> Result<bool, EgressGatewayError> {
        let record = self
            .records
            .get_mut(&acknowledgement.owner)
            .ok_or_else(|| EgressGatewayError::UnknownOwner(acknowledgement.owner.clone()))?;
        let changed = validate_reachability_ack(
            &record.desired,
            &acknowledgement,
            record.reachability.as_ref(),
        )?;
        if changed {
            record.reachability = Some(acknowledgement);
        }
        Ok(changed)
    }

    /// Returns true only when ensure state has exact Ready acknowledgements from
    /// both gateway and reachability providers.
    #[must_use]
    pub fn publication_ready(&self, owner: &EgressIntentOwner) -> bool {
        self.records.get(owner).is_some_and(|record| {
            record.desired.action == EgressGatewayAction::Ensure
                && record.gateway.as_ref().is_some_and(|ack| {
                    ack.outcome == EgressProviderOutcome::Ready
                        && validate_gateway_ack(&record.desired, ack, Some(ack)) == Ok(false)
                })
                && record.reachability.as_ref().is_some_and(|ack| {
                    ack.outcome == EgressProviderOutcome::Ready
                        && validate_reachability_ack(&record.desired, ack, Some(ack)) == Ok(false)
                })
        })
    }

    /// Projects only completely acknowledged ensure state into ranked contract
    /// facts. Node order is the deterministic provider rank for this milestone.
    ///
    /// # Errors
    ///
    /// Refuses missing, withdrawing, rejected, partial, or stale provider state.
    pub fn contract_facts(
        &self,
        owner: &EgressIntentOwner,
    ) -> Result<Vec<crate::EgressGatewayFact>, EgressGatewayError> {
        if !self.publication_ready(owner) {
            return Err(EgressGatewayError::NotReady(owner.clone()));
        }
        let record = self
            .records
            .get(owner)
            .ok_or_else(|| EgressGatewayError::UnknownOwner(owner.clone()))?;
        Ok(record
            .desired
            .nodes
            .iter()
            .enumerate()
            .map(|(rank, node)| crate::EgressGatewayFact {
                intent_uid: owner.uid.clone(),
                rank: u16::try_from(rank).unwrap_or(u16::MAX),
                node: node.clone(),
                lease_epoch: record.desired.lease_epoch,
                ready: true,
                reachable: true,
            })
            .collect())
    }

    /// Removes retained ownership only after both providers acknowledge withdraw.
    ///
    /// # Errors
    ///
    /// Rejects early release so address reuse cannot race stale gateway state.
    pub fn complete_withdrawal(
        &mut self,
        owner: &EgressIntentOwner,
    ) -> Result<EgressGatewayRecord, EgressGatewayError> {
        let record = self
            .records
            .get(owner)
            .ok_or_else(|| EgressGatewayError::UnknownOwner(owner.clone()))?;
        let complete = record.desired.action == EgressGatewayAction::Withdraw
            && record.gateway.as_ref().is_some_and(|ack| {
                ack.outcome == EgressProviderOutcome::Withdrawn
                    && validate_gateway_ack(&record.desired, ack, Some(ack)) == Ok(false)
            })
            && record.reachability.as_ref().is_some_and(|ack| {
                ack.outcome == EgressProviderOutcome::Withdrawn
                    && validate_reachability_ack(&record.desired, ack, Some(ack)) == Ok(false)
            });
        if !complete {
            return Err(EgressGatewayError::WithdrawalIncomplete(owner.clone()));
        }
        self.revision = self.revision.next();
        self.records
            .remove(owner)
            .ok_or_else(|| EgressGatewayError::UnknownOwner(owner.clone()))
    }

    #[must_use]
    pub fn record(&self, owner: &EgressIntentOwner) -> Option<&EgressGatewayRecord> {
        self.records.get(owner)
    }

    #[must_use]
    pub fn checkpoint(&self) -> EgressGatewayCheckpoint {
        EgressGatewayCheckpoint {
            schema_version: EGRESS_GATEWAY_CHECKPOINT_SCHEMA_VERSION,
            revision: self.revision,
            records: self.records.values().cloned().collect(),
        }
    }

    fn replace_desired(
        &mut self,
        mut desired: EgressGatewayDesired,
    ) -> Result<EgressGatewayDesired, EgressGatewayError> {
        let revision = checked_next_revision(self.revision)?;
        desired.revision = revision;
        validate_desired(&desired)?;
        self.records.insert(
            desired.owner.clone(),
            EgressGatewayRecord {
                desired: desired.clone(),
                gateway: None,
                reachability: None,
            },
        );
        self.revision = revision;
        Ok(desired)
    }
}

fn validate_desired(desired: &EgressGatewayDesired) -> Result<(), EgressGatewayError> {
    if desired.schema_version != EGRESS_GATEWAY_DESIRED_SCHEMA_VERSION {
        return Err(EgressGatewayError::UnsupportedSchema {
            actual: desired.schema_version,
            expected: EGRESS_GATEWAY_DESIRED_SCHEMA_VERSION,
        });
    }
    if desired.revision == Revision::INITIAL {
        return Err(EgressGatewayError::InvalidDesired(desired.owner.clone()));
    }
    validate_desired_without_revision(desired)
}

fn validate_desired_without_revision(
    desired: &EgressGatewayDesired,
) -> Result<(), EgressGatewayError> {
    if desired.allocation_revision == Revision::INITIAL
        || desired.lease_epoch == 0
        || desired.owner.name.is_empty()
        || desired.owner.name.len() > 253
        || desired.owner.uid.is_empty()
        || desired.owner.uid.len() > 128
        || !valid_provider(&desired.provider)
        || desired.addresses.is_empty()
        || desired.addresses.windows(2).any(|pair| pair[0] >= pair[1])
        || desired.nodes.is_empty()
        || desired.nodes.len() > MAX_EGRESS_GATEWAY_NODES
        || desired.nodes.windows(2).any(|pair| pair[0] >= pair[1])
        || desired.nodes.iter().any(|node| !valid_node(node))
        || desired
            .nodes
            .iter()
            .map(|node| node.name.as_str())
            .collect::<BTreeSet<_>>()
            .len()
            != desired.nodes.len()
        || desired
            .nodes
            .iter()
            .map(|node| node.uid.as_str())
            .collect::<BTreeSet<_>>()
            .len()
            != desired.nodes.len()
    {
        return Err(EgressGatewayError::InvalidDesired(desired.owner.clone()));
    }
    Ok(())
}

fn validate_gateway_ack(
    desired: &EgressGatewayDesired,
    acknowledgement: &EgressGatewayAcknowledgement,
    previous: Option<&EgressGatewayAcknowledgement>,
) -> Result<bool, EgressGatewayError> {
    if acknowledgement.schema_version != EGRESS_GATEWAY_ACK_SCHEMA_VERSION {
        return Err(EgressGatewayError::UnsupportedSchema {
            actual: acknowledgement.schema_version,
            expected: EGRESS_GATEWAY_ACK_SCHEMA_VERSION,
        });
    }
    if acknowledgement.revision == Revision::INITIAL
        || acknowledgement.desired_revision != desired.revision
        || acknowledgement.allocation_revision != desired.allocation_revision
        || acknowledgement.owner != desired.owner
        || acknowledgement.provider != desired.provider
        || acknowledgement.lease_epoch != desired.lease_epoch
        || acknowledgement.nodes != desired.nodes
    {
        return Err(EgressGatewayError::AcknowledgementMismatch(
            desired.owner.clone(),
        ));
    }
    validate_outcome(
        desired.action,
        acknowledgement.outcome,
        acknowledgement.error.as_ref(),
    )?;
    validate_ack_transition(
        desired,
        acknowledgement.revision,
        previous.map(|ack| (ack.revision, ack == acknowledgement)),
    )
}

fn validate_reachability_ack(
    desired: &EgressGatewayDesired,
    acknowledgement: &EgressReachabilityAcknowledgement,
    previous: Option<&EgressReachabilityAcknowledgement>,
) -> Result<bool, EgressGatewayError> {
    if acknowledgement.schema_version != EGRESS_GATEWAY_ACK_SCHEMA_VERSION {
        return Err(EgressGatewayError::UnsupportedSchema {
            actual: acknowledgement.schema_version,
            expected: EGRESS_GATEWAY_ACK_SCHEMA_VERSION,
        });
    }
    if acknowledgement.revision == Revision::INITIAL
        || acknowledgement.desired_revision != desired.revision
        || acknowledgement.allocation_revision != desired.allocation_revision
        || acknowledgement.owner != desired.owner
        || acknowledgement.provider != desired.provider
        || acknowledgement.lease_epoch != desired.lease_epoch
        || acknowledgement.addresses != desired.addresses
    {
        return Err(EgressGatewayError::AcknowledgementMismatch(
            desired.owner.clone(),
        ));
    }
    validate_outcome(
        desired.action,
        acknowledgement.outcome,
        acknowledgement.error.as_ref(),
    )?;
    validate_ack_transition(
        desired,
        acknowledgement.revision,
        previous.map(|ack| (ack.revision, ack == acknowledgement)),
    )
}

fn validate_ack_transition(
    desired: &EgressGatewayDesired,
    revision: Revision,
    previous: Option<(Revision, bool)>,
) -> Result<bool, EgressGatewayError> {
    let Some((previous_revision, identical)) = previous else {
        return Ok(true);
    };
    if revision < previous_revision || (revision == previous_revision && !identical) {
        return Err(EgressGatewayError::AcknowledgementRevisionConflict(
            desired.owner.clone(),
        ));
    }
    Ok(revision != previous_revision)
}

fn validate_outcome(
    action: EgressGatewayAction,
    outcome: EgressProviderOutcome,
    error: Option<&String>,
) -> Result<(), EgressGatewayError> {
    let valid = match (action, outcome, error) {
        (EgressGatewayAction::Ensure, EgressProviderOutcome::Ready, None)
        | (EgressGatewayAction::Withdraw, EgressProviderOutcome::Withdrawn, None) => true,
        (_, EgressProviderOutcome::Rejected, Some(error)) => {
            !error.is_empty() && error.len() <= 512
        }
        _ => false,
    };
    if valid {
        Ok(())
    } else {
        Err(EgressGatewayError::InvalidOutcome)
    }
}

fn valid_provider(provider: &EgressProviderRef) -> bool {
    !provider.name.is_empty()
        && provider.name.len() <= 253
        && !provider.instance.is_empty()
        && provider.instance.len() <= 128
}

fn valid_node(node: &EgressNode) -> bool {
    !node.name.is_empty() && node.name.len() <= 253 && !node.uid.is_empty() && node.uid.len() <= 128
}

fn checked_next_revision(revision: Revision) -> Result<Revision, EgressGatewayError> {
    let next = revision.next();
    (next != revision)
        .then_some(next)
        .ok_or(EgressGatewayError::CounterExhausted)
}

fn invalid_owner() -> EgressIntentOwner {
    EgressIntentOwner {
        scope: crate::EgressIntentScope::Cluster,
        name: "invalid".to_owned(),
        uid: "invalid".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        DEFAULT_EGRESS_INTENT_PRIORITY, EgressAddressRequest, EgressCapability, EgressDestinations,
        EgressIntent, EgressIntentScope, EgressSourceSelector,
    };

    fn ip(value: &str) -> IpAddr {
        value.parse().expect("valid test IP")
    }

    fn node(name: &str) -> EgressNode {
        EgressNode {
            name: name.to_owned(),
            uid: format!("uid-{name}"),
            capabilities: BTreeSet::from([
                EgressCapability::LeaseEpochFencing,
                EgressCapability::Ipv4TcpUdpNat,
                EgressCapability::Ipv6TcpUdpNat,
            ]),
        }
    }

    fn lease(name: &str, address: &str, epoch: u64) -> EgressAddressLease {
        let owner = EgressIntentOwner {
            scope: EgressIntentScope::Cluster,
            name: name.to_owned(),
            uid: format!("uid-{name}"),
        };
        EgressAddressLease {
            intent: EgressIntent {
                owner,
                priority: DEFAULT_EGRESS_INTENT_PRIORITY,
                source: EgressSourceSelector::default(),
                destinations: EgressDestinations::Any,
                fqdn: None,
                internet: None,
                addresses: EgressAddressRequest::Explicit {
                    addresses: vec![ip(address)],
                },
            },
            pool: None,
            provider: EgressProviderRef {
                name: "static".to_owned(),
                instance: "lab".to_owned(),
            },
            addresses: vec![ip(address)],
            lease_epoch: epoch,
            intent_epoch: 1,
            intent_revision: Revision::new(1),
            allocation_revision: Revision::new(epoch),
        }
    }

    fn gateway_ack(
        desired: &EgressGatewayDesired,
        revision: u64,
        outcome: EgressProviderOutcome,
    ) -> EgressGatewayAcknowledgement {
        EgressGatewayAcknowledgement {
            schema_version: EGRESS_GATEWAY_ACK_SCHEMA_VERSION,
            revision: Revision::new(revision),
            desired_revision: desired.revision,
            allocation_revision: desired.allocation_revision,
            owner: desired.owner.clone(),
            provider: desired.provider.clone(),
            lease_epoch: desired.lease_epoch,
            outcome,
            nodes: desired.nodes.clone(),
            error: None,
        }
    }

    fn reachability_ack(
        desired: &EgressGatewayDesired,
        revision: u64,
        outcome: EgressProviderOutcome,
    ) -> EgressReachabilityAcknowledgement {
        EgressReachabilityAcknowledgement {
            schema_version: EGRESS_GATEWAY_ACK_SCHEMA_VERSION,
            revision: Revision::new(revision),
            desired_revision: desired.revision,
            allocation_revision: desired.allocation_revision,
            owner: desired.owner.clone(),
            provider: desired.provider.clone(),
            lease_epoch: desired.lease_epoch,
            outcome,
            addresses: desired.addresses.clone(),
            error: None,
        }
    }

    #[test]
    fn publication_waits_for_independent_exact_acknowledgements() {
        let lease = lease("finance", "192.0.2.20", 1);
        let mut registry = EgressGatewayRegistry::default();
        let desired = registry
            .ensure(&lease, vec![node("gateway-b"), node("gateway-a")])
            .expect("desired state");
        assert_eq!(desired.nodes[0].name, "gateway-a");
        assert_eq!(
            registry
                .ensure(&lease, vec![node("gateway-a"), node("gateway-b")])
                .expect("idempotent ensure"),
            desired
        );
        assert!(!registry.publication_ready(&desired.owner));
        assert!(registry.contract_facts(&desired.owner).is_err());
        registry
            .acknowledge_gateway(gateway_ack(&desired, 10, EgressProviderOutcome::Ready))
            .expect("gateway ready");
        assert!(!registry.publication_ready(&desired.owner));
        registry
            .acknowledge_reachability(reachability_ack(&desired, 20, EgressProviderOutcome::Ready))
            .expect("reachability ready");
        assert!(registry.publication_ready(&desired.owner));
        let facts = registry
            .contract_facts(&desired.owner)
            .expect("fully acknowledged facts");
        assert_eq!(facts.len(), 2);
        assert_eq!(facts[0].rank, 0);
        assert_eq!(facts[0].lease_epoch, desired.lease_epoch);
    }

    #[test]
    fn stale_and_same_revision_mutated_acknowledgements_are_rejected() {
        let lease = lease("finance", "192.0.2.20", 1);
        let mut registry = EgressGatewayRegistry::default();
        let desired = registry
            .ensure(&lease, vec![node("gateway-a")])
            .expect("desired");
        let acknowledged = gateway_ack(&desired, 10, EgressProviderOutcome::Ready);
        assert!(
            registry
                .acknowledge_gateway(acknowledged.clone())
                .expect("first acknowledgement")
        );
        assert!(
            !registry
                .acknowledge_gateway(acknowledged.clone())
                .expect("exact replay")
        );
        let mut mutated = acknowledged.clone();
        mutated.outcome = EgressProviderOutcome::Rejected;
        mutated.error = Some("late rejection".to_owned());
        assert!(matches!(
            registry.acknowledge_gateway(mutated),
            Err(EgressGatewayError::AcknowledgementRevisionConflict(_))
        ));
        let mut stale = acknowledged;
        stale.revision = Revision::new(9);
        assert!(matches!(
            registry.acknowledge_gateway(stale),
            Err(EgressGatewayError::AcknowledgementRevisionConflict(_))
        ));
    }

    #[test]
    fn withdrawal_retains_fence_until_both_providers_remove_state() {
        let lease = lease("finance", "192.0.2.20", 1);
        let owner = lease.intent.owner.clone();
        let mut registry = EgressGatewayRegistry::default();
        registry
            .ensure(&lease, vec![node("gateway-a")])
            .expect("ensure");
        let withdraw = registry.withdraw(&owner).expect("withdraw intent");
        assert_eq!(withdraw.action, EgressGatewayAction::Withdraw);
        assert!(!registry.publication_ready(&owner));
        assert!(matches!(
            registry.complete_withdrawal(&owner),
            Err(EgressGatewayError::WithdrawalIncomplete(_))
        ));
        registry
            .acknowledge_gateway(gateway_ack(&withdraw, 11, EgressProviderOutcome::Withdrawn))
            .expect("gateway withdrawn");
        assert!(registry.complete_withdrawal(&owner).is_err());
        registry
            .acknowledge_reachability(reachability_ack(
                &withdraw,
                21,
                EgressProviderOutcome::Withdrawn,
            ))
            .expect("reachability withdrawn");
        registry
            .complete_withdrawal(&owner)
            .expect("fence can now be released");
        assert!(registry.record(&owner).is_none());
    }

    #[test]
    fn epochs_and_addresses_remain_fenced_until_record_completion() {
        let first = lease("finance", "192.0.2.20", 1);
        let replacement = lease("finance", "192.0.2.21", 2);
        let foreign = lease("other", "192.0.2.20", 2);
        let mut registry = EgressGatewayRegistry::default();
        registry
            .ensure(&first, vec![node("gateway-a")])
            .expect("first ensure");
        assert!(matches!(
            registry.ensure(&replacement, vec![node("gateway-b")]),
            Err(EgressGatewayError::LeaseEpochConflict(_))
        ));
        assert!(matches!(
            registry.ensure(&foreign, vec![node("gateway-b")]),
            Err(EgressGatewayError::AddressConflict { .. })
        ));
    }

    #[test]
    fn same_epoch_placement_refresh_gets_new_revision_and_clears_old_acks() {
        let lease = lease("finance", "192.0.2.20", 1);
        let owner = lease.intent.owner.clone();
        let mut registry = EgressGatewayRegistry::default();
        let first = registry
            .ensure(&lease, vec![node("gateway-a")])
            .expect("first placement");
        registry
            .acknowledge_gateway(gateway_ack(&first, 10, EgressProviderOutcome::Ready))
            .expect("gateway ready");
        registry
            .acknowledge_reachability(reachability_ack(&first, 20, EgressProviderOutcome::Ready))
            .expect("reachability ready");
        assert!(registry.publication_ready(&owner));

        let refreshed = registry
            .ensure(&lease, vec![node("gateway-b")])
            .expect("same ownership, new placement");
        assert!(refreshed.revision > first.revision);
        assert_eq!(refreshed.lease_epoch, first.lease_epoch);
        assert!(!registry.publication_ready(&owner));
        assert!(registry.record(&owner).expect("record").gateway.is_none());
    }

    #[test]
    fn checkpoint_replay_is_exact_and_rejects_foreign_mutation() {
        let lease = lease("finance", "192.0.2.20", 1);
        let mut registry = EgressGatewayRegistry::default();
        let desired = registry
            .ensure(&lease, vec![node("gateway-a")])
            .expect("desired");
        registry
            .acknowledge_gateway(gateway_ack(&desired, 10, EgressProviderOutcome::Ready))
            .expect("gateway ack");
        let checkpoint = registry.checkpoint();
        let encoded = serde_json::to_vec(&checkpoint).expect("checkpoint serializes");
        let decoded = serde_json::from_slice(&encoded).expect("checkpoint decodes");
        assert_eq!(
            EgressGatewayRegistry::restore(decoded)
                .expect("restore")
                .checkpoint(),
            checkpoint
        );
        let mut mutated = checkpoint;
        mutated.records[0]
            .gateway
            .as_mut()
            .expect("ack")
            .lease_epoch += 1;
        assert!(EgressGatewayRegistry::restore(mutated).is_err());
    }
}
