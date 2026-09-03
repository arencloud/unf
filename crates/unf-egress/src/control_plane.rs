//! Durable desired-state to allocation and gateway-intent orchestration.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use unf_common::Revision;

use crate::{
    EgressAllocationCheckpoint, EgressAllocationError, EgressAllocationRequest, EgressAllocator,
    EgressGatewayAcknowledgement, EgressGatewayCheckpoint, EgressGatewayError,
    EgressGatewayRegistry, EgressIntentOwner, EgressModel, EgressModelError, EgressNode,
    EgressProviderRef, EgressReachabilityAcknowledgement, MAX_EGRESS_GATEWAY_NODES,
    normalize_model,
};

pub const EGRESS_CONTROL_PLANE_CHECKPOINT_SCHEMA_VERSION: u16 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EgressControlPlaneCheckpoint {
    pub schema_version: u16,
    pub desired_revision: Revision,
    pub desired_model: EgressModel,
    pub allocation: EgressAllocationCheckpoint,
    pub gateways: EgressGatewayCheckpoint,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EgressControlPlaneReconcile {
    pub changed: bool,
    pub allocated: usize,
    pub ensuring: usize,
    pub withdrawing: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum EgressControlPlaneError {
    #[error("unsupported egress control-plane schema {actual}; expected {expected}")]
    UnsupportedSchema { actual: u16, expected: u16 },
    #[error("egress desired revision must be nonzero when desired state is nonempty")]
    ZeroDesiredRevision,
    #[error("egress desired revision regressed")]
    DesiredRevisionRegression,
    #[error("egress desired model mutated at the same revision")]
    DesiredRevisionMutation,
    #[error("explicit egress provider ownership is incomplete or foreign")]
    InvalidExplicitProviders,
    #[error("egress gateway candidate set is invalid")]
    InvalidGatewayCandidates,
    #[error(transparent)]
    Model(#[from] EgressModelError),
    #[error(transparent)]
    Allocation(#[from] EgressAllocationError),
    #[error(transparent)]
    Gateway(#[from] EgressGatewayError),
}

#[derive(Debug, Clone)]
pub struct EgressControlPlane {
    desired_revision: Revision,
    desired_model: EgressModel,
    allocator: EgressAllocator,
    gateways: EgressGatewayRegistry,
}

impl Default for EgressControlPlane {
    fn default() -> Self {
        Self {
            desired_revision: Revision::INITIAL,
            desired_model: EgressModel {
                pools: Vec::new(),
                intents: Vec::new(),
            },
            allocator: EgressAllocator::new(Vec::new()).expect("empty pool model is valid"),
            gateways: EgressGatewayRegistry::default(),
        }
    }
}

impl EgressControlPlane {
    /// Restores the complete allocation/gateway transaction after validating
    /// its desired-state fence and both subordinate checkpoints.
    ///
    /// # Errors
    ///
    /// Rejects unsupported, noncanonical, or cross-domain-incoherent state.
    pub fn restore(
        checkpoint: EgressControlPlaneCheckpoint,
    ) -> Result<Self, EgressControlPlaneError> {
        if checkpoint.schema_version != EGRESS_CONTROL_PLANE_CHECKPOINT_SCHEMA_VERSION {
            return Err(EgressControlPlaneError::UnsupportedSchema {
                actual: checkpoint.schema_version,
                expected: EGRESS_CONTROL_PLANE_CHECKPOINT_SCHEMA_VERSION,
            });
        }
        let original_model = checkpoint.desired_model;
        let desired_model =
            normalize_model(original_model.pools.clone(), original_model.intents.clone())?;
        if desired_model != original_model
            || (!desired_model.pools.is_empty() || !desired_model.intents.is_empty())
                && checkpoint.desired_revision == Revision::INITIAL
        {
            return Err(EgressControlPlaneError::ZeroDesiredRevision);
        }
        let allocator = EgressAllocator::restore(checkpoint.allocation)?;
        let gateways = EgressGatewayRegistry::restore(checkpoint.gateways)?;
        validate_cross_state(&allocator, &gateways)?;
        Ok(Self {
            desired_revision: checkpoint.desired_revision,
            desired_model,
            allocator,
            gateways,
        })
    }

    /// Atomically translates one canonical desired revision into address
    /// leases and lease-fenced gateway Ensure/Withdraw operations.
    ///
    /// # Errors
    ///
    /// Rejects stale/mutated desired state, incomplete provider ownership,
    /// invalid candidates, allocation conflicts, or gateway fence violations.
    pub fn reconcile(
        &mut self,
        desired_revision: Revision,
        model: EgressModel,
        explicit_providers: &BTreeMap<EgressIntentOwner, EgressProviderRef>,
        mut gateway_candidates: Vec<EgressNode>,
    ) -> Result<EgressControlPlaneReconcile, EgressControlPlaneError> {
        let model = normalize_model(model.pools, model.intents)?;
        validate_desired_fence(self, desired_revision, &model)?;
        validate_explicit_providers(&model, explicit_providers)?;
        gateway_candidates.sort_unstable();
        validate_candidates(&gateway_candidates)?;

        let before = self.checkpoint();
        let mut next = self.clone();
        next.finalize_withdrawals()?;

        let desired_owners = model
            .intents
            .iter()
            .map(|intent| intent.owner.clone())
            .collect::<BTreeSet<_>>();
        for owner in next.allocator.owners() {
            if desired_owners.contains(&owner) {
                continue;
            }
            if next.gateways.record(&owner).is_some() {
                next.gateways.withdraw(&owner)?;
            } else {
                next.allocator.release(&owner)?;
            }
        }
        next.allocator.reconcile_pools(model.pools.clone())?;

        for intent in &model.intents {
            if let crate::EgressAddressRequest::Pool { name, .. } = &intent.addresses {
                let desired_pool = model
                    .pools
                    .iter()
                    .find(|pool| &pool.name == name)
                    .ok_or(EgressControlPlaneError::InvalidExplicitProviders)?;
                if !next.allocator.has_exact_pool(desired_pool) {
                    if next.gateways.record(&intent.owner).is_some() {
                        next.gateways.withdraw(&intent.owner)?;
                    } else if next.allocator.lease(&intent.owner).is_some() {
                        next.allocator.release(&intent.owner)?;
                    }
                    continue;
                }
            }
            if next
                .gateways
                .record(&intent.owner)
                .is_some_and(|record| record.desired.action == crate::EgressGatewayAction::Withdraw)
            {
                continue;
            }
            let request = EgressAllocationRequest {
                intent: intent.clone(),
                explicit_provider: explicit_providers.get(&intent.owner).cloned(),
                intent_epoch: 1,
                intent_revision: desired_revision,
            };
            let lease = match next.allocator.allocate(request.clone()) {
                Ok(lease) => lease,
                Err(EgressAllocationError::ImmutableIntentChanged { .. }) => {
                    if next.gateways.record(&intent.owner).is_some() {
                        next.gateways.withdraw(&intent.owner)?;
                        continue;
                    }
                    next.allocator.release(&intent.owner)?;
                    next.allocator.allocate(request)?
                }
                Err(error) => return Err(error.into()),
            };
            if gateway_candidates.is_empty() {
                if next.gateways.record(&intent.owner).is_some() {
                    next.gateways.withdraw(&intent.owner)?;
                }
            } else {
                next.gateways.ensure(&lease, gateway_candidates.clone())?;
            }
        }
        next.allocator.reconcile_pools(model.pools.clone())?;
        next.desired_revision = desired_revision;
        next.desired_model = model;
        validate_cross_state(&next.allocator, &next.gateways)?;
        let checkpoint = next.checkpoint();
        let result = EgressControlPlaneReconcile {
            changed: checkpoint != before,
            allocated: checkpoint.allocation.leases.len(),
            ensuring: checkpoint
                .gateways
                .records
                .iter()
                .filter(|record| record.desired.action == crate::EgressGatewayAction::Ensure)
                .count(),
            withdrawing: checkpoint
                .gateways
                .records
                .iter()
                .filter(|record| record.desired.action == crate::EgressGatewayAction::Withdraw)
                .count(),
        };
        *self = next;
        Ok(result)
    }

    /// Applies one exact gateway-host result without changing other domains.
    ///
    /// # Errors
    ///
    /// Rejects stale, mutated, mismatched, or otherwise invalid results.
    pub fn acknowledge_gateway(
        &mut self,
        acknowledgement: EgressGatewayAcknowledgement,
    ) -> Result<bool, EgressControlPlaneError> {
        Ok(self.gateways.acknowledge_gateway(acknowledgement)?)
    }

    /// Applies one exact reachability result without changing other domains.
    ///
    /// # Errors
    ///
    /// Rejects stale, mutated, mismatched, or otherwise invalid results.
    pub fn acknowledge_reachability(
        &mut self,
        acknowledgement: EgressReachabilityAcknowledgement,
    ) -> Result<bool, EgressControlPlaneError> {
        Ok(self.gateways.acknowledge_reachability(acknowledgement)?)
    }

    #[must_use]
    pub fn checkpoint(&self) -> EgressControlPlaneCheckpoint {
        EgressControlPlaneCheckpoint {
            schema_version: EGRESS_CONTROL_PLANE_CHECKPOINT_SCHEMA_VERSION,
            desired_revision: self.desired_revision,
            desired_model: self.desired_model.clone(),
            allocation: self.allocator.checkpoint(),
            gateways: self.gateways.checkpoint(),
        }
    }

    fn finalize_withdrawals(&mut self) -> Result<(), EgressControlPlaneError> {
        for owner in self.allocator.owners() {
            let complete =
                self.gateways.record(&owner).is_some_and(|record| {
                    record.desired.action == crate::EgressGatewayAction::Withdraw
                        && record.gateway.as_ref().is_some_and(|ack| {
                            ack.outcome == crate::EgressProviderOutcome::Withdrawn
                        })
                        && record.reachability.as_ref().is_some_and(|ack| {
                            ack.outcome == crate::EgressProviderOutcome::Withdrawn
                        })
                });
            if !complete {
                continue;
            }
            self.gateways.complete_withdrawal(&owner)?;
            self.allocator.release(&owner)?;
        }
        Ok(())
    }
}

fn validate_desired_fence(
    current: &EgressControlPlane,
    revision: Revision,
    model: &EgressModel,
) -> Result<(), EgressControlPlaneError> {
    if revision == Revision::INITIAL && (!model.pools.is_empty() || !model.intents.is_empty()) {
        return Err(EgressControlPlaneError::ZeroDesiredRevision);
    }
    if revision < current.desired_revision {
        return Err(EgressControlPlaneError::DesiredRevisionRegression);
    }
    if revision == current.desired_revision && model != &current.desired_model {
        return Err(EgressControlPlaneError::DesiredRevisionMutation);
    }
    Ok(())
}

fn validate_explicit_providers(
    model: &EgressModel,
    providers: &BTreeMap<EgressIntentOwner, EgressProviderRef>,
) -> Result<(), EgressControlPlaneError> {
    let expected = model
        .intents
        .iter()
        .filter(|intent| {
            matches!(
                intent.addresses,
                crate::EgressAddressRequest::Explicit { .. }
            )
        })
        .map(|intent| intent.owner.clone())
        .collect::<BTreeSet<_>>();
    let actual = providers.keys().cloned().collect::<BTreeSet<_>>();
    if expected != actual
        || providers
            .values()
            .any(|provider| provider.name.is_empty() || provider.instance.is_empty())
    {
        return Err(EgressControlPlaneError::InvalidExplicitProviders);
    }
    Ok(())
}

fn validate_candidates(candidates: &[EgressNode]) -> Result<(), EgressControlPlaneError> {
    if candidates.len() > MAX_EGRESS_GATEWAY_NODES
        || candidates.windows(2).any(|pair| pair[0] >= pair[1])
        || candidates
            .iter()
            .any(|node| node.name.is_empty() || node.uid.is_empty())
    {
        return Err(EgressControlPlaneError::InvalidGatewayCandidates);
    }
    Ok(())
}

fn validate_cross_state(
    allocator: &EgressAllocator,
    gateways: &EgressGatewayRegistry,
) -> Result<(), EgressControlPlaneError> {
    for record in &gateways.checkpoint().records {
        let Some(lease) = allocator.lease(&record.desired.owner) else {
            return Err(EgressControlPlaneError::Gateway(
                EgressGatewayError::UnknownOwner(record.desired.owner.clone()),
            ));
        };
        if record.desired.lease_epoch != lease.lease_epoch
            || record.desired.provider != lease.provider
            || record.desired.addresses != lease.addresses
            || record.desired.allocation_revision > lease.allocation_revision
        {
            return Err(EgressControlPlaneError::Gateway(
                EgressGatewayError::LeaseEpochConflict(record.desired.owner.clone()),
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use super::*;
    use crate::{
        AddressFamily, DEFAULT_EGRESS_INTENT_PRIORITY, EGRESS_GATEWAY_ACK_SCHEMA_VERSION,
        EgressAddressPool, EgressAddressRequest, EgressCapability, EgressDestinations,
        EgressGatewayAction, EgressIntent, EgressIntentScope, EgressProviderOutcome,
        EgressSourceSelector, IpPrefix,
    };

    fn ip(value: &str) -> IpAddr {
        value.parse().expect("valid test address")
    }

    fn provider() -> EgressProviderRef {
        EgressProviderRef {
            name: "static".to_owned(),
            instance: "lab".to_owned(),
        }
    }

    fn pool() -> EgressAddressPool {
        EgressAddressPool {
            name: "public".to_owned(),
            uid: "uid-public".to_owned(),
            provider: provider(),
            prefixes: vec![IpPrefix {
                address: ip("192.0.2.0"),
                prefix_len: 29,
            }],
        }
    }

    fn intent(name: &str) -> EgressIntent {
        EgressIntent {
            owner: EgressIntentOwner {
                scope: EgressIntentScope::Cluster,
                name: name.to_owned(),
                uid: format!("uid-{name}"),
            },
            priority: DEFAULT_EGRESS_INTENT_PRIORITY,
            source: EgressSourceSelector::default(),
            destinations: EgressDestinations::Any,
            addresses: EgressAddressRequest::Pool {
                name: "public".to_owned(),
                families: vec![AddressFamily::Ipv4],
                addresses_per_family: 1,
            },
        }
    }

    fn model(intents: Vec<EgressIntent>) -> EgressModel {
        EgressModel {
            pools: vec![pool()],
            intents,
        }
    }

    fn node(name: &str) -> EgressNode {
        EgressNode {
            name: name.to_owned(),
            uid: format!("uid-{name}"),
            capabilities: BTreeSet::from([
                EgressCapability::IdentitySourceSteering,
                EgressCapability::LeaseEpochFencing,
            ]),
        }
    }

    fn providers() -> BTreeMap<EgressIntentOwner, EgressProviderRef> {
        BTreeMap::new()
    }

    #[test]
    fn desired_revision_atomically_allocates_and_orders_gateway_intent() {
        let mut control = EgressControlPlane::default();
        let result = control
            .reconcile(
                Revision::new(1),
                model(vec![intent("payments")]),
                &providers(),
                vec![node("gateway-b"), node("gateway-a")],
            )
            .expect("reconcile");
        assert!(result.changed);
        assert_eq!((result.allocated, result.ensuring), (1, 1));
        let checkpoint = control.checkpoint();
        assert_eq!(
            checkpoint.allocation.leases[0].addresses,
            vec![ip("192.0.2.1")]
        );
        assert_eq!(
            checkpoint.gateways.records[0].desired.nodes[0].name,
            "gateway-a"
        );
        assert_eq!(
            EgressControlPlane::restore(checkpoint.clone())
                .expect("exact restore")
                .checkpoint(),
            checkpoint
        );
        assert!(
            !control
                .reconcile(
                    Revision::new(1),
                    model(vec![intent("payments")]),
                    &providers(),
                    vec![node("gateway-a"), node("gateway-b")],
                )
                .expect("idempotent replay")
                .changed
        );
    }

    #[test]
    fn absent_candidates_retain_allocation_without_claiming_gateway_state() {
        let mut control = EgressControlPlane::default();
        let result = control
            .reconcile(
                Revision::new(1),
                model(vec![intent("payments")]),
                &providers(),
                Vec::new(),
            )
            .expect("allocation is independent from readiness");
        assert_eq!((result.allocated, result.ensuring), (1, 0));
        assert!(control.checkpoint().gateways.records.is_empty());
    }

    #[test]
    fn loss_of_all_candidates_withdraws_existing_gateway_authority() {
        let mut control = EgressControlPlane::default();
        control
            .reconcile(
                Revision::new(1),
                model(vec![intent("payments")]),
                &providers(),
                vec![node("gateway-a")],
            )
            .expect("ensure");
        control
            .reconcile(
                Revision::new(1),
                model(vec![intent("payments")]),
                &providers(),
                Vec::new(),
            )
            .expect("candidate loss withdraws");
        let checkpoint = control.checkpoint();
        assert_eq!(checkpoint.allocation.leases.len(), 1);
        assert_eq!(
            checkpoint.gateways.records[0].desired.action,
            EgressGatewayAction::Withdraw
        );
    }

    #[test]
    fn removal_retains_address_until_both_withdrawals_then_reuses_new_epoch() {
        let mut control = EgressControlPlane::default();
        control
            .reconcile(
                Revision::new(1),
                model(vec![intent("payments")]),
                &providers(),
                vec![node("gateway-a")],
            )
            .expect("ensure");
        control
            .reconcile(
                Revision::new(2),
                model(Vec::new()),
                &providers(),
                vec![node("gateway-a")],
            )
            .expect("begin withdrawal");
        let checkpoint = control.checkpoint();
        let desired = checkpoint.gateways.records[0].desired.clone();
        assert_eq!(desired.action, EgressGatewayAction::Withdraw);
        assert_eq!(checkpoint.allocation.leases.len(), 1);

        control
            .acknowledge_gateway(EgressGatewayAcknowledgement {
                schema_version: EGRESS_GATEWAY_ACK_SCHEMA_VERSION,
                revision: Revision::new(1),
                desired_revision: desired.revision,
                allocation_revision: desired.allocation_revision,
                owner: desired.owner.clone(),
                provider: desired.provider.clone(),
                lease_epoch: desired.lease_epoch,
                outcome: EgressProviderOutcome::Withdrawn,
                nodes: desired.nodes.clone(),
                error: None,
            })
            .expect("gateway withdrawn");
        control
            .acknowledge_reachability(EgressReachabilityAcknowledgement {
                schema_version: EGRESS_GATEWAY_ACK_SCHEMA_VERSION,
                revision: Revision::new(1),
                desired_revision: desired.revision,
                allocation_revision: desired.allocation_revision,
                owner: desired.owner.clone(),
                provider: desired.provider.clone(),
                lease_epoch: desired.lease_epoch,
                outcome: EgressProviderOutcome::Withdrawn,
                addresses: desired.addresses.clone(),
                error: None,
            })
            .expect("reachability withdrawn");
        control
            .reconcile(
                Revision::new(2),
                model(Vec::new()),
                &providers(),
                vec![node("gateway-a")],
            )
            .expect("complete withdrawal");
        assert!(control.checkpoint().allocation.leases.is_empty());

        let mut replacement = intent("replacement");
        replacement.owner.uid = "uid-replacement".to_owned();
        control
            .reconcile(
                Revision::new(3),
                model(vec![replacement]),
                &providers(),
                vec![node("gateway-a")],
            )
            .expect("safe reuse");
        let replacement = &control.checkpoint().allocation.leases[0];
        assert_eq!(replacement.addresses, desired.addresses);
        assert!(replacement.lease_epoch > desired.lease_epoch);
    }

    #[test]
    fn stale_mutated_and_conflicting_input_keeps_last_known_good() {
        let mut control = EgressControlPlane::default();
        control
            .reconcile(
                Revision::new(2),
                model(vec![intent("payments")]),
                &providers(),
                vec![node("gateway-a")],
            )
            .expect("baseline");
        let before = control.checkpoint();
        assert!(matches!(
            control.reconcile(
                Revision::new(1),
                model(vec![intent("payments")]),
                &providers(),
                vec![node("gateway-a")],
            ),
            Err(EgressControlPlaneError::DesiredRevisionRegression)
        ));
        assert!(matches!(
            control.reconcile(
                Revision::new(2),
                model(Vec::new()),
                &providers(),
                vec![node("gateway-a")],
            ),
            Err(EgressControlPlaneError::DesiredRevisionMutation)
        ));
        assert_eq!(control.checkpoint(), before);
    }

    #[test]
    fn pool_mutation_is_deferred_behind_the_existing_lease_withdrawal() {
        let mut control = EgressControlPlane::default();
        control
            .reconcile(
                Revision::new(1),
                model(vec![intent("payments")]),
                &providers(),
                vec![node("gateway-a")],
            )
            .expect("baseline");
        let mut changed = model(vec![intent("payments")]);
        changed.pools[0].prefixes[0] = IpPrefix {
            address: ip("198.51.100.0"),
            prefix_len: 29,
        };
        control
            .reconcile(
                Revision::new(2),
                changed,
                &providers(),
                vec![node("gateway-a")],
            )
            .expect("pool transition enters withdrawal instead of becoming stuck");
        let checkpoint = control.checkpoint();
        assert_eq!(
            checkpoint.allocation.leases[0].addresses,
            vec![ip("192.0.2.1")]
        );
        assert_eq!(
            checkpoint.gateways.records[0].desired.action,
            EgressGatewayAction::Withdraw
        );
    }
}
