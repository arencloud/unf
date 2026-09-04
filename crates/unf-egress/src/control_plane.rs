//! Durable desired-state to allocation and gateway-intent orchestration.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use unf_common::Revision;

use crate::{
    AdmittedEgressProjection, EgressAllocationCheckpoint, EgressAllocationError,
    EgressAllocationRequest, EgressAllocator, EgressGatewayAcknowledgement,
    EgressGatewayCheckpoint, EgressGatewayError, EgressGatewayRegistry,
    EgressHaActivationAuthority, EgressHaAgentChallenge, EgressHaAgentChallenges,
    EgressHaCandidate, EgressHaContinuityCutover, EgressHaContinuityError, EgressHaError,
    EgressHaFlowTwinAcknowledgement, EgressHaFlowTwinStream, EgressHaGatewayAcquisitionEvidence,
    EgressHaInfrastructureFenceEvidence, EgressHaOldOwnerRevocationEvidence, EgressHaPlan,
    EgressHaPromotionCheckpoint, EgressHaPromotionCoordinator, EgressHaPromotionError,
    EgressHaPromotionManifest, EgressHaPromotionPhase, EgressHaReachabilityHandoffEvidence,
    EgressHaSourceActivationEvidence, EgressHaSourceFenceEvidence, EgressIntentOwner, EgressModel,
    EgressModelError, EgressNode, EgressProjectionRecipient, EgressProviderRef,
    EgressReachabilityAcknowledgement, EgressRetirementManifest, EgressSafeForgettingError,
    EgressSafeReleaseAuthority, MAX_EGRESS_GATEWAY_NODES, MAX_EGRESS_INTENTS,
    compile_egress_ha_plan, normalize_model,
};

pub const EGRESS_CONTROL_PLANE_CHECKPOINT_SCHEMA_VERSION: u16 = 5;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EgressControlPlaneCheckpoint {
    pub schema_version: u16,
    pub desired_revision: Revision,
    pub desired_model: EgressModel,
    pub allocation: EgressAllocationCheckpoint,
    pub gateways: EgressGatewayCheckpoint,
    #[serde(default)]
    pub ha_plans: Vec<EgressHaPlan>,
    #[serde(default)]
    pub ha_promotions: Vec<EgressHaControlPlanePromotion>,
    pub retirements: Vec<EgressRetirementManifest>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EgressHaControlPlanePromotion {
    pub previous_plan: EgressHaPlan,
    pub coordinator: EgressHaPromotionCheckpoint,
    pub replacement_staged: bool,
    pub flow_streams: Vec<EgressHaFlowTwinStream>,
    pub flow_acknowledgements: Vec<EgressHaFlowTwinAcknowledgement>,
    #[serde(with = "recipient_cutovers")]
    pub cutovers: BTreeMap<EgressProjectionRecipient, EgressHaContinuityCutover>,
    #[serde(default)]
    pub source_activations: Vec<EgressHaSourceActivationEvidence>,
}

/// JSON object keys cannot represent a structured Node recipient. Persist the
/// map as a canonical, sorted entry list while accepting the empty object
/// emitted by pre-fix schema-v5 checkpoints before any cutover was sealed.
mod recipient_cutovers {
    use std::collections::BTreeMap;

    use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};

    use crate::{EgressHaContinuityCutover, EgressProjectionRecipient};

    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields, rename_all = "camelCase")]
    struct Entry {
        recipient: EgressProjectionRecipient,
        cutover: EgressHaContinuityCutover,
    }

    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Representation {
        Entries(Vec<Entry>),
        LegacyEmpty(BTreeMap<String, serde_json::Value>),
    }

    pub fn serialize<S>(
        cutovers: &BTreeMap<EgressProjectionRecipient, EgressHaContinuityCutover>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        cutovers
            .iter()
            .map(|(recipient, cutover)| Entry {
                recipient: recipient.clone(),
                cutover: cutover.clone(),
            })
            .collect::<Vec<_>>()
            .serialize(serializer)
    }

    pub fn deserialize<'de, D>(
        deserializer: D,
    ) -> Result<BTreeMap<EgressProjectionRecipient, EgressHaContinuityCutover>, D::Error>
    where
        D: Deserializer<'de>,
    {
        match Representation::deserialize(deserializer)? {
            Representation::Entries(entries) => {
                let mut cutovers = BTreeMap::new();
                for entry in entries {
                    if cutovers.insert(entry.recipient, entry.cutover).is_some() {
                        return Err(D::Error::custom("duplicate HA source cutover recipient"));
                    }
                }
                Ok(cutovers)
            }
            Representation::LegacyEmpty(entries) if entries.is_empty() => Ok(BTreeMap::new()),
            Representation::LegacyEmpty(_) => Err(D::Error::custom(
                "legacy HA source cutover object must be empty",
            )),
        }
    }
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
    #[error(transparent)]
    Ha(#[from] EgressHaError),
    #[error(transparent)]
    HaPromotion(#[from] EgressHaPromotionError),
    #[error(transparent)]
    HaContinuity(#[from] EgressHaContinuityError),
    #[error("durable HA plan set is missing, duplicated, or cross-domain incoherent")]
    InvalidHaCheckpoint,
    #[error(transparent)]
    SafeForgetting(#[from] EgressSafeForgettingError),
    #[error("safe release authority does not match retained provider evidence for {0:?}")]
    ReleaseAuthorityMismatch(EgressIntentOwner),
    #[error("retirement manifest is missing, mutated, or foreign for {0:?}")]
    RetirementManifestConflict(EgressIntentOwner),
    #[error("retirement checkpoint is oversized, duplicated, or noncanonical")]
    InvalidRetirementCheckpoint,
}

#[derive(Debug, Clone)]
pub struct EgressControlPlane {
    desired_revision: Revision,
    desired_model: EgressModel,
    allocator: EgressAllocator,
    gateways: EgressGatewayRegistry,
    ha_plans: BTreeMap<EgressIntentOwner, EgressHaPlan>,
    ha_promotions: BTreeMap<EgressIntentOwner, EgressHaControlPlanePromotion>,
    retirements: BTreeMap<EgressIntentOwner, EgressRetirementManifest>,
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
            ha_plans: BTreeMap::new(),
            ha_promotions: BTreeMap::new(),
            retirements: BTreeMap::new(),
        }
    }
}

fn challenge_sort_key(
    challenge: &EgressHaAgentChallenge,
) -> (crate::EgressHaPromotionDigest, u8, String) {
    match challenge {
        EgressHaAgentChallenge::SourceFence { manifest } => {
            (manifest.manifest_digest, 0, String::new())
        }
        EgressHaAgentChallenge::PrimarySnapshot {
            manifest,
            standby_gateway,
            ..
        } => (manifest.manifest_digest, 1, standby_gateway.uid.clone()),
        EgressHaAgentChallenge::OldOwnerRevocation { manifest } => {
            (manifest.manifest_digest, 2, String::new())
        }
        EgressHaAgentChallenge::StandbyReplica {
            manifest, stream, ..
        } => (
            manifest.manifest_digest,
            3,
            stream.primary_gateway.uid.clone(),
        ),
        EgressHaAgentChallenge::SourceActivation { authority, .. } => {
            (authority.manifest.manifest_digest, 4, String::new())
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
    #[allow(clippy::too_many_lines)]
    pub fn restore(
        checkpoint: EgressControlPlaneCheckpoint,
    ) -> Result<Self, EgressControlPlaneError> {
        if !matches!(
            checkpoint.schema_version,
            2 | 3 | 4 | EGRESS_CONTROL_PLANE_CHECKPOINT_SCHEMA_VERSION
        ) || matches!(checkpoint.schema_version, 2 | 3) && !checkpoint.ha_promotions.is_empty()
            || checkpoint.schema_version == 2 && !checkpoint.ha_plans.is_empty()
        {
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
        if checkpoint.ha_plans.len() > MAX_EGRESS_INTENTS
            || checkpoint
                .ha_plans
                .windows(2)
                .any(|pair| pair[0].owner >= pair[1].owner)
        {
            return Err(EgressControlPlaneError::InvalidHaCheckpoint);
        }
        let mut ha_plans = BTreeMap::new();
        for plan in checkpoint.ha_plans {
            validate_ha_plan_checkpoint(&plan, &allocator, &gateways)?;
            if ha_plans.insert(plan.owner.clone(), plan).is_some() {
                return Err(EgressControlPlaneError::InvalidHaCheckpoint);
            }
        }
        let expected_ha = gateways
            .checkpoint()
            .records
            .iter()
            .filter(|record| record.desired.nodes.len() > 1)
            .map(|record| record.desired.owner.clone())
            .collect::<BTreeSet<_>>();
        if ha_plans.keys().cloned().collect::<BTreeSet<_>>() != expected_ha {
            return Err(EgressControlPlaneError::InvalidHaCheckpoint);
        }
        if checkpoint.ha_promotions.len() > MAX_EGRESS_INTENTS
            || checkpoint.ha_promotions.windows(2).any(|pair| {
                pair[0].coordinator.manifest.owner >= pair[1].coordinator.manifest.owner
            })
        {
            return Err(EgressControlPlaneError::InvalidHaCheckpoint);
        }
        let mut ha_promotions = BTreeMap::new();
        for promotion in checkpoint.ha_promotions {
            let owner = promotion.coordinator.manifest.owner.clone();
            promotion.previous_plan.verify_integrity()?;
            if promotion.previous_plan.owner != owner {
                return Err(EgressControlPlaneError::InvalidHaCheckpoint);
            }
            EgressHaPromotionCoordinator::restore(
                &promotion.previous_plan,
                promotion.coordinator.clone(),
            )?;
            validate_promotion_continuity(&promotion)?;
            if !promotion.replacement_staged
                && ha_plans.get(&owner) != Some(&promotion.previous_plan)
            {
                return Err(EgressControlPlaneError::InvalidHaCheckpoint);
            }
            if ha_promotions.insert(owner, promotion).is_some() {
                return Err(EgressControlPlaneError::InvalidHaCheckpoint);
            }
        }
        if checkpoint.retirements.len() > MAX_EGRESS_INTENTS
            || checkpoint
                .retirements
                .windows(2)
                .any(|pair| pair[0].owner >= pair[1].owner)
        {
            return Err(EgressControlPlaneError::InvalidRetirementCheckpoint);
        }
        let mut retirements = BTreeMap::new();
        for manifest in checkpoint.retirements {
            let owner = manifest.owner.clone();
            let record = gateways.record(&owner).ok_or_else(|| {
                EgressControlPlaneError::RetirementManifestConflict(owner.clone())
            })?;
            manifest.verify(&record.desired)?;
            if retirements.insert(owner.clone(), manifest).is_some() {
                return Err(EgressControlPlaneError::RetirementManifestConflict(owner));
            }
        }
        validate_cross_state(&allocator, &gateways)?;
        Ok(Self {
            desired_revision: checkpoint.desired_revision,
            desired_model,
            allocator,
            gateways,
            ha_plans,
            ha_promotions,
            retirements,
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
        gateway_candidates: Vec<EgressNode>,
    ) -> Result<EgressControlPlaneReconcile, EgressControlPlaneError> {
        self.reconcile_with_ha_candidates(
            desired_revision,
            model,
            explicit_providers,
            gateway_candidates
                .into_iter()
                .map(|node| EgressHaCandidate {
                    node,
                    capacity_units: 1,
                    failure_domains: BTreeMap::new(),
                })
                .collect(),
        )
    }

    /// Reconciles desired state while durably compiling exact CCR ownership.
    /// Existing plans remain frozen until candidate membership explicitly
    /// changes through the promotion/drain transaction.
    ///
    /// # Errors
    ///
    /// Rejects invalid desired state, candidates, allocation, gateway state,
    /// or any CCR plan that cannot preserve the prior authority atomically.
    #[allow(clippy::too_many_lines)]
    pub fn reconcile_with_ha_candidates(
        &mut self,
        desired_revision: Revision,
        model: EgressModel,
        explicit_providers: &BTreeMap<EgressIntentOwner, EgressProviderRef>,
        mut ha_candidates: Vec<EgressHaCandidate>,
    ) -> Result<EgressControlPlaneReconcile, EgressControlPlaneError> {
        let model = normalize_model(model.pools, model.intents)?;
        validate_desired_fence(self, desired_revision, &model)?;
        validate_explicit_providers(&model, explicit_providers)?;
        ha_candidates.sort_unstable();
        if ha_candidates
            .windows(2)
            .any(|pair| pair[0].node >= pair[1].node)
        {
            return Err(EgressControlPlaneError::InvalidGatewayCandidates);
        }
        let mut gateway_candidates = ha_candidates
            .iter()
            .map(|candidate| candidate.node.clone())
            .collect::<Vec<_>>();
        gateway_candidates.sort_unstable();
        validate_candidates(&gateway_candidates)?;

        let before = self.checkpoint();
        let mut next = self.clone();

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
                let desired = next.gateways.ensure(&lease, gateway_candidates.clone())?;
                if gateway_candidates.len() > 1 {
                    let unchanged = next.ha_plans.get(&intent.owner).is_some_and(|plan| {
                        plan.owner == intent.owner
                            && plan.allocation_revision == lease.allocation_revision
                            && plan.lease_epoch == lease.lease_epoch
                            && plan.revision == desired.revision
                            && plan.candidates == ha_candidates
                    });
                    if !unchanged {
                        let previous = next.ha_plans.get(&intent.owner).filter(|plan| {
                            plan.owner == intent.owner
                                && plan.allocation_revision == lease.allocation_revision
                                && plan.lease_epoch == lease.lease_epoch
                        });
                        let plan = compile_egress_ha_plan(
                            &lease,
                            ha_candidates.clone(),
                            previous,
                            desired.revision,
                        )?;
                        next.ha_plans.insert(intent.owner.clone(), plan);
                    }
                } else {
                    next.ha_plans.remove(&intent.owner);
                }
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

    /// Persists one exact promotion investigation without changing ownership.
    ///
    /// # Errors
    ///
    /// Rejects unknown ownership, duplicate promotion, foreign failure, or an
    /// invalid source/epoch challenge.
    #[allow(clippy::too_many_arguments)]
    pub fn begin_ha_promotion(
        &mut self,
        owner: &EgressIntentOwner,
        failed_gateway_uid: &str,
        sources: Vec<EgressProjectionRecipient>,
        controller_epoch: u64,
        promotion_epoch: u64,
        authority_revision: Revision,
    ) -> Result<EgressHaPromotionManifest, EgressControlPlaneError> {
        if self.ha_promotions.contains_key(owner) {
            return Err(EgressControlPlaneError::InvalidHaCheckpoint);
        }
        let plan = self
            .ha_plans
            .get(owner)
            .cloned()
            .ok_or(EgressControlPlaneError::InvalidHaCheckpoint)?;
        let manifest = EgressHaPromotionManifest::issue(
            &plan,
            failed_gateway_uid,
            sources,
            controller_epoch,
            promotion_epoch,
            authority_revision,
        )?;
        let coordinator = EgressHaPromotionCoordinator::new(manifest.clone()).checkpoint();
        self.ha_promotions.insert(
            owner.clone(),
            EgressHaControlPlanePromotion {
                previous_plan: plan,
                coordinator,
                replacement_staged: false,
                flow_streams: Vec::new(),
                flow_acknowledgements: Vec::new(),
                cutovers: BTreeMap::new(),
                source_activations: Vec::new(),
            },
        );
        Ok(manifest)
    }

    /// Returns the durable transaction for status and exact agent challenges.
    #[must_use]
    pub fn ha_promotion(
        &self,
        owner: &EgressIntentOwner,
    ) -> Option<&EgressHaControlPlanePromotion> {
        self.ha_promotions.get(owner)
    }

    /// Derives the exact next live operations for one authenticated agent from
    /// durable transaction state. Empty output is a valid fail-closed wait.
    ///
    /// # Errors
    ///
    /// Rejects a malformed recipient or any promotion state that cannot be
    /// replayed against its certified previous plan.
    #[allow(clippy::too_many_lines)]
    pub fn ha_agent_challenges(
        &self,
        recipient: EgressProjectionRecipient,
        controller_epoch: u64,
    ) -> Result<EgressHaAgentChallenges, EgressControlPlaneError> {
        let mut challenges = Vec::new();
        for promotion in self.ha_promotions.values() {
            let coordinator = EgressHaPromotionCoordinator::restore(
                &promotion.previous_plan,
                promotion.coordinator.clone(),
            )?;
            let manifest = coordinator.manifest();
            if manifest.controller_epoch != controller_epoch {
                return Err(EgressHaPromotionError::InvalidAuthority.into());
            }
            let source_fenced = promotion
                .coordinator
                .source_fences
                .iter()
                .any(|evidence| evidence.recipient == recipient);
            if manifest.sources.contains(&recipient) && !source_fenced {
                challenges.push(EgressHaAgentChallenge::SourceFence {
                    manifest: Box::new(manifest.clone()),
                });
            }

            let sources_complete =
                promotion.coordinator.source_fences.len() == manifest.sources.len();
            if sources_complete
                && manifest.failed_gateway.name == recipient.node_name
                && manifest.failed_gateway.uid == recipient.node_uid
            {
                let mut pairs = BTreeMap::<EgressNode, Vec<u16>>::new();
                for handoff in &manifest.handoffs {
                    pairs
                        .entry(handoff.new_gateway.clone())
                        .or_default()
                        .push(handoff.shard_index);
                }
                for (standby_gateway, shard_indexes) in pairs {
                    let streamed = promotion.flow_streams.iter().any(|stream| {
                        stream.primary_gateway == manifest.failed_gateway
                            && stream.standby_gateway == standby_gateway
                    });
                    if !streamed {
                        challenges.push(EgressHaAgentChallenge::PrimarySnapshot {
                            manifest: Box::new(manifest.clone()),
                            standby_gateway,
                            shard_indexes,
                        });
                    }
                }
                let expected_pairs = manifest
                    .handoffs
                    .iter()
                    .map(|handoff| handoff.new_gateway.clone())
                    .collect::<BTreeSet<_>>()
                    .len();
                if promotion.flow_streams.len() == expected_pairs
                    && promotion.coordinator.old_owner_fence.is_none()
                {
                    challenges.push(EgressHaAgentChallenge::OldOwnerRevocation {
                        manifest: Box::new(manifest.clone()),
                    });
                }
            }

            for stream in &promotion.flow_streams {
                let acknowledged = promotion.flow_acknowledgements.iter().any(|ack| {
                    ack.primary_gateway == stream.primary_gateway
                        && ack.standby_gateway == stream.standby_gateway
                });
                if !acknowledged
                    && stream.standby_gateway.name == recipient.node_name
                    && stream.standby_gateway.uid == recipient.node_uid
                {
                    challenges.push(EgressHaAgentChallenge::StandbyReplica {
                        manifest: Box::new(manifest.clone()),
                        stream: Box::new(stream.clone()),
                    });
                }
            }

            if manifest.sources.contains(&recipient)
                && let Some(cutover) = promotion.cutovers.get(&recipient)
            {
                challenges.push(EgressHaAgentChallenge::SourceActivation {
                    authority: Box::new(coordinator.activation_authority()?),
                    cutover: Box::new(cutover.clone()),
                });
            }
        }
        challenges.sort_by_key(challenge_sort_key);
        let certified_plans = self
            .ha_promotions
            .values()
            .filter(|promotion| {
                let manifest = &promotion.coordinator.manifest;
                manifest.sources.contains(&recipient)
                    || manifest.failed_gateway.name == recipient.node_name
                        && manifest.failed_gateway.uid == recipient.node_uid
                    || manifest.handoffs.iter().any(|handoff| {
                        handoff.new_gateway.name == recipient.node_name
                            && handoff.new_gateway.uid == recipient.node_uid
                    })
            })
            .map(|promotion| promotion.previous_plan.clone())
            .collect();
        Ok(EgressHaAgentChallenges::issue(
            controller_epoch,
            recipient,
            certified_plans,
            challenges,
        )?)
    }

    /// Admits one source fence and checkpoints the monotonic transition.
    ///
    /// # Errors
    ///
    /// Rejects unknown, stale, duplicate, reordered, or partial evidence.
    pub fn admit_ha_source_fence(
        &mut self,
        evidence: EgressHaSourceFenceEvidence,
    ) -> Result<(), EgressControlPlaneError> {
        let owner = self.promotion_owner(evidence.manifest_digest)?;
        self.update_promotion(&owner, |coordinator| {
            coordinator.admit_source_fence(evidence)
        })
    }

    /// Admits graceful old-owner kernel revocation.
    ///
    /// # Errors
    ///
    /// Rejects evidence before all sources fence or any inexact readback.
    pub fn admit_ha_old_owner_revocation(
        &mut self,
        evidence: EgressHaOldOwnerRevocationEvidence,
    ) -> Result<(), EgressControlPlaneError> {
        let owner = self.promotion_owner(evidence.manifest_digest)?;
        self.update_promotion(&owner, |coordinator| {
            coordinator.admit_old_owner_revocation(evidence)
        })
    }

    /// Admits an independent non-Kubernetes infrastructure fence.
    ///
    /// # Errors
    ///
    /// Rejects health/Lease claims, unsafe ordering, or foreign evidence.
    pub fn admit_ha_infrastructure_fence(
        &mut self,
        evidence: EgressHaInfrastructureFenceEvidence,
    ) -> Result<(), EgressControlPlaneError> {
        let owner = self.promotion_owner(evidence.manifest_digest)?;
        self.update_promotion(&owner, |coordinator| {
            coordinator.admit_infrastructure_fence(evidence)
        })
    }

    /// After the old owner is fenced, stages the pre-certified survivor set.
    /// Sources remain fenced and cannot activate from this operation alone.
    ///
    /// # Errors
    ///
    /// Rejects premature staging, missing allocation, or invalid CCR output.
    pub fn stage_ha_replacement(
        &mut self,
        owner: &EgressIntentOwner,
    ) -> Result<bool, EgressControlPlaneError> {
        let promotion = self
            .ha_promotions
            .get(owner)
            .cloned()
            .ok_or(EgressControlPlaneError::InvalidHaCheckpoint)?;
        if promotion.replacement_staged {
            return Ok(false);
        }
        let coordinator = EgressHaPromotionCoordinator::restore(
            &promotion.previous_plan,
            promotion.coordinator.clone(),
        )?;
        if coordinator.phase() != EgressHaPromotionPhase::AcquiringNewOwners {
            return Err(EgressHaPromotionError::EvidenceOrder.into());
        }
        let lease = self
            .allocator
            .lease(owner)
            .cloned()
            .ok_or(EgressControlPlaneError::InvalidHaCheckpoint)?;
        let survivors = promotion
            .previous_plan
            .candidates
            .iter()
            .filter(|candidate| candidate.node != promotion.coordinator.manifest.failed_gateway)
            .cloned()
            .collect::<Vec<_>>();
        if survivors.is_empty() {
            return Err(EgressControlPlaneError::InvalidGatewayCandidates);
        }
        let desired = self.gateways.ensure(
            &lease,
            survivors
                .iter()
                .map(|candidate| candidate.node.clone())
                .collect(),
        )?;
        if survivors.len() > 1 {
            let plan = compile_egress_ha_plan(
                &lease,
                survivors,
                Some(&promotion.previous_plan),
                desired.revision,
            )?;
            self.ha_plans.insert(owner.clone(), plan);
        } else {
            self.ha_plans.remove(owner);
        }
        self.ha_promotions
            .get_mut(owner)
            .ok_or(EgressControlPlaneError::InvalidHaCheckpoint)?
            .replacement_staged = true;
        validate_cross_state(&self.allocator, &self.gateways)?;
        Ok(true)
    }

    /// Admits exact replacement kernel acquisition.
    ///
    /// # Errors
    ///
    /// Rejects acquisition before fencing or any address/identity mismatch.
    pub fn admit_ha_gateway_acquisition(
        &mut self,
        evidence: EgressHaGatewayAcquisitionEvidence,
    ) -> Result<(), EgressControlPlaneError> {
        let owner = self.promotion_owner(evidence.manifest_digest)?;
        if !self
            .ha_promotions
            .get(&owner)
            .is_some_and(|promotion| promotion.replacement_staged)
        {
            return Err(EgressHaPromotionError::EvidenceOrder.into());
        }
        self.update_promotion(&owner, |coordinator| {
            coordinator.admit_gateway_acquisition(evidence)
        })
    }

    /// Admits the independent reachability compare-and-swap readback.
    ///
    /// # Errors
    ///
    /// Rejects premature, foreign, stale, or non-CAS evidence.
    pub fn admit_ha_reachability_handoff(
        &mut self,
        evidence: EgressHaReachabilityHandoffEvidence,
    ) -> Result<(), EgressControlPlaneError> {
        let owner = self.promotion_owner(evidence.manifest_digest)?;
        self.update_promotion(&owner, |coordinator| {
            coordinator.admit_reachability_handoff(evidence)
        })
    }

    /// Stores one primary snapshot only after every source is fenced.
    ///
    /// # Errors
    ///
    /// Rejects a foreign handoff, duplicate stream, or premature snapshot.
    pub fn admit_ha_flow_twin_stream(
        &mut self,
        stream: EgressHaFlowTwinStream,
    ) -> Result<(), EgressControlPlaneError> {
        let owner = self
            .ha_promotions
            .iter()
            .find(|(_, promotion)| promotion.previous_plan.plan_digest == stream.owner_plan_digest)
            .map(|(owner, _)| owner.clone())
            .ok_or(EgressControlPlaneError::InvalidHaCheckpoint)?;
        let promotion = self
            .ha_promotions
            .get_mut(&owner)
            .ok_or(EgressControlPlaneError::InvalidHaCheckpoint)?;
        let coordinator = EgressHaPromotionCoordinator::restore(
            &promotion.previous_plan,
            promotion.coordinator.clone(),
        )?;
        if coordinator.phase() == EgressHaPromotionPhase::FencingSources {
            return Err(EgressHaPromotionError::EvidenceOrder.into());
        }
        stream.verify(&promotion.coordinator.manifest)?;
        if promotion.flow_streams.iter().any(|current| {
            current.primary_gateway == stream.primary_gateway
                && current.standby_gateway == stream.standby_gateway
        }) {
            return Err(EgressControlPlaneError::InvalidHaCheckpoint);
        }
        promotion.flow_streams.push(stream);
        promotion.flow_streams.sort_by(|left, right| {
            (&left.primary_gateway, &left.standby_gateway)
                .cmp(&(&right.primary_gateway, &right.standby_gateway))
        });
        Ok(())
    }

    /// Stores exact standby readback for one admitted flow-twin stream.
    ///
    /// # Errors
    ///
    /// Rejects missing stream state, duplicate acknowledgement, or mismatch.
    pub fn admit_ha_flow_twin_acknowledgement(
        &mut self,
        acknowledgement: EgressHaFlowTwinAcknowledgement,
    ) -> Result<(), EgressControlPlaneError> {
        let promotion = self
            .ha_promotions
            .values_mut()
            .find(|promotion| {
                promotion.previous_plan.plan_digest == acknowledgement.owner_plan_digest
            })
            .ok_or(EgressControlPlaneError::InvalidHaCheckpoint)?;
        let stream = promotion
            .flow_streams
            .iter()
            .find(|stream| {
                stream.primary_gateway == acknowledgement.primary_gateway
                    && stream.standby_gateway == acknowledgement.standby_gateway
            })
            .ok_or(EgressControlPlaneError::InvalidHaCheckpoint)?;
        acknowledgement.verify(stream, &promotion.coordinator.manifest)?;
        if promotion.flow_acknowledgements.iter().any(|current| {
            current.primary_gateway == acknowledgement.primary_gateway
                && current.standby_gateway == acknowledgement.standby_gateway
        }) {
            return Err(EgressControlPlaneError::InvalidHaCheckpoint);
        }
        promotion.flow_acknowledgements.push(acknowledgement);
        promotion.flow_acknowledgements.sort_by(|left, right| {
            (&left.primary_gateway, &left.standby_gateway)
                .cmp(&(&right.primary_gateway, &right.standby_gateway))
        });
        Ok(())
    }

    /// Seals one source-specific atomic cutover using its acknowledged target
    /// inactive bank.
    ///
    /// # Errors
    ///
    /// Rejects incomplete promotion/replication evidence or a foreign source.
    pub fn seal_ha_source_cutover(
        &mut self,
        owner: &EgressIntentOwner,
        source: &EgressProjectionRecipient,
        cutoff_ns: u64,
    ) -> Result<EgressHaContinuityCutover, EgressControlPlaneError> {
        let authority = self.ha_activation_authority(owner)?;
        let promotion = self
            .ha_promotions
            .get_mut(owner)
            .ok_or(EgressControlPlaneError::InvalidHaCheckpoint)?;
        if let Some(cutover) = promotion.cutovers.get(source) {
            return Ok(cutover.clone());
        }
        let target_bank = promotion
            .coordinator
            .source_fences
            .iter()
            .find(|fence| &fence.recipient == source)
            .map(|fence| fence.inactive_bank)
            .ok_or(EgressControlPlaneError::InvalidHaCheckpoint)?;
        let cutover = EgressHaContinuityCutover::issue(
            &authority,
            promotion.flow_streams.clone(),
            promotion.flow_acknowledgements.clone(),
            cutoff_ns,
            target_bank,
        )?;
        promotion.cutovers.insert(source.clone(), cutover.clone());
        Ok(cutover)
    }

    /// Returns the complete source-specific activation proof bundle.
    ///
    /// # Errors
    ///
    /// Rejects incomplete authority or a source without a sealed cutover.
    pub fn ha_activation_bundle(
        &self,
        owner: &EgressIntentOwner,
        source: &EgressProjectionRecipient,
    ) -> Result<(EgressHaActivationAuthority, EgressHaContinuityCutover), EgressControlPlaneError>
    {
        let authority = self.ha_activation_authority(owner)?;
        let cutover = self
            .ha_promotions
            .get(owner)
            .and_then(|promotion| promotion.cutovers.get(source))
            .cloned()
            .ok_or(EgressControlPlaneError::InvalidHaCheckpoint)?;
        cutover.verify(&authority)?;
        Ok((authority, cutover))
    }

    /// Stores one exact active-bank readback after source cutover.
    ///
    /// # Errors
    ///
    /// Rejects a missing bundle, foreign source, duplicate, or wrong bank.
    pub fn admit_ha_source_activation(
        &mut self,
        evidence: EgressHaSourceActivationEvidence,
    ) -> Result<(), EgressControlPlaneError> {
        let owner = self.promotion_owner(evidence.manifest_digest)?;
        let (authority, cutover) = self.ha_activation_bundle(&owner, &evidence.recipient)?;
        evidence.verify(&authority, &cutover)?;
        let promotion = self
            .ha_promotions
            .get_mut(&owner)
            .ok_or(EgressControlPlaneError::InvalidHaCheckpoint)?;
        if promotion
            .source_activations
            .iter()
            .any(|current| current.recipient == evidence.recipient)
        {
            return Err(EgressHaPromotionError::EvidenceOrder.into());
        }
        promotion.source_activations.push(evidence);
        promotion
            .source_activations
            .sort_by(|left, right| left.recipient.cmp(&right.recipient));
        Ok(())
    }

    /// Removes a completed promotion only after every challenged source has
    /// read back the exact target bank. The replacement plan remains active.
    ///
    /// # Errors
    ///
    /// Rejects premature finalization or an unknown transaction.
    pub fn finalize_ha_promotion(
        &mut self,
        owner: &EgressIntentOwner,
    ) -> Result<(), EgressControlPlaneError> {
        let promotion = self
            .ha_promotions
            .get(owner)
            .ok_or(EgressControlPlaneError::InvalidHaCheckpoint)?;
        let expected = promotion
            .coordinator
            .manifest
            .sources
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        let actual = promotion
            .source_activations
            .iter()
            .map(|evidence| evidence.recipient.clone())
            .collect::<BTreeSet<_>>();
        if expected != actual || promotion.cutovers.len() != expected.len() {
            return Err(EgressHaPromotionError::EvidenceOrder.into());
        }
        self.ha_promotions.remove(owner);
        Ok(())
    }

    /// Seals the activation capability only after every persisted witness.
    ///
    /// # Errors
    ///
    /// Rejects an unknown or incomplete transaction.
    pub fn ha_activation_authority(
        &self,
        owner: &EgressIntentOwner,
    ) -> Result<crate::EgressHaActivationAuthority, EgressControlPlaneError> {
        let promotion = self
            .ha_promotions
            .get(owner)
            .ok_or(EgressControlPlaneError::InvalidHaCheckpoint)?;
        if !promotion.replacement_staged {
            return Err(EgressHaPromotionError::EvidenceOrder.into());
        }
        Ok(EgressHaPromotionCoordinator::restore(
            &promotion.previous_plan,
            promotion.coordinator.clone(),
        )?
        .activation_authority()?)
    }

    fn promotion_owner(
        &self,
        digest: crate::EgressHaPromotionDigest,
    ) -> Result<EgressIntentOwner, EgressControlPlaneError> {
        self.ha_promotions
            .iter()
            .find(|(_, promotion)| promotion.coordinator.manifest.manifest_digest == digest)
            .map(|(owner, _)| owner.clone())
            .ok_or(EgressControlPlaneError::InvalidHaCheckpoint)
    }

    fn update_promotion<F>(
        &mut self,
        owner: &EgressIntentOwner,
        apply: F,
    ) -> Result<(), EgressControlPlaneError>
    where
        F: FnOnce(&mut EgressHaPromotionCoordinator) -> Result<(), EgressHaPromotionError>,
    {
        let promotion = self
            .ha_promotions
            .get(owner)
            .cloned()
            .ok_or(EgressControlPlaneError::InvalidHaCheckpoint)?;
        let mut coordinator =
            EgressHaPromotionCoordinator::restore(&promotion.previous_plan, promotion.coordinator)?;
        apply(&mut coordinator)?;
        self.ha_promotions
            .get_mut(owner)
            .ok_or(EgressControlPlaneError::InvalidHaCheckpoint)?
            .coordinator = coordinator.checkpoint();
        Ok(())
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

    /// Freezes the authoritative admitted-source snapshot for one withdrawal.
    /// An exact replay is idempotent; a different later snapshot is rejected.
    ///
    /// # Errors
    ///
    /// Rejects unknown/non-withdrawing ownership, malformed projections, or
    /// any attempt to mutate a previously registered retirement set.
    pub fn register_retirement(
        &mut self,
        owner: &EgressIntentOwner,
        admitted_sources: &[AdmittedEgressProjection],
    ) -> Result<EgressRetirementManifest, EgressControlPlaneError> {
        let record = self
            .gateways
            .record(owner)
            .ok_or_else(|| EgressGatewayError::UnknownOwner(owner.clone()))?;
        let manifest = EgressRetirementManifest::issue(&record.desired, admitted_sources)?;
        if let Some(previous) = self.retirements.get(owner) {
            if previous != &manifest {
                return Err(EgressControlPlaneError::RetirementManifestConflict(
                    owner.clone(),
                ));
            }
            return Ok(previous.clone());
        }
        self.retirements.insert(owner.clone(), manifest.clone());
        Ok(manifest)
    }

    /// Atomically consumes a complete, sealed proof that every source,
    /// gateway, and reachability owner has forgotten one withdrawn lease.
    /// Ordinary reconciliation never infers this condition.
    ///
    /// # Errors
    ///
    /// Rejects stale, incomplete, mutated, or foreign evidence and preserves
    /// both the gateway record and allocation on every failure.
    pub fn authorize_release(
        &mut self,
        authority: &EgressSafeReleaseAuthority,
    ) -> Result<bool, EgressControlPlaneError> {
        let owner = authority.manifest.owner.clone();
        let record = self
            .gateways
            .record(&owner)
            .ok_or_else(|| EgressGatewayError::UnknownOwner(owner.clone()))?
            .clone();
        authority.verify(&record.desired)?;
        if self.retirements.get(&owner) != Some(&authority.manifest)
            || record.reachability.as_ref() != Some(&authority.reachability)
        {
            return Err(EgressControlPlaneError::ReleaseAuthorityMismatch(owner));
        }

        let mut next = self.clone();
        next.gateways.complete_withdrawal(&owner)?;
        next.allocator.release(&owner)?;
        next.ha_plans.remove(&owner);
        next.ha_promotions.remove(&owner);
        next.retirements.remove(&owner);
        validate_cross_state(&next.allocator, &next.gateways)?;
        *self = next;
        Ok(true)
    }

    #[must_use]
    pub fn checkpoint(&self) -> EgressControlPlaneCheckpoint {
        EgressControlPlaneCheckpoint {
            schema_version: EGRESS_CONTROL_PLANE_CHECKPOINT_SCHEMA_VERSION,
            desired_revision: self.desired_revision,
            desired_model: self.desired_model.clone(),
            allocation: self.allocator.checkpoint(),
            gateways: self.gateways.checkpoint(),
            ha_plans: self.ha_plans.values().cloned().collect(),
            ha_promotions: self.ha_promotions.values().cloned().collect(),
            retirements: self.retirements.values().cloned().collect(),
        }
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

fn validate_ha_plan_checkpoint(
    plan: &EgressHaPlan,
    allocator: &EgressAllocator,
    gateways: &EgressGatewayRegistry,
) -> Result<(), EgressControlPlaneError> {
    plan.verify_integrity()?;
    let lease = allocator
        .lease(&plan.owner)
        .ok_or(EgressControlPlaneError::InvalidHaCheckpoint)?;
    let record = gateways
        .record(&plan.owner)
        .ok_or(EgressControlPlaneError::InvalidHaCheckpoint)?;
    let plan_nodes = plan
        .candidates
        .iter()
        .map(|candidate| candidate.node.clone())
        .collect::<Vec<_>>();
    let plan_addresses = plan
        .shards
        .iter()
        .flat_map(|shard| shard.addresses.iter().copied())
        .collect::<BTreeSet<_>>();
    if plan.owner != lease.intent.owner
        || plan.allocation_revision != lease.allocation_revision
        || plan.lease_epoch != lease.lease_epoch
        || (plan.revision != record.desired.revision
            && (record.desired.action != crate::EgressGatewayAction::Withdraw
                || plan.revision >= record.desired.revision))
        || plan_nodes != record.desired.nodes
        || plan_addresses != lease.addresses.iter().copied().collect()
    {
        return Err(EgressControlPlaneError::InvalidHaCheckpoint);
    }
    Ok(())
}

fn validate_promotion_continuity(
    promotion: &EgressHaControlPlanePromotion,
) -> Result<(), EgressControlPlaneError> {
    if promotion.flow_streams.windows(2).any(|pair| {
        (&pair[0].primary_gateway, &pair[0].standby_gateway)
            >= (&pair[1].primary_gateway, &pair[1].standby_gateway)
    }) || promotion.flow_acknowledgements.windows(2).any(|pair| {
        (&pair[0].primary_gateway, &pair[0].standby_gateway)
            >= (&pair[1].primary_gateway, &pair[1].standby_gateway)
    }) || promotion
        .source_activations
        .windows(2)
        .any(|pair| pair[0].recipient >= pair[1].recipient)
    {
        return Err(EgressControlPlaneError::InvalidHaCheckpoint);
    }
    for stream in &promotion.flow_streams {
        stream.verify(&promotion.coordinator.manifest)?;
    }
    for acknowledgement in &promotion.flow_acknowledgements {
        let stream = promotion
            .flow_streams
            .iter()
            .find(|stream| {
                stream.primary_gateway == acknowledgement.primary_gateway
                    && stream.standby_gateway == acknowledgement.standby_gateway
            })
            .ok_or(EgressControlPlaneError::InvalidHaCheckpoint)?;
        acknowledgement.verify(stream, &promotion.coordinator.manifest)?;
    }
    if !promotion.cutovers.is_empty() {
        let authority = EgressHaPromotionCoordinator::restore(
            &promotion.previous_plan,
            promotion.coordinator.clone(),
        )?
        .activation_authority()?;
        for (source, cutover) in &promotion.cutovers {
            if !promotion.coordinator.manifest.sources.contains(source) {
                return Err(EgressControlPlaneError::InvalidHaCheckpoint);
            }
            cutover.verify(&authority)?;
        }
        for evidence in &promotion.source_activations {
            let cutover = promotion
                .cutovers
                .get(&evidence.recipient)
                .ok_or(EgressControlPlaneError::InvalidHaCheckpoint)?;
            evidence.verify(&authority, cutover)?;
        }
    } else if !promotion.source_activations.is_empty() {
        return Err(EgressControlPlaneError::InvalidHaCheckpoint);
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
        EgressGatewayAction, EgressGatewayDrainEvidence, EgressIntent, EgressIntentScope,
        EgressProjectionRecipient, EgressProviderOutcome, EgressRetirementManifest,
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

    fn withdrawn_acknowledgements(
        desired: &crate::EgressGatewayDesired,
    ) -> (
        EgressGatewayAcknowledgement,
        EgressReachabilityAcknowledgement,
    ) {
        (
            EgressGatewayAcknowledgement {
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
            },
            EgressReachabilityAcknowledgement {
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
            },
        )
    }

    fn recipient(node: &EgressNode) -> EgressProjectionRecipient {
        EgressProjectionRecipient {
            node_name: node.name.clone(),
            node_uid: node.uid.clone(),
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
        assert_eq!(checkpoint.ha_plans.len(), 1);
        assert_eq!(checkpoint.ha_plans[0].candidates.len(), 2);
        assert_eq!(checkpoint.ha_plans[0].assignments.len(), 1);
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

        let mut v3 = serde_json::to_value(&checkpoint).unwrap();
        v3["schemaVersion"] = serde_json::json!(3);
        v3.as_object_mut().unwrap().remove("haPromotions");
        let migrated = EgressControlPlane::restore(serde_json::from_value(v3).unwrap()).unwrap();
        assert_eq!(
            migrated.checkpoint().schema_version,
            EGRESS_CONTROL_PLANE_CHECKPOINT_SCHEMA_VERSION
        );

        let mut mutated = checkpoint;
        mutated.ha_plans[0].assignments[0].gateway = node("foreign");
        assert!(matches!(
            EgressControlPlane::restore(mutated),
            Err(EgressControlPlaneError::Ha(_) | EgressControlPlaneError::InvalidHaCheckpoint)
        ));
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn ha_promotion_is_durable_ordered_and_never_health_authorized() {
        let mut payments = intent("payments");
        payments.addresses = EgressAddressRequest::Pool {
            name: "public".to_owned(),
            families: vec![AddressFamily::Ipv4],
            addresses_per_family: 4,
        };
        let mut control = EgressControlPlane::default();
        control
            .reconcile(
                Revision::new(1),
                model(vec![payments]),
                &providers(),
                vec![node("gateway-a"), node("gateway-b"), node("gateway-c")],
            )
            .unwrap();
        let checkpoint = control.checkpoint();
        let plan = checkpoint.ha_plans[0].clone();
        let failed = plan.assignments[0].gateway.clone();
        let source = recipient(&node("worker-a"));
        let manifest = control
            .begin_ha_promotion(
                &plan.owner,
                &failed.uid,
                vec![source.clone()],
                41,
                9,
                Revision::new(20),
            )
            .unwrap();
        let source_challenges = control
            .ha_agent_challenges(source.clone(), 41)
            .expect("derive exact source challenge");
        assert!(matches!(
            source_challenges.challenges.as_slice(),
            [EgressHaAgentChallenge::SourceFence { .. }]
        ));
        assert_eq!(source_challenges.certified_plans, vec![plan.clone()]);
        let primary_challenges = control
            .ha_agent_challenges(recipient(&failed), 41)
            .expect("old owner waits for all source fences");
        assert!(primary_challenges.challenges.is_empty());
        assert_eq!(control.checkpoint().ha_plans, vec![plan.clone()]);
        assert!(control.stage_ha_replacement(&plan.owner).is_err());

        control
            .admit_ha_source_fence(EgressHaSourceFenceEvidence {
                schema_version: crate::EGRESS_HA_PROMOTION_SCHEMA_VERSION,
                controller_epoch: 41,
                promotion_epoch: 9,
                recipient: source.clone(),
                manifest_digest: manifest.manifest_digest,
                active_plan_digest: plan.plan_digest,
                fenced_shards: manifest
                    .handoffs
                    .iter()
                    .map(|handoff| handoff.shard_index)
                    .collect(),
                inactive_bank: 1,
            })
            .unwrap();
        let primary_challenges = control
            .ha_agent_challenges(recipient(&failed), 41)
            .expect("source fence releases exact snapshot challenges");
        assert_eq!(
            primary_challenges
                .challenges
                .iter()
                .filter(|challenge| matches!(
                    challenge,
                    EgressHaAgentChallenge::PrimarySnapshot { .. }
                ))
                .count(),
            manifest
                .handoffs
                .iter()
                .map(|handoff| &handoff.new_gateway)
                .collect::<BTreeSet<_>>()
                .len()
        );
        let mut unsafe_fence = EgressHaInfrastructureFenceEvidence {
            schema_version: crate::EGRESS_HA_PROMOTION_SCHEMA_VERSION,
            controller_epoch: 41,
            promotion_epoch: 9,
            gateway: failed.clone(),
            manifest_digest: manifest.manifest_digest,
            provider: "kubernetes-node-ready".to_owned(),
            fence_token: "not-authority".to_owned(),
            provider_revision: 1,
            isolated: true,
        };
        assert!(
            control
                .admit_ha_infrastructure_fence(unsafe_fence.clone())
                .is_err()
        );
        unsafe_fence.provider = "redfish-bmc".to_owned();
        unsafe_fence.fence_token = "power-off-991".to_owned();
        control.admit_ha_infrastructure_fence(unsafe_fence).unwrap();
        assert!(control.stage_ha_replacement(&plan.owner).unwrap());
        assert!(!control.stage_ha_replacement(&plan.owner).unwrap());
        let staged = control.checkpoint();
        assert!(!staged.gateways.records[0].desired.nodes.contains(&failed));
        assert_eq!(
            EgressControlPlane::restore(staged.clone())
                .unwrap()
                .checkpoint(),
            staged
        );

        let mut acquisitions = BTreeMap::<EgressNode, BTreeSet<IpAddr>>::new();
        for handoff in &manifest.handoffs {
            acquisitions
                .entry(handoff.new_gateway.clone())
                .or_default()
                .extend(handoff.addresses.iter().copied());
        }
        for (gateway, addresses) in acquisitions {
            control
                .admit_ha_gateway_acquisition(EgressHaGatewayAcquisitionEvidence {
                    schema_version: crate::EGRESS_HA_PROMOTION_SCHEMA_VERSION,
                    controller_epoch: 41,
                    promotion_epoch: 9,
                    gateway,
                    manifest_digest: manifest.manifest_digest,
                    owned_addresses: addresses.into_iter().collect(),
                    kernel_revision: Revision::new(21),
                })
                .unwrap();
        }
        control
            .admit_ha_reachability_handoff(EgressHaReachabilityHandoffEvidence {
                schema_version: crate::EGRESS_HA_PROMOTION_SCHEMA_VERSION,
                controller_epoch: 41,
                promotion_epoch: 9,
                manifest_digest: manifest.manifest_digest,
                expected_plan_digest: manifest.active_plan_digest,
                installed_plan_digest: manifest.contingency_digest,
                handoffs: manifest.handoffs.clone(),
                provider: "static-l2-cas".to_owned(),
                provider_revision: 3,
                compare_and_swap_applied: true,
            })
            .unwrap();
        let mut pairs = BTreeMap::<(EgressNode, EgressNode), Vec<u16>>::new();
        for handoff in &manifest.handoffs {
            pairs
                .entry((handoff.old_gateway.clone(), handoff.new_gateway.clone()))
                .or_default()
                .push(handoff.shard_index);
        }
        for ((primary, standby), shards) in pairs {
            let stream =
                EgressHaFlowTwinStream::issue(&manifest, primary, standby, shards, 11).unwrap();
            let acknowledgement = stream.acknowledge(&manifest, Revision::new(22)).unwrap();
            control.admit_ha_flow_twin_stream(stream).unwrap();
            control
                .admit_ha_flow_twin_acknowledgement(acknowledgement)
                .unwrap();
        }
        let authority = control.ha_activation_authority(&plan.owner).unwrap();
        authority.verify().unwrap();
        let cutover = control
            .seal_ha_source_cutover(&plan.owner, &recipient(&node("worker-a")), 1_000_000)
            .unwrap();
        cutover.verify(&authority).unwrap();
        let cutover_checkpoint = control.checkpoint();
        let encoded = serde_json::to_string(&cutover_checkpoint)
            .expect("sealed structured-recipient cutover is JSON durable");
        assert!(encoded.contains("\"cutovers\":["));
        let decoded: EgressControlPlaneCheckpoint =
            serde_json::from_str(&encoded).expect("decode sealed cutover checkpoint");
        assert_eq!(
            EgressControlPlane::restore(decoded).unwrap().checkpoint(),
            cutover_checkpoint
        );
        let activation = control
            .ha_agent_challenges(source, 41)
            .expect("derive source activation proof bundle");
        assert!(
            activation.challenges.iter().any(|challenge| matches!(
                challenge,
                EgressHaAgentChallenge::SourceActivation { .. }
            ))
        );
        let mut mutated = serde_json::to_value(&activation).unwrap();
        mutated["unknown"] = serde_json::json!(true);
        assert!(serde_json::from_value::<EgressHaAgentChallenges>(mutated).is_err());
        let activation_evidence = EgressHaSourceActivationEvidence::issue(
            &authority,
            &cutover,
            recipient(&node("worker-a")),
            Revision::new(30),
            cutover.target_source_bank,
        )
        .unwrap();
        control
            .admit_ha_source_activation(activation_evidence)
            .unwrap();
        let final_checkpoint = control.checkpoint();
        assert_eq!(
            EgressControlPlane::restore(final_checkpoint.clone())
                .unwrap()
                .checkpoint(),
            final_checkpoint
        );
        control.finalize_ha_promotion(&plan.owner).unwrap();
        assert!(control.checkpoint().ha_promotions.is_empty());
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
    fn ha_withdrawal_retains_a_restorable_frozen_ownership_certificate() {
        let mut control = EgressControlPlane::default();
        control
            .reconcile(
                Revision::new(1),
                model(vec![intent("payments")]),
                &providers(),
                vec![node("gateway-a"), node("gateway-b")],
            )
            .expect("ensure HA ownership");
        control
            .reconcile(
                Revision::new(2),
                model(Vec::new()),
                &providers(),
                vec![node("gateway-a"), node("gateway-b")],
            )
            .expect("begin HA withdrawal");

        let checkpoint = control.checkpoint();
        let desired = &checkpoint.gateways.records[0].desired;
        assert_eq!(desired.action, EgressGatewayAction::Withdraw);
        assert!(checkpoint.ha_plans[0].revision < desired.revision);
        assert_eq!(
            EgressControlPlane::restore(checkpoint.clone())
                .expect("withdrawal certificate remains restart-safe")
                .checkpoint(),
            checkpoint
        );
    }

    #[test]
    fn removal_requires_safe_forgetting_authority_before_reuse() {
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

        let (gateway, reachability) = withdrawn_acknowledgements(&desired);
        control
            .acknowledge_gateway(gateway)
            .expect("gateway withdrawn");
        control
            .acknowledge_reachability(reachability.clone())
            .expect("reachability withdrawn");
        control
            .reconcile(
                Revision::new(2),
                model(Vec::new()),
                &providers(),
                vec![node("gateway-a")],
            )
            .expect("provider acknowledgements do not imply safe release");
        assert_eq!(control.checkpoint().allocation.leases.len(), 1);

        assert!(matches!(
            EgressGatewayDrainEvidence::issue(7, &desired, recipient(&desired.nodes[0]), 1, true,),
            Err(EgressSafeForgettingError::EvidenceMismatch)
        ));
        let manifest = EgressRetirementManifest::issue(&desired, &[])
            .expect("an unregistered empty source set can be sealed but is not authority");
        let gateway_drain =
            EgressGatewayDrainEvidence::issue(7, &desired, recipient(&desired.nodes[0]), 0, true)
                .expect("withdrawn gateway has no retained connections");
        let authority = EgressSafeReleaseAuthority::issue(
            7,
            Revision::new(1),
            &desired,
            manifest,
            Vec::new(),
            vec![gateway_drain],
            reachability,
        )
        .expect("complete proof of safe forgetting");
        assert!(matches!(
            control.authorize_release(&authority),
            Err(EgressControlPlaneError::ReleaseAuthorityMismatch(_))
        ));
        let registered = control
            .register_retirement(&desired.owner, &[])
            .expect("freeze authoritative source snapshot");
        assert_eq!(registered, authority.manifest);
        let checkpoint = control.checkpoint();
        assert_eq!(checkpoint.retirements, vec![registered]);
        let mut drift = checkpoint.clone();
        drift.retirements[0].lease_epoch += 1;
        assert!(matches!(
            EgressControlPlane::restore(drift),
            Err(EgressControlPlaneError::SafeForgetting(_))
        ));
        control = EgressControlPlane::restore(checkpoint).expect("retirement survives restart");
        assert!(control.authorize_release(&authority).expect("safe release"));
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
