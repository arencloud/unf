//! Proof-carrying, split-brain-safe HA ownership promotion.
//!
//! Health observations may start an investigation, but they cannot authorize
//! ownership transfer. Promotion requires source fencing plus either exact
//! old-owner revocation or an independent infrastructure fence. New ownership
//! and external reachability are then read back before a complete source table
//! may activate.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use unf_common::Revision;

use crate::{
    EgressHaAssignment, EgressHaContingency, EgressHaDigest, EgressHaPlan, EgressIntentOwner,
    EgressNode, EgressProjectionRecipient, MAX_EGRESS_CONTRACT_PLANS,
};

pub const EGRESS_HA_PROMOTION_SCHEMA_VERSION: u16 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EgressHaPromotionDigest(pub [u8; 32]);

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EgressHaShardHandoff {
    pub shard_index: u16,
    pub addresses: Vec<IpAddr>,
    pub old_gateway: EgressNode,
    pub new_gateway: EgressNode,
}

/// Immutable challenge describing exactly what may move in one promotion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EgressHaPromotionManifest {
    pub schema_version: u16,
    pub controller_epoch: u64,
    pub promotion_epoch: u64,
    pub authority_revision: Revision,
    pub owner: EgressIntentOwner,
    pub allocation_revision: Revision,
    pub lease_epoch: u64,
    pub active_plan_revision: Revision,
    pub active_plan_digest: EgressHaDigest,
    pub contingency_digest: EgressHaDigest,
    pub failed_gateway: EgressNode,
    pub handoffs: Vec<EgressHaShardHandoff>,
    pub sources: Vec<EgressProjectionRecipient>,
    pub manifest_digest: EgressHaPromotionDigest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EgressHaSourceFenceEvidence {
    pub schema_version: u16,
    pub controller_epoch: u64,
    pub promotion_epoch: u64,
    pub recipient: EgressProjectionRecipient,
    pub manifest_digest: EgressHaPromotionDigest,
    pub active_plan_digest: EgressHaDigest,
    pub fenced_shards: Vec<u16>,
    pub inactive_bank: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EgressHaOldOwnerRevocationEvidence {
    pub schema_version: u16,
    pub controller_epoch: u64,
    pub promotion_epoch: u64,
    pub gateway: EgressNode,
    pub manifest_digest: EgressHaPromotionDigest,
    pub absent_addresses: Vec<IpAddr>,
    pub kernel_revision: Revision,
}

/// Evidence from a power, hypervisor, cloud, or equivalent isolation plane.
/// Kubernetes Node readiness and Lease observations are deliberately excluded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EgressHaInfrastructureFenceEvidence {
    pub schema_version: u16,
    pub controller_epoch: u64,
    pub promotion_epoch: u64,
    pub gateway: EgressNode,
    pub manifest_digest: EgressHaPromotionDigest,
    pub provider: String,
    pub fence_token: String,
    pub provider_revision: u64,
    pub isolated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase", tag = "kind")]
pub enum EgressHaOldOwnerFenceEvidence {
    Revocation(EgressHaOldOwnerRevocationEvidence),
    Infrastructure(EgressHaInfrastructureFenceEvidence),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EgressHaGatewayAcquisitionEvidence {
    pub schema_version: u16,
    pub controller_epoch: u64,
    pub promotion_epoch: u64,
    pub gateway: EgressNode,
    pub manifest_digest: EgressHaPromotionDigest,
    pub owned_addresses: Vec<IpAddr>,
    pub kernel_revision: Revision,
}

/// Compare-and-swap readback from the independent reachability provider.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EgressHaReachabilityHandoffEvidence {
    pub schema_version: u16,
    pub controller_epoch: u64,
    pub promotion_epoch: u64,
    pub manifest_digest: EgressHaPromotionDigest,
    pub expected_plan_digest: EgressHaDigest,
    pub installed_plan_digest: EgressHaDigest,
    pub handoffs: Vec<EgressHaShardHandoff>,
    pub provider: String,
    pub provider_revision: u64,
    pub compare_and_swap_applied: bool,
}

/// Capability delivered to sources only after every safety witness agrees.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EgressHaActivationAuthority {
    pub schema_version: u16,
    pub manifest: EgressHaPromotionManifest,
    pub source_fences: Vec<EgressHaSourceFenceEvidence>,
    pub old_owner_fence: EgressHaOldOwnerFenceEvidence,
    pub acquisitions: Vec<EgressHaGatewayAcquisitionEvidence>,
    pub reachability: EgressHaReachabilityHandoffEvidence,
    pub authority_digest: EgressHaPromotionDigest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EgressHaPromotionPhase {
    FencingSources,
    FencingOldOwner,
    AcquiringNewOwners,
    ReadyToActivate,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum EgressHaPromotionError {
    #[error("HA promotion authority is malformed or stale")]
    InvalidAuthority,
    #[error("HA promotion does not match the certified contingency")]
    ContingencyMismatch,
    #[error("HA promotion evidence is incomplete, reordered, or duplicated")]
    EvidenceOrder,
    #[error("HA promotion evidence does not match its exact challenge")]
    EvidenceMismatch,
    #[error("Kubernetes health is not independent fencing authority")]
    UnsafeFenceProvider,
    #[error("HA promotion encoding failed: {0}")]
    Encoding(String),
}

/// In-memory verifier for the monotonic promotion protocol. Durable callers
/// may persist the manifest and admitted evidence after every transition.
#[derive(Debug, Clone)]
pub struct EgressHaPromotionCoordinator {
    manifest: EgressHaPromotionManifest,
    source_fences: BTreeMap<EgressProjectionRecipient, EgressHaSourceFenceEvidence>,
    old_owner_fence: Option<EgressHaOldOwnerFenceEvidence>,
    acquisitions: BTreeMap<EgressNode, EgressHaGatewayAcquisitionEvidence>,
    reachability: Option<EgressHaReachabilityHandoffEvidence>,
}

impl EgressHaPromotionManifest {
    /// Issues an exact promotion challenge from one pre-certified contingency.
    ///
    /// # Errors
    ///
    /// Rejects invalid epochs, sources, gateway identity, or contingency state.
    pub fn issue(
        plan: &EgressHaPlan,
        failed_gateway_uid: &str,
        mut sources: Vec<EgressProjectionRecipient>,
        controller_epoch: u64,
        promotion_epoch: u64,
        authority_revision: Revision,
    ) -> Result<Self, EgressHaPromotionError> {
        if controller_epoch == 0
            || promotion_epoch == 0
            || authority_revision == Revision::INITIAL
            || sources.len() > MAX_EGRESS_CONTRACT_PLANS
        {
            return Err(EgressHaPromotionError::InvalidAuthority);
        }
        sources.sort_unstable();
        if sources.windows(2).any(|pair| pair[0] == pair[1])
            || sources.iter().any(|source| {
                source.node_name.is_empty()
                    || source.node_uid.is_empty()
                    || source.node_name.len() > 253
                    || source.node_uid.len() > 128
            })
        {
            return Err(EgressHaPromotionError::InvalidAuthority);
        }
        let contingency = plan
            .contingencies
            .iter()
            .find(|item| item.failed_gateway.uid == failed_gateway_uid)
            .ok_or(EgressHaPromotionError::ContingencyMismatch)?;
        let handoffs = handoffs(plan, contingency)?;
        if handoffs.is_empty() {
            return Err(EgressHaPromotionError::ContingencyMismatch);
        }
        let mut manifest = Self {
            schema_version: EGRESS_HA_PROMOTION_SCHEMA_VERSION,
            controller_epoch,
            promotion_epoch,
            authority_revision,
            owner: plan.owner.clone(),
            allocation_revision: plan.allocation_revision,
            lease_epoch: plan.lease_epoch,
            active_plan_revision: plan.revision,
            active_plan_digest: plan.plan_digest,
            contingency_digest: contingency.digest,
            failed_gateway: contingency.failed_gateway.clone(),
            handoffs,
            sources,
            manifest_digest: EgressHaPromotionDigest([0; 32]),
        };
        manifest.manifest_digest = promotion_manifest_digest(&manifest)?;
        Ok(manifest)
    }

    /// Replays the challenge against the certified plan instead of trusting
    /// serialized assignments or digests.
    ///
    /// # Errors
    ///
    /// Rejects any field that differs from deterministic reconstruction.
    pub fn verify(&self, plan: &EgressHaPlan) -> Result<(), EgressHaPromotionError> {
        let expected = Self::issue(
            plan,
            &self.failed_gateway.uid,
            self.sources.clone(),
            self.controller_epoch,
            self.promotion_epoch,
            self.authority_revision,
        )?;
        if &expected == self {
            Ok(())
        } else {
            Err(EgressHaPromotionError::InvalidAuthority)
        }
    }
}

impl EgressHaPromotionCoordinator {
    #[must_use]
    pub fn new(manifest: EgressHaPromotionManifest) -> Self {
        Self {
            manifest,
            source_fences: BTreeMap::new(),
            old_owner_fence: None,
            acquisitions: BTreeMap::new(),
            reachability: None,
        }
    }

    #[must_use]
    pub fn manifest(&self) -> &EgressHaPromotionManifest {
        &self.manifest
    }

    #[must_use]
    pub fn phase(&self) -> EgressHaPromotionPhase {
        if self.source_fences.len() != self.manifest.sources.len() {
            EgressHaPromotionPhase::FencingSources
        } else if self.old_owner_fence.is_none() {
            EgressHaPromotionPhase::FencingOldOwner
        } else if !self.acquisitions_complete() || self.reachability.is_none() {
            EgressHaPromotionPhase::AcquiringNewOwners
        } else {
            EgressHaPromotionPhase::ReadyToActivate
        }
    }

    /// Admits an exact inactive-bank readback from one challenged source.
    ///
    /// # Errors
    ///
    /// Rejects stale, partial, foreign, duplicate, or reordered evidence.
    pub fn admit_source_fence(
        &mut self,
        evidence: EgressHaSourceFenceEvidence,
    ) -> Result<(), EgressHaPromotionError> {
        if self.old_owner_fence.is_some() || self.source_fences.contains_key(&evidence.recipient) {
            return Err(EgressHaPromotionError::EvidenceOrder);
        }
        let expected_shards = self
            .manifest
            .handoffs
            .iter()
            .map(|handoff| handoff.shard_index)
            .collect::<Vec<_>>();
        if evidence.schema_version != EGRESS_HA_PROMOTION_SCHEMA_VERSION
            || evidence.controller_epoch != self.manifest.controller_epoch
            || evidence.promotion_epoch != self.manifest.promotion_epoch
            || evidence.manifest_digest != self.manifest.manifest_digest
            || evidence.active_plan_digest != self.manifest.active_plan_digest
            || !self.manifest.sources.contains(&evidence.recipient)
            || evidence.fenced_shards != expected_shards
            || evidence.inactive_bank > 1
        {
            return Err(EgressHaPromotionError::EvidenceMismatch);
        }
        self.source_fences
            .insert(evidence.recipient.clone(), evidence);
        Ok(())
    }

    /// Admits graceful old-owner kernel readback after every source is fenced.
    ///
    /// # Errors
    ///
    /// Rejects missing source fences or inexact address/revision evidence.
    pub fn admit_old_owner_revocation(
        &mut self,
        evidence: EgressHaOldOwnerRevocationEvidence,
    ) -> Result<(), EgressHaPromotionError> {
        self.require_sources_fenced()?;
        if self.old_owner_fence.is_some() {
            return Err(EgressHaPromotionError::EvidenceOrder);
        }
        let expected = affected_addresses(&self.manifest);
        if evidence.schema_version != EGRESS_HA_PROMOTION_SCHEMA_VERSION
            || evidence.controller_epoch != self.manifest.controller_epoch
            || evidence.promotion_epoch != self.manifest.promotion_epoch
            || evidence.gateway != self.manifest.failed_gateway
            || evidence.manifest_digest != self.manifest.manifest_digest
            || evidence.absent_addresses != expected
            || evidence.kernel_revision == Revision::INITIAL
        {
            return Err(EgressHaPromotionError::EvidenceMismatch);
        }
        self.old_owner_fence = Some(EgressHaOldOwnerFenceEvidence::Revocation(evidence));
        Ok(())
    }

    /// Admits an independent infrastructure isolation witness.
    ///
    /// # Errors
    ///
    /// Rejects Kubernetes health as fencing, incomplete source fences, or an
    /// unconfirmed/foreign infrastructure operation.
    pub fn admit_infrastructure_fence(
        &mut self,
        evidence: EgressHaInfrastructureFenceEvidence,
    ) -> Result<(), EgressHaPromotionError> {
        self.require_sources_fenced()?;
        if self.old_owner_fence.is_some() {
            return Err(EgressHaPromotionError::EvidenceOrder);
        }
        let provider = evidence.provider.to_ascii_lowercase();
        if provider.contains("kubernetes")
            || provider.contains("node-ready")
            || provider.contains("node-lease")
            || provider == "ready"
            || provider == "lease"
        {
            return Err(EgressHaPromotionError::UnsafeFenceProvider);
        }
        if evidence.schema_version != EGRESS_HA_PROMOTION_SCHEMA_VERSION
            || evidence.controller_epoch != self.manifest.controller_epoch
            || evidence.promotion_epoch != self.manifest.promotion_epoch
            || evidence.gateway != self.manifest.failed_gateway
            || evidence.manifest_digest != self.manifest.manifest_digest
            || evidence.provider.is_empty()
            || evidence.provider.len() > 128
            || evidence.fence_token.is_empty()
            || evidence.fence_token.len() > 512
            || evidence.provider_revision == 0
            || !evidence.isolated
        {
            return Err(EgressHaPromotionError::EvidenceMismatch);
        }
        self.old_owner_fence = Some(EgressHaOldOwnerFenceEvidence::Infrastructure(evidence));
        Ok(())
    }

    /// Admits exact address ownership readback from one replacement gateway.
    ///
    /// # Errors
    ///
    /// Rejects acquisition before fencing or non-exact kernel ownership.
    pub fn admit_gateway_acquisition(
        &mut self,
        evidence: EgressHaGatewayAcquisitionEvidence,
    ) -> Result<(), EgressHaPromotionError> {
        self.require_old_owner_fenced()?;
        if self.acquisitions.contains_key(&evidence.gateway) {
            return Err(EgressHaPromotionError::EvidenceOrder);
        }
        let expected = addresses_for_new_gateway(&self.manifest, &evidence.gateway);
        if expected.is_empty()
            || evidence.schema_version != EGRESS_HA_PROMOTION_SCHEMA_VERSION
            || evidence.controller_epoch != self.manifest.controller_epoch
            || evidence.promotion_epoch != self.manifest.promotion_epoch
            || evidence.manifest_digest != self.manifest.manifest_digest
            || evidence.owned_addresses != expected
            || evidence.kernel_revision == Revision::INITIAL
        {
            return Err(EgressHaPromotionError::EvidenceMismatch);
        }
        self.acquisitions.insert(evidence.gateway.clone(), evidence);
        Ok(())
    }

    /// Admits atomic reachability compare-and-swap readback.
    ///
    /// # Errors
    ///
    /// Rejects fencing order violations or mismatched plan/provider evidence.
    pub fn admit_reachability_handoff(
        &mut self,
        evidence: EgressHaReachabilityHandoffEvidence,
    ) -> Result<(), EgressHaPromotionError> {
        self.require_old_owner_fenced()?;
        if self.reachability.is_some() {
            return Err(EgressHaPromotionError::EvidenceOrder);
        }
        if evidence.schema_version != EGRESS_HA_PROMOTION_SCHEMA_VERSION
            || evidence.controller_epoch != self.manifest.controller_epoch
            || evidence.promotion_epoch != self.manifest.promotion_epoch
            || evidence.manifest_digest != self.manifest.manifest_digest
            || evidence.expected_plan_digest != self.manifest.active_plan_digest
            || evidence.installed_plan_digest != self.manifest.contingency_digest
            || evidence.handoffs != self.manifest.handoffs
            || evidence.provider.is_empty()
            || evidence.provider.len() > 128
            || evidence.provider_revision == 0
            || !evidence.compare_and_swap_applied
        {
            return Err(EgressHaPromotionError::EvidenceMismatch);
        }
        self.reachability = Some(evidence);
        Ok(())
    }

    /// Seals the complete proof bundle that permits source-table activation.
    ///
    /// # Errors
    ///
    /// Rejects an incomplete fencing, acquisition, or reachability quorum.
    pub fn activation_authority(
        &self,
    ) -> Result<EgressHaActivationAuthority, EgressHaPromotionError> {
        self.require_old_owner_fenced()?;
        if !self.acquisitions_complete() {
            return Err(EgressHaPromotionError::EvidenceOrder);
        }
        let reachability = self
            .reachability
            .clone()
            .ok_or(EgressHaPromotionError::EvidenceOrder)?;
        let acquisitions = self.acquisitions.values().cloned().collect::<Vec<_>>();
        let source_fences = self.source_fences.values().cloned().collect::<Vec<_>>();
        let old_owner_fence = self
            .old_owner_fence
            .clone()
            .ok_or(EgressHaPromotionError::EvidenceOrder)?;
        let mut authority = EgressHaActivationAuthority {
            schema_version: EGRESS_HA_PROMOTION_SCHEMA_VERSION,
            manifest: self.manifest.clone(),
            source_fences,
            old_owner_fence,
            acquisitions,
            reachability,
            authority_digest: EgressHaPromotionDigest([0; 32]),
        };
        authority.authority_digest = digest(&(
            authority.schema_version,
            &authority.manifest,
            &authority.source_fences,
            &authority.old_owner_fence,
            &authority.acquisitions,
            &authority.reachability,
        ))?;
        authority.verify()?;
        Ok(authority)
    }

    fn require_sources_fenced(&self) -> Result<(), EgressHaPromotionError> {
        if self.source_fences.len() == self.manifest.sources.len() {
            Ok(())
        } else {
            Err(EgressHaPromotionError::EvidenceOrder)
        }
    }

    fn require_old_owner_fenced(&self) -> Result<(), EgressHaPromotionError> {
        self.require_sources_fenced()?;
        if self.old_owner_fence.is_some() {
            Ok(())
        } else {
            Err(EgressHaPromotionError::EvidenceOrder)
        }
    }

    fn acquisitions_complete(&self) -> bool {
        let expected = self
            .manifest
            .handoffs
            .iter()
            .map(|handoff| handoff.new_gateway.clone())
            .collect::<BTreeSet<_>>();
        self.acquisitions.keys().cloned().collect::<BTreeSet<_>>() == expected
    }
}

impl EgressHaActivationAuthority {
    /// Replays every embedded promotion witness and the outer seal.
    ///
    /// # Errors
    ///
    /// Rejects missing, reordered, stale, foreign, or mutated evidence.
    pub fn verify(&self) -> Result<(), EgressHaPromotionError> {
        let expected_gateways = self
            .manifest
            .handoffs
            .iter()
            .map(|handoff| handoff.new_gateway.clone())
            .collect::<BTreeSet<_>>();
        if self.schema_version != EGRESS_HA_PROMOTION_SCHEMA_VERSION
            || self.manifest.schema_version != EGRESS_HA_PROMOTION_SCHEMA_VERSION
            || self.source_fences.len() != self.manifest.sources.len()
            || self.acquisitions.len() != expected_gateways.len()
            || self
                .acquisitions
                .windows(2)
                .any(|pair| pair[0].gateway >= pair[1].gateway)
            || self
                .acquisitions
                .iter()
                .map(|item| item.gateway.clone())
                .collect::<BTreeSet<_>>()
                != expected_gateways
        {
            return Err(EgressHaPromotionError::EvidenceMismatch);
        }
        let expected_shards = self
            .manifest
            .handoffs
            .iter()
            .map(|handoff| handoff.shard_index)
            .collect::<Vec<_>>();
        for (source, fence) in self.manifest.sources.iter().zip(&self.source_fences) {
            if fence.schema_version != EGRESS_HA_PROMOTION_SCHEMA_VERSION
                || fence.controller_epoch != self.manifest.controller_epoch
                || fence.promotion_epoch != self.manifest.promotion_epoch
                || fence.recipient != *source
                || fence.manifest_digest != self.manifest.manifest_digest
                || fence.active_plan_digest != self.manifest.active_plan_digest
                || fence.fenced_shards != expected_shards
                || fence.inactive_bank > 1
            {
                return Err(EgressHaPromotionError::EvidenceMismatch);
            }
        }
        verify_old_owner_fence(&self.manifest, &self.old_owner_fence)?;
        for acquisition in &self.acquisitions {
            if acquisition.schema_version != EGRESS_HA_PROMOTION_SCHEMA_VERSION
                || acquisition.controller_epoch != self.manifest.controller_epoch
                || acquisition.promotion_epoch != self.manifest.promotion_epoch
                || acquisition.manifest_digest != self.manifest.manifest_digest
                || acquisition.owned_addresses
                    != addresses_for_new_gateway(&self.manifest, &acquisition.gateway)
                || acquisition.kernel_revision == Revision::INITIAL
            {
                return Err(EgressHaPromotionError::EvidenceMismatch);
            }
        }
        if self.reachability.schema_version != EGRESS_HA_PROMOTION_SCHEMA_VERSION
            || self.reachability.controller_epoch != self.manifest.controller_epoch
            || self.reachability.promotion_epoch != self.manifest.promotion_epoch
            || self.reachability.manifest_digest != self.manifest.manifest_digest
            || self.reachability.expected_plan_digest != self.manifest.active_plan_digest
            || self.reachability.installed_plan_digest != self.manifest.contingency_digest
            || self.reachability.handoffs != self.manifest.handoffs
            || !self.reachability.compare_and_swap_applied
        {
            return Err(EgressHaPromotionError::EvidenceMismatch);
        }
        let expected = digest(&(
            self.schema_version,
            &self.manifest,
            &self.source_fences,
            &self.old_owner_fence,
            &self.acquisitions,
            &self.reachability,
        ))?;
        if expected != self.authority_digest {
            return Err(EgressHaPromotionError::EvidenceMismatch);
        }
        Ok(())
    }
}

fn handoffs(
    plan: &EgressHaPlan,
    contingency: &EgressHaContingency,
) -> Result<Vec<EgressHaShardHandoff>, EgressHaPromotionError> {
    let active = assignments_by_shard(&plan.assignments)?;
    let next = assignments_by_shard(&contingency.assignments)?;
    let shards = plan
        .shards
        .iter()
        .map(|shard| (shard.index, shard.addresses.clone()))
        .collect::<BTreeMap<_, _>>();
    let mut result = Vec::new();
    for (shard_index, old_gateway) in active {
        let new_gateway = next
            .get(&shard_index)
            .ok_or(EgressHaPromotionError::ContingencyMismatch)?;
        if old_gateway != *new_gateway {
            if old_gateway != contingency.failed_gateway {
                return Err(EgressHaPromotionError::ContingencyMismatch);
            }
            result.push(EgressHaShardHandoff {
                shard_index,
                addresses: shards
                    .get(&shard_index)
                    .cloned()
                    .ok_or(EgressHaPromotionError::ContingencyMismatch)?,
                old_gateway,
                new_gateway: new_gateway.clone(),
            });
        }
    }
    Ok(result)
}

fn assignments_by_shard(
    assignments: &[EgressHaAssignment],
) -> Result<BTreeMap<u16, EgressNode>, EgressHaPromotionError> {
    let result = assignments
        .iter()
        .map(|item| (item.shard_index, item.gateway.clone()))
        .collect::<BTreeMap<_, _>>();
    if result.len() == assignments.len() {
        Ok(result)
    } else {
        Err(EgressHaPromotionError::ContingencyMismatch)
    }
}

fn verify_old_owner_fence(
    manifest: &EgressHaPromotionManifest,
    evidence: &EgressHaOldOwnerFenceEvidence,
) -> Result<(), EgressHaPromotionError> {
    match evidence {
        EgressHaOldOwnerFenceEvidence::Revocation(evidence) => {
            if evidence.schema_version != EGRESS_HA_PROMOTION_SCHEMA_VERSION
                || evidence.controller_epoch != manifest.controller_epoch
                || evidence.promotion_epoch != manifest.promotion_epoch
                || evidence.gateway != manifest.failed_gateway
                || evidence.manifest_digest != manifest.manifest_digest
                || evidence.absent_addresses != affected_addresses(manifest)
                || evidence.kernel_revision == Revision::INITIAL
            {
                return Err(EgressHaPromotionError::EvidenceMismatch);
            }
        }
        EgressHaOldOwnerFenceEvidence::Infrastructure(evidence) => {
            let provider = evidence.provider.to_ascii_lowercase();
            if provider.contains("kubernetes")
                || provider.contains("node-ready")
                || provider.contains("node-lease")
                || evidence.schema_version != EGRESS_HA_PROMOTION_SCHEMA_VERSION
                || evidence.controller_epoch != manifest.controller_epoch
                || evidence.promotion_epoch != manifest.promotion_epoch
                || evidence.gateway != manifest.failed_gateway
                || evidence.manifest_digest != manifest.manifest_digest
                || evidence.provider.is_empty()
                || evidence.fence_token.is_empty()
                || evidence.provider_revision == 0
                || !evidence.isolated
            {
                return Err(EgressHaPromotionError::EvidenceMismatch);
            }
        }
    }
    Ok(())
}

fn affected_addresses(manifest: &EgressHaPromotionManifest) -> Vec<IpAddr> {
    manifest
        .handoffs
        .iter()
        .flat_map(|handoff| handoff.addresses.iter().copied())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn addresses_for_new_gateway(
    manifest: &EgressHaPromotionManifest,
    gateway: &EgressNode,
) -> Vec<IpAddr> {
    manifest
        .handoffs
        .iter()
        .filter(|handoff| handoff.new_gateway == *gateway)
        .flat_map(|handoff| handoff.addresses.iter().copied())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn promotion_manifest_digest(
    manifest: &EgressHaPromotionManifest,
) -> Result<EgressHaPromotionDigest, EgressHaPromotionError> {
    digest(&(
        manifest.schema_version,
        manifest.controller_epoch,
        manifest.promotion_epoch,
        manifest.authority_revision,
        &manifest.owner,
        manifest.allocation_revision,
        manifest.lease_epoch,
        manifest.active_plan_revision,
        manifest.active_plan_digest,
        manifest.contingency_digest,
        &manifest.failed_gateway,
        &manifest.handoffs,
        &manifest.sources,
    ))
}

fn digest<T: Serialize>(value: &T) -> Result<EgressHaPromotionDigest, EgressHaPromotionError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| EgressHaPromotionError::Encoding(error.to_string()))?;
    let mut hasher = Sha256::new();
    hasher.update(b"unf.egress-ha-proof-carrying-promotion.v1\0");
    hasher.update(bytes);
    Ok(EgressHaPromotionDigest(hasher.finalize().into()))
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use super::*;
    use crate::{
        AddressFamily, DEFAULT_EGRESS_INTENT_PRIORITY, EgressAddressLease, EgressAddressRequest,
        EgressCapability, EgressDestinations, EgressHaCandidate, EgressIntent, EgressIntentScope,
        EgressProviderRef, EgressSourceSelector, compile_egress_ha_plan,
    };

    fn plan() -> EgressHaPlan {
        let owner = EgressIntentOwner {
            scope: EgressIntentScope::Cluster,
            name: "payments".to_owned(),
            uid: "uid-payments".to_owned(),
        };
        let lease = EgressAddressLease {
            intent: EgressIntent {
                owner,
                priority: DEFAULT_EGRESS_INTENT_PRIORITY,
                source: EgressSourceSelector::default(),
                destinations: EgressDestinations::Any,
                addresses: EgressAddressRequest::Pool {
                    name: "public".to_owned(),
                    families: vec![AddressFamily::Ipv4, AddressFamily::Ipv6],
                    addresses_per_family: 4,
                },
            },
            pool: None,
            provider: EgressProviderRef {
                name: "static".to_owned(),
                instance: "lab".to_owned(),
            },
            addresses: vec![
                "192.0.2.20".parse().unwrap(),
                "192.0.2.21".parse().unwrap(),
                "192.0.2.22".parse().unwrap(),
                "192.0.2.23".parse().unwrap(),
                "2001:db8::20".parse().unwrap(),
                "2001:db8::21".parse().unwrap(),
                "2001:db8::22".parse().unwrap(),
                "2001:db8::23".parse().unwrap(),
            ],
            lease_epoch: 7,
            intent_epoch: 1,
            intent_revision: Revision::new(2),
            allocation_revision: Revision::new(3),
        };
        let candidates = ["a", "b", "c"]
            .into_iter()
            .map(|name| EgressHaCandidate {
                node: EgressNode {
                    name: format!("gateway-{name}"),
                    uid: format!("uid-{name}"),
                    capabilities: BTreeSet::from([
                        EgressCapability::LeaseEpochFencing,
                        EgressCapability::Ipv4TcpUdpNat,
                        EgressCapability::Ipv6TcpUdpNat,
                    ]),
                },
                capacity_units: 1,
                failure_domains: BTreeMap::from([(
                    "topology.kubernetes.io/zone".to_owned(),
                    format!("zone-{name}"),
                )]),
            })
            .collect();
        compile_egress_ha_plan(&lease, candidates, None, Revision::new(9)).unwrap()
    }

    fn sources() -> Vec<EgressProjectionRecipient> {
        vec![
            EgressProjectionRecipient {
                node_name: "worker-a".to_owned(),
                node_uid: "worker-uid-a".to_owned(),
            },
            EgressProjectionRecipient {
                node_name: "worker-b".to_owned(),
                node_uid: "worker-uid-b".to_owned(),
            },
        ]
    }

    fn manifest(plan: &EgressHaPlan) -> EgressHaPromotionManifest {
        let failed = plan.assignments.first().unwrap().gateway.uid.clone();
        EgressHaPromotionManifest::issue(plan, &failed, sources(), 41, 12, Revision::new(19))
            .unwrap()
    }

    fn source_evidence(
        manifest: &EgressHaPromotionManifest,
        recipient: EgressProjectionRecipient,
    ) -> EgressHaSourceFenceEvidence {
        EgressHaSourceFenceEvidence {
            schema_version: EGRESS_HA_PROMOTION_SCHEMA_VERSION,
            controller_epoch: manifest.controller_epoch,
            promotion_epoch: manifest.promotion_epoch,
            recipient,
            manifest_digest: manifest.manifest_digest,
            active_plan_digest: manifest.active_plan_digest,
            fenced_shards: manifest
                .handoffs
                .iter()
                .map(|item| item.shard_index)
                .collect(),
            inactive_bank: 1,
        }
    }

    fn fence_sources(coordinator: &mut EgressHaPromotionCoordinator) {
        let manifest = coordinator.manifest().clone();
        for source in &manifest.sources {
            coordinator
                .admit_source_fence(source_evidence(&manifest, source.clone()))
                .unwrap();
        }
    }

    fn independent_fence(
        manifest: &EgressHaPromotionManifest,
    ) -> EgressHaInfrastructureFenceEvidence {
        EgressHaInfrastructureFenceEvidence {
            schema_version: EGRESS_HA_PROMOTION_SCHEMA_VERSION,
            controller_epoch: manifest.controller_epoch,
            promotion_epoch: manifest.promotion_epoch,
            gateway: manifest.failed_gateway.clone(),
            manifest_digest: manifest.manifest_digest,
            provider: "redfish-bmc".to_owned(),
            fence_token: "power-off-operation-991".to_owned(),
            provider_revision: 991,
            isolated: true,
        }
    }

    fn finish(mut coordinator: EgressHaPromotionCoordinator) -> EgressHaActivationAuthority {
        let manifest = coordinator.manifest().clone();
        let gateways = manifest
            .handoffs
            .iter()
            .map(|item| item.new_gateway.clone())
            .collect::<BTreeSet<_>>();
        for gateway in gateways {
            coordinator
                .admit_gateway_acquisition(EgressHaGatewayAcquisitionEvidence {
                    schema_version: EGRESS_HA_PROMOTION_SCHEMA_VERSION,
                    controller_epoch: manifest.controller_epoch,
                    promotion_epoch: manifest.promotion_epoch,
                    gateway: gateway.clone(),
                    manifest_digest: manifest.manifest_digest,
                    owned_addresses: addresses_for_new_gateway(&manifest, &gateway),
                    kernel_revision: Revision::new(25),
                })
                .unwrap();
        }
        coordinator
            .admit_reachability_handoff(EgressHaReachabilityHandoffEvidence {
                schema_version: EGRESS_HA_PROMOTION_SCHEMA_VERSION,
                controller_epoch: manifest.controller_epoch,
                promotion_epoch: manifest.promotion_epoch,
                manifest_digest: manifest.manifest_digest,
                expected_plan_digest: manifest.active_plan_digest,
                installed_plan_digest: manifest.contingency_digest,
                handoffs: manifest.handoffs.clone(),
                provider: "static-l2-cas".to_owned(),
                provider_revision: 72,
                compare_and_swap_applied: true,
            })
            .unwrap();
        coordinator.activation_authority().unwrap()
    }

    #[test]
    fn graceful_promotion_requires_source_fence_before_exact_revocation() {
        let plan = plan();
        let manifest = manifest(&plan);
        manifest.verify(&plan).unwrap();
        let mut coordinator = EgressHaPromotionCoordinator::new(manifest.clone());
        let revocation = EgressHaOldOwnerRevocationEvidence {
            schema_version: EGRESS_HA_PROMOTION_SCHEMA_VERSION,
            controller_epoch: manifest.controller_epoch,
            promotion_epoch: manifest.promotion_epoch,
            gateway: manifest.failed_gateway.clone(),
            manifest_digest: manifest.manifest_digest,
            absent_addresses: affected_addresses(&manifest),
            kernel_revision: Revision::new(20),
        };
        assert_eq!(
            coordinator.admit_old_owner_revocation(revocation.clone()),
            Err(EgressHaPromotionError::EvidenceOrder)
        );
        fence_sources(&mut coordinator);
        coordinator.admit_old_owner_revocation(revocation).unwrap();
        let authority = finish(coordinator);
        authority.verify().unwrap();
    }

    #[test]
    fn abrupt_failure_accepts_independent_fence_but_never_kubernetes_health() {
        let plan = plan();
        let manifest = manifest(&plan);
        let mut coordinator = EgressHaPromotionCoordinator::new(manifest.clone());
        fence_sources(&mut coordinator);
        let mut unsafe_evidence = independent_fence(&manifest);
        unsafe_evidence.provider = "kubernetes-node-ready".to_owned();
        assert_eq!(
            coordinator.admit_infrastructure_fence(unsafe_evidence),
            Err(EgressHaPromotionError::UnsafeFenceProvider)
        );
        coordinator
            .admit_infrastructure_fence(independent_fence(&manifest))
            .unwrap();
        finish(coordinator).verify().unwrap();
    }

    #[test]
    fn partial_source_fence_and_early_acquisition_fail_closed() {
        let plan = plan();
        let manifest = manifest(&plan);
        let mut coordinator = EgressHaPromotionCoordinator::new(manifest.clone());
        coordinator
            .admit_source_fence(source_evidence(&manifest, manifest.sources[0].clone()))
            .unwrap();
        assert_eq!(coordinator.phase(), EgressHaPromotionPhase::FencingSources);
        assert_eq!(
            coordinator.admit_infrastructure_fence(independent_fence(&manifest)),
            Err(EgressHaPromotionError::EvidenceOrder)
        );
    }

    #[test]
    fn stale_epoch_and_mutated_address_readback_are_rejected() {
        let plan = plan();
        let manifest = manifest(&plan);
        let mut coordinator = EgressHaPromotionCoordinator::new(manifest.clone());
        let mut stale = source_evidence(&manifest, manifest.sources[0].clone());
        stale.promotion_epoch -= 1;
        assert_eq!(
            coordinator.admit_source_fence(stale),
            Err(EgressHaPromotionError::EvidenceMismatch)
        );
        fence_sources(&mut coordinator);
        coordinator
            .admit_infrastructure_fence(independent_fence(&manifest))
            .unwrap();
        let gateway = manifest.handoffs[0].new_gateway.clone();
        let mut addresses = addresses_for_new_gateway(&manifest, &gateway);
        addresses.pop();
        assert_eq!(
            coordinator.admit_gateway_acquisition(EgressHaGatewayAcquisitionEvidence {
                schema_version: EGRESS_HA_PROMOTION_SCHEMA_VERSION,
                controller_epoch: manifest.controller_epoch,
                promotion_epoch: manifest.promotion_epoch,
                gateway,
                manifest_digest: manifest.manifest_digest,
                owned_addresses: addresses,
                kernel_revision: Revision::new(2),
            }),
            Err(EgressHaPromotionError::EvidenceMismatch)
        );
    }

    #[test]
    fn authority_mutation_cannot_be_hidden_by_recomputing_outer_digest() {
        let plan = plan();
        let manifest = manifest(&plan);
        let mut coordinator = EgressHaPromotionCoordinator::new(manifest.clone());
        fence_sources(&mut coordinator);
        coordinator
            .admit_infrastructure_fence(independent_fence(&manifest))
            .unwrap();
        let mut authority = finish(coordinator);
        authority.acquisitions[0].owned_addresses.pop();
        authority.authority_digest = digest(&(
            authority.schema_version,
            &authority.manifest,
            &authority.source_fences,
            &authority.old_owner_fence,
            &authority.acquisitions,
            &authority.reachability,
        ))
        .unwrap();
        assert_eq!(
            authority.verify(),
            Err(EgressHaPromotionError::EvidenceMismatch)
        );
    }
}
