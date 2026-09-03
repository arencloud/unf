//! Explicit, independently replayable authority for safe egress-state release.

use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use unf_common::{IdentityId, Revision};

use crate::{
    AdmittedEgressProjection, EgressContractDigest, EgressGatewayAction, EgressGatewayDesired,
    EgressIntentOwner, EgressNodeProjection, EgressProjectionRecipient, EgressProviderOutcome,
    EgressReachabilityAcknowledgement, MAX_EGRESS_CONTRACT_PLANS, MAX_EGRESS_GATEWAY_NODES,
};

pub const EGRESS_SAFE_FORGETTING_SCHEMA_VERSION: u16 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EgressRetirementDigest(pub [u8; 32]);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EgressRetiringSource {
    pub recipient: EgressProjectionRecipient,
    pub source_identity: IdentityId,
    pub contract_revision: Revision,
    pub contract_digest: EgressContractDigest,
}

impl Ord for EgressRetiringSource {
    fn cmp(&self, other: &Self) -> Ordering {
        (
            &self.recipient,
            self.source_identity,
            self.contract_revision,
            self.contract_digest.0,
        )
            .cmp(&(
                &other.recipient,
                other.source_identity,
                other.contract_revision,
                other.contract_digest.0,
            ))
    }
}

impl PartialOrd for EgressRetiringSource {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Controller snapshot of the exact source and gateway set that must forget a
/// lease before its address can be reused. An empty source set is explicit and
/// sealed rather than inferred from missing runtime state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EgressRetirementManifest {
    pub schema_version: u16,
    pub desired_revision: Revision,
    pub allocation_revision: Revision,
    pub owner: EgressIntentOwner,
    pub lease_epoch: u64,
    pub addresses: Vec<IpAddr>,
    pub sources: Vec<EgressRetiringSource>,
    pub gateways: Vec<EgressProjectionRecipient>,
    pub manifest_digest: EgressRetirementDigest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EgressSourceFenceEvidence {
    pub schema_version: u16,
    pub controller_epoch: u64,
    pub projection_revision: Revision,
    pub recipient: EgressProjectionRecipient,
    pub active_bank: u8,
    pub sources: Vec<EgressRetiringSource>,
    pub evidence_digest: EgressRetirementDigest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EgressSourceRetirementChallenges {
    pub schema_version: u16,
    pub controller_epoch: u64,
    pub manifests: Vec<EgressRetirementManifest>,
}

impl EgressSourceRetirementChallenges {
    /// Builds a bounded canonical challenge set for one authenticated source.
    ///
    /// # Errors
    ///
    /// Rejects zero epoch, malformed manifests, duplicates, or excess state.
    pub fn issue(
        controller_epoch: u64,
        manifests: Vec<EgressRetirementManifest>,
    ) -> Result<Self, EgressSafeForgettingError> {
        let challenges = Self {
            schema_version: EGRESS_SAFE_FORGETTING_SCHEMA_VERSION,
            controller_epoch,
            manifests,
        };
        challenges.verify()?;
        Ok(challenges)
    }

    /// Validates the self-contained challenge set.
    ///
    /// # Errors
    ///
    /// Rejects zero epoch, malformed manifests, duplicates, or excess state.
    pub fn verify(&self) -> Result<(), EgressSafeForgettingError> {
        if self.schema_version != EGRESS_SAFE_FORGETTING_SCHEMA_VERSION
            || self.controller_epoch == 0
            || self.manifests.len() > crate::MAX_EGRESS_INTENTS
            || self
                .manifests
                .windows(2)
                .any(|pair| pair[0].owner >= pair[1].owner)
        {
            return Err(EgressSafeForgettingError::EvidenceMismatch);
        }
        for manifest in &self.manifests {
            manifest.verify_seal()?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EgressGatewayDrainEvidence {
    pub schema_version: u16,
    pub desired_revision: Revision,
    pub allocation_revision: Revision,
    pub owner: EgressIntentOwner,
    pub lease_epoch: u64,
    pub recipient: EgressProjectionRecipient,
    pub addresses: Vec<IpAddr>,
    pub active_connections: u32,
    pub withdrawal_applied: bool,
    pub evidence_digest: EgressRetirementDigest,
}

/// Capability-style release token. Possession is insufficient: every field and
/// nested evidence record is replayed against the retained Withdraw record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EgressSafeReleaseAuthority {
    pub schema_version: u16,
    pub controller_epoch: u64,
    pub authority_revision: Revision,
    pub manifest: EgressRetirementManifest,
    pub source_fences: Vec<EgressSourceFenceEvidence>,
    pub gateway_drains: Vec<EgressGatewayDrainEvidence>,
    pub reachability: EgressReachabilityAcknowledgement,
    pub authority_digest: EgressRetirementDigest,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum EgressSafeForgettingError {
    #[error("safe-forgetting input is not exact canonical withdrawal state")]
    InvalidWithdrawal,
    #[error("retirement source set is duplicated, incomplete, or foreign")]
    InvalidSources,
    #[error("retirement gateway set is duplicated, incomplete, or foreign")]
    InvalidGateways,
    #[error("safe-forgetting evidence is malformed or does not match the retained lease")]
    EvidenceMismatch,
    #[error("safe-forgetting digest does not match its content")]
    DigestMismatch,
}

impl EgressRetirementManifest {
    /// Captures the exact admitted sources that reference one retained lease.
    ///
    /// # Errors
    ///
    /// Rejects non-Withdraw state, duplicate sources, or excessive bounds.
    pub fn issue(
        desired: &EgressGatewayDesired,
        admitted_sources: &[AdmittedEgressProjection],
    ) -> Result<Self, EgressSafeForgettingError> {
        validate_withdrawal(desired)?;
        let mut sources = admitted_sources
            .iter()
            .flat_map(|admitted| {
                let projection = admitted.projection();
                projection
                    .contract
                    .plans
                    .iter()
                    .filter(move |plan| {
                        plan.intent == desired.owner
                            && plan.allocation.lease_epoch == desired.lease_epoch
                    })
                    .map(|plan| EgressRetiringSource {
                        recipient: projection.recipient.clone(),
                        source_identity: plan.source.identity,
                        contract_revision: projection.contract.contract_revision,
                        contract_digest: projection.contract.contract_digest,
                    })
            })
            .collect::<Vec<_>>();
        sources.sort();
        if sources.len() > MAX_EGRESS_CONTRACT_PLANS
            || sources.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(EgressSafeForgettingError::InvalidSources);
        }
        let gateways = desired
            .nodes
            .iter()
            .map(|node| EgressProjectionRecipient {
                node_name: node.name.clone(),
                node_uid: node.uid.clone(),
            })
            .collect::<Vec<_>>();
        let mut manifest = Self {
            schema_version: EGRESS_SAFE_FORGETTING_SCHEMA_VERSION,
            desired_revision: desired.revision,
            allocation_revision: desired.allocation_revision,
            owner: desired.owner.clone(),
            lease_epoch: desired.lease_epoch,
            addresses: desired.addresses.clone(),
            sources,
            gateways,
            manifest_digest: EgressRetirementDigest([0; 32]),
        };
        manifest.validate(desired)?;
        manifest.manifest_digest = manifest.digest()?;
        Ok(manifest)
    }

    /// Replays the manifest against retained withdrawal state.
    ///
    /// # Errors
    ///
    /// Rejects any malformed, foreign, noncanonical, or mutated manifest.
    pub fn verify(&self, desired: &EgressGatewayDesired) -> Result<(), EgressSafeForgettingError> {
        self.validate(desired)?;
        if self.manifest_digest != self.digest()? {
            return Err(EgressSafeForgettingError::DigestMismatch);
        }
        Ok(())
    }

    /// Verifies the self-contained canonical shape and digest received by an
    /// agent before it uses the manifest as a retirement challenge.
    ///
    /// # Errors
    ///
    /// Rejects malformed, noncanonical, oversized, or digest-mutated state.
    pub fn verify_seal(&self) -> Result<(), EgressSafeForgettingError> {
        if self.schema_version != EGRESS_SAFE_FORGETTING_SCHEMA_VERSION
            || self.desired_revision == Revision::INITIAL
            || self.allocation_revision == Revision::INITIAL
            || self.owner.name.is_empty()
            || self.owner.uid.is_empty()
            || self.lease_epoch == 0
            || self.addresses.is_empty()
            || self.addresses.windows(2).any(|pair| pair[0] >= pair[1])
            || self.sources.len() > MAX_EGRESS_CONTRACT_PLANS
            || self.sources.windows(2).any(|pair| pair[0] >= pair[1])
            || self
                .sources
                .iter()
                .any(|source| source.source_identity.get() == 0)
            || self.gateways.is_empty()
            || self.gateways.len() > MAX_EGRESS_GATEWAY_NODES
            || self.gateways.windows(2).any(|pair| pair[0] >= pair[1])
            || self.manifest_digest != self.digest()?
        {
            return Err(EgressSafeForgettingError::DigestMismatch);
        }
        Ok(())
    }

    fn validate(&self, desired: &EgressGatewayDesired) -> Result<(), EgressSafeForgettingError> {
        validate_withdrawal(desired)?;
        let expected_gateways = desired
            .nodes
            .iter()
            .map(|node| EgressProjectionRecipient {
                node_name: node.name.clone(),
                node_uid: node.uid.clone(),
            })
            .collect::<Vec<_>>();
        if self.schema_version != EGRESS_SAFE_FORGETTING_SCHEMA_VERSION
            || self.desired_revision != desired.revision
            || self.allocation_revision != desired.allocation_revision
            || self.owner != desired.owner
            || self.lease_epoch != desired.lease_epoch
            || self.addresses != desired.addresses
            || self.gateways != expected_gateways
            || self.gateways.len() > MAX_EGRESS_GATEWAY_NODES
            || self.gateways.windows(2).any(|pair| pair[0] >= pair[1])
            || self.sources.len() > MAX_EGRESS_CONTRACT_PLANS
            || self.sources.windows(2).any(|pair| pair[0] >= pair[1])
            || self
                .sources
                .iter()
                .any(|source| source.source_identity.get() == 0)
        {
            return Err(EgressSafeForgettingError::InvalidWithdrawal);
        }
        Ok(())
    }

    fn digest(&self) -> Result<EgressRetirementDigest, EgressSafeForgettingError> {
        seal(
            b"unf.egress-retirement-manifest.v1\0",
            &(
                self.schema_version,
                self.desired_revision,
                self.allocation_revision,
                &self.owner,
                self.lease_epoch,
                &self.addresses,
                &self.sources,
                &self.gateways,
            ),
        )
    }
}

impl EgressSourceFenceEvidence {
    /// Derives evidence from the exact previously admitted source projection.
    /// The caller supplies the bank only after reading back every entry as
    /// destination-preserving `Fenced` state.
    ///
    /// # Errors
    ///
    /// Rejects non-withdrawal state, an invalid bank, or no matching sources.
    pub fn issue(
        desired: &EgressGatewayDesired,
        admitted: &AdmittedEgressProjection,
        active_bank: u8,
    ) -> Result<Self, EgressSafeForgettingError> {
        validate_withdrawal(desired)?;
        Self::issue_for_owner(
            &desired.owner,
            desired.lease_epoch,
            admitted.projection(),
            active_bank,
            admitted.projection().controller_epoch,
        )
    }

    /// Derives evidence from a controller-retained retirement manifest.
    ///
    /// # Errors
    ///
    /// Rejects a mutated manifest, invalid bank, or no matching source.
    pub fn issue_for_manifest(
        manifest: &EgressRetirementManifest,
        projection: &EgressNodeProjection,
        active_bank: u8,
    ) -> Result<Self, EgressSafeForgettingError> {
        manifest.verify_seal()?;
        Self::issue_for_owner(
            &manifest.owner,
            manifest.lease_epoch,
            projection,
            active_bank,
            projection.controller_epoch,
        )
    }

    /// Derives evidence under the current authenticated controller epoch.
    ///
    /// # Errors
    ///
    /// Rejects a malformed challenge, invalid bank, or no matching source.
    pub fn issue_for_challenge(
        challenges: &EgressSourceRetirementChallenges,
        manifest: &EgressRetirementManifest,
        projection: &EgressNodeProjection,
        active_bank: u8,
    ) -> Result<Self, EgressSafeForgettingError> {
        challenges.verify()?;
        if !challenges.manifests.contains(manifest) {
            return Err(EgressSafeForgettingError::EvidenceMismatch);
        }
        Self::issue_for_owner(
            &manifest.owner,
            manifest.lease_epoch,
            projection,
            active_bank,
            challenges.controller_epoch,
        )
    }

    fn issue_for_owner(
        owner: &EgressIntentOwner,
        lease_epoch: u64,
        projection: &EgressNodeProjection,
        active_bank: u8,
        controller_epoch: u64,
    ) -> Result<Self, EgressSafeForgettingError> {
        if active_bank >= 2 {
            return Err(EgressSafeForgettingError::EvidenceMismatch);
        }
        let mut sources = projection
            .contract
            .plans
            .iter()
            .filter(|plan| &plan.intent == owner && plan.allocation.lease_epoch == lease_epoch)
            .map(|plan| EgressRetiringSource {
                recipient: projection.recipient.clone(),
                source_identity: plan.source.identity,
                contract_revision: projection.contract.contract_revision,
                contract_digest: projection.contract.contract_digest,
            })
            .collect::<Vec<_>>();
        sources.sort();
        let mut evidence = Self {
            schema_version: EGRESS_SAFE_FORGETTING_SCHEMA_VERSION,
            controller_epoch,
            projection_revision: projection.revision,
            recipient: projection.recipient.clone(),
            active_bank,
            sources,
            evidence_digest: EgressRetirementDigest([0; 32]),
        };
        evidence.validate()?;
        evidence.evidence_digest = evidence.digest()?;
        Ok(evidence)
    }

    /// Verifies the canonical source-fence evidence and its sealed content.
    ///
    /// # Errors
    ///
    /// Rejects malformed, duplicate, foreign, or digest-mutated evidence.
    pub fn verify(&self) -> Result<(), EgressSafeForgettingError> {
        self.validate()?;
        if self.evidence_digest != self.digest()? {
            return Err(EgressSafeForgettingError::DigestMismatch);
        }
        Ok(())
    }

    fn validate(&self) -> Result<(), EgressSafeForgettingError> {
        if self.schema_version != EGRESS_SAFE_FORGETTING_SCHEMA_VERSION
            || self.controller_epoch == 0
            || self.projection_revision == Revision::INITIAL
            || self.active_bank >= 2
            || self.sources.is_empty()
            || self.sources.len() > MAX_EGRESS_CONTRACT_PLANS
            || self.sources.windows(2).any(|pair| pair[0] >= pair[1])
            || self.sources.iter().any(|source| {
                source.recipient != self.recipient || source.source_identity.get() == 0
            })
        {
            return Err(EgressSafeForgettingError::EvidenceMismatch);
        }
        Ok(())
    }

    fn digest(&self) -> Result<EgressRetirementDigest, EgressSafeForgettingError> {
        seal(
            b"unf.egress-source-fence-evidence.v1\0",
            &(
                self.schema_version,
                self.controller_epoch,
                self.projection_revision,
                &self.recipient,
                self.active_bank,
                &self.sources,
            ),
        )
    }
}

impl EgressGatewayDrainEvidence {
    /// Builds a zero-flow witness after the gateway has applied an empty
    /// contract projection and scanned the persistent NAT LRU for this lease.
    ///
    /// # Errors
    ///
    /// Rejects non-withdrawal state, foreign recipients, retained connections,
    /// or missing explicit withdrawal application.
    pub fn issue(
        desired: &EgressGatewayDesired,
        recipient: EgressProjectionRecipient,
        active_connections: u32,
        withdrawal_applied: bool,
    ) -> Result<Self, EgressSafeForgettingError> {
        let mut evidence = Self {
            schema_version: EGRESS_SAFE_FORGETTING_SCHEMA_VERSION,
            desired_revision: desired.revision,
            allocation_revision: desired.allocation_revision,
            owner: desired.owner.clone(),
            lease_epoch: desired.lease_epoch,
            recipient,
            addresses: desired.addresses.clone(),
            active_connections,
            withdrawal_applied,
            evidence_digest: EgressRetirementDigest([0; 32]),
        };
        evidence.validate(desired)?;
        evidence.evidence_digest = evidence.digest()?;
        Ok(evidence)
    }

    /// Replays gateway-drain evidence against retained withdrawal state.
    ///
    /// # Errors
    ///
    /// Rejects malformed, foreign, nonzero-flow, or digest-mutated evidence.
    pub fn verify(&self, desired: &EgressGatewayDesired) -> Result<(), EgressSafeForgettingError> {
        self.validate(desired)?;
        if self.evidence_digest != self.digest()? {
            return Err(EgressSafeForgettingError::DigestMismatch);
        }
        Ok(())
    }

    fn validate(&self, desired: &EgressGatewayDesired) -> Result<(), EgressSafeForgettingError> {
        validate_withdrawal(desired)?;
        let expected = desired.nodes.iter().any(|node| {
            node.name == self.recipient.node_name && node.uid == self.recipient.node_uid
        });
        if self.schema_version != EGRESS_SAFE_FORGETTING_SCHEMA_VERSION
            || self.desired_revision != desired.revision
            || self.allocation_revision != desired.allocation_revision
            || self.owner != desired.owner
            || self.lease_epoch != desired.lease_epoch
            || self.addresses != desired.addresses
            || !expected
            || self.active_connections != 0
            || !self.withdrawal_applied
        {
            return Err(EgressSafeForgettingError::EvidenceMismatch);
        }
        Ok(())
    }

    fn digest(&self) -> Result<EgressRetirementDigest, EgressSafeForgettingError> {
        seal(
            b"unf.egress-gateway-drain-evidence.v1\0",
            &(
                self.schema_version,
                self.desired_revision,
                self.allocation_revision,
                &self.owner,
                self.lease_epoch,
                &self.recipient,
                &self.addresses,
                self.active_connections,
                self.withdrawal_applied,
            ),
        )
    }
}

impl EgressSafeReleaseAuthority {
    /// Joins every independent proof into one replayable release capability.
    ///
    /// # Errors
    ///
    /// Rejects incomplete, duplicate, foreign, stale, or mutated evidence.
    pub fn issue(
        controller_epoch: u64,
        authority_revision: Revision,
        desired: &EgressGatewayDesired,
        manifest: EgressRetirementManifest,
        mut source_fences: Vec<EgressSourceFenceEvidence>,
        mut gateway_drains: Vec<EgressGatewayDrainEvidence>,
        reachability: EgressReachabilityAcknowledgement,
    ) -> Result<Self, EgressSafeForgettingError> {
        source_fences.sort_by(|left, right| left.recipient.cmp(&right.recipient));
        gateway_drains.sort_by(|left, right| left.recipient.cmp(&right.recipient));
        let mut authority = Self {
            schema_version: EGRESS_SAFE_FORGETTING_SCHEMA_VERSION,
            controller_epoch,
            authority_revision,
            manifest,
            source_fences,
            gateway_drains,
            reachability,
            authority_digest: EgressRetirementDigest([0; 32]),
        };
        authority.validate(desired)?;
        authority.authority_digest = authority.digest()?;
        Ok(authority)
    }

    /// Replays the complete release authority against retained withdrawal.
    ///
    /// # Errors
    ///
    /// Rejects any incomplete, foreign, stale, or digest-mutated authority.
    pub fn verify(&self, desired: &EgressGatewayDesired) -> Result<(), EgressSafeForgettingError> {
        self.validate(desired)?;
        if self.authority_digest != self.digest()? {
            return Err(EgressSafeForgettingError::DigestMismatch);
        }
        Ok(())
    }

    fn validate(&self, desired: &EgressGatewayDesired) -> Result<(), EgressSafeForgettingError> {
        if self.schema_version != EGRESS_SAFE_FORGETTING_SCHEMA_VERSION
            || self.controller_epoch == 0
            || self.authority_revision == Revision::INITIAL
        {
            return Err(EgressSafeForgettingError::EvidenceMismatch);
        }
        self.manifest.verify(desired)?;
        if self
            .source_fences
            .windows(2)
            .any(|pair| pair[0].recipient >= pair[1].recipient)
            || self
                .gateway_drains
                .windows(2)
                .any(|pair| pair[0].recipient >= pair[1].recipient)
        {
            return Err(EgressSafeForgettingError::EvidenceMismatch);
        }
        let mut fenced = BTreeSet::new();
        for evidence in &self.source_fences {
            evidence.verify()?;
            if evidence.controller_epoch != self.controller_epoch {
                return Err(EgressSafeForgettingError::EvidenceMismatch);
            }
            if evidence
                .sources
                .iter()
                .any(|source| self.manifest.sources.binary_search(source).is_err())
            {
                return Err(EgressSafeForgettingError::InvalidSources);
            }
            fenced.extend(evidence.sources.iter().cloned());
        }
        if fenced.into_iter().collect::<Vec<_>>() != self.manifest.sources {
            return Err(EgressSafeForgettingError::InvalidSources);
        }
        for evidence in &self.gateway_drains {
            evidence.verify(desired)?;
        }
        let drained = self
            .gateway_drains
            .iter()
            .map(|evidence| evidence.recipient.clone())
            .collect::<Vec<_>>();
        if drained != self.manifest.gateways {
            return Err(EgressSafeForgettingError::InvalidGateways);
        }
        if self.reachability.schema_version != crate::EGRESS_GATEWAY_ACK_SCHEMA_VERSION
            || self.reachability.desired_revision != desired.revision
            || self.reachability.allocation_revision != desired.allocation_revision
            || self.reachability.owner != desired.owner
            || self.reachability.provider != desired.provider
            || self.reachability.lease_epoch != desired.lease_epoch
            || self.reachability.addresses != desired.addresses
            || self.reachability.outcome != EgressProviderOutcome::Withdrawn
            || self.reachability.error.is_some()
            || self.reachability.revision == Revision::INITIAL
        {
            return Err(EgressSafeForgettingError::EvidenceMismatch);
        }
        Ok(())
    }

    fn digest(&self) -> Result<EgressRetirementDigest, EgressSafeForgettingError> {
        seal(
            b"unf.egress-safe-forgetting-authority.v1\0",
            &(
                self.schema_version,
                self.controller_epoch,
                self.authority_revision,
                &self.manifest,
                &self.source_fences,
                &self.gateway_drains,
                &self.reachability,
            ),
        )
    }
}

fn validate_withdrawal(desired: &EgressGatewayDesired) -> Result<(), EgressSafeForgettingError> {
    if desired.action != EgressGatewayAction::Withdraw
        || desired.revision == Revision::INITIAL
        || desired.allocation_revision == Revision::INITIAL
        || desired.lease_epoch == 0
        || desired.addresses.is_empty()
        || desired.nodes.is_empty()
    {
        return Err(EgressSafeForgettingError::InvalidWithdrawal);
    }
    Ok(())
}

fn seal<T: Serialize>(
    domain: &[u8],
    value: &T,
) -> Result<EgressRetirementDigest, EgressSafeForgettingError> {
    let material =
        serde_json::to_vec(value).map_err(|_| EgressSafeForgettingError::DigestMismatch)?;
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(material);
    Ok(EgressRetirementDigest(hasher.finalize().into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::distribution::test_support::admitted;

    fn withdrawal() -> (EgressGatewayDesired, AdmittedEgressProjection) {
        let admitted = admitted(30);
        let plan = &admitted.projection().contract.plans[0];
        let desired = EgressGatewayDesired {
            schema_version: crate::EGRESS_GATEWAY_DESIRED_SCHEMA_VERSION,
            revision: Revision::new(40),
            allocation_revision: plan.revisions.allocation,
            owner: plan.intent.clone(),
            provider: plan
                .allocation
                .pool
                .as_ref()
                .expect("pooled fixture")
                .provider
                .clone(),
            lease_epoch: plan.allocation.lease_epoch,
            action: EgressGatewayAction::Withdraw,
            addresses: plan.allocation.addresses.clone(),
            nodes: plan
                .gateways
                .iter()
                .map(|gateway| gateway.node.clone())
                .collect(),
        };
        (desired, admitted)
    }

    fn reachability(desired: &EgressGatewayDesired) -> EgressReachabilityAcknowledgement {
        EgressReachabilityAcknowledgement {
            schema_version: crate::EGRESS_GATEWAY_ACK_SCHEMA_VERSION,
            revision: Revision::new(41),
            desired_revision: desired.revision,
            allocation_revision: desired.allocation_revision,
            owner: desired.owner.clone(),
            provider: desired.provider.clone(),
            lease_epoch: desired.lease_epoch,
            outcome: EgressProviderOutcome::Withdrawn,
            addresses: desired.addresses.clone(),
            error: None,
        }
    }

    #[test]
    fn exact_source_gateway_and_reachability_union_authorizes_release() {
        let (desired, admitted) = withdrawal();
        let manifest = EgressRetirementManifest::issue(&desired, std::slice::from_ref(&admitted))
            .expect("seal exact retirement set");
        let fence = EgressSourceFenceEvidence::issue(&desired, &admitted, 1)
            .expect("source is fenced in read-back bank");
        let gateway = EgressGatewayDrainEvidence::issue(
            &desired,
            EgressProjectionRecipient {
                node_name: desired.nodes[0].name.clone(),
                node_uid: desired.nodes[0].uid.clone(),
            },
            0,
            true,
        )
        .expect("gateway is withdrawn and drained");
        EgressSafeReleaseAuthority::issue(
            10,
            Revision::new(42),
            &desired,
            manifest,
            vec![fence],
            vec![gateway],
            reachability(&desired),
        )
        .expect("all independent proofs form authority");
    }

    #[test]
    fn missing_foreign_or_mutated_evidence_fails_closed() {
        let (desired, admitted) = withdrawal();
        let manifest = EgressRetirementManifest::issue(&desired, std::slice::from_ref(&admitted))
            .expect("seal exact retirement set");
        let mut fence =
            EgressSourceFenceEvidence::issue(&desired, &admitted, 1).expect("source fence");
        let gateway = EgressGatewayDrainEvidence::issue(
            &desired,
            EgressProjectionRecipient {
                node_name: desired.nodes[0].name.clone(),
                node_uid: desired.nodes[0].uid.clone(),
            },
            0,
            true,
        )
        .expect("gateway drain");
        assert_eq!(
            EgressSafeReleaseAuthority::issue(
                10,
                Revision::new(42),
                &desired,
                manifest.clone(),
                Vec::new(),
                vec![gateway.clone()],
                reachability(&desired),
            ),
            Err(EgressSafeForgettingError::InvalidSources)
        );

        fence.evidence_digest.0[0] ^= 1;
        assert_eq!(
            EgressSafeReleaseAuthority::issue(
                10,
                Revision::new(42),
                &desired,
                manifest,
                vec![fence],
                vec![gateway],
                reachability(&desired),
            ),
            Err(EgressSafeForgettingError::DigestMismatch)
        );
    }

    #[test]
    fn duplicate_source_missing_gateway_and_epoch_skew_fail_closed() {
        let (desired, admitted) = withdrawal();
        assert_eq!(
            EgressRetirementManifest::issue(&desired, &[admitted.clone(), admitted.clone()]),
            Err(EgressSafeForgettingError::InvalidSources)
        );
        let manifest = EgressRetirementManifest::issue(&desired, std::slice::from_ref(&admitted))
            .expect("retirement manifest");
        let fence = EgressSourceFenceEvidence::issue(&desired, &admitted, 1).expect("source fence");
        assert_eq!(
            EgressSafeReleaseAuthority::issue(
                10,
                Revision::new(42),
                &desired,
                manifest.clone(),
                vec![fence.clone()],
                Vec::new(),
                reachability(&desired),
            ),
            Err(EgressSafeForgettingError::InvalidGateways)
        );
        let gateway = EgressGatewayDrainEvidence::issue(
            &desired,
            EgressProjectionRecipient {
                node_name: desired.nodes[0].name.clone(),
                node_uid: desired.nodes[0].uid.clone(),
            },
            0,
            true,
        )
        .expect("gateway drain");
        assert_eq!(
            EgressSafeReleaseAuthority::issue(
                11,
                Revision::new(42),
                &desired,
                manifest,
                vec![fence],
                vec![gateway],
                reachability(&desired),
            ),
            Err(EgressSafeForgettingError::EvidenceMismatch)
        );
    }
}
