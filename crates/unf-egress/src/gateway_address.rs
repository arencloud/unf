//! Exact-Node distribution for lease-fenced gateway address ownership.

use std::collections::BTreeSet;
use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use unf_common::Revision;

use crate::{
    AuthenticatedEgressAgent, EgressGatewayAction, EgressGatewayCheckpoint, EgressGatewayDesired,
    EgressGatewayRegistry, EgressProjectionRecipient, MAX_EGRESS_ADDRESSES_PER_INTENT,
    MAX_EGRESS_INTENTS,
};

pub const EGRESS_GATEWAY_ADDRESS_SCHEMA_VERSION: u16 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EgressGatewayAddressProjectionDigest(pub [u8; 32]);

/// Controller-issued exact lease set for one authenticated gateway Node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EgressGatewayAddressProjection {
    pub schema_version: u16,
    pub controller_epoch: u64,
    pub revision: Revision,
    pub recipient: EgressProjectionRecipient,
    pub leases: Vec<EgressGatewayDesired>,
    pub projection_digest: EgressGatewayAddressProjectionDigest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmittedEgressGatewayAddressProjection(EgressGatewayAddressProjection);

impl AdmittedEgressGatewayAddressProjection {
    #[must_use]
    pub const fn projection(&self) -> &EgressGatewayAddressProjection {
        &self.0
    }
}

/// Kernel readback evidence. `Ensure` leases must be applied; `Withdraw`
/// leases remain quarantined and allocator-fenced until a later release
/// authority proves all affected sources have installed their fence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EgressGatewayAddressAcknowledgement {
    pub schema_version: u16,
    pub controller_epoch: u64,
    pub projection_revision: Revision,
    pub recipient: EgressProjectionRecipient,
    pub projection_digest: EgressGatewayAddressProjectionDigest,
    pub interface_name: String,
    pub interface_index: u32,
    pub mtu: u32,
    pub owned_addresses: Vec<IpAddr>,
    pub applied_desired_revisions: Vec<Revision>,
    pub quarantined_desired_revisions: Vec<Revision>,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum EgressGatewayAddressError {
    #[error("invalid gateway-address authenticated principal")]
    InvalidPrincipal,
    #[error("gateway-address projection epoch/revision is invalid")]
    InvalidRevision,
    #[error("gateway-address projection recipient does not match the authenticated Node")]
    RecipientMismatch,
    #[error("gateway-address projection exceeds its bounded lease set")]
    TooManyLeases,
    #[error("gateway-address projection lease set is duplicated or noncanonical")]
    InvalidLeaseOrder,
    #[error("gateway-address projection contains a lease not assigned to its recipient")]
    LeaseNotAssigned,
    #[error("gateway-address projection digest does not match its content")]
    DigestMismatch,
    #[error("gateway-address acknowledgement does not prove the exact issued state")]
    AcknowledgementMismatch,
    #[error(transparent)]
    Gateway(#[from] crate::EgressGatewayError),
}

impl EgressGatewayAddressProjection {
    /// Filters a validated durable checkpoint to one exact Node and seals it.
    ///
    /// # Errors
    ///
    /// Rejects invalid durable state, identity, revision, or bounds.
    pub fn issue(
        principal: &AuthenticatedEgressAgent,
        controller_epoch: u64,
        checkpoint: EgressGatewayCheckpoint,
    ) -> Result<Self, EgressGatewayAddressError> {
        validate_principal(principal)?;
        EgressGatewayRegistry::restore(checkpoint.clone())?;
        if controller_epoch == 0 || checkpoint.revision == Revision::INITIAL {
            return Err(EgressGatewayAddressError::InvalidRevision);
        }
        let recipient = EgressProjectionRecipient {
            node_name: principal.node_name.clone(),
            node_uid: principal.node_uid.clone(),
        };
        let mut leases = checkpoint
            .records
            .into_iter()
            .map(|record| record.desired)
            .filter(|desired| {
                desired
                    .nodes
                    .iter()
                    .any(|node| node.name == recipient.node_name && node.uid == recipient.node_uid)
            })
            .collect::<Vec<_>>();
        leases.sort_by(|left, right| left.owner.cmp(&right.owner));
        let mut projection = Self {
            schema_version: EGRESS_GATEWAY_ADDRESS_SCHEMA_VERSION,
            controller_epoch,
            revision: checkpoint.revision,
            recipient,
            leases,
            projection_digest: EgressGatewayAddressProjectionDigest([0; 32]),
        };
        projection.validate_structure()?;
        projection.projection_digest = projection.digest()?;
        Ok(projection)
    }

    /// Rebinds wire state to the local authenticated Node before host mutation.
    ///
    /// # Errors
    ///
    /// Rejects identity, schema, lease assignment, ordering, or digest drift.
    pub fn admit(
        self,
        principal: &AuthenticatedEgressAgent,
    ) -> Result<AdmittedEgressGatewayAddressProjection, EgressGatewayAddressError> {
        validate_principal(principal)?;
        if self.schema_version != EGRESS_GATEWAY_ADDRESS_SCHEMA_VERSION
            || self.controller_epoch == 0
            || self.revision == Revision::INITIAL
        {
            return Err(EgressGatewayAddressError::InvalidRevision);
        }
        if self.recipient.node_name != principal.node_name
            || self.recipient.node_uid != principal.node_uid
        {
            return Err(EgressGatewayAddressError::RecipientMismatch);
        }
        self.validate_structure()?;
        if self.projection_digest != self.digest()? {
            return Err(EgressGatewayAddressError::DigestMismatch);
        }
        Ok(AdmittedEgressGatewayAddressProjection(self))
    }

    fn validate_structure(&self) -> Result<(), EgressGatewayAddressError> {
        if self.leases.len() > MAX_EGRESS_INTENTS {
            return Err(EgressGatewayAddressError::TooManyLeases);
        }
        if self
            .leases
            .windows(2)
            .any(|pair| pair[0].owner >= pair[1].owner)
        {
            return Err(EgressGatewayAddressError::InvalidLeaseOrder);
        }
        if self.leases.iter().any(|desired| {
            !desired.nodes.iter().any(|node| {
                node.name == self.recipient.node_name && node.uid == self.recipient.node_uid
            })
        }) {
            return Err(EgressGatewayAddressError::LeaseNotAssigned);
        }
        Ok(())
    }

    fn digest(&self) -> Result<EgressGatewayAddressProjectionDigest, EgressGatewayAddressError> {
        let material = serde_json::to_vec(&(
            self.schema_version,
            self.controller_epoch,
            self.revision,
            &self.recipient,
            &self.leases,
        ))
        .map_err(|_| EgressGatewayAddressError::DigestMismatch)?;
        let mut hasher = Sha256::new();
        hasher.update(b"unf.egress-gateway-address.v1\0");
        hasher.update(material);
        Ok(EgressGatewayAddressProjectionDigest(
            hasher.finalize().into(),
        ))
    }
}

impl EgressGatewayAddressAcknowledgement {
    /// Builds readback evidence for the complete issued projection.
    ///
    /// # Errors
    ///
    /// Rejects missing ensured addresses or noncanonical kernel evidence.
    pub fn issue(
        admitted: &AdmittedEgressGatewayAddressProjection,
        interface_name: String,
        interface_index: u32,
        mtu: u32,
        mut owned_addresses: Vec<IpAddr>,
    ) -> Result<Self, EgressGatewayAddressError> {
        let projection = admitted.projection();
        owned_addresses.sort_unstable();
        let mut acknowledgement = Self {
            schema_version: EGRESS_GATEWAY_ADDRESS_SCHEMA_VERSION,
            controller_epoch: projection.controller_epoch,
            projection_revision: projection.revision,
            recipient: projection.recipient.clone(),
            projection_digest: projection.projection_digest,
            interface_name,
            interface_index,
            mtu,
            owned_addresses,
            applied_desired_revisions: projection
                .leases
                .iter()
                .filter(|lease| lease.action == EgressGatewayAction::Ensure)
                .map(|lease| lease.revision)
                .collect(),
            quarantined_desired_revisions: projection
                .leases
                .iter()
                .filter(|lease| lease.action == EgressGatewayAction::Withdraw)
                .map(|lease| lease.revision)
                .collect(),
        };
        acknowledgement.applied_desired_revisions.sort_unstable();
        acknowledgement
            .quarantined_desired_revisions
            .sort_unstable();
        acknowledgement.verify(admitted)?;
        Ok(acknowledgement)
    }

    /// Verifies exact positive readiness and fail-closed quarantine evidence.
    ///
    /// # Errors
    ///
    /// Rejects metadata drift, noncanonical evidence, or a missing Ensure IP.
    pub fn verify(
        &self,
        admitted: &AdmittedEgressGatewayAddressProjection,
    ) -> Result<(), EgressGatewayAddressError> {
        let projection = admitted.projection();
        let expected_applied = projection
            .leases
            .iter()
            .filter(|lease| lease.action == EgressGatewayAction::Ensure)
            .map(|lease| lease.revision)
            .collect::<BTreeSet<_>>();
        let expected_quarantined = projection
            .leases
            .iter()
            .filter(|lease| lease.action == EgressGatewayAction::Withdraw)
            .map(|lease| lease.revision)
            .collect::<BTreeSet<_>>();
        let owned = self
            .owned_addresses
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        let required = projection
            .leases
            .iter()
            .filter(|lease| lease.action == EgressGatewayAction::Ensure)
            .flat_map(|lease| lease.addresses.iter().copied())
            .collect::<BTreeSet<_>>();
        if self.schema_version != EGRESS_GATEWAY_ADDRESS_SCHEMA_VERSION
            || self.controller_epoch != projection.controller_epoch
            || self.projection_revision != projection.revision
            || self.recipient != projection.recipient
            || self.projection_digest != projection.projection_digest
            || self.interface_name.is_empty()
            || self.interface_name.len() > 15
            || self.interface_index == 0
            || !(1_280..=65_535).contains(&self.mtu)
            || self
                .owned_addresses
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
            || self
                .applied_desired_revisions
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
            || self
                .quarantined_desired_revisions
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
            || self
                .applied_desired_revisions
                .iter()
                .copied()
                .collect::<BTreeSet<_>>()
                != expected_applied
            || self
                .quarantined_desired_revisions
                .iter()
                .copied()
                .collect::<BTreeSet<_>>()
                != expected_quarantined
            || !required.is_subset(&owned)
            || self.owned_addresses.len() > MAX_EGRESS_INTENTS * MAX_EGRESS_ADDRESSES_PER_INTENT
        {
            return Err(EgressGatewayAddressError::AcknowledgementMismatch);
        }
        Ok(())
    }
}

fn validate_principal(
    principal: &AuthenticatedEgressAgent,
) -> Result<(), EgressGatewayAddressError> {
    if principal.node_name.is_empty()
        || principal.node_name.len() > 253
        || principal.node_uid.is_empty()
        || principal.node_uid.len() > 128
    {
        return Err(EgressGatewayAddressError::InvalidPrincipal);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        DEFAULT_EGRESS_INTENT_PRIORITY, EGRESS_AGENT_SERVICE_ACCOUNT, EGRESS_AGENT_TOKEN_AUDIENCE,
        EgressAddressLease, EgressAddressRequest, EgressCapability, EgressDestinations,
        EgressIntent, EgressIntentOwner, EgressIntentScope, EgressNode, EgressProviderRef,
        EgressSourceSelector,
    };

    fn principal(name: &str) -> AuthenticatedEgressAgent {
        AuthenticatedEgressAgent {
            namespace: "unf-system".to_string(),
            service_account: EGRESS_AGENT_SERVICE_ACCOUNT.to_string(),
            pod_name: format!("unf-agent-{name}"),
            pod_uid: format!("pod-uid-{name}"),
            node_name: name.to_string(),
            node_uid: format!("node-uid-{name}"),
            audience: EGRESS_AGENT_TOKEN_AUDIENCE.to_string(),
        }
    }

    fn node(name: &str) -> EgressNode {
        EgressNode {
            name: name.to_string(),
            uid: format!("node-uid-{name}"),
            capabilities: BTreeSet::from([EgressCapability::LeaseEpochFencing]),
        }
    }

    fn lease(name: &str, addresses: &[&str], revision: u64) -> EgressAddressLease {
        let addresses = addresses
            .iter()
            .map(|address| address.parse().unwrap())
            .collect::<Vec<_>>();
        EgressAddressLease {
            intent: EgressIntent {
                owner: EgressIntentOwner {
                    scope: EgressIntentScope::Cluster,
                    name: name.to_string(),
                    uid: format!("uid-{name}"),
                },
                priority: DEFAULT_EGRESS_INTENT_PRIORITY,
                source: EgressSourceSelector::default(),
                destinations: EgressDestinations::Any,
                addresses: EgressAddressRequest::Explicit {
                    addresses: addresses.clone(),
                },
            },
            pool: None,
            provider: EgressProviderRef {
                name: "native".to_string(),
                instance: "default".to_string(),
            },
            addresses,
            lease_epoch: revision,
            intent_epoch: 1,
            intent_revision: Revision::new(revision),
            allocation_revision: Revision::new(revision),
        }
    }

    #[test]
    fn exact_node_projection_filters_and_seals_dual_stack_leases() {
        let mut registry = EgressGatewayRegistry::default();
        registry
            .ensure(
                &lease("payments", &["192.0.2.20", "2001:db8::20"], 1),
                vec![node("a"), node("b")],
            )
            .unwrap();
        registry
            .ensure(&lease("reports", &["192.0.2.21"], 2), vec![node("b")])
            .unwrap();
        let projection =
            EgressGatewayAddressProjection::issue(&principal("a"), 7, registry.checkpoint())
                .unwrap();
        assert_eq!(projection.leases.len(), 1);
        assert_eq!(projection.leases[0].owner.name, "payments");
        projection.clone().admit(&principal("a")).unwrap();

        let mut mutated = projection;
        mutated.leases[0].addresses[0] = "192.0.2.99".parse().unwrap();
        assert_eq!(
            mutated.admit(&principal("a")).unwrap_err(),
            EgressGatewayAddressError::DigestMismatch
        );
    }

    #[test]
    fn acknowledgement_requires_every_ensure_address_and_tracks_quarantine() {
        let mut registry = EgressGatewayRegistry::default();
        let payments = lease("payments", &["192.0.2.20", "2001:db8::20"], 1);
        registry.ensure(&payments, vec![node("a")]).unwrap();
        let reports = lease("reports", &["192.0.2.21"], 2);
        registry.ensure(&reports, vec![node("a")]).unwrap();
        registry.withdraw(&reports.intent.owner).unwrap();
        let admitted =
            EgressGatewayAddressProjection::issue(&principal("a"), 7, registry.checkpoint())
                .unwrap()
                .admit(&principal("a"))
                .unwrap();
        let ack = EgressGatewayAddressAcknowledgement::issue(
            &admitted,
            "unf-egress0".to_string(),
            12,
            1_500,
            vec![
                "192.0.2.20".parse().unwrap(),
                "192.0.2.21".parse().unwrap(),
                "2001:db8::20".parse().unwrap(),
            ],
        )
        .unwrap();
        assert_eq!(ack.applied_desired_revisions.len(), 1);
        assert_eq!(ack.quarantined_desired_revisions.len(), 1);

        let mut incomplete = ack;
        incomplete.owned_addresses.remove(0);
        assert_eq!(
            incomplete.verify(&admitted).unwrap_err(),
            EgressGatewayAddressError::AcknowledgementMismatch
        );
    }

    #[test]
    fn replacement_node_uid_cannot_admit_stale_address_authority() {
        let mut registry = EgressGatewayRegistry::default();
        registry
            .ensure(&lease("payments", &["192.0.2.20"], 1), vec![node("a")])
            .unwrap();
        let projection =
            EgressGatewayAddressProjection::issue(&principal("a"), 7, registry.checkpoint())
                .unwrap();
        let mut replacement = principal("a");
        replacement.node_uid = "replacement-node-uid".to_string();
        assert_eq!(
            projection.admit(&replacement).unwrap_err(),
            EgressGatewayAddressError::RecipientMismatch
        );
    }
}
