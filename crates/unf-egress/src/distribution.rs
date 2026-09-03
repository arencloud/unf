//! Authenticated, capability-negotiated exact-Node egress distribution.
//!
//! The transport authenticates the agent before constructing
//! [`AuthenticatedEgressAgent`]. This module then binds that principal to one
//! canonical behavior contract and requires independent replay before host
//! state can be compiled.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use unf_common::Revision;

use crate::{
    EGRESS_BEHAVIOR_CONTRACT_SCHEMA_VERSION, EgressBehaviorContract, EgressCapability,
    EgressContractDigest, EgressContractError, EgressContractFacts, EgressFlowProof, EgressModel,
    EgressNode, EgressOriginalFlow, EgressProofError, MAX_EGRESS_CONTRACT_PLANS,
    MAX_EGRESS_GATEWAY_NODES,
};

pub const EGRESS_DISTRIBUTION_SCHEMA_VERSION: u16 = 1;
pub const EGRESS_HOST_STATE_SCHEMA_VERSION: u16 = 1;
pub const EGRESS_APPLICATION_ACK_SCHEMA_VERSION: u16 = 1;
pub const EGRESS_SOURCE_ACTIVATION_SCHEMA_VERSION: u16 = 1;
pub const MAX_EGRESS_ADVERTISED_SCHEMAS: usize = 8;
pub const MAX_EGRESS_GATEWAY_SOURCE_CONTRACTS: usize = MAX_EGRESS_CONTRACT_PLANS;
pub const EGRESS_AGENT_SERVICE_ACCOUNT: &str = "unf-agent";
pub const EGRESS_AGENT_TOKEN_AUDIENCE: &str = "unf-controller.unf-system.svc";

/// An identity already established by the controller's Pod-bound `TokenReview`
/// boundary and authoritative Pod/Node cache.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedEgressAgent {
    pub namespace: String,
    pub service_account: String,
    pub pod_name: String,
    pub pod_uid: String,
    pub node_name: String,
    pub node_uid: String,
    pub audience: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EgressAgentAdvertisement {
    pub distribution_schemas: BTreeSet<u16>,
    pub host_state_schemas: BTreeSet<u16>,
    pub capabilities: BTreeSet<EgressCapability>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EgressNegotiatedCapabilities {
    pub distribution_schema: u16,
    pub contract_schema: u16,
    pub host_state_schema: u16,
    pub capabilities: BTreeSet<EgressCapability>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EgressProjectionRecipient {
    pub node_name: String,
    pub node_uid: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EgressNodeProjection {
    pub schema_version: u16,
    pub controller_epoch: u64,
    pub revision: Revision,
    pub recipient: EgressProjectionRecipient,
    pub negotiated: EgressNegotiatedCapabilities,
    pub contract: EgressBehaviorContract,
}

/// Self-contained source projection wire envelope. The model and independently
/// observed contract facts are carried alongside the controller-issued
/// commitment so the receiving agent can replay the contract instead of
/// trusting precompiled map bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EgressNodeProjectionEnvelope {
    pub projection: EgressNodeProjection,
    pub model: EgressModel,
    pub facts: EgressContractFacts,
}

/// A projection that has passed authenticated recipient checks and independent
/// contract replay. Host-state code accepts this type instead of an unchecked
/// wire object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmittedEgressProjection(EgressNodeProjection);

impl AdmittedEgressProjection {
    #[must_use]
    pub const fn projection(&self) -> &EgressNodeProjection {
        &self.0
    }

    #[must_use]
    pub fn into_projection(self) -> EgressNodeProjection {
        self.0
    }
}

/// Controller-authenticated aggregation of already admitted source contracts
/// for one exact gateway Node. Complete source contracts preserve the indexes
/// required to reproduce their decision witnesses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EgressGatewayProjection {
    pub schema_version: u16,
    pub controller_epoch: u64,
    pub revision: Revision,
    pub recipient: EgressProjectionRecipient,
    pub negotiated: EgressNegotiatedCapabilities,
    pub gateway: EgressNode,
    pub source_contracts: Vec<EgressBehaviorContract>,
    pub projection_digest: EgressGatewayProjectionDigest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EgressGatewayProjectionDigest(pub [u8; 32]);

/// Gateway projection admitted only after recipient, capability, contract,
/// ordering, gateway-membership, and envelope checks all agree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmittedEgressGatewayProjection(EgressGatewayProjection);

impl AdmittedEgressGatewayProjection {
    #[must_use]
    pub const fn projection(&self) -> &EgressGatewayProjection {
        &self.0
    }

    #[must_use]
    pub fn into_projection(self) -> EgressGatewayProjection {
        self.0
    }

    /// Reproduces a source-issued proof using its one exact retained contract.
    /// The caller obtains `flow.identity` from authoritative gateway metadata;
    /// proof bytes are never an identity credential.
    ///
    /// # Errors
    ///
    /// Rejects absent/ambiguous contract ownership or any proof mismatch.
    pub fn verify_flow(
        &self,
        proof: &EgressFlowProof,
        flow: EgressOriginalFlow,
    ) -> Result<(), EgressProofError> {
        let mut contracts = self.0.source_contracts.iter().filter(|contract| {
            contract.contract_revision == proof.contract_revision
                && contract.contract_digest == proof.contract_digest
                && contract
                    .plans
                    .iter()
                    .any(|plan| plan.source.identity == flow.identity)
        });
        let Some(contract) = contracts.next() else {
            return Err(EgressProofError::ProofMismatch);
        };
        if contracts.next().is_some() {
            return Err(EgressProofError::ProofMismatch);
        }
        proof.verify_at_gateway(contract, &self.0.gateway, flow)
    }
}

/// Exact evidence emitted only after a source projection has been committed to
/// one active egress map bank and read back successfully.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EgressSourceApplicationAcknowledgement {
    pub schema_version: u16,
    pub controller_epoch: u64,
    pub projection_revision: Revision,
    pub recipient: EgressProjectionRecipient,
    pub contract_revision: Revision,
    pub contract_digest: crate::EgressContractDigest,
    pub active_bank: u8,
    pub source_count: u32,
}

impl EgressSourceApplicationAcknowledgement {
    /// Builds exact source application evidence from an admitted projection.
    ///
    /// # Errors
    ///
    /// Rejects an invalid bank or count that disagrees with the contract.
    pub fn issue(
        projection: &AdmittedEgressProjection,
        active_bank: u8,
        source_count: usize,
    ) -> Result<Self, EgressDistributionError> {
        let projection = projection.projection();
        let acknowledgement = Self {
            schema_version: EGRESS_APPLICATION_ACK_SCHEMA_VERSION,
            controller_epoch: projection.controller_epoch,
            projection_revision: projection.revision,
            recipient: projection.recipient.clone(),
            contract_revision: projection.contract.contract_revision,
            contract_digest: projection.contract.contract_digest,
            active_bank,
            source_count: u32::try_from(source_count)
                .map_err(|_| EgressDistributionError::ApplicationAcknowledgementMismatch)?,
        };
        acknowledgement.verify_projection(projection)?;
        Ok(acknowledgement)
    }

    /// Verifies that application evidence names every immutable source tuple.
    ///
    /// # Errors
    ///
    /// Rejects schema, epoch, revision, recipient, digest, bank, or count drift.
    pub fn verify(
        &self,
        projection: &AdmittedEgressProjection,
    ) -> Result<(), EgressDistributionError> {
        self.verify_projection(projection.projection())
    }

    fn verify_projection(
        &self,
        projection: &EgressNodeProjection,
    ) -> Result<(), EgressDistributionError> {
        if self.schema_version != EGRESS_APPLICATION_ACK_SCHEMA_VERSION
            || self.controller_epoch != projection.controller_epoch
            || self.projection_revision != projection.revision
            || self.recipient != projection.recipient
            || self.contract_revision != projection.contract.contract_revision
            || self.contract_digest != projection.contract.contract_digest
            || self.active_bank >= 2
            || usize::try_from(self.source_count).ok() != Some(projection.contract.plans.len())
        {
            return Err(EgressDistributionError::ApplicationAcknowledgementMismatch);
        }
        Ok(())
    }
}

/// Exact evidence emitted after a gateway has adopted the complete selected
/// contract set (including an explicit empty withdrawal).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EgressGatewayApplicationAcknowledgement {
    pub schema_version: u16,
    pub controller_epoch: u64,
    pub projection_revision: Revision,
    pub recipient: EgressProjectionRecipient,
    pub projection_digest: EgressGatewayProjectionDigest,
    pub contract_count: u32,
    pub source_count: u32,
    pub withdrawn: bool,
}

/// Controller-issued activation authority. It binds the exact admitted source
/// contract to positive application evidence from every selected gateway.
/// Source-local path evidence remains independently required by the agent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EgressSourceActivationGrant {
    pub schema_version: u16,
    pub controller_epoch: u64,
    pub projection_revision: Revision,
    pub recipient: EgressProjectionRecipient,
    pub contract_revision: Revision,
    pub contract_digest: EgressContractDigest,
    pub gateway_applications: Vec<EgressGatewayApplicationAcknowledgement>,
    pub grant_digest: EgressSourceActivationDigest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EgressSourceActivationDigest(pub [u8; 32]);

impl EgressSourceActivationGrant {
    /// Seals exact gateway application evidence for one admitted source.
    ///
    /// # Errors
    ///
    /// Rejects missing, duplicate, withdrawn, stale, foreign, or oversized
    /// gateway evidence.
    pub fn issue(
        source: &AdmittedEgressProjection,
        mut gateway_applications: Vec<EgressGatewayApplicationAcknowledgement>,
    ) -> Result<Self, EgressDistributionError> {
        gateway_applications.sort_by(|left, right| left.recipient.cmp(&right.recipient));
        let projection = source.projection();
        let mut grant = Self {
            schema_version: EGRESS_SOURCE_ACTIVATION_SCHEMA_VERSION,
            controller_epoch: projection.controller_epoch,
            projection_revision: projection.revision,
            recipient: projection.recipient.clone(),
            contract_revision: projection.contract.contract_revision,
            contract_digest: projection.contract.contract_digest,
            gateway_applications,
            grant_digest: EgressSourceActivationDigest([0; 32]),
        };
        grant.validate_fields(projection)?;
        grant.grant_digest = grant.digest()?;
        Ok(grant)
    }

    /// Verifies the activation authority against an independently admitted
    /// source projection.
    ///
    /// # Errors
    ///
    /// Rejects any source, gateway-set, application, ordering, or digest drift.
    pub fn verify(&self, source: &AdmittedEgressProjection) -> Result<(), EgressDistributionError> {
        self.validate_fields(source.projection())?;
        if self.grant_digest != self.digest()? {
            return Err(EgressDistributionError::ActivationGrantDigestMismatch);
        }
        Ok(())
    }

    fn validate_fields(
        &self,
        projection: &EgressNodeProjection,
    ) -> Result<(), EgressDistributionError> {
        if self.schema_version != EGRESS_SOURCE_ACTIVATION_SCHEMA_VERSION
            || self.controller_epoch != projection.controller_epoch
            || self.projection_revision != projection.revision
            || self.recipient != projection.recipient
            || self.contract_revision != projection.contract.contract_revision
            || self.contract_digest != projection.contract.contract_digest
            || self.gateway_applications.is_empty()
            || self.gateway_applications.len() > MAX_EGRESS_GATEWAY_NODES
        {
            return Err(EgressDistributionError::ActivationGrantMismatch);
        }
        let expected = projection
            .contract
            .plans
            .iter()
            .flat_map(|plan| &plan.gateways)
            .map(|gateway| EgressProjectionRecipient {
                node_name: gateway.node.name.clone(),
                node_uid: gateway.node.uid.clone(),
            })
            .collect::<BTreeSet<_>>();
        let actual = self
            .gateway_applications
            .iter()
            .map(|application| application.recipient.clone())
            .collect::<BTreeSet<_>>();
        if actual != expected || actual.len() != self.gateway_applications.len() {
            return Err(EgressDistributionError::ActivationGrantMismatch);
        }
        if self
            .gateway_applications
            .windows(2)
            .any(|pair| pair[0].recipient >= pair[1].recipient)
            || self.gateway_applications.iter().any(|application| {
                application.schema_version != EGRESS_APPLICATION_ACK_SCHEMA_VERSION
                    || application.controller_epoch != self.controller_epoch
                    || application.projection_revision == Revision::INITIAL
                    || application.contract_count == 0
                    || application.source_count == 0
                    || application.withdrawn
            })
        {
            return Err(EgressDistributionError::ActivationGrantMismatch);
        }
        Ok(())
    }

    fn digest(&self) -> Result<EgressSourceActivationDigest, EgressDistributionError> {
        let material = serde_json::to_vec(&(
            self.schema_version,
            self.controller_epoch,
            self.projection_revision,
            &self.recipient,
            self.contract_revision,
            self.contract_digest,
            &self.gateway_applications,
        ))
        .map_err(|_| EgressDistributionError::ActivationGrantMismatch)?;
        let mut hasher = Sha256::new();
        hasher.update(b"unf.egress-source-activation.v1\0");
        hasher.update(material);
        Ok(EgressSourceActivationDigest(hasher.finalize().into()))
    }
}

impl EgressGatewayApplicationAcknowledgement {
    /// Builds exact gateway-host application evidence after ledger adoption.
    ///
    /// # Errors
    ///
    /// Rejects counts that exceed the fixed projection bounds.
    pub fn issue(
        projection: &AdmittedEgressGatewayProjection,
    ) -> Result<Self, EgressDistributionError> {
        let projection = projection.projection();
        let source_count = projection
            .source_contracts
            .iter()
            .try_fold(0_usize, |total, contract| {
                total.checked_add(contract.plans.len())
            })
            .ok_or(EgressDistributionError::GatewayProjectionTooLarge)?;
        let acknowledgement = Self {
            schema_version: EGRESS_APPLICATION_ACK_SCHEMA_VERSION,
            controller_epoch: projection.controller_epoch,
            projection_revision: projection.revision,
            recipient: projection.recipient.clone(),
            projection_digest: projection.projection_digest,
            contract_count: u32::try_from(projection.source_contracts.len())
                .map_err(|_| EgressDistributionError::GatewayProjectionTooLarge)?,
            source_count: u32::try_from(source_count)
                .map_err(|_| EgressDistributionError::GatewayProjectionTooLarge)?,
            withdrawn: projection.is_withdrawal(),
        };
        acknowledgement.verify_projection(projection)?;
        Ok(acknowledgement)
    }

    /// Verifies exact gateway application or withdrawal evidence.
    ///
    /// # Errors
    ///
    /// Rejects any schema, recipient, revision, digest, count, or action drift.
    pub fn verify(
        &self,
        projection: &AdmittedEgressGatewayProjection,
    ) -> Result<(), EgressDistributionError> {
        self.verify_projection(projection.projection())
    }

    fn verify_projection(
        &self,
        projection: &EgressGatewayProjection,
    ) -> Result<(), EgressDistributionError> {
        let source_count = projection
            .source_contracts
            .iter()
            .try_fold(0_usize, |total, contract| {
                total.checked_add(contract.plans.len())
            })
            .ok_or(EgressDistributionError::GatewayProjectionTooLarge)?;
        if self.schema_version != EGRESS_APPLICATION_ACK_SCHEMA_VERSION
            || self.controller_epoch != projection.controller_epoch
            || self.projection_revision != projection.revision
            || self.recipient != projection.recipient
            || self.projection_digest != projection.projection_digest
            || usize::try_from(self.contract_count).ok() != Some(projection.source_contracts.len())
            || usize::try_from(self.source_count).ok() != Some(source_count)
            || self.withdrawn != projection.is_withdrawal()
        {
            return Err(EgressDistributionError::ApplicationAcknowledgementMismatch);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum EgressDistributionError {
    #[error("invalid authenticated egress agent: {0}")]
    InvalidPrincipal(&'static str),
    #[error("egress application acknowledgement does not match issued projection")]
    ApplicationAcknowledgementMismatch,
    #[error("egress source activation grant does not match its admitted contract and gateway set")]
    ActivationGrantMismatch,
    #[error("egress source activation grant digest does not match its content")]
    ActivationGrantDigestMismatch,
    #[error("egress advertisement exceeds the schema bound")]
    AdvertisementTooLarge,
    #[error("no compatible egress {domain} schema; required {required}")]
    NoCompatibleSchema { domain: &'static str, required: u16 },
    #[error("egress projection has invalid epoch or revision")]
    InvalidRevision,
    #[error("egress projection recipient does not match the authenticated Node")]
    RecipientMismatch,
    #[error("egress projection capability set does not match the authenticated advertisement")]
    CapabilityMismatch,
    #[error("egress projection is missing required capability {0:?}")]
    MissingCapability(EgressCapability),
    #[error("egress projection epoch or revision regressed")]
    RevisionRegression,
    #[error("egress projection mutated at the same epoch and revision")]
    SameRevisionMutation,
    #[error("egress gateway projection contains no usable source contract")]
    EmptyGatewayProjection,
    #[error("egress gateway projection exceeds the source-contract bound")]
    GatewayProjectionTooLarge,
    #[error("egress gateway projection source contracts are duplicated or noncanonical")]
    InvalidGatewayContractOrder,
    #[error("egress gateway projection contains a duplicate source identity")]
    DuplicateGatewayIdentity,
    #[error("egress gateway is not a ready, reachable candidate for every projected contract")]
    GatewayNotSelected,
    #[error("egress gateway projection digest does not match its content")]
    GatewayProjectionDigestMismatch,
    #[error(transparent)]
    Contract(#[from] EgressContractError),
}

impl EgressNodeProjection {
    /// Creates a response for the exact authenticated Node and negotiated
    /// current schemas. No legacy fallback is permitted for selected egress.
    ///
    /// # Errors
    ///
    /// Rejects invalid principals, schema/capability mismatch, wrong-Node
    /// contracts, or zero revision state.
    pub fn issue(
        principal: &AuthenticatedEgressAgent,
        advertisement: &EgressAgentAdvertisement,
        controller_epoch: u64,
        revision: Revision,
        contract: EgressBehaviorContract,
    ) -> Result<Self, EgressDistributionError> {
        validate_principal(principal)?;
        let negotiated = negotiate(advertisement)?;
        if controller_epoch == 0 || revision == Revision::INITIAL {
            return Err(EgressDistributionError::InvalidRevision);
        }
        if contract.node.name != principal.node_name || contract.node.uid != principal.node_uid {
            return Err(EgressDistributionError::RecipientMismatch);
        }
        contract.verify_integrity()?;
        validate_capabilities(&contract, &negotiated)?;
        Ok(Self {
            schema_version: EGRESS_DISTRIBUTION_SCHEMA_VERSION,
            controller_epoch,
            revision,
            recipient: EgressProjectionRecipient {
                node_name: principal.node_name.clone(),
                node_uid: principal.node_uid.clone(),
            },
            negotiated,
            contract,
        })
    }

    /// Rebinds the wire response to the local authenticated identity and
    /// independently replays every contract domain before admission.
    ///
    /// # Errors
    ///
    /// Rejects wrong recipients, unsupported schemas, unadvertised
    /// capabilities, stale/mutated contracts, or invalid source facts.
    pub fn admit(
        self,
        principal: &AuthenticatedEgressAgent,
        advertisement: &EgressAgentAdvertisement,
        model: &EgressModel,
        facts: &EgressContractFacts,
    ) -> Result<AdmittedEgressProjection, EgressDistributionError> {
        validate_principal(principal)?;
        let expected = negotiate(advertisement)?;
        if self.schema_version != EGRESS_DISTRIBUTION_SCHEMA_VERSION
            || self.controller_epoch == 0
            || self.revision == Revision::INITIAL
        {
            return Err(EgressDistributionError::InvalidRevision);
        }
        if self.recipient.node_name != principal.node_name
            || self.recipient.node_uid != principal.node_uid
            || self.contract.node.name != principal.node_name
            || self.contract.node.uid != principal.node_uid
        {
            return Err(EgressDistributionError::RecipientMismatch);
        }
        if self.negotiated != expected {
            return Err(EgressDistributionError::CapabilityMismatch);
        }
        validate_capabilities(&self.contract, &self.negotiated)?;
        self.contract.verify(model, facts, &self.contract.node)?;
        Ok(AdmittedEgressProjection(self))
    }
}

impl EgressNodeProjectionEnvelope {
    /// Issues one self-contained response for the exact authenticated Node.
    ///
    /// # Errors
    ///
    /// Rejects invalid model/facts, recipient, schema, capability, or contract
    /// material before any bytes cross the distribution boundary.
    pub fn issue(
        principal: &AuthenticatedEgressAgent,
        advertisement: &EgressAgentAdvertisement,
        controller_epoch: u64,
        revision: Revision,
        model: EgressModel,
        facts: EgressContractFacts,
        contract: EgressBehaviorContract,
    ) -> Result<Self, EgressDistributionError> {
        let projection = EgressNodeProjection::issue(
            principal,
            advertisement,
            controller_epoch,
            revision,
            contract,
        )?;
        projection
            .contract
            .verify(&model, &facts, &projection.contract.node)?;
        Ok(Self {
            projection,
            model,
            facts,
        })
    }

    /// Independently replays all material and binds it to the local agent.
    ///
    /// # Errors
    ///
    /// Rejects any envelope or replay mismatch without producing admitted
    /// host state.
    pub fn admit(
        self,
        principal: &AuthenticatedEgressAgent,
        advertisement: &EgressAgentAdvertisement,
    ) -> Result<AdmittedEgressProjection, EgressDistributionError> {
        self.projection
            .admit(principal, advertisement, &self.model, &self.facts)
    }
}

impl EgressGatewayProjection {
    /// Aggregates contracts only from independently admitted source projections
    /// and targets one authenticated gateway agent.
    ///
    /// # Errors
    ///
    /// Rejects invalid authentication, bounds, capabilities, contract
    /// integrity, duplicate source Nodes, or a gateway absent from a contract.
    pub fn issue(
        principal: &AuthenticatedEgressAgent,
        advertisement: &EgressAgentAdvertisement,
        controller_epoch: u64,
        revision: Revision,
        sources: &[AdmittedEgressProjection],
    ) -> Result<Self, EgressDistributionError> {
        validate_principal(principal)?;
        let negotiated = negotiate(advertisement)?;
        if controller_epoch == 0 || revision == Revision::INITIAL {
            return Err(EgressDistributionError::InvalidRevision);
        }
        let mut source_contracts = sources
            .iter()
            .map(|source| source.projection().contract.clone())
            .collect::<Vec<_>>();
        source_contracts.sort_by(|left, right| {
            (&left.node.uid, &left.node.name).cmp(&(&right.node.uid, &right.node.name))
        });
        let mut projection = Self {
            schema_version: EGRESS_DISTRIBUTION_SCHEMA_VERSION,
            controller_epoch,
            revision,
            recipient: EgressProjectionRecipient {
                node_name: principal.node_name.clone(),
                node_uid: principal.node_uid.clone(),
            },
            negotiated,
            gateway: EgressNode {
                name: principal.node_name.clone(),
                uid: principal.node_uid.clone(),
                capabilities: advertisement.capabilities.clone(),
            },
            source_contracts,
            projection_digest: EgressGatewayProjectionDigest([0; 32]),
        };
        projection.validate_structure(false)?;
        projection.projection_digest = projection.digest()?;
        Ok(projection)
    }

    /// Issues an explicit empty projection that withdraws all previously
    /// admitted source contracts from one exact gateway Node.
    ///
    /// # Errors
    ///
    /// Rejects invalid authentication, schema negotiation, epoch, or revision.
    pub fn withdraw(
        principal: &AuthenticatedEgressAgent,
        advertisement: &EgressAgentAdvertisement,
        controller_epoch: u64,
        revision: Revision,
    ) -> Result<Self, EgressDistributionError> {
        validate_principal(principal)?;
        let negotiated = negotiate(advertisement)?;
        if controller_epoch == 0 || revision == Revision::INITIAL {
            return Err(EgressDistributionError::InvalidRevision);
        }
        let mut projection = Self {
            schema_version: EGRESS_DISTRIBUTION_SCHEMA_VERSION,
            controller_epoch,
            revision,
            recipient: EgressProjectionRecipient {
                node_name: principal.node_name.clone(),
                node_uid: principal.node_uid.clone(),
            },
            negotiated,
            gateway: EgressNode {
                name: principal.node_name.clone(),
                uid: principal.node_uid.clone(),
                capabilities: advertisement.capabilities.clone(),
            },
            source_contracts: Vec::new(),
            projection_digest: EgressGatewayProjectionDigest([0; 32]),
        };
        projection.projection_digest = projection.digest()?;
        Ok(projection)
    }

    #[must_use]
    pub fn is_withdrawal(&self) -> bool {
        self.source_contracts.is_empty()
    }

    /// Admits a wire projection on the exact gateway Node. The authenticated
    /// controller envelope contains complete contracts previously admitted by
    /// their source agents; the gateway verifies each immutable commitment and
    /// its own lease-fenced membership again.
    ///
    /// # Errors
    ///
    /// Rejects recipient/schema/capability mismatch, corrupt contracts,
    /// noncanonical aggregation, or an invalid envelope digest.
    pub fn admit(
        self,
        principal: &AuthenticatedEgressAgent,
        advertisement: &EgressAgentAdvertisement,
    ) -> Result<AdmittedEgressGatewayProjection, EgressDistributionError> {
        validate_principal(principal)?;
        if self.schema_version != EGRESS_DISTRIBUTION_SCHEMA_VERSION
            || self.controller_epoch == 0
            || self.revision == Revision::INITIAL
        {
            return Err(EgressDistributionError::InvalidRevision);
        }
        if self.recipient.node_name != principal.node_name
            || self.recipient.node_uid != principal.node_uid
            || self.gateway.name != principal.node_name
            || self.gateway.uid != principal.node_uid
        {
            return Err(EgressDistributionError::RecipientMismatch);
        }
        let expected = negotiate(advertisement)?;
        if self.negotiated != expected || self.gateway.capabilities != expected.capabilities {
            return Err(EgressDistributionError::CapabilityMismatch);
        }
        self.validate_structure(true)?;
        if self.projection_digest != self.digest()? {
            return Err(EgressDistributionError::GatewayProjectionDigestMismatch);
        }
        Ok(AdmittedEgressGatewayProjection(self))
    }

    fn validate_structure(&self, allow_withdrawal: bool) -> Result<(), EgressDistributionError> {
        if self.source_contracts.is_empty() && !allow_withdrawal {
            return Err(EgressDistributionError::EmptyGatewayProjection);
        }
        if self.source_contracts.len() > MAX_EGRESS_GATEWAY_SOURCE_CONTRACTS {
            return Err(EgressDistributionError::GatewayProjectionTooLarge);
        }
        let mut previous_node: Option<&str> = None;
        let mut total_plans = 0_usize;
        let mut identities = BTreeSet::new();
        for contract in &self.source_contracts {
            contract.verify_integrity()?;
            if contract.schema_version != self.negotiated.contract_schema
                || previous_node.is_some_and(|uid| uid >= contract.node.uid.as_str())
            {
                return Err(EgressDistributionError::InvalidGatewayContractOrder);
            }
            previous_node = Some(contract.node.uid.as_str());
            total_plans = total_plans
                .checked_add(contract.plans.len())
                .ok_or(EgressDistributionError::GatewayProjectionTooLarge)?;
            if total_plans > MAX_EGRESS_CONTRACT_PLANS {
                return Err(EgressDistributionError::GatewayProjectionTooLarge);
            }
            for plan in &contract.plans {
                if !identities.insert(plan.source.identity) {
                    return Err(EgressDistributionError::DuplicateGatewayIdentity);
                }
            }
            let selected = contract.plans.iter().any(|plan| {
                plan.gateways.iter().any(|candidate| {
                    candidate.node == self.gateway
                        && candidate.ready
                        && candidate.reachable
                        && candidate.lease_epoch == plan.allocation.lease_epoch
                        && plan
                            .required_capabilities
                            .is_subset(&self.gateway.capabilities)
                })
            });
            if !selected {
                return Err(EgressDistributionError::GatewayNotSelected);
            }
        }
        Ok(())
    }

    fn digest(&self) -> Result<EgressGatewayProjectionDigest, EgressDistributionError> {
        let material = serde_json::to_vec(&(
            self.schema_version,
            self.controller_epoch,
            self.revision,
            &self.recipient,
            &self.negotiated,
            &self.gateway,
            &self.source_contracts,
        ))
        .map_err(|error| EgressContractError::CanonicalEncoding(error.to_string()))?;
        let mut hasher = Sha256::new();
        hasher.update(b"unf.egress-gateway-projection.v1\0");
        hasher.update(material);
        Ok(EgressGatewayProjectionDigest(hasher.finalize().into()))
    }
}

/// Monotonic last-known-good selected-gateway projection ownership. Explicit
/// empty projections are retained as withdrawal authority.
#[derive(Debug, Clone, Default)]
pub struct EgressGatewayProjectionLedger {
    current: Option<EgressGatewayProjection>,
}

impl EgressGatewayProjectionLedger {
    #[must_use]
    pub const fn current(&self) -> Option<&EgressGatewayProjection> {
        self.current.as_ref()
    }

    /// Adopts an independently admitted gateway projection after monotonic
    /// epoch/revision fencing.
    ///
    /// # Errors
    ///
    /// Rejects regression or mutation at an already accepted revision tuple.
    pub fn adopt(
        &mut self,
        projection: AdmittedEgressGatewayProjection,
    ) -> Result<&EgressGatewayProjection, EgressDistributionError> {
        let candidate = projection.into_projection();
        if let Some(current) = &self.current {
            if candidate.controller_epoch < current.controller_epoch
                || (candidate.controller_epoch == current.controller_epoch
                    && candidate.revision < current.revision)
            {
                return Err(EgressDistributionError::RevisionRegression);
            }
            if candidate.controller_epoch == current.controller_epoch
                && candidate.revision == current.revision
            {
                if candidate != *current {
                    return Err(EgressDistributionError::SameRevisionMutation);
                }
                return self
                    .current
                    .as_ref()
                    .ok_or(EgressDistributionError::InvalidRevision);
            }
        }
        self.current = Some(candidate);
        self.current
            .as_ref()
            .ok_or(EgressDistributionError::InvalidRevision)
    }
}

/// Monotonic last-known-good projection ownership. Exact replay is idempotent;
/// regression and same-revision mutation fail without replacing current state.
#[derive(Debug, Clone, Default)]
pub struct EgressProjectionLedger {
    current: Option<EgressNodeProjection>,
}

impl EgressProjectionLedger {
    #[must_use]
    pub const fn current(&self) -> Option<&EgressNodeProjection> {
        self.current.as_ref()
    }

    /// Adopts a verified projection after monotonic epoch/revision fencing.
    ///
    /// # Errors
    ///
    /// Rejects controller epoch regression, revision regression inside one
    /// epoch, or mutation at an already accepted tuple.
    pub fn adopt(
        &mut self,
        projection: AdmittedEgressProjection,
    ) -> Result<&EgressNodeProjection, EgressDistributionError> {
        let candidate = projection.into_projection();
        let exact_replay = if let Some(current) = &self.current {
            if candidate.controller_epoch < current.controller_epoch
                || (candidate.controller_epoch == current.controller_epoch
                    && candidate.revision < current.revision)
            {
                return Err(EgressDistributionError::RevisionRegression);
            }
            if candidate.controller_epoch == current.controller_epoch
                && candidate.revision == current.revision
            {
                if candidate != *current {
                    return Err(EgressDistributionError::SameRevisionMutation);
                }
                true
            } else {
                false
            }
        } else {
            false
        };
        if exact_replay {
            return self
                .current
                .as_ref()
                .ok_or(EgressDistributionError::InvalidRevision);
        }
        self.current = Some(candidate);
        self.current
            .as_ref()
            .ok_or(EgressDistributionError::InvalidRevision)
    }
}

fn negotiate(
    advertisement: &EgressAgentAdvertisement,
) -> Result<EgressNegotiatedCapabilities, EgressDistributionError> {
    if advertisement.distribution_schemas.len() > MAX_EGRESS_ADVERTISED_SCHEMAS
        || advertisement.host_state_schemas.len() > MAX_EGRESS_ADVERTISED_SCHEMAS
    {
        return Err(EgressDistributionError::AdvertisementTooLarge);
    }
    for (domain, required, supported) in [
        (
            "distribution",
            EGRESS_DISTRIBUTION_SCHEMA_VERSION,
            &advertisement.distribution_schemas,
        ),
        (
            "host-state",
            EGRESS_HOST_STATE_SCHEMA_VERSION,
            &advertisement.host_state_schemas,
        ),
    ] {
        if !supported.contains(&required) {
            return Err(EgressDistributionError::NoCompatibleSchema { domain, required });
        }
    }
    Ok(EgressNegotiatedCapabilities {
        distribution_schema: EGRESS_DISTRIBUTION_SCHEMA_VERSION,
        contract_schema: EGRESS_BEHAVIOR_CONTRACT_SCHEMA_VERSION,
        host_state_schema: EGRESS_HOST_STATE_SCHEMA_VERSION,
        capabilities: advertisement.capabilities.clone(),
    })
}

fn validate_principal(principal: &AuthenticatedEgressAgent) -> Result<(), EgressDistributionError> {
    if principal.namespace.is_empty()
        || principal.namespace.len() > 63
        || principal.service_account != EGRESS_AGENT_SERVICE_ACCOUNT
        || principal.pod_name.is_empty()
        || principal.pod_name.len() > 253
        || principal.pod_uid.is_empty()
        || principal.pod_uid.len() > 128
        || principal.node_name.is_empty()
        || principal.node_name.len() > 253
        || principal.node_uid.is_empty()
        || principal.node_uid.len() > 128
        || principal.audience != EGRESS_AGENT_TOKEN_AUDIENCE
    {
        return Err(EgressDistributionError::InvalidPrincipal(
            "Pod, service-account, audience, or Node binding is invalid",
        ));
    }
    Ok(())
}

fn validate_capabilities(
    contract: &EgressBehaviorContract,
    negotiated: &EgressNegotiatedCapabilities,
) -> Result<(), EgressDistributionError> {
    if contract.schema_version != negotiated.contract_schema
        || contract.node.capabilities != negotiated.capabilities
    {
        return Err(EgressDistributionError::CapabilityMismatch);
    }
    let required = contract
        .plans
        .iter()
        .flat_map(|plan| plan.required_capabilities.iter().copied())
        .collect::<BTreeSet<_>>();
    if let Some(missing) = required.difference(&negotiated.capabilities).next() {
        return Err(EgressDistributionError::MissingCapability(*missing));
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod test_support {
    use std::collections::{BTreeMap, BTreeSet};
    use std::net::IpAddr;

    use unf_common::{IdentityId, PolicyId, Revision};

    use super::*;
    use crate::{
        AddressFamily, DEFAULT_EGRESS_INTENT_PRIORITY, EgressAddressPool, EgressAddressRequest,
        EgressAllocationFact, EgressContractRevisions, EgressDestinations, EgressGatewayFact,
        EgressIntent, EgressIntentOwner, EgressIntentScope, EgressNode, EgressPolicyFact,
        EgressProviderRef, EgressSourceFact, EgressSourceSelector, IpPrefix, normalize_model,
    };

    fn ip(value: &str) -> IpAddr {
        value.parse().expect("valid test address")
    }

    pub fn capabilities() -> BTreeSet<EgressCapability> {
        BTreeSet::from([
            EgressCapability::IdentitySourceSteering,
            EgressCapability::LeaseEpochFencing,
            EgressCapability::OriginalTupleWitness,
            EgressCapability::Ipv4TcpUdpNat,
            EgressCapability::Ipv6TcpUdpNat,
        ])
    }

    pub fn node(name: &str) -> EgressNode {
        EgressNode {
            name: name.to_owned(),
            uid: format!("uid-{name}"),
            capabilities: capabilities(),
        }
    }

    pub fn principal(name: &str) -> AuthenticatedEgressAgent {
        AuthenticatedEgressAgent {
            namespace: "unf-system".to_owned(),
            service_account: EGRESS_AGENT_SERVICE_ACCOUNT.to_owned(),
            pod_name: format!("unf-agent-{name}"),
            pod_uid: format!("pod-uid-{name}"),
            node_name: name.to_owned(),
            node_uid: format!("uid-{name}"),
            audience: EGRESS_AGENT_TOKEN_AUDIENCE.to_owned(),
        }
    }

    pub fn advertisement() -> EgressAgentAdvertisement {
        EgressAgentAdvertisement {
            distribution_schemas: BTreeSet::from([EGRESS_DISTRIBUTION_SCHEMA_VERSION]),
            host_state_schemas: BTreeSet::from([EGRESS_HOST_STATE_SCHEMA_VERSION]),
            capabilities: capabilities(),
        }
    }

    pub fn fixture() -> (EgressModel, EgressContractFacts, EgressBehaviorContract) {
        let source_node = node("worker-a");
        let model = normalize_model(
            vec![EgressAddressPool {
                name: "finance".to_owned(),
                uid: "pool-uid".to_owned(),
                provider: EgressProviderRef {
                    name: "static".to_owned(),
                    instance: "lab".to_owned(),
                },
                prefixes: vec![
                    IpPrefix {
                        address: ip("192.0.2.0"),
                        prefix_len: 24,
                    },
                    IpPrefix {
                        address: ip("2001:db8::"),
                        prefix_len: 64,
                    },
                ],
            }],
            vec![EgressIntent {
                owner: EgressIntentOwner {
                    scope: EgressIntentScope::Namespace("finance".to_owned()),
                    name: "payments".to_owned(),
                    uid: "intent-uid".to_owned(),
                },
                priority: DEFAULT_EGRESS_INTENT_PRIORITY,
                source: EgressSourceSelector::default(),
                destinations: EgressDestinations::Any,
                addresses: EgressAddressRequest::Pool {
                    name: "finance".to_owned(),
                    families: vec![AddressFamily::Ipv4, AddressFamily::Ipv6],
                    addresses_per_family: 1,
                },
            }],
        )
        .expect("valid model");
        let facts = EgressContractFacts {
            revisions: EgressContractRevisions {
                intent: Revision::new(11),
                identity: Revision::new(12),
                policy: Revision::new(13),
                allocation: Revision::new(14),
                gateway: Revision::new(15),
                reachability: Revision::new(16),
            },
            sources: vec![EgressSourceFact {
                identity: IdentityId::new(42),
                namespace: "finance".to_owned(),
                workload: "ledger-0".to_owned(),
                workload_uid: "ledger-uid".to_owned(),
                service_account: "settlement".to_owned(),
                namespace_labels: BTreeMap::new(),
                workload_labels: BTreeMap::new(),
                node: source_node.clone(),
                intent_uid: "intent-uid".to_owned(),
            }],
            policies: vec![EgressPolicyFact {
                identity: IdentityId::new(42),
                intent_uid: "intent-uid".to_owned(),
                allowed: true,
                policy_ids: vec![PolicyId::new(3)],
            }],
            allocations: vec![EgressAllocationFact {
                intent_uid: "intent-uid".to_owned(),
                pool_name: Some("finance".to_owned()),
                pool_uid: Some("pool-uid".to_owned()),
                addresses: vec![ip("192.0.2.20"), ip("2001:db8::20")],
                lease_epoch: 7,
            }],
            gateways: vec![EgressGatewayFact {
                intent_uid: "intent-uid".to_owned(),
                rank: 0,
                node: node("gateway-a"),
                lease_epoch: 7,
                ready: true,
                reachable: true,
            }],
        };
        let contract =
            EgressBehaviorContract::issue(&model, &facts, source_node, Revision::new(20))
                .expect("valid contract");
        (model, facts, contract)
    }

    pub fn admitted(revision: u64) -> AdmittedEgressProjection {
        let (model, facts, contract) = fixture();
        EgressNodeProjection::issue(
            &principal("worker-a"),
            &advertisement(),
            10,
            Revision::new(revision),
            contract,
        )
        .expect("issue projection")
        .admit(&principal("worker-a"), &advertisement(), &model, &facts)
        .expect("admit projection")
    }

    pub fn admitted_variant(revision: u64) -> AdmittedEgressProjection {
        let (model, mut facts, _) = fixture();
        facts.policies[0].policy_ids = vec![PolicyId::new(4)];
        let contract =
            EgressBehaviorContract::issue(&model, &facts, node("worker-a"), Revision::new(20))
                .expect("valid variant contract");
        EgressNodeProjection::issue(
            &principal("worker-a"),
            &advertisement(),
            10,
            Revision::new(revision),
            contract,
        )
        .expect("issue variant projection")
        .admit(&principal("worker-a"), &advertisement(), &model, &facts)
        .expect("admit variant projection")
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::*;
    use super::*;

    #[test]
    fn issue_binds_exact_authenticated_node_and_current_schemas() {
        let (_, _, contract) = fixture();
        let projection = EgressNodeProjection::issue(
            &principal("worker-a"),
            &advertisement(),
            9,
            Revision::new(4),
            contract,
        )
        .expect("issue exact projection");
        assert_eq!(projection.recipient.node_name, "worker-a");
        assert_eq!(
            projection.negotiated.host_state_schema,
            EGRESS_HOST_STATE_SCHEMA_VERSION
        );
    }

    #[test]
    fn issue_rejects_wrong_node_authentication_schema_and_capability() {
        let (_, _, contract) = fixture();
        assert_eq!(
            EgressNodeProjection::issue(
                &principal("worker-b"),
                &advertisement(),
                9,
                Revision::new(4),
                contract.clone(),
            ),
            Err(EgressDistributionError::RecipientMismatch)
        );
        let mut schemas = advertisement();
        schemas.host_state_schemas.clear();
        assert!(matches!(
            EgressNodeProjection::issue(
                &principal("worker-a"),
                &schemas,
                9,
                Revision::new(4),
                contract.clone(),
            ),
            Err(EgressDistributionError::NoCompatibleSchema { .. })
        ));
        let mut missing = advertisement();
        missing
            .capabilities
            .remove(&EgressCapability::Ipv6TcpUdpNat);
        assert_eq!(
            EgressNodeProjection::issue(
                &principal("worker-a"),
                &missing,
                9,
                Revision::new(4),
                contract,
            ),
            Err(EgressDistributionError::CapabilityMismatch)
        );
    }

    #[test]
    fn admission_independently_replays_and_rejects_wire_mutation() {
        let (model, facts, contract) = fixture();
        let projection = EgressNodeProjection::issue(
            &principal("worker-a"),
            &advertisement(),
            9,
            Revision::new(4),
            contract,
        )
        .expect("issue projection");
        projection
            .clone()
            .admit(&principal("worker-a"), &advertisement(), &model, &facts)
            .expect("independent replay");
        let mut mutation = projection;
        mutation.contract.plans[0].allocation.lease_epoch += 1;
        assert!(matches!(
            mutation.admit(&principal("worker-a"), &advertisement(), &model, &facts,),
            Err(EgressDistributionError::Contract(
                EgressContractError::ReplayMismatch
            ))
        ));
    }

    #[test]
    fn self_contained_envelope_replays_and_rejects_fact_mutation() {
        let (model, facts, contract) = fixture();
        let envelope = EgressNodeProjectionEnvelope::issue(
            &principal("worker-a"),
            &advertisement(),
            9,
            Revision::new(4),
            model,
            facts,
            contract,
        )
        .expect("issue replayable envelope");
        envelope
            .clone()
            .admit(&principal("worker-a"), &advertisement())
            .expect("agent independently replays the envelope");

        let mut mutation = envelope;
        mutation.facts.policies[0].allowed = false;
        assert!(matches!(
            mutation.admit(&principal("worker-a"), &advertisement()),
            Err(EgressDistributionError::Contract(_))
        ));
    }

    #[test]
    fn projection_ledger_fences_regression_and_same_revision_mutation() {
        let first = admitted(4);
        let mut ledger = EgressProjectionLedger::default();
        ledger.adopt(first.clone()).expect("adopt first");
        ledger.adopt(first.clone()).expect("exact replay");

        let mut mutation = first.clone().into_projection();
        mutation.recipient.node_uid.push_str("-mutated");
        assert_eq!(
            ledger.adopt(AdmittedEgressProjection(mutation)),
            Err(EgressDistributionError::SameRevisionMutation)
        );
        let mut regression = first.into_projection();
        regression.revision = Revision::new(3);
        assert_eq!(
            ledger.adopt(AdmittedEgressProjection(regression)),
            Err(EgressDistributionError::RevisionRegression)
        );
        ledger.adopt(admitted(5)).expect("advance revision");
        assert_eq!(
            ledger.current().expect("current").revision,
            Revision::new(5)
        );
    }

    #[test]
    fn wire_projection_rejects_unknown_fields() {
        let projection = admitted(4).into_projection();
        let mut value = serde_json::to_value(projection).expect("encode projection");
        value
            .as_object_mut()
            .expect("object")
            .insert("foreign".to_owned(), serde_json::json!(true));
        assert!(serde_json::from_value::<EgressNodeProjection>(value).is_err());
    }

    #[test]
    fn wire_envelope_rejects_unknown_fields() {
        let (model, facts, contract) = fixture();
        let envelope = EgressNodeProjectionEnvelope::issue(
            &principal("worker-a"),
            &advertisement(),
            9,
            Revision::new(4),
            model,
            facts,
            contract,
        )
        .expect("issue envelope");
        let mut value = serde_json::to_value(envelope).expect("encode envelope");
        value
            .as_object_mut()
            .expect("object")
            .insert("foreign".to_owned(), serde_json::json!(true));
        assert!(serde_json::from_value::<EgressNodeProjectionEnvelope>(value).is_err());
    }

    #[test]
    fn gateway_projection_aggregates_only_admitted_selected_source_contracts() {
        let source = admitted(4);
        let projection = EgressGatewayProjection::issue(
            &principal("gateway-a"),
            &advertisement(),
            10,
            Revision::new(5),
            std::slice::from_ref(&source),
        )
        .expect("issue gateway projection");
        assert_eq!(projection.gateway.uid, "uid-gateway-a");
        assert_eq!(projection.source_contracts.len(), 1);
        projection
            .clone()
            .admit(&principal("gateway-a"), &advertisement())
            .expect("admit exact gateway");
        assert_eq!(
            projection.admit(&principal("gateway-b"), &advertisement()),
            Err(EgressDistributionError::RecipientMismatch)
        );

        assert_eq!(
            EgressGatewayProjection::issue(
                &principal("gateway-a"),
                &advertisement(),
                10,
                Revision::new(5),
                &[],
            ),
            Err(EgressDistributionError::EmptyGatewayProjection)
        );
        assert_eq!(
            EgressGatewayProjection::issue(
                &principal("gateway-b"),
                &advertisement(),
                10,
                Revision::new(5),
                std::slice::from_ref(&source),
            ),
            Err(EgressDistributionError::GatewayNotSelected)
        );
        assert_eq!(
            EgressGatewayProjection::issue(
                &principal("gateway-a"),
                &advertisement(),
                10,
                Revision::new(5),
                &[source.clone(), source],
            ),
            Err(EgressDistributionError::InvalidGatewayContractOrder)
        );
    }

    #[test]
    fn application_acknowledgements_bind_exact_source_and_gateway_state() {
        let source = admitted(4);
        let source_ack = EgressSourceApplicationAcknowledgement::issue(&source, 1, 1)
            .expect("source application evidence");
        source_ack.verify(&source).expect("exact source evidence");
        let mut source_mutation = source_ack;
        source_mutation.source_count = 2;
        assert_eq!(
            source_mutation.verify(&source),
            Err(EgressDistributionError::ApplicationAcknowledgementMismatch)
        );
        let mut source_wire = serde_json::to_value(&source_mutation).expect("source JSON");
        source_wire["unknown"] = serde_json::json!(true);
        assert!(
            serde_json::from_value::<EgressSourceApplicationAcknowledgement>(source_wire).is_err()
        );

        let gateway = EgressGatewayProjection::issue(
            &principal("gateway-a"),
            &advertisement(),
            10,
            Revision::new(5),
            &[source],
        )
        .expect("gateway projection")
        .admit(&principal("gateway-a"), &advertisement())
        .expect("admitted gateway");
        let gateway_ack = EgressGatewayApplicationAcknowledgement::issue(&gateway)
            .expect("gateway application evidence");
        gateway_ack
            .verify(&gateway)
            .expect("exact gateway evidence");
        let mut gateway_mutation = gateway_ack;
        gateway_mutation.projection_digest.0[0] ^= 1;
        assert_eq!(
            gateway_mutation.verify(&gateway),
            Err(EgressDistributionError::ApplicationAcknowledgementMismatch)
        );
        let mut gateway_wire = serde_json::to_value(&gateway_mutation).expect("gateway JSON");
        gateway_wire["unknown"] = serde_json::json!(true);
        assert!(
            serde_json::from_value::<EgressGatewayApplicationAcknowledgement>(gateway_wire)
                .is_err()
        );

        let withdrawal = EgressGatewayProjection::withdraw(
            &principal("gateway-a"),
            &advertisement(),
            10,
            Revision::new(6),
        )
        .expect("gateway withdrawal")
        .admit(&principal("gateway-a"), &advertisement())
        .expect("admitted gateway withdrawal");
        let withdrawal_ack = EgressGatewayApplicationAcknowledgement::issue(&withdrawal)
            .expect("withdrawal application evidence");
        assert!(withdrawal_ack.withdrawn);
        assert_eq!(withdrawal_ack.contract_count, 0);
        assert_eq!(withdrawal_ack.source_count, 0);
        withdrawal_ack
            .verify(&withdrawal)
            .expect("exact withdrawal evidence");
        let mut active_mutation = withdrawal_ack;
        active_mutation.withdrawn = false;
        assert_eq!(
            active_mutation.verify(&withdrawal),
            Err(EgressDistributionError::ApplicationAcknowledgementMismatch)
        );
    }

    #[test]
    fn source_activation_grant_binds_every_selected_gateway_application() {
        let source = admitted(4);
        let gateway = EgressGatewayProjection::issue(
            &principal("gateway-a"),
            &advertisement(),
            10,
            Revision::new(5),
            std::slice::from_ref(&source),
        )
        .expect("gateway projection")
        .admit(&principal("gateway-a"), &advertisement())
        .expect("admitted gateway");
        let gateway_ack = EgressGatewayApplicationAcknowledgement::issue(&gateway)
            .expect("gateway application evidence");
        let grant = EgressSourceActivationGrant::issue(&source, vec![gateway_ack])
            .expect("source activation grant");
        grant
            .verify(&source)
            .expect("exact source activation grant");

        let mut missing = grant.clone();
        missing.gateway_applications.clear();
        assert_eq!(
            missing.verify(&source),
            Err(EgressDistributionError::ActivationGrantMismatch)
        );

        let mut withdrawn = grant.clone();
        withdrawn.gateway_applications[0].withdrawn = true;
        assert_eq!(
            withdrawn.verify(&source),
            Err(EgressDistributionError::ActivationGrantMismatch)
        );

        let mut digest_mutation = grant.clone();
        digest_mutation.grant_digest.0[0] ^= 1;
        assert_eq!(
            digest_mutation.verify(&source),
            Err(EgressDistributionError::ActivationGrantDigestMismatch)
        );

        let mut wire = serde_json::to_value(grant).expect("grant JSON");
        wire["unknown"] = serde_json::json!(true);
        assert!(serde_json::from_value::<EgressSourceActivationGrant>(wire).is_err());
    }

    #[test]
    fn admitted_gateway_independently_reproduces_source_flow_proof() {
        let source = admitted(4);
        let plan = &source.projection().contract.plans[0];
        let identity = plan.source.identity;
        let mut guard = crate::EgressAdmissionGuard::default();
        guard
            .fence(identity, plan.intent.clone(), plan.revisions.intent)
            .expect("fence explicit intent");
        guard
            .activate(identity, &source)
            .expect("activate source contract");
        let flow = EgressOriginalFlow {
            identity,
            source_address: "10.244.0.20".parse().expect("source"),
            destination_address: "198.51.100.30".parse().expect("destination"),
            source_port: 30_000,
            destination_port: 443,
            protocol: crate::EGRESS_PROTOCOL_TCP,
            fragmented: false,
        };
        let proof = EgressFlowProof::issue(&source, &guard, flow).expect("source proof");
        let gateway = EgressGatewayProjection::issue(
            &principal("gateway-a"),
            &advertisement(),
            10,
            Revision::new(5),
            &[source],
        )
        .expect("issue gateway projection")
        .admit(&principal("gateway-a"), &advertisement())
        .expect("admit gateway projection");
        gateway
            .verify_flow(&proof, flow)
            .expect("bilateral reproduction");

        let mutated = EgressOriginalFlow {
            destination_port: 8443,
            ..flow
        };
        assert_eq!(
            gateway.verify_flow(&proof, mutated),
            Err(EgressProofError::ProofMismatch)
        );
    }

    #[test]
    fn gateway_projection_wire_and_digest_mutation_fail_closed() {
        let source = admitted(4);
        let mut projection = EgressGatewayProjection::issue(
            &principal("gateway-a"),
            &advertisement(),
            10,
            Revision::new(5),
            &[source],
        )
        .expect("issue gateway projection");
        projection.projection_digest.0[0] ^= 1;
        assert_eq!(
            projection
                .clone()
                .admit(&principal("gateway-a"), &advertisement()),
            Err(EgressDistributionError::GatewayProjectionDigestMismatch)
        );
        let mut value = serde_json::to_value(projection).expect("encode projection");
        value
            .as_object_mut()
            .expect("object")
            .insert("trusted".to_owned(), serde_json::json!(true));
        assert!(serde_json::from_value::<EgressGatewayProjection>(value).is_err());
    }

    #[test]
    fn gateway_withdrawal_and_ledger_are_explicit_monotonic_and_idempotent() {
        let source = admitted(4);
        let active = EgressGatewayProjection::issue(
            &principal("gateway-a"),
            &advertisement(),
            10,
            Revision::new(5),
            &[source],
        )
        .expect("issue active gateway projection")
        .admit(&principal("gateway-a"), &advertisement())
        .expect("admit active gateway projection");
        let withdrawal = EgressGatewayProjection::withdraw(
            &principal("gateway-a"),
            &advertisement(),
            10,
            Revision::new(6),
        )
        .expect("issue explicit withdrawal");
        assert!(withdrawal.is_withdrawal());
        let withdrawal = withdrawal
            .admit(&principal("gateway-a"), &advertisement())
            .expect("admit explicit withdrawal");

        let mut ledger = EgressGatewayProjectionLedger::default();
        ledger.adopt(active.clone()).expect("adopt active state");
        ledger
            .adopt(withdrawal.clone())
            .expect("adopt newer withdrawal");
        ledger
            .adopt(withdrawal)
            .expect("exact withdrawal replay is idempotent");
        assert!(
            ledger
                .current()
                .expect("current projection")
                .is_withdrawal()
        );
        assert_eq!(
            ledger.adopt(active),
            Err(EgressDistributionError::RevisionRegression)
        );
    }
}
