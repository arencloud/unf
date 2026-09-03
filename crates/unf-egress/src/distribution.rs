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
    EgressContractError, EgressContractFacts, EgressFlowProof, EgressModel, EgressNode,
    EgressOriginalFlow, EgressProofError, MAX_EGRESS_CONTRACT_PLANS,
};

pub const EGRESS_DISTRIBUTION_SCHEMA_VERSION: u16 = 1;
pub const EGRESS_HOST_STATE_SCHEMA_VERSION: u16 = 1;
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum EgressDistributionError {
    #[error("invalid authenticated egress agent: {0}")]
    InvalidPrincipal(&'static str),
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
        projection.validate_structure()?;
        projection.projection_digest = projection.digest()?;
        Ok(projection)
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
        self.validate_structure()?;
        if self.projection_digest != self.digest()? {
            return Err(EgressDistributionError::GatewayProjectionDigestMismatch);
        }
        Ok(AdmittedEgressGatewayProjection(self))
    }

    fn validate_structure(&self) -> Result<(), EgressDistributionError> {
        if self.source_contracts.is_empty() {
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
}
