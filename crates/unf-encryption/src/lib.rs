//! Kubernetes-independent encryption intent, key authority, and attested path contracts.
//!
//! This crate is a pure userspace authority boundary. It contains public
//! Public intent and path contracts remain separate from Node-local private-key
//! authority. Kernel mutation, BPF state, packet processing, and Kubernetes
//! adapters deliberately live outside this crate.

mod activation_latch;
mod fast_path;
mod fast_path_transaction;
mod generation_distribution;
mod generation_frontier;
mod generation_reconciler;
mod kernel_provider;
mod key_authority;
mod local_orchestrator;
mod route_authority;

pub use activation_latch::*;
pub use fast_path::*;
pub use fast_path_transaction::*;
pub use generation_distribution::*;
pub use generation_frontier::*;
pub use generation_reconciler::*;
pub use kernel_provider::*;
pub use key_authority::*;
pub use local_orchestrator::*;
pub use route_authority::*;

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, SocketAddr};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use unf_common::{IdentityId, PolicyId, Revision};

pub const ENCRYPTION_MODEL_SCHEMA_VERSION: u16 = 1;
pub const ATTESTED_ENCRYPTION_PATH_CONTRACT_SCHEMA_VERSION: u16 = 1;
pub const MAX_ENCRYPTION_INTENTS: usize = 4_096;
pub const MAX_ENCRYPTION_IDENTITIES_PER_SELECTOR: usize = 4_096;
pub const MAX_ENCRYPTION_ENDPOINTS: usize = 4_096;
pub const MAX_ENCRYPTION_PATHS: usize = 65_536;
pub const MAX_ENCRYPTION_PREFIXES_PER_NODE: usize = 256;
pub const MAX_ENCRYPTION_UNDERLAY_ADDRESSES_PER_NODE: usize = 16;
pub const MAX_ENCRYPTION_FAILURE_OBSERVATIONS: usize = 4_096;
pub const MAX_ENCRYPTION_NAME_BYTES: usize = 253;
pub const MAX_WIREGUARD_INTERFACE_NAME_BYTES: usize = 15;
pub const MIN_DUAL_STACK_ENCRYPTION_MTU: u32 = 1_280;
pub const MAX_ENCRYPTION_MTU: u32 = 9_216;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum EncryptionBaseline {
    Native,
    Required,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum EncryptionDisposition {
    Native,
    Required,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "scope", content = "identities", rename_all = "camelCase")]
pub enum ManagedIdentitySelector {
    AllManaged,
    Identities(BTreeSet<IdentityId>),
}

impl ManagedIdentitySelector {
    #[must_use]
    pub fn selects(&self, identity: IdentityId) -> bool {
        match self {
            Self::AllManaged => true,
            Self::Identities(identities) => identities.contains(&identity),
        }
    }

    fn validate(&self) -> Result<(), EncryptionModelError> {
        if let Self::Identities(identities) = self {
            if identities.is_empty() {
                return Err(EncryptionModelError::EmptyIdentitySelector);
            }
            if identities.len() > MAX_ENCRYPTION_IDENTITIES_PER_SELECTOR {
                return Err(EncryptionModelError::TooManySelectorIdentities {
                    actual: identities.len(),
                    limit: MAX_ENCRYPTION_IDENTITIES_PER_SELECTOR,
                });
            }
            if identities.iter().any(|identity| identity.get() == 0) {
                return Err(EncryptionModelError::ZeroIdentity);
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EncryptionIntent {
    pub name: String,
    pub uid: String,
    pub priority: u32,
    pub sources: ManagedIdentitySelector,
    pub destinations: ManagedIdentitySelector,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EncryptionModel {
    pub schema_version: u16,
    pub cluster_id: String,
    pub baseline: EncryptionBaseline,
    pub intents: Vec<EncryptionIntent>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EncryptionRequirementDecision {
    pub disposition: EncryptionDisposition,
    pub intent_uids: Vec<String>,
}

impl EncryptionModel {
    /// Normalizes a complete encryption model.
    ///
    /// # Errors
    ///
    /// Rejects an unsupported schema, malformed cluster/intent identity,
    /// duplicate ownership, invalid selector, or capacity overflow.
    pub fn normalize(
        cluster_id: String,
        baseline: EncryptionBaseline,
        intents: Vec<EncryptionIntent>,
    ) -> Result<Self, EncryptionModelError> {
        validate_text(&cluster_id)
            .then_some(())
            .ok_or(EncryptionModelError::InvalidText {
                field: "cluster_id",
            })?;
        if intents.len() > MAX_ENCRYPTION_INTENTS {
            return Err(EncryptionModelError::TooManyIntents {
                actual: intents.len(),
                limit: MAX_ENCRYPTION_INTENTS,
            });
        }
        let mut names = BTreeSet::new();
        let mut uids = BTreeSet::new();
        for intent in &intents {
            if !validate_text(&intent.name) {
                return Err(EncryptionModelError::InvalidText {
                    field: "intent.name",
                });
            }
            if !validate_text(&intent.uid) {
                return Err(EncryptionModelError::InvalidText {
                    field: "intent.uid",
                });
            }
            if !names.insert(intent.name.as_str()) {
                return Err(EncryptionModelError::DuplicateIntentName(
                    intent.name.clone(),
                ));
            }
            if !uids.insert(intent.uid.as_str()) {
                return Err(EncryptionModelError::DuplicateIntentUid(intent.uid.clone()));
            }
            intent.sources.validate()?;
            intent.destinations.validate()?;
        }
        let mut intents = intents;
        intents.sort_by(|left, right| {
            (left.priority, left.name.as_str(), left.uid.as_str()).cmp(&(
                right.priority,
                right.name.as_str(),
                right.uid.as_str(),
            ))
        });
        Ok(Self {
            schema_version: ENCRYPTION_MODEL_SCHEMA_VERSION,
            cluster_id,
            baseline,
            intents,
        })
    }

    /// Resolves monotonic encryption requirements for an identity pair.
    ///
    /// Selective intents can add Required encryption but cannot weaken a
    /// Required cluster baseline.
    #[must_use]
    pub fn requirement(
        &self,
        source: IdentityId,
        destination: IdentityId,
    ) -> EncryptionRequirementDecision {
        let intent_uids = self
            .intents
            .iter()
            .filter(|intent| {
                intent.sources.selects(source) && intent.destinations.selects(destination)
            })
            .map(|intent| intent.uid.clone())
            .collect::<Vec<_>>();
        let disposition =
            if self.baseline == EncryptionBaseline::Required || !intent_uids.is_empty() {
                EncryptionDisposition::Required
            } else {
                EncryptionDisposition::Native
            };
        EncryptionRequirementDecision {
            disposition,
            intent_uids,
        }
    }

    fn verify_normalized(&self) -> Result<(), EncryptionModelError> {
        if self.schema_version != ENCRYPTION_MODEL_SCHEMA_VERSION {
            return Err(EncryptionModelError::UnsupportedSchema {
                actual: self.schema_version,
                expected: ENCRYPTION_MODEL_SCHEMA_VERSION,
            });
        }
        let expected =
            Self::normalize(self.cluster_id.clone(), self.baseline, self.intents.clone())?;
        if *self != expected {
            return Err(EncryptionModelError::NotNormalized);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum EncryptionModelError {
    #[error("unsupported encryption model schema {actual}; expected {expected}")]
    UnsupportedSchema { actual: u16, expected: u16 },
    #[error("invalid bounded encryption text field {field}")]
    InvalidText { field: &'static str },
    #[error("encryption model has {actual} intents; limit is {limit}")]
    TooManyIntents { actual: usize, limit: usize },
    #[error("encryption selector has {actual} identities; limit is {limit}")]
    TooManySelectorIdentities { actual: usize, limit: usize },
    #[error("encryption selector cannot be empty")]
    EmptyIdentitySelector,
    #[error("identity zero is reserved")]
    ZeroIdentity,
    #[error("duplicate encryption intent name {0}")]
    DuplicateIntentName(String),
    #[error("duplicate encryption intent UID {0}")]
    DuplicateIntentUid(String),
    #[error("encryption model is not canonical")]
    NotNormalized,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct IpPrefix {
    pub address: IpAddr,
    pub prefix_len: u8,
}

impl IpPrefix {
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
        self.contains(other.address) || other.contains(self.address)
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
pub enum EncryptionCapability {
    KernelWireGuard,
    DualStackUnderlay,
    PolicyRouting,
    TwoEpochRotation,
    EncryptedPathChallenge,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EncryptionNode {
    pub cluster_id: String,
    pub name: String,
    pub uid: String,
    pub pod_cidrs: Vec<IpPrefix>,
    pub underlay_addresses: Vec<IpAddr>,
    pub capabilities: BTreeSet<EncryptionCapability>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EncryptionEndpointFact {
    pub identity: IdentityId,
    pub workload_uid: String,
    pub node: EncryptionNode,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EncryptionPolicyFact {
    pub source: IdentityId,
    pub destination: IdentityId,
    pub allowed: bool,
    pub policy_ids: Vec<PolicyId>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct WireGuardPublicKey(pub [u8; 32]);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum EncryptionKeyPhase {
    Prepared,
    Active,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EncryptionKeyFact {
    pub node_uid: String,
    pub epoch: u64,
    pub public_key: WireGuardPublicKey,
    pub phase: EncryptionKeyPhase,
    pub valid_from_unix_ms: u64,
    pub valid_until_unix_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum EncryptionPathClass {
    ManagedPod,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EncryptionPathFact {
    pub source_node_uid: String,
    pub destination_node_uid: String,
    pub epoch: u64,
    pub path_class: EncryptionPathClass,
    pub peer_endpoint: SocketAddr,
    pub allowed_ips: Vec<IpPrefix>,
    pub interface_name: String,
    pub route_table: u32,
    pub fwmark: u32,
    pub mtu: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EncryptionContractRevisions {
    pub intent: Revision,
    pub identity: Revision,
    pub policy: Revision,
    pub routing: Revision,
    pub key: Revision,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EncryptionContractFacts {
    pub revisions: EncryptionContractRevisions,
    pub active_epoch: u64,
    pub endpoints: Vec<EncryptionEndpointFact>,
    pub policies: Vec<EncryptionPolicyFact>,
    pub keys: Vec<EncryptionKeyFact>,
    pub paths: Vec<EncryptionPathFact>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EncryptionPublicKeyDigest(pub [u8; 32]);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EncryptionKeyBinding {
    pub node_uid: String,
    pub epoch: u64,
    pub public_key: WireGuardPublicKey,
    pub public_key_digest: EncryptionPublicKeyDigest,
    pub phase: EncryptionKeyPhase,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EncryptionPolicyBinding {
    pub policy_ids: Vec<PolicyId>,
    pub revision: Revision,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EncryptionTransportBinding {
    pub forward: EncryptionPathFact,
    pub reverse: EncryptionPathFact,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AttestedEncryptionPathPlan {
    pub source: EncryptionEndpointFact,
    pub destination: EncryptionEndpointFact,
    pub disposition: EncryptionDisposition,
    pub intent_uids: Vec<String>,
    pub policy: EncryptionPolicyBinding,
    pub source_key: EncryptionKeyBinding,
    pub destination_key: EncryptionKeyBinding,
    pub transport: EncryptionTransportBinding,
    pub revisions: EncryptionContractRevisions,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum EncryptionInvariant {
    ModelNormalized,
    ExactNodeOwnership,
    SameClusterBound,
    IdentityPairSelected,
    PolicyAllowBeforeEncryption,
    RequiredNoPlaintextFallback,
    PublicKeysOnly,
    EpochAndLifetimeBound,
    BidirectionalRoutesExact,
    AllowedIpsDisjoint,
    CapabilitiesAdmitted,
    StateBounded,
    FailureEnvelopeBounded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum EncryptionFailureClass {
    SourceKeyUnavailable,
    DestinationKeyUnavailable,
    ForwardPathUnavailable,
    ReversePathUnavailable,
    MutualEvidenceUnavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum EncryptionFailureOutcome {
    DenyRequired,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EncryptionFailureObservation {
    pub source: IdentityId,
    pub source_workload_uid: String,
    pub destination: IdentityId,
    pub destination_workload_uid: String,
    pub class: EncryptionFailureClass,
    pub outcome: EncryptionFailureOutcome,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EncryptionFailureEnvelope {
    pub observations: Vec<EncryptionFailureObservation>,
    pub total_observations: u64,
    pub truncated: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AttestedEncryptionContractDigest(pub [u8; 32]);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EncryptionDecisionWitness(pub [u8; 16]);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AttestedEncryptionPathContract {
    pub schema_version: u16,
    pub contract_revision: Revision,
    pub local_node: EncryptionNode,
    pub valid_from_unix_ms: u64,
    pub valid_until_unix_ms: u64,
    pub plans: Vec<AttestedEncryptionPathPlan>,
    pub verified_invariants: Vec<EncryptionInvariant>,
    pub failure_envelope: EncryptionFailureEnvelope,
    pub contract_digest: AttestedEncryptionContractDigest,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum EncryptionContractError {
    #[error(transparent)]
    InvalidModel(#[from] EncryptionModelError),
    #[error("unsupported encryption contract schema {actual}; expected {expected}")]
    UnsupportedSchema { actual: u16, expected: u16 },
    #[error("encryption contract revisions, epoch, and lifetime must be nonzero and ordered")]
    InvalidRevisionOrLifetime,
    #[error("invalid encryption Node: {0}")]
    InvalidNode(&'static str),
    #[error("encryption contract has {actual} {kind}; limit is {limit}")]
    Capacity {
        kind: &'static str,
        actual: usize,
        limit: usize,
    },
    #[error("invalid or duplicate endpoint fact")]
    InvalidEndpoint,
    #[error("required identity pair is missing one exact policy fact")]
    MissingPolicy,
    #[error("allowed policy fact contains invalid or duplicate policy IDs")]
    InvalidPolicy,
    #[error("required identity pair is missing one exact Node key fact")]
    MissingKey,
    #[error("invalid public key epoch or lifetime")]
    InvalidKey,
    #[error("required identity pair is missing one exact directional path fact")]
    MissingPath,
    #[error("invalid encryption transport path: {0}")]
    InvalidPath(&'static str),
    #[error("required encryption capability {0:?} is unavailable")]
    MissingCapability(EncryptionCapability),
    #[error("active AllowedIPs overlap across different destination Nodes")]
    AmbiguousAllowedIp,
    #[error("encryption contract differs from independent replay")]
    ReplayMismatch,
    #[error("encryption contract canonical encoding failed: {0}")]
    CanonicalEncoding(String),
    #[error("encryption decision witness references an unknown plan")]
    UnknownWitnessSelection,
}

impl AttestedEncryptionPathContract {
    /// Issues one canonical exact-source-Node contract from complete facts.
    ///
    /// # Errors
    ///
    /// Rejects invalid models, Nodes, revisions, endpoint/policy/key/path facts,
    /// capabilities, bounds, ambiguous `AllowedIPs`, or encoding failures.
    pub fn issue(
        model: &EncryptionModel,
        facts: &EncryptionContractFacts,
        local_node: EncryptionNode,
        contract_revision: Revision,
        valid_from_unix_ms: u64,
        valid_until_unix_ms: u64,
    ) -> Result<Self, EncryptionContractError> {
        compile_contract(
            model,
            facts,
            local_node,
            contract_revision,
            valid_from_unix_ms,
            valid_until_unix_ms,
        )
    }

    /// Independently replays all model and fact inputs and compares every byte.
    ///
    /// # Errors
    ///
    /// Rejects schema drift, a wrong local Node, stale facts, or mutation.
    pub fn verify(
        &self,
        model: &EncryptionModel,
        facts: &EncryptionContractFacts,
        local_node: &EncryptionNode,
    ) -> Result<(), EncryptionContractError> {
        if self.schema_version != ATTESTED_ENCRYPTION_PATH_CONTRACT_SCHEMA_VERSION {
            return Err(EncryptionContractError::UnsupportedSchema {
                actual: self.schema_version,
                expected: ATTESTED_ENCRYPTION_PATH_CONTRACT_SCHEMA_VERSION,
            });
        }
        let expected = compile_contract(
            model,
            facts,
            local_node.clone(),
            self.contract_revision,
            self.valid_from_unix_ms,
            self.valid_until_unix_ms,
        )?;
        if *self != expected {
            return Err(EncryptionContractError::ReplayMismatch);
        }
        Ok(())
    }

    /// Verifies the self-contained commitment for durable-state corruption
    /// detection. Fresh activation still requires [`Self::verify`].
    ///
    /// # Errors
    ///
    /// Rejects schema drift or any digest-covered mutation.
    pub fn verify_integrity(&self) -> Result<(), EncryptionContractError> {
        if self.schema_version != ATTESTED_ENCRYPTION_PATH_CONTRACT_SCHEMA_VERSION {
            return Err(EncryptionContractError::UnsupportedSchema {
                actual: self.schema_version,
                expected: ATTESTED_ENCRYPTION_PATH_CONTRACT_SCHEMA_VERSION,
            });
        }
        let expected = contract_digest(
            self.contract_revision,
            &self.local_node,
            self.valid_from_unix_ms,
            self.valid_until_unix_ms,
            &self.plans,
            &self.verified_invariants,
            &self.failure_envelope,
        )?;
        if self.contract_digest != expected {
            return Err(EncryptionContractError::ReplayMismatch);
        }
        Ok(())
    }

    /// Derives compact provenance for one exact plan.
    ///
    /// The witness is not authority and resolves only with the retained full
    /// contract.
    ///
    /// # Errors
    ///
    /// Rejects an index outside canonical plan state.
    pub fn decision_witness(
        &self,
        plan_index: usize,
    ) -> Result<EncryptionDecisionWitness, EncryptionContractError> {
        let plan = self
            .plans
            .get(plan_index)
            .ok_or(EncryptionContractError::UnknownWitnessSelection)?;
        let material = serde_json::to_vec(&(
            plan.source.identity,
            plan.source.workload_uid.as_str(),
            plan.destination.identity,
            plan.destination.workload_uid.as_str(),
            plan.source.node.uid.as_str(),
            plan.destination.node.uid.as_str(),
            plan.source_key.epoch,
            plan.transport.forward.route_table,
            plan.transport.forward.fwmark,
            plan.revisions,
        ))
        .map_err(|error| EncryptionContractError::CanonicalEncoding(error.to_string()))?;
        let mut hasher = Sha256::new();
        hasher.update(b"unf.encryption-decision-witness.v1\0");
        hasher.update(self.contract_digest.0);
        hasher.update(material);
        let digest = hasher.finalize();
        let mut witness = [0_u8; 16];
        witness.copy_from_slice(&digest[..16]);
        Ok(EncryptionDecisionWitness(witness))
    }
}

fn compile_contract(
    model: &EncryptionModel,
    facts: &EncryptionContractFacts,
    local_node: EncryptionNode,
    contract_revision: Revision,
    valid_from_unix_ms: u64,
    valid_until_unix_ms: u64,
) -> Result<AttestedEncryptionPathContract, EncryptionContractError> {
    model.verify_normalized()?;
    validate_revisions_and_lifetime(
        facts,
        contract_revision,
        valid_from_unix_ms,
        valid_until_unix_ms,
    )?;
    let local_node = canonical_node(local_node)?;
    if local_node.cluster_id != model.cluster_id {
        return Err(EncryptionContractError::InvalidNode(
            "local cluster identity mismatch",
        ));
    }
    validate_fact_bounds(facts)?;
    let endpoints = canonical_endpoints(&facts.endpoints)?;
    if endpoints
        .iter()
        .any(|endpoint| endpoint.node.cluster_id != model.cluster_id)
    {
        return Err(EncryptionContractError::InvalidNode(
            "cross-cluster endpoint is outside Phase 9",
        ));
    }
    if endpoints.iter().any(|endpoint| {
        (endpoint.node.uid == local_node.uid && endpoint.node != local_node)
            || (endpoint.node.name == local_node.name && endpoint.node.uid != local_node.uid)
    }) {
        return Err(EncryptionContractError::InvalidNode(
            "local Node identity conflicts with endpoint facts",
        ));
    }
    let policies = canonical_policies(&facts.policies)?;
    let keys = canonical_keys(&facts.keys)?;
    let paths = canonical_paths(&facts.paths)?;
    let context = ContractCompileContext {
        model,
        facts,
        policies: &policies,
        keys: &keys,
        paths: &paths,
        valid_from_unix_ms,
        valid_until_unix_ms,
    };
    let plans = compile_plans(&context, &local_node, &endpoints)?;
    let verified_invariants = vec![
        EncryptionInvariant::ModelNormalized,
        EncryptionInvariant::ExactNodeOwnership,
        EncryptionInvariant::SameClusterBound,
        EncryptionInvariant::IdentityPairSelected,
        EncryptionInvariant::PolicyAllowBeforeEncryption,
        EncryptionInvariant::RequiredNoPlaintextFallback,
        EncryptionInvariant::PublicKeysOnly,
        EncryptionInvariant::EpochAndLifetimeBound,
        EncryptionInvariant::BidirectionalRoutesExact,
        EncryptionInvariant::AllowedIpsDisjoint,
        EncryptionInvariant::CapabilitiesAdmitted,
        EncryptionInvariant::StateBounded,
        EncryptionInvariant::FailureEnvelopeBounded,
    ];
    let failure_envelope = failure_envelope(&plans);
    let contract_digest = contract_digest(
        contract_revision,
        &local_node,
        valid_from_unix_ms,
        valid_until_unix_ms,
        &plans,
        &verified_invariants,
        &failure_envelope,
    )?;
    Ok(AttestedEncryptionPathContract {
        schema_version: ATTESTED_ENCRYPTION_PATH_CONTRACT_SCHEMA_VERSION,
        contract_revision,
        local_node,
        valid_from_unix_ms,
        valid_until_unix_ms,
        plans,
        verified_invariants,
        failure_envelope,
        contract_digest,
    })
}

struct ContractCompileContext<'a> {
    model: &'a EncryptionModel,
    facts: &'a EncryptionContractFacts,
    policies: &'a [EncryptionPolicyFact],
    keys: &'a [EncryptionKeyFact],
    paths: &'a [EncryptionPathFact],
    valid_from_unix_ms: u64,
    valid_until_unix_ms: u64,
}

fn compile_plans(
    context: &ContractCompileContext<'_>,
    local_node: &EncryptionNode,
    endpoints: &[EncryptionEndpointFact],
) -> Result<Vec<AttestedEncryptionPathPlan>, EncryptionContractError> {
    let mut plans = Vec::new();
    for source in endpoints
        .iter()
        .filter(|endpoint| endpoint.node == *local_node)
    {
        for destination in endpoints
            .iter()
            .filter(|endpoint| endpoint.node.uid != local_node.uid)
        {
            if let Some(plan) = compile_plan(context, source, destination)? {
                plans.push(plan);
            }
        }
    }
    if plans.len() > MAX_ENCRYPTION_PATHS {
        return Err(EncryptionContractError::Capacity {
            kind: "plans",
            actual: plans.len(),
            limit: MAX_ENCRYPTION_PATHS,
        });
    }
    plans.sort_by(|left, right| plan_key(left).cmp(&plan_key(right)));
    validate_disjoint_allowed_ips(&plans)?;
    Ok(plans)
}

fn compile_plan(
    context: &ContractCompileContext<'_>,
    source: &EncryptionEndpointFact,
    destination: &EncryptionEndpointFact,
) -> Result<Option<AttestedEncryptionPathPlan>, EncryptionContractError> {
    let requirement = context
        .model
        .requirement(source.identity, destination.identity);
    if requirement.disposition == EncryptionDisposition::Native {
        return Ok(None);
    }
    let policy = unique(context.policies.iter().filter(|policy| {
        policy.source == source.identity && policy.destination == destination.identity
    }))
    .ok_or(EncryptionContractError::MissingPolicy)?;
    if !policy.allowed {
        return Ok(None);
    }
    if policy.policy_ids.is_empty() {
        return Err(EncryptionContractError::InvalidPolicy);
    }
    let source_key = key_binding(
        context.keys,
        &source.node,
        context.facts.active_epoch,
        context.valid_from_unix_ms,
        context.valid_until_unix_ms,
    )?;
    let destination_key = key_binding(
        context.keys,
        &destination.node,
        context.facts.active_epoch,
        context.valid_from_unix_ms,
        context.valid_until_unix_ms,
    )?;
    let forward = directional_path(
        context.paths,
        &source.node.uid,
        &destination.node.uid,
        context.facts.active_epoch,
    )?;
    let reverse = directional_path(
        context.paths,
        &destination.node.uid,
        &source.node.uid,
        context.facts.active_epoch,
    )?;
    validate_path(&forward, &source.node, &destination.node)?;
    validate_path(&reverse, &destination.node, &source.node)?;
    Ok(Some(AttestedEncryptionPathPlan {
        source: source.clone(),
        destination: destination.clone(),
        disposition: EncryptionDisposition::Required,
        intent_uids: requirement.intent_uids,
        policy: EncryptionPolicyBinding {
            policy_ids: policy.policy_ids.clone(),
            revision: context.facts.revisions.policy,
        },
        source_key,
        destination_key,
        transport: EncryptionTransportBinding { forward, reverse },
        revisions: context.facts.revisions,
    }))
}

fn directional_path(
    paths: &[EncryptionPathFact],
    source_node_uid: &str,
    destination_node_uid: &str,
    epoch: u64,
) -> Result<EncryptionPathFact, EncryptionContractError> {
    unique(paths.iter().filter(|path| {
        path.source_node_uid == source_node_uid
            && path.destination_node_uid == destination_node_uid
            && path.epoch == epoch
    }))
    .cloned()
    .ok_or(EncryptionContractError::MissingPath)
}

fn validate_revisions_and_lifetime(
    facts: &EncryptionContractFacts,
    contract_revision: Revision,
    valid_from_unix_ms: u64,
    valid_until_unix_ms: u64,
) -> Result<(), EncryptionContractError> {
    let revisions = facts.revisions;
    if contract_revision.get() == 0
        || revisions.intent.get() == 0
        || revisions.identity.get() == 0
        || revisions.policy.get() == 0
        || revisions.routing.get() == 0
        || revisions.key.get() == 0
        || facts.active_epoch == 0
        || valid_from_unix_ms == 0
        || valid_from_unix_ms >= valid_until_unix_ms
    {
        return Err(EncryptionContractError::InvalidRevisionOrLifetime);
    }
    Ok(())
}

fn validate_fact_bounds(facts: &EncryptionContractFacts) -> Result<(), EncryptionContractError> {
    for (kind, actual, limit) in [
        ("endpoints", facts.endpoints.len(), MAX_ENCRYPTION_ENDPOINTS),
        ("policies", facts.policies.len(), MAX_ENCRYPTION_PATHS),
        ("keys", facts.keys.len(), MAX_ENCRYPTION_ENDPOINTS * 2),
        ("paths", facts.paths.len(), MAX_ENCRYPTION_PATHS * 2),
    ] {
        if actual > limit {
            return Err(EncryptionContractError::Capacity {
                kind,
                actual,
                limit,
            });
        }
    }
    Ok(())
}

fn canonical_node(mut node: EncryptionNode) -> Result<EncryptionNode, EncryptionContractError> {
    if !validate_text(&node.cluster_id)
        || !validate_text(&node.name)
        || !validate_text(&node.uid)
        || node.pod_cidrs.is_empty()
        || node.pod_cidrs.len() > MAX_ENCRYPTION_PREFIXES_PER_NODE
        || node.underlay_addresses.is_empty()
        || node.underlay_addresses.len() > MAX_ENCRYPTION_UNDERLAY_ADDRESSES_PER_NODE
    {
        return Err(EncryptionContractError::InvalidNode(
            "invalid identity or bounds",
        ));
    }
    node.pod_cidrs.sort_unstable();
    node.underlay_addresses.sort_unstable();
    if node.pod_cidrs.iter().any(|prefix| !prefix.is_canonical())
        || has_overlapping_prefixes(&node.pod_cidrs)
        || node.underlay_addresses.iter().any(|address| {
            address.is_unspecified() || address.is_loopback() || address.is_multicast()
        })
        || node
            .underlay_addresses
            .windows(2)
            .any(|pair| pair[0] == pair[1])
    {
        return Err(EncryptionContractError::InvalidNode(
            "invalid or duplicate network identity",
        ));
    }
    let required = [
        EncryptionCapability::KernelWireGuard,
        EncryptionCapability::DualStackUnderlay,
        EncryptionCapability::PolicyRouting,
        EncryptionCapability::TwoEpochRotation,
        EncryptionCapability::EncryptedPathChallenge,
    ];
    for capability in required {
        if !node.capabilities.contains(&capability) {
            return Err(EncryptionContractError::MissingCapability(capability));
        }
    }
    Ok(node)
}

fn canonical_endpoints(
    endpoints: &[EncryptionEndpointFact],
) -> Result<Vec<EncryptionEndpointFact>, EncryptionContractError> {
    let mut endpoints = endpoints.to_vec();
    for endpoint in &mut endpoints {
        if endpoint.identity.get() == 0 || !validate_text(&endpoint.workload_uid) {
            return Err(EncryptionContractError::InvalidEndpoint);
        }
        endpoint.node = canonical_node(endpoint.node.clone())?;
    }
    let mut node_uids = BTreeMap::<String, EncryptionNode>::new();
    let mut node_names = BTreeMap::<String, String>::new();
    let mut workloads = BTreeMap::<String, (IdentityId, String)>::new();
    for endpoint in &endpoints {
        if node_uids
            .insert(endpoint.node.uid.clone(), endpoint.node.clone())
            .is_some_and(|previous| previous != endpoint.node)
            || node_names
                .insert(endpoint.node.name.clone(), endpoint.node.uid.clone())
                .is_some_and(|previous| previous != endpoint.node.uid)
            || workloads
                .insert(
                    endpoint.workload_uid.clone(),
                    (endpoint.identity, endpoint.node.uid.clone()),
                )
                .is_some_and(|previous| previous != (endpoint.identity, endpoint.node.uid.clone()))
        {
            return Err(EncryptionContractError::InvalidNode(
                "Node name, UID, or workload UID has conflicting facts",
            ));
        }
    }
    endpoints.sort_by(|left, right| endpoint_key(left).cmp(&endpoint_key(right)));
    if endpoints
        .windows(2)
        .any(|pair| endpoint_key(&pair[0]) == endpoint_key(&pair[1]))
    {
        return Err(EncryptionContractError::InvalidEndpoint);
    }
    Ok(endpoints)
}

fn canonical_policies(
    policies: &[EncryptionPolicyFact],
) -> Result<Vec<EncryptionPolicyFact>, EncryptionContractError> {
    let mut policies = policies.to_vec();
    for policy in &mut policies {
        if policy.source.get() == 0 || policy.destination.get() == 0 {
            return Err(EncryptionContractError::InvalidPolicy);
        }
        policy.policy_ids.sort_unstable();
        if policy.policy_ids.iter().any(|id| id.get() == 0)
            || policy.policy_ids.windows(2).any(|pair| pair[0] == pair[1])
        {
            return Err(EncryptionContractError::InvalidPolicy);
        }
    }
    policies.sort_by_key(|policy| (policy.source, policy.destination));
    if policies
        .windows(2)
        .any(|pair| (pair[0].source, pair[0].destination) == (pair[1].source, pair[1].destination))
    {
        return Err(EncryptionContractError::InvalidPolicy);
    }
    Ok(policies)
}

fn canonical_keys(
    keys: &[EncryptionKeyFact],
) -> Result<Vec<EncryptionKeyFact>, EncryptionContractError> {
    let mut keys = keys.to_vec();
    let mut public_keys = BTreeSet::new();
    for key in &keys {
        if !validate_text(&key.node_uid)
            || key.epoch == 0
            || key.public_key.0 == [0; 32]
            || key.valid_from_unix_ms == 0
            || key.valid_from_unix_ms >= key.valid_until_unix_ms
        {
            return Err(EncryptionContractError::InvalidKey);
        }
        if !public_keys.insert((key.epoch, key.public_key)) {
            return Err(EncryptionContractError::InvalidKey);
        }
    }
    keys.sort_by(|left, right| {
        (left.node_uid.as_str(), left.epoch).cmp(&(right.node_uid.as_str(), right.epoch))
    });
    if keys.windows(2).any(|pair| {
        (pair[0].node_uid.as_str(), pair[0].epoch) == (pair[1].node_uid.as_str(), pair[1].epoch)
    }) {
        return Err(EncryptionContractError::InvalidKey);
    }
    Ok(keys)
}

fn has_overlapping_prefixes(prefixes: &[IpPrefix]) -> bool {
    prefixes.iter().enumerate().any(|(index, prefix)| {
        prefixes
            .iter()
            .skip(index + 1)
            .any(|other| prefix.overlaps(*other))
    })
}

fn canonical_paths(
    paths: &[EncryptionPathFact],
) -> Result<Vec<EncryptionPathFact>, EncryptionContractError> {
    let mut paths = paths.to_vec();
    for path in &mut paths {
        path.allowed_ips.sort_unstable();
        if path.allowed_ips.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(EncryptionContractError::InvalidPath("duplicate AllowedIPs"));
        }
    }
    paths.sort_by(|left, right| path_key(left).cmp(&path_key(right)));
    if paths
        .windows(2)
        .any(|pair| path_key(&pair[0]) == path_key(&pair[1]))
    {
        return Err(EncryptionContractError::InvalidPath(
            "duplicate directional path",
        ));
    }
    Ok(paths)
}

fn key_binding(
    keys: &[EncryptionKeyFact],
    node: &EncryptionNode,
    epoch: u64,
    valid_from_unix_ms: u64,
    valid_until_unix_ms: u64,
) -> Result<EncryptionKeyBinding, EncryptionContractError> {
    let key = unique(
        keys.iter()
            .filter(|key| key.node_uid == node.uid && key.epoch == epoch),
    )
    .ok_or(EncryptionContractError::MissingKey)?;
    if key.valid_from_unix_ms > valid_from_unix_ms || key.valid_until_unix_ms < valid_until_unix_ms
    {
        return Err(EncryptionContractError::InvalidKey);
    }
    Ok(EncryptionKeyBinding {
        node_uid: key.node_uid.clone(),
        epoch,
        public_key: key.public_key,
        public_key_digest: public_key_digest(key.public_key),
        phase: key.phase,
    })
}

fn validate_path(
    path: &EncryptionPathFact,
    source: &EncryptionNode,
    destination: &EncryptionNode,
) -> Result<(), EncryptionContractError> {
    if path.source_node_uid != source.uid || path.destination_node_uid != destination.uid {
        return Err(EncryptionContractError::InvalidPath(
            "Node identity mismatch",
        ));
    }
    if path.path_class != EncryptionPathClass::ManagedPod
        || path.epoch == 0
        || path.peer_endpoint.port() == 0
        || !destination
            .underlay_addresses
            .contains(&path.peer_endpoint.ip())
        || path.allowed_ips != destination.pod_cidrs
        || !valid_interface_name(&path.interface_name)
        || path.route_table == 0
        || path.fwmark == 0
        || !(MIN_DUAL_STACK_ENCRYPTION_MTU..=MAX_ENCRYPTION_MTU).contains(&path.mtu)
    {
        return Err(EncryptionContractError::InvalidPath(
            "endpoint, AllowedIPs, interface, route, mark, or MTU mismatch",
        ));
    }
    Ok(())
}

fn validate_disjoint_allowed_ips(
    plans: &[AttestedEncryptionPathPlan],
) -> Result<(), EncryptionContractError> {
    let mut ownership = BTreeMap::<IpPrefix, &str>::new();
    for plan in plans {
        for prefix in &plan.transport.forward.allowed_ips {
            for (owned, node_uid) in &ownership {
                if *node_uid != plan.destination.node.uid && prefix.overlaps(*owned) {
                    return Err(EncryptionContractError::AmbiguousAllowedIp);
                }
            }
            ownership.insert(*prefix, plan.destination.node.uid.as_str());
        }
    }
    Ok(())
}

fn failure_envelope(plans: &[AttestedEncryptionPathPlan]) -> EncryptionFailureEnvelope {
    const CLASSES: [EncryptionFailureClass; 5] = [
        EncryptionFailureClass::SourceKeyUnavailable,
        EncryptionFailureClass::DestinationKeyUnavailable,
        EncryptionFailureClass::ForwardPathUnavailable,
        EncryptionFailureClass::ReversePathUnavailable,
        EncryptionFailureClass::MutualEvidenceUnavailable,
    ];
    let total = plans.len().saturating_mul(CLASSES.len());
    let mut observations = Vec::with_capacity(total.min(MAX_ENCRYPTION_FAILURE_OBSERVATIONS));
    for plan in plans {
        for class in CLASSES {
            if observations.len() == MAX_ENCRYPTION_FAILURE_OBSERVATIONS {
                break;
            }
            observations.push(EncryptionFailureObservation {
                source: plan.source.identity,
                source_workload_uid: plan.source.workload_uid.clone(),
                destination: plan.destination.identity,
                destination_workload_uid: plan.destination.workload_uid.clone(),
                class,
                outcome: EncryptionFailureOutcome::DenyRequired,
            });
        }
    }
    EncryptionFailureEnvelope {
        observations,
        total_observations: u64::try_from(total).unwrap_or(u64::MAX),
        truncated: total > MAX_ENCRYPTION_FAILURE_OBSERVATIONS,
    }
}

fn public_key_digest(key: WireGuardPublicKey) -> EncryptionPublicKeyDigest {
    let mut hasher = Sha256::new();
    hasher.update(b"unf.wireguard-public-key.v1\0");
    hasher.update(key.0);
    EncryptionPublicKeyDigest(hasher.finalize().into())
}

fn contract_digest(
    contract_revision: Revision,
    local_node: &EncryptionNode,
    valid_from_unix_ms: u64,
    valid_until_unix_ms: u64,
    plans: &[AttestedEncryptionPathPlan],
    verified_invariants: &[EncryptionInvariant],
    failure_envelope: &EncryptionFailureEnvelope,
) -> Result<AttestedEncryptionContractDigest, EncryptionContractError> {
    let material = serde_json::to_vec(&(
        ATTESTED_ENCRYPTION_PATH_CONTRACT_SCHEMA_VERSION,
        contract_revision,
        local_node,
        valid_from_unix_ms,
        valid_until_unix_ms,
        plans,
        verified_invariants,
        failure_envelope,
    ))
    .map_err(|error| EncryptionContractError::CanonicalEncoding(error.to_string()))?;
    let mut hasher = Sha256::new();
    hasher.update(b"unf.attested-encryption-path-contract.v1\0");
    hasher.update(material);
    Ok(AttestedEncryptionContractDigest(hasher.finalize().into()))
}

fn endpoint_key(endpoint: &EncryptionEndpointFact) -> (IdentityId, &str, &str) {
    (
        endpoint.identity,
        endpoint.workload_uid.as_str(),
        endpoint.node.uid.as_str(),
    )
}

fn path_key(path: &EncryptionPathFact) -> (&str, &str, u64) {
    (
        path.source_node_uid.as_str(),
        path.destination_node_uid.as_str(),
        path.epoch,
    )
}

fn plan_key(plan: &AttestedEncryptionPathPlan) -> (IdentityId, &str, IdentityId, &str) {
    (
        plan.source.identity,
        plan.source.workload_uid.as_str(),
        plan.destination.identity,
        plan.destination.workload_uid.as_str(),
    )
}

fn unique<'a, T>(mut values: impl Iterator<Item = &'a T>) -> Option<&'a T> {
    let value = values.next()?;
    values.next().is_none().then_some(value)
}

fn validate_text(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_ENCRYPTION_NAME_BYTES
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

fn valid_interface_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_WIREGUARD_INTERFACE_NAME_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use proptest::collection::btree_set;
    use proptest::prelude::*;

    use super::*;

    fn ip(value: &str) -> IpAddr {
        value.parse().expect("valid IP")
    }

    fn prefix(address: IpAddr, prefix_len: u8) -> IpPrefix {
        IpPrefix {
            address,
            prefix_len,
        }
    }

    fn capabilities() -> BTreeSet<EncryptionCapability> {
        [
            EncryptionCapability::KernelWireGuard,
            EncryptionCapability::DualStackUnderlay,
            EncryptionCapability::PolicyRouting,
            EncryptionCapability::TwoEpochRotation,
            EncryptionCapability::EncryptedPathChallenge,
        ]
        .into_iter()
        .collect()
    }

    fn node(name: &str, ordinal: u8) -> EncryptionNode {
        EncryptionNode {
            cluster_id: "cluster-a".to_owned(),
            name: name.to_owned(),
            uid: format!("uid-{name}"),
            pod_cidrs: vec![
                prefix(IpAddr::V4(Ipv4Addr::new(10, 42, ordinal, 0)), 24),
                prefix(
                    IpAddr::V6(Ipv6Addr::new(0xfd42, u16::from(ordinal), 0, 0, 0, 0, 0, 0)),
                    64,
                ),
            ],
            underlay_addresses: vec![
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, ordinal)),
                IpAddr::V6(Ipv6Addr::new(
                    0x2001,
                    0xdb8,
                    0,
                    0,
                    0,
                    0,
                    0,
                    u16::from(ordinal),
                )),
            ],
            capabilities: capabilities(),
        }
    }

    fn path(source: &EncryptionNode, destination: &EncryptionNode) -> EncryptionPathFact {
        EncryptionPathFact {
            source_node_uid: source.uid.clone(),
            destination_node_uid: destination.uid.clone(),
            epoch: 7,
            path_class: EncryptionPathClass::ManagedPod,
            peer_endpoint: SocketAddr::new(destination.underlay_addresses[0], 51_820),
            allowed_ips: destination.pod_cidrs.clone(),
            interface_name: "unf-wg-a".to_owned(),
            route_table: 20_090,
            fwmark: 0x554e_4609,
            mtu: 1_420,
        }
    }

    fn fixture() -> (EncryptionModel, EncryptionContractFacts, EncryptionNode) {
        let source_node = node("worker-a", 1);
        let destination_node = node("worker-b", 2);
        let model = EncryptionModel::normalize(
            "cluster-a".to_owned(),
            EncryptionBaseline::Native,
            vec![EncryptionIntent {
                name: "payments-required".to_owned(),
                uid: "uid-intent-payments".to_owned(),
                priority: 100,
                sources: ManagedIdentitySelector::Identities(
                    [IdentityId::new(11)].into_iter().collect(),
                ),
                destinations: ManagedIdentitySelector::Identities(
                    [IdentityId::new(22)].into_iter().collect(),
                ),
            }],
        )
        .expect("valid model");
        let facts = EncryptionContractFacts {
            revisions: EncryptionContractRevisions {
                intent: Revision::new(1),
                identity: Revision::new(2),
                policy: Revision::new(3),
                routing: Revision::new(4),
                key: Revision::new(5),
            },
            active_epoch: 7,
            endpoints: vec![
                EncryptionEndpointFact {
                    identity: IdentityId::new(22),
                    workload_uid: "uid-ledger".to_owned(),
                    node: destination_node.clone(),
                },
                EncryptionEndpointFact {
                    identity: IdentityId::new(11),
                    workload_uid: "uid-payments".to_owned(),
                    node: source_node.clone(),
                },
            ],
            policies: vec![EncryptionPolicyFact {
                source: IdentityId::new(11),
                destination: IdentityId::new(22),
                allowed: true,
                policy_ids: vec![PolicyId::new(9), PolicyId::new(3)],
            }],
            keys: vec![
                EncryptionKeyFact {
                    node_uid: destination_node.uid.clone(),
                    epoch: 7,
                    public_key: WireGuardPublicKey([2; 32]),
                    phase: EncryptionKeyPhase::Active,
                    valid_from_unix_ms: 900,
                    valid_until_unix_ms: 3_000,
                },
                EncryptionKeyFact {
                    node_uid: source_node.uid.clone(),
                    epoch: 7,
                    public_key: WireGuardPublicKey([1; 32]),
                    phase: EncryptionKeyPhase::Active,
                    valid_from_unix_ms: 900,
                    valid_until_unix_ms: 3_000,
                },
            ],
            paths: vec![
                path(&destination_node, &source_node),
                path(&source_node, &destination_node),
            ],
        };
        (model, facts, source_node)
    }

    fn issue(
        model: &EncryptionModel,
        facts: &EncryptionContractFacts,
        source_node: &EncryptionNode,
    ) -> Result<AttestedEncryptionPathContract, EncryptionContractError> {
        AttestedEncryptionPathContract::issue(
            model,
            facts,
            source_node.clone(),
            Revision::new(6),
            1_000,
            2_000,
        )
    }

    #[test]
    fn monotonic_intent_adds_required_but_cannot_weaken_required_baseline() {
        let (selective, _, _) = fixture();
        assert_eq!(
            selective
                .requirement(IdentityId::new(11), IdentityId::new(22))
                .disposition,
            EncryptionDisposition::Required
        );
        assert_eq!(
            selective
                .requirement(IdentityId::new(22), IdentityId::new(11))
                .disposition,
            EncryptionDisposition::Native
        );
        let required = EncryptionModel::normalize(
            "cluster-a".to_owned(),
            EncryptionBaseline::Required,
            Vec::new(),
        )
        .expect("valid baseline");
        assert_eq!(
            required
                .requirement(IdentityId::new(22), IdentityId::new(11))
                .disposition,
            EncryptionDisposition::Required
        );
    }

    #[test]
    fn contract_binds_policy_keys_epoch_routes_and_replays_independently() {
        let (model, facts, source_node) = fixture();
        let contract = issue(&model, &facts, &source_node).expect("valid contract");
        contract
            .verify(&model, &facts, &source_node)
            .expect("independent replay");
        contract.verify_integrity().expect("integrity");
        assert_eq!(contract.plans.len(), 1);
        assert_eq!(
            contract.plans[0].policy.policy_ids,
            vec![PolicyId::new(3), PolicyId::new(9)]
        );
        assert_eq!(contract.plans[0].source_key.epoch, 7);
        assert_eq!(contract.plans[0].transport.forward.mtu, 1_420);
        assert_eq!(contract.verified_invariants.len(), 13);
        assert_eq!(contract.failure_envelope.total_observations, 5);
        assert!(!contract.failure_envelope.truncated);
    }

    #[test]
    fn canonical_input_order_produces_identical_digest_and_witness() {
        let (model, mut facts, source_node) = fixture();
        let first = issue(&model, &facts, &source_node).expect("valid contract");
        facts.endpoints.reverse();
        facts.keys.reverse();
        facts.paths.reverse();
        facts.policies[0].policy_ids.reverse();
        let second = issue(&model, &facts, &source_node).expect("order independent");
        assert_eq!(first, second);
        assert_eq!(
            first.decision_witness(0).expect("witness"),
            second.decision_witness(0).expect("witness")
        );
        assert_eq!(
            first.contract_digest,
            AttestedEncryptionContractDigest([
                144, 234, 201, 131, 134, 50, 71, 213, 141, 90, 159, 218, 133, 223, 8, 100, 107, 27,
                16, 117, 76, 129, 88, 142, 86, 31, 119, 200, 155, 216, 162, 193,
            ])
        );
        assert_eq!(
            first.decision_witness(0).expect("witness"),
            EncryptionDecisionWitness([
                139, 184, 20, 51, 222, 46, 0, 32, 250, 78, 33, 208, 63, 74, 222, 250,
            ])
        );
        assert!(first.decision_witness(1).is_err());
    }

    #[test]
    fn denied_policy_never_reaches_encryption_planning() {
        let (model, mut facts, source_node) = fixture();
        facts.policies[0].allowed = false;
        let contract = issue(&model, &facts, &source_node).expect("denial is valid policy state");
        assert!(contract.plans.is_empty());
        assert!(contract.failure_envelope.observations.is_empty());
    }

    #[test]
    fn missing_or_ambiguous_authority_fails_closed() {
        let (model, facts, source_node) = fixture();
        let cases = [
            {
                let mut value = facts.clone();
                value.policies.clear();
                value
            },
            {
                let mut value = facts.clone();
                value.keys.pop();
                value
            },
            {
                let mut value = facts.clone();
                value.paths.pop();
                value
            },
            {
                let mut value = facts.clone();
                value.paths[0].allowed_ips[0] = prefix(ip("10.99.0.0"), 16);
                value
            },
        ];
        for facts in cases {
            assert!(issue(&model, &facts, &source_node).is_err());
        }
    }

    #[test]
    fn independent_replay_rejects_every_mutated_authority_domain() {
        let (model, facts, source_node) = fixture();
        let contract = issue(&model, &facts, &source_node).expect("valid contract");
        let mutations = [
            {
                let mut value = contract.clone();
                value.plans[0].policy.policy_ids.clear();
                value
            },
            {
                let mut value = contract.clone();
                value.plans[0].destination_key.epoch += 1;
                value
            },
            {
                let mut value = contract.clone();
                value.plans[0].transport.forward.fwmark += 1;
                value
            },
            {
                let mut value = contract.clone();
                value.plans[0].revisions.routing = Revision::new(99);
                value
            },
            {
                let mut value = contract.clone();
                value.failure_envelope.observations[0].outcome =
                    EncryptionFailureOutcome::DenyRequired;
                value.failure_envelope.observations[0].destination = IdentityId::new(99);
                value
            },
        ];
        for mutation in mutations {
            assert!(matches!(
                mutation.verify(&model, &facts, &source_node),
                Err(EncryptionContractError::ReplayMismatch)
            ));
        }
    }

    #[test]
    fn key_lifetime_capability_and_cross_cluster_inputs_fail_closed() {
        let (model, facts, source_node) = fixture();
        let mut expired = facts.clone();
        expired.keys[0].valid_until_unix_ms = 1_500;
        assert!(matches!(
            issue(&model, &expired, &source_node),
            Err(EncryptionContractError::InvalidKey)
        ));

        let mut incapable = facts.clone();
        incapable.endpoints[0]
            .node
            .capabilities
            .remove(&EncryptionCapability::EncryptedPathChallenge);
        assert!(matches!(
            issue(&model, &incapable, &source_node),
            Err(EncryptionContractError::MissingCapability(
                EncryptionCapability::EncryptedPathChallenge
            ))
        ));

        let mut foreign = facts;
        foreign.endpoints[0].node.cluster_id = "cluster-b".to_owned();
        assert!(matches!(
            issue(&model, &foreign, &source_node),
            Err(EncryptionContractError::InvalidNode(_))
        ));
    }

    #[test]
    fn conflicting_node_identity_public_key_and_nested_prefixes_fail_closed() {
        let (model, facts, source_node) = fixture();

        let mut conflicting_node = facts.clone();
        let mut extra = conflicting_node.endpoints[0].clone();
        extra.identity = IdentityId::new(23);
        extra.workload_uid = "uid-conflict".to_owned();
        extra.node.name = "different-name".to_owned();
        conflicting_node.endpoints.push(extra);
        assert!(matches!(
            issue(&model, &conflicting_node, &source_node),
            Err(EncryptionContractError::InvalidNode(_))
        ));

        let mut shared_public_key = facts.clone();
        shared_public_key.keys[1].public_key = shared_public_key.keys[0].public_key;
        assert!(matches!(
            issue(&model, &shared_public_key, &source_node),
            Err(EncryptionContractError::InvalidKey)
        ));

        let mut conflicting_workload = facts.clone();
        let mut extra = conflicting_workload.endpoints[0].clone();
        extra.identity = IdentityId::new(23);
        conflicting_workload.endpoints.push(extra);
        assert!(matches!(
            issue(&model, &conflicting_workload, &source_node),
            Err(EncryptionContractError::InvalidNode(_))
        ));

        let mut local_identity_drift = facts.clone();
        local_identity_drift.endpoints[1].node.pod_cidrs[0] = prefix(ip("10.77.0.0"), 16);
        assert!(matches!(
            issue(&model, &local_identity_drift, &source_node),
            Err(EncryptionContractError::InvalidNode(_))
        ));

        let mut nested_prefix = facts;
        nested_prefix.endpoints[0]
            .node
            .pod_cidrs
            .push(prefix(ip("10.42.2.128"), 25));
        assert!(matches!(
            issue(&model, &nested_prefix, &source_node),
            Err(EncryptionContractError::InvalidNode(_))
        ));
    }

    #[test]
    fn overlapping_allowed_ips_across_destination_nodes_are_rejected() {
        let (model, mut facts, source_node) = fixture();
        let mut third_node = node("worker-c", 3);
        third_node.pod_cidrs = facts.endpoints[0].node.pod_cidrs.clone();
        facts.endpoints.push(EncryptionEndpointFact {
            identity: IdentityId::new(22),
            workload_uid: "uid-ledger-2".to_owned(),
            node: third_node.clone(),
        });
        facts.keys.push(EncryptionKeyFact {
            node_uid: third_node.uid.clone(),
            epoch: 7,
            public_key: WireGuardPublicKey([3; 32]),
            phase: EncryptionKeyPhase::Active,
            valid_from_unix_ms: 900,
            valid_until_unix_ms: 3_000,
        });
        facts.paths.push(path(&source_node, &third_node));
        facts.paths.push(path(&third_node, &source_node));
        assert!(matches!(
            issue(&model, &facts, &source_node),
            Err(EncryptionContractError::AmbiguousAllowedIp)
        ));
    }

    #[test]
    fn wire_shape_rejects_unknown_fields_and_contains_no_private_key_field() {
        let (model, facts, source_node) = fixture();
        let contract = issue(&model, &facts, &source_node).expect("valid contract");
        let encoded = serde_json::to_string(&contract).expect("serializes");
        assert!(!encoded.to_ascii_lowercase().contains("privatekey"));
        let mut json = serde_json::to_value(contract).expect("serializes");
        json.as_object_mut()
            .expect("object")
            .insert("privateKey".to_owned(), serde_json::json!(vec![7; 32]));
        assert!(serde_json::from_value::<AttestedEncryptionPathContract>(json).is_err());
    }

    proptest! {
        #[test]
        fn intent_normalization_is_permutation_independent(
            identities in btree_set(1_u32..10_000, 1..32)
        ) {
            let intents = identities
                .iter()
                .enumerate()
                .map(|(index, identity)| EncryptionIntent {
                    name: format!("intent-{identity}"),
                    uid: format!("uid-{identity}"),
                    priority: u32::try_from(index % 4).expect("bounded priority"),
                    sources: ManagedIdentitySelector::Identities(
                        [IdentityId::new(*identity)].into_iter().collect(),
                    ),
                    destinations: ManagedIdentitySelector::AllManaged,
                })
                .collect::<Vec<_>>();
            let first = EncryptionModel::normalize(
                "cluster-a".to_owned(),
                EncryptionBaseline::Native,
                intents.clone(),
            )
            .expect("valid model");
            let second = EncryptionModel::normalize(
                "cluster-a".to_owned(),
                EncryptionBaseline::Native,
                intents.into_iter().rev().collect(),
            )
            .expect("valid reversed model");
            prop_assert_eq!(first, second);
        }
    }
}
