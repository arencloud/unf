//! Fixed-width encrypted path challenge protocol and consuming delivery proof.

use std::net::IpAddr;

use sha2::{Digest as _, Sha256};

use crate::{
    AdmittedEncryptionPathProofAssignmentBatch, EncryptionGenerationRecipient,
    EncryptionPathEndpointRole, EncryptionPathProofAssignment, EncryptionPathProofAssignmentIndex,
    EncryptionPathProofError, EncryptionPathProofRound, EncryptionPathProofRoundDigest,
    PATH_FAMILY_IPV4, PATH_FAMILY_IPV6, derive_wireguard_proof_addresses,
};

pub const ENCRYPTION_PATH_PROBE_PORT: u16 = 51_971;
pub const ENCRYPTION_PATH_PROBE_FRAME_BYTES: usize = 72;
const PROBE_MAGIC: [u8; 4] = *b"UNFP";
const PROBE_SCHEMA_VERSION: u16 = 1;
const DELIVERY_DOMAIN: &[u8] = b"unf.encryption-path-challenge-delivery.v1\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum EncryptionPathProbeKind {
    Request = 1,
    Response = 2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncryptionPathProbeFrame {
    kind: EncryptionPathProbeKind,
    family: u8,
    round_digest: EncryptionPathProofRoundDigest,
    nonce: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncryptionPathProbeExchange {
    local_address: IpAddr,
    peer_address: IpAddr,
    request: EncryptionPathProbeFrame,
    response: EncryptionPathProbeFrame,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncryptionPathProbeTarget {
    pub family: u8,
    pub local_address: IpAddr,
    pub peer_address: IpAddr,
}

/// Non-cloneable evidence that the complete required family set returned the
/// exact round nonce over the expected contract-derived beacon pair.
pub struct EncryptionPathChallengeDelivery {
    round_digest: EncryptionPathProofRoundDigest,
    family_mask: u8,
    transcript_digest: [u8; 32],
}

impl EncryptionPathProbeFrame {
    /// Creates the fixed-width request for one required address family.
    ///
    /// # Errors
    ///
    /// Rejects an invalid round or a family outside its required mask.
    pub fn request(
        round: &EncryptionPathProofRound,
        family: u8,
    ) -> Result<Self, EncryptionPathProofError> {
        round.verify()?;
        if !valid_single_family(family) || round.family_mask & family == 0 {
            return Err(EncryptionPathProofError::ChallengeMismatch);
        }
        Ok(Self {
            kind: EncryptionPathProbeKind::Request,
            family,
            round_digest: round.round_digest,
            nonce: round.nonce,
        })
    }

    /// Converts an exact request into its fixed-width response.
    ///
    /// # Errors
    ///
    /// Rejects a malformed, foreign, or already-responded frame.
    pub fn response(
        round: &EncryptionPathProofRound,
        request: Self,
    ) -> Result<Self, EncryptionPathProofError> {
        request.verify_for(round, EncryptionPathProbeKind::Request)?;
        Ok(Self {
            kind: EncryptionPathProbeKind::Response,
            ..request
        })
    }

    #[must_use]
    pub fn encode(self) -> [u8; ENCRYPTION_PATH_PROBE_FRAME_BYTES] {
        let mut wire = [0_u8; ENCRYPTION_PATH_PROBE_FRAME_BYTES];
        wire[0..4].copy_from_slice(&PROBE_MAGIC);
        wire[4..6].copy_from_slice(&PROBE_SCHEMA_VERSION.to_be_bytes());
        wire[6] = self.kind as u8;
        wire[7] = self.family;
        wire[8..40].copy_from_slice(&self.round_digest.0);
        wire[40..72].copy_from_slice(&self.nonce);
        wire
    }

    /// Decodes only the closed fixed-width wire vocabulary.
    ///
    /// # Errors
    ///
    /// Rejects unknown size, magic, version, kind, family, or empty authority.
    pub fn decode(wire: &[u8]) -> Result<Self, EncryptionPathProofError> {
        if wire.len() != ENCRYPTION_PATH_PROBE_FRAME_BYTES
            || wire[0..4] != PROBE_MAGIC
            || u16::from_be_bytes([wire[4], wire[5]]) != PROBE_SCHEMA_VERSION
            || !valid_single_family(wire[7])
        {
            return Err(EncryptionPathProofError::ChallengeMismatch);
        }
        let kind = match wire[6] {
            1 => EncryptionPathProbeKind::Request,
            2 => EncryptionPathProbeKind::Response,
            _ => return Err(EncryptionPathProofError::ChallengeMismatch),
        };
        let mut round_digest = [0_u8; 32];
        round_digest.copy_from_slice(&wire[8..40]);
        let mut nonce = [0_u8; 32];
        nonce.copy_from_slice(&wire[40..72]);
        if round_digest == [0; 32] || nonce == [0; 32] {
            return Err(EncryptionPathProofError::ChallengeMismatch);
        }
        Ok(Self {
            kind,
            family: wire[7],
            round_digest: EncryptionPathProofRoundDigest(round_digest),
            nonce,
        })
    }

    /// Verifies that this frame carries one exact round and message kind.
    ///
    /// # Errors
    ///
    /// Rejects expired, mutated, foreign-round, or wrong-kind frames.
    pub fn verify_for(
        self,
        round: &EncryptionPathProofRound,
        kind: EncryptionPathProbeKind,
    ) -> Result<(), EncryptionPathProofError> {
        round.verify()?;
        if self.kind != kind
            || self.round_digest != round.round_digest
            || self.nonce != round.nonce
            || round.family_mask & self.family == 0
        {
            return Err(EncryptionPathProofError::ChallengeMismatch);
        }
        Ok(())
    }

    #[must_use]
    pub const fn kind(self) -> EncryptionPathProbeKind {
        self.kind
    }

    #[must_use]
    pub const fn family(self) -> u8 {
        self.family
    }

    #[must_use]
    pub const fn round_digest(self) -> EncryptionPathProofRoundDigest {
        self.round_digest
    }
}

impl EncryptionPathProbeExchange {
    /// Seals one received response with its observed local/peer beacon pair.
    ///
    /// # Errors
    ///
    /// Rejects malformed or nonmatching request/response bytes.
    pub fn from_wire(
        round: &EncryptionPathProofRound,
        local_address: IpAddr,
        peer_address: IpAddr,
        request_wire: &[u8],
        response_wire: &[u8],
    ) -> Result<Self, EncryptionPathProofError> {
        let request = EncryptionPathProbeFrame::decode(request_wire)?;
        let response = EncryptionPathProbeFrame::decode(response_wire)?;
        request.verify_for(round, EncryptionPathProbeKind::Request)?;
        response.verify_for(round, EncryptionPathProbeKind::Response)?;
        if request.family != response.family
            || request.round_digest != response.round_digest
            || request.nonce != response.nonce
            || local_address.is_ipv4() != peer_address.is_ipv4()
            || local_address.is_ipv4() != (request.family == PATH_FAMILY_IPV4)
        {
            return Err(EncryptionPathProofError::ChallengeMismatch);
        }
        Ok(Self {
            local_address,
            peer_address,
            request,
            response,
        })
    }
}

impl EncryptionPathChallengeDelivery {
    /// Joins one exact exchange per required family to contract-derived beacons.
    ///
    /// # Errors
    ///
    /// Rejects partial, duplicate, extra, foreign-address, or mutated evidence.
    pub fn issue(
        assignment: &EncryptionPathProofAssignment,
        recipient: &EncryptionGenerationRecipient,
        mut exchanges: Vec<EncryptionPathProbeExchange>,
    ) -> Result<Self, EncryptionPathProofError> {
        assignment.verify()?;
        let (local_node, peer_node) = endpoint_nodes(assignment, recipient)?;
        let local = derive_wireguard_proof_addresses(&local_node.pod_cidrs)
            .map_err(|error| EncryptionPathProofError::InvalidContract(error.to_string()))?;
        let peer = derive_wireguard_proof_addresses(&peer_node.pod_cidrs)
            .map_err(|error| EncryptionPathProofError::InvalidContract(error.to_string()))?;
        exchanges.sort_by_key(|exchange| exchange.request.family);
        let required = [PATH_FAMILY_IPV4, PATH_FAMILY_IPV6]
            .into_iter()
            .filter(|family| assignment.round.family_mask & family != 0)
            .collect::<Vec<_>>();
        if exchanges.len() != required.len()
            || exchanges
                .iter()
                .map(|exchange| exchange.request.family)
                .collect::<Vec<_>>()
                != required
        {
            return Err(EncryptionPathProofError::ChallengeMismatch);
        }
        for exchange in &exchanges {
            exchange
                .request
                .verify_for(&assignment.round, EncryptionPathProbeKind::Request)?;
            exchange
                .response
                .verify_for(&assignment.round, EncryptionPathProbeKind::Response)?;
            let expected_local = beacon_for_family(&local, exchange.request.family)?;
            let expected_peer = beacon_for_family(&peer, exchange.request.family)?;
            if exchange.local_address != expected_local || exchange.peer_address != expected_peer {
                return Err(EncryptionPathProofError::ChallengeMismatch);
            }
        }
        let transcript_digest = delivery_digest(assignment, recipient, &exchanges);
        Ok(Self {
            round_digest: assignment.round.round_digest,
            family_mask: assignment.round.family_mask,
            transcript_digest,
        })
    }

    /// Joins exchanges for one compact batch selection without duplicating its
    /// batch-owned contract.
    ///
    /// # Errors
    ///
    /// Rejects the same malformed or incomplete evidence as [`Self::issue`].
    pub fn issue_indexed(
        assignment: &EncryptionPathProofAssignmentIndex,
        contract: &crate::AttestedEncryptionPathContract,
        recipient: &EncryptionGenerationRecipient,
        exchanges: Vec<EncryptionPathProbeExchange>,
    ) -> Result<Self, EncryptionPathProofError> {
        assignment.verify_with(contract)?;
        Self::issue_indexed_for_verified_contract(assignment, contract, recipient, exchanges)
    }

    /// Joins an exact selection from a batch whose contracts were replayed
    /// once at admission.
    ///
    /// # Errors
    ///
    /// Rejects foreign work and every malformed exchange rejected by
    /// [`Self::issue_indexed`].
    pub fn issue_from_assignment_batch(
        batch: &AdmittedEncryptionPathProofAssignmentBatch,
        assignment: &EncryptionPathProofAssignmentIndex,
        recipient: &EncryptionGenerationRecipient,
        exchanges: Vec<EncryptionPathProbeExchange>,
    ) -> Result<Self, EncryptionPathProofError> {
        let contract = batch.contract_for(assignment)?;
        Self::issue_indexed_for_verified_contract(assignment, contract, recipient, exchanges)
    }

    fn issue_indexed_for_verified_contract(
        assignment: &EncryptionPathProofAssignmentIndex,
        contract: &crate::AttestedEncryptionPathContract,
        recipient: &EncryptionGenerationRecipient,
        mut exchanges: Vec<EncryptionPathProbeExchange>,
    ) -> Result<Self, EncryptionPathProofError> {
        let (local_node, peer_node) = indexed_endpoint_nodes(assignment, contract, recipient)?;
        let local = derive_wireguard_proof_addresses(&local_node.pod_cidrs)
            .map_err(|error| EncryptionPathProofError::InvalidContract(error.to_string()))?;
        let peer = derive_wireguard_proof_addresses(&peer_node.pod_cidrs)
            .map_err(|error| EncryptionPathProofError::InvalidContract(error.to_string()))?;
        exchanges.sort_by_key(|exchange| exchange.request.family);
        let required = [PATH_FAMILY_IPV4, PATH_FAMILY_IPV6]
            .into_iter()
            .filter(|family| assignment.round.family_mask & family != 0)
            .collect::<Vec<_>>();
        if exchanges.len() != required.len()
            || exchanges
                .iter()
                .map(|exchange| exchange.request.family)
                .collect::<Vec<_>>()
                != required
        {
            return Err(EncryptionPathProofError::ChallengeMismatch);
        }
        for exchange in &exchanges {
            exchange
                .request
                .verify_for(&assignment.round, EncryptionPathProbeKind::Request)?;
            exchange
                .response
                .verify_for(&assignment.round, EncryptionPathProbeKind::Response)?;
            let expected_local = beacon_for_family(&local, exchange.request.family)?;
            let expected_peer = beacon_for_family(&peer, exchange.request.family)?;
            if exchange.local_address != expected_local || exchange.peer_address != expected_peer {
                return Err(EncryptionPathProofError::ChallengeMismatch);
            }
        }
        let transcript_digest = indexed_delivery_digest(assignment, recipient, &exchanges);
        Ok(Self {
            round_digest: assignment.round.round_digest,
            family_mask: assignment.round.family_mask,
            transcript_digest,
        })
    }

    pub(crate) fn verify_for(
        &self,
        round: &EncryptionPathProofRound,
    ) -> Result<(), EncryptionPathProofError> {
        if self.round_digest != round.round_digest
            || self.family_mask != round.family_mask
            || self.transcript_digest == [0; 32]
        {
            return Err(EncryptionPathProofError::ChallengeMismatch);
        }
        Ok(())
    }

    #[must_use]
    pub const fn family_mask(&self) -> u8 {
        self.family_mask
    }

    #[must_use]
    pub const fn transcript_digest(&self) -> [u8; 32] {
        self.transcript_digest
    }
}

impl EncryptionPathProofAssignment {
    /// Resolves this authenticated Node's role without accepting name-only
    /// identity or a third-party assignment.
    ///
    /// # Errors
    ///
    /// Rejects malformed or foreign assignments.
    pub fn endpoint_role(
        &self,
        recipient: &EncryptionGenerationRecipient,
    ) -> Result<EncryptionPathEndpointRole, EncryptionPathProofError> {
        self.verify()?;
        if recipient == &self.round.source {
            Ok(EncryptionPathEndpointRole::Source)
        } else if recipient == &self.round.destination {
            Ok(EncryptionPathEndpointRole::Destination)
        } else {
            Err(EncryptionPathProofError::ForeignNode)
        }
    }

    /// Returns the exact contract path used by this endpoint.
    ///
    /// # Errors
    ///
    /// Rejects malformed, missing, or foreign assignments.
    pub fn local_path(
        &self,
        recipient: &EncryptionGenerationRecipient,
    ) -> Result<&crate::EncryptionPathFact, EncryptionPathProofError> {
        let role = self.endpoint_role(recipient)?;
        let plan = self
            .contract
            .plans
            .get(self.plan_index)
            .ok_or(EncryptionPathProofError::InvalidContractPlan)?;
        Ok(match role {
            EncryptionPathEndpointRole::Source => &plan.transport.forward,
            EncryptionPathEndpointRole::Destination => &plan.transport.reverse,
        })
    }

    /// Derives one exact local/peer beacon pair for every required family.
    ///
    /// # Errors
    ///
    /// Rejects malformed CIDRs, missing family coverage, or foreign assignment.
    pub fn probe_targets(
        &self,
        recipient: &EncryptionGenerationRecipient,
    ) -> Result<Vec<EncryptionPathProbeTarget>, EncryptionPathProofError> {
        self.verify()?;
        let (local_node, peer_node) = endpoint_nodes(self, recipient)?;
        let local = derive_wireguard_proof_addresses(&local_node.pod_cidrs)
            .map_err(|error| EncryptionPathProofError::InvalidContract(error.to_string()))?;
        let peer = derive_wireguard_proof_addresses(&peer_node.pod_cidrs)
            .map_err(|error| EncryptionPathProofError::InvalidContract(error.to_string()))?;
        [PATH_FAMILY_IPV4, PATH_FAMILY_IPV6]
            .into_iter()
            .filter(|family| self.round.family_mask & family != 0)
            .map(|family| {
                Ok(EncryptionPathProbeTarget {
                    family,
                    local_address: beacon_for_family(&local, family)?,
                    peer_address: beacon_for_family(&peer, family)?,
                })
            })
            .collect()
    }
}

impl EncryptionPathProofAssignmentIndex {
    /// Resolves this endpoint's role against the batch-owned contract.
    ///
    /// # Errors
    ///
    /// Rejects malformed, mismatched, or foreign selections.
    pub fn endpoint_role_with(
        &self,
        contract: &crate::AttestedEncryptionPathContract,
        recipient: &EncryptionGenerationRecipient,
    ) -> Result<EncryptionPathEndpointRole, EncryptionPathProofError> {
        self.verify_with(contract)?;
        self.endpoint_role_for_verified_contract(recipient)
    }

    /// Resolves the endpoint role from one admitted compact-batch selection.
    ///
    /// # Errors
    ///
    /// Rejects foreign or unadmitted work.
    pub fn endpoint_role_from_assignment_batch(
        &self,
        batch: &AdmittedEncryptionPathProofAssignmentBatch,
        recipient: &EncryptionGenerationRecipient,
    ) -> Result<EncryptionPathEndpointRole, EncryptionPathProofError> {
        batch.contract_for(self)?;
        self.endpoint_role_for_verified_contract(recipient)
    }

    fn endpoint_role_for_verified_contract(
        &self,
        recipient: &EncryptionGenerationRecipient,
    ) -> Result<EncryptionPathEndpointRole, EncryptionPathProofError> {
        if recipient == &self.round.source {
            Ok(EncryptionPathEndpointRole::Source)
        } else if recipient == &self.round.destination {
            Ok(EncryptionPathEndpointRole::Destination)
        } else {
            Err(EncryptionPathProofError::ForeignNode)
        }
    }

    /// Returns the selected local path from the batch-owned contract.
    ///
    /// # Errors
    ///
    /// Rejects malformed, missing, or foreign selections.
    pub fn local_path_with<'a>(
        &self,
        contract: &'a crate::AttestedEncryptionPathContract,
        recipient: &EncryptionGenerationRecipient,
    ) -> Result<&'a crate::EncryptionPathFact, EncryptionPathProofError> {
        let role = self.endpoint_role_with(contract, recipient)?;
        let plan = contract
            .plans
            .get(self.plan_index)
            .ok_or(EncryptionPathProofError::InvalidContractPlan)?;
        Ok(match role {
            EncryptionPathEndpointRole::Source => &plan.transport.forward,
            EncryptionPathEndpointRole::Destination => &plan.transport.reverse,
        })
    }

    /// Returns the selected local path from an admitted compact batch.
    ///
    /// # Errors
    ///
    /// Rejects malformed, missing, foreign, or unadmitted work.
    pub fn local_path_from_assignment_batch<'a>(
        &self,
        batch: &'a AdmittedEncryptionPathProofAssignmentBatch,
        recipient: &EncryptionGenerationRecipient,
    ) -> Result<&'a crate::EncryptionPathFact, EncryptionPathProofError> {
        let contract = batch.contract_for(self)?;
        let role = self.endpoint_role_for_verified_contract(recipient)?;
        let plan = contract
            .plans
            .get(self.plan_index)
            .ok_or(EncryptionPathProofError::InvalidContractPlan)?;
        Ok(match role {
            EncryptionPathEndpointRole::Source => &plan.transport.forward,
            EncryptionPathEndpointRole::Destination => &plan.transport.reverse,
        })
    }

    /// Derives exact proof beacons without owning a duplicate contract.
    ///
    /// # Errors
    ///
    /// Rejects malformed CIDRs, missing family coverage, or foreign work.
    pub fn probe_targets_with(
        &self,
        contract: &crate::AttestedEncryptionPathContract,
        recipient: &EncryptionGenerationRecipient,
    ) -> Result<Vec<EncryptionPathProbeTarget>, EncryptionPathProofError> {
        self.verify_with(contract)?;
        let (local_node, peer_node) = indexed_endpoint_nodes(self, contract, recipient)?;
        let local = derive_wireguard_proof_addresses(&local_node.pod_cidrs)
            .map_err(|error| EncryptionPathProofError::InvalidContract(error.to_string()))?;
        let peer = derive_wireguard_proof_addresses(&peer_node.pod_cidrs)
            .map_err(|error| EncryptionPathProofError::InvalidContract(error.to_string()))?;
        [PATH_FAMILY_IPV4, PATH_FAMILY_IPV6]
            .into_iter()
            .filter(|family| self.round.family_mask & family != 0)
            .map(|family| {
                Ok(EncryptionPathProbeTarget {
                    family,
                    local_address: beacon_for_family(&local, family)?,
                    peer_address: beacon_for_family(&peer, family)?,
                })
            })
            .collect()
    }

    /// Derives exact beacons from an admitted compact batch without rehashing
    /// the shared contract.
    ///
    /// # Errors
    ///
    /// Rejects malformed, missing, foreign, or unadmitted work.
    pub fn probe_targets_from_assignment_batch(
        &self,
        batch: &AdmittedEncryptionPathProofAssignmentBatch,
        recipient: &EncryptionGenerationRecipient,
    ) -> Result<Vec<EncryptionPathProbeTarget>, EncryptionPathProofError> {
        let contract = batch.contract_for(self)?;
        let (local_node, peer_node) = indexed_endpoint_nodes(self, contract, recipient)?;
        let local = derive_wireguard_proof_addresses(&local_node.pod_cidrs)
            .map_err(|error| EncryptionPathProofError::InvalidContract(error.to_string()))?;
        let peer = derive_wireguard_proof_addresses(&peer_node.pod_cidrs)
            .map_err(|error| EncryptionPathProofError::InvalidContract(error.to_string()))?;
        [PATH_FAMILY_IPV4, PATH_FAMILY_IPV6]
            .into_iter()
            .filter(|family| self.round.family_mask & family != 0)
            .map(|family| {
                Ok(EncryptionPathProbeTarget {
                    family,
                    local_address: beacon_for_family(&local, family)?,
                    peer_address: beacon_for_family(&peer, family)?,
                })
            })
            .collect()
    }
}

fn endpoint_nodes<'a>(
    assignment: &'a EncryptionPathProofAssignment,
    recipient: &EncryptionGenerationRecipient,
) -> Result<(&'a crate::EncryptionNode, &'a crate::EncryptionNode), EncryptionPathProofError> {
    let plan = assignment
        .contract
        .plans
        .get(assignment.plan_index)
        .ok_or(EncryptionPathProofError::InvalidContractPlan)?;
    if recipient == &assignment.round.source {
        Ok((&plan.source.node, &plan.destination.node))
    } else if recipient == &assignment.round.destination {
        Ok((&plan.destination.node, &plan.source.node))
    } else {
        Err(EncryptionPathProofError::ForeignNode)
    }
}

fn indexed_endpoint_nodes<'a>(
    assignment: &EncryptionPathProofAssignmentIndex,
    contract: &'a crate::AttestedEncryptionPathContract,
    recipient: &EncryptionGenerationRecipient,
) -> Result<(&'a crate::EncryptionNode, &'a crate::EncryptionNode), EncryptionPathProofError> {
    let plan = contract
        .plans
        .get(assignment.plan_index)
        .ok_or(EncryptionPathProofError::InvalidContractPlan)?;
    if recipient == &assignment.round.source {
        Ok((&plan.source.node, &plan.destination.node))
    } else if recipient == &assignment.round.destination {
        Ok((&plan.destination.node, &plan.source.node))
    } else {
        Err(EncryptionPathProofError::ForeignNode)
    }
}

fn beacon_for_family(
    addresses: &[crate::IpPrefix],
    family: u8,
) -> Result<IpAddr, EncryptionPathProofError> {
    addresses
        .iter()
        .map(|prefix| prefix.address)
        .find(|address| address.is_ipv4() == (family == PATH_FAMILY_IPV4))
        .ok_or(EncryptionPathProofError::ChallengeMismatch)
}

fn valid_single_family(family: u8) -> bool {
    matches!(family, PATH_FAMILY_IPV4 | PATH_FAMILY_IPV6)
}

fn delivery_digest(
    assignment: &EncryptionPathProofAssignment,
    recipient: &EncryptionGenerationRecipient,
    exchanges: &[EncryptionPathProbeExchange],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(DELIVERY_DOMAIN);
    hasher.update(assignment.generation.get().to_be_bytes());
    hasher.update(assignment.round.round_digest.0);
    hasher.update((recipient.node_uid.len() as u64).to_be_bytes());
    hasher.update(recipient.node_uid.as_bytes());
    for exchange in exchanges {
        hasher.update([exchange.request.family]);
        match exchange.local_address {
            IpAddr::V4(address) => hasher.update(address.octets()),
            IpAddr::V6(address) => hasher.update(address.octets()),
        }
        match exchange.peer_address {
            IpAddr::V4(address) => hasher.update(address.octets()),
            IpAddr::V6(address) => hasher.update(address.octets()),
        }
        hasher.update(exchange.request.encode());
        hasher.update(exchange.response.encode());
    }
    hasher.finalize().into()
}

fn indexed_delivery_digest(
    assignment: &EncryptionPathProofAssignmentIndex,
    recipient: &EncryptionGenerationRecipient,
    exchanges: &[EncryptionPathProbeExchange],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(DELIVERY_DOMAIN);
    hasher.update(assignment.generation.get().to_be_bytes());
    hasher.update(assignment.round.round_digest.0);
    hasher.update((recipient.node_uid.len() as u64).to_be_bytes());
    hasher.update(recipient.node_uid.as_bytes());
    for exchange in exchanges {
        hasher.update([exchange.request.family]);
        match exchange.local_address {
            IpAddr::V4(address) => hasher.update(address.octets()),
            IpAddr::V6(address) => hasher.update(address.octets()),
        }
        match exchange.peer_address {
            IpAddr::V4(address) => hasher.update(address.octets()),
            IpAddr::V6(address) => hasher.update(address.octets()),
        }
        hasher.update(exchange.request.encode());
        hasher.update(exchange.response.encode());
    }
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::path_proof::tests::assignment_fixture;

    #[test]
    #[allow(clippy::too_many_lines)]
    fn fixed_probe_frames_and_delivery_reject_mutation_partial_and_foreign_beacons() {
        let assignment = assignment_fixture();
        let recipient = assignment.round.source.clone();
        let local = derive_wireguard_proof_addresses(
            &assignment.contract.plans[assignment.plan_index]
                .source
                .node
                .pod_cidrs,
        )
        .unwrap();
        let peer = derive_wireguard_proof_addresses(
            &assignment.contract.plans[assignment.plan_index]
                .destination
                .node
                .pod_cidrs,
        )
        .unwrap();
        let exchanges = [PATH_FAMILY_IPV4, PATH_FAMILY_IPV6]
            .into_iter()
            .map(|family| {
                let request = EncryptionPathProbeFrame::request(&assignment.round, family).unwrap();
                let response =
                    EncryptionPathProbeFrame::response(&assignment.round, request).unwrap();
                EncryptionPathProbeExchange::from_wire(
                    &assignment.round,
                    beacon_for_family(&local, family).unwrap(),
                    beacon_for_family(&peer, family).unwrap(),
                    &request.encode(),
                    &response.encode(),
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        let delivery =
            EncryptionPathChallengeDelivery::issue(&assignment, &recipient, exchanges.clone())
                .unwrap();
        let indexed = EncryptionPathProofAssignmentIndex {
            schema_version: crate::ENCRYPTION_PATH_PROOF_SCHEMA_VERSION,
            generation: assignment.generation,
            round: assignment.round.clone(),
            contract_digest: assignment.contract.contract_digest,
            plan_index: assignment.plan_index,
        };
        let indexed_delivery = EncryptionPathChallengeDelivery::issue_indexed(
            &indexed,
            &assignment.contract,
            &recipient,
            exchanges.clone(),
        )
        .unwrap();
        assert_eq!(indexed_delivery.family_mask(), delivery.family_mask());
        assert_eq!(
            indexed_delivery.transcript_digest(),
            delivery.transcript_digest()
        );
        let batch = crate::EncryptionPathProofAssignmentBatch {
            schema_version: crate::ENCRYPTION_PATH_PROOF_ASSIGNMENT_BATCH_SCHEMA_VERSION,
            generation: assignment.generation,
            contracts: vec![assignment.contract.clone()],
            assignments: vec![indexed.clone()],
        }
        .admit()
        .unwrap();
        let admitted_delivery = EncryptionPathChallengeDelivery::issue_from_assignment_batch(
            &batch, &indexed, &recipient, exchanges,
        )
        .unwrap();
        assert_eq!(
            admitted_delivery.transcript_digest(),
            delivery.transcript_digest()
        );
        delivery.verify_for(&assignment.round).unwrap();
        assert_ne!(delivery.transcript_digest(), [0; 32]);

        let request = EncryptionPathProbeFrame::request(&assignment.round, PATH_FAMILY_IPV4)
            .unwrap()
            .encode();
        let response = EncryptionPathProbeFrame::response(
            &assignment.round,
            EncryptionPathProbeFrame::decode(&request).unwrap(),
        )
        .unwrap()
        .encode();
        let one = EncryptionPathProbeExchange::from_wire(
            &assignment.round,
            local[0].address,
            peer[0].address,
            &request,
            &response,
        )
        .unwrap();
        assert!(
            EncryptionPathChallengeDelivery::issue(&assignment, &recipient, vec![one]).is_err()
        );

        let mut mutated = response;
        mutated[40] ^= 1;
        assert!(
            EncryptionPathProbeExchange::from_wire(
                &assignment.round,
                local[0].address,
                peer[0].address,
                &request,
                &mutated,
            )
            .is_err()
        );
    }
}
