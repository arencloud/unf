//! Typed join of independently replayed placement and real kernel snapshots.
//! No eBPF program is published by this module and no packet is admitted.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::os::fd::BorrowedFd;

use thiserror::Error;
use unf_cni_state::{AttachmentJournal, AttachmentJournalCut, AttachmentPhase, AttachmentRecord};
use unf_common::IdentityId;
use unf_encryption::{
    EncryptionLocalityContext, EncryptionLocalityDigest, VerifiedEncryptionLocality,
};
use unf_link::{LinkReadback, NamespaceCookies, VethPlan};
use unf_route::{NativeAttachmentObservation, RouteReadback};

use crate::{IncarnationGate, IncarnationLease, LocalityGateError};

#[derive(Debug, Error)]
pub enum LocalityBankError {
    #[error("locality observation worker: {0}")]
    Worker(&'static str),
    #[error("locality observation runtime: {0}")]
    Runtime(std::io::Error),
    #[error("locality observation task: {0}")]
    Task(tokio::task::JoinError),
    #[error("locality bank has stale, foreign, ambiguous or incomplete input: {0}")]
    Invalid(&'static str),
    #[error("locality bank link: {0}")]
    Link(#[from] unf_link::LinkError),
    #[error("locality bank route: {0}")]
    Route(#[from] unf_route::RouteError),
    #[error("locality bank incarnation: {0}")]
    Gate(#[from] LocalityGateError),
}

/// Metadata index into one bank, not a separately constructible permission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocalityAddress {
    endpoint: usize,
    identity: IdentityId,
}

impl LocalityAddress {
    #[must_use]
    pub const fn endpoint(self) -> usize {
        self.endpoint
    }
    #[must_use]
    pub const fn identity(self) -> IdentityId {
        self.identity
    }
}

/// One observed attachment, shared by its IPv4/IPv6 address entries. No
/// source/destination-pair expansion and no globally unique peer-index rule.
pub struct ObservedLocalityEndpoint {
    observation: NativeAttachmentObservation,
    host_alias: Box<str>,
    peer_alias: Box<str>,
}

impl ObservedLocalityEndpoint {
    #[must_use]
    pub fn attachment(&self) -> &AttachmentRecord {
        self.observation.attachment()
    }
    #[must_use]
    pub fn readback(&self) -> Option<(&LinkReadback, &RouteReadback)> {
        self.observation.readback()
    }
    #[must_use]
    pub fn namespace_cookies(&self) -> Option<NamespaceCookies> {
        self.observation.namespace_cookies()
    }
    #[must_use]
    pub fn namespace_descriptors(&self) -> Option<(BorrowedFd<'_>, BorrowedFd<'_>)> {
        self.observation.namespace_descriptors()
    }
    #[must_use]
    pub fn ownership_aliases(&self) -> (&str, &str) {
        (&self.host_alias, &self.peer_alias)
    }
}

/// Opaque, non-deserializable preparation for a production immutable bank.
/// It retains actual namespace descriptors, independently observed links/routes,
/// exact aliases and replayed placement coordinates. Still only a snapshot.
pub struct ObservedLocalityBank {
    context: EncryptionLocalityContext,
    placement_digest: EncryptionLocalityDigest,
    endpoints: Option<Vec<ObservedLocalityEndpoint>>,
    addresses: BTreeMap<IpAddr, LocalityAddress>,
}

/// Prepared input plus journal-bound live serials, not a loaded eBPF program.
/// The publisher must additionally create frozen device bindings/private context
/// seeds, perform final rechecks and publish under the same current-cut fence.
pub struct LeasedLocalityBank {
    observed: ObservedLocalityBank,
    leases: Vec<IncarnationLease>,
}

impl ObservedLocalityBank {
    /// Join independently authenticated placement with real kernel observations.
    /// The expected context must come from current applied state, not be inferred
    /// from the certificate. Journal origin/currentness is checked separately
    /// by `bind`, never inferred from matching IPs or caller-supplied records.
    ///
    /// # Errors
    /// Rejects foreign/stale context, retired observations, missing UID/nonce,
    /// mismatched exact ownership, duplicate keys/nonces/addresses/devices or
    /// observations from different host namespaces. No partial bank escapes.
    pub fn join(
        evidence: &VerifiedEncryptionLocality,
        expected: &EncryptionLocalityContext,
        mut observations: Vec<NativeAttachmentObservation>,
    ) -> Result<Self, LocalityBankError> {
        if evidence.certificate().context() != expected || observations.len() > 65_536 {
            return Err(LocalityBankError::Invalid("context or inventory bound"));
        }
        observations.sort_unstable_by(|a, b| a.attachment().spec.key.cmp(&b.attachment().spec.key));
        let mut endpoints = Vec::with_capacity(observations.len());
        let mut addresses = BTreeMap::new();
        let mut keys = BTreeSet::new();
        let mut nonces = BTreeSet::new();
        let mut host_devices = BTreeSet::new();
        let mut peer_devices = BTreeSet::new();
        let mut host_cookie = None;
        for observation in observations {
            let record = observation.attachment();
            let owners = exact_owners(record, evidence)?;
            let (links, _) = observation
                .readback()
                .ok_or(LocalityBankError::Invalid("retired route/link observation"))?;
            let cookies = observation
                .namespace_cookies()
                .ok_or(LocalityBankError::Invalid("missing namespace coordinates"))?;
            if observation.namespace_descriptors().is_none()
                || host_cookie.is_some_and(|host| host != cookies.host())
                || !keys.insert(record.spec.key.clone())
                || !nonces.insert(record.creation_token)
                || !host_devices.insert(links.host_index)
                || !peer_devices.insert((cookies.peer(), links.peer_index))
            {
                return Err(LocalityBankError::Invalid(
                    "ambiguous attachment or device ownership",
                ));
            }
            host_cookie = Some(cookies.host());
            let plan = VethPlan::from_attachment(record)?;
            let (host_alias, peer_alias) = plan.ownership_aliases();
            for (address, identity) in owners.into_iter().flatten() {
                if addresses
                    .insert(
                        address,
                        LocalityAddress {
                            endpoint: endpoints.len(),
                            identity,
                        },
                    )
                    .is_some()
                {
                    return Err(LocalityBankError::Invalid("duplicate workload address"));
                }
            }
            endpoints.push(ObservedLocalityEndpoint {
                observation,
                host_alias: host_alias.into(),
                peer_alias: peer_alias.into(),
            });
        }
        Ok(Self {
            context: expected.clone(),
            placement_digest: evidence.certificate().certificate_digest(),
            endpoints: Some(endpoints),
            addresses,
        })
    }

    #[must_use]
    pub const fn context(&self) -> &EncryptionLocalityContext {
        &self.context
    }
    #[must_use]
    pub const fn placement_digest(&self) -> EncryptionLocalityDigest {
        self.placement_digest
    }
    #[must_use]
    pub fn endpoints(&self) -> Option<&[ObservedLocalityEndpoint]> {
        self.endpoints.as_deref()
    }
    #[must_use]
    pub fn addresses(&self) -> Option<&BTreeMap<IpAddr, LocalityAddress>> {
        self.endpoints.as_ref().map(|_| &self.addresses)
    }

    /// Recheck before acquiring the journal publication lock. A failed or
    /// cancelled check permanently retires this preparation, not just one entry.
    ///
    /// # Errors
    /// Rejects retired input or any snapshot drift. No link/route repair occurs.
    pub async fn recheck(&mut self) -> Result<(), LocalityBankError> {
        let mut endpoints = self
            .endpoints
            .take()
            .ok_or(LocalityBankError::Invalid("retired bank preparation"))?;
        NativeAttachmentObservation::recheck_batch(
            endpoints
                .iter_mut()
                .map(|endpoint| &mut endpoint.observation)
                .collect(),
        )
        .await?;
        self.endpoints = Some(endpoints);
        Ok(())
    }

    /// Bind every endpoint to the exact real journal under its transaction lock.
    /// Call only after asynchronous observation, and retain this same lock/cut
    /// through final publication. Supply freshly read applied placement context,
    /// not this object's saved context. No packet program is published here.
    ///
    /// # Errors
    /// Rejects a changed/foreign cut, any changed journal record, a retired bank
    /// or failed kernel issuance. No partially leased bank is returned. Issued
    /// gate entries alone cannot authorize packets; CNI retirement removes them.
    pub fn bind(
        self,
        journal: &AttachmentJournal,
        cut: &AttachmentJournalCut,
        gate: &IncarnationGate,
        current: &EncryptionLocalityContext,
    ) -> Result<LeasedLocalityBank, LocalityBankError> {
        let endpoints = self
            .endpoints
            .as_ref()
            .ok_or(LocalityBankError::Invalid("retired bank preparation"))?;
        if self.context != *current
            || !gate.matches_journal(journal)
            || !journal.is_current(cut)
            || endpoints.iter().any(|endpoint| {
                journal.get(&endpoint.attachment().spec.key) != Some(endpoint.attachment())
            })
        {
            return Err(LocalityBankError::Invalid(
                "journal changed before bank binding",
            ));
        }
        let leases = endpoints
            .iter()
            .map(|endpoint| gate.issue(journal, cut, endpoint.attachment()))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(LeasedLocalityBank {
            observed: self,
            leases,
        })
    }
}

impl LeasedLocalityBank {
    #[must_use]
    pub const fn observed(&self) -> &ObservedLocalityBank {
        &self.observed
    }
    #[must_use]
    pub fn leases(&self) -> &[IncarnationLease] {
        &self.leases
    }
}

type AddressOwners = [Option<(IpAddr, IdentityId)>; 2];

fn exact_owners(
    record: &AttachmentRecord,
    evidence: &VerifiedEncryptionLocality,
) -> Result<AddressOwners, LocalityBankError> {
    if record.phase != AttachmentPhase::Ready
        || record.creation_token.is_none_or(|nonce| nonce == [0; 32])
    {
        return Err(LocalityBankError::Invalid(
            "unbound or non-Ready attachment",
        ));
    }
    let uid = record
        .spec
        .workload_uid
        .as_deref()
        .ok_or(LocalityBankError::Invalid("missing workload UID"))?;
    let facts = evidence.certificate().addresses();
    let mut owners = [None, None];
    for (index, address) in [
        IpAddr::V4(record.lease.ipv4.address),
        IpAddr::V6(record.lease.ipv6.address),
    ]
    .into_iter()
    .enumerate()
    {
        if let Ok(found) = facts.binary_search_by_key(&address, |fact| fact.address) {
            let fact = &facts[found];
            if fact.workload_uid != uid
                || fact.node_uid != evidence.certificate().context().recipient.node_uid
            {
                return Err(LocalityBankError::Invalid(
                    "exact-address placement owner differs",
                ));
            }
            owners[index] = Some((address, fact.identity));
        }
    }
    if owners.iter().all(Option::is_none) {
        return Err(LocalityBankError::Invalid(
            "attachment has no replayed local address",
        ));
    }
    Ok(owners)
}

#[cfg(test)]
pub(crate) mod tests;
