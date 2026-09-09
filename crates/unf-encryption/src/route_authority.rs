//! Proof-carrying policy-route activation for the encryption fast path.
//!
//! Linux routes and masked rules must be exact before the Aya generation that
//! can emit their selector becomes authoritative. The publication permit is a
//! compact, replayable witness of that ordering; it is not packet-delivery
//! evidence.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use unf_common::Revision;
use unf_ebpf_common::{ENCRYPTION_ROUTE_MARK_MASK, encryption_route_mark};

use crate::{
    EncryptionFastPathDigest, EncryptionFastPathState, FastPathError, IpPrefix,
    UNF_WIREGUARD_ROUTE_PROTOCOL, WireGuardKernelError, WireGuardKernelSnapshot,
    WireGuardRouteScope,
};

#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "linux")]
pub use linux::LinuxEncryptionRouteProvider;

pub const ENCRYPTION_ROUTE_AUTHORITY_SCHEMA_VERSION: u16 = 1;
pub const ENCRYPTION_ROUTE_PUBLICATION_PERMIT_SCHEMA_VERSION: u16 = 1;
pub const UNF_ENCRYPTION_RULE_PRIORITY_BASE: u32 = 0x554e_0000;
pub const MAX_ENCRYPTION_POLICY_RULES: usize = 8_192;
pub const MAX_ENCRYPTION_ROUTE_WITNESSES: usize = 65_536;

const AUTHORITY_DIGEST_DOMAIN: &[u8] = b"unf.encryption-route-authority.v1\0";
const PERMIT_DIGEST_DOMAIN: &[u8] = b"unf.encryption-route-publication-permit.v1\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum EncryptionRouteFamily {
    Ipv4,
    Ipv6,
}

impl EncryptionRouteFamily {
    #[must_use]
    pub const fn for_address(address: IpAddr) -> Self {
        match address {
            IpAddr::V4(_) => Self::Ipv4,
            IpAddr::V6(_) => Self::Ipv6,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EncryptionPolicyRouteRule {
    pub family: EncryptionRouteFamily,
    pub priority: u32,
    pub route_mark: u32,
    pub route_mark_mask: u32,
    pub route_table: u32,
    pub outer_fwmark: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EncryptionRouteWitness {
    pub prefix: IpPrefix,
    pub interface_index: u32,
    pub route_table: u32,
    pub protocol: u8,
    pub scope: WireGuardRouteScope,
    pub kernel_configuration_digest: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EncryptionRouteAuthorityDigest(pub [u8; 32]);

/// Exact Linux route/rule prerequisites for one fast-path generation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EncryptionRouteAuthority {
    pub schema_version: u16,
    pub generation: Revision,
    pub fast_path_digest: EncryptionFastPathDigest,
    pub rules: Vec<EncryptionPolicyRouteRule>,
    pub routes: Vec<EncryptionRouteWitness>,
    pub authority_digest: EncryptionRouteAuthorityDigest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EncryptionRoutePublicationPermitDigest(pub [u8; 32]);

/// Proof that the exact route prerequisites were read back before map publish.
#[derive(Debug, PartialEq, Eq)]
pub struct EncryptionRoutePublicationPermit {
    schema_version: u16,
    generation: Revision,
    fast_path_digest: EncryptionFastPathDigest,
    authority_digest: EncryptionRouteAuthorityDigest,
    permit_digest: EncryptionRoutePublicationPermitDigest,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EncryptionRoutePublicationPermitWitness {
    schema_version: u16,
    generation: Revision,
    fast_path_digest: EncryptionFastPathDigest,
    authority_digest: EncryptionRouteAuthorityDigest,
    permit_digest: EncryptionRoutePublicationPermitDigest,
}

impl EncryptionRouteAuthority {
    /// Derives a minimal rule set from independently read-back kernel state.
    /// Identical Node/epoch transports share one rule per address family.
    ///
    /// # Errors
    ///
    /// Rejects mutated fast-path state, missing/extra/duplicate snapshots,
    /// mismatched kernel commitments, ambiguous rule authority, or capacity.
    pub fn issue(
        state: &EncryptionFastPathState,
        snapshots: &[WireGuardKernelSnapshot],
    ) -> Result<Self, EncryptionRouteAuthorityError> {
        state
            .verify_integrity()
            .map_err(EncryptionRouteAuthorityError::InvalidFastPath)?;
        let required_digests = state
            .transport_authority
            .iter()
            .map(|transport| transport.kernel_configuration_digest)
            .collect::<BTreeSet<_>>();
        if required_digests.len() != snapshots.len() {
            return Err(EncryptionRouteAuthorityError::KernelEvidenceMismatch);
        }
        let mut indexed = BTreeMap::new();
        for snapshot in snapshots {
            snapshot
                .verify_integrity()
                .map_err(EncryptionRouteAuthorityError::InvalidKernelSnapshot)?;
            if !required_digests.contains(&snapshot.configuration_digest.0)
                || indexed
                    .insert(snapshot.configuration_digest.0, snapshot)
                    .is_some()
            {
                return Err(EncryptionRouteAuthorityError::KernelEvidenceMismatch);
            }
        }

        let mut rules = BTreeSet::new();
        let mut routes = BTreeSet::new();
        let mut selector_tables = BTreeMap::new();
        for transport in &state.transport_authority {
            let snapshot = indexed
                .get(&transport.kernel_configuration_digest)
                .ok_or(EncryptionRouteAuthorityError::KernelEvidenceMismatch)?;
            if snapshot.interface_name != transport.interface_name
                || snapshot.interface_index != transport.interface_index
                || snapshot.fwmark != transport.fwmark
                || snapshot.mtu != transport.mtu
                || snapshot.routes.is_empty()
            {
                return Err(EncryptionRouteAuthorityError::KernelEvidenceMismatch);
            }
            let route_mark = encryption_route_mark(transport.fwmark)
                .ok_or(EncryptionRouteAuthorityError::InvalidRule)?;
            if selector_tables
                .insert(route_mark, transport.route_table)
                .is_some_and(|table| table != transport.route_table)
            {
                return Err(EncryptionRouteAuthorityError::AmbiguousAuthority);
            }
            let priority = rule_priority(route_mark)?;
            for route in &snapshot.routes {
                if route.interface_index != transport.interface_index
                    || route.table != transport.route_table
                    || route.protocol != UNF_WIREGUARD_ROUTE_PROTOCOL
                    || route.scope != WireGuardRouteScope::for_prefix(route.prefix)
                {
                    return Err(EncryptionRouteAuthorityError::KernelEvidenceMismatch);
                }
                let family = EncryptionRouteFamily::for_address(route.prefix.address);
                rules.insert(EncryptionPolicyRouteRule {
                    family,
                    priority,
                    route_mark,
                    route_mark_mask: ENCRYPTION_ROUTE_MARK_MASK,
                    route_table: transport.route_table,
                    outer_fwmark: transport.fwmark,
                });
                routes.insert(EncryptionRouteWitness {
                    prefix: route.prefix,
                    interface_index: route.interface_index,
                    route_table: route.table,
                    protocol: route.protocol,
                    scope: route.scope,
                    kernel_configuration_digest: snapshot.configuration_digest.0,
                });
            }
        }
        if rules.len() > MAX_ENCRYPTION_POLICY_RULES
            || routes.len() > MAX_ENCRYPTION_ROUTE_WITNESSES
        {
            return Err(EncryptionRouteAuthorityError::CapacityExceeded);
        }
        let mut authority = Self {
            schema_version: ENCRYPTION_ROUTE_AUTHORITY_SCHEMA_VERSION,
            generation: Revision::new(state.config.generation),
            fast_path_digest: state.state_digest,
            rules: rules.into_iter().collect(),
            routes: routes.into_iter().collect(),
            authority_digest: EncryptionRouteAuthorityDigest([0; 32]),
        };
        authority.authority_digest = authority.calculate_digest()?;
        authority.verify()?;
        Ok(authority)
    }

    /// Replays canonical structural and digest validation.
    ///
    /// # Errors
    ///
    /// Rejects malformed, reordered, ambiguous, or digest-mutated authority.
    pub fn verify(&self) -> Result<(), EncryptionRouteAuthorityError> {
        if self.schema_version != ENCRYPTION_ROUTE_AUTHORITY_SCHEMA_VERSION
            || self.generation == Revision::INITIAL
            || self.fast_path_digest.0 == [0; 32]
            || self.rules.len() > MAX_ENCRYPTION_POLICY_RULES
            || self.routes.len() > MAX_ENCRYPTION_ROUTE_WITNESSES
            || self.rules.windows(2).any(|pair| pair[0] >= pair[1])
            || self.routes.windows(2).any(|pair| pair[0] >= pair[1])
            || self.authority_digest != self.calculate_digest()?
        {
            return Err(EncryptionRouteAuthorityError::InvalidAuthority);
        }
        let mut families = BTreeSet::new();
        let mut selectors = BTreeMap::new();
        for rule in &self.rules {
            if rule.route_mark_mask != ENCRYPTION_ROUTE_MARK_MASK
                || encryption_route_mark(rule.outer_fwmark) != Some(rule.route_mark)
                || rule.priority != rule_priority(rule.route_mark)?
                || rule.route_table == 0
                || !families.insert((rule.family, rule.route_mark))
                || selectors
                    .insert(rule.route_mark, rule.route_table)
                    .is_some_and(|table| table != rule.route_table)
            {
                return Err(EncryptionRouteAuthorityError::InvalidRule);
            }
            if !self.routes.iter().any(|route| {
                EncryptionRouteFamily::for_address(route.prefix.address) == rule.family
                    && route.route_table == rule.route_table
            }) {
                return Err(EncryptionRouteAuthorityError::InvalidRouteWitness);
            }
        }
        for route in &self.routes {
            if !route.prefix.is_canonical()
                || route.interface_index == 0
                || route.route_table == 0
                || route.protocol != UNF_WIREGUARD_ROUTE_PROTOCOL
                || route.scope != WireGuardRouteScope::for_prefix(route.prefix)
                || route.kernel_configuration_digest == [0; 32]
                || !self.rules.iter().any(|rule| {
                    rule.family == EncryptionRouteFamily::for_address(route.prefix.address)
                        && rule.route_table == route.route_table
                })
            {
                return Err(EncryptionRouteAuthorityError::InvalidRouteWitness);
            }
        }
        if self.rules.is_empty() != self.routes.is_empty() {
            return Err(EncryptionRouteAuthorityError::InvalidAuthority);
        }
        Ok(())
    }

    /// Issues a map-publication permit only after exact rule readback.
    ///
    /// # Errors
    ///
    /// Rejects incomplete, duplicate, extra, or mutated observed rules.
    pub(crate) fn authorize_publication(
        &self,
        observed_rules: &[EncryptionPolicyRouteRule],
    ) -> Result<EncryptionRoutePublicationPermit, EncryptionRouteAuthorityError> {
        self.verify()?;
        if observed_rules != self.rules {
            return Err(EncryptionRouteAuthorityError::RuleReadbackMismatch);
        }
        let mut permit = EncryptionRoutePublicationPermit {
            schema_version: ENCRYPTION_ROUTE_PUBLICATION_PERMIT_SCHEMA_VERSION,
            generation: self.generation,
            fast_path_digest: self.fast_path_digest,
            authority_digest: self.authority_digest,
            permit_digest: EncryptionRoutePublicationPermitDigest([0; 32]),
        };
        permit.permit_digest = permit.calculate_digest()?;
        Ok(permit)
    }

    fn calculate_digest(
        &self,
    ) -> Result<EncryptionRouteAuthorityDigest, EncryptionRouteAuthorityError> {
        let mut canonical = self.clone();
        canonical.authority_digest = EncryptionRouteAuthorityDigest([0; 32]);
        hash_canonical(AUTHORITY_DIGEST_DOMAIN, &canonical).map(EncryptionRouteAuthorityDigest)
    }
}

impl EncryptionRoutePublicationPermit {
    #[must_use]
    pub const fn authority_digest(&self) -> EncryptionRouteAuthorityDigest {
        self.authority_digest
    }

    /// Verifies that this exact pre-publication proof authorizes `state`.
    ///
    /// # Errors
    ///
    /// Rejects mutation, generation reuse, or a different fast-path image.
    pub fn verify_for(
        &self,
        state: &EncryptionFastPathState,
    ) -> Result<(), EncryptionRouteAuthorityError> {
        state
            .verify_integrity()
            .map_err(EncryptionRouteAuthorityError::InvalidFastPath)?;
        if self.schema_version != ENCRYPTION_ROUTE_PUBLICATION_PERMIT_SCHEMA_VERSION
            || self.generation != Revision::new(state.config.generation)
            || self.fast_path_digest != state.state_digest
            || self.authority_digest.0 == [0; 32]
            || self.permit_digest != self.calculate_digest()?
        {
            return Err(EncryptionRouteAuthorityError::InvalidPublicationPermit);
        }
        Ok(())
    }

    fn calculate_digest(
        &self,
    ) -> Result<EncryptionRoutePublicationPermitDigest, EncryptionRouteAuthorityError> {
        let canonical = EncryptionRoutePublicationPermitWitness {
            schema_version: self.schema_version,
            generation: self.generation,
            fast_path_digest: self.fast_path_digest,
            authority_digest: self.authority_digest,
            permit_digest: EncryptionRoutePublicationPermitDigest([0; 32]),
        };
        hash_canonical(PERMIT_DIGEST_DOMAIN, &canonical).map(EncryptionRoutePublicationPermitDigest)
    }
}

fn rule_priority(route_mark: u32) -> Result<u32, EncryptionRouteAuthorityError> {
    if route_mark == 0 || route_mark & !ENCRYPTION_ROUTE_MARK_MASK != 0 {
        return Err(EncryptionRouteAuthorityError::InvalidRule);
    }
    UNF_ENCRYPTION_RULE_PRIORITY_BASE
        .checked_add((route_mark & ENCRYPTION_ROUTE_MARK_MASK) >> 8)
        .ok_or(EncryptionRouteAuthorityError::InvalidRule)
}

fn hash_canonical<T: Serialize>(
    domain: &[u8],
    value: &T,
) -> Result<[u8; 32], EncryptionRouteAuthorityError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| EncryptionRouteAuthorityError::CanonicalEncoding(error.to_string()))?;
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(bytes);
    Ok(hasher.finalize().into())
}

#[derive(Debug, Error)]
pub enum EncryptionRouteAuthorityError {
    #[error("invalid encryption fast-path authority: {0}")]
    InvalidFastPath(FastPathError),
    #[error("invalid WireGuard kernel snapshot: {0}")]
    InvalidKernelSnapshot(WireGuardKernelError),
    #[error("kernel evidence does not exactly cover fast-path transports")]
    KernelEvidenceMismatch,
    #[error("encryption policy-route authority is ambiguous")]
    AmbiguousAuthority,
    #[error("invalid encryption policy-route rule")]
    InvalidRule,
    #[error("invalid encryption route witness")]
    InvalidRouteWitness,
    #[error("encryption route authority exceeds bounded capacity")]
    CapacityExceeded,
    #[error("invalid or mutated encryption route authority")]
    InvalidAuthority,
    #[error("encryption policy-rule readback differs from desired authority")]
    RuleReadbackMismatch,
    #[error("invalid or stale route-before-authority publication permit")]
    InvalidPublicationPermit,
    #[error("Linux encryption route state contains foreign authority: {0}")]
    ForeignState(String),
    #[error("Linux encryption route operation {operation} failed: {message}")]
    Kernel {
        operation: &'static str,
        message: String,
    },
    #[error(
        "Linux encryption route activation failed ({cause}); rollback also failed ({rollback})"
    )]
    Rollback { cause: String, rollback: String },
    #[error("canonical encryption route encoding failed: {0}")]
    CanonicalEncoding(String),
}
