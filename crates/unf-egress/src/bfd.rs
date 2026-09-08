//! Digest-sealed BFD readback from an independently versioned routing daemon.
//!
//! These records are liveness evidence, never ownership or promotion proof.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use unf_common::Revision;

use crate::{
    EgressBgpConfig, EgressBgpConfigDigest, MAX_EGRESS_REACHABILITY_ID_BYTES,
    verify_egress_bgp_config,
};

pub const EGRESS_BFD_EVIDENCE_SCHEMA_VERSION: u16 = 1;
pub const EGRESS_BFD_EVIDENCE_ALGORITHM: &str = "bounded-bfd-liveness-v1";
const SNAPSHOT_DIGEST_DOMAIN: &[u8] = b"unf.egress.bfd.snapshot.v1\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EgressBfdSnapshotDigest(pub [u8; 32]);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum EgressBfdSessionState {
    Up,
    Down,
    AdminDown,
    Init,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum EgressBfdDiagnostic {
    None,
    DetectionTimeout,
    EchoFailed,
    NeighborSignaledDown,
    ForwardingPlaneReset,
    PathDown,
    ConcatenatedPathDown,
    AdministrativelyDown,
    ReverseConcatenatedPathDown,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EgressBfdSessionEvidence {
    pub peer_name: String,
    pub peer_address: IpAddr,
    pub failure_domain: String,
    pub state: EgressBfdSessionState,
    pub remote_state: EgressBfdSessionState,
    pub local_diagnostic: EgressBfdDiagnostic,
    pub remote_diagnostic: EgressBfdDiagnostic,
    pub failure_transitions: u64,
    pub local_discriminator: u32,
    pub remote_discriminator: u32,
    pub transmitted_packets: u64,
    pub received_packets: u64,
}

/// Complete exact-Node readback. The source epoch and revision make mutation
/// and replay checks possible at the authenticated controller boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EgressBfdSnapshot {
    pub schema_version: u16,
    pub algorithm: String,
    pub config_digest: EgressBgpConfigDigest,
    pub node_name: String,
    pub node_uid: String,
    pub source_epoch: u64,
    pub revision: Revision,
    pub observed_at_unix_seconds: u64,
    pub sessions: Vec<EgressBfdSessionEvidence>,
    pub digest: EgressBfdSnapshotDigest,
}

/// Self-contained authenticated-agent payload. Shipping the sealed public BGP
/// contract with its evidence lets the controller independently replay a
/// node-local provider configuration without sharing daemon state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EgressBfdEvidenceReport {
    pub config: EgressBgpConfig,
    pub snapshot: EgressBfdSnapshot,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum EgressBfdEvidenceError {
    #[error("invalid BFD evidence snapshot")]
    InvalidSnapshot,
    #[error("BFD evidence snapshot does not exactly match configured peers")]
    PeerMismatch,
    #[error("BFD evidence snapshot digest does not match")]
    DigestMismatch,
    #[error("BFD evidence canonical encoding failed: {0}")]
    Encoding(String),
}

/// Canonicalizes and seals complete daemon readback.
///
/// # Errors
///
/// Rejects invalid identity, source position, configuration, or any missing,
/// duplicate, extra, or drifted BFD peer.
pub fn seal_egress_bfd_snapshot(
    config: &EgressBgpConfig,
    mut snapshot: EgressBfdSnapshot,
) -> Result<EgressBfdSnapshot, EgressBfdEvidenceError> {
    let config = verify_egress_bgp_config(config.clone())
        .map_err(|_| EgressBfdEvidenceError::InvalidSnapshot)?;
    snapshot.sessions.sort_unstable();
    let expected = config
        .peers
        .iter()
        .filter(|peer| peer.bfd.is_some())
        .map(|peer| {
            (
                peer.name.as_str(),
                peer.address,
                peer.failure_domain.as_str(),
            )
        })
        .collect::<Vec<_>>();
    if snapshot.schema_version != EGRESS_BFD_EVIDENCE_SCHEMA_VERSION
        || snapshot.algorithm != EGRESS_BFD_EVIDENCE_ALGORITHM
        || snapshot.config_digest != config.digest
        || !valid_id(&snapshot.node_name)
        || !valid_id(&snapshot.node_uid)
        || snapshot.source_epoch == 0
        || snapshot.revision == Revision::INITIAL
        || snapshot.observed_at_unix_seconds == 0
        || snapshot.sessions.windows(2).any(|pair| {
            pair[0].peer_name == pair[1].peer_name || pair[0].peer_address == pair[1].peer_address
        })
    {
        return Err(EgressBfdEvidenceError::InvalidSnapshot);
    }
    if snapshot.sessions.len() != expected.len()
        || snapshot.sessions.iter().any(|session| {
            !expected.iter().any(|(name, address, domain)| {
                session.peer_name == *name
                    && session.peer_address == *address
                    && session.failure_domain == *domain
            })
        })
    {
        return Err(EgressBfdEvidenceError::PeerMismatch);
    }
    snapshot.digest = EgressBfdSnapshotDigest(hash(&(
        snapshot.schema_version,
        &snapshot.algorithm,
        snapshot.config_digest,
        &snapshot.node_name,
        &snapshot.node_uid,
        snapshot.source_epoch,
        snapshot.revision,
        snapshot.observed_at_unix_seconds,
        &snapshot.sessions,
    ))?);
    Ok(snapshot)
}

/// Independently replays a sealed BFD snapshot.
///
/// # Errors
///
/// Rejects any semantic, canonical, configuration, or digest drift.
pub fn verify_egress_bfd_snapshot(
    config: &EgressBgpConfig,
    snapshot: EgressBfdSnapshot,
) -> Result<EgressBfdSnapshot, EgressBfdEvidenceError> {
    let expected = snapshot.digest;
    let replayed = seal_egress_bfd_snapshot(config, snapshot)?;
    if replayed.digest != expected {
        return Err(EgressBfdEvidenceError::DigestMismatch);
    }
    Ok(replayed)
}

/// Independently verifies the self-contained agent report.
///
/// # Errors
///
/// Rejects an invalid BGP contract or a snapshot that fails exact replay.
pub fn verify_egress_bfd_evidence_report(
    report: EgressBfdEvidenceReport,
) -> Result<EgressBfdEvidenceReport, EgressBfdEvidenceError> {
    let config = verify_egress_bgp_config(report.config)
        .map_err(|_| EgressBfdEvidenceError::InvalidSnapshot)?;
    let snapshot = verify_egress_bfd_snapshot(&config, report.snapshot)?;
    Ok(EgressBfdEvidenceReport { config, snapshot })
}

fn hash<T: Serialize>(value: &T) -> Result<[u8; 32], EgressBfdEvidenceError> {
    let encoded = serde_json::to_vec(value)
        .map_err(|error| EgressBfdEvidenceError::Encoding(error.to_string()))?;
    let mut digest = Sha256::new();
    digest.update(SNAPSHOT_DIGEST_DOMAIN);
    digest.update(encoded);
    Ok(digest.finalize().into())
}

fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_EGRESS_REACHABILITY_ID_BYTES
        && !value.chars().any(char::is_control)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;
    use crate::{
        EGRESS_BFD_SINGLE_HOP_PORT, EGRESS_BGP_ALGORITHM, EGRESS_BGP_SCHEMA_VERSION,
        EgressBgpAddressFamily, EgressBgpBfdConfig, EgressBgpConfigDigest,
        EgressBgpGracefulRestart, EgressBgpPeer, EgressBgpPrefix,
        MAX_EGRESS_BFD_INTERVAL_MICROSECONDS, seal_egress_bgp_config,
    };

    fn config() -> EgressBgpConfig {
        seal_egress_bgp_config(EgressBgpConfig {
            schema_version: EGRESS_BGP_SCHEMA_VERSION,
            algorithm: EGRESS_BGP_ALGORITHM.to_owned(),
            revision: Revision::new(1),
            instance: "edge".to_owned(),
            local_asn: 64_512,
            router_id: "192.0.2.1".parse().unwrap(),
            ipv4_next_hop: Some("192.0.2.1".parse().unwrap()),
            ipv6_next_hop: None,
            peers: vec![EgressBgpPeer {
                name: "fabric-a".to_owned(),
                address: "192.0.2.2".parse().unwrap(),
                remote_asn: 64_513,
                failure_domain: "rack-a".to_owned(),
                families: BTreeSet::from([EgressBgpAddressFamily::Ipv4]),
                multihop_ttl: 1,
                maximum_received_prefixes: 100,
                bfd: Some(EgressBgpBfdConfig {
                    port: EGRESS_BFD_SINGLE_HOP_PORT,
                    desired_minimum_tx_interval_microseconds: 300_000,
                    required_minimum_receive_interval_microseconds: 300_000,
                    detection_multiplier: 3,
                }),
            }],
            permitted_export_prefixes: vec![EgressBgpPrefix {
                address: "192.0.2.0".parse().unwrap(),
                length: 24,
            }],
            maximum_changed_prefixes: 10,
            maximum_total_prefixes: 100,
            maximum_paths_per_prefix: 1,
            graceful_restart: EgressBgpGracefulRestart {
                restart_seconds: 30,
                stale_path_seconds: 90,
            },
            digest: EgressBgpConfigDigest([0; 32]),
        })
        .unwrap()
    }

    fn snapshot(config: &EgressBgpConfig) -> EgressBfdSnapshot {
        seal_egress_bfd_snapshot(
            config,
            EgressBfdSnapshot {
                schema_version: EGRESS_BFD_EVIDENCE_SCHEMA_VERSION,
                algorithm: EGRESS_BFD_EVIDENCE_ALGORITHM.to_owned(),
                config_digest: config.digest,
                node_name: "worker-a".to_owned(),
                node_uid: "worker-a-uid".to_owned(),
                source_epoch: 4,
                revision: Revision::new(7),
                observed_at_unix_seconds: 1_000,
                sessions: vec![EgressBfdSessionEvidence {
                    peer_name: "fabric-a".to_owned(),
                    peer_address: "192.0.2.2".parse().unwrap(),
                    failure_domain: "rack-a".to_owned(),
                    state: EgressBfdSessionState::Up,
                    remote_state: EgressBfdSessionState::Up,
                    local_diagnostic: EgressBfdDiagnostic::None,
                    remote_diagnostic: EgressBfdDiagnostic::None,
                    failure_transitions: 0,
                    local_discriminator: 10,
                    remote_discriminator: 20,
                    transmitted_packets: 30,
                    received_packets: 29,
                }],
                digest: EgressBfdSnapshotDigest([0; 32]),
            },
        )
        .unwrap()
    }

    #[test]
    fn exact_snapshot_replays_and_mutation_fails() {
        let config = config();
        let snapshot = snapshot(&config);
        assert_eq!(
            verify_egress_bfd_snapshot(&config, snapshot.clone()).unwrap(),
            snapshot
        );
        let mut changed = snapshot;
        changed.sessions[0].state = EgressBfdSessionState::Down;
        assert_eq!(
            verify_egress_bfd_snapshot(&config, changed),
            Err(EgressBfdEvidenceError::DigestMismatch)
        );
    }

    #[test]
    fn missing_peer_and_unsafe_bfd_policy_fail_closed() {
        let config = config();
        let mut missing = snapshot(&config);
        missing.sessions.clear();
        assert_eq!(
            seal_egress_bfd_snapshot(&config, missing),
            Err(EgressBfdEvidenceError::PeerMismatch)
        );

        let mut unsafe_config = config;
        unsafe_config.peers[0]
            .bfd
            .as_mut()
            .unwrap()
            .desired_minimum_tx_interval_microseconds = MAX_EGRESS_BFD_INTERVAL_MICROSECONDS + 1;
        assert!(seal_egress_bgp_config(unsafe_config).is_err());
    }
}
