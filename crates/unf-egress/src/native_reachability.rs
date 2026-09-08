//! Non-authoritative, nonce-bound proof that an exact gateway Node currently
//! owns an egress address in kernel state.
//!
//! The proof is intentionally only one input to DQR. It prevents cached HTTP
//! success or a response from the wrong gateway being mistaken for the exact
//! lease, while independent authenticated observers remain the authority that
//! decides external reachability.

use std::fmt::Write as _;
use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use unf_common::Revision;

use crate::{EgressReachabilityPlanDigest, MAX_EGRESS_REACHABILITY_ID_BYTES};

pub const NATIVE_EGRESS_REACHABILITY_PROBE_SCHEMA_VERSION: u16 = 1;
pub const NATIVE_EGRESS_REACHABILITY_PROBE_ALGORITHM: &str = "nonce-bound-kernel-ownership-v1";
pub const NATIVE_EGRESS_REACHABILITY_PROBE_MAX_AGE_SECONDS: u64 = 30;

const PROBE_DIGEST_DOMAIN: &[u8] = b"unf.egress.native-reachability-probe.v1\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct NativeEgressReachabilityNonce(pub [u8; 32]);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct NativeEgressReachabilityProbeDigest(pub [u8; 32]);

/// Exact challenge issued by a fabric observer. The plan digest transitively
/// binds owner, provider, allocation, lease, action, addresses, and paths.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct NativeEgressReachabilityChallenge {
    pub schema_version: u16,
    pub plan_digest: EgressReachabilityPlanDigest,
    pub desired_revision: Revision,
    pub lease_epoch: u64,
    pub address: IpAddr,
    pub nonce: NativeEgressReachabilityNonce,
}

/// Kernel-read-back ownership response. This is a freshness and path-binding
/// primitive, not a provider acknowledgement or standalone authorization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct NativeEgressReachabilityProbe {
    pub schema_version: u16,
    pub algorithm: String,
    pub challenge: NativeEgressReachabilityChallenge,
    pub node_name: String,
    pub node_uid: String,
    pub pod_name: String,
    pub pod_uid: String,
    pub observed_at_unix_seconds: u64,
    pub digest: NativeEgressReachabilityProbeDigest,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum NativeEgressReachabilityProbeError {
    #[error("native reachability challenge is invalid")]
    InvalidChallenge,
    #[error("native reachability probe identity is invalid")]
    InvalidIdentity,
    #[error("native reachability probe is stale or from the future")]
    StaleProbe,
    #[error("native reachability probe digest does not match")]
    DigestMismatch,
    #[error("native reachability hexadecimal value is invalid")]
    InvalidHex,
    #[error("native reachability probe encoding failed: {0}")]
    Encoding(String),
}

/// Issues a digest-bound response after the caller has read back exact kernel
/// address ownership.
///
/// # Errors
///
/// Rejects malformed challenges, identities, or timestamps.
pub fn issue_native_egress_reachability_probe(
    challenge: NativeEgressReachabilityChallenge,
    node_name: String,
    node_uid: String,
    pod_name: String,
    pod_uid: String,
    observed_at_unix_seconds: u64,
) -> Result<NativeEgressReachabilityProbe, NativeEgressReachabilityProbeError> {
    validate_challenge(&challenge)?;
    if [&node_name, &node_uid, &pod_name, &pod_uid]
        .into_iter()
        .any(|value| !valid_id(value))
    {
        return Err(NativeEgressReachabilityProbeError::InvalidIdentity);
    }
    if observed_at_unix_seconds == 0 {
        return Err(NativeEgressReachabilityProbeError::StaleProbe);
    }
    let mut probe = NativeEgressReachabilityProbe {
        schema_version: NATIVE_EGRESS_REACHABILITY_PROBE_SCHEMA_VERSION,
        algorithm: NATIVE_EGRESS_REACHABILITY_PROBE_ALGORITHM.to_owned(),
        challenge,
        node_name,
        node_uid,
        pod_name,
        pod_uid,
        observed_at_unix_seconds,
        digest: NativeEgressReachabilityProbeDigest([0; 32]),
    };
    probe.digest = probe_digest(&probe)?;
    Ok(probe)
}

/// Replays a probe and applies a bounded freshness window.
///
/// # Errors
///
/// Rejects semantic drift, mutation, expired evidence, or future evidence.
pub fn verify_native_egress_reachability_probe(
    probe: NativeEgressReachabilityProbe,
    expected: &NativeEgressReachabilityChallenge,
    expected_node_uid: &str,
    now_unix_seconds: u64,
) -> Result<NativeEgressReachabilityProbe, NativeEgressReachabilityProbeError> {
    if &probe.challenge != expected || probe.node_uid != expected_node_uid {
        return Err(NativeEgressReachabilityProbeError::InvalidIdentity);
    }
    let expected_digest = probe.digest;
    let replayed = issue_native_egress_reachability_probe(
        probe.challenge,
        probe.node_name,
        probe.node_uid,
        probe.pod_name,
        probe.pod_uid,
        probe.observed_at_unix_seconds,
    )?;
    if replayed.digest != expected_digest {
        return Err(NativeEgressReachabilityProbeError::DigestMismatch);
    }
    if replayed.observed_at_unix_seconds > now_unix_seconds.saturating_add(5)
        || now_unix_seconds.saturating_sub(replayed.observed_at_unix_seconds)
            > NATIVE_EGRESS_REACHABILITY_PROBE_MAX_AGE_SECONDS
    {
        return Err(NativeEgressReachabilityProbeError::StaleProbe);
    }
    Ok(replayed)
}

#[must_use]
pub fn encode_native_egress_reachability_hex(bytes: &[u8; 32]) -> String {
    let mut encoded = String::with_capacity(64);
    for byte in bytes {
        write!(&mut encoded, "{byte:02x}").expect("writing to String cannot fail");
    }
    encoded
}

/// Decodes an exact lowercase or uppercase 32-byte hexadecimal value.
///
/// # Errors
///
/// Rejects values that are not exactly 64 hexadecimal characters.
pub fn decode_native_egress_reachability_hex(
    value: &str,
) -> Result<[u8; 32], NativeEgressReachabilityProbeError> {
    if value.len() != 64 {
        return Err(NativeEgressReachabilityProbeError::InvalidHex);
    }
    let mut decoded = [0_u8; 32];
    for (index, slot) in decoded.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| NativeEgressReachabilityProbeError::InvalidHex)?;
    }
    Ok(decoded)
}

fn validate_challenge(
    challenge: &NativeEgressReachabilityChallenge,
) -> Result<(), NativeEgressReachabilityProbeError> {
    if challenge.schema_version != NATIVE_EGRESS_REACHABILITY_PROBE_SCHEMA_VERSION
        || challenge.desired_revision == Revision::INITIAL
        || challenge.lease_epoch == 0
        || challenge.address.is_unspecified()
        || challenge.address.is_multicast()
        || challenge.plan_digest.0 == [0; 32]
        || challenge.nonce.0 == [0; 32]
    {
        return Err(NativeEgressReachabilityProbeError::InvalidChallenge);
    }
    Ok(())
}

fn probe_digest(
    probe: &NativeEgressReachabilityProbe,
) -> Result<NativeEgressReachabilityProbeDigest, NativeEgressReachabilityProbeError> {
    let mut unsigned = probe.clone();
    unsigned.digest = NativeEgressReachabilityProbeDigest([0; 32]);
    let encoded = serde_json::to_vec(&unsigned)
        .map_err(|error| NativeEgressReachabilityProbeError::Encoding(error.to_string()))?;
    let mut hasher = Sha256::new();
    hasher.update(PROBE_DIGEST_DOMAIN);
    hasher.update(encoded);
    Ok(NativeEgressReachabilityProbeDigest(
        hasher.finalize().into(),
    ))
}

fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_EGRESS_REACHABILITY_ID_BYTES
        && !value.chars().any(char::is_control)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn challenge() -> NativeEgressReachabilityChallenge {
        NativeEgressReachabilityChallenge {
            schema_version: NATIVE_EGRESS_REACHABILITY_PROBE_SCHEMA_VERSION,
            plan_digest: EgressReachabilityPlanDigest([7; 32]),
            desired_revision: Revision::new(8),
            lease_epoch: 9,
            address: "192.0.2.240".parse().unwrap(),
            nonce: NativeEgressReachabilityNonce([11; 32]),
        }
    }

    #[test]
    fn probe_replay_binds_nonce_plan_lease_address_and_gateway() {
        let probe = issue_native_egress_reachability_probe(
            challenge(),
            "worker-a".to_owned(),
            "node-uid-a".to_owned(),
            "agent-a".to_owned(),
            "pod-uid-a".to_owned(),
            1_000,
        )
        .unwrap();
        assert!(
            verify_native_egress_reachability_probe(
                probe.clone(),
                &challenge(),
                "node-uid-a",
                1_010,
            )
            .is_ok()
        );

        let mut foreign_nonce = challenge();
        foreign_nonce.nonce = NativeEgressReachabilityNonce([12; 32]);
        assert!(
            verify_native_egress_reachability_probe(
                probe.clone(),
                &foreign_nonce,
                "node-uid-a",
                1_010,
            )
            .is_err()
        );
        assert!(
            verify_native_egress_reachability_probe(probe, &challenge(), "node-uid-b", 1_010)
                .is_err()
        );
    }

    #[test]
    fn probe_rejects_stale_or_mutated_evidence() {
        let mut probe = issue_native_egress_reachability_probe(
            challenge(),
            "worker-a".to_owned(),
            "node-uid-a".to_owned(),
            "agent-a".to_owned(),
            "pod-uid-a".to_owned(),
            1_000,
        )
        .unwrap();
        assert_eq!(
            verify_native_egress_reachability_probe(
                probe.clone(),
                &challenge(),
                "node-uid-a",
                1_031,
            ),
            Err(NativeEgressReachabilityProbeError::StaleProbe)
        );
        probe.pod_uid = "mutated".to_owned();
        assert_eq!(
            verify_native_egress_reachability_probe(probe, &challenge(), "node-uid-a", 1_001,),
            Err(NativeEgressReachabilityProbeError::DigestMismatch)
        );
    }

    #[test]
    fn exact_hex_round_trip_rejects_ambiguity() {
        let bytes = [0xab; 32];
        let encoded = encode_native_egress_reachability_hex(&bytes);
        assert_eq!(decode_native_egress_reachability_hex(&encoded), Ok(bytes));
        assert!(decode_native_egress_reachability_hex("ab").is_err());
        assert!(decode_native_egress_reachability_hex(&"zz".repeat(32)).is_err());
    }
}
