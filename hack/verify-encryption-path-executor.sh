#!/usr/bin/env bash
set -Eeuo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

require_text() {
    local expected=$1 relative_file=$2 description=$3
    rg --fixed-strings --quiet -- "${expected}" "${project_root}/${relative_file}" || {
        echo "Phase 9.6e check failed: ${description} (${relative_file})" >&2
        exit 1
    }
}

reject_text() {
    local rejected=$1 relative_file=$2 description=$3
    if rg --fixed-strings --quiet -- "${rejected}" "${project_root}/${relative_file}"; then
        echo "Phase 9.6e check failed: ${description} (${relative_file})" >&2
        exit 1
    fi
}

require_text 'pub const ENCRYPTION_PATH_PROBE_FRAME_BYTES: usize = 72;' \
    crates/unf-encryption/src/path_probe.rs \
    'the nonce protocol must retain one fixed-width frame'
require_text 'pub struct EncryptionPathChallengeDelivery {' \
    crates/unf-encryption/src/path_probe.rs \
    'only complete exact probe transcripts may become delivery evidence'
require_text 'generations.ensure_probe_routes().await?;' \
    bins/unf-agent/src/main.rs \
    'isolated routes must exist before a proof socket can transmit'
require_text 'execute_live_encryption_path_proofs' \
    bins/unf-agent/src/main.rs \
    'the running agent must execute controller assignments'
require_text 'set_path_probe_mark(&socket, item.route_mark)?;' \
    bins/unf-agent/src/main.rs \
    'every multiplexed exchange must select its exact isolated table'
require_text 'EncryptionPathChallengeDelivery::issue' \
    bins/unf-agent/src/main.rs \
    'wire observations must be sealed before endpoint proof issuance'
require_text '.entry(proof.round_digest)' \
    bins/unf-agent/src/main.rs \
    'retry must preserve the first exact proof for an active round'
reject_text '.bind_device(' \
    bins/unf-agent/src/main.rs \
    'proof execution must not silently require NET_RAW beyond the constrained agent boundary'
require_text 'Phase 9.6e adds the **Mark-Multiplexed Duplex Rendezvous**' \
    docs/adr/0198-mark-multiplexed-duplex-rendezvous.md \
    'ADR 0198 must define the live executor invariant'

echo 'Phase 9.6e path executor passed: fixed nonce frames use exact in-fabric beacons, per-exchange route marks, duplex response, volatile retry identity, and consuming activation without NET_RAW'
