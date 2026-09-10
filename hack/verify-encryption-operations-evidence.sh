#!/usr/bin/env bash
set -Eeuo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

require_text() {
    local expected=$1 relative_file=$2 description=$3
    rg --fixed-strings --quiet -- "${expected}" "${project_root}/${relative_file}" || {
        echo "Phase 9.7a check failed: ${description} (${relative_file})" >&2
        exit 1
    }
}

require_text 'pub const ENCRYPTION_OPERATIONAL_STAGE_COUNT: usize = 6;' \
    crates/unf-encryption/src/operations.rs \
    'operational stages must remain a closed cardinality domain'
require_text 'pub const ENCRYPTION_OPERATIONAL_OUTCOME_COUNT: usize = 9;' \
    crates/unf-encryption/src/operations.rs \
    'operational outcomes must remain a closed cardinality domain'
require_text 'pub reported_lost_observations: u64,' \
    crates/unf-encryption/src/operations.rs \
    'status and checkpoints must expose known upstream loss'
require_text 'pub evicted_observations: u64,' \
    crates/unf-encryption/src/operations.rs \
    'retention loss must not look like healthy silence'
require_text 'pub previous_record_digest: EncryptionOperationsHistoryDigest,' \
    crates/unf-encryption/src/operations.rs \
    'bounded history must preserve a tamper-evident causal chain'
require_text 'pub loss_affected: bool,' \
    crates/unf-encryption/src/operations.rs \
    'status must explicitly classify incomplete evidence'
require_text 'Fixed 54-cell metric matrix.' \
    crates/unf-encryption/src/operations.rs \
    'metrics must never label Nodes, peers, policies, contracts, or epochs'
require_text 'Causal Evidence Watermark' \
    docs/adr/0200-causal-evidence-watermark.md \
    'the operations contract must have an accepted design record'

production_source=$(sed '/^#\[cfg(test)\]/q' \
    "${project_root}/crates/unf-encryption/src/operations.rs")
if rg -n 'private_key|privateKey|challenge_(request|response)|nonce:|SocketAddr|IpAddr' \
    <<<"${production_source}"; then
    echo 'Phase 9.7a check failed: operational wire evidence contains secret, reusable, or address material' >&2
    exit 1
fi

echo 'Phase 9.7a operations evidence passed: fixed-cardinality lifecycle counters and a loss-explicit, hash-chained causal watermark expose safe provenance without secret or reusable authority'
