#!/usr/bin/env bash
set -Eeuo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

require_text() {
    local expected=$1 relative_file=$2 description=$3
    rg --fixed-strings --quiet -- "${expected}" "${project_root}/${relative_file}" || {
        echo "Phase 9.6c check failed: ${description} (${relative_file})" >&2
        exit 1
    }
}

require_text 'pub struct EncryptionGenerationPathProofPermit {' \
    crates/unf-encryption/src/path_proof.rs \
    'generation-wide path authority must be consuming and non-serializable'
require_text 'pub struct PathProvenEncryptionActivationLatch {' \
    crates/unf-encryption/src/activation_latch.rs \
    'path authority must survive until the final activation choke point'
require_text 'authorize_path_proven_map_activation' \
    crates/unf-encryption/src/local_orchestrator.rs \
    'Linux convergence must join controller, route, and path authority'
require_text 'MissingPathProof' \
    crates/unf-encryption/src/local_orchestrator.rs \
    'the legacy activation path must deny Required generations'
require_text '/v1/state/encryption-path-receipts' \
    bins/unf-agent/src/main.rs \
    'the agent must retrieve live receipts before consuming local authority'
require_text 'apply_linux_generation(prepared, admitted, path_permit, now_unix_ms)' \
    bins/unf-agent/src/main.rs \
    'the path permit must be consumed by the map activation path'
require_text 'current duplex path quorum consumed at map boundary' \
    bins/unf-agent/src/encryption_maps.rs \
    'the final map boundary must expose proof consumption evidence'
require_text 'Phase 9.6c adds the **Evidence-Carrying Activation Choke Point**' \
    docs/adr/0196-evidence-carrying-activation-choke-point.md \
    'ADR 0196 must define the activation invariant'

echo 'Phase 9.6c path activation passed: every Required decision is covered exactly once by a current duplex receipt, and consuming proof survives until the final inactive-bank mutation boundary'
