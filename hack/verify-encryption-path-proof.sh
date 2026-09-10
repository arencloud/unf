#!/usr/bin/env bash
set -Eeuo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

require_text() {
    local expected=$1 relative_file=$2 description=$3
    rg --fixed-strings --quiet -- "${expected}" "${project_root}/${relative_file}" || {
        echo "Phase 9.6a check failed: ${description} (${relative_file})" >&2
        exit 1
    }
}

require_text 'pub struct EncryptionPathProofRound {' \
    crates/unf-encryption/src/path_proof.rs \
    'the challenge round must bind fresh immutable authority'
require_text 'pub struct EncryptionPeerCounterDelta {' \
    crates/unf-encryption/src/path_proof.rs \
    'handshake recency must not replace counter movement'
require_text 'pub struct EncryptionEndpointPathProof {' \
    crates/unf-encryption/src/path_proof.rs \
    'each authenticated endpoint must publish independent evidence'
require_text 'pub struct EncryptionPathActivationReceipt {' \
    crates/unf-encryption/src/path_proof.rs \
    'only a complete duplex quorum may produce a receipt'
require_text 'causal_duplex_quorum_requires_both_authenticated_counter_backed_transcripts' \
    crates/unf-encryption/src/path_proof.rs \
    'the complete quorum boundary must be exercised'
require_text 'roaming_replay_counter_stall_and_mutation_deny_closed' \
    crates/unf-encryption/src/path_proof.rs \
    'stale or insufficient evidence must deny closed'
require_text 'Phase 9.6a introduces the **Causal Duplex Path Quorum**' \
    docs/adr/0194-causal-duplex-path-quorum.md \
    'ADR 0194 must define the evidence innovation'

echo 'Phase 9.6a path proof passed: exact two-ended identity, contract, kernel, counter, family, nonce, expiry, and challenge evidence form one non-substitutable quorum'
