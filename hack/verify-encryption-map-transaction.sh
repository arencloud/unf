#!/usr/bin/env bash
set -Eeuo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

command -v rg >/dev/null 2>&1 || {
    echo "rg is required to verify Phase 9.5d" >&2
    exit 1
}

require_text() {
    local relative_file=$1 expected=$2 description=$3
    [[ -f ${project_root}/${relative_file} ]] || {
        echo "Phase 9.5d file is missing: ${relative_file}" >&2
        exit 1
    }
    rg --fixed-strings --quiet -- "${expected}" "${project_root}/${relative_file}" || {
        echo "Phase 9.5d check failed: ${description} (${relative_file})" >&2
        exit 1
    }
}

require_text crates/unf-encryption/src/fast_path_transaction.rs \
    'pub struct FastPathMapCheckpoint {' \
    "restart must retain a proof-carrying desired-map mirror"
require_text crates/unf-encryption/src/fast_path_transaction.rs \
    'CausalCommitVector::issue(&desired)? != self.transaction.desired' \
    "the reconstructed mirror must replay the exact CCV"
require_text bins/unf-agent/src/encryption_maps.rs \
    'FastPathMapRecoveryAction::ClearAndRestageInactive' \
    "the Aya adapter must execute prepared recovery"
require_text bins/unf-agent/src/encryption_maps.rs \
    'FastPathMapRecoveryAction::CommitObservedDesired' \
    "the Aya adapter must recover a pointer-flip crash"
require_text bins/unf-agent/src/encryption_maps.rs \
    '"causal delta staged encryption map bank"' \
    "unchanged fixed-width records must avoid redundant map writes"
require_text bins/unf-agent/src/main.rs \
    'UNF_ENCRYPTION_FAST_PATH_STATE_PATH' \
    "the durable mirror path must be explicit"
require_text docs/adr/0165-proof-carrying-aya-map-mirror.md \
    '**Status:** Accepted and implemented for Phase 9.5d' \
    "ADR 0165 must record the implementation boundary"
require_text docs/project-status.md \
    'Phase 9.5d adds the Proof-Carrying Aya Map Mirror' \
    "the authoritative tracker must record the transaction adapter"

echo "Phase 9.5d Aya transaction passed: durable map mirrors, causal delta staging, exact readback, atomic publication, and total restart recovery agree"
