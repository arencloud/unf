#!/usr/bin/env bash
set -Eeuo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

require_text() {
    local expected=$1 relative_file=$2 description=$3
    rg --fixed-strings --quiet -- "${expected}" "${project_root}/${relative_file}" || {
        echo "Phase 9.7e check failed: ${description} (${relative_file})" >&2
        exit 1
    }
}

require_text '"/v1/encryption/explain"' bins/unf-controller/src/main.rs \
    'the controller must expose current causal explanation'
require_text '"/v1/encryption/simulate"' bins/unf-controller/src/main.rs \
    'the controller must expose read-only counterfactual evaluation'
require_text 'minimum_missing_stage: Option<EncryptionOperationalStage>' \
    bins/unf-controller/src/main.rs \
    'results must identify the minimum causal cut'
require_text 'mutex_lock(&state.encryption_operations).checkpoint(),' bins/unf-controller/src/main.rs \
    'simulation must prove that operational evidence is unchanged'
require_text 'Command::EncryptionExplain' bins/unfctl/src/main.rs \
    'operators need a dedicated explanation command'
require_text 'Command::EncryptionSimulate' bins/unfctl/src/main.rs \
    'operators need a dedicated counterfactual command'
require_text 'Minimum Causal Cut Explanation' \
    docs/adr/0204-minimum-causal-cut-explanation.md \
    'the diagnostic boundary must have an accepted design record'

echo 'Phase 9.7e operations query passed: policy-first explanations find the minimum causal cut while counterfactuals remain explicitly non-authoritative and side-effect free'
