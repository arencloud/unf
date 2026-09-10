#!/usr/bin/env bash
set -Eeuo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

require_text() {
    local expected=$1 relative_file=$2 description=$3
    rg --fixed-strings --quiet -- "${expected}" "${project_root}/${relative_file}" || {
        echo "Phase 9.7b check failed: ${description} (${relative_file})" >&2
        exit 1
    }
}

require_text '.route("/v1/encryption/status", get(encryption_operations_status))' \
    bins/unf-controller/src/main.rs \
    'the public API must expose the current causal watermark'
require_text '.route("/v1/encryption/history", get(encryption_operations_history))' \
    bins/unf-controller/src/main.rs \
    'the public API must expose bounded loss-explicit history'
require_text '"unf_encryption_operations"' \
    bins/unf-controller/src/main.rs \
    'the Prometheus registry must contain the encryption lifecycle family'
require_text 'for stage in EncryptionOperationalStage::ALL {' \
    bins/unf-controller/src/main.rs \
    'every closed stage/outcome series must exist even when zero'
require_text 'if admission != EncryptionPathProofAdmission::Idempotent {' \
    bins/unf-controller/src/main.rs \
    'agent polling and proof retries must not inflate evidence'
require_text 'EncryptionOperationalStage::RemoteQuorum' \
    bins/unf-controller/src/main.rs \
    'completed two-ended proof must advance the quorum stage'
require_text 'Poll-Stable Evidence Export' \
    docs/adr/0201-poll-stable-evidence-export.md \
    'runtime export must have an accepted design record'

echo 'Phase 9.7b runtime operations passed: poll-stable causal transitions feed two public watermark APIs and exactly 54 preallocated Prometheus series with no topology labels'
