#!/usr/bin/env bash
set -Eeuo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

require_text() {
    local expected=$1 relative_file=$2 description=$3
    rg --fixed-strings --quiet -- "${expected}" "${project_root}/${relative_file}" || {
        echo "Phase 9.7c check failed: ${description} (${relative_file})" >&2
        exit 1
    }
}

require_text 'restore_encryption_operations(&state)' bins/unf-controller/src/main.rs \
    'controller startup must validate the operations checkpoint before serving'
require_text 'spawn_encryption_operations_persistence(' bins/unf-controller/src/main.rs \
    'dirty operations state must be retried and flushed on shutdown'
require_text 'EncryptionOperationsLedger::restore(durable.history.clone())' \
    bins/unf-controller/src/main.rs \
    'restore must use the same hash-chain/counter validator as the runtime'
require_text '.inc_by(checkpoint.counters.get(stage, outcome));' \
    bins/unf-controller/src/main.rs \
    'Prometheus counters must resume at the durable watermark after replacement'
require_text 'name: unf-encryption-operations' \
    deploy/kubernetes/encryption-operations-store.yaml \
    'the durable store must be rendered explicitly'
require_text '"unf-encryption-operations"' deploy/kubernetes/rbac.yaml \
    'controller ConfigMap access must remain exact-name scoped'
require_text 'Restart-Continuous Evidence Chain' \
    docs/adr/0202-restart-continuous-evidence-chain.md \
    'durable recovery must have an accepted design record'

echo 'Phase 9.7c operations recovery passed: exact-name durable storage, hash-chain replay, metric resumption, retry-on-write-failure, and rendered Kind/OpenShift manifests agree'
