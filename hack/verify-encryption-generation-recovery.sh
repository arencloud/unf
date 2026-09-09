#!/usr/bin/env bash
set -euo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "${project_root}"

if ! command -v rg >/dev/null 2>&1; then
    echo "rg is required to verify Phase 9.5j" >&2
    exit 1
fi

require_text() {
    local relative_file=$1 pattern=$2 description=$3
    if [[ ! -f ${relative_file} ]]; then
        echo "Phase 9.5j file is missing: ${relative_file}" >&2
        exit 1
    fi
    if ! rg --fixed-strings --quiet -- "${pattern}" "${relative_file}"; then
        echo "Phase 9.5j check failed: ${description} (${relative_file})" >&2
        exit 1
    fi
}

require_text crates/unf-encryption/src/generation_frontier.rs \
    'pub struct EncryptionGenerationProducerCheckpoint {' \
    "the active cut and receipts must have one durable image"
require_text crates/unf-encryption/src/generation_frontier.rs \
    'acknowledgement.frontier_digest != active.frontier_digest' \
    "a receipt must be bound to the exact frontier"
require_text crates/unf-encryption/src/generation_frontier.rs \
    'acknowledgement.published != expected' \
    "a receipt must bind the exact per-Node generation"
require_text crates/unf-encryption/src/generation_frontier.rs \
    'PRODUCER_CHECKPOINT_DIGEST_DOMAIN' \
    "durable anti-entropy state must be domain separated"
require_text bins/unf-controller/src/main.rs \
    'restore_encryption_generation_producer(&state)' \
    "the controller must restore before serving agents"
require_text bins/unf-controller/src/main.rs \
    'persist_encryption_generation_if_dirty(&state).await' \
    "new receipts must enter the retrying durable loop"
require_text bins/unf-controller/src/main.rs \
    'encryption_generations_dirty' \
    "persistence races and failures must retain dirty state"
require_text deploy/kubernetes/encryption-generation-store.yaml \
    'name: unf-encryption-generation-frontier' \
    "the durable ConfigMap must be installed"
require_text deploy/kubernetes/rbac.yaml \
    '"unf-encryption-generation-frontier"' \
    "controller RBAC must name only the owned store"
require_text bins/unf-controller/src/main.rs \
    'encryption_generation_frontier_checkpoint_is_durable_and_fail_closed' \
    "controller decoding must fail closed under corruption"
require_text docs/adr/0171-proof-carrying-frontier-recovery.md \
    '**Status:** Accepted and implemented for Phase 9.5j' \
    "the restart decision must be recorded"
require_text docs/project-status.md \
    'Phase 9 proof-carrying frontier recovery' \
    "the authoritative tracker must include Phase 9.5j"

kubectl kustomize deploy >/dev/null
kubectl kustomize deploy/openshift >/dev/null
kubectl kustomize deploy/openshift-primary-cni/runtime >/dev/null

echo "Phase 9.5j generation recovery passed: the exact fleet cut and its frontier-bound receipts survive restart or fail closed"
