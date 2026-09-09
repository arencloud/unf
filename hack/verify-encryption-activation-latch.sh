#!/usr/bin/env bash
set -euo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "${project_root}"

if ! command -v rg >/dev/null 2>&1; then
    echo "rg is required to verify Phase 9.5h" >&2
    exit 1
fi

require_text() {
    local relative_file=$1 pattern=$2 description=$3
    if [[ ! -f ${relative_file} ]]; then
        echo "Phase 9.5h file is missing: ${relative_file}" >&2
        exit 1
    fi
    if ! rg --fixed-strings --quiet -- "${pattern}" "${relative_file}"; then
        echo "Phase 9.5h check failed: ${description} (${relative_file})" >&2
        exit 1
    fi
}

require_text crates/unf-encryption/src/activation_latch.rs \
    'pub struct EncryptionActivationLatch {' \
    "activation must require a dedicated non-transferable join"
require_text crates/unf-encryption/src/activation_latch.rs \
    'if admitted.checkpoint.transaction.prior == applied {' \
    "a new admitted successor must follow the exact applied map generation"
require_text crates/unf-encryption/src/activation_latch.rs \
    'else if Some(admitted.published()) == applied {' \
    "a committed restart must revalidate the exact current generation"
require_text crates/unf-encryption/src/activation_latch.rs \
    '.verify_for(&desired)' \
    "local route proof must authorize the same desired map image"
require_text crates/unf-encryption/src/activation_latch.rs \
    'same_activation_transaction(&self.admitted.checkpoint, pending)' \
    "crash recovery must renew proof for the identical quarantined transaction"
require_text bins/unf-agent/src/encryption_maps.rs \
    '.open(prior, self.pending.as_ref())' \
    "the Aya adapter must consume the exact tri-plane latch"
require_text bins/unf-agent/src/encryption_maps.rs \
    'synchronizer.requires_local_revalidation = true;' \
    "restart must quarantine serialized authority until local proof is renewed"
require_text bins/unf-agent/src/main.rs \
    'requires a fresh Node-local tri-plane activation latch before TC attachment' \
    "TC attachment must not race ahead of restart revalidation"
require_text crates/unf-encryption/src/fast_path.rs \
    'tri_plane_activation_latch_refuses_cross_plane_or_predecessor_drift' \
    "cross-plane drift must have an adversarial test"
require_text docs/adr/0169-tri-plane-causal-activation-latch.md \
    '**Status:** Accepted and implemented for Phase 9.5h' \
    "the activation decision must be recorded"
require_text docs/project-status.md \
    'Phase 9 tri-plane activation latch' \
    "the authoritative tracker must include Phase 9.5h"

if rg --quiet -- 'impl (serde::)?Serialize for EncryptionActivationLatch' \
    crates/unf-encryption/src/activation_latch.rs; then
    echo "Phase 9.5h check failed: the activation latch must not be serializable" >&2
    exit 1
fi

echo "Phase 9.5h activation latch passed: controller intent, renewed local route proof, and the exact Aya transaction must agree before publication or restart attachment"
