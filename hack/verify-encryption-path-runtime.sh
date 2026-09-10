#!/usr/bin/env bash
set -Eeuo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

require_text() {
    local expected=$1 relative_file=$2 description=$3
    rg --fixed-strings --quiet -- "${expected}" "${project_root}/${relative_file}" || {
        echo "Phase 9.6b check failed: ${description} (${relative_file})" >&2
        exit 1
    }
}

require_text 'pub struct EncryptionPathProofCoordinator {' \
    crates/unf-encryption/src/path_proof.rs \
    'the complete fleet generation must own challenge visibility'
require_text 'generation_fenced_coordinator_scopes_assignments_and_clears_old_evidence' \
    crates/unf-encryption/src/path_proof.rs \
    'generation replacement and endpoint scoping must be exercised'
require_text '/v1/state/encryption-path-proof-assignments' \
    bins/unf-controller/src/main.rs \
    'authenticated agents need an assignment endpoint'
require_text '/v1/state/encryption-path-proofs' \
    bins/unf-controller/src/main.rs \
    'authenticated agents need an append-only evidence endpoint'
require_text '/v1/state/encryption-path-receipts' \
    bins/unf-controller/src/main.rs \
    'complete receipts need a Node-scoped endpoint'
require_text 'require_current_encryption_agent(&state, &agent)?;' \
    bins/unf-controller/src/main.rs \
    'every runtime path must retain current Pod authentication'
require_text 'Phase 9.6b adds the **Pull-Synchronized Duplex Proof Exchange**' \
    docs/adr/0195-pull-synchronized-duplex-proof-exchange.md \
    'ADR 0195 must define the runtime boundary'

echo 'Phase 9.6b runtime exchange passed: one active fleet generation issues Node-scoped proof work, admits only current authenticated endpoint evidence, and exposes only completed live receipts'
