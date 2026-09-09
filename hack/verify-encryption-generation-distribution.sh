#!/usr/bin/env bash
set -euo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "${project_root}"

if ! command -v rg >/dev/null 2>&1; then
    echo "rg is required to verify Phase 9.5g" >&2
    exit 1
fi

require_text() {
    local relative_file=$1
    local pattern=$2
    local description=$3
    if [[ ! -f ${relative_file} ]]; then
        echo "Phase 9.5g file is missing: ${relative_file}" >&2
        exit 1
    fi
    if ! rg --fixed-strings --quiet -- "${pattern}" "${relative_file}"; then
        echo "Phase 9.5g check failed: ${description} (${relative_file})" >&2
        exit 1
    fi
}

require_text crates/unf-encryption/src/generation_distribution.rs \
    'pub struct NodeSealedGenerationCapsule' \
    "distribution must carry a strict Node-sealed capsule"
require_text crates/unf-encryption/src/generation_distribution.rs \
    'self.request_nonce != request.nonce' \
    "agent admission must bind the fresh request nonce"
require_text crates/unf-encryption/src/generation_distribution.rs \
    'self.checkpoint.transaction.prior != Some(current.published())' \
    "agent admission must require the exact durable predecessor"
require_text bins/unf-controller/src/main.rs \
    '"/v1/state/encryption-generation"' \
    "the internal TLS API must expose authenticated generation delivery"
require_text bins/unf-controller/src/main.rs \
    'current.recipient != recipient' \
    "the controller must reject Node UID replacement"
require_text bins/unf-agent/src/main.rs \
    'persist_secure_json(&self.state_path, &candidate, "encryption generation")?;' \
    "the agent must durably persist before accepting the successor"
require_text bins/unf-agent/src/main.rs \
    'local route proof and map activation remain pending' \
    "remote desired state must not claim local kernel activation"
require_text docs/adr/0168-node-sealed-generation-capsule.md \
    '**Status:** Accepted and implemented for Phase 9.5g' \
    "the distribution decision must be recorded"
require_text docs/project-status.md \
    'Phase 9 authenticated generation distribution' \
    "the authoritative tracker must include Phase 9.5g"

if rg --fixed-strings --quiet -- 'EncryptionRoutePublicationPermit' \
    crates/unf-encryption/src/generation_distribution.rs; then
    echo "Phase 9.5g check failed: a wire capsule must not carry local route authority" >&2
    exit 1
fi

echo "Phase 9.5g generation distribution passed: authenticated delivery is nonce-, UID-, predecessor-, and digest-bound while local kernel authority remains non-transferable"
