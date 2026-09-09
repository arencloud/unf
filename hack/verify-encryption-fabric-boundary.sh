#!/usr/bin/env bash
set -Eeuo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

command -v rg >/dev/null 2>&1 || {
    echo "rg is required to verify the Phase 9 encryption boundary" >&2
    exit 1
}

require_text() {
    local relative_file=$1 expected=$2 description=$3
    [[ -f ${project_root}/${relative_file} ]] || {
        echo "Phase 9 boundary file is missing: ${relative_file}" >&2
        exit 1
    }
    rg --fixed-strings --quiet -- "${expected}" "${project_root}/${relative_file}" || {
        echo "Phase 9 boundary check failed: ${description} (${relative_file})" >&2
        exit 1
    }
}

require_text '.master-prompt/Rust Universal eBPF Network Fabric.md' \
    '# 25. Encryption' \
    "the master-prompt encryption requirement must remain present"
require_text docs/project-status.md \
    '| Phase 9 — attested encryption fabric | **In progress** |' \
    "the authoritative Phase 9 state must be in progress"
require_text docs/project-status.md \
    '| Architecture and acceptance boundary | **Verified** |' \
    "milestone 9.1 must be tracked as verified"
require_text docs/development/phase9-attested-encryption-fabric-plan.md \
    '| 9.1 | Architecture and acceptance boundary | **Verified** |' \
    "the Phase 9 plan must verify milestone 9.1"
require_text docs/development/phase9-attested-encryption-fabric-plan.md \
    'source identity and security policy authorize the original flow before any' \
    "policy must precede encryption"
require_text docs/development/phase9-attested-encryption-fabric-plan.md \
    'they never fall back to plaintext;' \
    "required encryption must deny rather than downgrade"
require_text docs/development/phase9-attested-encryption-fabric-plan.md \
    'is never sent to the controller.' \
    "private keys must remain Node-local"
require_text docs/development/phase9-attested-encryption-fabric-plan.md \
    'Intent-Coalesced Cryptographic Fast Path' \
    "the bounded transport-coalescing design must remain explicit"
require_text docs/development/phase9-attested-encryption-fabric-plan.md \
    'No algorithm or performance advantage is accepted without a reproducible' \
    "performance claims must require measurements"
require_text docs/development/phase9-attested-encryption-fabric-plan.md \
    'hardware/TPM attestation' \
    "the attestation limitation must remain explicit"
require_text docs/adr/0158-bound-attested-encryption-fabric.md \
    'recency alone is insufficient.' \
    "configuration and path proof must remain distinct"
require_text docs/architecture/components.md \
    'The accepted Phase 9 boundary keeps encryption intent, key authority,' \
    "component ownership must remain explicit"
require_text README.md \
    'Phase 9 begins the attested encryption fabric.' \
    "the user-facing status must expose the active phase"
require_text docs/roadmap.md \
    '## Phase 9 — attested encryption fabric' \
    "the roadmap must include Phase 9"
require_text Makefile \
    'encryption-fabric-boundary-test:' \
    "the architecture gate must be invocable"

for milestone in 9.2 9.3 9.4 9.5 9.6 9.7 9.8 9.9; do
    require_text docs/development/phase9-attested-encryption-fabric-plan.md \
        "| ${milestone} |" \
        "milestone ${milestone} must remain tracked"
done

echo "Phase 9 encryption-fabric boundary passed: policy, contracts, keys, coalescing, rotation, evidence, performance, and exclusions agree"
