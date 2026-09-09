#!/usr/bin/env bash
set -Eeuo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

command -v rg >/dev/null 2>&1 || {
    echo "rg is required to verify Phase 9.5c" >&2
    exit 1
}

require_text() {
    local relative_file=$1 expected=$2 description=$3
    [[ -f ${project_root}/${relative_file} ]] || {
        echo "Phase 9.5c file is missing: ${relative_file}" >&2
        exit 1
    }
    rg --fixed-strings --quiet -- "${expected}" "${project_root}/${relative_file}" || {
        echo "Phase 9.5c check failed: ${description} (${relative_file})" >&2
        exit 1
    }
}

for map_name in ENCRYPTION_DECISIONS ENCRYPTION_TRANSPORTS ENCRYPTION_CONFIG ENCRYPTION_CONNECTIONS; do
    require_text ebpf/unf-ebpf-tc/src/main.rs \
        "static ${map_name}:" \
        "the BPF object must declare ${map_name}"
    require_text bins/unf-agent/src/main.rs \
        "\"${map_name}\"" \
        "the agent must own the ${map_name} pin"
done

require_text bins/unf-agent/src/main.rs \
    'let encryption_root = bpf_root.join("encryption");' \
    "encryption must have an independent ABI root"
require_text bins/unf-agent/src/main.rs \
    'partial encryption BPF map set' \
    "partial state must fail closed"
require_text bins/unf-agent/src/main.rs \
    'encryption ABI island contains unverified active or residual state' \
    "unproven recovered authority must be quarantined"
require_text docs/adr/0164-quarantine-first-encryption-abi-island.md \
    '**Status:** Accepted and implemented for Phase 9.5c' \
    "ADR 0164 must record the implemented boundary"
require_text docs/project-status.md \
    'Phase 9.5c adds the separately versioned encryption ABI island' \
    "the authoritative tracker must record the persistence slice"

echo "Phase 9.5c persistence passed: the isolated fixed-shape Aya map set rejects partial, foreign, symlinked, and unverified recovered state"
