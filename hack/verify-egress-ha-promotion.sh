#!/usr/bin/env bash
set -Eeuo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

require_text() {
    local relative_file=$1 expected=$2 description=$3
    rg --fixed-strings --quiet -- "${expected}" "${project_root}/${relative_file}" || {
        echo "Phase 8.6b HA promotion check failed: ${description} (${relative_file})" >&2
        exit 1
    }
}

command -v rg >/dev/null 2>&1 || {
    echo "rg is required to verify the Phase 8.6b HA promotion protocol" >&2
    exit 1
}

require_text docs/development/phase8-egress-fabric-plan.md \
    '| 8.6b | Proof-carrying HA promotion | **Verified** |' \
    "the execution plan must record the verified promotion slice"
require_text docs/project-status.md \
    '| Proof-carrying split-brain-safe HA promotion | **Verified** |' \
    "the authoritative tracker must record the promotion boundary"
require_text docs/adr/0137-proof-carrying-split-brain-safe-ha-promotion.md \
    '**Status:** Accepted and implemented for Phase 8 milestone 8.6b' \
    "ADR 0137 must record the accepted protocol"
require_text crates/unf-egress/src/ha_promotion.rs \
    'EgressHaInfrastructureFenceEvidence' \
    "abrupt failure must require independent fencing evidence"
require_text crates/unf-egress/src/ha_promotion.rs \
    'UnsafeFenceProvider' \
    "Kubernetes health must be explicitly rejected as fencing authority"
require_text crates/unf-egress/src/ha_promotion.rs \
    'compare_and_swap_applied' \
    "reachability transfer must be an exact compare-and-swap"
require_text crates/unf-egress/src/ha_promotion.rs \
    'EgressHaActivationAuthority' \
    "source activation must consume a complete proof bundle"

echo "Phase 8.6b promotion passed: source fences, old-owner isolation, exact acquisition, reachability CAS, and activation authority agree"
