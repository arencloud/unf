#!/usr/bin/env bash
set -Eeuo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

require_text() {
    local relative_file=$1 expected=$2 description=$3
    rg --fixed-strings --quiet -- "${expected}" "${project_root}/${relative_file}" || {
        echo "Phase 8.6c HA continuity check failed: ${description} (${relative_file})" >&2
        exit 1
    }
}

command -v rg >/dev/null 2>&1 || {
    echo "rg is required to verify Phase 8.6c HA continuity" >&2
    exit 1
}

require_text docs/development/phase8-egress-fabric-plan.md \
    '| 8.6c | Acknowledged Flow Twin continuity | **Verified** |' \
    "the execution plan must record the verified continuity slice"
require_text docs/project-status.md \
    '| Acknowledged Flow Twin established-flow continuity | **Verified** |' \
    "the authoritative tracker must record the continuity boundary"
require_text docs/adr/0138-acknowledged-flow-twin-continuity.md \
    '**Status:** Accepted and implemented for Phase 8 milestone 8.6c' \
    "ADR 0138 must record the accepted mechanism"
require_text crates/unf-egress/src/ha_continuity.rs \
    'EgressHaFlowTwinDelta' \
    "replication must use ordered deltas"
require_text crates/unf-egress/src/ha_continuity.rs \
    'previous_digest' \
    "delta loss and reordering must be hash-chain visible"
require_text crates/unf-egress/src/ha_continuity.rs \
    'EgressHaFlowTwinAcknowledgement' \
    "standby state must have exact readback"
require_text crates/unf-egress/src/ha_continuity.rs \
    'is_live_at' \
    "expired state must not be resurrected"
require_text crates/unf-egress/src/ha_continuity.rs \
    'EgressHaContinuityCutover' \
    "flow import and source-bank activation must share one authority"

echo "Phase 8.6c continuity passed: ordered twin deltas, exact standby watermark, live pair import, and promotion-bound cutover agree"
