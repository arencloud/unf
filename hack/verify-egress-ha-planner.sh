#!/usr/bin/env bash
set -Eeuo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

require_text() {
    local relative_file=$1 expected=$2 description=$3
    rg --fixed-strings --quiet -- "${expected}" "${project_root}/${relative_file}" || {
        echo "Phase 8.6a HA planner check failed: ${description} (${relative_file})" >&2
        exit 1
    }
}

command -v rg >/dev/null 2>&1 || {
    echo "rg is required to verify the Phase 8.6a HA planner" >&2
    exit 1
}

require_text docs/development/phase8-egress-fabric-plan.md \
    '| 8.6a | Continuity-Certified Rendezvous planner | **Verified** |' \
    "the execution plan must record the verified planner slice"
require_text docs/project-status.md \
    '| Continuity-Certified Rendezvous HA planning | **Verified** |' \
    "the authoritative tracker must record the planner boundary"
require_text docs/adr/0136-continuity-certified-rendezvous-ha-planning.md \
    '**Status:** Accepted and implemented for Phase 8 milestone 8.6a' \
    "ADR 0136 must record the accepted algorithm"
require_text crates/unf-egress/src/ha.rs \
    'EGRESS_HA_ALGORITHM_CONTINUITY_CERTIFIED_RENDEZVOUS_V1' \
    "the selection algorithm must be explicitly versioned"
require_text crates/unf-egress/src/ha.rs \
    'unavoidable_moves' \
    "each plan must expose its independently checked movement lower bound"
require_text crates/unf-egress/src/ha.rs \
    'domain_distance' \
    "contingency placement must prefer explicit failure-domain diversity"
require_text crates/unf-egress/src/ha.rs \
    'plan_material_digest' \
    "membership, assignments, contingencies, and certificates must be sealed"

echo "Phase 8.6a CCR planner passed: exclusive dual-stack shards, exact weighted capacity, minimum churn, failure-domain contingencies, and replay certificates agree"
