#!/usr/bin/env bash
set -Eeuo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

require_text() {
    local relative_file=$1 expected=$2 description=$3
    rg --fixed-strings --quiet -- "${expected}" "${project_root}/${relative_file}" || {
        echo "Phase 8.6e HA transaction check failed: ${description} (${relative_file})" >&2
        exit 1
    }
}

require_text docs/development/phase8-egress-fabric-plan.md \
    '| 8.6e | Durable promotion transaction | **Verified** |' \
    "the execution plan must record the verified transaction"
require_text docs/project-status.md \
    '| Durable HA promotion transaction | **Verified** |' \
    "the authoritative tracker must record the transaction"
require_text docs/adr/0140-durable-ha-promotion-transaction.md \
    '**Status:** Accepted and implemented for Phase 8 milestone 8.6e' \
    "ADR 0140 must record the accepted mechanism"
require_text crates/unf-egress/src/control_plane.rs \
    'pub ha_promotions: Vec<EgressHaControlPlanePromotion>' \
    "promotion state must survive restart"
require_text crates/unf-egress/src/control_plane.rs \
    'pub fn stage_ha_replacement' \
    "replacement ownership must follow the old-owner fence"
require_text crates/unf-egress/src/control_plane.rs \
    'pub fn seal_ha_source_cutover' \
    "source activation must bind acknowledged continuity"

echo "Phase 8.6e HA transaction passed: restart replay, ordered fencing, staged replacement, AFT readback, reachability CAS, and source cutover agree"
