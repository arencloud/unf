#!/usr/bin/env bash
set -Eeuo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

require_text() {
    local relative_file=$1 expected=$2 description=$3
    rg --fixed-strings --quiet -- "${expected}" "${project_root}/${relative_file}" || {
        echo "Phase 8.6d live HA ownership check failed: ${description} (${relative_file})" >&2
        exit 1
    }
}

command -v rg >/dev/null 2>&1 || {
    echo "rg is required to verify Phase 8.6d live HA ownership" >&2
    exit 1
}

require_text docs/development/phase8-egress-fabric-plan.md \
    '| 8.6d | Durable exclusive ownership and proof alignment | **Verified** |' \
    "the execution plan must record the verified live ownership slice"
require_text docs/project-status.md \
    '| Durable exclusive CCR ownership and dataplane alignment | **Verified** |' \
    "the authoritative tracker must record the live ownership boundary"
require_text docs/adr/0139-durable-exclusive-ccr-ownership.md \
    '**Status:** Accepted and implemented for Phase 8 milestone 8.6d' \
    "ADR 0139 must record the accepted mechanism"
require_text crates/unf-egress/src/control_plane.rs \
    'pub ha_plans: Vec<EgressHaPlan>' \
    "CCR plans must survive controller restart"
require_text crates/unf-egress/src/gateway_address.rs \
    'issue_exclusive_transition_with_releases' \
    "address handoff must start from exact acknowledged ownership"
require_text crates/unf-egress/src/proof.rs \
    'EGRESS_SELECTION_ALGORITHM_CCR_SHARD_V3' \
    "proof and dataplane must name the CCR selection algorithm"
require_text ebpf/unf-ebpf-tc/src/main.rs \
    'initial packet creation must never claim that acknowledgement early' \
    "standby certification must follow readback"

echo "Phase 8.6d live HA ownership passed: durable CCR, exclusive address sets, proof/dataplane selection, and acknowledgement semantics agree"
