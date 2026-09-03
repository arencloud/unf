#!/usr/bin/env bash
set -Eeuo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

require_text() {
    local relative_file=$1 expected=$2 description=$3
    rg --fixed-strings --quiet -- "${expected}" "${project_root}/${relative_file}" || {
        echo "Phase 8.5 control-plane check failed: ${description} (${relative_file})" >&2
        exit 1
    }
}

command -v rg >/dev/null 2>&1 || {
    echo "rg is required to verify the Phase 8.5 egress control plane" >&2
    exit 1
}

require_text crates/unf-egress/src/control_plane.rs \
    'pub struct EgressControlPlaneCheckpoint' \
    "allocation and gateway state must share one durable orchestration checkpoint"
require_text crates/unf-egress/src/control_plane.rs \
    'next.gateways.withdraw(&owner)?;' \
    "withdrawal must precede address release"
require_text bins/unf-controller/src/main.rs \
    'persist_egress_desired_if_dirty(&state).await;' \
    "authoritative watched state must persist before derived control state"
require_text bins/unf-controller/src/main.rs \
    'node.ready' \
    "gateway intent must use only Ready Nodes"
require_text deploy/kubernetes/egress-control-plane-store.yaml \
    'name: unf-egress-control-plane' \
    "the derived transaction must have an explicit durable store"
require_text docs/project-status.md \
    '| Live allocation and gateway-intent orchestration | **Verified** |' \
    "the authoritative tracker must record the bounded verified slice"
require_text docs/adr/0124-drive-live-egress-allocation-and-gateway-intent.md \
    '**Status:** Accepted and implemented for the Phase 8.5 live control-plane slice' \
    "the recovery and publication boundary must be recorded"

echo "Phase 8.5 live control plane passed: canonical intent, allocation, deterministic candidates, withdrawal fencing, persistence ordering, and restart replay agree"
