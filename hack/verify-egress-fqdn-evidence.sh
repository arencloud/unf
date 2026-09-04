#!/usr/bin/env bash
set -Eeuo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

require_text() {
    local relative_file=$1 expected=$2 description=$3
    rg --fixed-strings --quiet -- "${expected}" "${project_root}/${relative_file}" || {
        echo "Phase 8.7a FQDN evidence check failed: ${description} (${relative_file})" >&2
        exit 1
    }
}

command -v rg >/dev/null 2>&1 || {
    echo "rg is required to verify Phase 8.7a FQDN evidence" >&2
    exit 1
}

require_text docs/development/phase8-egress-fabric-plan.md \
    '| 8.7a | Provenance-Leased Resolution contract | **Verified** |' \
    "the execution plan must record the verified evidence contract"
require_text docs/project-status.md \
    '| Provenance-Leased FQDN destination evidence | **Verified** |' \
    "the authoritative tracker must record the verified evidence boundary"
require_text docs/adr/0142-provenance-leased-fqdn-destination-evidence.md \
    '**Status:** Accepted and implemented for Phase 8 milestone 8.7a' \
    "ADR 0142 must record the accepted algorithm"
require_text crates/unf-egress/src/fqdn.rs \
    'EGRESS_FQDN_ALGORITHM_PROVENANCE_LEASED_RESOLUTION_V1' \
    "the algorithm and replay boundary must be versioned"
require_text crates/unf-egress/src/fqdn.rs \
    'new_flows_until_unix_seconds' \
    "new-flow expiry must remain distinct from established-flow drain"
require_text crates/unf-egress/src/fqdn.rs \
    'CapacityExceeded' \
    "capacity pressure must reject rather than evict authority"
require_text crates/unf-egress/src/fqdn.rs \
    'wrong_view_observations' \
    "split-horizon observations must be visible and isolated"

echo "Phase 8.7a FQDN evidence passed: label-bounded wildcards, view-scoped observer quorum, TTL-capped temporal leases, fail-closed capacity, and independent replay agree"
