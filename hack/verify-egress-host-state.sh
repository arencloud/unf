#!/usr/bin/env bash
set -Eeuo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

require_text() {
    local relative_file=$1 expected=$2 description=$3
    rg --fixed-strings --quiet -- "${expected}" "${project_root}/${relative_file}" || {
        echo "Phase 8.4 check failed: ${description} (${relative_file})" >&2
        exit 1
    }
}

command -v rg >/dev/null 2>&1 || {
    echo "rg is required to verify Phase 8.4" >&2
    exit 1
}

require_text docs/project-status.md \
    '| Transactional distribution and gateway host state | **Verified** |' \
    "the authoritative tracker must verify milestone 8.4"
require_text docs/development/phase8-egress-fabric-plan.md \
    '| 8.4 | Transactional distribution and gateway host state | **Verified** |' \
    "the execution plan must verify milestone 8.4"
require_text docs/adr/0117-admit-and-transactionally-own-egress-host-state.md \
    '**Status:** Accepted and implemented for Phase 8.4' \
    "ADR 0117 must record the accepted distribution transaction"
require_text crates/unf-egress/src/distribution.rs \
    'pub struct AuthenticatedEgressAgent' \
    "projection must consume a previously authenticated principal"
require_text crates/unf-egress/src/distribution.rs \
    'pub fn admit(' \
    "agents must independently admit exact-Node projections"
require_text crates/unf-egress/src/distribution.rs \
    'pub struct EgressProjectionLedger' \
    "last-known-good projection revisions must be fenced"
require_text crates/unf-egress/src/host_state.rs \
    'pub const EGRESS_HOST_STATE_ABI_VERSION: u16 = 1;' \
    "gateway host state must have an independent versioned ABI"
require_text crates/unf-egress/src/host_state.rs \
    'pub trait EgressHostStateStore' \
    "host mutation and persistence must remain behind one exact store contract"
require_text crates/unf-egress/src/host_state.rs \
    'pub fn apply(' \
    "host state must use the transactional activation path"
require_text crates/unf-egress/src/host_state.rs \
    'pub fn recover(' \
    "interrupted transactions must be crash repairable"
require_text crates/unf-egress/src/host_state.rs \
    'pub fn cleanup(' \
    "cleanup must be exact and version scoped"

echo "Phase 8.4 egress host state passed: authentication binding, negotiation, replay, staging, readback, rollback, recovery, and cleanup agree"
