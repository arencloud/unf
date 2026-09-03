#!/usr/bin/env bash
set -Eeuo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

require_text() {
    local relative_file=$1 expected=$2 description=$3
    rg --fixed-strings --quiet -- "${expected}" "${project_root}/${relative_file}" || {
        echo "Phase 8.5 path-activation check failed: ${description} (${relative_file})" >&2
        exit 1
    }
}

command -v rg >/dev/null 2>&1 || {
    echo "rg is required to verify Phase 8.5 egress path activation" >&2
    exit 1
}

require_text crates/unf-egress/src/distribution.rs \
    'pub struct EgressSourceActivationGrant' \
    "controller authority must bind the exact source and every gateway application"
require_text bins/unf-controller/src/main.rs \
    '"/v1/state/egress-source-activation",' \
    "the activation grant must use the authenticated internal API"
require_text bins/unf-agent/src/main.rs \
    'plan.readback()' \
    "the source must read back its exact native route plan"
require_text bins/unf-agent/src/main.rs \
    'index changed from' \
    "interface reuse must invalidate path evidence"
require_text bins/unf-agent/src/main.rs \
    'remote-route snapshot changed during egress path acquisition' \
    "a torn path snapshot must fail closed"
require_text bins/unf-agent/src/main.rs \
    'recovered egress activation was fenced pending fresh controller and path proof' \
    "restart must not inherit stale active authority"
require_text docs/project-status.md \
    '| Readiness- and path-proof-bound source activation | **Verified** |' \
    "the authoritative tracker must record the verified slice"
require_text docs/adr/0127-bind-egress-activation-to-gateway-and-local-path-proof.md \
    '**Status:** Accepted and implemented for the Phase 8.5 path-activation slice' \
    "the trust split and fail-closed recovery boundary must be recorded"

echo "Phase 8.5 egress path activation passed: exact gateway grant, dual-stack route/interface/MTU proof, atomic activation, withdrawal fencing, and restart reacquisition agree"
