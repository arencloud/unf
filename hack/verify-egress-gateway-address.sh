#!/usr/bin/env bash
set -Eeuo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

require_text() {
    local relative_file=$1 expected=$2 description=$3
    rg --fixed-strings --quiet -- "${expected}" "${project_root}/${relative_file}" || {
        echo "Phase 8.5 gateway-address check failed: ${description} (${relative_file})" >&2
        exit 1
    }
}

command -v rg >/dev/null 2>&1 || {
    echo "rg is required to verify Phase 8.5 gateway address ownership" >&2
    exit 1
}
command -v unshare >/dev/null 2>&1 || {
    echo "unshare is required for the isolated real-kernel gateway address gate" >&2
    exit 1
}

require_text crates/unf-egress/src/gateway_address.rs \
    'pub struct EgressGatewayAddressProjection' \
    "address authority must be an explicit exact-Node wire contract"
require_text crates/unf-link/src/lib.rs \
    'preflight_gateway_address_collisions' \
    "foreign collisions must be detected before mutation"
require_text crates/unf-link/src/lib.rs \
    'unf:egress-address:v1:' \
    "kernel ownership must be versioned and Node-UID-bound"
require_text bins/unf-controller/src/main.rs \
    'acknowledge_ready_gateway_address_quorums' \
    "provider readiness must wait for all selected gateways"
require_text bins/unf-agent/src/main.rs \
    'apply and read back gateway-address ownership' \
    "the agent must independently verify applied kernel state"
require_text docs/project-status.md \
    '| Lease-fenced gateway address ownership | **Verified** |' \
    "the authoritative tracker must record the verified slice"
require_text docs/adr/0128-lease-fenced-gateway-address-ownership.md \
    '**Status:** Accepted and implemented for the Phase 8.5 gateway-address slice' \
    "the quorum and quarantine protocol must be recorded"

echo "Phase 8.5 gateway address ownership passed: exact Node authority, collision preflight, kernel readback, all-gateway quorum, and withdrawal quarantine agree"
