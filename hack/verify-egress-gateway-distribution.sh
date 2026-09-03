#!/usr/bin/env bash
set -Eeuo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

require_text() {
    local relative_file=$1 expected=$2 description=$3
    rg --fixed-strings --quiet -- "${expected}" "${project_root}/${relative_file}" || {
        echo "Phase 8.5 gateway-distribution check failed: ${description} (${relative_file})" >&2
        exit 1
    }
}

command -v rg >/dev/null 2>&1 || {
    echo "rg is required to verify Phase 8.5 gateway distribution" >&2
    exit 1
}

require_text bins/unf-controller/src/main.rs \
    '"/v1/state/egress-gateway",' \
    "the internal TLS API must expose the selected-gateway boundary"
require_text bins/unf-controller/src/main.rs \
    'let agent = authenticate_internal_agent(&state, &headers).await?;' \
    "the gateway endpoint must reuse Pod-bound TokenReview authentication"
require_text bins/unf-controller/src/main.rs \
    '.filter(|source| source_selects_gateway(source, &principal, advertisement))' \
    "the controller must derive exact selected-gateway membership"
require_text crates/unf-egress/src/distribution.rs \
    'pub struct EgressGatewayProjectionLedger' \
    "the gateway must fence replay and same-revision mutation"
require_text crates/unf-egress/src/distribution.rs \
    'pub fn withdraw(' \
    "empty selected state must be an explicit authenticated withdrawal"
require_text bins/unf-agent/src/main.rs \
    '.post(format!("{controller_url}/v1/state/egress-gateway"))' \
    "the agent must poll the authenticated gateway projection"
require_text bins/unf-agent/src/main.rs \
    '.context("independently admit selected-gateway projection")?' \
    "the gateway agent must independently validate before adoption"
require_text docs/project-status.md \
    '| Authenticated selected-gateway distribution | **Verified** |' \
    "the authoritative tracker must record the bounded verified slice"
require_text docs/adr/0123-distribute-authenticated-selected-gateway-contracts.md \
    '**Status:** Accepted and implemented for the Phase 8.5 selected-gateway distribution slice' \
    "the distribution and withdrawal boundary must be recorded"

echo "Phase 8.5 selected-gateway distribution passed: exact authentication, source admission, candidate filtering, independent replay, monotonic fencing, and explicit withdrawal agree"
