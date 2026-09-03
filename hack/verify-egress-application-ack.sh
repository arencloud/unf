#!/usr/bin/env bash
set -Eeuo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

require_text() {
    local relative_file=$1 expected=$2 description=$3
    rg --fixed-strings --quiet -- "${expected}" "${project_root}/${relative_file}" || {
        echo "Phase 8.5 application-ack check failed: ${description} (${relative_file})" >&2
        exit 1
    }
}

command -v rg >/dev/null 2>&1 || {
    echo "rg is required to verify Phase 8.5 egress application acknowledgements" >&2
    exit 1
}

require_text crates/unf-egress/src/distribution.rs \
    'pub struct EgressSourceApplicationAcknowledgement' \
    "source evidence must bind the exact committed source projection"
require_text crates/unf-egress/src/distribution.rs \
    'pub struct EgressGatewayApplicationAcknowledgement' \
    "gateway evidence must bind the exact active or withdrawn projection"
require_text bins/unf-controller/src/main.rs \
    '"/v1/state/egress-source-ack",' \
    "the authenticated source acknowledgement endpoint must be registered"
require_text bins/unf-controller/src/main.rs \
    '"/v1/state/egress-gateway-ack",' \
    "the authenticated gateway acknowledgement endpoint must be registered"
require_text bins/unf-controller/src/main.rs \
    'source acknowledgement does not match the issuing agent Pod' \
    "source evidence must be bound to the issuing Pod identity"
require_text bins/unf-controller/src/main.rs \
    'gateway acknowledgement does not match the issuing agent Pod' \
    "gateway evidence must be bound to the issuing Pod identity"
require_text bins/unf-controller/src/main.rs \
    'fn egress_source_activation_ready' \
    "bilateral readiness must be computed separately from distribution"
require_text bins/unf-agent/src/main.rs \
    '.post(format!("{controller_url}/v1/state/egress-source-ack"))' \
    "the source agent must publish evidence only after map application"
require_text bins/unf-agent/src/main.rs \
    '.post(format!("{controller_url}/v1/state/egress-gateway-ack"))' \
    "the gateway agent must publish ledger-adoption evidence"
require_text docs/project-status.md \
    '| Bilateral egress application acknowledgements | **Verified** |' \
    "the authoritative tracker must record the bounded verified slice"
require_text docs/adr/0125-require-bilateral-egress-application-acknowledgements.md \
    '**Status:** Accepted and implemented for the Phase 8.5 application-acknowledgement slice' \
    "the acknowledgement and activation boundary must be recorded"

echo "Phase 8.5 egress application acknowledgements passed: exact source commit, gateway ledger adoption, Pod binding, replay, withdrawal, invalidation, and bilateral readiness agree"
