#!/usr/bin/env bash
set -Eeuo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

for command in rg; do
    command -v "${command}" >/dev/null 2>&1 || {
        echo "${command} is required to verify the Phase 8 egress boundary" >&2
        exit 1
    }
done

require_text() {
    local relative_file=$1 expected=$2 description=$3
    [[ -f ${project_root}/${relative_file} ]] || {
        echo "Phase 8 boundary file is missing: ${relative_file}" >&2
        exit 1
    }
    rg --fixed-strings --quiet -- "${expected}" "${project_root}/${relative_file}" || {
        echo "Phase 8 boundary check failed: ${description} (${relative_file})" >&2
        exit 1
    }
}

require_text docs/project-status.md \
    '| Phase 8 — identity-aware egress fabric | **In progress** |' \
    "the authoritative Phase 8 state must be in progress"
require_text docs/project-status.md \
    '| Architecture and acceptance boundary | **Verified** |' \
    "milestone 8.1 must be tracked as verified"
require_text docs/development/phase8-egress-fabric-plan.md \
    '| 8.1 | Architecture and acceptance boundary | **Verified** |' \
    "the Phase 8 plan must verify milestone 8.1"
require_text docs/development/phase8-egress-fabric-plan.md \
    'enforce source-side security policy against the original destination;' \
    "policy must precede steering and NAT"
require_text docs/development/phase8-egress-fabric-plan.md \
    'or address lease never grants policy permission.' \
    "gateway state must not broaden policy"
require_text docs/development/phase8-egress-fabric-plan.md \
    'FQDN-derived IP membership is a' \
    "FQDN state must not become workload identity"
require_text docs/development/phase8-egress-fabric-plan.md \
    'no egress address, gateway, FQDN' \
    "default behavior must remain explicit and safe"
require_text docs/adr/0113-bound-identity-aware-egress-fabric.md \
    'OpenShift EgressIP is a compatibility input to the same egress engine' \
    "OpenShift compatibility must not fork the engine"
require_text docs/architecture/components.md \
    'The accepted Phase 8 boundary keeps egress policy, allocation, gateway' \
    "component ownership must be explicit"
require_text README.md \
    'Phase 8 begins an identity-aware enterprise egress fabric' \
    "the user-facing roadmap must expose the active phase"
require_text docs/roadmap.md \
    '## Phase 8 — identity-aware egress fabric' \
    "the roadmap must include Phase 8"

for excluded in \
    'production BGP/EVPN/ECMP/BFD' \
    'cross-cluster egress' \
    'WireGuard' \
    'SCTP egress NAT' \
    'generic NAT `RELATED`' \
    'HA, availability, or scale.'; do
    require_text docs/development/phase8-egress-fabric-plan.md "${excluded}" \
        "the ${excluded} exclusion must remain visible"
done

echo "Phase 8 egress-fabric boundary passed: ownership, precedence, contracts, HA, providers, recovery, and exclusions agree"
