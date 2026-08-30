#!/usr/bin/env bash
set -Eeuo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

required_files=(
    README.md
    docs/project-status.md
    docs/roadmap.md
    docs/architecture/components.md
    docs/development/phase6-loadbalancer-plan.md
    docs/adr/0093-separate-loadbalancer-ownership-domains.md
)

command -v rg >/dev/null 2>&1 || {
    echo "rg is required to verify the Phase 6 LoadBalancer boundary" >&2
    exit 1
}

require_text() {
    local relative_file=$1
    local expected=$2
    local description=$3

    if ! rg --fixed-strings --quiet -- "${expected}" "${project_root}/${relative_file}"; then
        echo "Phase 6 boundary check failed: ${description} (${relative_file})" >&2
        exit 1
    fi
}

for relative_file in "${required_files[@]}"; do
    if [[ ! -f ${project_root}/${relative_file} ]]; then
        echo "Phase 6 boundary document is missing: ${relative_file}" >&2
        exit 1
    fi
done

for relative_file in \
    README.md \
    docs/project-status.md \
    docs/roadmap.md \
    docs/development/phase6-loadbalancer-plan.md \
    docs/adr/0093-separate-loadbalancer-ownership-domains.md; do
    require_text "${relative_file}" "network.unf.io/load-balancer" \
        "the exact UNF LoadBalancer class must remain explicit"
done

require_text docs/project-status.md \
    '| Phase 6 — LoadBalancer exposure | **In progress** |' \
    "the authoritative phase state must be in progress"
require_text docs/development/phase6-loadbalancer-plan.md \
    '| 6.1 | Architecture, ownership, and acceptance boundary | **Verified** |' \
    "milestone 6.1 must remain verified"
require_text docs/development/phase6-loadbalancer-plan.md \
    '| 6.2 | LoadBalancer domain and Kubernetes compiler | **In progress** |' \
    "milestone 6.2 must be the active implementation slice"
require_text docs/project-status.md \
    '| LoadBalancer domain and Kubernetes compiler | **In progress** |' \
    "the authoritative tracker must identify milestone 6.2 as active"
require_text docs/adr/0093-separate-loadbalancer-ownership-domains.md \
    '**Status:** Accepted and implemented for the Phase 6.1 architecture boundary' \
    "ADR 0093 must record the implemented architecture boundary"
require_text README.md \
    'no LoadBalancer packet-support claim exists yet.' \
    "the README must not overstate LoadBalancer packet support"
require_text docs/development/phase6-loadbalancer-plan.md \
    '`allocateLoadBalancerNodePorts: false` is preserved.' \
    "direct VIP delivery must not depend on traffic NodePorts"

for ownership_domain in allocation advertisement dataplane; do
    require_text docs/development/phase6-loadbalancer-plan.md "${ownership_domain}" \
        "the ${ownership_domain} ownership domain must remain explicit"
done

for excluded_capability in \
    'BGP, EVPN' \
    'session affinity' \
    '`internalTrafficPolicy`' \
    'Maglev' \
    'DSR' \
    'SCTP Service forwarding' \
    'Gateway API'; do
    require_text docs/development/phase6-loadbalancer-plan.md "${excluded_capability}" \
        "the ${excluded_capability} exclusion must remain visible"
done

echo "Phase 6.1 LoadBalancer boundary passed: explicit ownership, three-domain convergence, compatibility path, milestone state, and exclusions agree"
