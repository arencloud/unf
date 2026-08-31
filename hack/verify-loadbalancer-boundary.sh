#!/usr/bin/env bash
set -Eeuo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

required_files=(
    Makefile
    README.md
    docs/project-status.md
    docs/roadmap.md
    docs/architecture/components.md
    docs/development/phase6-loadbalancer-plan.md
    docs/adr/0093-separate-loadbalancer-ownership-domains.md
    docs/adr/0094-model-loadbalancer-intent-in-service-schema-v3.md
    docs/adr/0095-durable-loadbalancer-allocation-and-reachability.md
    docs/adr/0096-compatible-loadbalancer-host-state.md
    docs/adr/0097-enforce-loadbalancer-cluster-vips-in-tc.md
    docs/adr/0098-enforce-loadbalancer-local-source-ranges-and-health.md
    docs/adr/0099-operate-simulate-and-recover-loadbalancers.md
    deploy/kind-loadbalancer/kustomization.yaml
    deploy/kind-loadbalancer/controller-loadbalancer-patch.yaml
    hack/verify-kind-loadbalancer.sh
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
    '| 6.2 | LoadBalancer domain and Kubernetes compiler | **Verified** |' \
    "milestone 6.2 must remain verified"
require_text docs/project-status.md \
    '| LoadBalancer domain and Kubernetes compiler | **Verified** |' \
    "the authoritative tracker must identify milestone 6.2 as verified"
require_text docs/development/phase6-loadbalancer-plan.md \
    '| 6.3 | Address allocation and reachability-provider contract | **Verified** |' \
    "milestone 6.3 must remain verified"
require_text docs/project-status.md \
    '| Address allocation and reachability-provider contract | **Verified** |' \
    "the authoritative tracker must identify milestone 6.3 as verified"
require_text docs/development/phase6-loadbalancer-plan.md \
    '| 6.4 | Compatible distribution and transactional host state | **Verified** |' \
    "milestone 6.4 must remain verified"
require_text docs/project-status.md \
    '| Compatible distribution and transactional host state | **Verified** |' \
    "the authoritative tracker must identify milestone 6.4 as verified"
require_text docs/development/phase6-loadbalancer-plan.md \
    '| 6.5 | `externalTrafficPolicy: Cluster` LoadBalancer dataplane | **Verified** |' \
    "milestone 6.5 must remain verified"
require_text docs/project-status.md \
    '| LoadBalancer `Cluster` dataplane | **Verified** |' \
    "the authoritative tracker must identify milestone 6.5 as verified"
require_text docs/development/phase6-loadbalancer-plan.md \
    '| 6.6 | `externalTrafficPolicy: Local`, source ranges, and health checks | **Verified** |' \
    "milestone 6.6 must remain verified"
require_text docs/project-status.md \
    '| LoadBalancer `Local`, source ranges, and health | **Verified** |' \
    "the authoritative tracker must identify milestone 6.6 as verified"
require_text docs/development/phase6-loadbalancer-plan.md \
    '| 6.7 | Operations, simulation, upgrade, and recovery | **Verified** |' \
    "milestone 6.7 must remain verified"
require_text docs/project-status.md \
    '| Operations, simulation, upgrade, and recovery | **Verified** |' \
    "the authoritative tracker must identify milestone 6.7 as verified"
require_text docs/adr/0093-separate-loadbalancer-ownership-domains.md \
    '**Status:** Accepted and implemented for the Phase 6.1 architecture boundary' \
    "ADR 0093 must record the implemented architecture boundary"
require_text README.md \
    'make loadbalancer-cluster-dataplane-test' \
    "the README must bind LoadBalancer Cluster support to its regression gate"
require_text README.md \
    'make loadbalancer-local-dataplane-test' \
    "the README must bind LoadBalancer Local support to its regression gate"
require_text README.md \
    'make loadbalancer-operations-test' \
    "the README must bind LoadBalancer operations support to its regression gate"
require_text Makefile \
    'loadbalancer-kind-test:' \
    "the build must expose an isolated LoadBalancer Kind qualification gate"
require_text deploy/kind-loadbalancer/controller-loadbalancer-patch.yaml \
    'kind-direct-node-v1' \
    "the Kind provider identity must remain explicit and stable"
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

echo "Phase 6 LoadBalancer boundary passed: explicit ownership, three-domain convergence, compatibility path, milestone state, and exclusions agree"
