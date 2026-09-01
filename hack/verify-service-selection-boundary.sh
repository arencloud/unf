#!/usr/bin/env bash
set -Eeuo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

required_files=(
    Makefile
    README.md
    docs/project-status.md
    docs/roadmap.md
    docs/architecture/components.md
    docs/development/phase7-service-selection-plan.md
    docs/adr/0102-bound-advanced-service-selection.md
    docs/adr/0103-model-advanced-service-selection-in-schema-v4.md
    docs/adr/0104-verify-network-behavior-contracts-before-activation.md
    docs/adr/0105-distribute-and-transactionally-activate-selection-contracts.md
    docs/adr/0106-enforce-locality-and-topology-from-verified-contracts.md
    docs/adr/0107-enforce-client-ip-affinity-and-graceful-draining.md
    docs/adr/0108-adopt-bounded-measured-maglev-selection.md
    docs/adr/0109-enforce-explicit-loadbalancer-dsr.md
    docs/adr/0110-preserve-and-explain-service-selection-outcomes.md
    docs/adr/0111-qualify-advanced-service-selection-on-kind.md
    docs/benchmarks/phase7-maglev-measurement.md
)

command -v rg >/dev/null 2>&1 || {
    echo "rg is required to verify the Phase 7 service-selection boundary" >&2
    exit 1
}

require_text() {
    local relative_file=$1
    local expected=$2
    local description=$3

    if ! rg --fixed-strings --quiet -- "${expected}" "${project_root}/${relative_file}"; then
        echo "Phase 7 boundary check failed: ${description} (${relative_file})" >&2
        exit 1
    fi
}

for relative_file in "${required_files[@]}"; do
    [[ -f ${project_root}/${relative_file} ]] || {
        echo "Phase 7 boundary document is missing: ${relative_file}" >&2
        exit 1
    }
done

require_text docs/project-status.md \
    '| Phase 7 — advanced Service selection | **In progress** |' \
    "the authoritative phase state must be in progress"
require_text docs/development/phase7-service-selection-plan.md \
    '| 7.1 | Architecture and acceptance boundary | **Verified** |' \
    "milestone 7.1 must remain verified"
require_text docs/project-status.md \
    '| Architecture and acceptance boundary | **Verified** |' \
    "the work breakdown must identify milestone 7.1 as verified"
require_text docs/development/phase7-service-selection-plan.md \
    '| 7.2 | Service schema v4 and Kubernetes compiler | **Verified** |' \
    "milestone 7.2 must remain verified"
require_text docs/project-status.md \
    '| Service schema v4 and Kubernetes compiler | **Verified** |' \
    "the work breakdown must identify milestone 7.2 as verified"
require_text docs/development/phase7-service-selection-plan.md \
    '| 7.2a | Network Behavior Contract and reference validator | **Verified** |' \
    "milestone 7.2a must remain verified"
require_text docs/project-status.md \
    '| Network Behavior Contract and reference validator | **Verified** |' \
    "the work breakdown must identify milestone 7.2a as verified"
require_text docs/development/phase7-service-selection-plan.md \
    '| 7.3 | Compatible distribution and transactional selection state | **Verified** |' \
    "milestone 7.3 must remain verified"
require_text docs/project-status.md \
    '| Compatible distribution and transactional selection state | **Verified** |' \
    "the work breakdown must identify milestone 7.3 as verified"
require_text docs/development/phase7-service-selection-plan.md \
    '| 7.4 | Internal locality and topology-aware dataplane | **Verified** |' \
    "milestone 7.4 must remain verified"
require_text docs/project-status.md \
    '| Internal locality and topology-aware dataplane | **Verified** |' \
    "the work breakdown must identify milestone 7.4 as verified"
require_text docs/development/phase7-service-selection-plan.md \
    '| 7.5 | ClientIP affinity and graceful draining | **Verified** |' \
    "milestone 7.5 must remain verified"
require_text docs/project-status.md \
    '| ClientIP affinity and graceful draining | **Verified** |' \
    "the work breakdown must identify milestone 7.5 as verified"
require_text docs/development/phase7-service-selection-plan.md \
    '| 7.6 | Measured Maglev selection | **Verified** |' \
    "milestone 7.6 must be verified"
require_text docs/project-status.md \
    '| Measured Maglev selection | **Verified** |' \
    "the work breakdown must identify milestone 7.6 as verified"
require_text docs/development/phase7-service-selection-plan.md \
    '| 7.7 | Opt-in DSR dataplane | **Verified** |' \
    "milestone 7.7 must be verified"
require_text docs/project-status.md \
    '| Opt-in DSR dataplane | **Verified** |' \
    "the work breakdown must identify milestone 7.7 as verified"
require_text docs/development/phase7-service-selection-plan.md \
    '| 7.8 | Operations, simulation, upgrade, and recovery | **Verified** |' \
    "milestone 7.8 must remain verified"
require_text docs/project-status.md \
    '| Operations, simulation, upgrade, and recovery | **Verified** |' \
    "the work breakdown must identify milestone 7.8 as verified"
require_text docs/development/phase7-service-selection-plan.md \
    '| 7.9 | Kube-proxy-free Kind qualification | **Verified** |' \
    "milestone 7.9 must be verified"
require_text docs/project-status.md \
    '| Kube-proxy-free Kind qualification | **Verified** |' \
    "the work breakdown must identify milestone 7.9 as verified"
require_text docs/adr/0111-qualify-advanced-service-selection-on-kind.md \
    'This promotes no OpenShift' \
    "the Kind result must remain explicitly non-transitive"
require_text Makefile \
    'service-selection-contract-test:' \
    "the build must expose an isolated Network Behavior Contract gate"
require_text Makefile \
    'service-selection-state-test:' \
    "the build must expose an isolated transactional selection-state gate"
require_text Makefile \
    'service-selection-dataplane-test:' \
    "the build must expose an isolated locality/topology dataplane gate"
require_text Makefile \
    'service-affinity-dataplane-test:' \
    "the build must expose an isolated affinity/draining dataplane gate"
require_text Makefile \
    'service-maglev-dataplane-test:' \
    "the build must expose an isolated measured Maglev gate"
require_text Makefile \
    'service-dsr-dataplane-test:' \
    "the build must expose an isolated explicit DSR gate"
require_text docs/adr/0107-enforce-client-ip-affinity-and-graceful-draining.md \
    'Existing validated connections win before affinity lookup.' \
    "per-flow connection state must precede affinity"
require_text docs/adr/0108-adopt-bounded-measured-maglev-selection.md \
    'hash/modulo/one-slot-lookup path' \
    "Maglev must retain the bounded one-map packet path"
require_text docs/benchmarks/phase7-maglev-measurement.md \
    'network.unf.io/service-selection-algorithm: maglev' \
    "Maglev admission must be explicit and documented"
require_text docs/adr/0109-enforce-explicit-loadbalancer-dsr.md \
    'network.unf.io/dsr-backend-vip-ownership: acknowledged' \
    "DSR backend VIP ownership must be explicitly acknowledged"
require_text docs/adr/0109-enforce-explicit-loadbalancer-dsr.md \
    'it never falls back per flow' \
    "explicit DSR must not silently fall back to NAT"
require_text docs/adr/0104-verify-network-behavior-contracts-before-activation.md \
    'It does **not** mathematically prove the' \
    "the contract must not overclaim formal verification"

for relative_file in \
    README.md \
    docs/project-status.md \
    docs/roadmap.md \
    docs/development/phase7-service-selection-plan.md \
    docs/adr/0102-bound-advanced-service-selection.md; do
    require_text "${relative_file}" 'internalTrafficPolicy' \
        "strict internal policy must remain explicit"
done

require_text docs/development/phase7-service-selection-plan.md \
    'Affinity never restores an unready, removed, wrong-Node, wrong-tier, or' \
    "affinity must not broaden eligibility"
require_text docs/development/phase7-service-selection-plan.md \
    'Maglev is evaluated against the current stable selector' \
    "Maglev adoption must remain evidence driven"
require_text docs/development/phase7-service-selection-plan.md \
    'DSR is never inferred from Service type or enabled cluster-wide by accident.' \
    "DSR must remain explicit and non-default"
require_text docs/architecture/components.md \
    'The agent transactionally owns verified per-Node contract state through' \
    "userspace selection ownership must remain explicit"
require_text Makefile \
    'service-selection-boundary-test:' \
    "the build must expose an isolated Phase 7 boundary gate"
require_text Makefile \
    'service-selection-ir-test:' \
    "the build must expose an isolated schema-v4 compiler gate"

for excluded_capability in \
    'weighted traffic splitting' \
    'cross-cluster selection' \
    'production BGP/EVPN/ECMP/BFD' \
    'SCTP Service forwarding' \
    'Gateway API' \
    'production availability/scale'; do
    require_text docs/development/phase7-service-selection-plan.md "${excluded_capability}" \
        "the ${excluded_capability} exclusion must remain visible"
done

echo "Phase 7 service-selection boundary passed: precedence, ownership, measurement, compatibility, platform gates, and exclusions agree"
