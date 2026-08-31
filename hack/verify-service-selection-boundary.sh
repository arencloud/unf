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
    'The agent will compile and transactionally own per-Node eligibility and' \
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
