#!/usr/bin/env bash
set -Eeuo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

for command in jq rg; do
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
require_text Makefile \
    'egress-phase8-openshift-test: cli' \
    "the independent OpenShift gate must be invocable"
require_text hack/verify-openshift-egress-phase8.sh \
    'OpenShift cl02 Phase 8.11 egress qualification passed' \
    "the OpenShift gate must emit an explicit terminal result"
require_text deploy/openshift-primary-cni/egress/kustomization.yaml \
    'digest: sha256:c5d552a42d818c706fc04146546101fb7aef9a04ebe157e10b76721721e51df0' \
    "the Phase 8 controller image must remain immutable"
require_text deploy/openshift-primary-cni/egress/kustomization.yaml \
    'digest: sha256:502ec481e74a3b292b00cd0085f8d3fb444c66a151f0cd67e91d944c920c09e6' \
    "the Phase 8 agent image must remain immutable"

jq -e '
    .schemaVersion == 1 and .phase == "8.11"
    and .sourceRevision == "7c576643626a1ec68f309c881743093a1551a50e"
    and .kindQualification.phase == "8.10" and .kindQualification.result == "passed"
    and .contracts.persistentBpfStateAbiVersion == 15
    and .contracts.egressDistributionSchemaVersion == 2
    and .contracts.egressHostStateSchemaVersion == 2
    and .contracts.egressMapSchemaVersion == 4
    and .contracts.flowExportSchemaVersion == 7
    and all(.images[]; test("^quay\\.io/arencloud/unf-[a-z-]+-dev@sha256:[0-9a-f]{64}$"))
' "${project_root}/deploy/openshift-primary-cni/egress/release.json" >/dev/null || {
    echo "Phase 8 OpenShift release record is invalid" >&2
    exit 1
}

for excluded in \
    'production-scale BGP/ECMP/BFD availability' \
    'cross-cluster egress' \
    'WireGuard' \
    'SCTP egress NAT' \
    'generic NAT `RELATED`' \
    'HA, availability, or scale.'; do
    require_text docs/development/phase8-egress-fabric-plan.md "${excluded}" \
        "the ${excluded} exclusion must remain visible"
done

echo "Phase 8 egress-fabric boundary passed: ownership, precedence, contracts, HA, providers, recovery, and exclusions agree"
