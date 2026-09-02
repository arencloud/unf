#!/usr/bin/env bash
set -Eeuo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

require_text() {
    local relative_file=$1 expected=$2 description=$3
    [[ -f ${project_root}/${relative_file} ]] || {
        echo "Phase 8.2 file is missing: ${relative_file}" >&2
        exit 1
    }
    rg --fixed-strings --quiet -- "${expected}" "${project_root}/${relative_file}" || {
        echo "Phase 8.2 check failed: ${description} (${relative_file})" >&2
        exit 1
    }
}

command -v rg >/dev/null 2>&1 || {
    echo "rg is required to verify Phase 8.2" >&2
    exit 1
}

require_text docs/project-status.md \
    '| Egress intent, pool, and compatibility model | **Verified** |' \
    "the authoritative tracker must verify milestone 8.2"
require_text docs/development/phase8-egress-fabric-plan.md \
    '| 8.2 | Egress intent, pool, and compatibility model | **Verified** |' \
    "the execution plan must verify milestone 8.2"
require_text docs/adr/0114-normalize-egress-intent-and-openshift-egressip.md \
    '**Status:** Accepted and implemented for Phase 8.2' \
    "ADR 0114 must record the accepted implementation"
require_text crates/unf-egress/src/lib.rs \
    'pub fn normalize_model(' \
    "the complete provider-neutral model must be validated"
require_text crates/unf-egress/src/lib.rs \
    'pub service_accounts: BTreeSet<String>' \
    "ServiceAccount selection must be explicit"
require_text crates/unf-egress/src/lib.rs \
    'MissingPoolFamily' \
    "pool family coherence must fail closed"
require_text bins/unf-controller/src/openshift_egress_ip.rs \
    'pub fn translate_openshift_egress_ip(' \
    "OpenShift compatibility must translate into the shared model"
require_text bins/unf-controller/src/openshift_egress_ip.rs \
    'spec.pod_selector.unwrap_or_default()' \
    "the optional OpenShift Pod selector must default explicitly"
require_text bins/unf-controller/src/openshift_egress_ip.rs \
    'pub fn reconcile_openshift_egress_ip_status(' \
    "foreign-preserving status ownership must be explicit"

if rg --quiet 'k8s_openapi|kube::|OpenShift' "${project_root}/crates/unf-egress/src"; then
    echo "Phase 8.2 check failed: provider-specific APIs leaked into unf-egress" >&2
    exit 1
fi

echo "Phase 8.2 egress intent passed: typed selectors, pools, compatibility, bounds, and foreign ownership agree"
