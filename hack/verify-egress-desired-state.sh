#!/usr/bin/env bash
set -Eeuo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

require_text() {
    local relative_file=$1 expected=$2 description=$3
    rg --fixed-strings --quiet -- "${expected}" "${project_root}/${relative_file}" || {
        echo "Phase 8.5 desired-state check failed: ${description} (${relative_file})" >&2
        exit 1
    }
}

command -v rg >/dev/null 2>&1 || {
    echo "rg is required to verify Phase 8.5 desired state" >&2
    exit 1
}

require_text deploy/crds/kustomization.yaml \
    'network.unf.io_egresspools.yaml' \
    "the native EgressPool CRD must be installed"
require_text deploy/crds/kustomization.yaml \
    'network.unf.io_egresspolicies.yaml' \
    "the native EgressPolicy CRD must be installed"
require_text deploy/kubernetes/rbac.yaml \
    'resources: ["securitypolicies", "egresspools", "egresspolicies"]' \
    "the controller must have bounded read/watch authority"
require_text deploy/kubernetes/rbac.yaml \
    'resources: ["egressips"]' \
    "the OpenShift compatibility input must be read-only"
require_text deploy/kubernetes/egress-desired-store.yaml \
    'name: unf-egress-desired-state' \
    "the revisioned desired model must have durable cluster storage"
require_text crates/unf-egress/src/desired.rs \
    'pub struct EgressDesiredStore' \
    "native and compatibility adapters must share one canonical store"
require_text bins/unf-controller/src/main.rs \
    '.replace_pools(NATIVE_EGRESS_POOL_SOURCE_PREFIX, replacement)' \
    "a complete pool relist must replace its source transactionally"
require_text bins/unf-controller/src/main.rs \
    '.replace_intents(OPENSHIFT_EGRESS_IP_SOURCE_PREFIX, replacement)' \
    "a complete OpenShift relist must replace only its owned source set"
require_text bins/unf-controller/src/main.rs \
    'write_lock(&state.egress_source_distributions).clear();' \
    "accepted model changes must withdraw stale source authority"
require_text docs/project-status.md \
    '| Watched durable egress desired state | **Verified** |' \
    "the authoritative tracker must record the bounded verified slice"
require_text docs/adr/0122-own-watched-egress-desired-state.md \
    '**Status:** Accepted and implemented for the Phase 8.5 desired-state slice' \
    "the safety and ownership boundary must be recorded"

echo "Phase 8.5 desired state passed: structural APIs, bounded RBAC, canonical transactions, exact relists, durable replay, and stale-authority withdrawal agree"
