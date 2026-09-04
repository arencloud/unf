#!/usr/bin/env bash
set -Eeuo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

require_text() {
    local relative_file=$1 expected=$2 description=$3
    rg --fixed-strings --quiet -- "${expected}" "${project_root}/${relative_file}" || {
        echo "Phase 8.7b FQDN control check failed: ${description} (${relative_file})" >&2
        exit 1
    }
}

command -v rg >/dev/null 2>&1 || {
    echo "rg is required to verify Phase 8.7b FQDN control" >&2
    exit 1
}

require_text docs/development/phase8-egress-fabric-plan.md \
    '| 8.7b | Native intent and durable observation ledger | **Verified** |' \
    "the execution plan must record the verified control slice"
require_text docs/project-status.md \
    '| Native FQDN intent and durable observation control | **Verified** |' \
    "the authoritative tracker must record the verified control boundary"
require_text docs/adr/0143-native-fqdn-intent-and-durable-observation-ledger.md \
    '**Status:** Accepted and implemented for Phase 8 milestone 8.7b' \
    "ADR 0143 must record the accepted control contract"
require_text crates/unf-egress/src/fqdn_observation.rs \
    'EGRESS_FQDN_OBSERVATION_CHECKPOINT_SCHEMA_VERSION' \
    "restart state must use an explicit schema"
require_text crates/unf-egress/src/dataplane.rs \
    'unresolved_fqdn_owns_both_families_and_fences_even_an_active_guard' \
    "unresolved FQDN intent must have a direct zero-leak regression"
require_text bins/unf-controller/src/main.rs \
    '/v1/state/egress-fqdn-observations' \
    "authenticated observation ingestion must have a stable internal route"
require_text deploy/crds/network.unf.io_egresspolicies.yaml \
    'requiredObservers:' \
    "the generated native CRD must expose bounded DNS controls"

echo "Phase 8.7b FQDN control passed: native bounded intent, Pod/Node-bound monotonic batches, authoritative-empty semantics, durable replay, and unresolved dual-stack fencing agree"
