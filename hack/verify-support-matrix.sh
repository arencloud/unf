#!/usr/bin/env bash
set -euo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
matrix=${UNF_SUPPORT_MATRIX:-"${project_root}/docs/development/support-matrix.json"}

command -v jq >/dev/null 2>&1 || {
    echo "jq is required to validate ${matrix}" >&2
    exit 1
}

jq -e '
    .schema_version == 1 and
    (.last_reviewed | test("^[0-9]{4}-[0-9]{2}-[0-9]{2}$")) and
    .qualification_semantics.non_transitive == true and
    (.rows | type == "array" and length >= 3) and
    ([.rows[].id] | length == (unique | length)) and
    all(.rows[];
        .state == "qualified" and
        (.id | test("^[a-z0-9][a-z0-9.-]+$")) and
        (.platform.distribution == "Kubernetes" or
            .platform.distribution == "OpenShift") and
        (.platform.environment | type == "string" and length > 0) and
        (.platform.kubernetes_version | test("^v[0-9]+\\.[0-9]+\\.[0-9]+$")) and
        (.platform.openshift_version == null or
            (.platform.openshift_version | test("^[0-9]+\\.[0-9]+\\.[0-9]+$"))) and
        (.nodes.count | type == "number" and . >= 2) and
        (.nodes.os | type == "string" and length > 0) and
        (.nodes.kernels | type == "array" and length > 0 and
            all(.[]; type == "string" and length > 0)) and
        (.nodes.architecture | IN("amd64", "arm64", "s390x", "ppc64le")) and
        (.nodes.container_runtime | type == "string" and length > 0) and
        (.networking.cni | type == "string" and length > 0) and
        (.networking.address_families | type == "array" and length > 0 and
            all(.[]; IN("ipv4", "ipv6")) and length == (unique | length)) and
        (.dataplane.attachment_modes | type == "array" and length > 0 and
            all(.[]; IN("tcx_pinned", "legacy_netlink")) and
            length == (unique | length)) and
        .evidence.outcome == "passed" and
        (.evidence.verified_at | test("^[0-9]{4}-[0-9]{2}-[0-9]{2}$")) and
        (.evidence.revision | test("^[0-9a-f]{40}$")) and
        (.evidence.commands | type == "array" and length > 0 and
            all(.[]; type == "string" and length > 0)) and
        (.evidence.records | type == "array" and length > 0 and
            all(.[]; type == "string" and length > 0)) and
        (.evidence.decisions | type == "array" and length > 0 and
            all(.[]; type == "string" and length > 0)) and
        (.qualified_scope | type == "array" and length > 0 and
            all(.[]; type == "string" and length > 0))
    ) and
    (.unsupported_boundaries | type == "array" and length >= 5) and
    ([.unsupported_boundaries[].dimension] | length == (unique | length)) and
    all(.unsupported_boundaries[];
        (.dimension | type == "string" and length > 0) and
        (.qualified_values | type == "array" and length > 0 and
            all(.[]; type == "string" and length > 0)) and
        (.boundary | type == "string" and length > 0)
    )
' "${matrix}" >/dev/null

while IFS= read -r revision; do
    git -C "${project_root}" cat-file -e "${revision}^{commit}" 2>/dev/null || {
        echo "support-matrix evidence revision is not a local commit: ${revision}" >&2
        exit 1
    }
done < <(jq -r '.rows[].evidence.revision' "${matrix}")

while IFS= read -r decision; do
    [[ -f ${project_root}/${decision} ]] || {
        echo "support-matrix decision reference is missing: ${decision}" >&2
        exit 1
    }
done < <(jq -r '.rows[].evidence.decisions[]' "${matrix}")

echo "Support matrix schema v1 passed: $(jq '.rows | length' "${matrix}") exact qualified tuples and $(jq '.unsupported_boundaries | length' "${matrix}") explicit boundary dimensions"
