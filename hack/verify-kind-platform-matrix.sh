#!/usr/bin/env bash
set -euo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cluster_name=${UNF_MATRIX_KIND_NAME:-unf-matrix-134}
kubeconfig=${UNF_MATRIX_KIND_KUBECONFIG:-"${project_root}/.tools/kind-${cluster_name}.kubeconfig"}
context=kind-${cluster_name}
config=${UNF_MATRIX_KIND_CONFIG:-"${project_root}/hack/kind-config-1.34.yaml"}
result_record=${UNF_MATRIX_KIND_RESULT_RECORD:-"${project_root}/.artifacts/phase3-kind-kubernetes-1.34-result.json"}
attempt_history=${UNF_MATRIX_KIND_ATTEMPT_HISTORY:-"${project_root}/.artifacts/phase3-kind-kubernetes-1.34-attempts.jsonl"}
started_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
revision=$(git -C "${project_root}" rev-parse HEAD)
stage=preflight
cluster_created=false
cluster_removed=true
outcome=failed
kubernetes_version=
node_image=$(awk '/image: kindest\/node:/ {print $2; exit}' "${config}")
environment_file=$(mktemp)

mkdir -p "$(dirname "${result_record}")" "$(dirname "${attempt_history}")"

write_result() {
    local completed_at
    completed_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    jq -n \
        --arg started_at "${started_at}" \
        --arg completed_at "${completed_at}" \
        --arg outcome "${outcome}" \
        --arg completed_stage "${stage}" \
        --arg revision "${revision}" \
        --arg cluster_name "${cluster_name}" \
        --arg node_image "${node_image}" \
        --arg kubernetes_version "${kubernetes_version}" \
        --argjson cluster_removed "${cluster_removed}" \
        --slurpfile environment "${environment_file}" \
        '{
            schema_version: 1,
            started_at: $started_at,
            completed_at: $completed_at,
            outcome: $outcome,
            completed_stage: $completed_stage,
            git_revision: $revision,
            fixture: {
                cluster_name: $cluster_name,
                node_image: $node_image,
                kubernetes_version: $kubernetes_version,
                address_families: ["ipv4", "ipv6"]
            },
            environment: (if ($environment | length) == 1 then $environment[0] else null end),
            gates: {
                endpoint_enforcement_recovery: ($outcome == "passed"),
                tcx_and_legacy_attachment: ($outcome == "passed"),
                adjacent_revision_upgrade_rollback: ($outcome == "passed")
            },
            cleanup: {
                dedicated_cluster_removed: $cluster_removed
            }
        }' >"${result_record}"
    jq -c . "${result_record}" >>"${attempt_history}"
}

cleanup() {
    local exit_code=$?
    trap - EXIT
    if [[ ${cluster_created} == true ]]; then
        cluster_removed=false
        if make -C "${project_root}" kind-down \
            KIND_NAME="${cluster_name}" \
            KIND_KUBECONFIG="${kubeconfig}" \
            KUBE_CONTEXT="${context}" >/dev/null 2>&1; then
            cluster_removed=true
        fi
    fi
    write_result
    rm -f "${kubeconfig}" "${environment_file}"
    if [[ ${exit_code} -ne 0 ]]; then
        echo "Kubernetes 1.34 platform-matrix qualification failed at stage ${stage}; dedicated cluster removed=${cluster_removed}, and the attempt was retained" >&2
    fi
    exit "${exit_code}"
}
trap cleanup EXIT

[[ -s ${config} ]] || {
    echo "matrix Kind config does not exist: ${config}" >&2
    exit 1
}
[[ ${cluster_name} == unf-matrix-* ]] || {
    echo "matrix cluster name must use the isolated unf-matrix-* prefix" >&2
    exit 1
}
[[ ${node_image} == kindest/node:*@sha256:* ]] || {
    echo "matrix Kind node image must be tag-and-digest pinned" >&2
    exit 1
}
[[ -z $(git -C "${project_root}" status --porcelain) ]] || {
    echo "platform-matrix qualification requires a clean committed tree" >&2
    exit 1
}
if sudo env KIND_EXPERIMENTAL_PROVIDER=podman "${project_root}/.tools/bin/kind" get clusters 2>/dev/null | grep -Fxq "${cluster_name}"; then
    echo "refusing to reuse existing matrix cluster ${cluster_name}" >&2
    exit 1
fi

stage=cluster-create
cluster_created=true
make -C "${project_root}" kind-up \
    KIND_NAME="${cluster_name}" \
    KIND_CONFIG="${config}" \
    KIND_KUBECONFIG="${kubeconfig}" \
    KUBE_CONTEXT="${context}"

kubernetes_version=$(KUBECONFIG="${kubeconfig}" kubectl --context "${context}" \
    version -o json | jq -r '.serverVersion.gitVersion')
[[ ${kubernetes_version} == v1.34.* ]] || {
    echo "matrix fixture expected Kubernetes v1.34.x, got ${kubernetes_version}" >&2
    exit 1
}

KUBECONFIG="${kubeconfig}" kubectl --context "${context}" get nodes -o json | jq '{
    nodes: [.items[] | {
        name: .metadata.name,
        os: .status.nodeInfo.osImage,
        kernel: .status.nodeInfo.kernelVersion,
        architecture: .status.nodeInfo.architecture,
        container_runtime: .status.nodeInfo.containerRuntimeVersion,
        pod_cidrs: .spec.podCIDRs
    }]
}' >"${environment_file}"

stage=endpoint-enforcement-recovery
make -C "${project_root}" kind-deploy \
    KIND_NAME="${cluster_name}" \
    KIND_KUBECONFIG="${kubeconfig}" \
    KUBE_CONTEXT="${context}"
make -C "${project_root}" kind-test \
    KIND_NAME="${cluster_name}" \
    KIND_KUBECONFIG="${kubeconfig}" \
    KUBE_CONTEXT="${context}"

stage=adjacent-upgrade-rollback
make -C "${project_root}" kind-upgrade-test \
    KIND_NAME="${cluster_name}" \
    KIND_KUBECONFIG="${kubeconfig}" \
    KUBE_CONTEXT="${context}"

stage=complete
outcome=passed
echo "Kubernetes ${kubernetes_version} platform-matrix qualification passed: full dual-stack endpoints, TCX/legacy attachment, recovery, and adjacent-revision upgrade/rollback"
