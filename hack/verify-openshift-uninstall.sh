#!/usr/bin/env bash
set -euo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
kubeconfig=${KUBECONFIG:-"${project_root}/.tools/cl02-audit.kubeconfig"}
context=${KUBE_CONTEXT:-$(oc --kubeconfig "${kubeconfig}" config current-context)}
kc=(oc --kubeconfig "${kubeconfig}" --context "${context}")
temporary_dir=$(mktemp -d)
restore_needed=false

cleanup() {
    local result=$?
    trap - EXIT
    set +e
    if ${restore_needed}; then
        if "${kc[@]}" get namespace unf-system >/dev/null 2>&1; then
            "${kc[@]}" -n unf-system delete job \
                -l app.kubernetes.io/name=unf-agent-cleanup \
                --ignore-not-found --wait=true >/dev/null 2>&1
        fi
        KUBECONFIG="${kubeconfig}" KUBE_CONTEXT="${context}" \
            "${project_root}/hack/deploy-openshift.sh" >/dev/null 2>&1
    fi
    rm -rf "${temporary_dir}"
    exit "${result}"
}
trap cleanup EXIT

for command in oc jq; do
    command -v "${command}" >/dev/null
done
[[ -s ${kubeconfig} ]]
"${kc[@]}" get clusterversion version >/dev/null
"${kc[@]}" -n unf-system wait --for=condition=Available \
    deployment/unf-controller --timeout=120s >/dev/null
"${kc[@]}" -n unf-system rollout status daemonset/unf-agent \
    --timeout=120s >/dev/null

crd_uid=$("${kc[@]}" get customresourcedefinition \
    securitypolicies.network.unf.io -o jsonpath='{.metadata.uid}')
before_agents=$("${kc[@]}" -n unf-system get pod \
    -l app.kubernetes.io/name=unf-agent -o json | jq -r '
        [.items[] | [.spec.nodeName, .metadata.uid] | @tsv] | sort | .[]
    ')
agent_count=$(grep -c $'\t' <<<"${before_agents}")
[[ ${agent_count} -gt 0 ]]
before_controller=$("${kc[@]}" -n unf-system get deployment unf-controller \
    -o jsonpath='{.metadata.uid}')

KUBECONFIG="${kubeconfig}" KUBE_CONTEXT="${context}" \
    "${project_root}/hack/uninstall-openshift.sh" --delete-namespace \
    >"${temporary_dir}/plan.txt"
grep -q 'UNF coordinated uninstall plan (dry-run)' "${temporary_dir}/plan.txt"
grep -q 'stop DaemonSet unf-system/unf-agent before host mutation' \
    "${temporary_dir}/plan.txt"
grep -q 'delete dedicated Namespace unf-system' "${temporary_dir}/plan.txt"
grep -q 'preserve SecurityPolicy CRD' "${temporary_dir}/plan.txt"
grep -q 'dry run only' "${temporary_dir}/plan.txt"
[[ $(grep -c 'remove map pin: /sys/fs/bpf/unf/v6/' \
    "${temporary_dir}/plan.txt") -eq $((agent_count * 24)) ]]
[[ $(grep -c 'remove map pin: /sys/fs/bpf/unf/v5/' \
    "${temporary_dir}/plan.txt") -eq $((agent_count * 21)) ]]
[[ $("${kc[@]}" -n unf-system get deployment unf-controller \
    -o jsonpath='{.metadata.uid}') == "${before_controller}" ]]
[[ $("${kc[@]}" -n unf-system get pod \
    -l app.kubernetes.io/name=unf-agent -o json | jq -r '
        [.items[] | [.spec.nodeName, .metadata.uid] | @tsv] | sort | .[]
    ') == "${before_agents}" ]]

if KUBECONFIG="${kubeconfig}" KUBE_CONTEXT="${context}" \
    "${project_root}/hack/uninstall-openshift.sh" --execute \
    --confirm-context wrong-context --delete-namespace \
    >"${temporary_dir}/wrong-context.txt" 2>&1; then
    echo "uninstall accepted an incorrect context confirmation" >&2
    exit 1
fi
grep -q 'refusing execution: --confirm-context must exactly match' \
    "${temporary_dir}/wrong-context.txt"

restore_needed=true
KUBECONFIG="${kubeconfig}" KUBE_CONTEXT="${context}" \
    "${project_root}/hack/uninstall-openshift.sh" --execute \
    --confirm-context "${context}" --delete-namespace \
    >"${temporary_dir}/execution.txt"
grep -q 'UNF coordinated uninstall completed' "${temporary_dir}/execution.txt"

if "${kc[@]}" get namespace unf-system >/dev/null 2>&1; then
    echo "unf-system remained after requested Namespace deletion" >&2
    exit 1
fi
for resource in \
    validatingadmissionpolicybinding/unf-agent-daemonset-host-mounts \
    validatingadmissionpolicybinding/unf-agent-pod-host-mounts \
    validatingadmissionpolicy/unf-agent-daemonset-host-mounts \
    validatingadmissionpolicy/unf-agent-pod-host-mounts \
    clusterrolebinding/unf-agent-scc-use \
    clusterrolebinding/unf-controller \
    clusterrole/unf-agent-scc-use \
    clusterrole/unf-controller \
    securitycontextconstraints/unf-agent; do
    if "${kc[@]}" get "${resource}" >/dev/null 2>&1; then
        echo "UNF cluster resource remained after uninstall: ${resource}" >&2
        exit 1
    fi
done
[[ $("${kc[@]}" get customresourcedefinition \
    securitypolicies.network.unf.io -o jsonpath='{.metadata.uid}') == "${crd_uid}" ]]

mapfile -t nodes < <(cut -f1 <<<"${before_agents}")
for node in "${nodes[@]}"; do
    verification=$("${kc[@]}" debug "node/${node}" --quiet -- \
        chroot /host sh -eu -c '
            test ! -e /sys/fs/bpf/unf/v4
            test ! -e /sys/fs/bpf/unf/v5
            test ! -e /sys/fs/bpf/unf/v6
            for path in /sys/class/net/*; do
                interface=${path##*/}
                [ "${interface}" = lo ] && continue
                for direction in ingress egress; do
                    filters=$(tc filter show dev "${interface}" "${direction}" 2>/dev/null || true)
                    if printf "%s\n" "${filters}" \
                        | grep -Eq "unf_observe_(ingress|egress)|handle 0x554e000[12] "; then
                        exit 1
                    fi
                done
            done
            echo host-clean
        ' 2>&1)
    grep -q 'host-clean' <<<"${verification}"
done

KUBECONFIG="${kubeconfig}" KUBE_CONTEXT="${context}" \
    "${project_root}/hack/deploy-openshift.sh" \
    >"${temporary_dir}/redeploy.txt"
[[ $("${kc[@]}" get customresourcedefinition \
    securitypolicies.network.unf.io -o jsonpath='{.metadata.uid}') == "${crd_uid}" ]]
KUBECONFIG="${kubeconfig}" KUBE_CONTEXT="${context}" \
    "${project_root}/hack/verify-openshift.sh" \
    >"${temporary_dir}/qualification.txt"
qualification_mode=$(sed -n \
    's/^OpenShift \(IPv4\|dual-stack\) qualification passed:.*/\1/p' \
    "${temporary_dir}/qualification.txt")
[[ -n ${qualification_mode} ]]
restore_needed=false

echo "OpenShift coordinated uninstall qualification passed: dry-run non-mutation, context confirmation, agent shutdown, per-node host cleanup, exact resource removal, CRD preservation, clean redeploy, and full ${qualification_mode} recovery"
