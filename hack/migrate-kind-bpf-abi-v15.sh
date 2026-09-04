#!/usr/bin/env bash
set -Eeuo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
kubeconfig=${KUBECONFIG:-"${project_root}/.tools/kind-unf-service-dev.kubeconfig"}
context=${KUBE_CONTEXT:-kind-unf-service-dev}
kc=(kubectl --kubeconfig "${kubeconfig}" --context "${context}")

command -v kubectl >/dev/null
command -v rg >/dev/null
command -v jq >/dev/null
[[ ${context} == kind-* ]]
[[ $("${kc[@]}" config current-context) == "${context}" ]]

mapfile -t nodes < <("${kc[@]}" get nodes -o name | sed 's|node/||' | sort)
mapfile -t pods < <("${kc[@]}" -n unf-system get pods \
    -l app.kubernetes.io/name=unf-agent -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' | sort)
(( ${#nodes[@]} > 0 && ${#pods[@]} == ${#nodes[@]} ))

for pod in "${pods[@]}"; do
    configured_path=$("${kc[@]}" -n unf-system get pod "${pod}" -o json \
        | jq -r '.spec.containers[] | select(.name == "agent") | .args as $args |
            ($args | index("--bpf-pin-path")) as $index | $args[$index + 1]')
    [[ ${configured_path} == /sys/fs/bpf/unf/v15 ]]
    plan=$("${kc[@]}" -n unf-system exec "${pod}" -c agent -- \
        /usr/local/bin/unf-component cleanup --abi-version 14)
    rg --fixed-strings --quiet 'ABI directory: /sys/fs/bpf/unf/v14' <<<"${plan}"
    "${kc[@]}" -n unf-system exec "${pod}" -c agent -- \
        /usr/local/bin/unf-component cleanup --abi-version 14 --execute >/dev/null
    "${kc[@]}" -n unf-system exec "${pod}" -c agent -- /bin/sh -ec \
        'test ! -e /sys/fs/bpf/unf/v14 && test -e /sys/fs/bpf/unf/v15/EGRESS_CONFIG'
done

echo "Kind BPF migration passed: current v15 ownership is live and exact historical v14 pins are absent"
