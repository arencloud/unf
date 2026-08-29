#!/usr/bin/env bash
set -euo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
kubeconfig=${KUBECONFIG:-"${project_root}/.tools/kind-unf-service-dev.kubeconfig"}
context=${KUBE_CONTEXT:-kind-unf-service-dev}
kc=(kubectl --kubeconfig "${kubeconfig}" --context "${context}")

if [[ ${context} != kind-* ]] || [[ $("${kc[@]}" config current-context) != "${context}" ]]; then
    echo "refusing service bootstrap outside exact Kind context ${context}" >&2
    exit 1
fi
if "${kc[@]}" -n kube-system get daemonset kube-proxy >/dev/null 2>&1; then
    echo "service bootstrap requires kube-proxy to be absent" >&2
    exit 1
fi
if [[ $("${kc[@]}" -n unf-system get service unf-controller \
    -o jsonpath='{.spec.clusterIP}') != None ]]; then
    echo "service bootstrap requires the controller Service to be headless" >&2
    exit 1
fi

agent_selector=$("${kc[@]}" -n unf-system get daemonset unf-agent \
    -o json | jq -cS '.spec.template.spec.nodeSelector // {}')
if [[ ${agent_selector} == '{"network.unf.io/rollback-hold":"true"}' ]]; then
    "${kc[@]}" -n unf-system patch daemonset unf-agent --type=merge \
        --patch '{"spec":{"template":{"spec":{"nodeSelector":null}}}}' >/dev/null
fi

controller_ip=$("${kc[@]}" get nodes -l node-role.kubernetes.io/control-plane \
    -o json | jq -r '.items[0].status.addresses[] | select(.type == "InternalIP" and (.address | contains("."))) | .address')
[[ -n ${controller_ip} ]]
patch=$(jq -cn --arg ip "${controller_ip}" '
    {spec:{template:{spec:{hostAliases:[{
        ip:$ip,
        hostnames:[
            "unf-controller",
            "unf-controller.unf-system",
            "unf-controller.unf-system.svc",
            "unf-controller.unf-system.svc.cluster.local"
        ]
    }]}}}}')
"${kc[@]}" -n unf-system patch daemonset unf-agent --type=strategic \
    --patch "${patch}" >/dev/null

echo "configured exact controller bootstrap hostname for ${context}"
