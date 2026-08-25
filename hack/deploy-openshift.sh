#!/usr/bin/env bash
set -euo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
command -v oc >/dev/null
kubeconfig=${KUBECONFIG:-"${project_root}/.tools/cl01-audit.kubeconfig"}
auth_file=${QUAY_AUTH_FILE:-"${project_root}/.tools/quay-auth.json"}
context=${KUBE_CONTEXT:-$(oc --kubeconfig "${kubeconfig}" config current-context)}
kc=(oc --kubeconfig "${kubeconfig}" --context "${context}")

[[ -s ${kubeconfig} ]] || {
    echo "OpenShift kubeconfig not found: ${kubeconfig}" >&2
    exit 1
}
[[ -s ${auth_file} ]] || {
    echo "Quay authentication file not found: ${auth_file}" >&2
    exit 1
}

"${kc[@]}" get clusterversion version >/dev/null
"${kc[@]}" apply -f "${project_root}/deploy/kubernetes/namespace.yaml"
"${kc[@]}" -n unf-system create secret generic unf-quay-pull \
    --from-file=.dockerconfigjson="${auth_file}" \
    --type=kubernetes.io/dockerconfigjson \
    --dry-run=client -o yaml | "${kc[@]}" apply -f -
"${kc[@]}" apply -k "${project_root}/deploy/openshift"

for _ in {1..60}; do
    if "${kc[@]}" -n unf-system get secret unf-internal-tls >/dev/null 2>&1 \
        && [[ $("${kc[@]}" -n unf-system get configmap unf-internal-ca \
            -o jsonpath='{.data.service-ca\.crt}' | wc -c) -gt 1 ]]; then
        break
    fi
    sleep 1
done
"${kc[@]}" -n unf-system get secret unf-internal-tls >/dev/null
[[ $("${kc[@]}" -n unf-system get configmap unf-internal-ca \
    -o jsonpath='{.data.service-ca\.crt}' | wc -c) -gt 1 ]]

"${kc[@]}" -n unf-system rollout restart deployment/unf-controller
"${kc[@]}" -n unf-system rollout restart daemonset/unf-agent
"${kc[@]}" -n unf-system rollout status deployment/unf-controller --timeout=180s
"${kc[@]}" -n unf-system rollout status daemonset/unf-agent --timeout=180s

echo "deployed UNF OpenShift development overlay to ${context}"
