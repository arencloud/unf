#!/usr/bin/env bash
set -euo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
kubeconfig=${KUBECONFIG:-"${project_root}/.tools/cl02-audit.kubeconfig"}
context=${KUBE_CONTEXT:-$(oc --kubeconfig "${kubeconfig}" config current-context)}
internal_port=${UNF_TLS_ROTATION_PORT:-19964}
kc=(oc --kubeconfig "${kubeconfig}" --context "${context}")

for command in oc openssl curl jq; do
    command -v "${command}" >/dev/null
done
[[ -s ${kubeconfig} ]] || {
    echo "OpenShift kubeconfig not found: ${kubeconfig}" >&2
    exit 1
}

temporary_dir=$(mktemp -d)
port_forward_pid=
restored=false

disable_service_ca_management() {
    "${kc[@]}" -n unf-system annotate service/unf-controller \
        service.beta.openshift.io/serving-cert-secret-name- \
        service.alpha.openshift.io/serving-cert-signed-by- \
        service.beta.openshift.io/serving-cert-signed-by- >/dev/null 2>&1 || true
    "${kc[@]}" -n unf-system annotate configmap/unf-internal-ca \
        service.beta.openshift.io/inject-cabundle- \
        openshift.io/owning-component- \
        openshift.io/description- >/dev/null 2>&1 || true
}

restore_service_ca() {
    disable_service_ca_management
    "${kc[@]}" -n unf-system create secret tls unf-internal-tls \
        --cert="${temporary_dir}/original-tls.crt" \
        --key="${temporary_dir}/original-tls.key" \
        --dry-run=client -o yaml | "${kc[@]}" apply -f - >/dev/null
    "${kc[@]}" -n unf-system create configmap unf-internal-ca \
        --from-file=service-ca.crt="${temporary_dir}/original-ca.crt" \
        --dry-run=client -o yaml | "${kc[@]}" apply -f - >/dev/null
    "${kc[@]}" -n unf-system annotate service/unf-controller \
        service.beta.openshift.io/serving-cert-secret-name=unf-internal-tls \
        --overwrite >/dev/null
    "${kc[@]}" -n unf-system annotate configmap/unf-internal-ca \
        service.beta.openshift.io/inject-cabundle=true --overwrite >/dev/null
}

cleanup() {
    if [[ -n ${port_forward_pid} ]]; then
        kill "${port_forward_pid}" >/dev/null 2>&1 || true
        wait "${port_forward_pid}" >/dev/null 2>&1 || true
    fi
    if [[ ${restored} != true && -s ${temporary_dir}/original-tls.crt ]]; then
        restore_service_ca
    fi
    rm -rf "${temporary_dir}"
}
trap cleanup EXIT

controller_pod() {
    "${kc[@]}" -n unf-system get pod \
        -l app.kubernetes.io/name=unf-controller \
        -o jsonpath='{.items[0].metadata.name}'
}

agent_pods() {
    "${kc[@]}" -n unf-system get pod \
        -l app.kubernetes.io/name=unf-agent \
        -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' | sort
}

pod_runtime_state() {
    "${kc[@]}" -n unf-system get pod \
        -l 'app.kubernetes.io/name in (unf-controller,unf-agent)' -o json \
        | jq -r '.items[] | [.metadata.uid, (.status.containerStatuses[0].restartCount // 0)] | @tsv' \
        | sort
}

metric_value() {
    local pod=$1
    local port=$2
    local metric=$3
    "${kc[@]}" get --raw \
        "/api/v1/namespaces/unf-system/pods/${pod}:${port}/proxy/metrics" 2>/dev/null \
        | awk -v metric="${metric}" '$1 == metric { print int($2) }'
}

wait_for_metric() {
    local pod=$1
    local port=$2
    local metric=$3
    local minimum=$4
    local value=0
    for _ in {1..90}; do
        value=$(metric_value "${pod}" "${port}" "${metric}" || true)
        if [[ ${value:-0} -ge ${minimum} ]]; then
            return 0
        fi
        sleep 2
    done
    echo "timed out waiting for ${metric} >= ${minimum} on ${pod}" >&2
    return 1
}

wait_for_agents() {
    local controller
    local status
    for _ in {1..60}; do
        controller=$(controller_pod)
        status=$("${kc[@]}" get --raw \
            "/api/v1/namespaces/unf-system/pods/${controller}:9962/proxy/v1/status" \
            2>/dev/null || true)
        if jq -e '.agents.all_converged == true and .agents.missing_agents == 0' \
            <<<"${status}" >/dev/null 2>&1; then
            return 0
        fi
        sleep 2
    done
    echo "agents did not remain converged during TLS rotation" >&2
    return 1
}

wait_for_mounted_ca() {
    local path=$1
    local expected
    local actual
    local pod
    local complete
    expected=$(sha256sum "${path}" | awk '{ print $1 }')
    for _ in {1..120}; do
        complete=true
        while IFS= read -r pod; do
            actual=$("${kc[@]}" -n unf-system exec "${pod}" -- \
                sha256sum /var/run/secrets/unf-internal-ca/ca.crt 2>/dev/null \
                | awk '{ print $1 }' || true)
            if [[ ${actual} != "${expected}" ]]; then
                complete=false
                break
            fi
        done < <(agent_pods)
        if [[ ${complete} == true ]]; then
            return 0
        fi
        sleep 2
    done
    echo "CA bundle did not project to every agent" >&2
    return 1
}

apply_trust_bundle() {
    local path=$1
    "${kc[@]}" -n unf-system create configmap unf-internal-ca \
        --from-file=service-ca.crt="${path}" \
        --dry-run=client -o yaml | "${kc[@]}" apply -f - >/dev/null
}

apply_keypair() {
    local certificate=$1
    local private_key=$2
    "${kc[@]}" -n unf-system create secret tls unf-internal-tls \
        --cert="${certificate}" --key="${private_key}" \
        --dry-run=client -o yaml | "${kc[@]}" apply -f - >/dev/null
}

wait_for_trust_metric() {
    local metric=$1
    local increment=$2
    local pod
    local baseline
    while IFS= read -r pod; do
        baseline=$(awk -v pod="${pod}" '$1 == pod { print $2 }' "${temporary_dir}/${metric}.baseline")
        wait_for_metric "${pod}" 9963 "${metric}" "$((baseline + increment))"
    done < <(agent_pods)
}

wait_for_any_trust_error() {
    local metric=unf_agent_controller_trust_reload_errors_total
    local baseline=0
    local current=0
    local pod
    local value
    while IFS= read -r pod; do
        baseline=$((baseline + $(awk -v pod="${pod}" \
            '$1 == pod { print $2 }' "${temporary_dir}/${metric}.baseline")))
    done < <(agent_pods)
    for _ in {1..90}; do
        current=0
        while IFS= read -r pod; do
            value=$(metric_value "${pod}" 9963 "${metric}" || true)
            current=$((current + ${value:-0}))
        done < <(agent_pods)
        if [[ ${current} -ge $((baseline + 1)) ]]; then
            return 0
        fi
        sleep 2
    done
    echo "no agent observed and rejected the malformed CA update" >&2
    return 1
}

"${kc[@]}" get clusterversion version >/dev/null
"${kc[@]}" -n unf-system wait --for=condition=Available deployment/unf-controller \
    --timeout=120s >/dev/null
"${kc[@]}" -n unf-system rollout status daemonset/unf-agent --timeout=120s >/dev/null
wait_for_agents

install -d -m 0700 "${temporary_dir}/original" "${temporary_dir}/original-ca"
"${kc[@]}" -n unf-system extract secret/unf-internal-tls \
    --keys=tls.crt,tls.key --to="${temporary_dir}/original" >/dev/null
mv "${temporary_dir}/original/tls.crt" "${temporary_dir}/original-tls.crt"
mv "${temporary_dir}/original/tls.key" "${temporary_dir}/original-tls.key"
"${kc[@]}" -n unf-system extract configmap/unf-internal-ca \
    --keys=service-ca.crt --to="${temporary_dir}/original-ca" >/dev/null
mv "${temporary_dir}/original-ca/service-ca.crt" "${temporary_dir}/original-ca.crt"
chmod 0600 "${temporary_dir}/original-tls.key"

initial_runtime_state=$(pod_runtime_state)
controller=$(controller_pod)
controller_reload_baseline=$(metric_value "${controller}" 9962 \
    unf_controller_tls_reloads_total)
controller_error_baseline=$(metric_value "${controller}" 9962 \
    unf_controller_tls_reload_errors_total)
while IFS= read -r pod; do
    printf '%s %s\n' "${pod}" "$(metric_value "${pod}" 9963 \
        unf_agent_controller_trust_reloads_total)"
done < <(agent_pods) >"${temporary_dir}/unf_agent_controller_trust_reloads_total.baseline"
while IFS= read -r pod; do
    printf '%s %s\n' "${pod}" "$(metric_value "${pod}" 9963 \
        unf_agent_controller_trust_reload_errors_total)"
done < <(agent_pods) >"${temporary_dir}/unf_agent_controller_trust_reload_errors_total.baseline"

openssl req -x509 -newkey rsa:3072 -nodes -sha256 -days 30 \
    -subj '/CN=UNF rotation qualification CA' \
    -keyout "${temporary_dir}/rotation-ca.key" \
    -out "${temporary_dir}/rotation-ca.crt" >/dev/null 2>&1
openssl req -new -newkey rsa:2048 -nodes -sha256 \
    -subj '/CN=unf-controller.unf-system.svc.cluster.local' \
    -keyout "${temporary_dir}/rotation-tls.key" \
    -out "${temporary_dir}/rotation-tls.csr" >/dev/null 2>&1
printf '%s\n' \
    'basicConstraints=critical,CA:FALSE' \
    'keyUsage=critical,digitalSignature,keyEncipherment' \
    'extendedKeyUsage=serverAuth' \
    'subjectAltName=DNS:unf-controller,DNS:unf-controller.unf-system,DNS:unf-controller.unf-system.svc,DNS:unf-controller.unf-system.svc.cluster.local' \
    >"${temporary_dir}/rotation-tls.ext"
openssl x509 -req -sha256 -days 30 \
    -in "${temporary_dir}/rotation-tls.csr" \
    -CA "${temporary_dir}/rotation-ca.crt" \
    -CAkey "${temporary_dir}/rotation-ca.key" -CAcreateserial \
    -extfile "${temporary_dir}/rotation-tls.ext" \
    -out "${temporary_dir}/rotation-tls.crt" >/dev/null 2>&1

disable_service_ca_management

awk '1' "${temporary_dir}/original-ca.crt" "${temporary_dir}/rotation-ca.crt" \
    >"${temporary_dir}/overlap-ca.crt"
apply_trust_bundle "${temporary_dir}/overlap-ca.crt"
wait_for_trust_metric unf_agent_controller_trust_reloads_total 1

apply_keypair "${temporary_dir}/rotation-tls.crt" "${temporary_dir}/rotation-tls.key"
wait_for_metric "${controller}" 9962 unf_controller_tls_reloads_total \
    "$((controller_reload_baseline + 1))"
wait_for_agents

"${kc[@]}" -n unf-system exec "$(agent_pods | head -n 1)" -- \
    cat /var/run/secrets/unf-agent/token >"${temporary_dir}/token"
chmod 0600 "${temporary_dir}/token"
"${kc[@]}" -n unf-system port-forward service/unf-controller \
    "${internal_port}:9964" >"${temporary_dir}/port-forward.log" 2>&1 &
port_forward_pid=$!
for _ in {1..30}; do
    if curl --noproxy '*' --fail --silent \
        --cacert "${temporary_dir}/rotation-ca.crt" \
        --resolve "unf-controller.unf-system.svc.cluster.local:${internal_port}:127.0.0.1" \
        --header "Authorization: Bearer $(<"${temporary_dir}/token")" \
        "https://unf-controller.unf-system.svc.cluster.local:${internal_port}/v1/state/identities" \
        >/dev/null 2>&1; then
        break
    fi
    sleep 1
done
curl --noproxy '*' --fail --silent \
    --cacert "${temporary_dir}/rotation-ca.crt" \
    --resolve "unf-controller.unf-system.svc.cluster.local:${internal_port}:127.0.0.1" \
    --header "Authorization: Bearer $(<"${temporary_dir}/token")" \
    "https://unf-controller.unf-system.svc.cluster.local:${internal_port}/v1/state/identities" \
    | jq -e '.schema_version >= 1' >/dev/null

apply_trust_bundle "${temporary_dir}/rotation-ca.crt"
wait_for_trust_metric unf_agent_controller_trust_reloads_total 2
wait_for_agents

printf '%s\n' 'not a certificate' >"${temporary_dir}/invalid-ca.crt"
apply_trust_bundle "${temporary_dir}/invalid-ca.crt"
wait_for_any_trust_error
wait_for_agents
apply_trust_bundle "${temporary_dir}/rotation-ca.crt"
wait_for_mounted_ca "${temporary_dir}/rotation-ca.crt"
wait_for_agents

"${kc[@]}" -n unf-system patch secret unf-internal-tls --type=merge \
    -p '{"data":{"tls.crt":"bm90IGEgY2VydGlmaWNhdGU="}}' >/dev/null
wait_for_metric "${controller}" 9962 unf_controller_tls_reload_errors_total \
    "$((controller_error_baseline + 1))"
wait_for_agents
apply_keypair "${temporary_dir}/rotation-tls.crt" "${temporary_dir}/rotation-tls.key"
wait_for_metric "${controller}" 9962 unf_controller_tls_reloads_total \
    "$((controller_reload_baseline + 2))"

apply_trust_bundle "${temporary_dir}/overlap-ca.crt"
wait_for_mounted_ca "${temporary_dir}/overlap-ca.crt"
apply_keypair "${temporary_dir}/original-tls.crt" "${temporary_dir}/original-tls.key"
wait_for_metric "${controller}" 9962 unf_controller_tls_reloads_total \
    "$((controller_reload_baseline + 3))"
apply_trust_bundle "${temporary_dir}/original-ca.crt"
wait_for_mounted_ca "${temporary_dir}/original-ca.crt"
restore_service_ca
restored=true

wait_for_agents
[[ $(pod_runtime_state) == "${initial_runtime_state}" ]]
openssl verify -CAfile "${temporary_dir}/original-ca.crt" \
    "${temporary_dir}/original-tls.crt" >/dev/null

echo "OpenShift TLS rotation qualification passed: overlapping CA transition, external-PKI leaf handoff, malformed leaf/CA rejection, last-known-good continuity, Service CA restoration, and zero Pod replacements"
