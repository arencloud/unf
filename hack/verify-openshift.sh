#!/usr/bin/env bash
set -euo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
for command in oc yq jq curl openssl timeout; do
    command -v "${command}" >/dev/null
done
kubeconfig=${KUBECONFIG:-"${project_root}/.tools/cl01-audit.kubeconfig"}
auth_file=${QUAY_AUTH_FILE:-"${project_root}/.tools/quay-auth.json"}
context=${KUBE_CONTEXT:-$(oc --kubeconfig "${kubeconfig}" config current-context)}
public_port=${UNF_OPENSHIFT_PUBLIC_PORT:-29962}
internal_port=${UNF_OPENSHIFT_INTERNAL_PORT:-29964}
client_namespace=unf-qualification-client
server_namespace=unf-qualification-server
qualification_manifest=${project_root}/deploy/openshift/qualification-ipv4.yaml
kc=(oc --kubeconfig "${kubeconfig}" --context "${context}")
temporary_dir=$(mktemp -d)
port_forward_pid=

cleanup() {
    local result=$?
    trap - EXIT
    set +e
    if [[ -n ${port_forward_pid} ]]; then
        kill "${port_forward_pid}" >/dev/null 2>&1
        wait "${port_forward_pid}" 2>/dev/null
    fi
    "${kc[@]}" delete namespace "${client_namespace}" "${server_namespace}" \
        --ignore-not-found --wait=true >/dev/null 2>&1
    rm -rf "${temporary_dir}"
    exit "${result}"
}
trap cleanup EXIT

[[ -s ${kubeconfig} ]] || {
    echo "OpenShift kubeconfig not found: ${kubeconfig}" >&2
    exit 1
}
[[ -s ${auth_file} ]] || {
    echo "Quay authentication file not found: ${auth_file}" >&2
    exit 1
}

"${kc[@]}" get clusterversion version >/dev/null
unhealthy_operators=$("${kc[@]}" get clusteroperators -o json | jq '[
    .items[] | select(
        ([.status.conditions[] | select(.type == "Available")][0].status) != "True"
        or ([.status.conditions[] | select(.type == "Degraded")][0].status) == "True"
    )
] | length')
[[ ${unhealthy_operators} -eq 0 ]]
ipv4_cluster_networks=$("${kc[@]}" get network.config.openshift.io cluster -o json \
    | jq '[.status.clusterNetwork[].cidr | select(contains(":") | not)] | length')
[[ ${ipv4_cluster_networks} -gt 0 ]]

mapfile -t workers < <("${kc[@]}" get nodes -l node-role.kubernetes.io/worker \
    -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}')
[[ ${#workers[@]} -ge 2 ]]
for node in "${workers[@]}"; do
    [[ $("${kc[@]}" get node "${node}" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}') == True ]]
done

controller=$("${kc[@]}" -n unf-system get pods \
    -l app.kubernetes.io/name=unf-controller \
    -o jsonpath='{.items[0].metadata.name}')
mapfile -t agents < <("${kc[@]}" -n unf-system get pods \
    -l app.kubernetes.io/name=unf-agent \
    -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}')
[[ ${#agents[@]} -eq ${#workers[@]} ]]
[[ $("${kc[@]}" -n unf-system get pod "${controller}" \
    -o jsonpath='{.metadata.annotations.openshift\.io/scc}') == restricted-v2 ]]

uid_allocation=$("${kc[@]}" get namespace unf-system \
    -o jsonpath='{.metadata.annotations.openshift\.io/sa\.scc\.uid-range}')
uid_base=${uid_allocation%/*}
uid_size=${uid_allocation#*/}
controller_uid=$("${kc[@]}" -n unf-system get pod "${controller}" \
    -o jsonpath='{.spec.containers[0].securityContext.runAsUser}')
(( controller_uid >= uid_base && controller_uid < uid_base + uid_size ))

for agent in "${agents[@]}"; do
    [[ $("${kc[@]}" -n unf-system get pod "${agent}" \
        -o jsonpath='{.metadata.annotations.openshift\.io/scc}') == privileged ]]
    node=$("${kc[@]}" -n unf-system get pod "${agent}" -o jsonpath='{.spec.nodeName}')
    "${kc[@]}" get node "${node}" -o json \
        | jq -e '.metadata.labels | has("node-role.kubernetes.io/worker")' >/dev/null
    agent_status=$("${kc[@]}" get --raw \
        "/api/v1/namespaces/unf-system/pods/${agent}:9963/proxy/v1/status")
    jq -e '
        .ready == true
        and .bpf_loaded == true
        and .tc_attachment_mode == "legacy_netlink"
        and .capabilities.btf == true
        and .capabilities.bpffs == true
        and .capabilities.cgroup_v2 == true
        and .ipv4_identity_map_entries > 0
        and .ipv6_identity_map_entries == 0
    ' <<<"${agent_status}" >/dev/null
    "${kc[@]}" -n unf-system exec "${agent}" -- sh -eu -c '
        test -r /sys/kernel/btf/vmlinux
        test "$(stat -f -c %T /sys/fs/bpf)" = bpf_fs
    '
done

controller_status=$("${kc[@]}" get --raw \
    "/api/v1/namespaces/unf-system/pods/${controller}:9962/proxy/v1/status")
jq -e --argjson workers "${#workers[@]}" '
    .agents.expected_agents == $workers
    and .agents.reporting_agents == $workers
    and .agents.converged_agents == $workers
    and .agents.missing_agents == 0
    and .agents.unexpected_agents == 0
    and .agents.all_converged == true
' <<<"${controller_status}" >/dev/null

for node in "${workers[@]}"; do
    host_probe=$("${kc[@]}" debug "node/${node}" --quiet -- chroot /host sh -eu -c '
        printf "selinux=%s\n" "$(getenforce)"
        found=0
        for path in /sys/class/net/*; do
            interface=${path##*/}
            [ "${interface}" = lo ] && continue
            if tc filter show dev "${interface}" ingress pref 21838 2>/dev/null \
                | grep -q "handle 0x554e0001 "; then
                found=1
                break
            fi
        done
        printf "legacy_filter=%s\n" "${found}"
        [ "${found}" -eq 1 ]
    ' 2>&1)
    grep -q 'selinux=Enforcing' <<<"${host_probe}"
    grep -q 'legacy_filter=1' <<<"${host_probe}"
done

install -d -m 0700 "${temporary_dir}/ca" "${temporary_dir}/cert"
"${kc[@]}" -n unf-system extract configmap/unf-internal-ca \
    --keys=service-ca.crt --to="${temporary_dir}/ca" >/dev/null
"${kc[@]}" -n unf-system extract secret/unf-internal-tls \
    --keys=tls.crt --to="${temporary_dir}/cert" >/dev/null
openssl verify -CAfile "${temporary_dir}/ca/service-ca.crt" \
    "${temporary_dir}/cert/tls.crt" >/dev/null
openssl x509 -checkend 86400 -noout -in "${temporary_dir}/cert/tls.crt"
openssl x509 -noout -ext subjectAltName -in "${temporary_dir}/cert/tls.crt" \
    | grep -q 'DNS:unf-controller.unf-system.svc'

"${kc[@]}" -n unf-system exec "${agents[0]}" -- \
    cat /var/run/secrets/unf-agent/token >"${temporary_dir}/token"
chmod 0600 "${temporary_dir}/token"
"${kc[@]}" -n unf-system port-forward service/unf-controller \
    "${public_port}:9962" "${internal_port}:9964" \
    >"${temporary_dir}/port-forward.log" 2>&1 &
port_forward_pid=$!
for _ in {1..30}; do
    if curl --noproxy '*' --fail --silent \
        "http://127.0.0.1:${public_port}/healthz" >/dev/null 2>&1; then
        break
    fi
    sleep 1
done
curl --noproxy '*' --fail --silent \
    "http://127.0.0.1:${public_port}/healthz" >/dev/null
public_identity_code=$(curl --noproxy '*' --silent --output /dev/null \
    --write-out '%{http_code}' \
    "http://127.0.0.1:${public_port}/v1/state/identities")
[[ ${public_identity_code} == 404 ]]

internal_host=unf-controller.unf-system.svc
internal_url="https://${internal_host}:${internal_port}"
if curl --noproxy '*' --fail --silent \
    --resolve "${internal_host}:${internal_port}:127.0.0.1" \
    "${internal_url}/v1/state/identities" >/dev/null 2>&1; then
    echo "OpenShift serving certificate was trusted without its injected CA" >&2
    exit 1
fi
anonymous_code=$(curl --noproxy '*' \
    --cacert "${temporary_dir}/ca/service-ca.crt" \
    --resolve "${internal_host}:${internal_port}:127.0.0.1" \
    --silent --output /dev/null --write-out '%{http_code}' \
    "${internal_url}/v1/state/identities")
invalid_code=$(curl --noproxy '*' \
    --cacert "${temporary_dir}/ca/service-ca.crt" \
    --resolve "${internal_host}:${internal_port}:127.0.0.1" \
    --header 'Authorization: Bearer invalid-token' \
    --silent --output /dev/null --write-out '%{http_code}' \
    "${internal_url}/v1/state/identities")
[[ ${anonymous_code} == 401 && ${invalid_code} == 401 ]]

token=$(<"${temporary_dir}/token")
identity_snapshot=$(curl --noproxy '*' --fail --silent \
    --cacert "${temporary_dir}/ca/service-ca.crt" \
    --resolve "${internal_host}:${internal_port}:127.0.0.1" \
    --header "Authorization: Bearer ${token}" \
    "${internal_url}/v1/state/identities")
jq -e '
    .schema_version >= 1
    and (.ipv4_entries | length) > 0
    and (.ipv6_entries | length) == 0
' <<<"${identity_snapshot}" >/dev/null

report=$("${kc[@]}" get --raw \
    "/api/v1/namespaces/unf-system/pods/${agents[0]}:9963/proxy/v1/status")
actual_node=$(jq -r .node_name <<<"${report}")
other_node=$(printf '%s\n' "${workers[@]}" | grep -v -Fx "${actual_node}" | head -n 1)
forged_report=$(jq --arg node "${other_node}" '.node_name = $node' <<<"${report}")
forged_code=$(curl --noproxy '*' \
    --cacert "${temporary_dir}/ca/service-ca.crt" \
    --resolve "${internal_host}:${internal_port}:127.0.0.1" \
    --header "Authorization: Bearer ${token}" \
    --header 'Content-Type: application/json' \
    --data "${forged_report}" \
    --silent --output /dev/null --write-out '%{http_code}' \
    "${internal_url}/v1/state/agents")
[[ ${forged_code} == 403 ]]
unset token

"${kc[@]}" delete namespace "${client_namespace}" "${server_namespace}" \
    --ignore-not-found --wait=true >/dev/null
baseline_security_policies=
for _ in {1..60}; do
    api_security_policies=$("${kc[@]}" get securitypolicies.network.unf.io \
        --all-namespaces -o json | jq '.items | length')
    observed_security_policies=$("${kc[@]}" get --raw \
        "/api/v1/namespaces/unf-system/pods/${controller}:9962/proxy/v1/status" \
        | jq .security_policies)
    if [[ ${api_security_policies} -eq ${observed_security_policies} ]]; then
        baseline_security_policies=${observed_security_policies}
        break
    fi
    sleep 1
done
[[ -n ${baseline_security_policies} ]]
yq eval-all 'select(.kind == "Namespace")' "${qualification_manifest}" \
    | "${kc[@]}" apply -f - >/dev/null
for namespace in "${client_namespace}" "${server_namespace}"; do
    "${kc[@]}" -n "${namespace}" create secret generic unf-quay-pull \
        --from-file=.dockerconfigjson="${auth_file}" \
        --type=kubernetes.io/dockerconfigjson \
        --dry-run=client -o yaml | "${kc[@]}" apply -f - >/dev/null
done
yq eval-all 'select(.kind != "Namespace")' "${qualification_manifest}" \
    | "${kc[@]}" apply -f - >/dev/null
"${kc[@]}" -n "${client_namespace}" wait --for=condition=Ready \
    pod/client --timeout=180s >/dev/null
"${kc[@]}" -n "${server_namespace}" wait --for=condition=Ready \
    pod/server --timeout=180s >/dev/null

client_node=$("${kc[@]}" -n "${client_namespace}" get pod client \
    -o jsonpath='{.spec.nodeName}')
server_node=$("${kc[@]}" -n "${server_namespace}" get pod server \
    -o jsonpath='{.spec.nodeName}')
server_ip=$("${kc[@]}" -n "${server_namespace}" get pod server \
    -o jsonpath='{.status.podIP}')
[[ ${client_node} != "${server_node}" && ${server_ip} != *:* ]]

converged=false
for _ in {1..90}; do
    controller_status=$("${kc[@]}" get --raw \
        "/api/v1/namespaces/unf-system/pods/${controller}:9962/proxy/v1/status")
    if jq -e --argjson expected "$((baseline_security_policies + 1))" '
        .security_policies == $expected
        and .agents.all_converged == true
    ' <<<"${controller_status}" >/dev/null; then
        converged=true
        break
    fi
    sleep 1
done
[[ ${converged} == true ]]

allowed=$(timeout 12 "${kc[@]}" -n "${client_namespace}" exec client -- \
    wget -qO- -T 2 -t 1 "http://${server_ip}:8080")
[[ ${allowed} == unf-openshift-ok ]]
if timeout 12 "${kc[@]}" -n "${client_namespace}" exec client -- \
    wget -qO- -T 2 -t 1 "http://${server_ip}:9090" >/dev/null 2>&1; then
    echo "OpenShift IPv4 qualification TCP/9090 unexpectedly passed" >&2
    exit 1
fi

history_verified=false
for _ in {1..20}; do
    flow_history=$("${kc[@]}" get --raw \
        "/api/v1/namespaces/unf-system/pods/${controller}:9962/proxy/v1/flows")
    if jq -e '
        any(.entries[];
            (.source_workloads | index("unf-qualification-client/client"))
            and (.destination_workloads | index("unf-qualification-server/server"))
            and .key.destination_port == 8080
            and .decision.verdict == "Allow"
            and .decision.policy_id != null)
        and any(.entries[];
            (.source_workloads | index("unf-qualification-client/client"))
            and (.destination_workloads | index("unf-qualification-server/server"))
            and .key.destination_port == 9090
            and .decision.verdict == "Deny"
            and .decision.policy_id != null)
    ' <<<"${flow_history}" >/dev/null; then
        history_verified=true
        break
    fi
    timeout 12 "${kc[@]}" -n "${client_namespace}" exec client -- \
        wget -qO- -T 2 -t 1 "http://${server_ip}:8080" >/dev/null
    timeout 12 "${kc[@]}" -n "${client_namespace}" exec client -- \
        wget -qO- -T 2 -t 1 "http://${server_ip}:9090" >/dev/null 2>&1 || true
    sleep 1
done
[[ ${history_verified} == true ]]

for agent in "${agents[@]}"; do
    metric=$("${kc[@]}" get --raw \
        "/api/v1/namespaces/unf-system/pods/${agent}:9963/proxy/metrics" \
        | awk '/^unf_management_flow_events_filtered_total / {print $2; exit}')
    awk -v value="${metric}" 'BEGIN { exit !(value + 0 > 0) }'
done

unhealthy_operators=$("${kc[@]}" get clusteroperators -o json | jq '[
    .items[] | select(
        ([.status.conditions[] | select(.type == "Available")][0].status) != "True"
        or ([.status.conditions[] | select(.type == "Degraded")][0].status) == "True"
    )
] | length')
[[ ${unhealthy_operators} -eq 0 ]]

echo "OpenShift IPv4 qualification passed: restricted-v2 controller, privileged worker-only agents, enforcing SELinux, BTF/bpffs, native legacy netlink filters, Service CA TLS, Pod-bound TokenReview, two-worker convergence, IPv4 allow/drop provenance, and healthy cluster operators"
