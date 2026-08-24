#!/usr/bin/env bash
set -euo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
kubeconfig=${KUBECONFIG:-"${project_root}/.tools/kind-unf-dev.kubeconfig"}
context=${KUBE_CONTEXT:-kind-unf-dev}
controller_port=${UNF_CONTROLLER_TEST_PORT:-19962}
unfctl=${UNFCTL:-"${project_root}/target/debug/unfctl"}
temporary_dir=$(mktemp -d)
controller_forward_pid=
policy_mutated=false
network_policy_mutated=false
network_policy_protocol_mutated=false
network_policy_peer_mutated=false
network_policy_deleted=false
network_policy_conformance_created=false
network_policy_sctp_created=false
namespace_mutated=false
topology_service_created=false
network_policy_selector_peer='[{"namespaceSelector":{"matchLabels":{"environment":"production"},"matchExpressions":[{"key":"team","operator":"In","values":["checkout"]}]},"podSelector":{"matchExpressions":[{"key":"app.kubernetes.io/name","operator":"In","values":["client"]}]}}]'

cleanup() {
    if [[ ${network_policy_sctp_created} == true ]]; then
        "${kc[@]}" delete -f \
            "${project_root}/deploy/examples/networkpolicy-sctp.yaml" \
            --ignore-not-found >/dev/null 2>&1 || true
    fi
    if [[ ${network_policy_conformance_created} == true ]]; then
        "${kc[@]}" delete -f \
            "${project_root}/deploy/examples/networkpolicy-conformance.yaml" \
            --ignore-not-found >/dev/null 2>&1 || true
    fi
    if [[ ${topology_service_created} == true ]]; then
        "${kc[@]}" delete -f "${project_root}/deploy/examples/topology-probe.yaml" \
            --ignore-not-found >/dev/null 2>&1 || true
    fi
    if [[ ${policy_mutated} == true ]]; then
        "${kc[@]}" patch securitypolicy -n backend frontend-to-backend \
            --type=merge -p '{"spec":{"enforcementMode":"Enforce"}}' >/dev/null 2>&1 || true
    fi
    if [[ ${network_policy_mutated} == true ]]; then
        "${kc[@]}" patch networkpolicy -n backend frontend-to-np-server --type=json \
            -p '[{"op":"replace","path":"/spec/ingress/0/ports/1/endPort","value":8083}]' \
            >/dev/null 2>&1 || true
    fi
    if [[ ${network_policy_protocol_mutated} == true ]]; then
        "${kc[@]}" patch networkpolicy -n backend frontend-to-np-server --type=json \
            -p '[{"op":"remove","path":"/spec/ingress/0/ports/2"}]' \
            >/dev/null 2>&1 || true
    fi
    if [[ ${network_policy_peer_mutated} == true ]]; then
        "${kc[@]}" patch networkpolicy -n backend frontend-to-np-server --type=json \
            -p "[{\"op\":\"replace\",\"path\":\"/spec/ingress/0/from\",\"value\":${network_policy_selector_peer}}]" \
            >/dev/null 2>&1 || true
    fi
    if [[ ${network_policy_deleted} == true ]]; then
        "${kc[@]}" apply -f "${project_root}/deploy/examples/demo.yaml" >/dev/null 2>&1 || true
    fi
    if [[ ${namespace_mutated} == true ]]; then
        "${kc[@]}" label namespace frontend environment=production team=checkout --overwrite \
            >/dev/null 2>&1 || true
    fi
    if [[ -n ${controller_forward_pid} ]]; then
        kill "${controller_forward_pid}" 2>/dev/null || true
    fi
    rm -rf "${temporary_dir}"
}
trap cleanup EXIT

kc=(kubectl --kubeconfig "${kubeconfig}" --context "${context}")

agent_status() {
    "${kc[@]}" get --raw "/api/v1/namespaces/unf-system/pods/${1}/proxy/v1/status"
}

json_number() {
    local field=$1
    sed -nE "s/.*\"${field}\":([0-9]+).*/\1/p"
}

wait_for_policy_transition() {
    local floor_revision=$1
    local all_converged status desired applied bank pod candidate_revision controller_revision
    for _ in {1..30}; do
        all_converged=true
        candidate_revision=
        controller_revision=$("${unfctl}" \
            --controller-url "http://127.0.0.1:${controller_port}" --output json status \
            | sed -nE 's/.*"policy": ([0-9]+).*/\1/p')
        for pod in "${agent_pods[@]}"; do
            status=$(agent_status "${pod}" || true)
            desired=$(json_number desired_policy_revision <<<"${status}")
            applied=$(json_number applied_policy_revision <<<"${status}")
            bank=$(json_number active_policy_bank <<<"${status}")
            if [[ -z ${applied} || ${applied} -le ${floor_revision} \
                || ${desired} != "${applied}" || ${bank} == "${policy_banks[${pod}]}" ]]; then
                all_converged=false
                break
            fi
            if [[ -n ${candidate_revision} && ${candidate_revision} != "${applied}" ]]; then
                all_converged=false
                break
            fi
            candidate_revision=${applied}
        done
        if [[ -z ${candidate_revision} || ${candidate_revision} != "${controller_revision}" ]]; then
            all_converged=false
        fi
        if [[ ${all_converged} == true ]]; then
            transition_revision=${candidate_revision}
            for pod in "${agent_pods[@]}"; do
                status=$(agent_status "${pod}")
                policy_banks[${pod}]=$(json_number active_policy_bank <<<"${status}")
            done
            return 0
        fi
        sleep 1
    done
    return 1
}

wait_for_policy_batch_convergence() {
    local floor_revision=$1
    local all_converged status desired applied pod candidate_revision controller_revision
    for _ in {1..30}; do
        all_converged=true
        candidate_revision=
        controller_revision=$("${unfctl}" \
            --controller-url "http://127.0.0.1:${controller_port}" --output json status \
            | sed -nE 's/.*"policy": ([0-9]+).*/\1/p')
        for pod in "${agent_pods[@]}"; do
            status=$(agent_status "${pod}" || true)
            desired=$(json_number desired_policy_revision <<<"${status}")
            applied=$(json_number applied_policy_revision <<<"${status}")
            if [[ -z ${applied} || ${applied} -le ${floor_revision} \
                || ${desired} != "${applied}" ]]; then
                all_converged=false
                break
            fi
            if [[ -n ${candidate_revision} && ${candidate_revision} != "${applied}" ]]; then
                all_converged=false
                break
            fi
            candidate_revision=${applied}
        done
        if [[ -z ${candidate_revision} || ${candidate_revision} != "${controller_revision}" ]]; then
            all_converged=false
        fi
        if [[ ${all_converged} == true ]]; then
            transition_revision=${candidate_revision}
            for pod in "${agent_pods[@]}"; do
                status=$(agent_status "${pod}")
                policy_banks[${pod}]=$(json_number active_policy_bank <<<"${status}")
            done
            return 0
        fi
        sleep 1
    done
    return 1
}

all_agent_logs() {
    "${kc[@]}" -n unf-system logs -l app.kubernetes.io/name=unf-agent \
        --all-containers=true --prefix=true --since=30s --tail=-1
}

wait_for_controller_policy_counts() {
    local accepted=$1
    local rejected=$2
    local floor_revision=$3
    local status actual_accepted actual_rejected revision
    for _ in {1..30}; do
        status=$("${unfctl}" \
            --controller-url "http://127.0.0.1:${controller_port}" --output json status)
        actual_accepted=$(sed -nE 's/.*"network_policies": ([0-9]+).*/\1/p' <<<"${status}")
        actual_rejected=$(sed -nE 's/.*"rejected_network_policies": ([0-9]+).*/\1/p' \
            <<<"${status}")
        revision=$(sed -nE 's/.*"policy": ([0-9]+).*/\1/p' <<<"${status}")
        if [[ ${actual_accepted} == "${accepted}" && ${actual_rejected} == "${rejected}" \
            && -n ${revision} && ${revision} -gt ${floor_revision} ]]; then
            controller_state_revision=${revision}
            return 0
        fi
        sleep 1
    done
    return 1
}

wait_for_topology_transition() {
    local floor_revision=$1
    local snapshot revision
    for _ in {1..30}; do
        snapshot=$("${unfctl}" \
            --controller-url "http://127.0.0.1:${controller_port}" --output json topology)
        revision=$(sed -nE 's/.*"revision": ([0-9]+).*/\1/p' <<<"${snapshot}")
        if [[ -n ${revision} && ${revision} -gt ${floor_revision} ]]; then
            topology_state_revision=${revision}
            return 0
        fi
        sleep 1
    done
    return 1
}

wait_for_topology_probe_backend() {
    local floor_revision=$1
    local expected_ready=$2
    local snapshot compact revision
    for _ in {1..30}; do
        snapshot=$("${unfctl}" \
            --controller-url "http://127.0.0.1:${controller_port}" --output json topology)
        compact=$(tr -d '\n' <<<"${snapshot}")
        revision=$(sed -nE 's/.*"revision": ([0-9]+).*/\1/p' <<<"${snapshot}")
        if [[ -n ${revision} && ${revision} -gt ${floor_revision} ]] \
            && grep -q '"reference": "frontend/topology-probe"' <<<"${compact}" \
            && grep -q "\"endpoint_slice\": \"frontend/topology-probe-manual\".*\"ready\": ${expected_ready}.*\"target_workload\": \"frontend/client\"" \
                <<<"${compact}"; then
            topology_state_revision=${revision}
            topology_probe_snapshot=${snapshot}
            return 0
        fi
        sleep 1
    done
    return 1
}

wait_for_topology_probe_backend_removal() {
    local floor_revision=$1
    local snapshot compact revision
    for _ in {1..30}; do
        snapshot=$("${unfctl}" \
            --controller-url "http://127.0.0.1:${controller_port}" --output json topology)
        compact=$(tr -d '\n' <<<"${snapshot}")
        revision=$(sed -nE 's/.*"revision": ([0-9]+).*/\1/p' <<<"${snapshot}")
        if [[ -n ${revision} && ${revision} -gt ${floor_revision} ]] \
            && grep -q '"reference": "frontend/topology-probe"' <<<"${compact}" \
            && ! grep -q '"endpoint_slice": "frontend/topology-probe-manual"' \
                <<<"${compact}"; then
            topology_state_revision=${revision}
            return 0
        fi
        sleep 1
    done
    return 1
}

wait_for_historical_demo_flow() {
    local snapshot
    for _ in {1..30}; do
        snapshot=$("${unfctl}" \
            --controller-url "http://127.0.0.1:${controller_port}" --output json flows)
        if grep -q '"source_workloads": \[' <<<"${snapshot}" \
            && grep -q '"frontend/client"' <<<"${snapshot}" \
            && grep -q '"backend/server"' <<<"${snapshot}" \
            && grep -q '"destination_port": 8080' <<<"${snapshot}"; then
            flow_history=${snapshot}
            return 0
        fi
        "${kc[@]}" exec -n frontend client -- \
            wget -T 2 -t 1 -qO- http://server.backend.svc.cluster.local:8080 >/dev/null
        sleep 1
    done
    return 1
}

wait_for_historical_ipv6_demo_flow() {
    local snapshot compact
    for _ in {1..30}; do
        snapshot=$("${unfctl}" \
            --controller-url "http://127.0.0.1:${controller_port}" --output json flows)
        compact=$(tr -d '\n' <<<"${snapshot}")
        if grep -q '"source_ipv6": "' <<<"${compact}" \
            && grep -q '"destination_ipv6": "' <<<"${compact}" \
            && grep -q '"destination_port": 8080' <<<"${compact}" \
            && grep -q '"frontend/client"' <<<"${compact}" \
            && grep -q '"backend/server"' <<<"${compact}"; then
            ipv6_flow_history=${snapshot}
            return 0
        fi
        "${kc[@]}" exec -n frontend client -- \
            wget -T 2 -t 1 -qO- "http://[${server_ipv6}]:8080" >/dev/null
        sleep 1
    done
    return 1
}

pod_ipv4() {
    "${kc[@]}" get pod -n "$1" "$2" \
        -o jsonpath='{range .status.podIPs[*]}{.ip}{"\n"}{end}' \
        | awk 'index($0, ".") > 0 && index($0, ":") == 0 { print; exit }'
}

pod_ipv6() {
    "${kc[@]}" get pod -n "$1" "$2" \
        -o jsonpath='{range .status.podIPs[*]}{.ip}{"\n"}{end}' \
        | awk 'index($0, ":") > 0 { print; exit }'
}

"${kc[@]}" wait --for=condition=Ready nodes --all --timeout=120s
"${kc[@]}" -n kube-system rollout status daemonset/kindnet --timeout=120s
"${kc[@]}" -n unf-system rollout status deployment/unf-controller --timeout=120s
"${kc[@]}" -n unf-system rollout status daemonset/unf-agent --timeout=120s

mapfile -t agent_pods < <("${kc[@]}" -n unf-system get pods \
    -l app.kubernetes.io/name=unf-agent -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}')
if [[ ${#agent_pods[@]} -eq 0 ]]; then
    echo "UNF agent DaemonSet has no pods" >&2
    exit 1
fi

"${kc[@]}" -n unf-system port-forward service/unf-controller \
    "${controller_port}:9962" >"${temporary_dir}/controller-forward.log" 2>&1 &
controller_forward_pid=$!
for _ in {1..20}; do
    if curl --fail --silent "http://127.0.0.1:${controller_port}/readyz" >/dev/null; then
        break
    fi
    sleep 1
done
curl --fail --silent "http://127.0.0.1:${controller_port}/readyz" >/dev/null

controller_status=$("${unfctl}" \
    --controller-url "http://127.0.0.1:${controller_port}" --output json status)
grep -Eq '"identities": [1-9][0-9]*' <<<"${controller_status}"
grep -Eq '"indexed_pod_ips": [1-9][0-9]*' <<<"${controller_status}"
grep -Eq '"resolved_policy_entries": [1-9][0-9]*' <<<"${controller_status}"
grep -Eq '"network_policies": [1-9][0-9]*' <<<"${controller_status}"
grep -Eq '"endpoint_slices": [1-9][0-9]*' <<<"${controller_status}"
grep -q '"rejected_network_policies": 0' <<<"${controller_status}"

allow_explanation=$("${unfctl}" \
    --controller-url "http://127.0.0.1:${controller_port}" --output json \
    explain --from frontend/client --to backend/server --protocol tcp --port 8080)
grep -q '"reason": "ExplicitRule"' <<<"${allow_explanation}"
grep -q '"verdict": "Allow"' <<<"${allow_explanation}"
grep -q '"dataplane_enforcement": true' <<<"${allow_explanation}"

deny_explanation=$("${unfctl}" \
    --controller-url "http://127.0.0.1:${controller_port}" --output json \
    explain --from frontend/client --to backend/server --protocol tcp --port 9090)
grep -q '"reason": "ExplicitRule"' <<<"${deny_explanation}"
grep -q '"verdict": "Deny"' <<<"${deny_explanation}"
grep -Eq '"policy_id": [1-9][0-9]*' <<<"${deny_explanation}"
grep -Eq '"rule_id": [1-9][0-9]*' <<<"${deny_explanation}"

network_policy_allow_explanation=$("${unfctl}" \
    --controller-url "http://127.0.0.1:${controller_port}" --output json \
    explain --from frontend/client --to backend/np-server --protocol tcp --port 8081)
grep -q '"reason": "ExplicitRule"' <<<"${network_policy_allow_explanation}"
grep -q '"verdict": "Allow"' <<<"${network_policy_allow_explanation}"
grep -Eq '"policy_id": [1-9][0-9]*' <<<"${network_policy_allow_explanation}"

network_policy_deny_explanation=$("${unfctl}" \
    --controller-url "http://127.0.0.1:${controller_port}" --output json \
    explain --from frontend/client --to backend/np-server --protocol tcp --port 9091)
grep -q '"reason": "DefaultAction"' <<<"${network_policy_deny_explanation}"
grep -q '"verdict": "Deny"' <<<"${network_policy_deny_explanation}"
grep -Eq '"policy_id": [1-9][0-9]*' <<<"${network_policy_deny_explanation}"

for port in 8082 8083; do
    range_explanation=$("${unfctl}" \
        --controller-url "http://127.0.0.1:${controller_port}" --output json \
        explain --from frontend/client --to backend/np-server --protocol tcp --port "${port}")
    grep -q '"reason": "ExplicitRule"' <<<"${range_explanation}"
    grep -q '"verdict": "Allow"' <<<"${range_explanation}"
done
outside_range_explanation=$("${unfctl}" \
    --controller-url "http://127.0.0.1:${controller_port}" --output json \
    explain --from frontend/client --to backend/np-server --protocol tcp --port 8084)
grep -q '"reason": "DefaultAction"' <<<"${outside_range_explanation}"
grep -q '"verdict": "Deny"' <<<"${outside_range_explanation}"

declare -A policy_banks
initial_synced=false
for _ in {1..30}; do
    initial_synced=true
    expected_policy_revision=
    controller_status=$("${unfctl}" \
        --controller-url "http://127.0.0.1:${controller_port}" --output json status)
    controller_identity_epoch=$(sed -nE 's/.*"identity_epoch": ([0-9]+).*/\1/p' \
        <<<"${controller_status}")
    controller_identity_revision=$(sed -nE 's/.*"identity": ([0-9]+).*/\1/p' \
        <<<"${controller_status}")
    controller_policy_revision=$(sed -nE 's/.*"policy": ([0-9]+).*/\1/p' \
        <<<"${controller_status}")
    for pod in "${agent_pods[@]}"; do
        status=$(agent_status "${pod}" || true)
        desired_identity=$(json_number desired_identity_revision <<<"${status}")
        applied_identity=$(json_number applied_identity_revision <<<"${status}")
        desired_epoch=$(json_number desired_identity_epoch <<<"${status}")
        applied_epoch=$(json_number applied_identity_epoch <<<"${status}")
        identity_entries=$(json_number identity_map_entries <<<"${status}")
        ipv4_identity_entries=$(json_number ipv4_identity_map_entries <<<"${status}")
        ipv6_identity_entries=$(json_number ipv6_identity_map_entries <<<"${status}")
        desired_policy=$(json_number desired_policy_revision <<<"${status}")
        applied_policy=$(json_number applied_policy_revision <<<"${status}")
        desired_policy_epoch=$(json_number desired_policy_epoch <<<"${status}")
        applied_policy_epoch=$(json_number applied_policy_epoch <<<"${status}")
        policy_entries=$(json_number policy_map_entries <<<"${status}")
        if [[ -z ${desired_identity} || ${desired_identity} != "${applied_identity}" \
            || ${applied_identity} != "${controller_identity_revision}" \
            || -z ${desired_epoch} || ${desired_epoch} != "${applied_epoch}" \
            || ${applied_epoch} != "${controller_identity_epoch}" \
            || ${identity_entries:-0} -eq 0 \
            || ${ipv4_identity_entries:-0} -eq 0 \
            || ${ipv6_identity_entries:-0} -eq 0 \
            || -z ${desired_policy} || ${desired_policy} != "${applied_policy}" \
            || ${applied_policy} != "${controller_policy_revision}" \
            || -z ${desired_policy_epoch} || ${desired_policy_epoch} != "${applied_policy_epoch}" \
            || ${applied_policy_epoch} != "${controller_identity_epoch}" \
            || ${policy_entries:-0} -eq 0 ]] \
            || ! grep -q '"bpf_loaded":true' <<<"${status}"; then
            initial_synced=false
            break
        fi
        if [[ -n ${expected_policy_revision} && ${expected_policy_revision} != "${applied_policy}" ]]; then
            initial_synced=false
            break
        fi
        expected_policy_revision=${applied_policy}
        policy_banks[${pod}]=$(json_number active_policy_bank <<<"${status}")
    done
    if [[ ${initial_synced} == true ]]; then
        break
    fi
    sleep 1
done
if [[ ${initial_synced} != true ]]; then
    echo "UNF agents did not apply matching identity and policy revisions" >&2
    exit 1
fi
initial_policy_revision=${expected_policy_revision}

initial_topology=$("${unfctl}" \
    --controller-url "http://127.0.0.1:${controller_port}" --output json topology)
compact_initial_topology=$(tr -d '\n' <<<"${initial_topology}")
grep -q '"schema_version": 3' <<<"${initial_topology}"
grep -Eq '"revision": [1-9][0-9]*' <<<"${initial_topology}"
grep -Eq '"identity_revision": [1-9][0-9]*' <<<"${initial_topology}"
grep -q '"name": "unf-dev-control-plane"' <<<"${initial_topology}"
grep -q '"name": "unf-dev-worker"' <<<"${initial_topology}"
grep -q '"reference": "frontend/client"' <<<"${initial_topology}"
grep -q '"reference": "backend/server"' <<<"${initial_topology}"
grep -q '"reference": "backend/np-server"' <<<"${initial_topology}"
grep -q '"node_name": "unf-dev-control-plane"' <<<"${initial_topology}"
grep -q '"node_name": "unf-dev-worker"' <<<"${initial_topology}"
grep -Eq '"ipv6_addresses": \[[[:space:]]*"[^" ]*:[^" ]*"' \
    <<<"${compact_initial_topology}"
grep -q '"selected_workloads": \[' <<<"${initial_topology}"
initial_topology_revision=$(sed -nE 's/.*"revision": ([0-9]+).*/\1/p' \
    <<<"${initial_topology}")

"${kc[@]}" apply -f "${project_root}/deploy/examples/topology-probe.yaml" >/dev/null
topology_service_created=true
if ! wait_for_topology_probe_backend "${initial_topology_revision}" false; then
    echo "controller did not expose the not-ready EndpointSlice backend" >&2
    exit 1
fi
created_topology_revision=${topology_state_revision}
compact_topology_probe=$(tr -d '\n' <<<"${topology_probe_snapshot}")
grep -q '"selected_workloads": \[\]' <<<"${compact_topology_probe}"
grep -q '"serving": true' <<<"${compact_topology_probe}"
grep -q '"terminating": false' <<<"${compact_topology_probe}"
grep -q '"port": 8080' <<<"${compact_topology_probe}"

"${kc[@]}" patch endpointslice -n frontend topology-probe-manual --type=json \
    -p '[{"op":"replace","path":"/endpoints/0/conditions/ready","value":true}]' >/dev/null
if ! wait_for_topology_probe_backend "${created_topology_revision}" true; then
    echo "controller did not advance topology after EndpointSlice readiness changed" >&2
    exit 1
fi
ready_topology_revision=${topology_state_revision}

"${kc[@]}" delete endpointslice -n frontend topology-probe-manual >/dev/null
if ! wait_for_topology_probe_backend_removal "${ready_topology_revision}"; then
    echo "controller did not remove the deleted EndpointSlice backend" >&2
    exit 1
fi
backend_removed_topology_revision=${topology_state_revision}

"${kc[@]}" delete -f "${project_root}/deploy/examples/topology-probe.yaml" \
    --ignore-not-found >/dev/null
if ! wait_for_topology_transition "${backend_removed_topology_revision}"; then
    echo "controller did not advance topology after Service deletion" >&2
    exit 1
fi
restored_topology_revision=${topology_state_revision}
topology_service_created=false
restored_topology=$("${unfctl}" \
    --controller-url "http://127.0.0.1:${controller_port}" --output json topology)
if grep -q '"reference": "frontend/topology-probe"' <<<"${restored_topology}"; then
    echo "deleted Service remained in the topology snapshot" >&2
    exit 1
fi
policy_revision_after_topology=$("${unfctl}" \
    --controller-url "http://127.0.0.1:${controller_port}" --output json status \
    | sed -nE 's/.*"policy": ([0-9]+).*/\1/p')
if [[ ${policy_revision_after_topology} != "${initial_policy_revision}" ]]; then
    echo "Service-only topology changes unexpectedly changed the policy revision" >&2
    exit 1
fi

client_ipv6=$(pod_ipv6 frontend client)
server_ipv6=$(pod_ipv6 backend server)
network_policy_server_ipv6=$(pod_ipv6 backend np-server)
if [[ -z ${client_ipv6} || -z ${server_ipv6} || -z ${network_policy_server_ipv6} ]]; then
    echo "demo Pods do not all have IPv6 addresses" >&2
    exit 1
fi

if ! wait_for_historical_demo_flow; then
    echo "controller did not retain the exported frontend-to-backend flow" >&2
    exit 1
fi
grep -q '"schema_version": 2' <<<"${flow_history}"
grep -Eq '"revision": [1-9][0-9]*' <<<"${flow_history}"
grep -q '"capacity": 4096' <<<"${flow_history}"
grep -Eq '"retained_flows": [1-9][0-9]*' <<<"${flow_history}"
grep -Eq '"retained_observations": [1-9][0-9]*' <<<"${flow_history}"
grep -q '"unf-dev-worker"' <<<"${flow_history}"

if ! wait_for_historical_ipv6_demo_flow; then
    echo "controller did not retain the exported IPv6 frontend-to-backend flow" >&2
    exit 1
fi
grep -q "\"source_ipv6\": \"${client_ipv6}\"" <<<"${ipv6_flow_history}"
grep -q "\"destination_ipv6\": \"${server_ipv6}\"" <<<"${ipv6_flow_history}"

policy_simulation=$("${unfctl}" \
    --controller-url "http://127.0.0.1:${controller_port}" --output json \
    policy simulate "${project_root}/deploy/examples/simulation-deny.yaml")
grep -q '"schema_version": 2' <<<"${policy_simulation}"
grep -q '"operation": "replace"' <<<"${policy_simulation}"
grep -q '"flow_source": "current-topology representative matrix"' <<<"${policy_simulation}"
grep -Eq '"would_be_denied": [1-9][0-9]*' <<<"${policy_simulation}"
grep -Eq '"decision_changes": [1-9][0-9]*' <<<"${policy_simulation}"
grep -Eq '"flow_history_revision": [1-9][0-9]*' <<<"${policy_simulation}"
grep -Eq '"evaluated_observations": [1-9][0-9]*' <<<"${policy_simulation}"
grep -Eq '"would_be_denied_observations": [1-9][0-9]*' <<<"${policy_simulation}"
grep -q '"affected_services": \[' <<<"${policy_simulation}"
grep -q '"backend/server"' <<<"${policy_simulation}"
grep -q '"reference": "frontend/client"' <<<"${policy_simulation}"
grep -q '"reference": "backend/server"' <<<"${policy_simulation}"
grep -q '"destination_port": 8080' <<<"${policy_simulation}"
grep -q '"verdict": "Allow"' <<<"${policy_simulation}"
grep -q '"verdict": "Deny"' <<<"${policy_simulation}"
grep -q "\"policy_revision\": ${initial_policy_revision}" <<<"${policy_simulation}"
grep -q "\"topology_revision\": ${restored_topology_revision}" <<<"${policy_simulation}"
policy_revision_after_simulation=$("${unfctl}" \
    --controller-url "http://127.0.0.1:${controller_port}" --output json status \
    | sed -nE 's/.*"policy": ([0-9]+).*/\1/p')
if [[ ${policy_revision_after_simulation} != "${initial_policy_revision}" ]]; then
    echo "read-only policy simulation changed the live policy revision" >&2
    exit 1
fi

client_ip=$(pod_ipv4 frontend client)
if [[ ! ${client_ip} =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
    echo "frontend client does not have an IPv4 Pod address" >&2
    exit 1
fi
IFS=. read -r client_ip_a client_ip_b client_ip_c client_ip_d <<<"${client_ip}"
client_pair_cidr="${client_ip_a}.${client_ip_b}.${client_ip_c}.$((client_ip_d & 254))/31"

local_response=$("${kc[@]}" exec -n backend server -- wget -T 2 -t 1 -qO- http://127.0.0.1:9090)
if [[ ${local_response} != "unf-demo-ok" ]]; then
    echo "demo server is not listening on the deny-test port" >&2
    exit 1
fi
network_policy_local_response=$("${kc[@]}" exec -n backend np-server -- \
    wget -T 2 -t 1 -qO- http://127.0.0.1:9091)
if [[ ${network_policy_local_response} != "unf-networkpolicy-ok" ]]; then
    echo "NetworkPolicy demo server is not listening on the deny-test port" >&2
    exit 1
fi
network_policy_range_local_response=$("${kc[@]}" exec -n backend np-server -- \
    wget -T 2 -t 1 -qO- http://127.0.0.1:8084)
if [[ ${network_policy_range_local_response} != "unf-networkpolicy-ok" ]]; then
    echo "NetworkPolicy demo server is not listening outside the allowed port range" >&2
    exit 1
fi

allow_response=$("${kc[@]}" exec -n frontend client -- \
    wget -T 2 -t 1 -qO- http://server.backend.svc.cluster.local:8080)
if [[ ${allow_response} != "unf-demo-ok" ]]; then
    echo "unexpected allow response: ${allow_response}" >&2
    exit 1
fi
if "${kc[@]}" exec -n frontend client -- \
    wget -T 2 -t 1 -qO- http://server.backend.svc.cluster.local:9090 >/dev/null 2>&1; then
    echo "enforce mode did not drop the explicit deny flow" >&2
    exit 1
fi

ipv6_allow_response=$("${kc[@]}" exec -n frontend client -- \
    wget -T 2 -t 1 -qO- "http://[${server_ipv6}]:8080")
if [[ ${ipv6_allow_response} != "unf-demo-ok" ]]; then
    echo "native policy IPv6 allow flow failed" >&2
    exit 1
fi
if "${kc[@]}" exec -n frontend client -- \
    wget -T 2 -t 1 -qO- "http://[${server_ipv6}]:9090" >/dev/null 2>&1; then
    echo "native policy IPv6 explicit deny did not drop the open port" >&2
    exit 1
fi
ipv6_network_policy_allow_response=$("${kc[@]}" exec -n frontend client -- \
    wget -T 2 -t 1 -qO- "http://[${network_policy_server_ipv6}]:8081")
if [[ ${ipv6_network_policy_allow_response} != "unf-networkpolicy-ok" ]]; then
    echo "NetworkPolicy IPv6 selector allow flow failed" >&2
    exit 1
fi
if "${kc[@]}" exec -n frontend client -- \
    wget -T 2 -t 1 -qO- "http://[${network_policy_server_ipv6}]:9091" >/dev/null 2>&1; then
    echo "NetworkPolicy IPv6 default deny did not drop the open port" >&2
    exit 1
fi

"${kc[@]}" patch securitypolicy -n backend frontend-to-backend \
    --type=merge -p '{"spec":{"enforcementMode":"Shadow"}}' >/dev/null
policy_mutated=true
if ! wait_for_policy_transition "${initial_policy_revision}"; then
    echo "UNF agents did not atomically activate the shadow policy revision" >&2
    exit 1
fi
shadow_policy_revision=${transition_revision}

shadow_response=$("${kc[@]}" exec -n frontend client -- \
    wget -T 2 -t 1 -qO- http://server.backend.svc.cluster.local:9090)
if [[ ${shadow_response} != "unf-demo-ok" ]]; then
    echo "shadow mode changed forwarding behavior" >&2
    exit 1
fi

network_policy_allow_response=$("${kc[@]}" exec -n frontend client -- \
    wget -T 2 -t 1 -qO- http://np-server.backend.svc.cluster.local:8081)
if [[ ${network_policy_allow_response} != "unf-networkpolicy-ok" ]]; then
    echo "NetworkPolicy compatibility allow flow failed" >&2
    exit 1
fi
for port in 8082 8083; do
    range_response=$("${kc[@]}" exec -n frontend client -- \
        wget -T 2 -t 1 -qO- "http://np-server.backend.svc.cluster.local:${port}")
    if [[ ${range_response} != "unf-networkpolicy-ok" ]]; then
        echo "NetworkPolicy compatibility range flow ${port} failed" >&2
        exit 1
    fi
done
if "${kc[@]}" exec -n frontend client -- \
    wget -T 2 -t 1 -qO- http://np-server.backend.svc.cluster.local:8084 >/dev/null 2>&1; then
    echo "NetworkPolicy compatibility range allowed adjacent open port 8084" >&2
    exit 1
fi
if "${kc[@]}" exec -n frontend client -- \
    wget -T 2 -t 1 -qO- http://np-server.backend.svc.cluster.local:9091 >/dev/null 2>&1; then
    echo "NetworkPolicy compatibility default deny did not drop the open port" >&2
    exit 1
fi
sleep 1
shadow_line=$(all_agent_logs | grep '"destination_port":9090' \
    | grep '"shadow_verdict":2' | grep "\"policy_revision\":${shadow_policy_revision}" \
    | tail -n 1 || true)
if ! grep -q '"verdict":"Allow"' <<<"${shadow_line}" \
    || ! grep -Eq '"shadow_policy_id":[1-9][0-9]*' <<<"${shadow_line}" \
    || ! grep -Eq '"shadow_rule_id":[1-9][0-9]*' <<<"${shadow_line}"; then
    echo "UNF did not emit allow-plus-shadow-deny provenance" >&2
    exit 1
fi

"${kc[@]}" patch securitypolicy -n backend frontend-to-backend \
    --type=merge -p '{"spec":{"enforcementMode":"Enforce"}}' >/dev/null
if ! wait_for_policy_transition "${shadow_policy_revision}"; then
    echo "UNF agents did not atomically restore enforce mode" >&2
    exit 1
fi
enforced_policy_revision=${transition_revision}
policy_mutated=false

allow_response=$("${kc[@]}" exec -n frontend client -- \
    wget -T 2 -t 1 -qO- http://server.backend.svc.cluster.local:8080)
if [[ ${allow_response} != "unf-demo-ok" ]]; then
    echo "allow flow failed after restoring enforce mode" >&2
    exit 1
fi
if "${kc[@]}" exec -n frontend client -- \
    wget -T 2 -t 1 -qO- http://server.backend.svc.cluster.local:9090 >/dev/null 2>&1; then
    echo "restored enforce mode did not drop the explicit deny flow" >&2
    exit 1
fi
network_policy_allow_response=$("${kc[@]}" exec -n frontend client -- \
    wget -T 2 -t 1 -qO- http://np-server.backend.svc.cluster.local:8081)
if [[ ${network_policy_allow_response} != "unf-networkpolicy-ok" ]]; then
    echo "NetworkPolicy compatibility allow failed after policy reconvergence" >&2
    exit 1
fi
ipv6_allow_response=$("${kc[@]}" exec -n frontend client -- \
    wget -T 2 -t 1 -qO- "http://[${server_ipv6}]:8080")
if [[ ${ipv6_allow_response} != "unf-demo-ok" ]]; then
    echo "IPv6 allow flow failed after restoring enforce mode" >&2
    exit 1
fi
if "${kc[@]}" exec -n frontend client -- \
    wget -T 2 -t 1 -qO- "http://[${server_ipv6}]:9090" >/dev/null 2>&1; then
    echo "restored enforce mode did not drop the IPv6 explicit deny flow" >&2
    exit 1
fi
ipv6_network_policy_allow_response=$("${kc[@]}" exec -n frontend client -- \
    wget -T 2 -t 1 -qO- "http://[${network_policy_server_ipv6}]:8081")
if [[ ${ipv6_network_policy_allow_response} != "unf-networkpolicy-ok" ]]; then
    echo "NetworkPolicy IPv6 allow failed after policy reconvergence" >&2
    exit 1
fi
if "${kc[@]}" exec -n frontend client -- \
    wget -T 2 -t 1 -qO- "http://[${network_policy_server_ipv6}]:9091" >/dev/null 2>&1; then
    echo "NetworkPolicy IPv6 deny failed after policy reconvergence" >&2
    exit 1
fi
for port in 8082 8083; do
    range_response=$("${kc[@]}" exec -n frontend client -- \
        wget -T 2 -t 1 -qO- "http://np-server.backend.svc.cluster.local:${port}")
    if [[ ${range_response} != "unf-networkpolicy-ok" ]]; then
        echo "NetworkPolicy range flow ${port} failed after policy reconvergence" >&2
        exit 1
    fi
done
if "${kc[@]}" exec -n frontend client -- \
    wget -T 2 -t 1 -qO- http://np-server.backend.svc.cluster.local:8084 >/dev/null 2>&1; then
    echo "NetworkPolicy range allowed adjacent port after policy reconvergence" >&2
    exit 1
fi
if "${kc[@]}" exec -n frontend client -- \
    wget -T 2 -t 1 -qO- http://np-server.backend.svc.cluster.local:9091 >/dev/null 2>&1; then
    echo "NetworkPolicy compatibility deny failed after policy reconvergence" >&2
    exit 1
fi
sleep 1

flow_logs=$(all_agent_logs)
allow_line=$(grep '"destination_port":8080' <<<"${flow_logs}" \
    | grep '"verdict":"Allow"' | grep "\"policy_revision\":${enforced_policy_revision}" \
    | tail -n 1 || true)
deny_line=$(grep '"destination_port":9090' <<<"${flow_logs}" \
    | grep '"verdict":"Deny"' | grep '"reason":2' \
    | grep "\"policy_revision\":${enforced_policy_revision}" | tail -n 1 || true)
network_policy_allow_line=$(grep '"destination_port":8081' <<<"${flow_logs}" \
    | grep '"verdict":"Allow"' | grep '"reason":1' \
    | grep "\"policy_revision\":${enforced_policy_revision}" | tail -n 1 || true)
network_policy_deny_line=$(grep '"destination_port":9091' <<<"${flow_logs}" \
    | grep '"verdict":"Deny"' | grep '"reason":3' \
    | grep "\"policy_revision\":${enforced_policy_revision}" | tail -n 1 || true)
network_policy_range_line=$(grep '"destination_port":8083' <<<"${flow_logs}" \
    | grep '"verdict":"Allow"' | grep '"reason":1' \
    | grep "\"policy_revision\":${enforced_policy_revision}" | tail -n 1 || true)
ipv6_allow_line=$(grep '"destination_port":8080' <<<"${flow_logs}" \
    | grep '"address_family":6' | grep '"verdict":"Allow"' \
    | grep "\"policy_revision\":${enforced_policy_revision}" | tail -n 1 || true)
ipv6_deny_line=$(grep '"destination_port":9090' <<<"${flow_logs}" \
    | grep '"address_family":6' | grep '"verdict":"Deny"' | grep '"reason":2' \
    | grep "\"policy_revision\":${enforced_policy_revision}" | tail -n 1 || true)
ipv6_network_policy_allow_line=$(grep '"destination_port":8081' <<<"${flow_logs}" \
    | grep '"address_family":6' | grep '"verdict":"Allow"' | grep '"reason":1' \
    | grep "\"policy_revision\":${enforced_policy_revision}" | tail -n 1 || true)
ipv6_network_policy_deny_line=$(grep '"destination_port":9091' <<<"${flow_logs}" \
    | grep '"address_family":6' | grep '"verdict":"Deny"' | grep '"reason":3' \
    | grep "\"policy_revision\":${enforced_policy_revision}" | tail -n 1 || true)
if ! grep -Eq '"source_identity":[1-9][0-9]*' <<<"${allow_line}" \
    || ! grep -Eq '"destination_identity":[1-9][0-9]*' <<<"${allow_line}" \
    || ! grep -Eq '"policy_id":[1-9][0-9]*' <<<"${allow_line}"; then
    echo "UNF did not emit revisioned allow provenance" >&2
    exit 1
fi
if ! grep -Eq '"source_identity":[1-9][0-9]*' <<<"${deny_line}" \
    || ! grep -Eq '"destination_identity":[1-9][0-9]*' <<<"${deny_line}" \
    || ! grep -Eq '"policy_id":[1-9][0-9]*' <<<"${deny_line}" \
    || ! grep -Eq '"rule_id":[1-9][0-9]*' <<<"${deny_line}"; then
    echo "UNF did not emit revisioned explicit-deny provenance" >&2
    exit 1
fi
if ! grep -Eq '"source_identity":[1-9][0-9]*' <<<"${network_policy_allow_line}" \
    || ! grep -Eq '"destination_identity":[1-9][0-9]*' <<<"${network_policy_allow_line}" \
    || ! grep -Eq '"policy_id":[1-9][0-9]*' <<<"${network_policy_allow_line}"; then
    echo "UNF did not emit NetworkPolicy allow provenance" >&2
    exit 1
fi
if ! grep -Eq '"source_identity":[1-9][0-9]*' <<<"${network_policy_deny_line}" \
    || ! grep -Eq '"destination_identity":[1-9][0-9]*' <<<"${network_policy_deny_line}" \
    || ! grep -Eq '"policy_id":[1-9][0-9]*' <<<"${network_policy_deny_line}"; then
    echo "UNF did not emit NetworkPolicy default-deny provenance" >&2
    exit 1
fi
if ! grep -Eq '"source_identity":[1-9][0-9]*' <<<"${network_policy_range_line}" \
    || ! grep -Eq '"destination_identity":[1-9][0-9]*' <<<"${network_policy_range_line}" \
    || ! grep -Eq '"policy_id":[1-9][0-9]*' <<<"${network_policy_range_line}"; then
    echo "UNF did not emit NetworkPolicy port-range allow provenance" >&2
    exit 1
fi
if ! grep -Eq '"source_identity":[1-9][0-9]*' <<<"${ipv6_allow_line}" \
    || ! grep -Eq '"destination_identity":[1-9][0-9]*' <<<"${ipv6_allow_line}" \
    || ! grep -Eq '"policy_id":[1-9][0-9]*' <<<"${ipv6_allow_line}"; then
    echo "UNF did not emit revisioned IPv6 allow provenance" >&2
    exit 1
fi
if ! grep -Eq '"source_identity":[1-9][0-9]*' <<<"${ipv6_deny_line}" \
    || ! grep -Eq '"destination_identity":[1-9][0-9]*' <<<"${ipv6_deny_line}" \
    || ! grep -Eq '"policy_id":[1-9][0-9]*' <<<"${ipv6_deny_line}" \
    || ! grep -Eq '"rule_id":[1-9][0-9]*' <<<"${ipv6_deny_line}"; then
    echo "UNF did not emit revisioned IPv6 explicit-deny provenance" >&2
    exit 1
fi
if ! grep -Eq '"source_identity":[1-9][0-9]*' <<<"${ipv6_network_policy_allow_line}" \
    || ! grep -Eq '"destination_identity":[1-9][0-9]*' \
        <<<"${ipv6_network_policy_allow_line}" \
    || ! grep -Eq '"policy_id":[1-9][0-9]*' <<<"${ipv6_network_policy_allow_line}"; then
    echo "UNF did not emit NetworkPolicy IPv6 allow provenance" >&2
    exit 1
fi
if ! grep -Eq '"source_identity":[1-9][0-9]*' <<<"${ipv6_network_policy_deny_line}" \
    || ! grep -Eq '"destination_identity":[1-9][0-9]*' \
        <<<"${ipv6_network_policy_deny_line}" \
    || ! grep -Eq '"policy_id":[1-9][0-9]*' <<<"${ipv6_network_policy_deny_line}"; then
    echo "UNF did not emit NetworkPolicy IPv6 default-deny provenance" >&2
    exit 1
fi

"${kc[@]}" patch networkpolicy -n backend frontend-to-np-server --type=json \
    -p '[{"op":"add","path":"/spec/ingress/0/ports/-","value":{"protocol":"TCP"}}]' \
    >/dev/null
network_policy_protocol_mutated=true
if ! wait_for_controller_policy_counts 1 0 "${enforced_policy_revision}"; then
    echo "controller did not compile the protocol-only NetworkPolicy port" >&2
    exit 1
fi
protocol_wildcard_revision=${controller_state_revision}
if ! wait_for_policy_transition "${enforced_policy_revision}"; then
    echo "agents did not activate the protocol-only NetworkPolicy port" >&2
    exit 1
fi
protocol_wildcard_tcp_explanation=$("${unfctl}" \
    --controller-url "http://127.0.0.1:${controller_port}" --output json \
    explain --from frontend/client --to backend/np-server --protocol tcp --port 9091)
grep -q '"reason": "ExplicitRule"' <<<"${protocol_wildcard_tcp_explanation}"
grep -q '"verdict": "Allow"' <<<"${protocol_wildcard_tcp_explanation}"
protocol_wildcard_udp_explanation=$("${unfctl}" \
    --controller-url "http://127.0.0.1:${controller_port}" --output json \
    explain --from frontend/client --to backend/np-server --protocol udp --port 9091)
grep -q '"reason": "DefaultAction"' <<<"${protocol_wildcard_udp_explanation}"
grep -q '"verdict": "Deny"' <<<"${protocol_wildcard_udp_explanation}"
protocol_wildcard_response=$("${kc[@]}" exec -n frontend client -- \
    wget -T 2 -t 1 -qO- http://np-server.backend.svc.cluster.local:9091)
if [[ ${protocol_wildcard_response} != "unf-networkpolicy-ok" ]]; then
    echo "protocol-only TCP NetworkPolicy port did not allow an arbitrary TCP port" >&2
    exit 1
fi
sleep 1
protocol_wildcard_line=$(all_agent_logs | grep '"destination_port":9091' \
    | grep '"verdict":"Allow"' | grep '"reason":1' \
    | grep "\"policy_revision\":${protocol_wildcard_revision}" | tail -n 1 || true)
if ! grep -Eq '"source_identity":[1-9][0-9]*' <<<"${protocol_wildcard_line}" \
    || ! grep -Eq '"destination_identity":[1-9][0-9]*' <<<"${protocol_wildcard_line}" \
    || ! grep -Eq '"policy_id":[1-9][0-9]*' <<<"${protocol_wildcard_line}"; then
    echo "UNF did not emit protocol-only NetworkPolicy allow provenance" >&2
    exit 1
fi

"${kc[@]}" patch networkpolicy -n backend frontend-to-np-server --type=json \
    -p '[{"op":"remove","path":"/spec/ingress/0/ports/2"}]' >/dev/null
if ! wait_for_controller_policy_counts 1 0 "${protocol_wildcard_revision}"; then
    echo "controller did not restore the exact-port NetworkPolicy" >&2
    exit 1
fi
restored_protocol_policy_revision=${controller_state_revision}
if ! wait_for_policy_transition "${protocol_wildcard_revision}"; then
    echo "agents did not remove the protocol-only NetworkPolicy wildcard" >&2
    exit 1
fi
network_policy_protocol_mutated=false
if "${kc[@]}" exec -n frontend client -- \
    wget -T 2 -t 1 -qO- http://np-server.backend.svc.cluster.local:9091 >/dev/null 2>&1; then
    echo "removing the protocol-only NetworkPolicy port did not restore default deny" >&2
    exit 1
fi

namespace_identity_revision=$("${unfctl}" \
    --controller-url "http://127.0.0.1:${controller_port}" --output json status \
    | sed -nE 's/.*"identity": ([0-9]+).*/\1/p')
"${kc[@]}" label namespace frontend environment=staging --overwrite >/dev/null
namespace_mutated=true
if ! wait_for_controller_policy_counts 1 0 "${restored_protocol_policy_revision}"; then
    echo "controller did not revise policy state after the Namespace label change" >&2
    exit 1
fi
namespace_denied_revision=${controller_state_revision}
if ! wait_for_policy_transition "${restored_protocol_policy_revision}"; then
    echo "agents did not activate the Namespace label change" >&2
    exit 1
fi
if "${kc[@]}" exec -n frontend client -- \
    wget -T 2 -t 1 -qO- http://np-server.backend.svc.cluster.local:8081 >/dev/null 2>&1; then
    echo "namespace selector continued allowing a non-matching Namespace" >&2
    exit 1
fi

"${kc[@]}" label namespace frontend environment=production --overwrite >/dev/null
if ! wait_for_controller_policy_counts 1 0 "${namespace_denied_revision}"; then
    echo "controller did not revise policy state after the Namespace label restore" >&2
    exit 1
fi
restored_namespace_policy_revision=${controller_state_revision}
if ! wait_for_policy_transition "${namespace_denied_revision}"; then
    echo "agents did not activate the restored Namespace selector match" >&2
    exit 1
fi
namespace_mutated=false
namespace_identity_after=$("${unfctl}" \
    --controller-url "http://127.0.0.1:${controller_port}" --output json status \
    | sed -nE 's/.*"identity": ([0-9]+).*/\1/p')
if [[ ${namespace_identity_after} != "${namespace_identity_revision}" ]]; then
    echo "Namespace label changes unexpectedly changed identity revision" >&2
    exit 1
fi
network_policy_allow_response=$("${kc[@]}" exec -n frontend client -- \
    wget -T 2 -t 1 -qO- http://np-server.backend.svc.cluster.local:8081)
if [[ ${network_policy_allow_response} != "unf-networkpolicy-ok" ]]; then
    echo "restored Namespace selector did not restore the allow flow" >&2
    exit 1
fi

"${kc[@]}" patch networkpolicy -n backend frontend-to-np-server --type=json \
    -p '[{"op":"replace","path":"/spec/ingress/0/ports/1/endPort","value":65535}]' \
    >/dev/null
network_policy_mutated=true
if ! wait_for_controller_policy_counts 0 1 "${restored_namespace_policy_revision}"; then
    echo "controller did not report the oversized NetworkPolicy range update" >&2
    exit 1
fi
rejected_policy_revision=${controller_state_revision}
if ! wait_for_policy_transition "${restored_namespace_policy_revision}"; then
    echo "agents did not remove the rejected NetworkPolicy revision" >&2
    exit 1
fi

"${kc[@]}" patch networkpolicy -n backend frontend-to-np-server --type=json \
    -p '[{"op":"replace","path":"/spec/ingress/0/ports/1/endPort","value":8083}]' \
    >/dev/null
if ! wait_for_controller_policy_counts 1 0 "${rejected_policy_revision}"; then
    echo "controller did not readmit the restored NetworkPolicy" >&2
    exit 1
fi
restored_policy_revision=${controller_state_revision}
if ! wait_for_policy_transition "${rejected_policy_revision}"; then
    echo "agents did not activate the restored NetworkPolicy" >&2
    exit 1
fi
network_policy_mutated=false

"${kc[@]}" patch networkpolicy -n backend frontend-to-np-server --type=json \
    -p "[{\"op\":\"replace\",\"path\":\"/spec/ingress/0/from\",\"value\":[{\"ipBlock\":{\"cidr\":\"${client_ip}/32\"}}]}]" \
    >/dev/null
network_policy_peer_mutated=true
if ! wait_for_controller_policy_counts 1 0 "${restored_policy_revision}"; then
    echo "controller did not compile the bounded NetworkPolicy ipBlock" >&2
    exit 1
fi
ipblock_allow_revision=${controller_state_revision}
if ! wait_for_policy_transition "${restored_policy_revision}"; then
    echo "agents did not atomically activate the bounded NetworkPolicy ipBlock" >&2
    exit 1
fi
ipblock_allow_explanation=$("${unfctl}" \
    --controller-url "http://127.0.0.1:${controller_port}" --output json \
    explain --from frontend/client --to backend/np-server --protocol tcp --port 8081)
grep -q '"reason": "ExplicitRule"' <<<"${ipblock_allow_explanation}"
grep -q '"verdict": "Allow"' <<<"${ipblock_allow_explanation}"
ipblock_allow_response=$("${kc[@]}" exec -n frontend client -- \
    wget -T 2 -t 1 -qO- http://np-server.backend.svc.cluster.local:8081)
if [[ ${ipblock_allow_response} != "unf-networkpolicy-ok" ]]; then
    echo "bounded NetworkPolicy ipBlock did not allow its exact source" >&2
    exit 1
fi
sleep 1
ipblock_allow_line=$(all_agent_logs | grep '"destination_port":8081' \
    | grep '"verdict":"Allow"' | grep '"reason":1' \
    | grep "\"policy_revision\":${ipblock_allow_revision}" | tail -n 1 || true)
if ! grep -Eq '"source_identity":[1-9][0-9]*' <<<"${ipblock_allow_line}" \
    || ! grep -Eq '"destination_identity":[1-9][0-9]*' <<<"${ipblock_allow_line}" \
    || ! grep -Eq '"policy_id":[1-9][0-9]*' <<<"${ipblock_allow_line}"; then
    echo "UNF did not emit revisioned ipBlock allow provenance" >&2
    exit 1
fi

"${kc[@]}" patch networkpolicy -n backend frontend-to-np-server --type=json \
    -p "[{\"op\":\"replace\",\"path\":\"/spec/ingress/0/from/0/ipBlock\",\"value\":{\"cidr\":\"${client_pair_cidr}\",\"except\":[\"${client_ip}/32\"]}}]" \
    >/dev/null
if ! wait_for_controller_policy_counts 1 0 "${ipblock_allow_revision}"; then
    echo "controller did not compile the NetworkPolicy ipBlock exception" >&2
    exit 1
fi
ipblock_except_revision=${controller_state_revision}
if ! wait_for_policy_transition "${ipblock_allow_revision}"; then
    echo "agents did not atomically activate the NetworkPolicy ipBlock exception" >&2
    exit 1
fi
ipblock_deny_explanation=$("${unfctl}" \
    --controller-url "http://127.0.0.1:${controller_port}" --output json \
    explain --from frontend/client --to backend/np-server --protocol tcp --port 8081)
grep -q '"reason": "DefaultAction"' <<<"${ipblock_deny_explanation}"
grep -q '"verdict": "Deny"' <<<"${ipblock_deny_explanation}"
if "${kc[@]}" exec -n frontend client -- \
    wget -T 2 -t 1 -qO- http://np-server.backend.svc.cluster.local:8081 >/dev/null 2>&1; then
    echo "NetworkPolicy ipBlock exception did not exclude its exact source" >&2
    exit 1
fi

"${kc[@]}" patch networkpolicy -n backend frontend-to-np-server --type=json \
    -p "[{\"op\":\"replace\",\"path\":\"/spec/ingress/0/from/0/ipBlock\",\"value\":{\"cidr\":\"${client_pair_cidr}\"}}]" \
    >/dev/null
if ! wait_for_controller_policy_counts 1 0 "${ipblock_except_revision}"; then
    echo "controller did not restore the bounded NetworkPolicy ipBlock" >&2
    exit 1
fi
ipblock_restored_revision=${controller_state_revision}
if ! wait_for_policy_transition "${ipblock_except_revision}"; then
    echo "agents did not restore the bounded NetworkPolicy ipBlock allow" >&2
    exit 1
fi
ipblock_restored_response=$("${kc[@]}" exec -n frontend client -- \
    wget -T 2 -t 1 -qO- http://np-server.backend.svc.cluster.local:8081)
if [[ ${ipblock_restored_response} != "unf-networkpolicy-ok" ]]; then
    echo "removing the ipBlock exception did not restore its allow" >&2
    exit 1
fi

"${kc[@]}" patch networkpolicy -n backend frontend-to-np-server --type=json \
    -p '[{"op":"replace","path":"/spec/ingress/0/from/0/ipBlock","value":{"cidr":"10.0.0.0/21"}}]' \
    >/dev/null
if ! wait_for_controller_policy_counts 0 1 "${ipblock_restored_revision}"; then
    echo "controller did not reject the oversized NetworkPolicy ipBlock" >&2
    exit 1
fi
rejected_ipblock_revision=${controller_state_revision}
if ! wait_for_policy_transition "${ipblock_restored_revision}"; then
    echo "agents did not remove the rejected NetworkPolicy ipBlock revision" >&2
    exit 1
fi

"${kc[@]}" patch networkpolicy -n backend frontend-to-np-server --type=json \
    -p "[{\"op\":\"replace\",\"path\":\"/spec/ingress/0/from\",\"value\":${network_policy_selector_peer}}]" \
    >/dev/null
if ! wait_for_controller_policy_counts 1 0 "${rejected_ipblock_revision}"; then
    echo "controller did not readmit the restored NetworkPolicy selector peer" >&2
    exit 1
fi
restored_ipblock_policy_revision=${controller_state_revision}
if ! wait_for_policy_transition "${rejected_ipblock_revision}"; then
    echo "agents did not activate the restored NetworkPolicy selector peer" >&2
    exit 1
fi
network_policy_peer_mutated=false

"${kc[@]}" delete networkpolicy -n backend frontend-to-np-server >/dev/null
network_policy_deleted=true
if ! wait_for_controller_policy_counts 0 0 "${restored_ipblock_policy_revision}"; then
    echo "controller did not remove the deleted NetworkPolicy" >&2
    exit 1
fi
deleted_policy_revision=${controller_state_revision}
if ! wait_for_policy_transition "${restored_ipblock_policy_revision}"; then
    echo "agents did not activate NetworkPolicy deletion" >&2
    exit 1
fi
deleted_response=$("${kc[@]}" exec -n frontend client -- \
    wget -T 2 -t 1 -qO- http://np-server.backend.svc.cluster.local:9091)
if [[ ${deleted_response} != "unf-networkpolicy-ok" ]]; then
    echo "NetworkPolicy deletion did not restore forwarding" >&2
    exit 1
fi

"${kc[@]}" apply -f "${project_root}/deploy/examples/demo.yaml" >/dev/null
if ! wait_for_controller_policy_counts 1 0 "${deleted_policy_revision}"; then
    echo "controller did not reconcile the recreated NetworkPolicy" >&2
    exit 1
fi
if ! wait_for_policy_transition "${deleted_policy_revision}"; then
    echo "agents did not activate the recreated NetworkPolicy" >&2
    exit 1
fi
recreated_policy_revision=${transition_revision}
network_policy_deleted=false
if "${kc[@]}" exec -n frontend client -- \
    wget -T 2 -t 1 -qO- http://np-server.backend.svc.cluster.local:9091 >/dev/null 2>&1; then
    echo "recreated NetworkPolicy did not restore default-deny enforcement" >&2
    exit 1
fi

"${kc[@]}" apply -f \
    "${project_root}/deploy/examples/networkpolicy-conformance.yaml" >/dev/null
network_policy_conformance_created=true
"${kc[@]}" wait --for=condition=Ready pod/conformance-server -n backend --timeout=120s
conformance_endpoint_observed=false
for _ in {1..30}; do
    if "${unfctl}" --controller-url "http://127.0.0.1:${controller_port}" \
        --output json explain --from frontend/client --to backend/conformance-server \
        --protocol tcp --port 8085 >/dev/null 2>&1; then
        conformance_endpoint_observed=true
        break
    fi
    sleep 1
done
if [[ ${conformance_endpoint_observed} != true ]]; then
    echo "controller did not observe the NetworkPolicy conformance endpoint" >&2
    exit 1
fi
if ! wait_for_controller_policy_counts 2 0 "${recreated_policy_revision}"; then
    echo "controller did not accept the omitted-podSelector NetworkPolicy" >&2
    exit 1
fi
if ! wait_for_policy_batch_convergence "${recreated_policy_revision}"; then
    echo "agents did not activate namespace-wide default target isolation" >&2
    exit 1
fi
conformance_policy_revision=${transition_revision}
conformance_allow=$("${unfctl}" \
    --controller-url "http://127.0.0.1:${controller_port}" --output json \
    explain --from frontend/client --to backend/conformance-server \
    --protocol tcp --port 8085)
grep -q '"reason": "ExplicitRule"' <<<"${conformance_allow}"
grep -q '"verdict": "Allow"' <<<"${conformance_allow}"
conformance_deny=$("${unfctl}" \
    --controller-url "http://127.0.0.1:${controller_port}" --output json \
    explain --from frontend/client --to backend/conformance-server \
    --protocol tcp --port 9092)
grep -q '"reason": "DefaultAction"' <<<"${conformance_deny}"
grep -q '"verdict": "Deny"' <<<"${conformance_deny}"
conformance_response=$("${kc[@]}" exec -n frontend client -- \
    wget -T 2 -t 1 -qO- http://conformance-server.backend.svc.cluster.local:8085)
if [[ ${conformance_response} != "unf-conformance-ok" ]]; then
    echo "default-TCP NetworkPolicy conformance allow failed" >&2
    exit 1
fi
if "${kc[@]}" exec -n frontend client -- \
    wget -T 2 -t 1 -qO- \
        http://conformance-server.backend.svc.cluster.local:9092 >/dev/null 2>&1; then
    echo "omitted podSelector did not isolate the conformance Pod" >&2
    exit 1
fi

"${kc[@]}" patch networkpolicy -n backend namespace-wide-default-target \
    --type=merge -p '{"spec":{"podSelector":{"matchLabels":{"app":"np-server"}}}}' \
    >/dev/null
if ! wait_for_controller_policy_counts 2 0 "${conformance_policy_revision}"; then
    echo "controller did not narrow the conformance policy target" >&2
    exit 1
fi
if ! wait_for_policy_transition "${conformance_policy_revision}"; then
    echo "agents did not activate the narrowed conformance target" >&2
    exit 1
fi
narrowed_conformance_revision=${transition_revision}
non_selected_explanation=$("${unfctl}" \
    --controller-url "http://127.0.0.1:${controller_port}" --output json \
    explain --from frontend/client --to backend/conformance-server \
    --protocol tcp --port 9092)
grep -q '"reason": "NoApplicablePolicy"' <<<"${non_selected_explanation}"
grep -q '"verdict": "Allow"' <<<"${non_selected_explanation}"
non_selected_response=$("${kc[@]}" exec -n frontend client -- \
    wget -T 2 -t 1 -qO- http://conformance-server.backend.svc.cluster.local:9092)
if [[ ${non_selected_response} != "unf-conformance-ok" ]]; then
    echo "a Pod not selected by ingress policy remained isolated" >&2
    exit 1
fi

"${kc[@]}" delete -f \
    "${project_root}/deploy/examples/networkpolicy-conformance.yaml" >/dev/null
network_policy_conformance_created=false
if ! wait_for_controller_policy_counts 1 0 "${narrowed_conformance_revision}"; then
    echo "controller did not remove the conformance NetworkPolicy" >&2
    exit 1
fi
if ! wait_for_policy_batch_convergence "${narrowed_conformance_revision}"; then
    echo "agents did not remove the conformance NetworkPolicy" >&2
    exit 1
fi
post_conformance_revision=${transition_revision}

"${kc[@]}" apply -f "${project_root}/deploy/examples/networkpolicy-sctp.yaml" >/dev/null
network_policy_sctp_created=true
"${kc[@]}" wait --for=condition=Ready pod/sctp-client -n frontend --timeout=120s
"${kc[@]}" wait --for=condition=Ready pod/sctp-server -n backend --timeout=120s
sctp_server_ip=$("${kc[@]}" get pod -n backend sctp-server \
    -o jsonpath='{.status.podIP}')
if [[ -z ${sctp_server_ip} ]]; then
    echo "SCTP conformance server has no Pod IP" >&2
    exit 1
fi
sctp_exchange() {
    local payload=$1
    local port=$2
    local timeout_seconds=${3:-3}
    local command_timeout=$((timeout_seconds + 2))
    {
        printf '%s' "${payload}"
        sleep 1
    } | "${kc[@]}" exec -i -n frontend sctp-client -- \
        timeout "${command_timeout}" socat -T "${timeout_seconds}" - \
            "SCTP:${sctp_server_ip}:${port}"
}
if ! wait_for_controller_policy_counts 2 0 "${post_conformance_revision}"; then
    echo "controller did not accept the SCTP NetworkPolicy" >&2
    exit 1
fi
if ! wait_for_policy_batch_convergence "${post_conformance_revision}"; then
    echo "agents did not activate SCTP NetworkPolicy isolation" >&2
    exit 1
fi
sctp_policy_revision=${transition_revision}
sctp_allow=$("${unfctl}" \
    --controller-url "http://127.0.0.1:${controller_port}" --output json \
    explain --from frontend/sctp-client --to backend/sctp-server \
    --protocol sctp --port 8086)
grep -q '"reason": "ExplicitRule"' <<<"${sctp_allow}"
grep -q '"verdict": "Allow"' <<<"${sctp_allow}"
sctp_deny=$("${unfctl}" \
    --controller-url "http://127.0.0.1:${controller_port}" --output json \
    explain --from frontend/sctp-client --to backend/sctp-server \
    --protocol sctp --port 9093)
grep -q '"reason": "DefaultAction"' <<<"${sctp_deny}"
grep -q '"verdict": "Deny"' <<<"${sctp_deny}"
sctp_response=$(sctp_exchange unf-sctp-ok 8086)
if [[ ${sctp_response} != "unf-sctp-ok" ]]; then
    echo "named-port SCTP NetworkPolicy allow failed" >&2
    exit 1
fi
if sctp_exchange unf-sctp-deny 9093 2 >/dev/null 2>&1; then
    echo "SCTP NetworkPolicy isolation did not drop the non-allowed port" >&2
    exit 1
fi

sctp_provenance=
sctp_history=
for _ in {1..20}; do
    sctp_provenance=$(all_agent_logs | grep '"destination_port":8086' \
        | grep '"protocol":132' | grep '"verdict":"Allow"' | grep '"reason":1' \
        | grep "\"policy_revision\":${sctp_policy_revision}" | tail -n 1 || true)
    sctp_history=$("${unfctl}" \
        --controller-url "http://127.0.0.1:${controller_port}" --output json flows)
    if grep -Eq '"source_identity":[1-9][0-9]*' <<<"${sctp_provenance}" \
        && grep -Eq '"destination_identity":[1-9][0-9]*' <<<"${sctp_provenance}" \
        && grep -Eq '"policy_id":[1-9][0-9]*' <<<"${sctp_provenance}" \
        && grep -q '"protocol": 132' <<<"${sctp_history}" \
        && grep -q '"frontend/sctp-client"' <<<"${sctp_history}" \
        && grep -q '"backend/sctp-server"' <<<"${sctp_history}"; then
        break
    fi
    sctp_exchange unf-sctp-ok 8086 >/dev/null
    sleep 1
done
if ! grep -Eq '"source_identity":[1-9][0-9]*' <<<"${sctp_provenance}" \
    || ! grep -Eq '"destination_identity":[1-9][0-9]*' <<<"${sctp_provenance}" \
    || ! grep -Eq '"policy_id":[1-9][0-9]*' <<<"${sctp_provenance}"; then
    echo "UNF did not emit revisioned SCTP allow provenance" >&2
    exit 1
fi
if ! grep -q '"protocol": 132' <<<"${sctp_history}" \
    || ! grep -q '"frontend/sctp-client"' <<<"${sctp_history}" \
    || ! grep -q '"backend/sctp-server"' <<<"${sctp_history}"; then
    echo "controller did not retain the enriched SCTP flow" >&2
    exit 1
fi

"${kc[@]}" patch networkpolicy -n backend allow-sctp-client --type=json \
    -p '[{"op":"add","path":"/spec/ingress/0/ports/-","value":{"protocol":"SCTP"}}]' \
    >/dev/null
if ! wait_for_controller_policy_counts 2 0 "${sctp_policy_revision}"; then
    echo "controller did not compile the protocol-only SCTP port" >&2
    exit 1
fi
if ! wait_for_policy_transition "${sctp_policy_revision}"; then
    echo "agents did not activate the protocol-only SCTP port" >&2
    exit 1
fi
sctp_wildcard_revision=${transition_revision}
sctp_wildcard=$("${unfctl}" \
    --controller-url "http://127.0.0.1:${controller_port}" --output json \
    explain --from frontend/sctp-client --to backend/sctp-server \
    --protocol sctp --port 9093)
grep -q '"reason": "ExplicitRule"' <<<"${sctp_wildcard}"
grep -q '"verdict": "Allow"' <<<"${sctp_wildcard}"
sctp_wildcard_response=$(sctp_exchange unf-sctp-wildcard 9093)
if [[ ${sctp_wildcard_response} != "unf-sctp-wildcard" ]]; then
    echo "protocol-only SCTP NetworkPolicy allow failed" >&2
    exit 1
fi

"${kc[@]}" patch networkpolicy -n backend allow-sctp-client --type=json \
    -p '[{"op":"remove","path":"/spec/ingress/0/ports/1"}]' >/dev/null
if ! wait_for_controller_policy_counts 2 0 "${sctp_wildcard_revision}"; then
    echo "controller did not restore the named SCTP port" >&2
    exit 1
fi
if ! wait_for_policy_transition "${sctp_wildcard_revision}"; then
    echo "agents did not remove the protocol-only SCTP port" >&2
    exit 1
fi
sctp_restored_revision=${transition_revision}
if sctp_exchange unf-sctp-deny 9093 2 >/dev/null 2>&1; then
    echo "removing the protocol-only SCTP port did not restore isolation" >&2
    exit 1
fi

"${kc[@]}" delete -f "${project_root}/deploy/examples/networkpolicy-sctp.yaml" \
    >/dev/null
network_policy_sctp_created=false
if ! wait_for_controller_policy_counts 1 0 "${sctp_restored_revision}"; then
    echo "controller did not remove the SCTP NetworkPolicy" >&2
    exit 1
fi
if ! wait_for_policy_batch_convergence "${sctp_restored_revision}"; then
    echo "agents did not remove the SCTP NetworkPolicy" >&2
    exit 1
fi

KUBECONFIG="${kubeconfig}" KUBE_CONTEXT="${context}" \
    UNF_CONTROLLER_URL="http://127.0.0.1:${controller_port}" UNFCTL="${unfctl}" \
    "${project_root}/hack/verify-networkpolicy-ingress.sh"

"${kc[@]}" -n kube-system rollout status daemonset/kindnet --timeout=120s
if "${kc[@]}" -n kube-system get pods -l app=kindnet \
    -o jsonpath='{range .items[*]}{.status.containerStatuses[0].restartCount}{"\n"}{end}' \
    | grep -vq '^0$'; then
    echo "kindnet restarted during dual-stack verification" >&2
    exit 1
fi

echo "kind verification passed: dual-stack identity maps, native/NetworkPolicy IPv6 enforcement and history, upstream-aligned ingress matrix, named/protocol-only SCTP and namespace-wide/default-TCP conformance, EndpointSlice readiness, history-aware simulation, topology v3, flow export v2, bounded ranges and IPv4 ipBlocks, lifecycle recovery, shadow mode, transactional activation, and provenance"
