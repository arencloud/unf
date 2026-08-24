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
network_policy_deleted=false
namespace_mutated=false

cleanup() {
    if [[ ${policy_mutated} == true ]]; then
        "${kc[@]}" patch securitypolicy -n backend frontend-to-backend \
            --type=merge -p '{"spec":{"enforcementMode":"Enforce"}}' >/dev/null 2>&1 || true
    fi
    if [[ ${network_policy_mutated} == true ]]; then
        "${kc[@]}" patch networkpolicy -n backend frontend-to-np-server --type=json \
            -p '[{"op":"replace","path":"/spec/ingress/0/ports/1/endPort","value":8083}]' \
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

"${kc[@]}" wait --for=condition=Ready nodes --all --timeout=120s
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

namespace_identity_revision=$("${unfctl}" \
    --controller-url "http://127.0.0.1:${controller_port}" --output json status \
    | sed -nE 's/.*"identity": ([0-9]+).*/\1/p')
"${kc[@]}" label namespace frontend environment=staging --overwrite >/dev/null
namespace_mutated=true
if ! wait_for_controller_policy_counts 1 0 "${enforced_policy_revision}"; then
    echo "controller did not revise policy state after the Namespace label change" >&2
    exit 1
fi
namespace_denied_revision=${controller_state_revision}
if ! wait_for_policy_transition "${enforced_policy_revision}"; then
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

"${kc[@]}" delete networkpolicy -n backend frontend-to-np-server >/dev/null
network_policy_deleted=true
if ! wait_for_controller_policy_counts 0 0 "${restored_policy_revision}"; then
    echo "controller did not remove the deleted NetworkPolicy" >&2
    exit 1
fi
deleted_policy_revision=${controller_state_revision}
if ! wait_for_policy_transition "${restored_policy_revision}"; then
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
network_policy_deleted=false
if "${kc[@]}" exec -n frontend client -- \
    wget -T 2 -t 1 -qO- http://np-server.backend.svc.cluster.local:9091 >/dev/null 2>&1; then
    echo "recreated NetworkPolicy did not restore default-deny enforcement" >&2
    exit 1
fi

echo "kind verification passed: native/NetworkPolicy enforcement, bounded port ranges, namespace/rejection/deletion recovery, shadow mode, transactional activation, and provenance"
