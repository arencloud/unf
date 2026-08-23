#!/usr/bin/env bash
set -euo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
kubeconfig=${KUBECONFIG:-"${project_root}/.tools/kind-unf-dev.kubeconfig"}
context=${KUBE_CONTEXT:-kind-unf-dev}
controller_port=${UNF_CONTROLLER_TEST_PORT:-19962}
agent_port=${UNF_AGENT_TEST_PORT:-19963}
unfctl=${UNFCTL:-"${project_root}/target/debug/unfctl"}
temporary_dir=$(mktemp -d)
controller_forward_pid=
agent_forward_pid=
policy_mutated=false

cleanup() {
    if [[ ${policy_mutated} == true ]]; then
        "${kc[@]}" patch securitypolicy -n backend frontend-to-backend \
            --type=merge -p '{"spec":{"priority":100}}' >/dev/null 2>&1 || true
    fi
    if [[ -n ${controller_forward_pid} ]]; then
        kill "${controller_forward_pid}" 2>/dev/null || true
    fi
    if [[ -n ${agent_forward_pid} ]]; then
        kill "${agent_forward_pid}" 2>/dev/null || true
    fi
    rm -rf "${temporary_dir}"
}
trap cleanup EXIT

kc=(kubectl --kubeconfig "${kubeconfig}" --context "${context}")

"${kc[@]}" wait --for=condition=Ready nodes --all --timeout=120s
"${kc[@]}" -n unf-system rollout status deployment/unf-controller --timeout=120s
"${kc[@]}" -n unf-system rollout status daemonset/unf-agent --timeout=120s

server_node=$("${kc[@]}" get pod -n backend server -o jsonpath='{.spec.nodeName}')
server_agent=$("${kc[@]}" get pod -n unf-system \
    -l app.kubernetes.io/name=unf-agent \
    --field-selector "spec.nodeName=${server_node}" \
    -o jsonpath='{.items[0].metadata.name}')

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

allow_explanation=$("${unfctl}" \
    --controller-url "http://127.0.0.1:${controller_port}" --output json \
    explain --from frontend/client --to backend/server --protocol tcp --port 8080)
grep -q '"shadow_reason": "ExplicitRule"' <<<"${allow_explanation}"
grep -q '"shadow_verdict": "Allow"' <<<"${allow_explanation}"

deny_explanation=$("${unfctl}" \
    --controller-url "http://127.0.0.1:${controller_port}" --output json \
    explain --from frontend/client --to backend/server --protocol tcp --port 9090)
grep -q '"shadow_reason": "DefaultAction"' <<<"${deny_explanation}"
grep -q '"shadow_verdict": "Deny"' <<<"${deny_explanation}"

"${kc[@]}" -n unf-system port-forward "pod/${server_agent}" \
    "${agent_port}:9963" >"${temporary_dir}/agent-forward.log" 2>&1 &
agent_forward_pid=$!
identity_synced=false
for _ in {1..20}; do
    agent_status=$(curl --fail --silent "http://127.0.0.1:${agent_port}/v1/status" || true)
    desired_revision=$(sed -nE 's/.*"desired_identity_revision":([0-9]+).*/\1/p' <<<"${agent_status}")
    applied_revision=$(sed -nE 's/.*"applied_identity_revision":([0-9]+).*/\1/p' <<<"${agent_status}")
    desired_epoch=$(sed -nE 's/.*"desired_identity_epoch":([0-9]+).*/\1/p' <<<"${agent_status}")
    applied_epoch=$(sed -nE 's/.*"applied_identity_epoch":([0-9]+).*/\1/p' <<<"${agent_status}")
    map_entries=$(sed -nE 's/.*"identity_map_entries":([0-9]+).*/\1/p' <<<"${agent_status}")
    desired_policy_revision=$(sed -nE 's/.*"desired_policy_revision":([0-9]+).*/\1/p' <<<"${agent_status}")
    applied_policy_revision=$(sed -nE 's/.*"applied_policy_revision":([0-9]+).*/\1/p' <<<"${agent_status}")
    desired_policy_epoch=$(sed -nE 's/.*"desired_policy_epoch":([0-9]+).*/\1/p' <<<"${agent_status}")
    applied_policy_epoch=$(sed -nE 's/.*"applied_policy_epoch":([0-9]+).*/\1/p' <<<"${agent_status}")
    policy_entries=$(sed -nE 's/.*"policy_map_entries":([0-9]+).*/\1/p' <<<"${agent_status}")
    if [[ -n ${desired_revision} && ${desired_revision} == "${applied_revision}" \
        && -n ${desired_epoch} && ${desired_epoch} == "${applied_epoch}" \
        && ${map_entries:-0} -gt 0 \
        && -n ${desired_policy_revision} && ${desired_policy_revision} == "${applied_policy_revision}" \
        && -n ${desired_policy_epoch} && ${desired_policy_epoch} == "${applied_policy_epoch}" \
        && ${policy_entries:-0} -gt 0 ]]; then
        identity_synced=true
        break
    fi
    sleep 1
done
if [[ ${identity_synced} != true ]]; then
    echo "UNF agent did not apply the controller identity and policy revisions" >&2
    exit 1
fi
grep -q '"bpf_loaded":true' <<<"${agent_status}"
grep -Eq '"active_policy_bank":[01]' <<<"${agent_status}"

initial_policy_revision=${applied_policy_revision}
initial_policy_bank=$(sed -nE 's/.*"active_policy_bank":([0-9]+).*/\1/p' <<<"${agent_status}")
"${kc[@]}" patch securitypolicy -n backend frontend-to-backend \
    --type=merge -p '{"spec":{"priority":101}}' >/dev/null
policy_mutated=true
policy_switched=false
for _ in {1..30}; do
    agent_status=$(curl --fail --silent "http://127.0.0.1:${agent_port}/v1/status" || true)
    desired_policy_revision=$(sed -nE 's/.*"desired_policy_revision":([0-9]+).*/\1/p' <<<"${agent_status}")
    applied_policy_revision=$(sed -nE 's/.*"applied_policy_revision":([0-9]+).*/\1/p' <<<"${agent_status}")
    active_policy_bank=$(sed -nE 's/.*"active_policy_bank":([0-9]+).*/\1/p' <<<"${agent_status}")
    if [[ -n ${applied_policy_revision} \
        && ${applied_policy_revision} -gt ${initial_policy_revision} \
        && ${desired_policy_revision} == "${applied_policy_revision}" \
        && ${active_policy_bank} != "${initial_policy_bank}" ]]; then
        policy_switched=true
        break
    fi
    sleep 1
done
if [[ ${policy_switched} != true ]]; then
    echo "UNF agent did not atomically switch to the staged policy bank" >&2
    exit 1
fi

staged_policy_revision=${applied_policy_revision}
"${kc[@]}" patch securitypolicy -n backend frontend-to-backend \
    --type=merge -p '{"spec":{"priority":100}}' >/dev/null
policy_mutated=false
policy_restored=false
for _ in {1..30}; do
    agent_status=$(curl --fail --silent "http://127.0.0.1:${agent_port}/v1/status" || true)
    desired_policy_revision=$(sed -nE 's/.*"desired_policy_revision":([0-9]+).*/\1/p' <<<"${agent_status}")
    applied_policy_revision=$(sed -nE 's/.*"applied_policy_revision":([0-9]+).*/\1/p' <<<"${agent_status}")
    if [[ -n ${applied_policy_revision} \
        && ${applied_policy_revision} -gt ${staged_policy_revision} \
        && ${desired_policy_revision} == "${applied_policy_revision}" ]]; then
        policy_restored=true
        break
    fi
    sleep 1
done
if [[ ${policy_restored} != true ]]; then
    echo "UNF agent did not converge after restoring the demo policy" >&2
    exit 1
fi

response=$("${kc[@]}" exec -n frontend client -- \
    wget -qO- http://server.backend.svc.cluster.local:8080)
if [[ ${response} != "unf-demo-ok" ]]; then
    echo "unexpected demo response: ${response}" >&2
    exit 1
fi

flow_line=$("${kc[@]}" -n unf-system logs "pod/${server_agent}" \
    --since=15s --tail=-1 | grep '"destination_port":8080' | tail -n 1 || true)
if ! grep -Eq '"source_identity":[1-9][0-9]*' <<<"${flow_line}" \
    || ! grep -Eq '"destination_identity":[1-9][0-9]*' <<<"${flow_line}"; then
    echo "UNF did not observe the demo flow with resolved identities" >&2
    exit 1
fi

echo "kind verification passed: transactional policy/identity distribution, enriched eBPF flow, and shadow explanations"
