#!/usr/bin/env bash
set -euo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
kubeconfig=${KUBECONFIG:-"${project_root}/.tools/cl02-audit.kubeconfig"}
context=${KUBE_CONTEXT:-$(oc --kubeconfig "${kubeconfig}" config current-context)}
kc=(oc --kubeconfig "${kubeconfig}" --context "${context}")

for command in oc jq; do
    command -v "${command}" >/dev/null
done
[[ -s ${kubeconfig} ]] || {
    echo "OpenShift kubeconfig not found: ${kubeconfig}" >&2
    exit 1
}

active_controller() {
    "${kc[@]}" -n unf-system get pod \
        -l app.kubernetes.io/name=unf-controller -o json \
        | jq -r '.items[] | select(.metadata.deletionTimestamp == null and .status.phase == "Running") | .metadata.name'
}

agent_runtime_state() {
    "${kc[@]}" -n unf-system get pod \
        -l app.kubernetes.io/name=unf-agent -o json \
        | jq -r '.items[] | [.metadata.uid, (.status.containerStatuses[0].restartCount // 0)] | @tsv' \
        | sort
}

checkpoint() {
    "${kc[@]}" -n unf-system get configmap unf-agent-acknowledgements \
        -o jsonpath='{.data.reports\.json}'
}

wait_for_checkpoint() {
    local expected=$1
    local encoded
    for _ in {1..30}; do
        encoded=$(checkpoint 2>/dev/null || true)
        if jq -e --argjson expected "${expected}" '
            .schema_version == 1
            and (.reports | length) == $expected
            and all(.reports[];
                .last_received_unix_ms > 0
                and .report.schema_version == 2
                and .report.node_name != ""
                and .report.pod_name != ""
                and .report.pod_uid != "")
        ' <<<"${encoded}" >/dev/null 2>&1; then
            printf '%s' "${encoded}"
            return 0
        fi
        sleep 2
    done
    echo "durable agent-report checkpoint did not reach ${expected} valid entries" >&2
    return 1
}

wait_for_convergence() {
    local controller=$1
    local expected=$2
    local status
    for _ in {1..60}; do
        status=$("${kc[@]}" get --raw \
            "/api/v1/namespaces/unf-system/pods/${controller}:9962/proxy/v1/status" \
            2>/dev/null || true)
        if jq -e --argjson expected "${expected}" '
            .agents.expected_agents == $expected
            and .agents.reporting_agents == $expected
            and .agents.missing_agents == 0
            and .agents.stale_agents == 0
            and .agents.all_converged == true
        ' <<<"${status}" >/dev/null 2>&1; then
            return 0
        fi
        sleep 2
    done
    echo "agents did not reconverge after controller restart" >&2
    return 1
}

"${kc[@]}" get clusterversion version >/dev/null
"${kc[@]}" -n unf-system wait --for=condition=Available deployment/unf-controller \
    --timeout=120s >/dev/null
"${kc[@]}" -n unf-system rollout status daemonset/unf-agent --timeout=120s >/dev/null

expected_agents=$("${kc[@]}" get node -l node-role.kubernetes.io/worker \
    -o json | jq '.items | length')
[[ ${expected_agents} -gt 0 ]]
controller=$(active_controller)
[[ $(wc -w <<<"${controller}") -eq 1 ]]
wait_for_convergence "${controller}" "${expected_agents}"

service_account=system:serviceaccount:unf-system:unf-controller
[[ $("${kc[@]}" auth can-i get configmap/unf-agent-acknowledgements \
    --as="${service_account}" -n unf-system) == yes ]]
[[ $("${kc[@]}" auth can-i patch configmap/unf-agent-acknowledgements \
    --as="${service_account}" -n unf-system) == yes ]]
[[ $("${kc[@]}" auth can-i create configmaps \
    --as="${service_account}" -n unf-system) == no ]]
[[ $("${kc[@]}" auth can-i delete configmap/unf-agent-acknowledgements \
    --as="${service_account}" -n unf-system) == no ]]

before=$(wait_for_checkpoint "${expected_agents}")
before_timestamp=$(jq '[.reports[].last_received_unix_ms] | max' <<<"${before}")
old_controller_uid=$("${kc[@]}" -n unf-system get pod "${controller}" \
    -o jsonpath='{.metadata.uid}')
agent_state=$(agent_runtime_state)

"${kc[@]}" -n unf-system rollout restart deployment/unf-controller >/dev/null
"${kc[@]}" -n unf-system rollout status deployment/unf-controller \
    --timeout=180s >/dev/null
for _ in {1..30}; do
    controller=$(active_controller)
    if [[ $(wc -w <<<"${controller}") -eq 1 ]]; then
        break
    fi
    sleep 2
done
[[ $(wc -w <<<"${controller}") -eq 1 ]]
new_controller_uid=$("${kc[@]}" -n unf-system get pod "${controller}" \
    -o jsonpath='{.metadata.uid}')
[[ ${new_controller_uid} != "${old_controller_uid}" ]]
[[ $(agent_runtime_state) == "${agent_state}" ]]

metrics=$("${kc[@]}" get --raw \
    "/api/v1/namespaces/unf-system/pods/${controller}:9962/proxy/metrics")
restored=$(awk '$1 == "unf_agent_reports_restored_total" { print int($2) }' \
    <<<"${metrics}")
errors=$(awk '$1 == "unf_agent_report_persistence_errors_total" { print int($2) }' \
    <<<"${metrics}")
[[ ${restored} -eq ${expected_agents} ]]
[[ ${errors} -eq 0 ]]
controller_logs=$("${kc[@]}" -n unf-system logs "${controller}")
grep -q "restored durable agent acknowledgements" <<<"${controller_logs}"

wait_for_convergence "${controller}" "${expected_agents}"
for _ in {1..30}; do
    after=$(wait_for_checkpoint "${expected_agents}")
    after_timestamp=$(jq '[.reports[].last_received_unix_ms] | max' <<<"${after}")
    if [[ ${after_timestamp} -gt ${before_timestamp} ]]; then
        break
    fi
    sleep 2
done
[[ ${after_timestamp} -gt ${before_timestamp} ]]
[[ $(agent_runtime_state) == "${agent_state}" ]]

echo "OpenShift agent-report retention qualification passed: ${expected_agents} authenticated reports checkpointed, restored across controller replacement, reconverged, and advanced with zero agent replacements or persistence errors"
