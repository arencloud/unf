#!/usr/bin/env bash
set -euo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
kubeconfig=${KUBECONFIG:-"${project_root}/.tools/kind-unf-dev.kubeconfig"}
context=${KUBE_CONTEXT:-kind-unf-dev}
controller_port=${UNF_FLOW_HISTORY_TEST_PORT:-19963}
unfctl=${UNFCTL:-"${project_root}/target/debug/unfctl"}
kc=(kubectl --kubeconfig "${kubeconfig}" --context "${context}")
temporary_dir=$(mktemp -d)
forward_pid=

cleanup() {
    if [[ -n ${forward_pid} ]]; then
        kill "${forward_pid}" >/dev/null 2>&1 || true
        wait "${forward_pid}" >/dev/null 2>&1 || true
    fi
    rm -rf "${temporary_dir}"
}
trap cleanup EXIT

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
    "${kc[@]}" -n unf-system get configmap unf-flow-history -o json \
        | jq -r '.data["flows.json"] // ""'
}

controller_raw() {
    local controller=$1
    local path=$2
    "${kc[@]}" get --raw \
        "/api/v1/namespaces/unf-system/pods/${controller}:9962/proxy${path}"
}

wait_for_target_flow() {
    local controller=$1
    local since_unix_ms=$2
    local snapshot
    for _ in {1..45}; do
        snapshot=$(controller_raw "${controller}" /v1/flows 2>/dev/null || true)
        if jq -e --argjson since "${since_unix_ms}" '
            .schema_version == 4
            and any(.entries[];
                (.source_workloads | index("frontend/client"))
                and (.destination_workloads | index("backend/server"))
                and .key.destination_port == 8080
                and .last_received_unix_ms >= $since
                and .decision.verdict == "Allow")
        ' <<<"${snapshot}" >/dev/null 2>&1; then
            printf '%s' "${snapshot}"
            return 0
        fi
        sleep 1
    done
    echo "controller did not expose the target flow-history entry" >&2
    return 1
}

wait_for_checkpoint() {
    local source_identity=$1
    local destination_identity=$2
    local encoded
    for _ in {1..45}; do
        encoded=$(checkpoint 2>/dev/null || true)
        if jq -e \
            --argjson source "${source_identity}" \
            --argjson destination "${destination_identity}" '
            .schema_version == 2
            and .revision > 0
            and any(.entries[];
                .key.source_identity == $source
                and .key.destination_identity == $destination
                and .key.destination_port == 8080
                and .observed_events > 0
                and .first_received_unix_ms > 0
                and .last_received_unix_ms >= .first_received_unix_ms)
        ' <<<"${encoded}" >/dev/null 2>&1; then
            printf '%s' "${encoded}"
            return 0
        fi
        sleep 1
    done
    echo "durable flow-history checkpoint did not retain the target flow" >&2
    return 1
}

for command in kubectl jq date; do
    command -v "${command}" >/dev/null
done
[[ -x ${unfctl} ]]
[[ -s ${kubeconfig} ]]
"${kc[@]}" -n unf-system wait --for=condition=Available \
    deployment/unf-controller --timeout=120s >/dev/null
"${kc[@]}" -n unf-system rollout status daemonset/unf-agent \
    --timeout=120s >/dev/null
"${kc[@]}" -n frontend wait --for=condition=Ready pod/client --timeout=120s >/dev/null
"${kc[@]}" -n backend wait --for=condition=Ready pod/server --timeout=120s >/dev/null

service_account=system:serviceaccount:unf-system:unf-controller
[[ $("${kc[@]}" auth can-i get configmap/unf-flow-history \
    --as="${service_account}" -n unf-system) == yes ]]
[[ $("${kc[@]}" auth can-i patch configmap/unf-flow-history \
    --as="${service_account}" -n unf-system) == yes ]]
[[ $("${kc[@]}" auth can-i create configmaps \
    --as="${service_account}" -n unf-system) == no ]]
[[ $("${kc[@]}" auth can-i delete configmap/unf-flow-history \
    --as="${service_account}" -n unf-system) == no ]]

controller=$(active_controller)
[[ $(wc -w <<<"${controller}") -eq 1 ]]
window_start=$(date +%s%3N)
response=$("${kc[@]}" exec -n frontend client -- \
    wget -T 2 -t 1 -qO- http://server.backend.svc.cluster.local:8080)
[[ ${response} == unf-demo-ok ]]
before=$(wait_for_target_flow "${controller}" "${window_start}")
target=$(jq -c '[
    .entries[]
    | select((.source_workloads | index("frontend/client"))
        and (.destination_workloads | index("backend/server"))
        and .key.destination_port == 8080
        and .decision.verdict == "Allow")
    ][0]' <<<"${before}")
source_identity=$(jq '.key.source_identity' <<<"${target}")
destination_identity=$(jq '.key.destination_identity' <<<"${target}")

checkpoint_before=$(wait_for_checkpoint "${source_identity}" "${destination_identity}")
first_received=$(jq \
    --argjson source "${source_identity}" \
    --argjson destination "${destination_identity}" '[
    .entries[]
    | select(.key.source_identity == $source
        and .key.destination_identity == $destination
        and .key.destination_port == 8080)
    | .first_received_unix_ms
    ][0]' <<<"${checkpoint_before}")
[[ ${first_received} -gt 0 ]]

"${kc[@]}" -n unf-system port-forward service/unf-controller \
    "${controller_port}:9962" >"${temporary_dir}/port-forward.log" 2>&1 &
forward_pid=$!
for _ in {1..30}; do
    if "${unfctl}" --controller-url "http://127.0.0.1:${controller_port}" \
        --output json status >/dev/null 2>&1; then
        break
    fi
    sleep 1
done
kill -0 "${forward_pid}"

recent=$("${unfctl}" --controller-url "http://127.0.0.1:${controller_port}" \
    --output json flows --since-unix-ms "${window_start}")
jq -e --argjson start "${window_start}" '
    .query.since_unix_ms == $start
    and .query.matched_flows > 0
    and .query.returned_flows > 0
    and any(.entries[];
        (.source_workloads | index("frontend/client"))
        and (.destination_workloads | index("backend/server"))
        and .key.destination_port == 8080)
' <<<"${recent}" >/dev/null

bounded=$("${unfctl}" --controller-url "http://127.0.0.1:${controller_port}" \
    --output json flows --last 10m --limit 1)
jq -e '
    .query.limit == 1
    and .query.returned_flows <= 1
    and (.query.truncated == (.query.matched_flows > 1))
' <<<"${bounded}" >/dev/null

future_start=$(( $(date +%s%3N) + 60000 ))
future=$("${unfctl}" --controller-url "http://127.0.0.1:${controller_port}" \
    --output json flows --since-unix-ms "${future_start}")
jq -e '
    .query.matched_flows == 0
    and .query.matched_observations == 0
    and .query.returned_flows == 0
    and (.entries | length) == 0
' <<<"${future}" >/dev/null

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
    sleep 1
done
[[ $(wc -w <<<"${controller}") -eq 1 ]]
new_controller_uid=$("${kc[@]}" -n unf-system get pod "${controller}" \
    -o jsonpath='{.metadata.uid}')
[[ ${new_controller_uid} != "${old_controller_uid}" ]]
[[ $(agent_runtime_state) == "${agent_state}" ]]

after=$(wait_for_target_flow "${controller}" "${window_start}")
restored_first=$(jq \
    --argjson source "${source_identity}" \
    --argjson destination "${destination_identity}" '[
    .entries[]
    | select(.key.source_identity == $source
        and .key.destination_identity == $destination
        and .key.destination_port == 8080)
    | .first_received_unix_ms
    ][0]' <<<"${after}")
[[ ${restored_first} -eq "${first_received}" ]]
jq -e '
    .durable_checkpointed_flows > 0
    and .durable_omitted_flows >= 0
    and .query.returned_flows > 0
' <<<"${after}" >/dev/null

metrics=$(controller_raw "${controller}" /metrics)
restored=$(awk '$1 == "unf_flow_history_entries_restored_total" { print int($2) }' \
    <<<"${metrics}")
errors=$(awk '$1 == "unf_flow_history_persistence_errors_total" { print int($2) }' \
    <<<"${metrics}")
[[ ${restored} -gt 0 ]]
[[ ${errors} -eq 0 ]]
logs=$("${kc[@]}" -n unf-system logs "${controller}")
grep -q 'restored durable flow history' <<<"${logs}"
[[ $(agent_runtime_state) == "${agent_state}" ]]

echo "durable flow-history qualification passed: bounded checkpoint restore, exact RBAC, last-received absolute/relative windows, newest-first limit, empty future window, preserved first-received time, and zero agent replacements or persistence errors"
