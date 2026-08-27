#!/usr/bin/env bash
set -Eeuo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
kubeconfig=${KUBECONFIG:-"${project_root}/.tools/kind-unf-dev.kubeconfig"}
context=${KUBE_CONTEXT:-kind-unf-dev}
controller_port=${UNF_FLOW_HISTORY_TEST_PORT:-19963}
unfctl=${UNFCTL:-"${project_root}/target/debug/unfctl"}
kc=(kubectl --kubeconfig "${kubeconfig}" --context "${context}")
temporary_dir=$(mktemp -d)
forward_pid=
qualification_stage=initialization

report_failure() {
    local status=$?
    local line=${BASH_LINENO[0]:-unknown}
    echo "durable flow-history qualification failed during ${qualification_stage} at line ${line}: ${BASH_COMMAND}" >&2
    return "${status}"
}

cleanup() {
    if [[ -n ${forward_pid} ]]; then
        kill "${forward_pid}" >/dev/null 2>&1 || true
        wait "${forward_pid}" >/dev/null 2>&1 || true
    fi
    rm -rf "${temporary_dir}"
}
trap report_failure ERR
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
    local target_url=$3
    local expected_key=${4:-null}
    local snapshot
    local response
    for attempt in {1..45}; do
        if (( (attempt - 1) % 5 == 0 )); then
            for _ in {1..4}; do
                if response=$("${kc[@]}" exec -n frontend client -- \
                    wget -T 2 -t 1 -qO- "${target_url}" 2>/dev/null) \
                    && [[ ${response} == unf-demo-ok ]]; then
                    continue
                fi
                # A single sample may race a just-completed dataplane recovery.
                # Keep the overall wait bounded and require a qualifying flow.
                break
            done
        fi
        snapshot=$(controller_raw "${controller}" /v1/flows 2>/dev/null || true)
        if jq -e --argjson since "${since_unix_ms}" \
            --argjson expected_key "${expected_key}" '
            .schema_version == 4
            and any(.entries[];
                (if $expected_key == null then
                    (.source_workloads | index("frontend/client"))
                    and (.destination_workloads | index("backend/server"))
                    and .key.destination_port == 8080
                else
                    .key == $expected_key
                end)
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
    local target_key=$1
    local encoded
    for _ in {1..45}; do
        encoded=$(checkpoint 2>/dev/null || true)
        if jq -e \
            --argjson target_key "${target_key}" '
            .schema_version == 2
            and .revision > 0
            and any(.entries[];
                .key == $target_key
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
qualification_stage=prerequisites
[[ -x ${unfctl} ]]
[[ -s ${kubeconfig} ]]
"${kc[@]}" -n unf-system wait --for=condition=Available \
    deployment/unf-controller --timeout=120s >/dev/null
"${kc[@]}" -n unf-system rollout status daemonset/unf-agent \
    --timeout=120s >/dev/null
"${kc[@]}" -n frontend wait --for=condition=Ready pod/client --timeout=120s >/dev/null
"${kc[@]}" -n backend wait --for=condition=Ready pod/server --timeout=120s >/dev/null
server_ipv4=$("${kc[@]}" -n backend get pod server -o json \
    | jq -r '[.status.podIPs[].ip | select(contains("."))][0] // empty')
[[ -n ${server_ipv4} ]]
target_url="http://${server_ipv4}:8080"

service_account=system:serviceaccount:unf-system:unf-controller
[[ $("${kc[@]}" auth can-i get configmap/unf-flow-history \
    --as="${service_account}" -n unf-system) == yes ]]
[[ $("${kc[@]}" auth can-i patch configmap/unf-flow-history \
    --as="${service_account}" -n unf-system) == yes ]]
can_create_configmaps=$("${kc[@]}" auth can-i create configmaps \
    --as="${service_account}" -n unf-system || true)
[[ ${can_create_configmaps} == no ]]
can_delete_checkpoint=$("${kc[@]}" auth can-i delete configmap/unf-flow-history \
    --as="${service_account}" -n unf-system || true)
[[ ${can_delete_checkpoint} == no ]]

controller=$(active_controller)
[[ $(wc -w <<<"${controller}") -eq 1 ]]
window_start=$(date +%s%3N)
qualification_stage=traffic-generation
# A bounded burst makes the persistence fixture independent of the agent's
# aggregation sampling boundary after the high-volume conformance matrix.
for _ in {1..8}; do
    response=$("${kc[@]}" exec -n frontend client -- \
        wget -T 2 -t 1 -qO- "${target_url}")
    [[ ${response} == unf-demo-ok ]]
done
qualification_stage=live-flow-observation
before=$(wait_for_target_flow "${controller}" "${window_start}" "${target_url}")
target=$(jq -c '[
    .entries[]
    | select((.source_workloads | index("frontend/client"))
        and (.destination_workloads | index("backend/server"))
        and .key.destination_port == 8080
        and .decision.verdict == "Allow")
    ][0]' <<<"${before}")
target_key=$(jq -c '.key' <<<"${target}")

qualification_stage=durable-checkpoint
checkpoint_before=$(wait_for_checkpoint "${target_key}")
first_received=$(jq --argjson target_key "${target_key}" '[
    .entries[]
    | select(.key == $target_key)
    | .first_received_unix_ms
    ][0]' <<<"${checkpoint_before}")
[[ ${first_received} -gt 0 ]]

"${kc[@]}" -n unf-system port-forward service/unf-controller \
    "${controller_port}:9962" >"${temporary_dir}/port-forward.log" 2>&1 &
forward_pid=$!
qualification_stage=client-api-readiness
client_api_ready=false
for _ in {1..30}; do
    if "${unfctl}" --controller-url "http://127.0.0.1:${controller_port}" \
        --output json status >/dev/null 2>&1; then
        client_api_ready=true
        break
    fi
    sleep 1
done
if [[ ${client_api_ready} != true ]] || ! kill -0 "${forward_pid}" 2>/dev/null; then
    echo "controller client API did not become ready; port-forward log follows:" >&2
    sed -n '1,80p' "${temporary_dir}/port-forward.log" >&2
    false
fi

qualification_stage=bounded-history-queries
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
qualification_stage=controller-restart
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

qualification_stage=checkpoint-restore
after=$(wait_for_target_flow \
    "${controller}" "${window_start}" "${target_url}" "${target_key}")
restored_first=$(jq --argjson target_key "${target_key}" '[
    .entries[]
    | select(.key == $target_key)
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

qualification_stage=complete
echo "durable flow-history qualification passed: bounded checkpoint restore, exact RBAC, last-received absolute/relative windows, newest-first limit, empty future window, preserved first-received time, and zero agent replacements or persistence errors"
