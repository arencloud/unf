#!/usr/bin/env bash
set -euo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
kubeconfig=${KUBECONFIG:-"${project_root}/.tools/kind-unf-dev.kubeconfig"}
context=${KUBE_CONTEXT:-kind-unf-dev}
controller_port=${UNF_TOPOLOGY_HISTORY_TEST_PORT:-19965}
unfctl=${UNFCTL:-"${project_root}/target/debug/unfctl"}
kc=(kubectl --kubeconfig "${kubeconfig}" --context "${context}")
probe_service=unf-topology-history-probe
probe_slice=unf-topology-history-probe-v4
forward_pid=

cleanup() {
    "${kc[@]}" -n backend delete endpointslice "${probe_slice}" \
        --ignore-not-found --wait=false >/dev/null 2>&1 || true
    "${kc[@]}" -n backend delete service "${probe_service}" \
        --ignore-not-found --wait=false >/dev/null 2>&1 || true
    if [[ -n ${forward_pid} ]]; then
        kill "${forward_pid}" >/dev/null 2>&1 || true
        wait "${forward_pid}" >/dev/null 2>&1 || true
    fi
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

controller_raw() {
    local controller=$1
    local path=$2
    "${kc[@]}" get --raw \
        "/api/v1/namespaces/unf-system/pods/${controller}:9962/proxy${path}"
}

wait_for_current_topology() {
    local controller=$1
    local expression=$2
    local snapshot
    for _ in {1..45}; do
        snapshot=$(controller_raw "${controller}" /v1/topology 2>/dev/null || true)
        if jq -e "${expression}" <<<"${snapshot}" >/dev/null 2>&1; then
            printf '%s' "${snapshot}"
            return 0
        fi
        sleep 1
    done
    echo "current topology did not reach expected probe state" >&2
    return 1
}

checkpoint() {
    "${kc[@]}" -n unf-system get configmap unf-topology-history -o json \
        | jq -r '.data["history.json"] // ""'
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
"${kc[@]}" -n backend wait --for=condition=Ready pod/server --timeout=120s >/dev/null

service_account=system:serviceaccount:unf-system:unf-controller
[[ $("${kc[@]}" auth can-i get configmap/unf-topology-history \
    --as="${service_account}" -n unf-system) == yes ]]
[[ $("${kc[@]}" auth can-i patch configmap/unf-topology-history \
    --as="${service_account}" -n unf-system) == yes ]]
[[ $("${kc[@]}" auth can-i create configmaps \
    --as="${service_account}" -n unf-system) == no ]]
[[ $("${kc[@]}" auth can-i delete configmap/unf-topology-history \
    --as="${service_account}" -n unf-system) == no ]]

controller=$(active_controller)
[[ $(wc -w <<<"${controller}") -eq 1 ]]
controller_uid=$("${kc[@]}" -n unf-system get pod "${controller}" \
    -o jsonpath='{.metadata.uid}')
agent_state=$(agent_runtime_state)
baseline=$(controller_raw "${controller}" /v1/topology)
baseline_revision=$(jq '.revision' <<<"${baseline}")
baseline_epoch=$(jq '.source_epoch' <<<"${baseline}")
policy_revision=$(controller_raw "${controller}" /v1/status | jq '.revisions.policy')
window_start=$(date +%s%3N)

"${kc[@]}" -n unf-system port-forward service/unf-controller \
    "${controller_port}:9962" >/dev/null 2>&1 &
forward_pid=$!
for _ in {1..30}; do
    if "${unfctl}" --controller-url "http://127.0.0.1:${controller_port}" \
        status >/dev/null 2>&1; then
        break
    fi
    sleep 1
done
kill -0 "${forward_pid}"

server_ipv4=$("${kc[@]}" -n backend get pod server -o json \
    | jq -r '.status.podIPs[].ip | select(contains(":") | not)' | head -n 1)
server_node=$("${kc[@]}" -n backend get pod server -o jsonpath='{.spec.nodeName}')
[[ -n ${server_ipv4} ]]
[[ -n ${server_node} ]]

"${kc[@]}" apply -f - >/dev/null <<YAML
apiVersion: v1
kind: Service
metadata:
  name: ${probe_service}
  namespace: backend
spec:
  ports:
    - name: http
      port: 8080
      targetPort: 8080
YAML
service_snapshot=$(wait_for_current_topology "${controller}" \
    'any(.services[]; .reference == "backend/unf-topology-history-probe" and (.backends | length) == 0)')
service_revision=$(jq '.revision' <<<"${service_snapshot}")
[[ ${service_revision} -gt ${baseline_revision} ]]

"${kc[@]}" apply -f - >/dev/null <<YAML
apiVersion: discovery.k8s.io/v1
kind: EndpointSlice
metadata:
  name: ${probe_slice}
  namespace: backend
  labels:
    kubernetes.io/service-name: ${probe_service}
addressType: IPv4
ports:
  - name: http
    protocol: TCP
    port: 8080
endpoints:
  - addresses: ["${server_ipv4}"]
    conditions:
      ready: false
      serving: true
      terminating: false
    targetRef:
      kind: Pod
      namespace: backend
      name: server
    nodeName: ${server_node}
YAML
not_ready_snapshot=$(wait_for_current_topology "${controller}" \
    'any(.services[]; .reference == "backend/unf-topology-history-probe" and any(.backends[]; .ready == false and .serving == true))')
not_ready_revision=$(jq '.revision' <<<"${not_ready_snapshot}")

"${kc[@]}" apply -f - >/dev/null <<YAML
apiVersion: discovery.k8s.io/v1
kind: EndpointSlice
metadata:
  name: ${probe_slice}
  namespace: backend
  labels:
    kubernetes.io/service-name: ${probe_service}
addressType: IPv4
ports:
  - name: http
    protocol: TCP
    port: 8080
endpoints:
  - addresses: ["${server_ipv4}"]
    conditions:
      ready: true
      serving: true
      terminating: false
    targetRef:
      kind: Pod
      namespace: backend
      name: server
    nodeName: ${server_node}
YAML
ready_snapshot=$(wait_for_current_topology "${controller}" \
    'any(.services[]; .reference == "backend/unf-topology-history-probe" and any(.backends[]; .ready == true and .serving == true))')
ready_revision=$(jq '.revision' <<<"${ready_snapshot}")

"${kc[@]}" -n backend delete endpointslice "${probe_slice}" --wait=true >/dev/null
empty_backend_snapshot=$(wait_for_current_topology "${controller}" \
    'any(.services[]; .reference == "backend/unf-topology-history-probe" and (.backends | length) == 0)')
empty_backend_revision=$(jq '.revision' <<<"${empty_backend_snapshot}")
"${kc[@]}" -n backend delete service "${probe_service}" --wait=true >/dev/null
deleted_snapshot=$(wait_for_current_topology "${controller}" \
    'all(.services[]; .reference != "backend/unf-topology-history-probe")')
deleted_revision=$(jq '.revision' <<<"${deleted_snapshot}")
[[ ${service_revision} -lt ${not_ready_revision} ]]
[[ ${not_ready_revision} -lt ${ready_revision} ]]
[[ ${ready_revision} -lt ${empty_backend_revision} ]]
[[ ${empty_backend_revision} -lt ${deleted_revision} ]]
[[ $(controller_raw "${controller}" /v1/status | jq '.revisions.policy') -eq ${policy_revision} ]]

history=$("${unfctl}" --controller-url "http://127.0.0.1:${controller_port}" \
    --output json topology-history --since-revision "$((baseline_revision + 1))" \
    --since-unix-ms "${window_start}" --limit 32)
if ! jq -e \
    --argjson not_ready "${not_ready_revision}" \
    --argjson ready "${ready_revision}" \
    --argjson deleted "${deleted_revision}" '
    .schema_version == 1
    and .capacity == 32
    and .query.returned_snapshots >= 5
    and ([.entries[].snapshot.revision] == ([.entries[].snapshot.revision] | sort | reverse))
    and any(.entries[];
        .snapshot.revision == $not_ready
        and any(.snapshot.services[];
            .reference == "backend/unf-topology-history-probe"
            and any(.backends[]; .ready == false and .serving == true)))
    and any(.entries[];
        .snapshot.revision == $ready
        and any(.snapshot.services[];
            .reference == "backend/unf-topology-history-probe"
            and any(.backends[]; .ready == true and .serving == true)))
    and any(.entries[];
        .snapshot.revision == $deleted
        and all(.snapshot.services[];
            .reference != "backend/unf-topology-history-probe"))
' <<<"${history}" >/dev/null; then
    echo "bounded topology-history query did not retain the full probe lifecycle" >&2
    exit 1
fi

recent=$("${unfctl}" --controller-url "http://127.0.0.1:${controller_port}" \
    --output json topology-history --last 10m --limit 1)
jq -e '
    .query.since_unix_ms != null
    and .query.until_unix_ms != null
    and .query.limit == 1
    and .query.returned_snapshots == 1
    and .query.truncated == (.query.matched_snapshots > 1)
' <<<"${recent}" >/dev/null
"${unfctl}" --controller-url "http://127.0.0.1:${controller_port}" \
    topology-history --since-revision "${ready_revision}" --limit 2 \
    | grep -q '^Topology History$'

checkpoint_before=
for _ in {1..45}; do
    checkpoint_before=$(checkpoint 2>/dev/null || true)
    if jq -e --argjson ready "${ready_revision}" --argjson deleted "${deleted_revision}" '
        .schema_version == 1
        and any(.entries[];
            .snapshot.revision == $ready
            and any(.snapshot.services[];
                .reference == "backend/unf-topology-history-probe"
                and any(.backends[]; .ready == true)))
        and any(.entries[];
            .snapshot.revision == $deleted
            and all(.snapshot.services[];
                .reference != "backend/unf-topology-history-probe"))
    ' <<<"${checkpoint_before}" >/dev/null 2>&1; then
        break
    fi
    sleep 1
done
if ! jq -e --argjson ready "${ready_revision}" '
    any(.entries[]; .snapshot.revision == $ready)
' <<<"${checkpoint_before}" >/dev/null 2>&1; then
    echo "durable topology-history checkpoint did not retain the probe" >&2
    exit 1
fi
ready_capture=$(jq --argjson ready "${ready_revision}" '
    [.entries[] | select(.snapshot.revision == $ready) | .captured_at_unix_ms][0]
' <<<"${checkpoint_before}")

kill "${forward_pid}" >/dev/null 2>&1 || true
wait "${forward_pid}" >/dev/null 2>&1 || true
forward_pid=
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
[[ ${new_controller_uid} != "${controller_uid}" ]]

restored=$(controller_raw "${controller}" \
    "/v1/topology/history?since_revision=${ready_revision}&until_revision=${ready_revision}&limit=1")
if ! jq -e \
    --argjson ready "${ready_revision}" \
    --argjson capture "${ready_capture}" \
    --argjson epoch "${baseline_epoch}" '
    .durable_checkpointed_snapshots > 0
    and .query.returned_snapshots == 1
    and .entries[0].captured_at_unix_ms == $capture
    and .entries[0].snapshot.revision == $ready
    and .entries[0].snapshot.source_epoch == $epoch
    and any(.entries[0].snapshot.services[];
        .reference == "backend/unf-topology-history-probe"
        and any(.backends[]; .ready == true))
' <<<"${restored}" >/dev/null; then
    echo "controller restart did not restore the exact topology-history fence" >&2
    exit 1
fi
current=$(controller_raw "${controller}" /v1/topology)
[[ $(jq '.revision' <<<"${current}") -gt ${deleted_revision} ]]
metrics=$(controller_raw "${controller}" /metrics)
restored_total=$(awk '$1 == "unf_topology_history_entries_restored_total" { print int($2) }' \
    <<<"${metrics}")
errors=$(awk '$1 == "unf_topology_history_persistence_errors_total" { print int($2) }' \
    <<<"${metrics}")
[[ ${restored_total} -gt 0 ]]
[[ ${errors} -eq 0 ]]
logs=$("${kc[@]}" -n unf-system logs "${controller}")
grep -q 'restored durable topology history' <<<"${logs}"
[[ $(agent_runtime_state) == "${agent_state}" ]]

trap - EXIT
cleanup
echo "durable topology-history qualification passed: exact RBAC, semantic not-ready/ready/deleted revisions, combined time/revision bounds, newest-first limits, table output, checkpoint fencing, controller restart recovery, and zero agent replacements"
