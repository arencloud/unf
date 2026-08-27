#!/usr/bin/env bash
set -euo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
kubeconfig=${KUBECONFIG:-"${project_root}/.tools/kind-unf-dev.kubeconfig"}
context=${KUBE_CONTEXT:-kind-unf-dev}
baseline_controller_image=${UNF_UPGRADE_BASELINE_CONTROLLER_IMAGE:-localhost/unf-controller:upgrade-n}
baseline_agent_image=${UNF_UPGRADE_BASELINE_AGENT_IMAGE:-localhost/unf-agent:upgrade-n}
current_controller_image=${UNF_UPGRADE_CURRENT_CONTROLLER_IMAGE:-localhost/unf-controller:dev}
current_agent_image=${UNF_UPGRADE_CURRENT_AGENT_IMAGE:-localhost/unf-agent:dev}
current_revision=${UNF_UPGRADE_CURRENT_REVISION:-unknown}
kc=(kubectl --kubeconfig "${kubeconfig}" --context "${context}")
temporary_dir=$(mktemp -d)
probe_pid=

patch_controller_image() {
    local image=$1
    local payload
    payload=$(jq -nc --arg image "${image}" \
        '{spec:{template:{spec:{containers:[{name:"controller",image:$image}]}}}}')
    "${kc[@]}" -n unf-system patch deployment unf-controller \
        --type=strategic -p "${payload}" >/dev/null
    "${kc[@]}" -n unf-system rollout status deployment/unf-controller \
        --timeout=180s >/dev/null
}

patch_agent_image() {
    local image=$1
    local strategy=$2
    local payload
    if [[ ${strategy} == OnDelete ]]; then
        payload=$(jq -nc --arg image "${image}" \
            '{spec:{updateStrategy:{type:"OnDelete",rollingUpdate:null},template:{spec:{containers:[{name:"agent",image:$image}]}}}}')
    else
        payload=$(jq -nc --arg image "${image}" \
            '{spec:{updateStrategy:{type:"RollingUpdate",rollingUpdate:{maxUnavailable:1}},template:{spec:{containers:[{name:"agent",image:$image}]}}}}')
    fi
    "${kc[@]}" -n unf-system patch daemonset unf-agent \
        --type=strategic -p "${payload}" >/dev/null
    if [[ ${strategy} == RollingUpdate ]]; then
        "${kc[@]}" -n unf-system rollout status daemonset/unf-agent \
            --timeout=240s >/dev/null
    fi
}

stop_probe() {
    if [[ -n ${probe_pid} ]]; then
        if ! kill -0 "${probe_pid}" 2>/dev/null; then
            wait "${probe_pid}" 2>/dev/null || true
            probe_pid=
            cat "${temporary_dir}/traffic-probe.log" >&2
            echo "allow/deny continuity probe exited before the version transitions completed" >&2
            return 1
        fi
        "${kc[@]}" -n frontend exec client -- touch /tmp/unf-upgrade-stop \
            >/dev/null 2>&1 || true
        for _ in {1..30}; do
            if ! kill -0 "${probe_pid}" 2>/dev/null; then
                break
            fi
            sleep 1
        done
        if kill -0 "${probe_pid}" 2>/dev/null; then
            kill "${probe_pid}" 2>/dev/null || true
            wait "${probe_pid}" 2>/dev/null || true
            probe_pid=
            echo "allow/deny continuity probe did not stop within 30 seconds" >&2
            return 1
        fi
        wait "${probe_pid}" 2>/dev/null || true
        probe_pid=
        if ! "${kc[@]}" -n frontend exec client -- \
            test ! -s /tmp/unf-upgrade-breach >/dev/null 2>&1; then
            cat "${temporary_dir}/traffic-probe.log" >&2
            echo "allow/deny continuity failed during the version transition" >&2
            return 1
        fi
    fi
}

cleanup() {
    local exit_code=$?
    stop_probe || exit_code=1
    patch_controller_image "${current_controller_image}" >/dev/null 2>&1 || true
    patch_agent_image "${current_agent_image}" RollingUpdate >/dev/null 2>&1 || true
    rm -rf -- "${temporary_dir}"
    exit "${exit_code}"
}
trap cleanup EXIT

for command in kubectl jq awk; do
    command -v "${command}" >/dev/null
done
[[ -s ${kubeconfig} ]]
[[ ${baseline_controller_image} != "${current_controller_image}" ]]
[[ ${baseline_agent_image} != "${current_agent_image}" ]]
[[ ${current_revision} != unknown ]]

"${kc[@]}" wait --for=condition=Ready nodes --all --timeout=120s >/dev/null
[[ $("${kc[@]}" get nodes -o json | jq '.items | length') -eq 2 ]]
"${kc[@]}" -n frontend wait --for=condition=Ready pod/client --timeout=120s >/dev/null
"${kc[@]}" -n backend wait --for=condition=Ready pod/server --timeout=120s >/dev/null
server_node=$("${kc[@]}" -n backend get pod server -o jsonpath='{.spec.nodeName}')
other_node=$("${kc[@]}" get nodes -o json \
    | jq -r --arg server_node "${server_node}" '.items[].metadata.name | select(. != $server_node)' \
    | head -n 1)
[[ -n ${server_node} && -n ${other_node} ]]

controller_pod() {
    "${kc[@]}" -n unf-system get pods -l app.kubernetes.io/name=unf-controller -o json \
        | jq -r '.items[] | select(.metadata.deletionTimestamp == null and .status.phase == "Running") | .metadata.name' \
        | head -n 1
}

controller_raw() {
    local path=$1
    local pod
    pod=$(controller_pod)
    [[ -n ${pod} ]]
    "${kc[@]}" get --raw \
        "/api/v1/namespaces/unf-system/pods/${pod}:9962/proxy${path}"
}

agent_pod_on_node() {
    local node=$1
    "${kc[@]}" -n unf-system get pods -l app.kubernetes.io/name=unf-agent -o json \
        | jq -r --arg node "${node}" '
            .items[]
            | select(.spec.nodeName == $node and .metadata.deletionTimestamp == null)
            | .metadata.name
        ' \
        | head -n 1
}

agent_raw() {
    local node=$1
    local path=$2
    local pod
    pod=$(agent_pod_on_node "${node}")
    [[ -n ${pod} ]]
    "${kc[@]}" get --raw \
        "/api/v1/namespaces/unf-system/pods/${pod}:9963/proxy${path}"
}

metric() {
    local name=$1
    controller_raw /metrics \
        | awk -v metric_name="${name}" '$1 == metric_name { print int($2); found=1 } END { if (!found) print 0 }'
}

wait_for_convergence() {
    local snapshot=
    for _ in {1..120}; do
        snapshot=$(controller_raw /v1/state/agents 2>/dev/null || true)
        if jq -e '
            .expected_agents == 2
            and .reporting_agents == 2
            and .missing_agents == 0
            and .stale_agents == 0
            and .converged_agents == 2
            and .unexpected_agents == 0
            and .all_converged == true
            and all(.nodes[]; .fresh and .converged and .report.ready and .report.bpf_loaded)
        ' <<<"${snapshot}" >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    echo "agents did not converge for the active controller version" >&2
    jq . <<<"${snapshot}" >&2 || true
    return 1
}

wait_for_agent_replacement() {
    local node=$1
    local old_uid=$2
    local expected_image=$3
    local pod_json=
    for _ in {1..180}; do
        pod_json=$("${kc[@]}" -n unf-system get pods \
            -l app.kubernetes.io/name=unf-agent -o json 2>/dev/null || true)
        if jq -e --arg node "${node}" --arg uid "${old_uid}" --arg image "${expected_image}" '
            any(.items[];
                .spec.nodeName == $node
                and .metadata.uid != $uid
                and .metadata.deletionTimestamp == null
                and .spec.containers[0].image == $image
                and .status.phase == "Running"
                and any(.status.conditions[]?; .type == "Ready" and .status == "True"))
        ' <<<"${pod_json}" >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    echo "agent on ${node} did not become Ready with image ${expected_image}" >&2
    return 1
}

replace_agent_on_node() {
    local node=$1
    local expected_image=$2
    local pod old_uid
    pod=$(agent_pod_on_node "${node}")
    old_uid=$("${kc[@]}" -n unf-system get pod "${pod}" -o jsonpath='{.metadata.uid}')
    "${kc[@]}" -n unf-system delete pod "${pod}" --wait=false >/dev/null
    wait_for_agent_replacement "${node}" "${old_uid}" "${expected_image}"
}

assert_agent_image_counts() {
    local baseline_count=$1
    local current_count=$2
    local pods
    pods=$("${kc[@]}" -n unf-system get pods -l app.kubernetes.io/name=unf-agent -o json)
    [[ $(jq --arg image "${baseline_agent_image}" \
        '[.items[] | select(.metadata.deletionTimestamp == null and .spec.containers[0].image == $image)] | length' \
        <<<"${pods}") -eq ${baseline_count} ]]
    [[ $(jq --arg image "${current_agent_image}" \
        '[.items[] | select(.metadata.deletionTimestamp == null and .spec.containers[0].image == $image)] | length' \
        <<<"${pods}") -eq ${current_count} ]]
}

assert_current_version() {
    local json=$1
    local component=$2
    jq -e --arg component "${component}" --arg revision "${current_revision}" '
        .schema_version == 1
        and .component == $component
        and (.software_version | strings | length) > 0
        and .build_revision == $revision
        and .persistent_bpf_state_abi_version == 3
        and .identity_snapshot_schema_version == 2
        and .policy_snapshot_schema_version == 4
        and .agent_status_schema_version == 2
        and .flow_export_schema_version == 3
    ' <<<"${json}" >/dev/null
}

compatibility_tuple() {
    jq -c '[
        .schema_version,
        .persistent_bpf_state_abi_version,
        .identity_snapshot_schema_version,
        .policy_snapshot_schema_version,
        .agent_status_schema_version,
        .flow_export_schema_version
    ]'
}

assert_current_agent_state() {
    local node=$1
    local status
    assert_current_version "$(agent_raw "${node}" /v1/version)" unf-agent
    status=$(agent_raw "${node}" /v1/status)
    jq -e '
        .ready
        and .bpf_loaded
        and .desired_identity_revision == .applied_identity_revision
        and .desired_policy_revision == .applied_policy_revision
        and .desired_identity_epoch == .applied_identity_epoch
        and .desired_policy_epoch == .applied_policy_epoch
        and .identity_map_entries > 0
        and .policy_map_entries > 0
        and (.tc_attachment_mode == "tcx_pinned" or .tc_attachment_mode == "legacy_netlink")
    ' <<<"${status}" >/dev/null
}

emit_and_require_telemetry() {
    local baseline
    baseline=$(metric unf_telemetry_observations_total)
    for _ in {1..12}; do
        "${kc[@]}" -n frontend exec client -- \
            wget -qO- --timeout=2 http://server.backend.svc.cluster.local:8080 >/dev/null
    done
    for _ in {1..45}; do
        if [[ $(metric unf_telemetry_observations_total) -gt ${baseline} ]]; then
            return 0
        fi
        sleep 1
    done
    echo "flow telemetry did not advance across the active version pairing" >&2
    return 1
}

start_probe() {
    "${kc[@]}" -n frontend exec client -- \
        rm -f /tmp/unf-upgrade-stop /tmp/unf-upgrade-breach >/dev/null
    "${kc[@]}" -n frontend exec client -- sh -c '
        while [ ! -e /tmp/unf-upgrade-stop ]; do
            if ! timeout 3 wget -qO- --timeout=1 --tries=1 http://server.backend.svc.cluster.local:8080 >/dev/null; then
                echo allow-outage >>/tmp/unf-upgrade-breach
            fi
            if timeout 3 wget -qO- --timeout=1 --tries=1 http://server.backend.svc.cluster.local:9090 >/dev/null 2>&1; then
                echo deny-breach >>/tmp/unf-upgrade-breach
            fi
            sleep 0.2
        done
        test ! -s /tmp/unf-upgrade-breach
    ' >"${temporary_dir}/traffic-probe.log" 2>&1 &
    probe_pid=$!
    sleep 2
    kill -0 "${probe_pid}"
}

start_probe

# Establish N/N from the adjacent committed baseline.
patch_controller_image "${baseline_controller_image}"
patch_agent_image "${baseline_agent_image}" RollingUpdate
assert_agent_image_counts 2 0
wait_for_convergence
emit_and_require_telemetry
baseline_tuple=
if baseline_version=$(controller_raw /v1/version 2>/dev/null); then
    baseline_tuple=$(compatibility_tuple <<<"${baseline_version}")
    for node in "${server_node}" "${other_node}"; do
        agent_baseline_tuple=$(agent_raw "${node}" /v1/version | compatibility_tuple)
        [[ ${agent_baseline_tuple} == "${baseline_tuple}" ]]
    done
fi

# Upgrade the controller first: controller N+1 must serve agent N.
patch_controller_image "${current_controller_image}"
current_controller_version=$(controller_raw /v1/version)
assert_current_version "${current_controller_version}" unf-controller
if [[ -n ${baseline_tuple} ]]; then
    [[ $(compatibility_tuple <<<"${current_controller_version}") == "${baseline_tuple}" ]]
fi
assert_agent_image_counts 2 0
wait_for_convergence
emit_and_require_telemetry

# Hold the DaemonSet on delete so the mixed N/N+1 agent state is deterministic.
patch_agent_image "${current_agent_image}" OnDelete
replace_agent_on_node "${server_node}" "${current_agent_image}"
assert_agent_image_counts 1 1
wait_for_convergence
assert_current_agent_state "${server_node}"
emit_and_require_telemetry

replace_agent_on_node "${other_node}" "${current_agent_image}"
assert_agent_image_counts 0 2
wait_for_convergence
assert_current_agent_state "${server_node}"
assert_current_agent_state "${other_node}"
emit_and_require_telemetry

# Roll one dataplane node back to N, then forward again without changing the controller.
patch_agent_image "${baseline_agent_image}" OnDelete
replace_agent_on_node "${server_node}" "${baseline_agent_image}"
assert_agent_image_counts 1 1
wait_for_convergence
emit_and_require_telemetry
patch_agent_image "${current_agent_image}" OnDelete
replace_agent_on_node "${server_node}" "${current_agent_image}"
assert_agent_image_counts 0 2
wait_for_convergence
assert_current_agent_state "${server_node}"

# Roll the controller back while agents remain N+1, then complete forward recovery.
patch_controller_image "${baseline_controller_image}"
assert_agent_image_counts 0 2
wait_for_convergence
emit_and_require_telemetry
patch_controller_image "${current_controller_image}"
assert_current_version "$(controller_raw /v1/version)" unf-controller
wait_for_convergence
assert_current_agent_state "${server_node}"
assert_current_agent_state "${other_node}"
emit_and_require_telemetry

patch_agent_image "${current_agent_image}" RollingUpdate
stop_probe
trap - EXIT
rm -rf -- "${temporary_dir}"

echo "Kind upgrade qualification passed: observable schema/ABI build metadata, N/N baseline, controller-first N+1/N compatibility, deterministic one-node mixed agent rollout, full N+1 convergence, agent rollback/forward recovery, controller rollback with N+1 agents, uninterrupted allow/deny enforcement, and telemetry continuity"
