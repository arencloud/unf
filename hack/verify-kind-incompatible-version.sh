#!/usr/bin/env bash
set -euo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
kubeconfig=${KUBECONFIG:-"${project_root}/.tools/kind-unf-dev.kubeconfig"}
context=${KUBE_CONTEXT:-kind-unf-dev}
current_controller_image=${UNF_CURRENT_CONTROLLER_IMAGE:-localhost/unf-controller:dev}
current_agent_image=${UNF_CURRENT_AGENT_IMAGE:-localhost/unf-agent:dev}
incompatible_controller_image=${UNF_INCOMPATIBLE_CONTROLLER_IMAGE:-localhost/unf-controller:incompatible-tuple}
incompatible_agent_image=${UNF_INCOMPATIBLE_AGENT_IMAGE:-localhost/unf-agent:incompatible-tuple}
current_revision=${UNF_CURRENT_REVISION:-unknown}
kc=(kubectl --kubeconfig "${kubeconfig}" --context "${context}")
temporary_dir=$(mktemp -d)
probe_pid=
helper_created=false

patch_controller_image() {
    local image=$1 payload
    payload=$(jq -nc --arg image "${image}" \
        '{spec:{template:{spec:{containers:[{name:"controller",image:$image}]}}}}')
    "${kc[@]}" -n unf-system patch deployment unf-controller \
        --type=strategic -p "${payload}" >/dev/null
    "${kc[@]}" -n unf-system rollout status deployment/unf-controller \
        --timeout=180s >/dev/null
}

patch_agent_image() {
    local image=$1 strategy=$2 payload
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
    if [[ -z ${probe_pid} ]]; then
        return 0
    fi
    if ! kill -0 "${probe_pid}" 2>/dev/null; then
        wait "${probe_pid}" 2>/dev/null || true
        probe_pid=
        cat "${temporary_dir}/traffic-probe.log" >&2
        echo "allow/deny continuity probe exited before compatibility recovery" >&2
        return 1
    fi
    "${kc[@]}" -n frontend exec client -- touch /tmp/unf-version-stop \
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
        test ! -s /tmp/unf-version-breach >/dev/null 2>&1; then
        cat "${temporary_dir}/traffic-probe.log" >&2
        echo "allow/deny enforcement changed during incompatible-version rejection" >&2
        return 1
    fi
}

cleanup() {
    local exit_code=$?
    stop_probe || exit_code=1
    patch_controller_image "${current_controller_image}" >/dev/null 2>&1 || true
    patch_agent_image "${current_agent_image}" RollingUpdate >/dev/null 2>&1 || true
    if [[ ${helper_created} == true ]]; then
        "${kc[@]}" delete -f "${project_root}/deploy/examples/bpf-fault-helper.yaml" \
            --ignore-not-found >/dev/null 2>&1 || true
    fi
    rm -rf -- "${temporary_dir}"
    exit "${exit_code}"
}
trap cleanup EXIT

for command in kubectl jq awk sha256sum; do
    command -v "${command}" >/dev/null
done
[[ -s ${kubeconfig} ]]
[[ ${current_revision} != unknown ]]
[[ ${current_controller_image} != "${incompatible_controller_image}" ]]
[[ ${current_agent_image} != "${incompatible_agent_image}" ]]

controller_pod() {
    "${kc[@]}" -n unf-system get pods -l app.kubernetes.io/name=unf-controller -o json \
        | jq -r '.items[] | select(.metadata.deletionTimestamp == null and .status.phase == "Running") | .metadata.name' \
        | head -n 1
}

controller_raw() {
    local pod path=$1
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
        ' | head -n 1
}

agent_raw() {
    local node=$1 path=$2 pod
    pod=$(agent_pod_on_node "${node}")
    [[ -n ${pod} ]]
    "${kc[@]}" get --raw \
        "/api/v1/namespaces/unf-system/pods/${pod}:9963/proxy${path}"
}

agent_metric() {
    local node=$1 metric=$2
    agent_raw "${node}" /metrics \
        | awk -v metric_name="${metric}" '$1 == metric_name { print int($2); found=1 } END { if (!found) print 0 }'
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
    echo "agents did not converge after compatible-version recovery" >&2
    jq . <<<"${snapshot}" >&2 || true
    return 1
}

helper_pod_on_node() {
    local node=$1
    "${kc[@]}" -n unf-system get pods \
        -l app.kubernetes.io/name=unf-bpf-fault-helper -o json \
        | jq -r --arg node "${node}" '
            .items[]
            | select(.spec.nodeName == $node and .metadata.deletionTimestamp == null)
            | .metadata.name
        ' | head -n 1
}

map_digest() {
    local node=$1 scope=$2 helper map
    local -a maps=(POLICY_RULES POLICY_IPV4 POLICY_IPV6 EGRESS_IPV4 EGRESS_IPV6 POLICY_CONFIG)
    if [[ ${scope} == persistent ]]; then
        maps=(IDENTITY_V4 IDENTITY_V4_B IDENTITY_V6 IDENTITY_V6_B IDENTITY_CONFIG "${maps[@]}"
            SERVICE_FRONTENDS_V4 SERVICE_FRONTENDS_V6 SERVICE_BACKENDS_V4
            SERVICE_BACKENDS_V6 SERVICE_BACKEND_SLOTS SERVICE_CONFIG SERVICE_CONNECTIONS)
    fi
    helper=$(helper_pod_on_node "${node}")
    [[ -n ${helper} ]]
    {
        for map in "${maps[@]}"; do
            printf '%s\n' "${map}"
            "${kc[@]}" -n unf-system exec "${helper}" -- \
                bpftool -j map dump pinned "/sys/fs/bpf/unf/v4/${map}" \
                | jq -Sc 'sort_by(.key | tostring)'
        done
    } | sha256sum | awk '{print $1}'
}

policy_fingerprint() {
    local node=$1
    agent_raw "${node}" /v1/status | jq -cS '{
        desired_policy_revision,
        applied_policy_revision,
        desired_policy_epoch,
        applied_policy_epoch,
        policy_map_entries,
        active_policy_bank
    }'
}

assert_equal() {
    local actual=$1 expected=$2 message=$3
    if [[ ${actual} != "${expected}" ]]; then
        echo "${message}" >&2
        printf 'expected: %s\nactual:   %s\n' "${expected}" "${actual}" >&2
        return 1
    fi
}

wait_for_agent_pod() {
    local node=$1 old_uid=$2 image=$3 require_ready=$4 pod_json=
    for _ in {1..180}; do
        pod_json=$("${kc[@]}" -n unf-system get pods \
            -l app.kubernetes.io/name=unf-agent -o json 2>/dev/null || true)
        if jq -e --arg node "${node}" --arg uid "${old_uid}" --arg image "${image}" \
            --argjson ready "${require_ready}" '
            any(.items[];
                .spec.nodeName == $node
                and .metadata.uid != $uid
                and .metadata.deletionTimestamp == null
                and .spec.containers[0].image == $image
                and (($ready | not) or any(.status.conditions[]?;
                    .type == "Ready" and .status == "True")))
        ' <<<"${pod_json}" >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    echo "agent on ${node} did not transition to ${image}" >&2
    return 1
}

replace_agent_on_node() {
    local node=$1 image=$2 require_ready=$3 pod old_uid
    pod=$(agent_pod_on_node "${node}")
    old_uid=$("${kc[@]}" -n unf-system get pod "${pod}" -o jsonpath='{.metadata.uid}')
    "${kc[@]}" -n unf-system delete pod "${pod}" --wait=false >/dev/null
    wait_for_agent_pod "${node}" "${old_uid}" "${image}" "${require_ready}"
}

wait_for_incompatible_agent_rejection() {
    local node=$1 pod logs=
    for _ in {1..120}; do
        pod=$(agent_pod_on_node "${node}")
        if [[ -n ${pod} ]]; then
            logs=$("${kc[@]}" -n unf-system logs "${pod}" --all-containers=true \
                --tail=-1 2>&1 || true)
            if grep -Fq "configured BPF pin path" <<<"${logs}" \
                && grep -Fq "incompatible with persistent BPF-state ABI" <<<"${logs}" \
                && grep -Fq "expected a /v${incompatible_abi} directory" <<<"${logs}"; then
                return 0
            fi
        fi
        sleep 1
    done
    echo "incompatible agent did not report the expected pre-BPF ABI rejection" >&2
    printf '%s\n' "${logs}" >&2
    return 1
}

wait_for_policy_rejection() {
    local node=$1 baseline_errors=$2
    for _ in {1..60}; do
        if [[ $(agent_metric "${node}" unf_policy_sync_errors_total) -gt ${baseline_errors} ]]; then
            return 0
        fi
        sleep 1
    done
    echo "agent on ${node} did not count the incompatible policy snapshot rejection" >&2
    return 1
}

start_probe() {
    "${kc[@]}" -n frontend exec client -- \
        rm -f /tmp/unf-version-stop /tmp/unf-version-breach >/dev/null
    "${kc[@]}" -n frontend exec client -- sh -c '
        while [ ! -e /tmp/unf-version-stop ]; do
            if ! timeout 3 wget -qO- --timeout=1 --tries=1 http://server.backend.svc.cluster.local:8080 >/dev/null; then
                echo allow-outage >>/tmp/unf-version-breach
            fi
            if timeout 3 wget -qO- --timeout=1 --tries=1 http://server.backend.svc.cluster.local:9090 >/dev/null 2>&1; then
                echo deny-breach >>/tmp/unf-version-breach
            fi
            sleep 0.2
        done
        test ! -s /tmp/unf-version-breach
    ' >"${temporary_dir}/traffic-probe.log" 2>&1 &
    probe_pid=$!
    sleep 2
    kill -0 "${probe_pid}"
}

"${kc[@]}" wait --for=condition=Ready nodes --all --timeout=120s >/dev/null
[[ $("${kc[@]}" get nodes -o json | jq '.items | length') -eq 2 ]]
"${kc[@]}" -n frontend wait --for=condition=Ready pod/client --timeout=120s >/dev/null
"${kc[@]}" -n backend wait --for=condition=Ready pod/server --timeout=120s >/dev/null
wait_for_convergence

normal_version=$(controller_raw /v1/version)
jq -e --arg revision "${current_revision}" '
    .schema_version == 1
    and .component == "unf-controller"
    and .build_revision == $revision
' <<<"${normal_version}" >/dev/null
normal_abi=$(jq '.persistent_bpf_state_abi_version' <<<"${normal_version}")
normal_policy_schema=$(jq '.policy_snapshot_schema_version' <<<"${normal_version}")
incompatible_abi=$((normal_abi + 1))
incompatible_policy_schema=$((normal_policy_schema + 1))

"${kc[@]}" apply -f "${project_root}/deploy/examples/bpf-fault-helper.yaml" >/dev/null
helper_created=true
"${kc[@]}" -n unf-system rollout status daemonset/unf-bpf-fault-helper \
    --timeout=120s >/dev/null
wait_for_convergence

mapfile -t nodes < <("${kc[@]}" get nodes -o json | jq -r '.items[].metadata.name' | sort)
[[ ${#nodes[@]} -eq 2 ]]
server_node=$("${kc[@]}" -n backend get pod server -o jsonpath='{.spec.nodeName}')
[[ -n ${server_node} ]]

declare -A persistent_before
for node in "${nodes[@]}"; do
    persistent_before[${node}]=$(map_digest "${node}" persistent)
done
start_probe

# A new incompatible agent must fail before opening or adopting persistent maps.
patch_agent_image "${incompatible_agent_image}" OnDelete
replace_agent_on_node "${server_node}" "${incompatible_agent_image}" false
wait_for_incompatible_agent_rejection "${server_node}"
assert_equal "$(map_digest "${server_node}" persistent)" \
    "${persistent_before[${server_node}]}" \
    "incompatible agent changed persistent maps on ${server_node} before rejection"

patch_agent_image "${current_agent_image}" OnDelete
replace_agent_on_node "${server_node}" "${current_agent_image}" true
patch_agent_image "${current_agent_image}" RollingUpdate
wait_for_convergence

# A live incompatible controller may cause the old compatible controller to
# observe rollout topology before termination. Establish the mutation window
# only after the first incompatible snapshot is rejected, then require another
# rejection without desired state, staging, or bank commit.
declare -A policy_before policy_digest_before error_before
for node in "${nodes[@]}"; do
    error_before[${node}]=$(agent_metric "${node}" unf_policy_sync_errors_total)
done

patch_controller_image "${incompatible_controller_image}"
incompatible_version=$(controller_raw /v1/version)
jq -e --argjson abi "${incompatible_abi}" --argjson policy "${incompatible_policy_schema}" '
    .schema_version == 1
    and .component == "unf-controller"
    and .persistent_bpf_state_abi_version == $abi
    and .policy_snapshot_schema_version == $policy
' <<<"${incompatible_version}" >/dev/null

for node in "${nodes[@]}"; do
    wait_for_policy_rejection "${node}" "${error_before[${node}]}"
    policy_before[${node}]=$(policy_fingerprint "${node}")
    policy_digest_before[${node}]=$(map_digest "${node}" policy)
    error_before[${node}]=$(agent_metric "${node}" unf_policy_sync_errors_total)
done

for node in "${nodes[@]}"; do
    wait_for_policy_rejection "${node}" "${error_before[${node}]}"
    assert_equal "$(policy_fingerprint "${node}")" "${policy_before[${node}]}" \
        "incompatible policy schema changed agent policy state on ${node}"
    assert_equal "$(map_digest "${node}" policy)" "${policy_digest_before[${node}]}" \
        "incompatible policy schema changed pinned policy maps on ${node}"
    pod=$(agent_pod_on_node "${node}")
    logs=$("${kc[@]}" -n unf-system logs "${pod}" --tail=-1 --since=2m 2>&1 || true)
    grep -Fq "unsupported policy snapshot schema ${incompatible_policy_schema}; expected ${normal_policy_schema}" \
        <<<"${logs}"
done

patch_controller_image "${current_controller_image}"
wait_for_convergence
stop_probe
patch_agent_image "${current_agent_image}" RollingUpdate
"${kc[@]}" delete -f "${project_root}/deploy/examples/bpf-fault-helper.yaml" >/dev/null
helper_created=false

trap - EXIT
rm -rf -- "${temporary_dir}"

echo "Kind incompatible-version qualification passed: exact tuple mismatch was observable, incompatible agent ABI/schema startup stopped before persistent BPF access, live policy-schema snapshots were rejected before desired/staging/active-bank mutation, pinned enforcement remained uninterrupted, and the current tuple reconverged"
