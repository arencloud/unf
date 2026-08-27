#!/usr/bin/env bash
set -euo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
kubeconfig=${KUBECONFIG:-"${project_root}/.tools/kind-unf-dev.kubeconfig"}
context=${KUBE_CONTEXT:-kind-unf-dev}
current_controller_image=${UNF_CURRENT_CONTROLLER_IMAGE:-localhost/unf-controller:dev}
current_agent_image=${UNF_CURRENT_AGENT_IMAGE:-localhost/unf-agent:dev}
future_controller_image=${UNF_CLEAN_REBUILD_CONTROLLER_IMAGE:-localhost/unf-controller:clean-rebuild-abi4}
future_agent_image=${UNF_CLEAN_REBUILD_AGENT_IMAGE:-localhost/unf-agent:clean-rebuild-abi4}
current_revision=${UNF_CURRENT_REVISION:-unknown}
require_unsupported_downgrade=${UNF_REQUIRE_UNSUPPORTED_DOWNGRADE:-false}
kc=(kubectl --kubeconfig "${kubeconfig}" --context "${context}")
temporary_dir=$(mktemp -d)
probe_pid=
helper_created=false
cleanup_pods=()
downgrade_result=
map_names=(
    IDENTITY_V4 IDENTITY_V4_B IDENTITY_V6 IDENTITY_V6_B IDENTITY_CONFIG
    POLICY_RULES POLICY_IPV4 POLICY_IPV6 EGRESS_IPV4 EGRESS_IPV6 POLICY_CONFIG
)

patch_controller_image() {
    local image=$1 payload
    payload=$(jq -nc --arg image "${image}" \
        '{spec:{template:{spec:{containers:[{name:"controller",image:$image}]}}}}')
    "${kc[@]}" -n unf-system patch deployment unf-controller \
        --type=strategic -p "${payload}" >/dev/null
    "${kc[@]}" -n unf-system rollout status deployment/unf-controller \
        --timeout=180s >/dev/null
}

patch_agent_template() {
    local image=$1 abi=$2 strategy=$3 payload
    payload=$(jq -nc --arg image "${image}" --arg path "/sys/fs/bpf/unf/v${abi}" \
        --arg strategy "${strategy}" '{
            spec:{
                updateStrategy:(if $strategy == "OnDelete" then
                    {type:"OnDelete",rollingUpdate:null}
                else
                    {type:"RollingUpdate",rollingUpdate:{maxUnavailable:1}}
                end),
                template:{spec:{containers:[{
                    name:"agent",
                    image:$image,
                    args:[
                        "--listen","0.0.0.0:9963","--all-interfaces",
                        "--ebpf-object","/opt/unf/ebpf/unf-ebpf-tc",
                        "--bpf-pin-path",$path,
                        "--controller-url","https://unf-controller.unf-system.svc.cluster.local:9964",
                        "--controller-ca-path","/var/run/secrets/unf-internal-ca/ca.crt"
                    ]
                }]}}
            }
        }')
    "${kc[@]}" -n unf-system patch daemonset unf-agent \
        --type=strategic -p "${payload}" >/dev/null
    if [[ ${strategy} == RollingUpdate ]]; then
        "${kc[@]}" -n unf-system rollout status daemonset/unf-agent \
            --timeout=240s >/dev/null
    fi
}

controller_pod() {
    "${kc[@]}" -n unf-system get pods -l app.kubernetes.io/name=unf-controller -o json \
        | jq -r '.items[] | select(.metadata.deletionTimestamp == null and .status.phase == "Running") | .metadata.name' \
        | head -n 1
}

controller_raw() {
    local path=$1 pod
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

wait_for_convergence() {
    local snapshot=
    for _ in {1..150}; do
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
    echo "agents did not converge during the clean-rebuild transition" >&2
    jq . <<<"${snapshot}" >&2 || true
    return 1
}

wait_for_agent_replacement() {
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
    echo "agent on ${node} did not become Ready with image ${image}" >&2
    return 1
}

replace_agent_on_node() {
    local node=$1 image=$2 require_ready=${3:-true} pod old_uid
    pod=$(agent_pod_on_node "${node}")
    old_uid=$("${kc[@]}" -n unf-system get pod "${pod}" -o jsonpath='{.metadata.uid}')
    "${kc[@]}" -n unf-system delete pod "${pod}" --wait=false >/dev/null
    wait_for_agent_replacement "${node}" "${old_uid}" "${image}" "${require_ready}"
}

assert_agent_state() {
    local node=$1 abi=$2 status version
    version=$(agent_raw "${node}" /v1/version)
    jq -e --argjson abi "${abi}" '
        .schema_version == 1
        and .component == "unf-agent"
        and .persistent_bpf_state_abi_version == $abi
        and .identity_snapshot_schema_version == 2
        and .policy_snapshot_schema_version == 4
        and .agent_status_schema_version == 2
        and .flow_export_schema_version == 3
    ' <<<"${version}" >/dev/null
    status=$(agent_raw "${node}" /v1/status)
    jq -e '
        .ready and .bpf_loaded
        and .desired_identity_revision == .applied_identity_revision
        and .desired_policy_revision == .applied_policy_revision
        and .desired_identity_epoch == .applied_identity_epoch
        and .desired_policy_epoch == .applied_policy_epoch
        and .identity_map_entries > 0
        and .policy_map_entries > 0
        and .tc_attachment_mode == "tcx_pinned"
    ' <<<"${status}" >/dev/null
}

assert_abi_present() {
    local node=$1 abi=$2 helper map link_count
    helper=$(helper_pod_on_node "${node}")
    [[ -n ${helper} ]]
    for map in "${map_names[@]}"; do
        "${kc[@]}" -n unf-system exec "${helper}" -- \
            test -e "/sys/fs/bpf/unf/v${abi}/${map}"
    done
    link_count=$("${kc[@]}" -n unf-system exec "${helper}" -- sh -c \
        "find /sys/fs/bpf/unf/v${abi}/links -mindepth 1 -maxdepth 1 | wc -l")
    [[ ${link_count} -gt 0 ]]
}

assert_abi_absent() {
    local node=$1 abi=$2 helper
    helper=$(helper_pod_on_node "${node}")
    [[ -n ${helper} ]]
    "${kc[@]}" -n unf-system exec "${helper}" -- \
        test ! -e "/sys/fs/bpf/unf/v${abi}"
}

map_digest() {
    local node=$1 abi=$2 helper map
    helper=$(helper_pod_on_node "${node}")
    [[ -n ${helper} ]]
    {
        for map in "${map_names[@]}"; do
            printf '%s\n' "${map}"
            "${kc[@]}" -n unf-system exec "${helper}" -- \
                bpftool -j map dump pinned "/sys/fs/bpf/unf/v${abi}/${map}" \
                | jq -Sc 'sort_by(.key | tostring)'
        done
    } | sha256sum | awk '{print $1}'
}

assert_prepopulation_log() {
    local node=$1 pod logs=
    pod=$(agent_pod_on_node "${node}")
    for _ in {1..30}; do
        logs=$("${kc[@]}" -n unf-system logs "${pod}" --tail=-1 2>&1 || true)
        if grep -Fq "fresh persistent BPF state populated before attachment" <<<"${logs}"; then
            return 0
        fi
        sleep 1
    done
    echo "agent on ${node} did not report pre-attachment population" >&2
    printf '%s\n' "${logs}" >&2
    return 1
}

wait_for_unsupported_downgrade_rejection() {
    local node=$1 current_abi=$2 future_abi=$3 pod logs=
    for _ in {1..90}; do
        pod=$(agent_pod_on_node "${node}")
        if [[ -n ${pod} ]]; then
            logs=$("${kc[@]}" -n unf-system logs "${pod}" --all-containers=true \
                --tail=-1 2>&1 || true)
            if grep -Fq "configured BPF pin path /sys/fs/bpf/unf/v${future_abi}" <<<"${logs}" \
                && grep -Fq "incompatible with persistent BPF-state ABI v${current_abi}" <<<"${logs}" \
                && grep -Fq "expected a /v${current_abi} directory" <<<"${logs}"; then
                return 0
            fi
        fi
        sleep 1
    done
    echo "unsupported downgrade did not fail at the local ABI boundary on ${node}" >&2
    printf '%s\n' "${logs}" >&2
    return 1
}

cleanup_older_abi_from_agent() {
    local node=$1 abi=$2 pod output
    pod=$(agent_pod_on_node "${node}")
    output=$("${kc[@]}" -n unf-system exec "${pod}" -- \
        /usr/local/bin/unf-component cleanup \
        --bpf-root /sys/fs/bpf/unf --abi-version "${abi}" --execute)
    grep -Fq "UNF cleanup completed" <<<"${output}"
}

run_scoped_cleanup_pod() {
    local node=$1 abi=$2 name payload output
    name="unf-clean-abi-${abi}-$(tr -cd 'a-z0-9' <<<"${node}" | tail -c 24)"
    cleanup_pods+=("${name}")
    payload=$(jq -nc --arg name "${name}" --arg node "${node}" \
        --arg image "${future_agent_image}" --arg abi "${abi}" '{
            apiVersion:"v1",kind:"Pod",
            metadata:{name:$name,namespace:"unf-system",labels:{"app.kubernetes.io/name":"unf-abi-cleanup"}},
            spec:{
                nodeName:$node,restartPolicy:"Never",automountServiceAccountToken:false,
                containers:[{
                    name:"cleanup",image:$image,imagePullPolicy:"Never",
                    args:["cleanup","--bpf-root","/sys/fs/bpf/unf","--abi-version",$abi,"--allow-current-abi","--execute"],
                    securityContext:{privileged:true},
                    volumeMounts:[{name:"bpffs",mountPath:"/sys/fs/bpf"}]
                }],
                volumes:[{name:"bpffs",hostPath:{path:"/sys/fs/bpf",type:"Directory"}}]
            }
        }')
    printf '%s\n' "${payload}" | "${kc[@]}" create -f - >/dev/null
    for _ in {1..90}; do
        phase=$("${kc[@]}" -n unf-system get pod "${name}" \
            -o jsonpath='{.status.phase}' 2>/dev/null || true)
        if [[ ${phase} == Succeeded ]]; then
            output=$("${kc[@]}" -n unf-system logs "${name}")
            grep -Fq "UNF cleanup completed" <<<"${output}"
            "${kc[@]}" -n unf-system delete pod "${name}" --wait=true >/dev/null
            return 0
        fi
        if [[ ${phase} == Failed ]]; then
            "${kc[@]}" -n unf-system logs "${name}" >&2 || true
            return 1
        fi
        sleep 1
    done
    echo "scoped ABI cleanup pod ${name} did not complete" >&2
    return 1
}

start_probe() {
    "${kc[@]}" -n frontend exec client -- \
        rm -f /tmp/unf-rebuild-stop /tmp/unf-rebuild-breach >/dev/null
    "${kc[@]}" -n frontend exec client -- sh -c '
        while [ ! -e /tmp/unf-rebuild-stop ]; do
            if ! timeout 3 wget -qO- --timeout=1 --tries=1 http://server.backend.svc.cluster.local:8080 >/dev/null; then
                echo allow-outage >>/tmp/unf-rebuild-breach
            fi
            if timeout 3 wget -qO- --timeout=1 --tries=1 http://server.backend.svc.cluster.local:9090 >/dev/null 2>&1; then
                echo deny-breach >>/tmp/unf-rebuild-breach
            fi
            sleep 0.2
        done
        test ! -s /tmp/unf-rebuild-breach
    ' >"${temporary_dir}/traffic-probe.log" 2>&1 &
    probe_pid=$!
    sleep 2
    kill -0 "${probe_pid}"
}

stop_probe() {
    if [[ -z ${probe_pid} ]]; then
        return 0
    fi
    if ! kill -0 "${probe_pid}" 2>/dev/null; then
        wait "${probe_pid}" 2>/dev/null || true
        probe_pid=
        cat "${temporary_dir}/traffic-probe.log" >&2
        echo "allow/deny continuity probe exited before clean-rebuild recovery" >&2
        return 1
    fi
    "${kc[@]}" -n frontend exec client -- touch /tmp/unf-rebuild-stop \
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
        echo "allow/deny continuity probe did not stop" >&2
        return 1
    fi
    wait "${probe_pid}" 2>/dev/null || true
    probe_pid=
    if ! "${kc[@]}" -n frontend exec client -- \
        test ! -s /tmp/unf-rebuild-breach >/dev/null 2>&1; then
        cat "${temporary_dir}/traffic-probe.log" >&2
        echo "allow/deny enforcement changed during the clean rebuild" >&2
        return 1
    fi
}

cleanup() {
    local exit_code=$? node
    stop_probe || exit_code=1
    patch_controller_image "${current_controller_image}" >/dev/null 2>&1 || true
    patch_agent_template "${current_agent_image}" 3 RollingUpdate >/dev/null 2>&1 || true
    if [[ -s ${kubeconfig} ]]; then
        while read -r node; do
            [[ -n ${node} ]] || continue
            run_scoped_cleanup_pod "${node}" 4 >/dev/null 2>&1 || true
        done < <("${kc[@]}" get nodes -o name 2>/dev/null | sed 's#node/##')
    fi
    for pod in "${cleanup_pods[@]}"; do
        "${kc[@]}" -n unf-system delete pod "${pod}" --ignore-not-found \
            --wait=false >/dev/null 2>&1 || true
    done
    if [[ ${helper_created} == true ]]; then
        "${kc[@]}" delete -f "${project_root}/deploy/examples/bpf-fault-helper.yaml" \
            --ignore-not-found >/dev/null 2>&1 || true
    fi
    rm -rf -- "${temporary_dir}"
    exit "${exit_code}"
}
trap cleanup EXIT

for command in kubectl jq grep sed tr awk sha256sum; do
    command -v "${command}" >/dev/null
done
[[ -s ${kubeconfig} ]]
[[ ${current_revision} != unknown ]]
[[ ${current_controller_image} != "${future_controller_image}" ]]
[[ ${current_agent_image} != "${future_agent_image}" ]]
[[ ${require_unsupported_downgrade} == true || ${require_unsupported_downgrade} == false ]]

"${kc[@]}" wait --for=condition=Ready nodes --all --timeout=120s >/dev/null
[[ $("${kc[@]}" get nodes -o json | jq '.items | length') -eq 2 ]]
"${kc[@]}" -n frontend wait --for=condition=Ready pod/client --timeout=120s >/dev/null
"${kc[@]}" -n backend wait --for=condition=Ready pod/server --timeout=120s >/dev/null
wait_for_convergence

current_version=$(controller_raw /v1/version)
current_abi=$(jq '.persistent_bpf_state_abi_version' <<<"${current_version}")
future_abi=$((current_abi + 1))
[[ ${current_abi} -eq 3 ]]
jq -e --arg revision "${current_revision}" '
    .schema_version == 1
    and .component == "unf-controller"
    and .build_revision == $revision
' <<<"${current_version}" >/dev/null

"${kc[@]}" apply -f "${project_root}/deploy/examples/bpf-fault-helper.yaml" >/dev/null
helper_created=true
"${kc[@]}" -n unf-system rollout status daemonset/unf-bpf-fault-helper \
    --timeout=120s >/dev/null
wait_for_convergence

mapfile -t nodes < <("${kc[@]}" get nodes -o json | jq -r '.items[].metadata.name' | sort)
[[ ${#nodes[@]} -eq 2 ]]
for node in "${nodes[@]}"; do
    assert_agent_state "${node}" "${current_abi}"
    assert_abi_present "${node}" "${current_abi}"
    assert_abi_absent "${node}" "${future_abi}"
done
start_probe

# The wire schemas are unchanged, so the future controller must continue to
# serve the running v3 agents before any dataplane node changes.
patch_controller_image "${future_controller_image}"
future_version=$(controller_raw /v1/version)
jq -e --argjson abi "${future_abi}" '
    .schema_version == 1
    and .component == "unf-controller"
    and .persistent_bpf_state_abi_version == $abi
    and .identity_snapshot_schema_version == 2
    and .policy_snapshot_schema_version == 4
    and .agent_status_schema_version == 2
    and .flow_export_schema_version == 3
' <<<"${future_version}" >/dev/null
wait_for_convergence

# Build and attach a fresh v4 map set one node at a time. Each Ready agent must
# prove its snapshots were committed before attachment, while v3 remains pinned.
patch_agent_template "${future_agent_image}" "${future_abi}" OnDelete
for node in "${nodes[@]}"; do
    replace_agent_on_node "${node}" "${future_agent_image}"
    wait_for_convergence
    assert_agent_state "${node}" "${future_abi}"
    assert_prepopulation_log "${node}"
    assert_abi_present "${node}" "${current_abi}"
    assert_abi_present "${node}" "${future_abi}"
done

# A direct older binary pointed at newer persistent state is unsupported. It
# must reject the local ABI path before opening the v4 maps; the pinned v4 TCX
# attachment remains active until the compatible v4 agent recovers.
if [[ ${require_unsupported_downgrade} == true ]]; then
    downgrade_node=${nodes[0]}
    future_digest_before=$(map_digest "${downgrade_node}" "${future_abi}")
    patch_agent_template "${current_agent_image}" "${future_abi}" OnDelete
    replace_agent_on_node "${downgrade_node}" "${current_agent_image}" false
    wait_for_unsupported_downgrade_rejection \
        "${downgrade_node}" "${current_abi}" "${future_abi}"
    [[ $(map_digest "${downgrade_node}" "${future_abi}") == "${future_digest_before}" ]]
    assert_abi_present "${downgrade_node}" "${future_abi}"

    patch_agent_template "${future_agent_image}" "${future_abi}" OnDelete
    replace_agent_on_node "${downgrade_node}" "${future_agent_image}"
    wait_for_convergence
    assert_agent_state "${downgrade_node}" "${future_abi}"
    downgrade_result=", unsupported direct v${future_abi}->v${current_abi} downgrade rejection without v${future_abi} map mutation"
fi

# Only the fully converged v4 agents are authorized to remove their older v3
# pins and links. The v4 attachment continues enforcement during each removal.
for node in "${nodes[@]}"; do
    cleanup_older_abi_from_agent "${node}" "${current_abi}"
    assert_abi_absent "${node}" "${current_abi}"
    assert_abi_present "${node}" "${future_abi}"
done
wait_for_convergence

# Exercise the reverse clean rebuild. Fresh v3 state is populated and attached
# node-serially before a scoped v4 binary retires future-version state.
patch_controller_image "${current_controller_image}"
patch_agent_template "${current_agent_image}" "${current_abi}" OnDelete
for node in "${nodes[@]}"; do
    replace_agent_on_node "${node}" "${current_agent_image}"
    wait_for_convergence
    assert_agent_state "${node}" "${current_abi}"
    assert_prepopulation_log "${node}"
    assert_abi_present "${node}" "${current_abi}"
    assert_abi_present "${node}" "${future_abi}"
done
for node in "${nodes[@]}"; do
    run_scoped_cleanup_pod "${node}" "${future_abi}"
    assert_abi_absent "${node}" "${future_abi}"
    assert_abi_present "${node}" "${current_abi}"
done
patch_agent_template "${current_agent_image}" "${current_abi}" RollingUpdate
wait_for_convergence
stop_probe

"${kc[@]}" delete -f "${project_root}/deploy/examples/bpf-fault-helper.yaml" >/dev/null
helper_created=false
trap - EXIT
rm -rf -- "${temporary_dir}"

echo "Kind clean-rebuild qualification passed: controller-first ABI v${current_abi}->v${future_abi}, pre-attachment snapshot population, node-serial mixed-ABI handoff${downgrade_result}, post-convergence old-state retirement, reverse clean rebuild, scoped future-state cleanup, uninterrupted allow/deny enforcement, and current-version convergence were verified"
