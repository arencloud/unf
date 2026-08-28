#!/usr/bin/env bash
set -euo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
kubeconfig=${KUBECONFIG:-"${project_root}/.tools/cl02-audit.kubeconfig"}
image_record=${UNF_OPENSHIFT_UPGRADE_IMAGE_RECORD:-"${project_root}/.artifacts/phase3-openshift-upgrade-images.json"}
result_record=${UNF_OPENSHIFT_UPGRADE_RESULT_RECORD:-"${project_root}/.artifacts/phase3-openshift-upgrade-result.json"}
attempt_history=${UNF_OPENSHIFT_UPGRADE_ATTEMPT_HISTORY:-"${project_root}/.artifacts/phase3-openshift-upgrade-attempts.jsonl"}
context=${KUBE_CONTEXT:-$(oc --kubeconfig "${kubeconfig}" config current-context)}
kc=(oc --kubeconfig "${kubeconfig}" --context "${context}")
client_namespace=unf-qualification-client
server_namespace=unf-qualification-server
temporary_dir=$(mktemp -d)
started_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
completed_stage=initialization
probe_pid=
restoration_enabled=false

for command in git jq oc openssl timeout yq; do
    command -v "${command}" >/dev/null
done
[[ -s ${kubeconfig} && -s ${image_record} ]]
[[ -z $(git -C "${project_root}" status --porcelain) ]] || {
    echo "OpenShift upgrade qualification requires a clean committed tree" >&2
    exit 2
}

baseline_revision=$(jq -er .baseline.revision "${image_record}")
current_revision=$(jq -er .current.revision "${image_record}")
baseline_controller_image=$(jq -er .baseline.controller "${image_record}")
baseline_agent_image=$(jq -er .baseline.agent "${image_record}")
baseline_test_tools_image=$(jq -er .baseline.test_tools "${image_record}")
current_controller_image=$(jq -er .current.controller "${image_record}")
current_agent_image=$(jq -er .current.agent "${image_record}")
current_test_tools_image=$(jq -er .current.test_tools "${image_record}")
[[ ${current_revision} == "$(git -C "${project_root}" rev-parse HEAD)" ]]
git -C "${project_root}" merge-base --is-ancestor "${baseline_revision}" "${current_revision}"
for image in "${baseline_controller_image}" "${baseline_agent_image}" \
    "${baseline_test_tools_image}" "${current_controller_image}" \
    "${current_agent_image}" "${current_test_tools_image}"; do
    [[ ${image} =~ @sha256:[0-9a-f]{64}$ ]]
done

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

patch_controller_image() {
    local image=$1 payload
    payload=$(jq -nc --arg image "${image}" \
        '{spec:{template:{spec:{containers:[{name:"controller",image:$image}]}}}}')
    "${kc[@]}" -n unf-system patch deployment unf-controller \
        --type=strategic -p "${payload}" >/dev/null
    "${kc[@]}" -n unf-system rollout status deployment/unf-controller \
        --timeout=240s >/dev/null
}

patch_agent_image() {
    local image=$1 strategy=$2 payload
    if [[ ${strategy} == OnDelete ]]; then
        payload=$(jq -nc --arg image "${image}" '
            {spec:{updateStrategy:{type:"OnDelete",rollingUpdate:null},
                template:{spec:{containers:[{name:"agent",image:$image}]}}}}
        ')
    else
        payload=$(jq -nc --arg image "${image}" '
            {spec:{updateStrategy:{type:"RollingUpdate",rollingUpdate:{maxUnavailable:1}},
                template:{spec:{containers:[{name:"agent",image:$image}]}}}}
        ')
    fi
    "${kc[@]}" -n unf-system patch daemonset unf-agent \
        --type=strategic -p "${payload}" >/dev/null
    if [[ ${strategy} == RollingUpdate ]]; then
        "${kc[@]}" -n unf-system rollout status daemonset/unf-agent \
            --timeout=300s >/dev/null
    fi
}

wait_for_agent_replacement() {
    local node=$1 old_uid=$2 expected_image=$3 pods=
    for _ in {1..240}; do
        pods=$("${kc[@]}" -n unf-system get pods \
            -l app.kubernetes.io/name=unf-agent -o json 2>/dev/null || true)
        if jq -e --arg node "${node}" --arg uid "${old_uid}" \
            --arg image "${expected_image}" '
            any(.items[];
                .spec.nodeName == $node
                and .metadata.uid != $uid
                and .metadata.deletionTimestamp == null
                and .spec.containers[0].image == $image
                and .status.phase == "Running"
                and any(.status.conditions[]?; .type == "Ready" and .status == "True"))
        ' <<<"${pods}" >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    echo "agent on ${node} did not become Ready with ${expected_image}" >&2
    return 1
}

replace_agent_on_node() {
    local node=$1 expected_image=$2 pod old_uid
    pod=$(agent_pod_on_node "${node}")
    old_uid=$("${kc[@]}" -n unf-system get pod "${pod}" -o jsonpath='{.metadata.uid}')
    "${kc[@]}" -n unf-system delete pod "${pod}" --wait=false >/dev/null
    wait_for_agent_replacement "${node}" "${old_uid}" "${expected_image}"
}

wait_for_convergence() {
    local snapshot=
    for _ in {1..180}; do
        snapshot=$(controller_raw /v1/state/agents 2>/dev/null || true)
        if jq -e --argjson expected "${#workers[@]}" '
            .expected_agents == $expected
            and .reporting_agents == $expected
            and .missing_agents == 0
            and .stale_agents == 0
            and .converged_agents == $expected
            and .unexpected_agents == 0
            and .all_converged == true
            and all(.nodes[]; .fresh and .converged and .report.ready and .report.bpf_loaded)
        ' <<<"${snapshot}" >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    echo "agents did not converge during OpenShift upgrade stage ${completed_stage}" >&2
    jq . <<<"${snapshot}" >&2 || true
    return 1
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

assert_version() {
    local json=$1 component=$2 revision=$3
    jq -e --arg component "${component}" --arg revision "${revision}" '
        .schema_version == 1
        and .component == $component
        and .build_revision == $revision
        and .persistent_bpf_state_abi_version == 3
        and .identity_snapshot_schema_version == 2
        and .policy_snapshot_schema_version == 4
        and .agent_status_schema_version == 2
        and .flow_export_schema_version == 3
    ' <<<"${json}" >/dev/null
}

assert_operator_health() {
    local unhealthy
    unhealthy=$("${kc[@]}" get clusteroperators -o json | jq '[
        .items[] | select(
            ([.status.conditions[] | select(.type == "Available")][0].status) != "True"
            or ([.status.conditions[] | select(.type == "Degraded")][0].status) == "True"
        )
    ] | length')
    [[ ${unhealthy} -eq 0 ]]
}

reconcile_controller_prerequisites() {
    local store
    "${kc[@]}" apply -f "${project_root}/deploy/kubernetes/rbac.yaml" >/dev/null
    for store in agent-report-store flow-history-store topology-history-store; do
        if ! "${kc[@]}" -n unf-system get configmap \
            "$(yq -r .metadata.name "${project_root}/deploy/kubernetes/${store}.yaml")" \
            >/dev/null 2>&1; then
            "${kc[@]}" create -f \
                "${project_root}/deploy/kubernetes/${store}.yaml" >/dev/null
        fi
    done
    [[ $("${kc[@]}" auth can-i get configmap/unf-topology-history \
        --as=system:serviceaccount:unf-system:unf-controller \
        -n unf-system 2>/dev/null) == yes ]]
}

assert_agent_images() {
    local baseline_count=$1 current_count=$2 pods
    pods=$("${kc[@]}" -n unf-system get pods \
        -l app.kubernetes.io/name=unf-agent -o json)
    [[ $(jq --arg image "${baseline_agent_image}" \
        '[.items[] | select(.metadata.deletionTimestamp == null and .spec.containers[0].image == $image)] | length' \
        <<<"${pods}") -eq ${baseline_count} ]]
    [[ $(jq --arg image "${current_agent_image}" \
        '[.items[] | select(.metadata.deletionTimestamp == null and .spec.containers[0].image == $image)] | length' \
        <<<"${pods}") -eq ${current_count} ]]
}

assert_agent_platform_state() {
    local node=$1 expected_revision=$2 pod status
    pod=$(agent_pod_on_node "${node}")
    [[ $("${kc[@]}" -n unf-system get pod "${pod}" \
        -o jsonpath='{.metadata.annotations.openshift\.io/scc}') == unf-agent ]]
    assert_version "$(agent_raw "${node}" /v1/version)" unf-agent "${expected_revision}"
    status=$(agent_raw "${node}" /v1/status)
    jq -e '
        .ready == true
        and .bpf_loaded == true
        and .tc_attachment_mode == "legacy_netlink"
        and .capabilities.btf == true
        and .capabilities.bpffs == true
        and .capabilities.cgroup_v2 == true
        and .ipv4_identity_map_entries > 0
        and .ipv6_identity_map_entries > 0
        and .desired_identity_revision == .applied_identity_revision
        and .desired_policy_revision == .applied_policy_revision
        and .applied_policy_revision > 0
        and .policy_map_entries > 0
        and ((.version_transition // "normal") == "normal")
    ' <<<"${status}" >/dev/null
}

controller_metric() {
    local name=$1
    controller_raw /metrics | awk -v metric_name="${name}" \
        '$1 == metric_name { print int($2); found=1 } END { if (!found) print 0 }'
}

probe_once() {
    local address host response
    for address in "${server_ipv4}" "${server_ipv6}"; do
        host=${address}
        [[ ${address} != *:* ]] || host="[${address}]"
        response=$(timeout 15 "${kc[@]}" -n "${client_namespace}" exec client -- \
            wget -qO- -T 2 -t 1 "http://${host}:8080")
        [[ ${response} == unf-openshift-ok ]]
        if timeout 15 "${kc[@]}" -n "${client_namespace}" exec client -- \
            wget -qO- -T 2 -t 1 "http://${host}:9090" >/dev/null 2>&1; then
            echo "denied transition probe unexpectedly passed for ${address}" >&2
            return 1
        fi
    done
}

emit_and_require_telemetry() {
    local baseline history=
    baseline=$(controller_metric unf_telemetry_observations_total)
    probe_once
    for _ in {1..60}; do
        if [[ $(controller_metric unf_telemetry_observations_total) -gt ${baseline} ]]; then
            history=$(controller_raw /v1/flows 2>/dev/null || true)
            if jq -e '
                any(.entries[];
                    (.source_workloads | index("unf-qualification-client/client"))
                    and (.destination_workloads | index("unf-qualification-server/server"))
                    and .decision.verdict == "Allow"
                    and .decision.policy_id != null)
                and any(.entries[];
                    (.source_workloads | index("unf-qualification-client/client"))
                    and (.destination_workloads | index("unf-qualification-server/server"))
                    and .decision.verdict == "Deny"
                    and .decision.policy_id != null)
            ' <<<"${history}" >/dev/null 2>&1; then
                return 0
            fi
        fi
        sleep 1
    done
    echo "telemetry/provenance did not advance during ${completed_stage}" >&2
    return 1
}

assert_stage() {
    local stage=$1 controller_revision=$2 baseline_agents=$3 current_agents=$4
    completed_stage=${stage}
    assert_version "$(controller_raw /v1/version)" unf-controller "${controller_revision}"
    wait_for_convergence
    assert_agent_images "${baseline_agents}" "${current_agents}"
    for node in "${workers[@]}"; do
        pod=$(agent_pod_on_node "${node}")
        image=$("${kc[@]}" -n unf-system get pod "${pod}" -o jsonpath='{.spec.containers[0].image}')
        if [[ ${image} == "${baseline_agent_image}" ]]; then
            assert_agent_platform_state "${node}" "${baseline_revision}"
        else
            [[ ${image} == "${current_agent_image}" ]]
            assert_agent_platform_state "${node}" "${current_revision}"
        fi
    done
    [[ $("${kc[@]}" -n unf-system get pod "$(controller_pod)" \
        -o jsonpath='{.metadata.annotations.openshift\.io/scc}') == restricted-v2 ]]
    assert_operator_health
    emit_and_require_telemetry
    printf 'verified OpenShift upgrade stage: %s\n' "${stage}"
}

start_probe() {
    "${kc[@]}" -n "${client_namespace}" exec client -- \
        rm -f /tmp/unf-openshift-upgrade-stop /tmp/unf-openshift-upgrade-breach >/dev/null
    "${kc[@]}" -n "${client_namespace}" exec client -- sh -c '
        ipv4=$1
        ipv6=$2
        allow_with_retry() {
            address=$1
            for attempt in 1 2 3; do
                if timeout 3 wget -qO- -T 1 -t 1 "http://${address}:8080" >/dev/null; then
                    return 0
                fi
                sleep 0.2
            done
            return 1
        }
        while [ ! -e /tmp/unf-openshift-upgrade-stop ]; do
            for address in "${ipv4}" "[${ipv6}]"; do
                if ! allow_with_retry "${address}"; then
                    printf "%s allow-outage address=%s\n" \
                        "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "${address}" \
                        >>/tmp/unf-openshift-upgrade-breach
                fi
                if timeout 3 wget -qO- -T 1 -t 1 "http://${address}:9090" >/dev/null 2>&1; then
                    echo deny-breach >>/tmp/unf-openshift-upgrade-breach
                fi
            done
            sleep 0.2
        done
        test ! -s /tmp/unf-openshift-upgrade-breach
    ' sh "${server_ipv4}" "${server_ipv6}" >"${temporary_dir}/traffic-probe.log" 2>&1 &
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
        cat "${temporary_dir}/traffic-probe.log" >&2
        probe_pid=
        return 1
    fi
    "${kc[@]}" -n "${client_namespace}" exec client -- \
        touch /tmp/unf-openshift-upgrade-stop >/dev/null 2>&1 || true
    for _ in {1..45}; do
        kill -0 "${probe_pid}" 2>/dev/null || break
        sleep 1
    done
    if kill -0 "${probe_pid}" 2>/dev/null; then
        kill "${probe_pid}" 2>/dev/null || true
    fi
    if ! wait "${probe_pid}"; then
        cat "${temporary_dir}/traffic-probe.log" >&2
        "${kc[@]}" -n "${client_namespace}" exec client -- \
            cat /tmp/unf-openshift-upgrade-breach >&2 || true
        probe_pid=
        return 1
    fi
    probe_pid=
}

delete_fixture() {
    "${kc[@]}" delete namespace "${client_namespace}" "${server_namespace}" \
        --ignore-not-found --wait=true >/dev/null 2>&1
}

create_fixture() {
    local fixture=${temporary_dir}/qualification.yaml
    delete_fixture
    UNF_TEST_TOOLS_IMAGE="${baseline_test_tools_image}" yq eval '
        (select(.kind == "Pod" and .metadata.namespace == "unf-qualification-client")
            .spec.containers[0].image) = strenv(UNF_TEST_TOOLS_IMAGE)
    ' "${project_root}/deploy/openshift/qualification.yaml" >"${fixture}"
    yq eval-all 'select(.kind == "Namespace")' "${fixture}" | "${kc[@]}" apply -f - >/dev/null
    yq eval-all 'select(.kind != "Namespace")' "${fixture}" | "${kc[@]}" apply -f - >/dev/null
    "${kc[@]}" -n "${client_namespace}" wait --for=condition=Ready pod/client --timeout=240s >/dev/null
    "${kc[@]}" -n "${server_namespace}" wait --for=condition=Ready pod/server --timeout=240s >/dev/null
    client_node=$("${kc[@]}" -n "${client_namespace}" get pod client -o jsonpath='{.spec.nodeName}')
    server_node=$("${kc[@]}" -n "${server_namespace}" get pod server -o jsonpath='{.spec.nodeName}')
    [[ ${client_node} != "${server_node}" ]]
    server_json=$("${kc[@]}" -n "${server_namespace}" get pod server -o json)
    server_ipv4=$(jq -r '[.status.podIPs[]?.ip | select(contains(":") | not)][0] // empty' <<<"${server_json}")
    server_ipv6=$(jq -r '[.status.podIPs[]?.ip | select(contains(":"))][0] // empty' <<<"${server_json}")
    [[ -n ${server_ipv4} && -n ${server_ipv6} ]]
    wait_for_convergence
}

record_attempt() {
    local outcome=$1 completed_at cluster_version kubernetes_version operators
    completed_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    cluster_version=$("${kc[@]}" get clusterversion version -o jsonpath='{.status.desired.version}' 2>/dev/null || echo unknown)
    kubernetes_version=$("${kc[@]}" get nodes -o json 2>/dev/null \
        | jq -r '.items[0].status.nodeInfo.kubeletVersion // "unknown"')
    operators=$("${kc[@]}" get clusteroperators -o json 2>/dev/null | jq '.items | length' || echo 0)
    install -d -m 0700 "$(dirname "${result_record}")"
    jq -n --arg started_at "${started_at}" --arg completed_at "${completed_at}" \
        --arg outcome "${outcome}" --arg completed_stage "${completed_stage}" \
        --arg context "${context}" --arg cluster_version "${cluster_version}" \
        --arg kubernetes_version "${kubernetes_version}" --argjson operators "${operators}" \
        --arg baseline_revision "${baseline_revision}" --arg current_revision "${current_revision}" \
        --arg baseline_controller "${baseline_controller_image}" --arg baseline_agent "${baseline_agent_image}" \
        --arg baseline_test_tools "${baseline_test_tools_image}" \
        --arg current_controller "${current_controller_image}" --arg current_agent "${current_agent_image}" \
        --arg current_test_tools "${current_test_tools_image}" '
        {
            schema_version: 1,
            started_at: $started_at,
            completed_at: $completed_at,
            outcome: $outcome,
            completed_stage: $completed_stage,
            environment: {
                context: $context,
                openshift_version: $cluster_version,
                kubernetes_version: $kubernetes_version,
                worker_count: 2,
                address_families: ["ipv4", "ipv6"],
                attachment: "legacy_netlink",
                cluster_operators: $operators
            },
            baseline: {
                revision: $baseline_revision,
                controller: $baseline_controller,
                agent: $baseline_agent,
                test_tools: $baseline_test_tools
            },
            current: {
                revision: $current_revision,
                controller: $current_controller,
                agent: $current_agent,
                test_tools: $current_test_tools
            }
        }
    ' >"${result_record}"
    chmod 0600 "${result_record}"
    jq -c . "${result_record}" >>"${attempt_history}"
    chmod 0600 "${attempt_history}"
}

cleanup() {
    local exit_code=$?
    trap - EXIT
    set +e
    stop_probe || exit_code=1
    delete_fixture
    if [[ ${restoration_enabled} == true ]]; then
        patch_controller_image "${current_controller_image}" || exit_code=1
        patch_agent_image "${current_agent_image}" RollingUpdate || exit_code=1
    fi
    record_attempt failed
    rm -rf -- "${temporary_dir}"
    exit "${exit_code}"
}
trap cleanup EXIT
trap 'echo "OpenShift upgrade qualification failed at line ${LINENO} during ${completed_stage}" >&2' ERR

"${kc[@]}" get clusterversion version >/dev/null
network_config=$("${kc[@]}" get network.config.openshift.io cluster -o json)
jq -e '
    any(.status.clusterNetwork[]; .cidr | contains(":") | not)
    and any(.status.clusterNetwork[]; .cidr | contains(":"))
    and any(.status.serviceNetwork[]; contains(":") | not)
    and any(.status.serviceNetwork[]; contains(":"))
' <<<"${network_config}" >/dev/null
mapfile -t workers < <("${kc[@]}" get nodes -l node-role.kubernetes.io/worker \
    -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' | sort)
[[ ${#workers[@]} -eq 2 ]]
for node in "${workers[@]}"; do
    [[ $("${kc[@]}" get node "${node}" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}') == True ]]
done
assert_operator_health
reconcile_controller_prerequisites
restoration_enabled=true

completed_stage=baseline-deployment
patch_controller_image "${baseline_controller_image}"
patch_agent_image "${baseline_agent_image}" RollingUpdate
KUBECONFIG="${kubeconfig}" KUBE_CONTEXT="${context}" \
    UNF_TEST_TOOLS_IMAGE="${baseline_test_tools_image}" \
    "${project_root}/hack/verify-openshift.sh"

create_fixture
start_probe
baseline_tuple=$(controller_raw /v1/version | compatibility_tuple)
for node in "${workers[@]}"; do
    [[ $(agent_raw "${node}" /v1/version | compatibility_tuple) == "${baseline_tuple}" ]]
done
assert_stage baseline-n-n "${baseline_revision}" 2 0

patch_controller_image "${current_controller_image}"
[[ $(controller_raw /v1/version | compatibility_tuple) == "${baseline_tuple}" ]]
assert_stage controller-first-n1-n "${current_revision}" 2 0

patch_agent_image "${current_agent_image}" OnDelete
replace_agent_on_node "${workers[0]}" "${current_agent_image}"
assert_stage worker-serial-mixed "${current_revision}" 1 1
replace_agent_on_node "${workers[1]}" "${current_agent_image}"
assert_stage full-n1 "${current_revision}" 0 2

patch_agent_image "${baseline_agent_image}" OnDelete
replace_agent_on_node "${workers[0]}" "${baseline_agent_image}"
assert_stage rollback-mixed "${current_revision}" 1 1
replace_agent_on_node "${workers[1]}" "${baseline_agent_image}"
assert_stage rollback-agents-n "${current_revision}" 2 0
patch_controller_image "${baseline_controller_image}"
assert_stage rollback-n-n "${baseline_revision}" 2 0

patch_controller_image "${current_controller_image}"
assert_stage recovery-controller-first "${current_revision}" 2 0
patch_agent_image "${current_agent_image}" OnDelete
replace_agent_on_node "${workers[0]}" "${current_agent_image}"
assert_stage recovery-mixed "${current_revision}" 1 1
replace_agent_on_node "${workers[1]}" "${current_agent_image}"
assert_stage recovery-full-n1 "${current_revision}" 0 2
patch_agent_image "${current_agent_image}" RollingUpdate
stop_probe
delete_fixture

completed_stage=final-platform-qualification
KUBECONFIG="${kubeconfig}" KUBE_CONTEXT="${context}" \
    UNF_TEST_TOOLS_IMAGE="${current_test_tools_image}" \
    "${project_root}/hack/verify-openshift.sh"
assert_operator_health
wait_for_convergence
assert_agent_images 0 2
completed_stage=complete
record_attempt passed
restoration_enabled=false
trap - EXIT
rm -rf -- "${temporary_dir}"

echo "OpenShift cl02 upgrade qualification passed: digest-pinned N/N+1 images, baseline and final platform gates, controller-first compatibility, worker-serial mixed rollout, full agent/controller rollback and recovery, uninterrupted dual-stack enforcement, provenance/telemetry continuity, and healthy operators"
