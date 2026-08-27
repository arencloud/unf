#!/usr/bin/env bash
set -euo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
kubeconfig=${KUBECONFIG:-"${project_root}/.tools/kind-unf-dev.kubeconfig"}
context=${KUBE_CONTEXT:-kind-unf-dev}
namespace_count=${UNF_SCALE_NAMESPACE_COUNT:-4}
client_replicas=${UNF_SCALE_CLIENT_REPLICAS:-4}
server_replicas=${UNF_SCALE_SERVER_REPLICAS:-2}
prefix=${UNF_SCALE_NAMESPACE_PREFIX:-unf-scale}
client_node=${UNF_SCALE_CLIENT_NODE:-unf-dev-control-plane}
server_node=${UNF_SCALE_SERVER_NODE:-unf-dev-worker}
churn_cycles=${UNF_SCALE_CHURN_CYCLES:-3}
apply_budget=${UNF_SCALE_APPLY_BUDGET_SECONDS:-180}
churn_budget=${UNF_SCALE_CHURN_BUDGET_SECONDS:-180}
agent_recovery_budget=${UNF_SCALE_AGENT_RECOVERY_BUDGET_SECONDS:-180}
controller_recovery_budget=${UNF_SCALE_CONTROLLER_RECOVERY_BUDGET_SECONDS:-180}
queue_drain_budget=${UNF_SCALE_QUEUE_DRAIN_BUDGET_SECONDS:-60}
max_agent_sync_errors=${UNF_SCALE_MAX_AGENT_SYNC_ERRORS:-10}
max_telemetry_drop_delta=${UNF_SCALE_MAX_TELEMETRY_DROP_DELTA:-0}
result_file=${UNF_SCALE_RESULT_FILE:-"${project_root}/.artifacts/phase3-scale-kind-result.json"}
attempts_file=${UNF_SCALE_ATTEMPTS_FILE:-"${result_file%.json}-attempts.jsonl"}
kc=(kubectl --kubeconfig "${kubeconfig}" --context "${context}")
temporary_dir=$(mktemp -d)
manifest="${temporary_dir}/scale-fixture.yaml"
manifest_copy="${temporary_dir}/scale-fixture-copy.yaml"
probe_log="${temporary_dir}/traffic-probe.log"
probe_pid=
fixture_applied=false
controller_scaled_down=false
result_written=false
original_controller_replicas=1
baseline_status=null
scaled_status=null
post_cleanup_status=null
agent_statuses=null
kubernetes_environment=null
node_environment=null
cni_images='[]'
controller_version=null
agent_versions='[]'
offload_configuration=unavailable
pod_mtu=unavailable
apply_seconds=0
churn_seconds=0
agent_recovery_seconds=0
controller_recovery_seconds=0
queue_drain_seconds=0
agent_sync_errors=0
telemetry_drop_delta=0

bounded_integer() {
    local name=$1
    local value=$2
    local minimum=$3
    local maximum=$4
    if [[ ! ${value} =~ ^[0-9]+$ ]] || ((value < minimum || value > maximum)); then
        echo "${name} must be an integer in [${minimum}, ${maximum}]; got ${value}" >&2
        exit 2
    fi
}

now_seconds() {
    date +%s
}

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

controller_status() {
    controller_raw /v1/status
}

controller_metric() {
    local name=$1
    controller_raw /metrics \
        | awk -v metric_name="${name}" '$1 == metric_name { print int($2); found=1 } END { if (!found) print 0 }'
}

agent_pods() {
    "${kc[@]}" -n unf-system get pods -l app.kubernetes.io/name=unf-agent -o json \
        | jq -r '.items[] | select(.metadata.deletionTimestamp == null and .status.phase == "Running") | .metadata.name' \
        | sort
}

all_agent_statuses() {
    local pod
    local output='[]'
    while read -r pod; do
        [[ -n ${pod} ]] || continue
        output=$(jq -c --argjson item "$("${kc[@]}" get --raw \
            "/api/v1/namespaces/unf-system/pods/${pod}:9963/proxy/v1/status")" \
            '. + [$item]' <<<"${output}")
    done < <(agent_pods)
    printf '%s' "${output}"
}

all_agent_versions() {
    local pod
    local output='[]'
    while read -r pod; do
        [[ -n ${pod} ]] || continue
        output=$(jq -c --argjson item "$("${kc[@]}" get --raw \
            "/api/v1/namespaces/unf-system/pods/${pod}:9963/proxy/v1/version")" \
            '. + [$item]' <<<"${output}")
    done < <(agent_pods)
    printf '%s' "${output}"
}

agent_metric_sum() {
    local name=$1
    local pod
    local total=0
    local value
    while read -r pod; do
        [[ -n ${pod} ]] || continue
        value=$("${kc[@]}" get --raw \
            "/api/v1/namespaces/unf-system/pods/${pod}:9963/proxy/metrics" \
            | awk -v metric_name="${name}" '$1 == metric_name { print int($2); found=1 } END { if (!found) print 0 }')
        total=$((total + value))
    done < <(agent_pods)
    printf '%s' "${total}"
}

wait_for_scaled_state() {
    local minimum_pods=$1
    local minimum_namespaces=$2
    local minimum_policies=$3
    local baseline_ingress=$4
    local baseline_egress=$5
    local timeout=$6
    local status=
    for ((attempt = 0; attempt < timeout; attempt++)); do
        status=$(controller_status 2>/dev/null || true)
        if jq -e \
            --argjson minimum_pods "${minimum_pods}" \
            --argjson minimum_namespaces "${minimum_namespaces}" \
            --argjson minimum_policies "${minimum_policies}" \
            --argjson baseline_ingress "${baseline_ingress}" \
            --argjson baseline_egress "${baseline_egress}" '
                .pods >= $minimum_pods
                and .namespaces >= $minimum_namespaces
                and .network_policies >= $minimum_policies
                and .rejected_network_policies == 0
                and .resolved_ingress_policy_entries > $baseline_ingress
                and .resolved_egress_policy_entries > $baseline_egress
                and .agents.expected_agents == 2
                and .agents.converged_agents == 2
                and .agents.all_converged
            ' <<<"${status}" >/dev/null 2>&1; then
            printf '%s' "${status}"
            return 0
        fi
        sleep 1
    done
    echo "scale fixture did not converge within ${timeout} seconds" >&2
    jq . <<<"${status:-null}" >&2 || true
    return 1
}

wait_for_policy_revision() {
    local previous=$1
    local timeout=$2
    local require_indexed=$3
    local status=
    for ((attempt = 0; attempt < timeout; attempt++)); do
        status=$(controller_status 2>/dev/null || true)
        if jq -e \
            --argjson previous "${previous}" \
            --argjson require_indexed "${require_indexed}" '
                .revisions.policy > $previous
                and .indexed_pod_ips == $require_indexed
                and .rejected_network_policies == 0
                and .agents.expected_agents == 2
                and .agents.converged_agents == 2
                and .agents.all_converged
            ' <<<"${status}" >/dev/null 2>&1; then
            printf '%s' "${status}"
            return 0
        fi
        sleep 1
    done
    echo "policy revision did not converge after ${previous} within ${timeout} seconds" >&2
    jq . <<<"${status:-null}" >&2 || true
    return 1
}

wait_for_deployments() {
    local expected=$1
    local timeout=$2
    local deployments=
    for ((attempt = 0; attempt < timeout; attempt++)); do
        deployments=$("${kc[@]}" get deployments -A \
            -l unf.network/scale-fixture=true -o json 2>/dev/null || true)
        if jq -e --argjson expected "${expected}" '
            (.items | length) == $expected
            and all(.items[]; .status.availableReplicas == .spec.replicas)
        ' <<<"${deployments}" >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    echo "scale fixture Deployments did not become available within ${timeout} seconds" >&2
    return 1
}

wait_for_agents_offline_recovery() {
    local old_uids=$1
    local minimum_entries=$2
    local expected_identity_revision=$3
    local expected_policy_revision=$4
    local timeout=$5
    local pods=
    local statuses=
    local uids=
    for ((attempt = 0; attempt < timeout; attempt++)); do
        pods=$("${kc[@]}" -n unf-system get pods \
            -l app.kubernetes.io/name=unf-agent -o json 2>/dev/null || true)
        uids=$(jq -c '[.items[] | select(.metadata.deletionTimestamp == null and .status.phase == "Running" and any(.status.conditions[]?; .type == "Ready" and .status == "True")) | .metadata.uid] | sort' \
            <<<"${pods}" 2>/dev/null || printf '[]')
        if [[ ${uids} != "${old_uids}" ]] && [[ $(jq 'length' <<<"${uids}") -eq 2 ]]; then
            statuses=$(all_agent_statuses 2>/dev/null || true)
            if jq -e \
                --argjson minimum_entries "${minimum_entries}" \
                --argjson expected_identity_revision "${expected_identity_revision}" \
                --argjson expected_policy_revision "${expected_policy_revision}" '
                length == 2
                and all(.[];
                    .ready and .bpf_loaded
                    and .desired_identity_revision == 0
                    and .desired_policy_revision == 0
                    and .applied_identity_revision == $expected_identity_revision
                    and .applied_policy_revision == $expected_policy_revision
                    and .policy_map_entries >= $minimum_entries
                )
            ' <<<"${statuses}" >/dev/null 2>&1; then
                printf '%s' "${statuses}"
                return 0
            fi
        fi
        sleep 1
    done
    echo "both agents did not recover last-known-good state within ${timeout} seconds" >&2
    return 1
}

wait_for_baseline_cleanup() {
    local expected_namespaces=$1
    local expected_policies=$2
    local expected_indexed=$3
    local timeout=$4
    local status=
    for ((attempt = 0; attempt < timeout; attempt++)); do
        status=$(controller_status 2>/dev/null || true)
        if jq -e \
            --argjson expected_namespaces "${expected_namespaces}" \
            --argjson expected_policies "${expected_policies}" \
            --argjson expected_indexed "${expected_indexed}" '
                .namespaces == $expected_namespaces
                and .network_policies == $expected_policies
                and .indexed_pod_ips == $expected_indexed
                and .rejected_network_policies == 0
                and .agents.expected_agents == 2
                and .agents.converged_agents == 2
                and .agents.all_converged
            ' <<<"${status}" >/dev/null 2>&1; then
            printf '%s' "${status}"
            return 0
        fi
        sleep 1
    done
    echo "scale fixture cleanup did not restore baseline counts within ${timeout} seconds" >&2
    jq . <<<"${status:-null}" >&2 || true
    return 1
}

wait_for_agent_queue_drain() {
    local timeout=$1
    local statuses=
    for ((attempt = 0; attempt < timeout; attempt++)); do
        statuses=$(all_agent_statuses 2>/dev/null || true)
        if jq -e '
            length == 2
            and all(.[];
                .ready and .bpf_loaded
                and .queued_flow_exports == 0
                and .dropped_flow_exports == 0
                and .desired_identity_revision == .applied_identity_revision
                and .desired_policy_revision == .applied_policy_revision
            )
        ' <<<"${statuses}" >/dev/null 2>&1; then
            printf '%s' "${statuses}"
            return 0
        fi
        sleep 1
    done
    echo "agent export queues did not drain within ${timeout} seconds" >&2
    jq . <<<"${statuses:-null}" >&2 || true
    return 1
}

stop_probe() {
    if [[ -z ${probe_pid} ]]; then
        return 0
    fi
    "${kc[@]}" -n "${prefix}-0" exec "${probe_client}" -- \
        touch /tmp/unf-scale-stop >/dev/null 2>&1 || true
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
        echo "continuous scale probe did not stop within 30 seconds" >&2
        return 1
    fi
    if ! wait "${probe_pid}"; then
        probe_pid=
        cat "${probe_log}" >&2
        echo "continuous scale allow/deny probe reported a breach" >&2
        return 1
    fi
    probe_pid=
}

delete_fixture() {
    local namespaces=()
    for ((index = 0; index < namespace_count; index++)); do
        namespaces+=("${prefix}-${index}")
    done
    "${kc[@]}" delete namespace "${namespaces[@]}" \
        --ignore-not-found --wait=false >/dev/null 2>&1 || true
}

write_result() {
    local outcome=$1
    local exit_code=$2
    local host_cpu
    local host_kernel
    local revision
    local tree_state=clean
    host_cpu=$(awk -F ': ' '/model name/ { print $2; exit }' /proc/cpuinfo)
    host_kernel=$(uname -srmo)
    revision=$(git -C "${project_root}" rev-parse HEAD 2>/dev/null || printf unknown)
    if [[ -n $(git -C "${project_root}" status --porcelain 2>/dev/null) ]]; then
        tree_state=dirty
    fi
    mkdir -p "$(dirname "${result_file}")"
    jq -n \
        --arg outcome "${outcome}" \
        --argjson exit_code "${exit_code}" \
        --arg revision "${revision}" \
        --arg tree_state "${tree_state}" \
        --arg verified_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        --arg host_cpu "${host_cpu}" \
        --arg host_kernel "${host_kernel}" \
        --arg pod_mtu "${pod_mtu}" \
        --arg offload_configuration "${offload_configuration}" \
        --argjson kubernetes "${kubernetes_environment}" \
        --argjson nodes "${node_environment}" \
        --argjson cni_images "${cni_images}" \
        --argjson controller_version "${controller_version}" \
        --argjson agent_versions "${agent_versions}" \
        --argjson namespace_count "${namespace_count}" \
        --argjson client_replicas "${client_replicas}" \
        --argjson server_replicas "${server_replicas}" \
        --argjson churn_cycles "${churn_cycles}" \
        --argjson apply_budget "${apply_budget}" \
        --argjson churn_budget "${churn_budget}" \
        --argjson agent_recovery_budget "${agent_recovery_budget}" \
        --argjson controller_recovery_budget "${controller_recovery_budget}" \
        --argjson queue_drain_budget "${queue_drain_budget}" \
        --argjson max_agent_sync_errors "${max_agent_sync_errors}" \
        --argjson max_telemetry_drop_delta "${max_telemetry_drop_delta}" \
        --argjson apply_seconds "${apply_seconds}" \
        --argjson churn_seconds "${churn_seconds}" \
        --argjson agent_recovery_seconds "${agent_recovery_seconds}" \
        --argjson controller_recovery_seconds "${controller_recovery_seconds}" \
        --argjson queue_drain_seconds "${queue_drain_seconds}" \
        --argjson agent_sync_errors "${agent_sync_errors}" \
        --argjson telemetry_drop_delta "${telemetry_drop_delta}" \
        --argjson baseline "${baseline_status}" \
        --argjson scaled "${scaled_status}" \
        --argjson agents "${agent_statuses}" \
        --argjson post_cleanup "${post_cleanup_status}" '
        {
            schema_version: 1,
            outcome: $outcome,
            exit_code: $exit_code,
            git_revision: $revision,
            git_tree_state: $tree_state,
            verified_at: $verified_at,
            profile: {
                namespace_count: $namespace_count,
                client_replicas_per_namespace: $client_replicas,
                server_replicas_per_namespace: $server_replicas,
                total_workload_pods: ($namespace_count * ($client_replicas + $server_replicas)),
                network_policies: ($namespace_count * 2),
                churn_cycles: $churn_cycles
            },
            budgets_seconds: {
                initial_apply: $apply_budget,
                churn_total: $churn_budget,
                simultaneous_agent_recovery: $agent_recovery_budget,
                controller_reconvergence: $controller_recovery_budget,
                export_queue_drain: $queue_drain_budget,
                maximum_agent_sync_errors: $max_agent_sync_errors,
                maximum_telemetry_drop_delta: $max_telemetry_drop_delta
            },
            measurements_seconds: {
                initial_apply: $apply_seconds,
                churn_total: $churn_seconds,
                simultaneous_agent_recovery: $agent_recovery_seconds,
                controller_reconvergence: $controller_recovery_seconds,
                export_queue_drain: $queue_drain_seconds,
                agent_sync_errors: $agent_sync_errors,
                telemetry_drop_delta: $telemetry_drop_delta
            },
            environment: {
                host_cpu: $host_cpu,
                host_kernel: $host_kernel,
                kubernetes: $kubernetes,
                nodes: $nodes,
                cni_images: $cni_images,
                component_versions: {
                    controller: $controller_version,
                    agents: $agent_versions
                },
                workload_pod_mtu: $pod_mtu,
                workload_pod_offloads: $offload_configuration
            },
            observations: {
                baseline_controller_status: $baseline,
                scaled_controller_status: $scaled,
                recovered_agent_statuses: $agents,
                post_cleanup_controller_status: $post_cleanup
            }
        }
    ' >"${result_file}"
    jq -c . "${result_file}" >>"${attempts_file}"
}

cleanup() {
    local exit_code=$?
    trap - EXIT
    set +e
    stop_probe >/dev/null 2>&1
    if [[ ${controller_scaled_down} == true ]]; then
        "${kc[@]}" -n unf-system scale deployment/unf-controller \
            --replicas="${original_controller_replicas}" >/dev/null 2>&1
        "${kc[@]}" -n unf-system rollout status deployment/unf-controller \
            --timeout=180s >/dev/null 2>&1
    fi
    if [[ ${fixture_applied} == true ]]; then
        delete_fixture
    fi
    if [[ ${result_written} != true ]]; then
        write_result failed "${exit_code}" >/dev/null 2>&1 || true
    fi
    rm -rf -- "${temporary_dir}"
    exit "${exit_code}"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

for command in awk diff git jq kubectl tail; do
    command -v "${command}" >/dev/null
done
[[ -s ${kubeconfig} ]]
bounded_integer UNF_SCALE_NAMESPACE_COUNT "${namespace_count}" 2 16
bounded_integer UNF_SCALE_CLIENT_REPLICAS "${client_replicas}" 1 32
bounded_integer UNF_SCALE_SERVER_REPLICAS "${server_replicas}" 1 16
bounded_integer UNF_SCALE_CHURN_CYCLES "${churn_cycles}" 1 10
bounded_integer UNF_SCALE_APPLY_BUDGET_SECONDS "${apply_budget}" 30 900
bounded_integer UNF_SCALE_CHURN_BUDGET_SECONDS "${churn_budget}" 30 900
bounded_integer UNF_SCALE_AGENT_RECOVERY_BUDGET_SECONDS "${agent_recovery_budget}" 30 900
bounded_integer UNF_SCALE_CONTROLLER_RECOVERY_BUDGET_SECONDS "${controller_recovery_budget}" 30 900
bounded_integer UNF_SCALE_QUEUE_DRAIN_BUDGET_SECONDS "${queue_drain_budget}" 10 300
bounded_integer UNF_SCALE_MAX_AGENT_SYNC_ERRORS "${max_agent_sync_errors}" 0 100
bounded_integer UNF_SCALE_MAX_TELEMETRY_DROP_DELTA "${max_telemetry_drop_delta}" 0 1000000

if [[ -s ${result_file} ]]; then
    previous_result=$(jq -c . "${result_file}")
    previous_attempt=
    if [[ -s ${attempts_file} ]]; then
        previous_attempt=$(tail -n 1 "${attempts_file}")
    fi
    if [[ ${previous_result} != "${previous_attempt}" ]]; then
        mkdir -p "$(dirname "${attempts_file}")"
        printf '%s\n' "${previous_result}" >>"${attempts_file}"
    fi
fi

"${kc[@]}" wait --for=condition=Ready nodes --all --timeout=120s >/dev/null
[[ $("${kc[@]}" get nodes -o json | jq '.items | length') -eq 2 ]]
"${kc[@]}" get node "${client_node}" "${server_node}" >/dev/null
"${kc[@]}" -n unf-system wait --for=condition=Available \
    deployment/unf-controller --timeout=120s >/dev/null
"${kc[@]}" -n unf-system rollout status daemonset/unf-agent \
    --timeout=120s >/dev/null

original_controller_replicas=$("${kc[@]}" -n unf-system get deployment/unf-controller \
    -o jsonpath='{.spec.replicas}')
[[ ${original_controller_replicas} -eq 1 ]]
kubernetes_environment=$("${kc[@]}" version -o json | jq -c .)
node_environment=$("${kc[@]}" get nodes -o json | jq -c '[.items[] | {
    name: .metadata.name,
    kernel: .status.nodeInfo.kernelVersion,
    os_image: .status.nodeInfo.osImage,
    architecture: .status.nodeInfo.architecture,
    container_runtime: .status.nodeInfo.containerRuntimeVersion,
    capacity_cpu: .status.capacity.cpu,
    capacity_memory: .status.capacity.memory,
    capacity_pods: .status.capacity.pods
}]')
cni_images=$("${kc[@]}" -n kube-system get daemonsets -o json | jq -c '[
    .items[]
    | select(.metadata.name | test("kindnet|cni"; "i"))
    | .spec.template.spec.containers[].image
] | unique')
controller_version=$(controller_raw /v1/version | jq -c .)
agent_versions=$(all_agent_versions)

delete_fixture
for ((attempt = 0; attempt < 120; attempt++)); do
    if [[ $("${kc[@]}" get namespaces -l unf.network/scale-fixture=true -o json | jq '.items | length') -eq 0 ]]; then
        break
    fi
    sleep 1
done
[[ $("${kc[@]}" get namespaces -l unf.network/scale-fixture=true -o json | jq '.items | length') -eq 0 ]]

UNF_SCALE_NAMESPACE_COUNT="${namespace_count}" \
UNF_SCALE_CLIENT_REPLICAS="${client_replicas}" \
UNF_SCALE_SERVER_REPLICAS="${server_replicas}" \
UNF_SCALE_NAMESPACE_PREFIX="${prefix}" \
UNF_SCALE_CLIENT_NODE="${client_node}" \
UNF_SCALE_SERVER_NODE="${server_node}" \
    "${project_root}/hack/generate-scale-fixture.sh" >"${manifest}"
UNF_SCALE_NAMESPACE_COUNT="${namespace_count}" \
UNF_SCALE_CLIENT_REPLICAS="${client_replicas}" \
UNF_SCALE_SERVER_REPLICAS="${server_replicas}" \
UNF_SCALE_NAMESPACE_PREFIX="${prefix}" \
UNF_SCALE_CLIENT_NODE="${client_node}" \
UNF_SCALE_SERVER_NODE="${server_node}" \
    "${project_root}/hack/generate-scale-fixture.sh" >"${manifest_copy}"
diff -u "${manifest}" "${manifest_copy}"
[[ $(grep -c '^kind: Namespace$' "${manifest}") -eq ${namespace_count} ]]
[[ $(grep -c '^kind: Deployment$' "${manifest}") -eq $((namespace_count * 2)) ]]
[[ $(grep -c '^kind: NetworkPolicy$' "${manifest}") -eq $((namespace_count * 2)) ]]
"${kc[@]}" apply --dry-run=client -f "${manifest}" >/dev/null

baseline_status=$(controller_status)
baseline_pods=$(jq '.pods' <<<"${baseline_status}")
baseline_namespaces=$(jq '.namespaces' <<<"${baseline_status}")
baseline_policies=$(jq '.network_policies' <<<"${baseline_status}")
baseline_indexed=$(jq '.indexed_pod_ips' <<<"${baseline_status}")
baseline_ingress=$(jq '.resolved_ingress_policy_entries' <<<"${baseline_status}")
baseline_egress=$(jq '.resolved_egress_policy_entries' <<<"${baseline_status}")
baseline_telemetry_drops=$(jq '.telemetry_dropped_events' <<<"${baseline_status}")
expected_workload_pods=$((namespace_count * (client_replicas + server_replicas)))

apply_started=$(now_seconds)
"${kc[@]}" apply -f "${manifest}" >/dev/null
fixture_applied=true
wait_for_deployments $((namespace_count * 2)) "${apply_budget}"
scaled_status=$(wait_for_scaled_state \
    $((baseline_pods + expected_workload_pods)) \
    $((baseline_namespaces + namespace_count)) \
    $((baseline_policies + namespace_count * 2)) \
    "${baseline_ingress}" "${baseline_egress}" "${apply_budget}")
apply_seconds=$(($(now_seconds) - apply_started))
((apply_seconds <= apply_budget))

probe_client=$("${kc[@]}" -n "${prefix}-0" get pods -l role=client -o json \
    | jq -r '.items[] | select(.status.phase == "Running") | .metadata.name' | head -n 1)
probe_server=$("${kc[@]}" -n "${prefix}-0" get pods -l role=server -o json \
    | jq -r '.items[] | select(.status.phase == "Running") | .metadata.name' | head -n 1)
[[ -n ${probe_client} && -n ${probe_server} ]]
server_ipv4=$("${kc[@]}" -n "${prefix}-0" get pod "${probe_server}" -o json \
    | jq -r '.status.podIPs[]?.ip | select(contains(":") | not)' | head -n 1)
server_ipv6=$("${kc[@]}" -n "${prefix}-0" get pod "${probe_server}" -o json \
    | jq -r '.status.podIPs[]?.ip | select(contains(":"))' | head -n 1)
[[ -n ${server_ipv4} && -n ${server_ipv6} ]]
allow_ipv4="http://${server_ipv4}:8080"
allow_ipv6="http://[${server_ipv6}]:8080"
deny_ipv4="http://${server_ipv4}:9090"
deny_ipv6="http://[${server_ipv6}]:9090"
"${kc[@]}" -n "${prefix}-0" exec "${probe_client}" -- \
    wget -qO- --timeout=2 --tries=1 "${allow_ipv4}" | grep -q '^unf-scale-ok$'
"${kc[@]}" -n "${prefix}-0" exec "${probe_client}" -- \
    wget -qO- --timeout=2 --tries=1 "${allow_ipv6}" | grep -q '^unf-scale-ok$'
if "${kc[@]}" -n "${prefix}-0" exec "${probe_client}" -- \
    wget -qO- --timeout=2 --tries=1 "${deny_ipv4}" >/dev/null 2>&1; then
    echo "scale fixture IPv4 deny baseline unexpectedly passed" >&2
    exit 1
fi
if "${kc[@]}" -n "${prefix}-0" exec "${probe_client}" -- \
    wget -qO- --timeout=2 --tries=1 "${deny_ipv6}" >/dev/null 2>&1; then
    echo "scale fixture IPv6 deny baseline unexpectedly passed" >&2
    exit 1
fi
pod_mtu=$("${kc[@]}" -n "${prefix}-0" exec "${probe_client}" -- \
    cat /sys/class/net/eth0/mtu)
offload_configuration=$("${kc[@]}" -n "${prefix}-0" exec "${probe_client}" -- \
    ethtool -k eth0 | sed '1d' | tr '\n' ';')

"${kc[@]}" -n "${prefix}-0" exec "${probe_client}" -- sh -c \
    'rm -f /tmp/unf-scale-stop /tmp/unf-scale-breach' >/dev/null
"${kc[@]}" -n "${prefix}-0" exec "${probe_client}" -- sh -c '
    while [ ! -e /tmp/unf-scale-stop ]; do
        for url in "$1" "$2"; do
            if ! timeout 3 wget -qO- --timeout=1 --tries=1 "$url" >/dev/null; then
                echo "allow-outage $url" >>/tmp/unf-scale-breach
            fi
        done
        for url in "$3" "$4"; do
            if timeout 3 wget -qO- --timeout=1 --tries=1 "$url" >/dev/null 2>&1; then
                echo "deny-breach $url" >>/tmp/unf-scale-breach
            fi
        done
        sleep 0.2
    done
    test ! -s /tmp/unf-scale-breach
' sh "${allow_ipv4}" "${allow_ipv6}" "${deny_ipv4}" "${deny_ipv6}" \
    >"${probe_log}" 2>&1 &
probe_pid=$!

churn_started=$(now_seconds)
churn_namespace="${prefix}-$((namespace_count - 1))"
for ((cycle = 0; cycle < churn_cycles; cycle++)); do
    revision=$(jq '.revisions.policy' <<<"${scaled_status}")
    "${kc[@]}" label namespace "${churn_namespace}" \
        unf.network/scale-enabled=false --overwrite >/dev/null
    scaled_status=$(wait_for_policy_revision "${revision}" "${churn_budget}" \
        "$(jq '.indexed_pod_ips' <<<"${scaled_status}")")
    revision=$(jq '.revisions.policy' <<<"${scaled_status}")
    "${kc[@]}" label namespace "${churn_namespace}" \
        unf.network/scale-enabled=true --overwrite >/dev/null
    scaled_status=$(wait_for_policy_revision "${revision}" "${churn_budget}" \
        "$(jq '.indexed_pod_ips' <<<"${scaled_status}")")
done

churn_pod=$("${kc[@]}" -n "${churn_namespace}" get pods -l role=client -o json \
    | jq -r '.items[] | select(.status.phase == "Running") | .metadata.name' | head -n 1)
revision=$(jq '.revisions.policy' <<<"${scaled_status}")
indexed_before_label=$(jq '.indexed_pod_ips' <<<"${scaled_status}")
"${kc[@]}" -n "${churn_namespace}" label pod "${churn_pod}" \
    role=client-quarantined --overwrite >/dev/null
scaled_status=$(wait_for_policy_revision "${revision}" "${churn_budget}" "${indexed_before_label}")
revision=$(jq '.revisions.policy' <<<"${scaled_status}")
"${kc[@]}" -n "${churn_namespace}" label pod "${churn_pod}" \
    role=client --overwrite >/dev/null
scaled_status=$(wait_for_policy_revision "${revision}" "${churn_budget}" "${indexed_before_label}")

revision=$(jq '.revisions.policy' <<<"${scaled_status}")
"${kc[@]}" -n "${churn_namespace}" patch networkpolicy allow-scale-ingress \
    --type=json -p='[{"op":"add","path":"/spec/ingress/0/ports/-","value":{"protocol":"TCP","port":8081}}]' >/dev/null
"${kc[@]}" -n "${churn_namespace}" patch networkpolicy allow-scale-egress \
    --type=json -p='[{"op":"add","path":"/spec/egress/0/ports/-","value":{"protocol":"TCP","port":8081}}]' >/dev/null
scaled_status=$(wait_for_policy_revision "${revision}" "${churn_budget}" "${indexed_before_label}")
revision=$(jq '.revisions.policy' <<<"${scaled_status}")
"${kc[@]}" -n "${churn_namespace}" patch networkpolicy allow-scale-ingress \
    --type=json -p='[{"op":"remove","path":"/spec/ingress/0/ports/1"}]' >/dev/null
"${kc[@]}" -n "${churn_namespace}" patch networkpolicy allow-scale-egress \
    --type=json -p='[{"op":"remove","path":"/spec/egress/0/ports/1"}]' >/dev/null
scaled_status=$(wait_for_policy_revision "${revision}" "${churn_budget}" "${indexed_before_label}")
churn_seconds=$(($(now_seconds) - churn_started))
((churn_seconds <= churn_budget))

old_agent_uids=$("${kc[@]}" -n unf-system get pods \
    -l app.kubernetes.io/name=unf-agent -o json \
    | jq -c '[.items[] | select(.metadata.deletionTimestamp == null) | .metadata.uid] | sort')
minimum_recovered_entries=$(jq '[.agents.nodes[].report.policy_map_entries] | min' \
    <<<"${scaled_status}")
expected_recovered_identity_revision=$(jq '.revisions.identity' <<<"${scaled_status}")
expected_recovered_policy_revision=$(jq '.revisions.policy' <<<"${scaled_status}")
"${kc[@]}" -n unf-system scale deployment/unf-controller --replicas=0 >/dev/null
controller_scaled_down=true
"${kc[@]}" -n unf-system wait --for=delete pod \
    -l app.kubernetes.io/name=unf-controller --timeout=120s >/dev/null

"${kc[@]}" -n "${churn_namespace}" patch networkpolicy allow-scale-ingress \
    --type=json -p='[{"op":"add","path":"/spec/ingress/0/ports/-","value":{"protocol":"UDP","port":8082}}]' >/dev/null
agent_recovery_started=$(now_seconds)
"${kc[@]}" -n unf-system delete pod -l app.kubernetes.io/name=unf-agent \
    --wait=false >/dev/null
agent_statuses=$(wait_for_agents_offline_recovery "${old_agent_uids}" \
    "${minimum_recovered_entries}" "${expected_recovered_identity_revision}" \
    "${expected_recovered_policy_revision}" "${agent_recovery_budget}")
agent_recovery_seconds=$(($(now_seconds) - agent_recovery_started))
((agent_recovery_seconds <= agent_recovery_budget))

controller_recovery_started=$(now_seconds)
"${kc[@]}" -n unf-system scale deployment/unf-controller \
    --replicas="${original_controller_replicas}" >/dev/null
controller_scaled_down=false
"${kc[@]}" -n unf-system rollout status deployment/unf-controller \
    --timeout="${controller_recovery_budget}s" >/dev/null
scaled_status=$(wait_for_scaled_state \
    $((baseline_pods + expected_workload_pods)) \
    $((baseline_namespaces + namespace_count)) \
    $((baseline_policies + namespace_count * 2)) \
    "${baseline_ingress}" "${baseline_egress}" "${controller_recovery_budget}")
controller_recovery_seconds=$(($(now_seconds) - controller_recovery_started))
((controller_recovery_seconds <= controller_recovery_budget))

revision=$(jq '.revisions.policy' <<<"${scaled_status}")
"${kc[@]}" -n "${churn_namespace}" patch networkpolicy allow-scale-ingress \
    --type=json -p='[{"op":"remove","path":"/spec/ingress/0/ports/1"}]' >/dev/null
scaled_status=$(wait_for_policy_revision "${revision}" "${churn_budget}" \
    "$(jq '.indexed_pod_ips' <<<"${scaled_status}")")

queue_drain_started=$(now_seconds)
agent_statuses=$(wait_for_agent_queue_drain "${queue_drain_budget}")
queue_drain_seconds=$(($(now_seconds) - queue_drain_started))
((queue_drain_seconds <= queue_drain_budget))
agent_sync_errors=$(agent_metric_sum unf_policy_sync_errors_total)
((agent_sync_errors <= max_agent_sync_errors))
[[ $(controller_metric unf_controller_reconcile_errors_total) -eq 0 ]]
telemetry_drop_delta=$(($(jq '.telemetry_dropped_events' <<<"${scaled_status}") - baseline_telemetry_drops))
((telemetry_drop_delta >= 0 && telemetry_drop_delta <= max_telemetry_drop_delta))
stop_probe

delete_fixture
fixture_applied=false
for ((attempt = 0; attempt < 120; attempt++)); do
    if [[ $("${kc[@]}" get namespaces -l unf.network/scale-fixture=true -o json | jq '.items | length') -eq 0 ]]; then
        break
    fi
    sleep 1
done
[[ $("${kc[@]}" get namespaces -l unf.network/scale-fixture=true -o json | jq '.items | length') -eq 0 ]]
post_cleanup_status=$(wait_for_baseline_cleanup "${baseline_namespaces}" \
    "${baseline_policies}" "${baseline_indexed}" 180)

write_result passed 0
result_written=true
echo "Kind scale/failure qualification passed: deterministic bounded fixture, measured convergence and churn, simultaneous two-agent last-known-good recovery with the controller offline, dual-stack allow/deny continuity, bounded queue/error accounting, exact cleanup, and schema-versioned environment evidence at ${result_file}"
