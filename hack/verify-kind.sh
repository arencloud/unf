#!/usr/bin/env bash
set -euo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
kubeconfig=${KUBECONFIG:-"${project_root}/.tools/kind-unf-dev.kubeconfig"}
context=${KUBE_CONTEXT:-kind-unf-dev}
controller_port=${UNF_CONTROLLER_TEST_PORT:-19962}
controller_internal_port=${UNF_CONTROLLER_INTERNAL_TEST_PORT:-19964}
controller_internal_host=unf-controller.unf-system.svc.cluster.local
controller_internal_url=https://${controller_internal_host}:${controller_internal_port}
unfctl=${UNFCTL:-"${project_root}/target/debug/unfctl"}
temporary_dir=$(mktemp -d)
control_plane_node=${UNF_KIND_CONTROL_PLANE_NODE:-unf-dev-control-plane}
worker_node=${UNF_KIND_WORKER_NODE:-unf-dev-worker}
topology_probe_manifest=${temporary_dir}/topology-probe.yaml
policy_transition_attempts=${UNF_POLICY_TRANSITION_ATTEMPTS:-30}
controller_forward_pid=
handoff_probe_pid=
map_pressure_pid=
map_pressure_helper=
pressure_inactive_bank=
controller_scaled_down=false
policy_mutated=false
network_policy_mutated=false
network_policy_protocol_mutated=false
network_policy_peer_mutated=false
network_policy_deleted=false
network_policy_conformance_created=false
network_policy_sctp_created=false
namespace_mutated=false
topology_service_created=false
bpf_fault_helper_created=false
egress_recovery_policy_created=false
stale_abi_fixture_helper=
stale_abi_unknown_helper=
network_policy_selector_peer='[{"namespaceSelector":{"matchLabels":{"environment":"production"},"matchExpressions":[{"key":"team","operator":"In","values":["checkout"]}]},"podSelector":{"matchExpressions":[{"key":"app.kubernetes.io/name","operator":"In","values":["client"]}]}}]'

[[ ${control_plane_node} =~ ^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$ ]] || {
    echo "invalid Kind control-plane Node name: ${control_plane_node}" >&2
    exit 1
}
[[ ${worker_node} =~ ^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$ ]] || {
    echo "invalid Kind worker Node name: ${worker_node}" >&2
    exit 1
}
[[ ${policy_transition_attempts} =~ ^[0-9]+$ ]] \
    && ((policy_transition_attempts >= 30 && policy_transition_attempts <= 180)) || {
    echo "policy transition attempts must be an integer from 30 through 180" >&2
    exit 1
}
sed "s/nodeName: unf-dev-control-plane/nodeName: ${control_plane_node}/" \
    "${project_root}/deploy/examples/topology-probe.yaml" >"${topology_probe_manifest}"

cleanup() {
    if [[ -n ${handoff_probe_pid} ]]; then
        "${kc[@]}" exec -n frontend client -- touch /tmp/unf-handoff-stop \
            >/dev/null 2>&1 || true
        kill "${handoff_probe_pid}" 2>/dev/null || true
        wait "${handoff_probe_pid}" 2>/dev/null || true
    fi
    if [[ -n ${map_pressure_pid} ]]; then
        if [[ -n ${map_pressure_helper} ]]; then
            "${kc[@]}" -n unf-system exec "${map_pressure_helper}" -- \
                touch /run/unf-test/pressure-stop >/dev/null 2>&1 || true
        fi
        wait "${map_pressure_pid}" 2>/dev/null || true
    fi
    if [[ ${controller_scaled_down} == true ]]; then
        "${kc[@]}" -n unf-system scale deployment/unf-controller --replicas=1 \
            >/dev/null 2>&1 || true
    fi
    if [[ ${network_policy_sctp_created} == true ]]; then
        "${kc[@]}" delete -f \
            "${project_root}/deploy/examples/networkpolicy-sctp.yaml" \
            --ignore-not-found >/dev/null 2>&1 || true
    fi
    if [[ ${network_policy_conformance_created} == true ]]; then
        "${kc[@]}" delete -f \
            "${project_root}/deploy/examples/networkpolicy-conformance.yaml" \
            --ignore-not-found >/dev/null 2>&1 || true
    fi
    if [[ ${topology_service_created} == true ]]; then
        "${kc[@]}" delete -f "${project_root}/deploy/examples/topology-probe.yaml" \
            --ignore-not-found >/dev/null 2>&1 || true
    fi
    if [[ ${bpf_fault_helper_created} == true ]]; then
        if [[ -n ${stale_abi_unknown_helper} ]]; then
            "${kc[@]}" -n unf-system exec "${stale_abi_unknown_helper}" -- \
                rmdir /sys/fs/bpf/unf/v1/unknown-state >/dev/null 2>&1 || true
        fi
        if [[ -n ${stale_abi_fixture_helper} ]]; then
            "${kc[@]}" -n unf-system exec "${stale_abi_fixture_helper}" -- \
                rm -rf /sys/fs/bpf/unf/v1 >/dev/null 2>&1 || true
        fi
        while read -r helper; do
            [[ -n ${helper} ]] || continue
            "${kc[@]}" -n unf-system exec "${helper}" -- \
                rm -rf /sys/fs/bpf/unf/fault-tests-v2 >/dev/null 2>&1 || true
            if [[ -n ${pressure_inactive_bank} ]]; then
                "${kc[@]}" -n unf-system exec "${helper}" -- \
                    /usr/local/bin/unf-bpf-map-pressure clear \
                    /sys/fs/bpf/unf/v3/POLICY_RULES "${pressure_inactive_bank}" \
                    >/dev/null 2>&1 || true
            fi
        done < <("${kc[@]}" -n unf-system get pods \
            -l app.kubernetes.io/name=unf-bpf-fault-helper \
            -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' 2>/dev/null || true)
        "${kc[@]}" delete -f \
            "${project_root}/deploy/examples/bpf-fault-helper.yaml" \
            --ignore-not-found >/dev/null 2>&1 || true
    fi
    if [[ ${egress_recovery_policy_created} == true ]]; then
        "${kc[@]}" -n frontend delete networkpolicy offline-egress-recovery \
            --ignore-not-found >/dev/null 2>&1 || true
    fi
    if [[ ${policy_mutated} == true ]]; then
        "${kc[@]}" patch securitypolicy -n backend frontend-to-backend \
            --type=merge -p '{"spec":{"enforcementMode":"Enforce"}}' >/dev/null 2>&1 || true
    fi
    if [[ ${network_policy_mutated} == true ]]; then
        "${kc[@]}" patch networkpolicy -n backend frontend-to-np-server --type=json \
            -p '[{"op":"replace","path":"/spec/ingress/0/ports/1/endPort","value":8083}]' \
            >/dev/null 2>&1 || true
    fi
    if [[ ${network_policy_protocol_mutated} == true ]]; then
        "${kc[@]}" patch networkpolicy -n backend frontend-to-np-server --type=json \
            -p '[{"op":"remove","path":"/spec/ingress/0/ports/2"}]' \
            >/dev/null 2>&1 || true
    fi
    if [[ ${network_policy_peer_mutated} == true ]]; then
        "${kc[@]}" patch networkpolicy -n backend frontend-to-np-server --type=json \
            -p "[{\"op\":\"replace\",\"path\":\"/spec/ingress/0/from\",\"value\":${network_policy_selector_peer}}]" \
            >/dev/null 2>&1 || true
    fi
    if [[ ${network_policy_deleted} == true ]]; then
        "${kc[@]}" apply -f "${project_root}/deploy/examples/demo.yaml" >/dev/null 2>&1 || true
    fi
    if [[ ${namespace_mutated} == true ]]; then
        "${kc[@]}" label namespace frontend environment=production team=checkout --overwrite \
            >/dev/null 2>&1 || true
    fi
    if [[ -n ${controller_forward_pid} ]]; then
        kill "${controller_forward_pid}" 2>/dev/null || true
    fi
    rm -rf "${temporary_dir}"
}
trap cleanup EXIT

kc=(kubectl --kubeconfig "${kubeconfig}" --context "${context}")

start_controller_forward() {
    "${kc[@]}" -n unf-system get configmap unf-internal-ca \
        -o 'jsonpath={.data.ca\.crt}' >"${temporary_dir}/internal-ca.crt"
    "${kc[@]}" -n unf-system port-forward service/unf-controller \
        "${controller_port}:9962" "${controller_internal_port}:9964" \
        >"${temporary_dir}/controller-forward.log" 2>&1 &
    controller_forward_pid=$!
    for _ in {1..20}; do
        if curl --fail --silent "http://127.0.0.1:${controller_port}/readyz" >/dev/null; then
            return 0
        fi
        sleep 1
    done
    return 1
}

wait_for_controller_baseline() {
    local status
    for _ in {1..30}; do
        status=$("${unfctl}" \
            --controller-url "http://127.0.0.1:${controller_port}" --output json status \
            2>/dev/null || true)
        if grep -Eq '"identities": [1-9][0-9]*' <<<"${status}" \
            && grep -Eq '"indexed_pod_ips": [1-9][0-9]*' <<<"${status}" \
            && grep -Eq '"resolved_policy_entries": [1-9][0-9]*' <<<"${status}" \
            && grep -Eq '"network_policies": [1-9][0-9]*' <<<"${status}" \
            && grep -Eq '"endpoint_slices": [1-9][0-9]*' <<<"${status}" \
            && grep -q '"rejected_network_policies": 0' <<<"${status}" \
            && grep -q '"all_converged": true' <<<"${status}"; then
            controller_status=${status}
            return 0
        fi
        sleep 1
    done
    return 1
}

agent_status() {
    "${kc[@]}" get --raw "/api/v1/namespaces/unf-system/pods/${1}/proxy/v1/status"
}

agent_metric() {
    local agent=$1 metric=$2
    "${kc[@]}" get --raw "/api/v1/namespaces/unf-system/pods/${agent}/proxy/metrics" \
        | awk -v metric="${metric}" '$1 == metric { print $2; exit }'
}

post_agent_status_with_token() {
    local token=$1 report=$2 response_path=$3
    printf 'Authorization: Bearer %s\n' "${token}" | curl \
        --silent --show-error --max-time 5 \
        --noproxy '*' \
        --cacert "${temporary_dir}/internal-ca.crt" \
        --resolve "${controller_internal_host}:${controller_internal_port}:127.0.0.1" \
        --output "${response_path}" --write-out '%{http_code}' \
        --request POST --header @- --header 'Content-Type: application/json' \
        --data-binary "${report}" \
        "${controller_internal_url}/v1/state/agents"
}

json_number() {
    local field=$1
    sed -nE "s/.*\"${field}\":([0-9]+).*/\1/p"
}

expected_attachment_mode() {
    local status=$1
    local version major minor
    version=$(sed -nE \
        's/.*"kernel_release":"([0-9]+)\.([0-9]+)[^"]*".*/\1 \2/p' <<<"${status}")
    read -r major minor <<<"${version}"
    if [[ -n ${major:-} && -n ${minor:-} \
        && ( ${major} -gt 6 || ( ${major} -eq 6 && ${minor} -ge 6 ) ) ]]; then
        echo tcx_pinned
    else
        echo legacy_netlink
    fi
}

prepare_fault_map_set() {
    local helper=$1 target=$2 omitted=$3
    "${kc[@]}" -n unf-system exec "${helper}" -- sh -eu -c '
        source=/sys/fs/bpf/unf/v3
        target=$1
        omitted=$2
        rm -rf "${target}"
        mkdir -p "${target}"
        for map in \
            IDENTITY_V4 IDENTITY_V4_B IDENTITY_V6 IDENTITY_V6_B \
            IDENTITY_CONFIG POLICY_RULES POLICY_IPV4 POLICY_IPV6 \
            EGRESS_IPV4 EGRESS_IPV6 POLICY_CONFIG
        do
            if [ "${map}" = "${omitted}" ]; then
                continue
            fi
            bpftool map pin pinned "${source}/${map}" "${target}/${map}"
        done
    ' sh "${target}" "${omitted}"
}

expect_agent_startup_rejection() {
    local agent=$1 pin_path=$2 expected=$3 output
    if output=$("${kc[@]}" -n unf-system exec "${agent}" -- \
        env -u UNF_CONTROLLER_URL /usr/local/bin/unf-component \
        --listen 127.0.0.1:19964 \
        --all-interfaces \
        --ebpf-object /opt/unf/ebpf/unf-ebpf-tc \
        --bpf-pin-path "${pin_path}" 2>&1); then
        echo "faulted persistent state unexpectedly passed agent startup" >&2
        return 1
    fi
    if ! grep -Fq "${expected}" <<<"${output}"; then
        echo "agent rejected faulted state without the expected reason: ${expected}" >&2
        printf '%s\n' "${output}" >&2
        return 1
    fi
}

wait_for_aggregated_agent_convergence() {
    local expected_agents=$1
    local status expected reporting missing stale converged unexpected
    for _ in {1..30}; do
        status=$("${unfctl}" \
            --controller-url "http://127.0.0.1:${controller_port}" --output json status)
        expected=$(sed -nE 's/.*"expected_agents": ([0-9]+).*/\1/p' <<<"${status}")
        reporting=$(sed -nE 's/.*"reporting_agents": ([0-9]+).*/\1/p' <<<"${status}")
        missing=$(sed -nE 's/.*"missing_agents": ([0-9]+).*/\1/p' <<<"${status}")
        stale=$(sed -nE 's/.*"stale_agents": ([0-9]+).*/\1/p' <<<"${status}")
        converged=$(sed -nE 's/.*"converged_agents": ([0-9]+).*/\1/p' <<<"${status}")
        unexpected=$(sed -nE 's/.*"unexpected_agents": ([0-9]+).*/\1/p' <<<"${status}")
        if [[ ${expected} == "${expected_agents}" && ${reporting} == "${expected_agents}" \
            && ${converged} == "${expected_agents}" && ${missing} == 0 && ${stale} == 0 \
            && ${unexpected} == 0 ]] && grep -q '"all_converged": true' <<<"${status}"; then
            agent_convergence_status=${status}
            return 0
        fi
        sleep 1
    done
    return 1
}

wait_for_policy_transition() {
    local floor_revision=$1
    local all_converged status desired applied bank pod candidate_revision controller_revision
    local attempt
    for ((attempt = 1; attempt <= policy_transition_attempts; attempt++)); do
        all_converged=true
        candidate_revision=
        controller_revision=$("${unfctl}" \
            --controller-url "http://127.0.0.1:${controller_port}" --output json status \
            | sed -nE 's/.*"policy": ([0-9]+).*/\1/p')
        for pod in "${agent_pods[@]}"; do
            status=$(agent_status "${pod}" || true)
            desired=$(json_number desired_policy_revision <<<"${status}")
            applied=$(json_number applied_policy_revision <<<"${status}")
            bank=$(json_number active_policy_bank <<<"${status}")
            if [[ -z ${applied} || ${applied} -le ${floor_revision} \
                || ${desired} != "${applied}" || ${bank} == "${policy_banks[${pod}]}" ]]; then
                all_converged=false
                break
            fi
            if [[ -n ${candidate_revision} && ${candidate_revision} != "${applied}" ]]; then
                all_converged=false
                break
            fi
            candidate_revision=${applied}
        done
        if [[ -z ${candidate_revision} || ${candidate_revision} != "${controller_revision}" ]]; then
            all_converged=false
        fi
        if [[ ${all_converged} == true ]]; then
            transition_revision=${candidate_revision}
            for pod in "${agent_pods[@]}"; do
                status=$(agent_status "${pod}")
                policy_banks[${pod}]=$(json_number active_policy_bank <<<"${status}")
            done
            return 0
        fi
        sleep 1
    done
    echo "policy transition timed out: floor=${floor_revision} controller=${controller_revision:-unknown} attempts=${policy_transition_attempts}" >&2
    for pod in "${agent_pods[@]}"; do
        status=$(agent_status "${pod}" || true)
        desired=$(json_number desired_policy_revision <<<"${status}")
        applied=$(json_number applied_policy_revision <<<"${status}")
        bank=$(json_number active_policy_bank <<<"${status}")
        echo "policy transition agent=${pod} desired=${desired:-unknown} applied=${applied:-unknown} bank=${bank:-unknown} previous_bank=${policy_banks[${pod}]:-unknown}" >&2
    done
    return 1
}

wait_for_policy_batch_convergence() {
    local floor_revision=$1
    local all_converged status desired applied pod candidate_revision controller_revision
    for _ in {1..30}; do
        all_converged=true
        candidate_revision=
        controller_revision=$("${unfctl}" \
            --controller-url "http://127.0.0.1:${controller_port}" --output json status \
            | sed -nE 's/.*"policy": ([0-9]+).*/\1/p')
        for pod in "${agent_pods[@]}"; do
            status=$(agent_status "${pod}" || true)
            desired=$(json_number desired_policy_revision <<<"${status}")
            applied=$(json_number applied_policy_revision <<<"${status}")
            if [[ -z ${applied} || ${applied} -le ${floor_revision} \
                || ${desired} != "${applied}" ]]; then
                all_converged=false
                break
            fi
            if [[ -n ${candidate_revision} && ${candidate_revision} != "${applied}" ]]; then
                all_converged=false
                break
            fi
            candidate_revision=${applied}
        done
        if [[ -z ${candidate_revision} || ${candidate_revision} != "${controller_revision}" ]]; then
            all_converged=false
        fi
        if [[ ${all_converged} == true ]]; then
            transition_revision=${candidate_revision}
            for pod in "${agent_pods[@]}"; do
                status=$(agent_status "${pod}")
                policy_banks[${pod}]=$(json_number active_policy_bank <<<"${status}")
            done
            return 0
        fi
        sleep 1
    done
    return 1
}

all_agent_logs() {
    "${kc[@]}" -n unf-system logs -l app.kubernetes.io/name=unf-agent \
        --all-containers=true --prefix=true --since=30s --tail=-1
}

wait_for_shadow_deny_provenance() {
    local revision=$1 logs line
    for _ in {1..20}; do
        logs=$(all_agent_logs)
        line=$(grep '"destination_port":9090' <<<"${logs}" \
            | grep '"shadow_verdict":2' | grep "\"policy_revision\":${revision}" \
            | tail -n 1 || true)
        if grep -q '"verdict":"Allow"' <<<"${line}" \
            && grep -Eq '"shadow_policy_id":[1-9][0-9]*' <<<"${line}" \
            && grep -Eq '"shadow_rule_id":[1-9][0-9]*' <<<"${line}"; then
            return 0
        fi
        "${kc[@]}" exec -n frontend client -- \
            wget -T 2 -t 1 -qO- http://server.backend.svc.cluster.local:9090 \
            >/dev/null
        sleep 1
    done
    return 1
}

has_policy_provenance() {
    local line=$1
    grep -Eq '"source_identity":[1-9][0-9]*' <<<"${line}" \
        && grep -Eq '"destination_identity":[1-9][0-9]*' <<<"${line}" \
        && grep -Eq '"policy_id":[1-9][0-9]*' <<<"${line}"
}

has_rule_provenance() {
    local line=$1
    has_policy_provenance "${line}" \
        && grep -Eq '"rule_id":[1-9][0-9]*' <<<"${line}"
}

wait_for_enforced_provenance() {
    local revision=$1 logs
    for _ in {1..20}; do
        logs=$(all_agent_logs)
        allow_line=$(grep '"destination_port":8080' <<<"${logs}" \
            | grep '"address_family":4' | grep '"verdict":"Allow"' \
            | grep "\"policy_revision\":${revision}" | tail -n 1 || true)
        deny_line=$(grep '"destination_port":9090' <<<"${logs}" \
            | grep '"address_family":4' | grep '"verdict":"Deny"' | grep '"reason":2' \
            | grep "\"policy_revision\":${revision}" | tail -n 1 || true)
        network_policy_allow_line=$(grep '"destination_port":8081' <<<"${logs}" \
            | grep '"address_family":4' | grep '"verdict":"Allow"' | grep '"reason":1' \
            | grep "\"policy_revision\":${revision}" | tail -n 1 || true)
        network_policy_deny_line=$(grep '"destination_port":9091' <<<"${logs}" \
            | grep '"address_family":4' | grep '"verdict":"Deny"' | grep '"reason":3' \
            | grep "\"policy_revision\":${revision}" | tail -n 1 || true)
        network_policy_range_line=$(grep '"destination_port":8083' <<<"${logs}" \
            | grep '"address_family":4' | grep '"verdict":"Allow"' | grep '"reason":1' \
            | grep "\"policy_revision\":${revision}" | tail -n 1 || true)
        ipv6_allow_line=$(grep '"destination_port":8080' <<<"${logs}" \
            | grep '"address_family":6' | grep '"verdict":"Allow"' \
            | grep "\"policy_revision\":${revision}" | tail -n 1 || true)
        ipv6_deny_line=$(grep '"destination_port":9090' <<<"${logs}" \
            | grep '"address_family":6' | grep '"verdict":"Deny"' | grep '"reason":2' \
            | grep "\"policy_revision\":${revision}" | tail -n 1 || true)
        ipv6_network_policy_allow_line=$(grep '"destination_port":8081' <<<"${logs}" \
            | grep '"address_family":6' | grep '"verdict":"Allow"' | grep '"reason":1' \
            | grep "\"policy_revision\":${revision}" | tail -n 1 || true)
        ipv6_network_policy_deny_line=$(grep '"destination_port":9091' <<<"${logs}" \
            | grep '"address_family":6' | grep '"verdict":"Deny"' | grep '"reason":3' \
            | grep "\"policy_revision\":${revision}" | tail -n 1 || true)
        if has_policy_provenance "${allow_line}" \
            && has_rule_provenance "${deny_line}" \
            && has_policy_provenance "${network_policy_allow_line}" \
            && has_policy_provenance "${network_policy_deny_line}" \
            && has_policy_provenance "${network_policy_range_line}" \
            && has_policy_provenance "${ipv6_allow_line}" \
            && has_rule_provenance "${ipv6_deny_line}" \
            && has_policy_provenance "${ipv6_network_policy_allow_line}" \
            && has_policy_provenance "${ipv6_network_policy_deny_line}"; then
            return 0
        fi
        "${kc[@]}" exec -n frontend client -- \
            wget -T 2 -t 1 -qO- "http://${server_ipv4}:8080" >/dev/null
        "${kc[@]}" exec -n frontend client -- \
            wget -T 2 -t 1 -qO- "http://${server_ipv4}:9090" >/dev/null 2>&1 || true
        "${kc[@]}" exec -n frontend client -- \
            wget -T 2 -t 1 -qO- "http://${network_policy_server_ipv4}:8081" >/dev/null
        "${kc[@]}" exec -n frontend client -- \
            wget -T 2 -t 1 -qO- "http://${network_policy_server_ipv4}:8083" >/dev/null
        "${kc[@]}" exec -n frontend client -- \
            wget -T 2 -t 1 -qO- "http://${network_policy_server_ipv4}:9091" \
            >/dev/null 2>&1 || true
        "${kc[@]}" exec -n frontend client -- \
            wget -T 2 -t 1 -qO- "http://[${server_ipv6}]:8080" >/dev/null
        "${kc[@]}" exec -n frontend client -- \
            wget -T 2 -t 1 -qO- "http://[${server_ipv6}]:9090" >/dev/null 2>&1 || true
        "${kc[@]}" exec -n frontend client -- \
            wget -T 2 -t 1 -qO- "http://[${network_policy_server_ipv6}]:8081" >/dev/null
        "${kc[@]}" exec -n frontend client -- \
            wget -T 2 -t 1 -qO- "http://[${network_policy_server_ipv6}]:9091" \
            >/dev/null 2>&1 || true
        sleep 1
    done
    return 1
}

wait_for_controller_policy_counts() {
    local accepted=$1
    local rejected=$2
    local floor_revision=$3
    local status actual_accepted actual_rejected revision
    for _ in {1..30}; do
        status=$("${unfctl}" \
            --controller-url "http://127.0.0.1:${controller_port}" --output json status)
        actual_accepted=$(sed -nE 's/.*"network_policies": ([0-9]+).*/\1/p' <<<"${status}")
        actual_rejected=$(sed -nE 's/.*"rejected_network_policies": ([0-9]+).*/\1/p' \
            <<<"${status}")
        revision=$(sed -nE 's/.*"policy": ([0-9]+).*/\1/p' <<<"${status}")
        if [[ ${actual_accepted} == "${accepted}" && ${actual_rejected} == "${rejected}" \
            && -n ${revision} && ${revision} -gt ${floor_revision} ]]; then
            controller_state_revision=${revision}
            return 0
        fi
        sleep 1
    done
    return 1
}

wait_for_topology_transition() {
    local floor_revision=$1
    local snapshot revision
    for _ in {1..30}; do
        snapshot=$("${unfctl}" \
            --controller-url "http://127.0.0.1:${controller_port}" --output json topology)
        revision=$(sed -nE 's/.*"revision": ([0-9]+).*/\1/p' <<<"${snapshot}")
        if [[ -n ${revision} && ${revision} -gt ${floor_revision} ]]; then
            topology_state_revision=${revision}
            return 0
        fi
        sleep 1
    done
    return 1
}

wait_for_topology_probe_backend() {
    local floor_revision=$1
    local expected_ready=$2
    local snapshot compact revision
    for _ in {1..30}; do
        snapshot=$("${unfctl}" \
            --controller-url "http://127.0.0.1:${controller_port}" --output json topology)
        compact=$(tr -d '\n' <<<"${snapshot}")
        revision=$(sed -nE 's/.*"revision": ([0-9]+).*/\1/p' <<<"${snapshot}")
        if [[ -n ${revision} && ${revision} -gt ${floor_revision} ]] \
            && grep -q '"reference": "frontend/topology-probe"' <<<"${compact}" \
            && grep -q "\"endpoint_slice\": \"frontend/topology-probe-manual\".*\"ready\": ${expected_ready}.*\"target_workload\": \"frontend/client\"" \
                <<<"${compact}"; then
            topology_state_revision=${revision}
            topology_probe_snapshot=${snapshot}
            return 0
        fi
        sleep 1
    done
    return 1
}

wait_for_topology_probe_backend_removal() {
    local floor_revision=$1
    local snapshot compact revision
    for _ in {1..30}; do
        snapshot=$("${unfctl}" \
            --controller-url "http://127.0.0.1:${controller_port}" --output json topology)
        compact=$(tr -d '\n' <<<"${snapshot}")
        revision=$(sed -nE 's/.*"revision": ([0-9]+).*/\1/p' <<<"${snapshot}")
        if [[ -n ${revision} && ${revision} -gt ${floor_revision} ]] \
            && grep -q '"reference": "frontend/topology-probe"' <<<"${compact}" \
            && ! grep -q '"endpoint_slice": "frontend/topology-probe-manual"' \
                <<<"${compact}"; then
            topology_state_revision=${revision}
            return 0
        fi
        sleep 1
    done
    return 1
}

wait_for_historical_demo_flow() {
    local snapshot
    for _ in {1..30}; do
        snapshot=$("${unfctl}" \
            --controller-url "http://127.0.0.1:${controller_port}" --output json flows)
        if grep -q '"source_workloads": \[' <<<"${snapshot}" \
            && grep -q '"frontend/client"' <<<"${snapshot}" \
            && grep -q '"backend/server"' <<<"${snapshot}" \
            && grep -q '"destination_port": 8080' <<<"${snapshot}"; then
            flow_history=${snapshot}
            return 0
        fi
        "${kc[@]}" exec -n frontend client -- \
            wget -T 2 -t 1 -qO- http://server.backend.svc.cluster.local:8080 >/dev/null
        sleep 1
    done
    return 1
}

wait_for_historical_ipv6_demo_flow() {
    local snapshot
    for _ in {1..30}; do
        snapshot=$("${unfctl}" \
            --controller-url "http://127.0.0.1:${controller_port}" --output json flows)
        if jq -e \
            --arg source_ipv6 "${client_ipv6}" \
            --arg destination_ipv6 "${server_ipv6}" '
                any(.entries[];
                    .key.source_ipv6 == $source_ipv6
                    and .key.destination_ipv6 == $destination_ipv6
                    and .key.destination_port == 8080
                    and (.source_workloads | index("frontend/client")) != null
                    and (.destination_workloads | index("backend/server")) != null
                )
            ' <<<"${snapshot}" >/dev/null; then
            ipv6_flow_history=${snapshot}
            return 0
        fi
        "${kc[@]}" exec -n frontend client -- \
            wget -T 2 -t 1 -qO- "http://[${server_ipv6}]:8080" >/dev/null
        sleep 1
    done
    return 1
}

pod_ipv4() {
    "${kc[@]}" get pod -n "$1" "$2" \
        -o jsonpath='{range .status.podIPs[*]}{.ip}{"\n"}{end}' \
        | awk 'index($0, ".") > 0 && index($0, ":") == 0 { print; exit }'
}

pod_ipv6() {
    "${kc[@]}" get pod -n "$1" "$2" \
        -o jsonpath='{range .status.podIPs[*]}{.ip}{"\n"}{end}' \
        | awk 'index($0, ":") > 0 { print; exit }'
}

"${kc[@]}" wait --for=condition=Ready nodes --all --timeout=120s
"${kc[@]}" -n kube-system rollout status daemonset/kindnet --timeout=120s
"${kc[@]}" -n unf-system rollout status deployment/unf-controller --timeout=120s
"${kc[@]}" -n unf-system rollout status daemonset/unf-agent --timeout=120s

mapfile -t agent_pods < <("${kc[@]}" -n unf-system get pods \
    -l app.kubernetes.io/name=unf-agent -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}')
if [[ ${#agent_pods[@]} -eq 0 ]]; then
    echo "UNF agent DaemonSet has no pods" >&2
    exit 1
fi

if ! start_controller_forward; then
    echo "controller port-forward did not become ready" >&2
    exit 1
fi

if ! wait_for_controller_baseline; then
    echo "controller did not reconcile the demo baseline after Pod updates" >&2
    exit 1
fi

allow_explanation=$("${unfctl}" \
    --controller-url "http://127.0.0.1:${controller_port}" --output json \
    explain --from frontend/client --to backend/server --protocol tcp --port 8080)
grep -q '"reason": "ExplicitRule"' <<<"${allow_explanation}"
grep -q '"verdict": "Allow"' <<<"${allow_explanation}"
grep -q '"dataplane_enforcement": true' <<<"${allow_explanation}"

deny_explanation=$("${unfctl}" \
    --controller-url "http://127.0.0.1:${controller_port}" --output json \
    explain --from frontend/client --to backend/server --protocol tcp --port 9090)
grep -q '"reason": "ExplicitRule"' <<<"${deny_explanation}"
grep -q '"verdict": "Deny"' <<<"${deny_explanation}"
grep -Eq '"policy_id": [1-9][0-9]*' <<<"${deny_explanation}"
grep -Eq '"rule_id": [1-9][0-9]*' <<<"${deny_explanation}"

network_policy_allow_explanation=$("${unfctl}" \
    --controller-url "http://127.0.0.1:${controller_port}" --output json \
    explain --from frontend/client --to backend/np-server --protocol tcp --port 8081)
grep -q '"reason": "ExplicitRule"' <<<"${network_policy_allow_explanation}"
grep -q '"verdict": "Allow"' <<<"${network_policy_allow_explanation}"
grep -Eq '"policy_id": [1-9][0-9]*' <<<"${network_policy_allow_explanation}"

network_policy_deny_explanation=$("${unfctl}" \
    --controller-url "http://127.0.0.1:${controller_port}" --output json \
    explain --from frontend/client --to backend/np-server --protocol tcp --port 9091)
grep -q '"reason": "DefaultAction"' <<<"${network_policy_deny_explanation}"
grep -q '"verdict": "Deny"' <<<"${network_policy_deny_explanation}"
grep -Eq '"policy_id": [1-9][0-9]*' <<<"${network_policy_deny_explanation}"

for port in 8082 8083; do
    range_explanation=$("${unfctl}" \
        --controller-url "http://127.0.0.1:${controller_port}" --output json \
        explain --from frontend/client --to backend/np-server --protocol tcp --port "${port}")
    grep -q '"reason": "ExplicitRule"' <<<"${range_explanation}"
    grep -q '"verdict": "Allow"' <<<"${range_explanation}"
done
outside_range_explanation=$("${unfctl}" \
    --controller-url "http://127.0.0.1:${controller_port}" --output json \
    explain --from frontend/client --to backend/np-server --protocol tcp --port 8084)
grep -q '"reason": "DefaultAction"' <<<"${outside_range_explanation}"
grep -q '"verdict": "Deny"' <<<"${outside_range_explanation}"

declare -A policy_banks
initial_synced=false
for _ in {1..30}; do
    initial_synced=true
    expected_policy_revision=
    controller_status=$("${unfctl}" \
        --controller-url "http://127.0.0.1:${controller_port}" --output json status)
    controller_identity_epoch=$(sed -nE 's/.*"identity_epoch": ([0-9]+).*/\1/p' \
        <<<"${controller_status}")
    controller_identity_revision=$(sed -nE 's/.*"identity": ([0-9]+).*/\1/p' \
        <<<"${controller_status}")
    controller_policy_revision=$(sed -nE 's/.*"policy": ([0-9]+).*/\1/p' \
        <<<"${controller_status}")
    for pod in "${agent_pods[@]}"; do
        status=$(agent_status "${pod}" || true)
        attachment_mode=$(expected_attachment_mode "${status}")
        desired_identity=$(json_number desired_identity_revision <<<"${status}")
        applied_identity=$(json_number applied_identity_revision <<<"${status}")
        desired_epoch=$(json_number desired_identity_epoch <<<"${status}")
        applied_epoch=$(json_number applied_identity_epoch <<<"${status}")
        identity_entries=$(json_number identity_map_entries <<<"${status}")
        ipv4_identity_entries=$(json_number ipv4_identity_map_entries <<<"${status}")
        ipv6_identity_entries=$(json_number ipv6_identity_map_entries <<<"${status}")
        desired_policy=$(json_number desired_policy_revision <<<"${status}")
        applied_policy=$(json_number applied_policy_revision <<<"${status}")
        desired_policy_epoch=$(json_number desired_policy_epoch <<<"${status}")
        applied_policy_epoch=$(json_number applied_policy_epoch <<<"${status}")
        policy_entries=$(json_number policy_map_entries <<<"${status}")
        if [[ -z ${desired_identity} || ${desired_identity} != "${applied_identity}" \
            || ${applied_identity} != "${controller_identity_revision}" \
            || -z ${desired_epoch} || ${desired_epoch} != "${applied_epoch}" \
            || ${applied_epoch} != "${controller_identity_epoch}" \
            || ${identity_entries:-0} -eq 0 \
            || ${ipv4_identity_entries:-0} -eq 0 \
            || ${ipv6_identity_entries:-0} -eq 0 \
            || -z ${desired_policy} || ${desired_policy} != "${applied_policy}" \
            || ${applied_policy} != "${controller_policy_revision}" \
            || -z ${desired_policy_epoch} || ${desired_policy_epoch} != "${applied_policy_epoch}" \
            || ${applied_policy_epoch} != "${controller_identity_epoch}" \
            || ${policy_entries:-0} -eq 0 ]] \
            || ! grep -q '"bpf_loaded":true' <<<"${status}" \
            || ! grep -q "\"tc_attachment_mode\":\"${attachment_mode}\"" <<<"${status}"; then
            initial_synced=false
            break
        fi
        if [[ ${attachment_mode} == tcx_pinned ]] \
            && ! "${kc[@]}" -n unf-system exec "${pod}" -- sh -c \
                'find /sys/fs/bpf/unf/v3/links -maxdepth 1 -type f -name "tcx-ingress-*" | grep -q .' \
                >/dev/null 2>&1; then
            initial_synced=false
            break
        fi
        if [[ -n ${expected_policy_revision} && ${expected_policy_revision} != "${applied_policy}" ]]; then
            initial_synced=false
            break
        fi
        expected_policy_revision=${applied_policy}
        policy_banks[${pod}]=$(json_number active_policy_bank <<<"${status}")
    done
    if [[ ${initial_synced} == true ]]; then
        break
    fi
    sleep 1
done
if [[ ${initial_synced} != true ]]; then
    echo "UNF agents did not apply matching identity and policy revisions" >&2
    exit 1
fi
initial_policy_revision=${expected_policy_revision}

for pod in "${agent_pods[@]}"; do
    filtered_management_events=$(agent_metric \
        "${pod}" unf_management_flow_events_filtered_total || true)
    if [[ -z ${filtered_management_events} || ${filtered_management_events} -eq 0 ]]; then
        echo "agent did not account for filtered controller management traffic" >&2
        exit 1
    fi
done

if ! wait_for_aggregated_agent_convergence "${#agent_pods[@]}"; then
    echo "controller did not aggregate converged status from every node agent" >&2
    exit 1
fi
grep -q '"schema_version": 2' <<<"${agent_convergence_status}"
grep -Fq "\"node_name\": \"${control_plane_node}\"" <<<"${agent_convergence_status}"
grep -Fq "\"node_name\": \"${worker_node}\"" <<<"${agent_convergence_status}"
if [[ $(grep -c '"converged": true' <<<"${agent_convergence_status}") -ne 2 ]]; then
    echo "controller did not expose two converged per-node acknowledgements" >&2
    exit 1
fi

authentication_agent=${agent_pods[0]}
authentication_report=$(agent_status "${authentication_agent}")
if ! grep -q '"schema_version":2' <<<"${authentication_report}" \
    || ! grep -Eq '"pod_name":"unf-agent-[^"]+"' <<<"${authentication_report}" \
    || ! grep -Eq '"pod_uid":"[^"]+"' <<<"${authentication_report}"; then
    echo "agent did not expose its schema v2 Pod-bound acknowledgement identity" >&2
    exit 1
fi
plaintext_snapshot_code=$(curl --silent --show-error --max-time 5 \
    --output "${temporary_dir}/plaintext-snapshot.json" --write-out '%{http_code}' \
    "http://127.0.0.1:${controller_port}/v1/state/identities")
plaintext_report_code=$(curl --silent --show-error --max-time 5 \
    --output "${temporary_dir}/plaintext-agent-report.json" --write-out '%{http_code}' \
    --request POST --header 'Content-Type: application/json' \
    --data-binary "${authentication_report}" \
    "http://127.0.0.1:${controller_port}/v1/state/agents")
if [[ ${plaintext_snapshot_code} != 404 || ${plaintext_report_code} != 405 ]]; then
    echo "controller exposed an agent-only route on its plaintext public listener" >&2
    exit 1
fi
if curl --fail --silent --show-error --max-time 5 --noproxy '*' \
    --resolve "${controller_internal_host}:${controller_internal_port}:127.0.0.1" \
    "${controller_internal_url}/v1/state/identities" >/dev/null 2>&1; then
    echo "controller internal TLS unexpectedly validated without the UNF CA" >&2
    exit 1
fi
unauthenticated_code=$(curl --silent --show-error --max-time 5 --noproxy '*' \
    --cacert "${temporary_dir}/internal-ca.crt" \
    --resolve "${controller_internal_host}:${controller_internal_port}:127.0.0.1" \
    --output "${temporary_dir}/unauthenticated-agent-report.json" \
    --write-out '%{http_code}' --request POST \
    --header 'Content-Type: application/json' --data-binary "${authentication_report}" \
    "${controller_internal_url}/v1/state/agents")
if [[ ${unauthenticated_code} != 401 ]] \
    || ! grep -q 'missing bearer token' \
        "${temporary_dir}/unauthenticated-agent-report.json"; then
    echo "controller did not reject an unauthenticated agent report" >&2
    exit 1
fi
invalid_token_code=$(post_agent_status_with_token \
    invalid-token "${authentication_report}" \
    "${temporary_dir}/invalid-token-agent-report.json")
if [[ ${invalid_token_code} != 401 ]] \
    || ! grep -q 'agent token was not authenticated' \
        "${temporary_dir}/invalid-token-agent-report.json"; then
    echo "controller did not reject an invalid agent token" >&2
    exit 1
fi
authentication_token=$("${kc[@]}" -n unf-system exec "${authentication_agent}" -- \
    sh -eu -c 'cat /var/run/secrets/unf-agent/token')
if [[ -z ${authentication_token} ]]; then
    echo "agent projected authentication token is empty" >&2
    exit 1
fi
authenticated_code=$(post_agent_status_with_token \
    "${authentication_token}" "${authentication_report}" \
    "${temporary_dir}/authenticated-agent-report.json")
if [[ ${authenticated_code} != 204 ]]; then
    cat "${temporary_dir}/authenticated-agent-report.json" >&2
    echo "controller rejected a valid Pod-bound agent token" >&2
    exit 1
fi
printf 'Authorization: Bearer %s\n' "${authentication_token}" | curl \
    --fail --silent --show-error --max-time 5 --noproxy '*' \
    --cacert "${temporary_dir}/internal-ca.crt" \
    --resolve "${controller_internal_host}:${controller_internal_port}:127.0.0.1" \
    --header @- "${controller_internal_url}/v1/state/identities" \
    >"${temporary_dir}/authenticated-identity-snapshot.json"
grep -q '"schema_version"' "${temporary_dir}/authenticated-identity-snapshot.json"
forged_report=$(sed -E \
    's/"node_name":"[^"]+"/"node_name":"forged-node"/' \
    <<<"${authentication_report}")
forged_code=$(post_agent_status_with_token \
    "${authentication_token}" "${forged_report}" \
    "${temporary_dir}/forged-agent-report.json")
unset authentication_token
if [[ ${forged_code} != 403 ]] \
    || ! grep -q 'authoritative Pod placement' \
        "${temporary_dir}/forged-agent-report.json"; then
    echo "controller did not reject a valid token with a forged Node claim" >&2
    exit 1
fi
authentication_failures=$(curl --fail --silent \
    "http://127.0.0.1:${controller_port}/metrics" \
    | awk '$1 == "unf_agent_authentication_failures_total" { print $2; exit }')
if [[ -z ${authentication_failures} || ${authentication_failures} -lt 3 ]]; then
    echo "controller did not account for rejected agent credentials" >&2
    exit 1
fi
controller_status_table=$("${unfctl}" \
    --controller-url "http://127.0.0.1:${controller_port}" status)
grep -q '^Controller Status$' <<<"${controller_status_table}"
grep -q 'agents.*converged=2/2.*all_converged=true' <<<"${controller_status_table}"
grep -Eq "agent.*${control_plane_node}.*converged=true" <<<"${controller_status_table}"
grep -Eq "agent.*${worker_node}.*converged=true" <<<"${controller_status_table}"

initial_topology=$("${unfctl}" \
    --controller-url "http://127.0.0.1:${controller_port}" --output json topology)
compact_initial_topology=$(tr -d '\n' <<<"${initial_topology}")
grep -q '"schema_version": 3' <<<"${initial_topology}"
grep -Eq '"revision": [1-9][0-9]*' <<<"${initial_topology}"
grep -Eq '"identity_revision": [1-9][0-9]*' <<<"${initial_topology}"
grep -Fq "\"name\": \"${control_plane_node}\"" <<<"${initial_topology}"
grep -Fq "\"name\": \"${worker_node}\"" <<<"${initial_topology}"
grep -q '"reference": "frontend/client"' <<<"${initial_topology}"
grep -q '"reference": "backend/server"' <<<"${initial_topology}"
grep -q '"reference": "backend/np-server"' <<<"${initial_topology}"
grep -Fq "\"node_name\": \"${control_plane_node}\"" <<<"${initial_topology}"
grep -Fq "\"node_name\": \"${worker_node}\"" <<<"${initial_topology}"
grep -Eq '"ipv6_addresses": \[[[:space:]]*"[^" ]*:[^" ]*"' \
    <<<"${compact_initial_topology}"
grep -q '"selected_workloads": \[' <<<"${initial_topology}"
initial_topology_revision=$(sed -nE 's/.*"revision": ([0-9]+).*/\1/p' \
    <<<"${initial_topology}")

"${kc[@]}" apply -f "${topology_probe_manifest}" >/dev/null
topology_service_created=true
if ! wait_for_topology_probe_backend "${initial_topology_revision}" false; then
    echo "controller did not expose the not-ready EndpointSlice backend" >&2
    exit 1
fi
created_topology_revision=${topology_state_revision}
compact_topology_probe=$(tr -d '\n' <<<"${topology_probe_snapshot}")
grep -q '"selected_workloads": \[\]' <<<"${compact_topology_probe}"
grep -q '"serving": true' <<<"${compact_topology_probe}"
grep -q '"terminating": false' <<<"${compact_topology_probe}"
grep -q '"port": 8080' <<<"${compact_topology_probe}"

"${kc[@]}" patch endpointslice -n frontend topology-probe-manual --type=json \
    -p '[{"op":"replace","path":"/endpoints/0/conditions/ready","value":true}]' >/dev/null
if ! wait_for_topology_probe_backend "${created_topology_revision}" true; then
    echo "controller did not advance topology after EndpointSlice readiness changed" >&2
    exit 1
fi
ready_topology_revision=${topology_state_revision}

"${kc[@]}" delete endpointslice -n frontend topology-probe-manual >/dev/null
if ! wait_for_topology_probe_backend_removal "${ready_topology_revision}"; then
    echo "controller did not remove the deleted EndpointSlice backend" >&2
    exit 1
fi
backend_removed_topology_revision=${topology_state_revision}

"${kc[@]}" delete -f "${project_root}/deploy/examples/topology-probe.yaml" \
    --ignore-not-found >/dev/null
if ! wait_for_topology_transition "${backend_removed_topology_revision}"; then
    echo "controller did not advance topology after Service deletion" >&2
    exit 1
fi
restored_topology_revision=${topology_state_revision}
topology_service_created=false
restored_topology=$("${unfctl}" \
    --controller-url "http://127.0.0.1:${controller_port}" --output json topology)
if grep -q '"reference": "frontend/topology-probe"' <<<"${restored_topology}"; then
    echo "deleted Service remained in the topology snapshot" >&2
    exit 1
fi
policy_revision_after_topology=$("${unfctl}" \
    --controller-url "http://127.0.0.1:${controller_port}" --output json status \
    | sed -nE 's/.*"policy": ([0-9]+).*/\1/p')
if [[ ${policy_revision_after_topology} != "${initial_policy_revision}" ]]; then
    echo "Service-only topology changes unexpectedly changed the policy revision" >&2
    exit 1
fi

client_ipv4=$(pod_ipv4 frontend client)
server_ipv4=$(pod_ipv4 backend server)
network_policy_server_ipv4=$(pod_ipv4 backend np-server)
client_ipv6=$(pod_ipv6 frontend client)
server_ipv6=$(pod_ipv6 backend server)
network_policy_server_ipv6=$(pod_ipv6 backend np-server)
if [[ -z ${client_ipv4} || -z ${server_ipv4} || -z ${network_policy_server_ipv4} \
    || -z ${client_ipv6} || -z ${server_ipv6} || -z ${network_policy_server_ipv6} ]]; then
    echo "demo Pods do not all have dual-stack addresses" >&2
    exit 1
fi

if ! wait_for_historical_demo_flow; then
    echo "controller did not retain the exported frontend-to-backend flow" >&2
    exit 1
fi
grep -q '"schema_version": 4' <<<"${flow_history}"
grep -Eq '"revision": [1-9][0-9]*' <<<"${flow_history}"
grep -q '"capacity": 4096' <<<"${flow_history}"
grep -Eq '"retained_flows": [1-9][0-9]*' <<<"${flow_history}"
grep -Eq '"retained_observations": [1-9][0-9]*' <<<"${flow_history}"
grep -Fq "\"${worker_node}\"" <<<"${flow_history}"
if grep -q '"destination_port": 9964' <<<"${flow_history}"; then
    echo "controller management traffic recursively entered flow history" >&2
    exit 1
fi

if ! wait_for_historical_ipv6_demo_flow; then
    echo "controller did not retain the exported IPv6 frontend-to-backend flow" >&2
    exit 1
fi
grep -q "\"source_ipv6\": \"${client_ipv6}\"" <<<"${ipv6_flow_history}"
grep -q "\"destination_ipv6\": \"${server_ipv6}\"" <<<"${ipv6_flow_history}"

policy_simulation=$("${unfctl}" \
    --controller-url "http://127.0.0.1:${controller_port}" --output json \
    policy simulate "${project_root}/deploy/examples/simulation-deny.yaml")
grep -q '"schema_version": 4' <<<"${policy_simulation}"
grep -q '"operation": "replace"' <<<"${policy_simulation}"
grep -q '"flow_source": "current-topology representative matrix"' <<<"${policy_simulation}"
grep -Eq '"would_be_denied": [1-9][0-9]*' <<<"${policy_simulation}"
grep -Eq '"decision_changes": [1-9][0-9]*' <<<"${policy_simulation}"
grep -Eq '"flow_history_revision": [1-9][0-9]*' <<<"${policy_simulation}"
grep -Eq '"evaluated_observations": [1-9][0-9]*' <<<"${policy_simulation}"
grep -Eq '"would_be_denied_observations": [1-9][0-9]*' <<<"${policy_simulation}"
grep -q '"affected_services": \[' <<<"${policy_simulation}"
grep -q '"backend/server"' <<<"${policy_simulation}"
grep -q '"reference": "frontend/client"' <<<"${policy_simulation}"
grep -q '"reference": "backend/server"' <<<"${policy_simulation}"
grep -q '"destination_port": 8080' <<<"${policy_simulation}"
grep -q '"verdict": "Allow"' <<<"${policy_simulation}"
grep -q '"verdict": "Deny"' <<<"${policy_simulation}"
grep -q "\"policy_revision\": ${initial_policy_revision}" <<<"${policy_simulation}"
grep -q "\"topology_revision\": ${restored_topology_revision}" <<<"${policy_simulation}"
jq -e '
    .historical_query.since_unix_ms == null
    and .historical_query.until_unix_ms == null
    and .historical_query.limit == 4096
    and .historical_query.returned_flows == .historical_query.matched_flows
    and (.historical_query.truncated | not)
' <<<"${policy_simulation}" >/dev/null

simulation_window_start=$(date +%s%3N)
"${kc[@]}" exec -n frontend client -- \
    wget -T 2 -t 1 -qO- http://server.backend.svc.cluster.local:8080 \
    | grep -q '^unf-demo-ok$'
for _ in {1..45}; do
    recent_flows=$("${unfctl}" \
        --controller-url "http://127.0.0.1:${controller_port}" --output json \
        flows --since-unix-ms "${simulation_window_start}" 2>/dev/null || true)
    if jq -e '
        any(.entries[];
            (.source_workloads | index("frontend/client"))
            and (.destination_workloads | index("backend/server"))
            and .key.destination_port == 8080)
    ' <<<"${recent_flows}" >/dev/null 2>&1; then
        break
    fi
    sleep 1
done
jq -e '
    any(.entries[];
        (.source_workloads | index("frontend/client"))
        and (.destination_workloads | index("backend/server"))
        and .key.destination_port == 8080)
' <<<"${recent_flows}" >/dev/null

windowed_policy_simulation=$("${unfctl}" \
    --controller-url "http://127.0.0.1:${controller_port}" --output json \
    policy simulate "${project_root}/deploy/examples/simulation-deny.yaml" \
    --since-unix-ms "${simulation_window_start}")
jq -e --argjson start "${simulation_window_start}" '
    .schema_version == 4
    and .historical_query.since_unix_ms == $start
    and .historical_query.matched_flows > 0
    and .historical_query.returned_flows > 0
    and .historical_summary.evaluated_observations > 0
    and .historical_summary.would_be_denied_observations > 0
    and any(.historical_changes[];
        .source.reference == "frontend/client"
        and .destination.reference == "backend/server"
        and .destination_port == 8080)
' <<<"${windowed_policy_simulation}" >/dev/null

bounded_policy_simulation=$("${unfctl}" \
    --controller-url "http://127.0.0.1:${controller_port}" --output json \
    policy simulate "${project_root}/deploy/examples/simulation-deny.yaml" \
    --last 10m --limit 1)
jq -e '
    .historical_query.limit == 1
    and .historical_query.returned_flows <= 1
    and (.historical_query.truncated == (.historical_query.matched_flows > 1))
' <<<"${bounded_policy_simulation}" >/dev/null

future_simulation_start=$(( $(date +%s%3N) + 60000 ))
future_policy_simulation=$("${unfctl}" \
    --controller-url "http://127.0.0.1:${controller_port}" --output json \
    policy simulate "${project_root}/deploy/examples/simulation-deny.yaml" \
    --since-unix-ms "${future_simulation_start}")
jq -e --argjson start "${future_simulation_start}" '
    .historical_query.since_unix_ms == $start
    and .historical_query.matched_flows == 0
    and .historical_query.matched_observations == 0
    and .historical_query.returned_flows == 0
    and .historical_summary.evaluated_flows == 0
    and .historical_summary.evaluated_observations == 0
    and (.historical_changes | length) == 0
    and .summary.would_be_denied > 0
' <<<"${future_policy_simulation}" >/dev/null
policy_revision_after_simulation=$("${unfctl}" \
    --controller-url "http://127.0.0.1:${controller_port}" --output json status \
    | sed -nE 's/.*"policy": ([0-9]+).*/\1/p')
if [[ ${policy_revision_after_simulation} != "${initial_policy_revision}" ]]; then
    echo "read-only policy simulation changed the live policy revision" >&2
    exit 1
fi

client_ip=$(pod_ipv4 frontend client)
if [[ ! ${client_ip} =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
    echo "frontend client does not have an IPv4 Pod address" >&2
    exit 1
fi
IFS=. read -r client_ip_a client_ip_b client_ip_c client_ip_d <<<"${client_ip}"
client_pair_cidr="${client_ip_a}.${client_ip_b}.${client_ip_c}.$((client_ip_d & 254))/31"

local_response=$("${kc[@]}" exec -n backend server -- wget -T 2 -t 1 -qO- http://127.0.0.1:9090)
if [[ ${local_response} != "unf-demo-ok" ]]; then
    echo "demo server is not listening on the deny-test port" >&2
    exit 1
fi
network_policy_local_response=$("${kc[@]}" exec -n backend np-server -- \
    wget -T 2 -t 1 -qO- http://127.0.0.1:9091)
if [[ ${network_policy_local_response} != "unf-networkpolicy-ok" ]]; then
    echo "NetworkPolicy demo server is not listening on the deny-test port" >&2
    exit 1
fi
network_policy_range_local_response=$("${kc[@]}" exec -n backend np-server -- \
    wget -T 2 -t 1 -qO- http://127.0.0.1:8084)
if [[ ${network_policy_range_local_response} != "unf-networkpolicy-ok" ]]; then
    echo "NetworkPolicy demo server is not listening outside the allowed port range" >&2
    exit 1
fi

allow_response=$("${kc[@]}" exec -n frontend client -- \
    wget -T 2 -t 1 -qO- http://server.backend.svc.cluster.local:8080)
if [[ ${allow_response} != "unf-demo-ok" ]]; then
    echo "unexpected allow response: ${allow_response}" >&2
    exit 1
fi
if "${kc[@]}" exec -n frontend client -- \
    wget -T 2 -t 1 -qO- http://server.backend.svc.cluster.local:9090 >/dev/null 2>&1; then
    echo "enforce mode did not drop the explicit deny flow" >&2
    exit 1
fi

ipv6_allow_response=$("${kc[@]}" exec -n frontend client -- \
    wget -T 2 -t 1 -qO- "http://[${server_ipv6}]:8080")
if [[ ${ipv6_allow_response} != "unf-demo-ok" ]]; then
    echo "native policy IPv6 allow flow failed" >&2
    exit 1
fi
if "${kc[@]}" exec -n frontend client -- \
    wget -T 2 -t 1 -qO- "http://[${server_ipv6}]:9090" >/dev/null 2>&1; then
    echo "native policy IPv6 explicit deny did not drop the open port" >&2
    exit 1
fi
"${kc[@]}" exec -n frontend client -- \
    unf-ipv6-extension-probe "${server_ipv6}" 8087 hop
"${kc[@]}" exec -n frontend client -- \
    unf-ipv6-extension-probe "${server_ipv6}" 8088 destination
"${kc[@]}" exec -n frontend client -- \
    unf-ipv6-extension-probe "${server_ipv6}" 8089 both
"${kc[@]}" exec -n frontend client -- \
    unf-ipv6-extension-probe "${server_ipv6}" 9097 hop
extension_probe_logs=
for _ in {1..20}; do
    extension_probe_logs=$(all_agent_logs)
    if grep -q '"destination_port":8087' <<<"${extension_probe_logs}" \
        && grep -q '"destination_port":8088' <<<"${extension_probe_logs}" \
        && grep -q '"destination_port":8089' <<<"${extension_probe_logs}" \
        && grep -q '"destination_port":9097' <<<"${extension_probe_logs}"; then
        break
    fi
    sleep 1
done
for port in 8087 8088 8089; do
    extension_allow_line=$(grep "\"destination_port\":${port}" \
        <<<"${extension_probe_logs}" | grep '"protocol":17' \
        | grep '"address_family":6' | grep '"verdict":"Allow"' \
        | grep '"reason":1' | grep "\"policy_revision\":${initial_policy_revision}" \
        | tail -n 1 || true)
    if ! grep -Eq '"source_identity":[1-9][0-9]*' <<<"${extension_allow_line}" \
        || ! grep -Eq '"destination_identity":[1-9][0-9]*' <<<"${extension_allow_line}" \
        || ! grep -Eq '"policy_id":[1-9][0-9]*' <<<"${extension_allow_line}"; then
        echo "UNF did not emit revisioned IPv6 extension-header allow provenance for UDP/${port}" >&2
        exit 1
    fi
done
extension_deny_line=$(grep '"destination_port":9097' \
    <<<"${extension_probe_logs}" | grep '"protocol":17' \
    | grep '"address_family":6' | grep '"verdict":"Deny"' \
    | grep '"reason":2' | grep "\"policy_revision\":${initial_policy_revision}" \
    | tail -n 1 || true)
if ! grep -Eq '"source_identity":[1-9][0-9]*' <<<"${extension_deny_line}" \
    || ! grep -Eq '"destination_identity":[1-9][0-9]*' <<<"${extension_deny_line}" \
    || ! grep -Eq '"policy_id":[1-9][0-9]*' <<<"${extension_deny_line}" \
    || ! grep -Eq '"rule_id":[1-9][0-9]*' <<<"${extension_deny_line}"; then
    echo "UNF did not enforce the IPv6 extension-header explicit deny" >&2
    exit 1
fi
ipv6_network_policy_allow_response=$("${kc[@]}" exec -n frontend client -- \
    wget -T 2 -t 1 -qO- "http://[${network_policy_server_ipv6}]:8081")
if [[ ${ipv6_network_policy_allow_response} != "unf-networkpolicy-ok" ]]; then
    echo "NetworkPolicy IPv6 selector allow flow failed" >&2
    exit 1
fi
if "${kc[@]}" exec -n frontend client -- \
    wget -T 2 -t 1 -qO- "http://[${network_policy_server_ipv6}]:9091" >/dev/null 2>&1; then
    echo "NetworkPolicy IPv6 default deny did not drop the open port" >&2
    exit 1
fi

"${kc[@]}" patch securitypolicy -n backend frontend-to-backend \
    --type=merge -p '{"spec":{"enforcementMode":"Shadow"}}' >/dev/null
policy_mutated=true
if ! wait_for_policy_transition "${initial_policy_revision}"; then
    echo "UNF agents did not atomically activate the shadow policy revision" >&2
    exit 1
fi
shadow_policy_revision=${transition_revision}

shadow_response=$("${kc[@]}" exec -n frontend client -- \
    wget -T 2 -t 1 -qO- http://server.backend.svc.cluster.local:9090)
if [[ ${shadow_response} != "unf-demo-ok" ]]; then
    echo "shadow mode changed forwarding behavior" >&2
    exit 1
fi

network_policy_allow_response=$("${kc[@]}" exec -n frontend client -- \
    wget -T 2 -t 1 -qO- http://np-server.backend.svc.cluster.local:8081)
if [[ ${network_policy_allow_response} != "unf-networkpolicy-ok" ]]; then
    echo "NetworkPolicy compatibility allow flow failed" >&2
    exit 1
fi
for port in 8082 8083; do
    range_response=$("${kc[@]}" exec -n frontend client -- \
        wget -T 2 -t 1 -qO- "http://np-server.backend.svc.cluster.local:${port}")
    if [[ ${range_response} != "unf-networkpolicy-ok" ]]; then
        echo "NetworkPolicy compatibility range flow ${port} failed" >&2
        exit 1
    fi
done
if "${kc[@]}" exec -n frontend client -- \
    wget -T 2 -t 1 -qO- http://np-server.backend.svc.cluster.local:8084 >/dev/null 2>&1; then
    echo "NetworkPolicy compatibility range allowed adjacent open port 8084" >&2
    exit 1
fi
if "${kc[@]}" exec -n frontend client -- \
    wget -T 2 -t 1 -qO- http://np-server.backend.svc.cluster.local:9091 >/dev/null 2>&1; then
    echo "NetworkPolicy compatibility default deny did not drop the open port" >&2
    exit 1
fi
if ! wait_for_shadow_deny_provenance "${shadow_policy_revision}"; then
    echo "UNF did not emit allow-plus-shadow-deny provenance" >&2
    exit 1
fi

shadow_history_file="${temporary_dir}/shadow-flow-history.json"
shadow_history_verified=false
for _ in {1..30}; do
    "${unfctl}" --controller-url "http://127.0.0.1:${controller_port}" \
        --output json flows --limit 4096 >"${shadow_history_file}"
    if jq -e --argjson revision "${shadow_policy_revision}" '
        .schema_version == 4
        and any(.entries[];
            .policy_revision == $revision
            and .key.direction == "Ingress"
            and .key.destination_port == 9090
            and .decision.verdict == "Allow"
            and .shadow.verdict == "Deny"
            and .observed_events > 0)
    ' "${shadow_history_file}" >/dev/null; then
        shadow_history_verified=true
        break
    fi
    "${kc[@]}" exec -n frontend client -- \
        wget -T 2 -t 1 -qO- http://server.backend.svc.cluster.local:9090 \
        >/dev/null
    sleep 1
done
if [[ ${shadow_history_verified} != true ]]; then
    echo "shadow decision was not retained for impact analysis" >&2
    exit 1
fi

shadow_live_report=$("${unfctl}" \
    --controller-url "http://127.0.0.1:${controller_port}" --output json \
    policy shadow-impact --limit 4096)
if ! jq -e --argjson revision "${shadow_policy_revision}" '
    .schema_version == 1
    and .analysis == "shadow_impact"
    and (.analysis_source | startswith("live:"))
    and .flow_history_schema_version == 4
    and .summary.shadowed_flows > 0
    and .summary.would_deny_flows > 0
    and .summary.would_deny_observations > 0
    and (.shadow_policy_ids | any(. > 0))
    and any(.changes[];
        .classification == "would_deny"
        and .flow.policy_revision == $revision
        and .flow.key.destination_port == 9090
        and .flow.decision.verdict == "Allow"
        and .flow.shadow.verdict == "Deny")
' <<<"${shadow_live_report}" >/dev/null; then
    echo "live shadow-impact analysis was incomplete" >&2
    exit 1
fi

shadow_offline_report=$("${unfctl}" --controller-url http://127.0.0.1:1 \
    --output json policy shadow-impact --flows-file "${shadow_history_file}")
if ! jq -e --argjson revision "${shadow_policy_revision}" '
    .schema_version == 1
    and (.analysis_source | startswith("offline:"))
    and .summary.would_deny_flows > 0
    and .summary.would_deny_observations > 0
    and any(.changes[];
        .classification == "would_deny"
        and .flow.policy_revision == $revision
        and .flow.key.destination_port == 9090)
' <<<"${shadow_offline_report}" >/dev/null; then
    echo "controller-independent shadow-impact analysis was incomplete" >&2
    exit 1
fi
if ! "${unfctl}" --controller-url http://127.0.0.1:1 \
    policy shadow-impact --flows-file "${shadow_history_file}" \
    | grep -q '^Shadow Impact$'; then
    echo "offline shadow-impact table rendering failed" >&2
    exit 1
fi
echo "shadow rollout impact qualification passed: retained actual/shadow provenance, observation-weighted live analysis, and controller-independent saved-snapshot JSON/table analysis"

"${kc[@]}" patch securitypolicy -n backend frontend-to-backend \
    --type=merge -p '{"spec":{"enforcementMode":"Enforce"}}' >/dev/null
if ! wait_for_policy_transition "${shadow_policy_revision}"; then
    echo "UNF agents did not atomically restore enforce mode" >&2
    exit 1
fi
enforced_policy_revision=${transition_revision}
policy_mutated=false

allow_response=$("${kc[@]}" exec -n frontend client -- \
    wget -T 2 -t 1 -qO- http://server.backend.svc.cluster.local:8080)
if [[ ${allow_response} != "unf-demo-ok" ]]; then
    echo "allow flow failed after restoring enforce mode" >&2
    exit 1
fi
if "${kc[@]}" exec -n frontend client -- \
    wget -T 2 -t 1 -qO- http://server.backend.svc.cluster.local:9090 >/dev/null 2>&1; then
    echo "restored enforce mode did not drop the explicit deny flow" >&2
    exit 1
fi
network_policy_allow_response=$("${kc[@]}" exec -n frontend client -- \
    wget -T 2 -t 1 -qO- http://np-server.backend.svc.cluster.local:8081)
if [[ ${network_policy_allow_response} != "unf-networkpolicy-ok" ]]; then
    echo "NetworkPolicy compatibility allow failed after policy reconvergence" >&2
    exit 1
fi
ipv6_allow_response=$("${kc[@]}" exec -n frontend client -- \
    wget -T 2 -t 1 -qO- "http://[${server_ipv6}]:8080")
if [[ ${ipv6_allow_response} != "unf-demo-ok" ]]; then
    echo "IPv6 allow flow failed after restoring enforce mode" >&2
    exit 1
fi
if "${kc[@]}" exec -n frontend client -- \
    wget -T 2 -t 1 -qO- "http://[${server_ipv6}]:9090" >/dev/null 2>&1; then
    echo "restored enforce mode did not drop the IPv6 explicit deny flow" >&2
    exit 1
fi
ipv6_network_policy_allow_response=$("${kc[@]}" exec -n frontend client -- \
    wget -T 2 -t 1 -qO- "http://[${network_policy_server_ipv6}]:8081")
if [[ ${ipv6_network_policy_allow_response} != "unf-networkpolicy-ok" ]]; then
    echo "NetworkPolicy IPv6 allow failed after policy reconvergence" >&2
    exit 1
fi
if "${kc[@]}" exec -n frontend client -- \
    wget -T 2 -t 1 -qO- "http://[${network_policy_server_ipv6}]:9091" >/dev/null 2>&1; then
    echo "NetworkPolicy IPv6 deny failed after policy reconvergence" >&2
    exit 1
fi
for port in 8082 8083; do
    range_response=$("${kc[@]}" exec -n frontend client -- \
        wget -T 2 -t 1 -qO- "http://np-server.backend.svc.cluster.local:${port}")
    if [[ ${range_response} != "unf-networkpolicy-ok" ]]; then
        echo "NetworkPolicy range flow ${port} failed after policy reconvergence" >&2
        exit 1
    fi
done
if "${kc[@]}" exec -n frontend client -- \
    wget -T 2 -t 1 -qO- http://np-server.backend.svc.cluster.local:8084 >/dev/null 2>&1; then
    echo "NetworkPolicy range allowed adjacent port after policy reconvergence" >&2
    exit 1
fi
if "${kc[@]}" exec -n frontend client -- \
    wget -T 2 -t 1 -qO- http://np-server.backend.svc.cluster.local:9091 >/dev/null 2>&1; then
    echo "NetworkPolicy compatibility deny failed after policy reconvergence" >&2
    exit 1
fi
wait_for_enforced_provenance "${enforced_policy_revision}" || true
if ! grep -Eq '"source_identity":[1-9][0-9]*' <<<"${allow_line}" \
    || ! grep -Eq '"destination_identity":[1-9][0-9]*' <<<"${allow_line}" \
    || ! grep -Eq '"policy_id":[1-9][0-9]*' <<<"${allow_line}"; then
    echo "UNF did not emit revisioned allow provenance" >&2
    exit 1
fi
if ! grep -Eq '"source_identity":[1-9][0-9]*' <<<"${deny_line}" \
    || ! grep -Eq '"destination_identity":[1-9][0-9]*' <<<"${deny_line}" \
    || ! grep -Eq '"policy_id":[1-9][0-9]*' <<<"${deny_line}" \
    || ! grep -Eq '"rule_id":[1-9][0-9]*' <<<"${deny_line}"; then
    echo "UNF did not emit revisioned explicit-deny provenance" >&2
    exit 1
fi
if ! grep -Eq '"source_identity":[1-9][0-9]*' <<<"${network_policy_allow_line}" \
    || ! grep -Eq '"destination_identity":[1-9][0-9]*' <<<"${network_policy_allow_line}" \
    || ! grep -Eq '"policy_id":[1-9][0-9]*' <<<"${network_policy_allow_line}"; then
    echo "UNF did not emit NetworkPolicy allow provenance" >&2
    exit 1
fi
if ! grep -Eq '"source_identity":[1-9][0-9]*' <<<"${network_policy_deny_line}" \
    || ! grep -Eq '"destination_identity":[1-9][0-9]*' <<<"${network_policy_deny_line}" \
    || ! grep -Eq '"policy_id":[1-9][0-9]*' <<<"${network_policy_deny_line}"; then
    echo "UNF did not emit NetworkPolicy default-deny provenance" >&2
    exit 1
fi
if ! grep -Eq '"source_identity":[1-9][0-9]*' <<<"${network_policy_range_line}" \
    || ! grep -Eq '"destination_identity":[1-9][0-9]*' <<<"${network_policy_range_line}" \
    || ! grep -Eq '"policy_id":[1-9][0-9]*' <<<"${network_policy_range_line}"; then
    echo "UNF did not emit NetworkPolicy port-range allow provenance" >&2
    exit 1
fi
if ! grep -Eq '"source_identity":[1-9][0-9]*' <<<"${ipv6_allow_line}" \
    || ! grep -Eq '"destination_identity":[1-9][0-9]*' <<<"${ipv6_allow_line}" \
    || ! grep -Eq '"policy_id":[1-9][0-9]*' <<<"${ipv6_allow_line}"; then
    echo "UNF did not emit revisioned IPv6 allow provenance" >&2
    exit 1
fi
if ! grep -Eq '"source_identity":[1-9][0-9]*' <<<"${ipv6_deny_line}" \
    || ! grep -Eq '"destination_identity":[1-9][0-9]*' <<<"${ipv6_deny_line}" \
    || ! grep -Eq '"policy_id":[1-9][0-9]*' <<<"${ipv6_deny_line}" \
    || ! grep -Eq '"rule_id":[1-9][0-9]*' <<<"${ipv6_deny_line}"; then
    echo "UNF did not emit revisioned IPv6 explicit-deny provenance" >&2
    exit 1
fi
if ! grep -Eq '"source_identity":[1-9][0-9]*' <<<"${ipv6_network_policy_allow_line}" \
    || ! grep -Eq '"destination_identity":[1-9][0-9]*' \
        <<<"${ipv6_network_policy_allow_line}" \
    || ! grep -Eq '"policy_id":[1-9][0-9]*' <<<"${ipv6_network_policy_allow_line}"; then
    echo "UNF did not emit NetworkPolicy IPv6 allow provenance" >&2
    exit 1
fi
if ! grep -Eq '"source_identity":[1-9][0-9]*' <<<"${ipv6_network_policy_deny_line}" \
    || ! grep -Eq '"destination_identity":[1-9][0-9]*' \
        <<<"${ipv6_network_policy_deny_line}" \
    || ! grep -Eq '"policy_id":[1-9][0-9]*' <<<"${ipv6_network_policy_deny_line}"; then
    echo "UNF did not emit NetworkPolicy IPv6 default-deny provenance" >&2
    exit 1
fi

"${kc[@]}" patch networkpolicy -n backend frontend-to-np-server --type=json \
    -p '[{"op":"add","path":"/spec/ingress/0/ports/-","value":{"protocol":"TCP"}}]' \
    >/dev/null
network_policy_protocol_mutated=true
if ! wait_for_controller_policy_counts 1 0 "${enforced_policy_revision}"; then
    echo "controller did not compile the protocol-only NetworkPolicy port" >&2
    exit 1
fi
protocol_wildcard_revision=${controller_state_revision}
if ! wait_for_policy_transition "${enforced_policy_revision}"; then
    echo "agents did not activate the protocol-only NetworkPolicy port" >&2
    exit 1
fi
protocol_wildcard_tcp_explanation=$("${unfctl}" \
    --controller-url "http://127.0.0.1:${controller_port}" --output json \
    explain --from frontend/client --to backend/np-server --protocol tcp --port 9091)
grep -q '"reason": "ExplicitRule"' <<<"${protocol_wildcard_tcp_explanation}"
grep -q '"verdict": "Allow"' <<<"${protocol_wildcard_tcp_explanation}"
protocol_wildcard_udp_explanation=$("${unfctl}" \
    --controller-url "http://127.0.0.1:${controller_port}" --output json \
    explain --from frontend/client --to backend/np-server --protocol udp --port 9091)
grep -q '"reason": "DefaultAction"' <<<"${protocol_wildcard_udp_explanation}"
grep -q '"verdict": "Deny"' <<<"${protocol_wildcard_udp_explanation}"
protocol_wildcard_response=$("${kc[@]}" exec -n frontend client -- \
    wget -T 2 -t 1 -qO- http://np-server.backend.svc.cluster.local:9091)
if [[ ${protocol_wildcard_response} != "unf-networkpolicy-ok" ]]; then
    echo "protocol-only TCP NetworkPolicy port did not allow an arbitrary TCP port" >&2
    exit 1
fi
protocol_wildcard_line=
for _ in {1..20}; do
    protocol_wildcard_line=$(all_agent_logs | grep '"destination_port":9091' \
        | grep '"verdict":"Allow"' | grep '"reason":1' \
        | grep "\"policy_revision\":${protocol_wildcard_revision}" | tail -n 1 || true)
    if [[ -n ${protocol_wildcard_line} ]]; then
        break
    fi
    sleep 1
done
if ! grep -Eq '"source_identity":[1-9][0-9]*' <<<"${protocol_wildcard_line}" \
    || ! grep -Eq '"destination_identity":[1-9][0-9]*' <<<"${protocol_wildcard_line}" \
    || ! grep -Eq '"policy_id":[1-9][0-9]*' <<<"${protocol_wildcard_line}"; then
    echo "UNF did not emit protocol-only NetworkPolicy allow provenance" >&2
    exit 1
fi

"${kc[@]}" patch networkpolicy -n backend frontend-to-np-server --type=json \
    -p '[{"op":"remove","path":"/spec/ingress/0/ports/2"}]' >/dev/null
if ! wait_for_controller_policy_counts 1 0 "${protocol_wildcard_revision}"; then
    echo "controller did not restore the exact-port NetworkPolicy" >&2
    exit 1
fi
restored_protocol_policy_revision=${controller_state_revision}
if ! wait_for_policy_transition "${protocol_wildcard_revision}"; then
    echo "agents did not remove the protocol-only NetworkPolicy wildcard" >&2
    exit 1
fi
network_policy_protocol_mutated=false
if "${kc[@]}" exec -n frontend client -- \
    wget -T 2 -t 1 -qO- http://np-server.backend.svc.cluster.local:9091 >/dev/null 2>&1; then
    echo "removing the protocol-only NetworkPolicy port did not restore default deny" >&2
    exit 1
fi

namespace_identity_revision=$("${unfctl}" \
    --controller-url "http://127.0.0.1:${controller_port}" --output json status \
    | sed -nE 's/.*"identity": ([0-9]+).*/\1/p')
"${kc[@]}" label namespace frontend environment=staging --overwrite >/dev/null
namespace_mutated=true
if ! wait_for_controller_policy_counts 1 0 "${restored_protocol_policy_revision}"; then
    echo "controller did not revise policy state after the Namespace label change" >&2
    exit 1
fi
namespace_denied_revision=${controller_state_revision}
if ! wait_for_policy_transition "${restored_protocol_policy_revision}"; then
    echo "agents did not activate the Namespace label change" >&2
    exit 1
fi
if "${kc[@]}" exec -n frontend client -- \
    wget -T 2 -t 1 -qO- http://np-server.backend.svc.cluster.local:8081 >/dev/null 2>&1; then
    echo "namespace selector continued allowing a non-matching Namespace" >&2
    exit 1
fi

"${kc[@]}" label namespace frontend environment=production --overwrite >/dev/null
if ! wait_for_controller_policy_counts 1 0 "${namespace_denied_revision}"; then
    echo "controller did not revise policy state after the Namespace label restore" >&2
    exit 1
fi
restored_namespace_policy_revision=${controller_state_revision}
if ! wait_for_policy_transition "${namespace_denied_revision}"; then
    echo "agents did not activate the restored Namespace selector match" >&2
    exit 1
fi
namespace_mutated=false
namespace_identity_after=$("${unfctl}" \
    --controller-url "http://127.0.0.1:${controller_port}" --output json status \
    | sed -nE 's/.*"identity": ([0-9]+).*/\1/p')
if [[ ${namespace_identity_after} != "${namespace_identity_revision}" ]]; then
    echo "Namespace label changes unexpectedly changed identity revision" >&2
    exit 1
fi
network_policy_allow_response=$("${kc[@]}" exec -n frontend client -- \
    wget -T 2 -t 1 -qO- http://np-server.backend.svc.cluster.local:8081)
if [[ ${network_policy_allow_response} != "unf-networkpolicy-ok" ]]; then
    echo "restored Namespace selector did not restore the allow flow" >&2
    exit 1
fi

"${kc[@]}" patch networkpolicy -n backend frontend-to-np-server --type=json \
    -p '[{"op":"replace","path":"/spec/ingress/0/ports/1/endPort","value":65535}]' \
    >/dev/null
network_policy_mutated=true
if ! wait_for_controller_policy_counts 0 1 "${restored_namespace_policy_revision}"; then
    echo "controller did not report the oversized NetworkPolicy range update" >&2
    exit 1
fi
rejected_policy_revision=${controller_state_revision}
if ! wait_for_policy_transition "${restored_namespace_policy_revision}"; then
    echo "agents did not remove the rejected NetworkPolicy revision" >&2
    exit 1
fi

"${kc[@]}" patch networkpolicy -n backend frontend-to-np-server --type=json \
    -p '[{"op":"replace","path":"/spec/ingress/0/ports/1/endPort","value":8083}]' \
    >/dev/null
if ! wait_for_controller_policy_counts 1 0 "${rejected_policy_revision}"; then
    echo "controller did not readmit the restored NetworkPolicy" >&2
    exit 1
fi
restored_policy_revision=${controller_state_revision}
if ! wait_for_policy_transition "${rejected_policy_revision}"; then
    echo "agents did not activate the restored NetworkPolicy" >&2
    exit 1
fi
network_policy_mutated=false

"${kc[@]}" patch networkpolicy -n backend frontend-to-np-server --type=json \
    -p '[{"op":"replace","path":"/spec/ingress/0/from","value":[{"ipBlock":{"cidr":"::/0"}}]}]' \
    >/dev/null
network_policy_peer_mutated=true
if ! wait_for_controller_policy_counts 1 0 "${restored_policy_revision}"; then
    echo "controller did not compile the IPv6 NetworkPolicy ipBlock" >&2
    exit 1
fi
ipv6_ipblock_allow_revision=${controller_state_revision}
if ! wait_for_policy_transition "${restored_policy_revision}"; then
    echo "agents did not atomically activate the IPv6 NetworkPolicy ipBlock" >&2
    exit 1
fi
ipv6_ipblock_allow_response=$("${kc[@]}" exec -n frontend client -- \
    wget -T 2 -t 1 -qO- "http://[${network_policy_server_ipv6}]:8081")
if [[ ${ipv6_ipblock_allow_response} != "unf-networkpolicy-ok" ]]; then
    echo "IPv6 NetworkPolicy ipBlock did not allow its exact source" >&2
    exit 1
fi

"${kc[@]}" patch networkpolicy -n backend frontend-to-np-server --type=json \
    -p "[{\"op\":\"replace\",\"path\":\"/spec/ingress/0/from/0/ipBlock\",\"value\":{\"cidr\":\"::/0\",\"except\":[\"${client_ipv6}/128\"]}}]" \
    >/dev/null
if ! wait_for_controller_policy_counts 1 0 "${ipv6_ipblock_allow_revision}"; then
    echo "controller did not compile the IPv6 NetworkPolicy ipBlock exception" >&2
    exit 1
fi
ipv6_ipblock_except_revision=${controller_state_revision}
if ! wait_for_policy_transition "${ipv6_ipblock_allow_revision}"; then
    echo "agents did not activate the IPv6 NetworkPolicy ipBlock exception" >&2
    exit 1
fi
if "${kc[@]}" exec -n frontend client -- \
    wget -T 2 -t 1 -qO- "http://[${network_policy_server_ipv6}]:8081" >/dev/null 2>&1; then
    echo "IPv6 NetworkPolicy ipBlock exception did not exclude its source" >&2
    exit 1
fi

"${kc[@]}" patch networkpolicy -n backend frontend-to-np-server --type=json \
    -p '[{"op":"replace","path":"/spec/ingress/0/from/0/ipBlock","value":{"cidr":"::/0"}}]' \
    >/dev/null
if ! wait_for_controller_policy_counts 1 0 "${ipv6_ipblock_except_revision}"; then
    echo "controller did not restore the IPv6 NetworkPolicy ipBlock" >&2
    exit 1
fi
ipv6_ipblock_restored_revision=${controller_state_revision}
if ! wait_for_policy_transition "${ipv6_ipblock_except_revision}"; then
    echo "agents did not restore the IPv6 NetworkPolicy ipBlock allow" >&2
    exit 1
fi

"${kc[@]}" patch networkpolicy -n backend frontend-to-np-server --type=json \
    -p "[{\"op\":\"replace\",\"path\":\"/spec/ingress/0/from\",\"value\":[{\"ipBlock\":{\"cidr\":\"${client_ip}/32\"}}]}]" \
    >/dev/null
network_policy_peer_mutated=true
if ! wait_for_controller_policy_counts 1 0 "${ipv6_ipblock_restored_revision}"; then
    echo "controller did not compile the bounded NetworkPolicy ipBlock" >&2
    exit 1
fi
ipblock_allow_revision=${controller_state_revision}
if ! wait_for_policy_transition "${ipv6_ipblock_restored_revision}"; then
    echo "agents did not atomically activate the bounded NetworkPolicy ipBlock" >&2
    exit 1
fi
ipblock_allow_explanation=$("${unfctl}" \
    --controller-url "http://127.0.0.1:${controller_port}" --output json \
    explain --from frontend/client --to backend/np-server --protocol tcp --port 8081)
grep -q '"reason": "ExplicitRule"' <<<"${ipblock_allow_explanation}"
grep -q '"verdict": "Allow"' <<<"${ipblock_allow_explanation}"
ipblock_allow_response=$("${kc[@]}" exec -n frontend client -- \
    wget -T 2 -t 1 -qO- http://np-server.backend.svc.cluster.local:8081)
if [[ ${ipblock_allow_response} != "unf-networkpolicy-ok" ]]; then
    echo "bounded NetworkPolicy ipBlock did not allow its exact source" >&2
    exit 1
fi
sleep 1
ipblock_allow_line=$(all_agent_logs | grep '"destination_port":8081' \
    | grep '"verdict":"Allow"' | grep '"reason":1' \
    | grep "\"policy_revision\":${ipblock_allow_revision}" | tail -n 1 || true)
if ! grep -Eq '"source_identity":[1-9][0-9]*' <<<"${ipblock_allow_line}" \
    || ! grep -Eq '"destination_identity":[1-9][0-9]*' <<<"${ipblock_allow_line}" \
    || ! grep -Eq '"policy_id":[1-9][0-9]*' <<<"${ipblock_allow_line}"; then
    echo "UNF did not emit revisioned ipBlock allow provenance" >&2
    exit 1
fi

"${kc[@]}" patch networkpolicy -n backend frontend-to-np-server --type=json \
    -p "[{\"op\":\"replace\",\"path\":\"/spec/ingress/0/from/0/ipBlock\",\"value\":{\"cidr\":\"${client_pair_cidr}\",\"except\":[\"${client_ip}/32\"]}}]" \
    >/dev/null
if ! wait_for_controller_policy_counts 1 0 "${ipblock_allow_revision}"; then
    echo "controller did not compile the NetworkPolicy ipBlock exception" >&2
    exit 1
fi
ipblock_except_revision=${controller_state_revision}
if ! wait_for_policy_transition "${ipblock_allow_revision}"; then
    echo "agents did not atomically activate the NetworkPolicy ipBlock exception" >&2
    exit 1
fi
ipblock_deny_explanation=$("${unfctl}" \
    --controller-url "http://127.0.0.1:${controller_port}" --output json \
    explain --from frontend/client --to backend/np-server --protocol tcp --port 8081)
grep -q '"reason": "DefaultAction"' <<<"${ipblock_deny_explanation}"
grep -q '"verdict": "Deny"' <<<"${ipblock_deny_explanation}"
if "${kc[@]}" exec -n frontend client -- \
    wget -T 2 -t 1 -qO- http://np-server.backend.svc.cluster.local:8081 >/dev/null 2>&1; then
    echo "NetworkPolicy ipBlock exception did not exclude its exact source" >&2
    exit 1
fi

"${kc[@]}" patch networkpolicy -n backend frontend-to-np-server --type=json \
    -p "[{\"op\":\"replace\",\"path\":\"/spec/ingress/0/from/0/ipBlock\",\"value\":{\"cidr\":\"${client_pair_cidr}\"}}]" \
    >/dev/null
if ! wait_for_controller_policy_counts 1 0 "${ipblock_except_revision}"; then
    echo "controller did not restore the bounded NetworkPolicy ipBlock" >&2
    exit 1
fi
ipblock_restored_revision=${controller_state_revision}
if ! wait_for_policy_transition "${ipblock_except_revision}"; then
    echo "agents did not restore the bounded NetworkPolicy ipBlock allow" >&2
    exit 1
fi
ipblock_restored_response=$("${kc[@]}" exec -n frontend client -- \
    wget -T 2 -t 1 -qO- http://np-server.backend.svc.cluster.local:8081)
if [[ ${ipblock_restored_response} != "unf-networkpolicy-ok" ]]; then
    echo "removing the ipBlock exception did not restore its allow" >&2
    exit 1
fi

"${kc[@]}" patch networkpolicy -n backend frontend-to-np-server --type=json \
    -p '[{"op":"replace","path":"/spec/ingress/0/from/0/ipBlock","value":{"cidr":"10.0.0.0/21"}}]' \
    >/dev/null
if ! wait_for_controller_policy_counts 0 1 "${ipblock_restored_revision}"; then
    echo "controller did not reject the oversized NetworkPolicy ipBlock" >&2
    exit 1
fi
rejected_ipblock_revision=${controller_state_revision}
if ! wait_for_policy_transition "${ipblock_restored_revision}"; then
    echo "agents did not remove the rejected NetworkPolicy ipBlock revision" >&2
    exit 1
fi

"${kc[@]}" patch networkpolicy -n backend frontend-to-np-server --type=json \
    -p "[{\"op\":\"replace\",\"path\":\"/spec/ingress/0/from\",\"value\":${network_policy_selector_peer}}]" \
    >/dev/null
if ! wait_for_controller_policy_counts 1 0 "${rejected_ipblock_revision}"; then
    echo "controller did not readmit the restored NetworkPolicy selector peer" >&2
    exit 1
fi
restored_ipblock_policy_revision=${controller_state_revision}
if ! wait_for_policy_transition "${rejected_ipblock_revision}"; then
    echo "agents did not activate the restored NetworkPolicy selector peer" >&2
    exit 1
fi
network_policy_peer_mutated=false

"${kc[@]}" delete networkpolicy -n backend frontend-to-np-server >/dev/null
network_policy_deleted=true
if ! wait_for_controller_policy_counts 0 0 "${restored_ipblock_policy_revision}"; then
    echo "controller did not remove the deleted NetworkPolicy" >&2
    exit 1
fi
deleted_policy_revision=${controller_state_revision}
if ! wait_for_policy_transition "${restored_ipblock_policy_revision}"; then
    echo "agents did not activate NetworkPolicy deletion" >&2
    exit 1
fi
deleted_response=$("${kc[@]}" exec -n frontend client -- \
    wget -T 2 -t 1 -qO- http://np-server.backend.svc.cluster.local:9091)
if [[ ${deleted_response} != "unf-networkpolicy-ok" ]]; then
    echo "NetworkPolicy deletion did not restore forwarding" >&2
    exit 1
fi

"${kc[@]}" apply -f "${project_root}/deploy/examples/demo.yaml" >/dev/null
if ! wait_for_controller_policy_counts 1 0 "${deleted_policy_revision}"; then
    echo "controller did not reconcile the recreated NetworkPolicy" >&2
    exit 1
fi
if ! wait_for_policy_transition "${deleted_policy_revision}"; then
    echo "agents did not activate the recreated NetworkPolicy" >&2
    exit 1
fi
recreated_policy_revision=${transition_revision}
network_policy_deleted=false
if "${kc[@]}" exec -n frontend client -- \
    wget -T 2 -t 1 -qO- http://np-server.backend.svc.cluster.local:9091 >/dev/null 2>&1; then
    echo "recreated NetworkPolicy did not restore default-deny enforcement" >&2
    exit 1
fi

"${kc[@]}" apply -f \
    "${project_root}/deploy/examples/networkpolicy-conformance.yaml" >/dev/null
network_policy_conformance_created=true
"${kc[@]}" wait --for=condition=Ready pod/conformance-server -n backend --timeout=120s
conformance_endpoint_observed=false
for _ in {1..30}; do
    if "${unfctl}" --controller-url "http://127.0.0.1:${controller_port}" \
        --output json explain --from frontend/client --to backend/conformance-server \
        --protocol tcp --port 8085 >/dev/null 2>&1; then
        conformance_endpoint_observed=true
        break
    fi
    sleep 1
done
if [[ ${conformance_endpoint_observed} != true ]]; then
    echo "controller did not observe the NetworkPolicy conformance endpoint" >&2
    exit 1
fi
if ! wait_for_controller_policy_counts 2 0 "${recreated_policy_revision}"; then
    echo "controller did not accept the omitted-podSelector NetworkPolicy" >&2
    exit 1
fi
if ! wait_for_policy_batch_convergence "${recreated_policy_revision}"; then
    echo "agents did not activate namespace-wide default target isolation" >&2
    exit 1
fi
conformance_policy_revision=${transition_revision}
conformance_allow=$("${unfctl}" \
    --controller-url "http://127.0.0.1:${controller_port}" --output json \
    explain --from frontend/client --to backend/conformance-server \
    --protocol tcp --port 8085)
grep -q '"reason": "ExplicitRule"' <<<"${conformance_allow}"
grep -q '"verdict": "Allow"' <<<"${conformance_allow}"
conformance_deny=$("${unfctl}" \
    --controller-url "http://127.0.0.1:${controller_port}" --output json \
    explain --from frontend/client --to backend/conformance-server \
    --protocol tcp --port 9092)
grep -q '"reason": "DefaultAction"' <<<"${conformance_deny}"
grep -q '"verdict": "Deny"' <<<"${conformance_deny}"
conformance_response=$("${kc[@]}" exec -n frontend client -- \
    wget -T 2 -t 1 -qO- http://conformance-server.backend.svc.cluster.local:8085)
if [[ ${conformance_response} != "unf-conformance-ok" ]]; then
    echo "default-TCP NetworkPolicy conformance allow failed" >&2
    exit 1
fi
if "${kc[@]}" exec -n frontend client -- \
    wget -T 2 -t 1 -qO- \
        http://conformance-server.backend.svc.cluster.local:9092 >/dev/null 2>&1; then
    echo "omitted podSelector did not isolate the conformance Pod" >&2
    exit 1
fi

"${kc[@]}" patch networkpolicy -n backend namespace-wide-default-target \
    --type=merge -p '{"spec":{"podSelector":{"matchLabels":{"app":"np-server"}}}}' \
    >/dev/null
if ! wait_for_controller_policy_counts 2 0 "${conformance_policy_revision}"; then
    echo "controller did not narrow the conformance policy target" >&2
    exit 1
fi
if ! wait_for_policy_transition "${conformance_policy_revision}"; then
    echo "agents did not activate the narrowed conformance target" >&2
    exit 1
fi
narrowed_conformance_revision=${transition_revision}
non_selected_explanation=$("${unfctl}" \
    --controller-url "http://127.0.0.1:${controller_port}" --output json \
    explain --from frontend/client --to backend/conformance-server \
    --protocol tcp --port 9092)
grep -q '"reason": "NoApplicablePolicy"' <<<"${non_selected_explanation}"
grep -q '"verdict": "Allow"' <<<"${non_selected_explanation}"
non_selected_response=$("${kc[@]}" exec -n frontend client -- \
    wget -T 2 -t 1 -qO- http://conformance-server.backend.svc.cluster.local:9092)
if [[ ${non_selected_response} != "unf-conformance-ok" ]]; then
    echo "a Pod not selected by ingress policy remained isolated" >&2
    exit 1
fi

"${kc[@]}" delete -f \
    "${project_root}/deploy/examples/networkpolicy-conformance.yaml" >/dev/null
network_policy_conformance_created=false
if ! wait_for_controller_policy_counts 1 0 "${narrowed_conformance_revision}"; then
    echo "controller did not remove the conformance NetworkPolicy" >&2
    exit 1
fi
if ! wait_for_policy_batch_convergence "${narrowed_conformance_revision}"; then
    echo "agents did not remove the conformance NetworkPolicy" >&2
    exit 1
fi
post_conformance_revision=${transition_revision}

"${kc[@]}" apply -f "${project_root}/deploy/examples/networkpolicy-sctp.yaml" >/dev/null
network_policy_sctp_created=true
"${kc[@]}" wait --for=condition=Ready pod/sctp-client -n frontend --timeout=120s
"${kc[@]}" wait --for=condition=Ready pod/sctp-server -n backend --timeout=120s
sctp_server_ip=$("${kc[@]}" get pod -n backend sctp-server \
    -o jsonpath='{.status.podIP}')
if [[ -z ${sctp_server_ip} ]]; then
    echo "SCTP conformance server has no Pod IP" >&2
    exit 1
fi
sctp_exchange() {
    local payload=$1
    local port=$2
    local timeout_seconds=${3:-3}
    local command_timeout=$((timeout_seconds + 2))
    {
        printf '%s' "${payload}"
        sleep 1
    } | "${kc[@]}" exec -i -n frontend sctp-client -- \
        timeout "${command_timeout}" socat -T "${timeout_seconds}" - \
            "SCTP:${sctp_server_ip}:${port}"
}
if ! wait_for_controller_policy_counts 2 0 "${post_conformance_revision}"; then
    echo "controller did not accept the SCTP NetworkPolicy" >&2
    exit 1
fi
if ! wait_for_policy_batch_convergence "${post_conformance_revision}"; then
    echo "agents did not activate SCTP NetworkPolicy isolation" >&2
    exit 1
fi
sctp_policy_revision=${transition_revision}
sctp_allow=$("${unfctl}" \
    --controller-url "http://127.0.0.1:${controller_port}" --output json \
    explain --from frontend/sctp-client --to backend/sctp-server \
    --protocol sctp --port 8086)
grep -q '"reason": "ExplicitRule"' <<<"${sctp_allow}"
grep -q '"verdict": "Allow"' <<<"${sctp_allow}"
sctp_deny=$("${unfctl}" \
    --controller-url "http://127.0.0.1:${controller_port}" --output json \
    explain --from frontend/sctp-client --to backend/sctp-server \
    --protocol sctp --port 9093)
grep -q '"reason": "DefaultAction"' <<<"${sctp_deny}"
grep -q '"verdict": "Deny"' <<<"${sctp_deny}"
sctp_response=$(sctp_exchange unf-sctp-ok 8086)
if [[ ${sctp_response} != "unf-sctp-ok" ]]; then
    echo "named-port SCTP NetworkPolicy allow failed" >&2
    exit 1
fi
if sctp_exchange unf-sctp-deny 9093 2 >/dev/null 2>&1; then
    echo "SCTP NetworkPolicy isolation did not drop the non-allowed port" >&2
    exit 1
fi

sctp_provenance=
sctp_history=
for _ in {1..20}; do
    sctp_provenance=$(all_agent_logs | grep '"destination_port":8086' \
        | grep '"protocol":132' | grep '"verdict":"Allow"' | grep '"reason":1' \
        | grep "\"policy_revision\":${sctp_policy_revision}" | tail -n 1 || true)
    sctp_history=$("${unfctl}" \
        --controller-url "http://127.0.0.1:${controller_port}" --output json flows)
    if grep -Eq '"source_identity":[1-9][0-9]*' <<<"${sctp_provenance}" \
        && grep -Eq '"destination_identity":[1-9][0-9]*' <<<"${sctp_provenance}" \
        && grep -Eq '"policy_id":[1-9][0-9]*' <<<"${sctp_provenance}" \
        && grep -q '"protocol": 132' <<<"${sctp_history}" \
        && grep -q '"frontend/sctp-client"' <<<"${sctp_history}" \
        && grep -q '"backend/sctp-server"' <<<"${sctp_history}"; then
        break
    fi
    sctp_exchange unf-sctp-ok 8086 >/dev/null
    sleep 1
done
if ! grep -Eq '"source_identity":[1-9][0-9]*' <<<"${sctp_provenance}" \
    || ! grep -Eq '"destination_identity":[1-9][0-9]*' <<<"${sctp_provenance}" \
    || ! grep -Eq '"policy_id":[1-9][0-9]*' <<<"${sctp_provenance}"; then
    echo "UNF did not emit revisioned SCTP allow provenance" >&2
    exit 1
fi
if ! grep -q '"protocol": 132' <<<"${sctp_history}" \
    || ! grep -q '"frontend/sctp-client"' <<<"${sctp_history}" \
    || ! grep -q '"backend/sctp-server"' <<<"${sctp_history}"; then
    echo "controller did not retain the enriched SCTP flow" >&2
    exit 1
fi

"${kc[@]}" patch networkpolicy -n backend allow-sctp-client --type=json \
    -p '[{"op":"add","path":"/spec/ingress/0/ports/-","value":{"protocol":"SCTP"}}]' \
    >/dev/null
if ! wait_for_controller_policy_counts 2 0 "${sctp_policy_revision}"; then
    echo "controller did not compile the protocol-only SCTP port" >&2
    exit 1
fi
if ! wait_for_policy_transition "${sctp_policy_revision}"; then
    echo "agents did not activate the protocol-only SCTP port" >&2
    exit 1
fi
sctp_wildcard_revision=${transition_revision}
sctp_wildcard=$("${unfctl}" \
    --controller-url "http://127.0.0.1:${controller_port}" --output json \
    explain --from frontend/sctp-client --to backend/sctp-server \
    --protocol sctp --port 9093)
grep -q '"reason": "ExplicitRule"' <<<"${sctp_wildcard}"
grep -q '"verdict": "Allow"' <<<"${sctp_wildcard}"
sctp_wildcard_response=$(sctp_exchange unf-sctp-wildcard 9093)
if [[ ${sctp_wildcard_response} != "unf-sctp-wildcard" ]]; then
    echo "protocol-only SCTP NetworkPolicy allow failed" >&2
    exit 1
fi

"${kc[@]}" patch networkpolicy -n backend allow-sctp-client --type=json \
    -p '[{"op":"remove","path":"/spec/ingress/0/ports/1"}]' >/dev/null
if ! wait_for_controller_policy_counts 2 0 "${sctp_wildcard_revision}"; then
    echo "controller did not restore the named SCTP port" >&2
    exit 1
fi
if ! wait_for_policy_transition "${sctp_wildcard_revision}"; then
    echo "agents did not remove the protocol-only SCTP port" >&2
    exit 1
fi
sctp_restored_revision=${transition_revision}
if sctp_exchange unf-sctp-deny 9093 2 >/dev/null 2>&1; then
    echo "removing the protocol-only SCTP port did not restore isolation" >&2
    exit 1
fi

"${kc[@]}" delete -f "${project_root}/deploy/examples/networkpolicy-sctp.yaml" \
    >/dev/null
network_policy_sctp_created=false
if ! wait_for_controller_policy_counts 1 0 "${sctp_restored_revision}"; then
    echo "controller did not remove the SCTP NetworkPolicy" >&2
    exit 1
fi
if ! wait_for_policy_batch_convergence "${sctp_restored_revision}"; then
    echo "agents did not remove the SCTP NetworkPolicy" >&2
    exit 1
fi

KUBECONFIG="${kubeconfig}" KUBE_CONTEXT="${context}" \
    UNF_CONTROLLER_URL="http://127.0.0.1:${controller_port}" UNFCTL="${unfctl}" \
    "${project_root}/hack/verify-networkpolicy-ingress.sh"

KUBECONFIG="${kubeconfig}" KUBE_CONTEXT="${context}" \
    UNF_CONTROLLER_URL="http://127.0.0.1:${controller_port}" UNFCTL="${unfctl}" \
    "${project_root}/hack/verify-networkpolicy-egress.sh"

if ! wait_for_aggregated_agent_convergence "${#agent_pods[@]}"; then
    echo "controller did not retain cluster-wide agent convergence after the full matrix" >&2
    exit 1
fi

server_node=$("${kc[@]}" -n backend get pod server -o jsonpath='{.spec.nodeName}')
restart_agent=$("${kc[@]}" -n unf-system get pods \
    -l app.kubernetes.io/name=unf-agent \
    -o jsonpath="{range .items[?(@.spec.nodeName=='${server_node}')]}{.metadata.name}{'\n'}{end}" \
    | head -n 1)
if [[ -z ${restart_agent} ]]; then
    echo "could not identify the agent on the demo server node" >&2
    exit 1
fi

"${kc[@]}" apply -f "${project_root}/deploy/examples/bpf-fault-helper.yaml" >/dev/null
bpf_fault_helper_created=true
"${kc[@]}" -n unf-system rollout status daemonset/unf-bpf-fault-helper --timeout=120s
fault_helper=$("${kc[@]}" -n unf-system get pods \
    -l app.kubernetes.io/name=unf-bpf-fault-helper \
    -o jsonpath="{range .items[?(@.spec.nodeName=='${server_node}')]}{.metadata.name}{'\n'}{end}" \
    | head -n 1)
if [[ -z ${fault_helper} ]]; then
    echo "could not identify the BPF fault helper on the demo server node" >&2
    exit 1
fi

fault_root=/sys/fs/bpf/unf/fault-tests-v2
partial_pin_path=${fault_root}/partial
prepare_fault_map_set "${fault_helper}" "${partial_pin_path}" POLICY_CONFIG
expect_agent_startup_rejection \
    "${restart_agent}" "${partial_pin_path}" "partial persistent BPF map set"

corrupt_config_path=${fault_root}/active-config
prepare_fault_map_set "${fault_helper}" "${corrupt_config_path}" POLICY_CONFIG
"${kc[@]}" -n unf-system exec "${fault_helper}" -- sh -eu -c '
    target=$1
    bpftool map create "${target}/POLICY_CONFIG" \
        type array key 4 value 24 entries 1 name POLICY_CONFIG
    bpftool map update pinned "${target}/POLICY_CONFIG" \
        key hex 00 00 00 00 \
        value hex \
        01 00 00 00 00 00 00 00 \
        00 00 00 00 00 00 00 00 \
        00 00 00 00 00 00 00 00
' sh "${corrupt_config_path}"
expect_agent_startup_rejection \
    "${restart_agent}" "${corrupt_config_path}" \
    "persistent policy config is invalid or incompatible"

restart_status=$(agent_status "${restart_agent}")
active_policy_bank=$(json_number active_policy_bank <<<"${restart_status}")
if [[ ${active_policy_bank} != 0 && ${active_policy_bank} != 1 ]]; then
    echo "agent did not report a valid active policy bank for fault injection" >&2
    exit 1
fi
inactive_policy_bank=$((1 - active_policy_bank))
inactive_stage_path=${fault_root}/inactive-stage
prepare_fault_map_set "${fault_helper}" "${inactive_stage_path}" POLICY_RULES
"${kc[@]}" -n unf-system exec "${fault_helper}" -- sh -eu -c '
    target=$1
    inactive_bank=$2
    bpftool map create "${target}/POLICY_RULES" \
        type hash key 12 value 32 entries 262144 name POLICY_RULES
    bpftool map update pinned "${target}/POLICY_RULES" \
        key hex \
        00 00 00 00 00 00 00 00 00 00 00 "${inactive_bank}" \
        value hex \
        00 00 00 00 00 00 00 00 \
        00 00 00 00 00 00 00 00 \
        00 00 00 00 00 00 00 00 \
        00 00 00 00 00 00 00 00
' sh "${inactive_stage_path}" "${inactive_policy_bank}"
expect_agent_startup_rejection \
    "${restart_agent}" "${inactive_stage_path}" \
    "persistent policy map contains an incompatible value"

fault_allow_response=$("${kc[@]}" exec -n frontend client -- \
    wget -T 2 -t 1 -qO- http://server.backend.svc.cluster.local:8080)
if [[ ${fault_allow_response} != "unf-demo-ok" ]]; then
    echo "isolated persistent-state fault injection disturbed the allowed flow" >&2
    exit 1
fi
if "${kc[@]}" exec -n frontend client -- \
    wget -T 2 -t 1 -qO- http://server.backend.svc.cluster.local:9090 >/dev/null 2>&1; then
    echo "isolated persistent-state fault injection disturbed deny enforcement" >&2
    exit 1
fi

pressure_status=$(agent_status "${restart_agent}")
pressure_applied_revision=$(json_number applied_policy_revision <<<"${pressure_status}")
pressure_active_bank=$(json_number active_policy_bank <<<"${pressure_status}")
pressure_errors_before=$(agent_metric \
    "${restart_agent}" unf_policy_sync_errors_total)
if [[ -z ${pressure_applied_revision} || -z ${pressure_errors_before} \
    || ( ${pressure_active_bank} != 0 && ${pressure_active_bank} != 1 ) ]]; then
    echo "agent did not expose a valid pressure-test baseline" >&2
    exit 1
fi
pressure_inactive_bank=$((1 - pressure_active_bank))
map_pressure_helper=${fault_helper}
"${kc[@]}" -n unf-system exec "${fault_helper}" -- \
    rm -f /run/unf-test/pressure-ready /run/unf-test/pressure-stop
"${kc[@]}" -n unf-system exec "${fault_helper}" -- \
    /usr/local/bin/unf-bpf-map-pressure hold \
    /sys/fs/bpf/unf/v3/POLICY_RULES "${pressure_inactive_bank}" \
    /run/unf-test/pressure-ready /run/unf-test/pressure-stop \
    >"${temporary_dir}/map-pressure.log" 2>&1 &
map_pressure_pid=$!
pressure_ready=false
for _ in {1..60}; do
    if "${kc[@]}" -n unf-system exec "${fault_helper}" -- \
        test -s /run/unf-test/pressure-ready >/dev/null 2>&1; then
        pressure_ready=true
        break
    fi
    if ! kill -0 "${map_pressure_pid}" 2>/dev/null; then
        break
    fi
    sleep 1
done
if [[ ${pressure_ready} != true ]]; then
    cat "${temporary_dir}/map-pressure.log" >&2
    echo "physical policy map pressure did not reach capacity" >&2
    exit 1
fi

"${kc[@]}" patch securitypolicy -n backend frontend-to-backend --type=merge \
    -p '{"spec":{"enforcementMode":"Shadow"}}' >/dev/null
policy_mutated=true
pressure_failure_observed=false
pressure_failed_revision=
for _ in {1..60}; do
    status=$(agent_status "${restart_agent}" || true)
    desired=$(json_number desired_policy_revision <<<"${status}")
    applied=$(json_number applied_policy_revision <<<"${status}")
    bank=$(json_number active_policy_bank <<<"${status}")
    errors=$(agent_metric "${restart_agent}" unf_policy_sync_errors_total || true)
    if [[ -n ${desired} && ${desired} -gt ${pressure_applied_revision} \
        && ${applied} == "${pressure_applied_revision}" \
        && ${bank} == "${pressure_active_bank}" \
        && -n ${errors} && ${errors} -gt ${pressure_errors_before} ]]; then
        pressure_failed_revision=${desired}
        pressure_failure_observed=true
        break
    fi
    sleep 1
done
if [[ ${pressure_failure_observed} != true ]]; then
    cat "${temporary_dir}/map-pressure.log" >&2
    echo "agent did not preserve the active revision under physical map pressure" >&2
    exit 1
fi
pressure_agent_logs=$("${kc[@]}" -n unf-system logs "${restart_agent}" --since=90s)
if ! grep -q 'policy update failed' <<<"${pressure_agent_logs}" \
    || ! grep -q 'stage identity policy map bank' <<<"${pressure_agent_logs}"; then
    echo "agent did not report the staging-map pressure failure and rollback" >&2
    exit 1
fi
pressure_allow_response=$("${kc[@]}" exec -n frontend client -- \
    wget -T 2 -t 1 -qO- http://server.backend.svc.cluster.local:8080)
if [[ ${pressure_allow_response} != "unf-demo-ok" ]]; then
    echo "map pressure disturbed the selected bank's allowed flow" >&2
    exit 1
fi
if "${kc[@]}" exec -n frontend client -- \
    wget -T 2 -t 1 -qO- http://server.backend.svc.cluster.local:9090 >/dev/null 2>&1; then
    echo "map pressure disturbed the selected bank's denied flow" >&2
    exit 1
fi

"${kc[@]}" -n unf-system exec "${fault_helper}" -- \
    touch /run/unf-test/pressure-stop >/dev/null
if ! wait "${map_pressure_pid}"; then
    cat "${temporary_dir}/map-pressure.log" >&2
    echo "physical map pressure cleanup failed" >&2
    exit 1
fi
map_pressure_pid=
if ! grep -q 'pressure map reached capacity' "${temporary_dir}/map-pressure.log"; then
    cat "${temporary_dir}/map-pressure.log" >&2
    echo "pressure helper did not confirm physical map exhaustion" >&2
    exit 1
fi
if ! wait_for_policy_batch_convergence "${pressure_applied_revision}"; then
    echo "agents did not apply the waiting policy revision after pressure cleanup" >&2
    exit 1
fi
pressure_recovered_status=$(agent_status "${restart_agent}")
pressure_recovered_revision=$(json_number applied_policy_revision \
    <<<"${pressure_recovered_status}")
pressure_recovered_bank=$(json_number active_policy_bank \
    <<<"${pressure_recovered_status}")
if [[ ${pressure_recovered_revision} != "${pressure_failed_revision}" \
    || ${pressure_recovered_bank} == "${pressure_active_bank}" ]]; then
    echo "agent did not activate the previously failed revision after pressure cleanup" >&2
    exit 1
fi
pressure_shadow_response=$("${kc[@]}" exec -n frontend client -- \
    wget -T 2 -t 1 -qO- http://server.backend.svc.cluster.local:9090)
if [[ ${pressure_shadow_response} != "unf-demo-ok" ]]; then
    echo "recovered shadow revision did not become active after pressure cleanup" >&2
    exit 1
fi

"${kc[@]}" patch securitypolicy -n backend frontend-to-backend --type=merge \
    -p '{"spec":{"enforcementMode":"Enforce"}}' >/dev/null
if ! wait_for_policy_batch_convergence "${pressure_recovered_revision}"; then
    echo "agents did not restore enforcement after the pressure test" >&2
    exit 1
fi
policy_mutated=false
if "${kc[@]}" exec -n frontend client -- \
    wget -T 2 -t 1 -qO- http://server.backend.svc.cluster.local:9090 >/dev/null 2>&1; then
    echo "restoring enforcement after map pressure did not restore the deny" >&2
    exit 1
fi
pressure_inactive_bank=
map_pressure_helper=

if current_abi_refusal=$("${kc[@]}" -n unf-system exec "${restart_agent}" -- \
    /usr/local/bin/unf-component cleanup --abi-version 3 --execute 2>&1); then
    echo "cleanup accepted current ABI removal without explicit confirmation" >&2
    exit 1
fi
if ! grep -q 'refusing to clean current ABI v3 without --allow-current-abi' \
    <<<"${current_abi_refusal}"; then
    printf '%s\n' "${current_abi_refusal}" >&2
    echo "cleanup did not report the current-ABI confirmation requirement" >&2
    exit 1
fi
if ! existing_v1_plan=$("${kc[@]}" -n unf-system exec "${restart_agent}" -- \
    /usr/local/bin/unf-component cleanup --abi-version 1 2>&1); then
    printf '%s\n' "${existing_v1_plan}" >&2
    echo "pre-existing v1 state is outside the cleanup ownership boundary" >&2
    exit 1
fi
if "${kc[@]}" -n unf-system exec "${fault_helper}" -- \
    test ! -e /sys/fs/bpf/unf/v1; then
    "${kc[@]}" -n unf-system exec "${fault_helper}" -- sh -eu -c '
        source=/sys/fs/bpf/unf/v3
        target=/sys/fs/bpf/unf/v1
        mkdir "${target}"
        for map in \
            IDENTITY_V4 IDENTITY_V6 POLICY_RULES POLICY_IPV4 POLICY_IPV6 POLICY_CONFIG
        do
            bpftool map pin pinned "${source}/${map}" "${target}/${map}"
        done
    '
    stale_abi_fixture_helper=${fault_helper}
fi
"${kc[@]}" -n unf-system exec "${fault_helper}" -- \
    mkdir /sys/fs/bpf/unf/v1/unknown-state
stale_abi_unknown_helper=${fault_helper}

if cleanup_refusal=$("${kc[@]}" -n unf-system exec "${restart_agent}" -- \
    /usr/local/bin/unf-component cleanup --abi-version 1 --execute 2>&1); then
    echo "cleanup accepted unrecognized stale ABI content" >&2
    exit 1
fi
if ! grep -q 'unrecognized ABI state; refusing cleanup' <<<"${cleanup_refusal}"; then
    printf '%s\n' "${cleanup_refusal}" >&2
    echo "cleanup did not report its unknown-content refusal" >&2
    exit 1
fi
"${kc[@]}" -n unf-system exec "${fault_helper}" -- sh -eu -c '
    target=/sys/fs/bpf/unf/v1
    test "$(find "${target}" -maxdepth 1 -type f | wc -l)" -eq 6
    test -d "${target}/unknown-state"
    rmdir "${target}/unknown-state"
'
stale_abi_unknown_helper=

cleanup_dry_run=$("${kc[@]}" -n unf-system exec "${restart_agent}" -- \
    /usr/local/bin/unf-component cleanup --abi-version 1)
if ! grep -q 'UNF cleanup plan (dry-run)' <<<"${cleanup_dry_run}" \
    || ! grep -q 'dry run only' <<<"${cleanup_dry_run}"; then
    printf '%s\n' "${cleanup_dry_run}" >&2
    echo "cleanup did not expose its dry-run contract" >&2
    exit 1
fi
"${kc[@]}" -n unf-system exec "${fault_helper}" -- sh -eu -c '
    test "$(find /sys/fs/bpf/unf/v1 -maxdepth 1 -type f | wc -l)" -eq 6
'

cleanup_execution=$("${kc[@]}" -n unf-system exec "${restart_agent}" -- \
    /usr/local/bin/unf-component cleanup --abi-version 1 --execute)
if ! grep -q 'UNF cleanup completed' <<<"${cleanup_execution}"; then
    printf '%s\n' "${cleanup_execution}" >&2
    echo "cleanup did not confirm stale ABI removal" >&2
    exit 1
fi
"${kc[@]}" -n unf-system exec "${fault_helper}" -- sh -eu -c '
    test ! -e /sys/fs/bpf/unf/v1
    test "$(find /sys/fs/bpf/unf/v3 -maxdepth 1 -type f | wc -l)" -eq 11
'
stale_abi_fixture_helper=

mapfile -t cleanup_agents < <("${kc[@]}" -n unf-system get pods \
    -l app.kubernetes.io/name=unf-agent \
    -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}')
for cleanup_agent in "${cleanup_agents[@]}"; do
    cleanup_execution=$("${kc[@]}" -n unf-system exec "${cleanup_agent}" -- \
        /usr/local/bin/unf-component cleanup --abi-version 1 --execute)
    if ! grep -q 'UNF cleanup completed' <<<"${cleanup_execution}"; then
        printf '%s\n' "${cleanup_execution}" >&2
        echo "cleanup did not complete on agent ${cleanup_agent}" >&2
        exit 1
    fi
done
while read -r cleanup_helper; do
    [[ -n ${cleanup_helper} ]] || continue
    "${kc[@]}" -n unf-system exec "${cleanup_helper}" -- sh -eu -c '
        test ! -e /sys/fs/bpf/unf/v1
        test "$(find /sys/fs/bpf/unf/v3 -maxdepth 1 -type f | wc -l)" -eq 11
    '
done < <("${kc[@]}" -n unf-system get pods \
    -l app.kubernetes.io/name=unf-bpf-fault-helper \
    -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}')

"${kc[@]}" -n unf-system exec "${fault_helper}" -- rm -rf "${fault_root}"
"${kc[@]}" delete -f "${project_root}/deploy/examples/bpf-fault-helper.yaml" >/dev/null
bpf_fault_helper_created=false

"${kc[@]}" exec -n frontend client -- sh -c '
    rm -f /tmp/unf-handoff-stop /tmp/unf-handoff-breach
    while [ ! -e /tmp/unf-handoff-stop ]; do
        attempt=0
        while [ "${attempt}" -lt 16 ]; do
            (
                if wget -T 1 -t 1 -qO- \
                    http://server.backend.svc.cluster.local:9090 >/dev/null 2>&1; then
                    echo policy-bypass >>/tmp/unf-handoff-breach
                fi
            ) &
            attempt=$((attempt + 1))
        done
        wait
    done
    test ! -s /tmp/unf-handoff-breach
' >"${temporary_dir}/handoff-probe.log" 2>&1 &
handoff_probe_pid=$!
sleep 1
if ! kill -0 "${handoff_probe_pid}" 2>/dev/null; then
    cat "${temporary_dir}/handoff-probe.log" >&2
    echo "continuous deny probe did not start before agent replacement" >&2
    exit 1
fi

"${kc[@]}" -n unf-system scale deployment/unf-controller --replicas=0 >/dev/null
controller_scaled_down=true
"${kc[@]}" -n unf-system wait --for=delete pod \
    -l app.kubernetes.io/name=unf-controller --timeout=120s
"${kc[@]}" -n unf-system delete pod "${restart_agent}" --wait=true >/dev/null

recovered_agent=
for _ in {1..60}; do
    recovered_agent=$("${kc[@]}" -n unf-system get pods \
        -l app.kubernetes.io/name=unf-agent \
        -o jsonpath="{range .items[?(@.spec.nodeName=='${server_node}')]}{.metadata.name}{'\n'}{end}" \
        | grep -v "^${restart_agent}$" | head -n 1 || true)
    if [[ -n ${recovered_agent} ]] && "${kc[@]}" -n unf-system wait \
        --for=condition=Ready "pod/${recovered_agent}" --timeout=2s >/dev/null 2>&1; then
        break
    fi
    recovered_agent=
    sleep 1
done
if [[ -z ${recovered_agent} ]]; then
    echo "replacement agent did not become Ready from pinned state with the controller offline" >&2
    exit 1
fi
"${kc[@]}" exec -n frontend client -- touch /tmp/unf-handoff-stop >/dev/null
if ! wait "${handoff_probe_pid}"; then
    cat "${temporary_dir}/handoff-probe.log" >&2
    echo "deny enforcement opened during TC attachment replacement" >&2
    exit 1
fi
handoff_probe_pid=
recovered_status=$(agent_status "${recovered_agent}")
recovered_attachment_mode=$(expected_attachment_mode "${recovered_status}")
if ! grep -q '"ready":true' <<<"${recovered_status}" \
    || ! grep -Eq '"applied_identity_epoch":[1-9][0-9]*' <<<"${recovered_status}" \
    || ! grep -Eq '"applied_identity_revision":[1-9][0-9]*' <<<"${recovered_status}" \
    || ! grep -Eq '"applied_policy_revision":[1-9][0-9]*' <<<"${recovered_status}" \
    || ! grep -q "\"tc_attachment_mode\":\"${recovered_attachment_mode}\"" \
        <<<"${recovered_status}"; then
    echo "replacement agent did not expose the validated recovered identity epoch and revisions" >&2
    exit 1
fi
recovered_agent_logs=$("${kc[@]}" -n unf-system logs "${recovered_agent}")
if ! grep -q 'validated pinned last-known-good dataplane' <<<"${recovered_agent_logs}" \
    || ! grep -Eq '"active_identity_bank":[01]' <<<"${recovered_agent_logs}" \
    || ! grep -Eq 'TCX observation program atomically replaced|persistent netlink TC observation program installed' \
        <<<"${recovered_agent_logs}"; then
    echo "replacement agent did not report pinned last-known-good validation" >&2
    exit 1
fi
recovered_allow_response=$("${kc[@]}" exec -n frontend client -- \
    wget -T 2 -t 1 -qO- http://server.backend.svc.cluster.local:8080)
if [[ ${recovered_allow_response} != "unf-demo-ok" ]]; then
    echo "pinned agent recovery lost the allowed flow while the controller was offline" >&2
    exit 1
fi
if "${kc[@]}" exec -n frontend client -- \
    wget -T 2 -t 1 -qO- http://server.backend.svc.cluster.local:9090 >/dev/null 2>&1; then
    echo "pinned agent recovery lost deny enforcement while the controller was offline" >&2
    exit 1
fi

"${kc[@]}" -n unf-system scale deployment/unf-controller --replicas=1 >/dev/null
controller_scaled_down=false
"${kc[@]}" -n unf-system rollout status deployment/unf-controller --timeout=120s
if [[ -n ${controller_forward_pid} ]]; then
    kill "${controller_forward_pid}" 2>/dev/null || true
    wait "${controller_forward_pid}" 2>/dev/null || true
    controller_forward_pid=
fi
if ! start_controller_forward; then
    echo "controller port-forward did not recover after the restart test" >&2
    exit 1
fi
mapfile -t agent_pods < <("${kc[@]}" -n unf-system get pods \
    -l app.kubernetes.io/name=unf-agent -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}')
if ! wait_for_aggregated_agent_convergence "${#agent_pods[@]}"; then
    echo "agents did not reconverge after pinned restart recovery" >&2
    exit 1
fi

egress_recovery_floor=$("${unfctl}" \
    --controller-url "http://127.0.0.1:${controller_port}" --output json status \
    | sed -nE 's/.*"policy": ([0-9]+).*/\1/p')
"${kc[@]}" apply -f - >/dev/null <<'EOF'
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: offline-egress-recovery
  namespace: frontend
spec:
  podSelector:
    matchLabels:
      app.kubernetes.io/name: client
  policyTypes:
    - Egress
  egress:
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: backend
          podSelector:
            matchLabels:
              app.kubernetes.io/name: server
      ports:
        - protocol: TCP
          port: 8080
EOF
egress_recovery_policy_created=true
if ! wait_for_policy_batch_convergence "${egress_recovery_floor}"; then
    echo "populated egress recovery policy did not converge" >&2
    exit 1
fi
egress_recovery_revision=${transition_revision}
egress_recovery_status=$("${unfctl}" \
    --controller-url "http://127.0.0.1:${controller_port}" --output json status)
if ! grep -Eq '"resolved_egress_policy_entries": [1-9][0-9]*' \
    <<<"${egress_recovery_status}"; then
    echo "controller did not expose populated egress maps before offline recovery" >&2
    exit 1
fi
for endpoint in \
    "http://${server_ipv4}:8080" \
    "http://[${server_ipv6}]:8080"; do
    if [[ $("${kc[@]}" exec -n frontend client -- \
        wget -T 2 -t 1 -qO- "${endpoint}") != unf-demo-ok ]]; then
        echo "egress recovery allow baseline failed for ${endpoint}" >&2
        exit 1
    fi
done

source_node=$("${kc[@]}" -n frontend get pod client -o jsonpath='{.spec.nodeName}')
source_agent=$("${kc[@]}" -n unf-system get pods \
    -l app.kubernetes.io/name=unf-agent \
    -o jsonpath="{range .items[?(@.spec.nodeName=='${source_node}')]}{.metadata.name}{'\n'}{end}" \
    | head -n 1)
if [[ -z ${source_agent} ]]; then
    echo "could not identify the source-node agent for egress recovery" >&2
    exit 1
fi
"${kc[@]}" -n unf-system scale deployment/unf-controller --replicas=0 >/dev/null
controller_scaled_down=true
"${kc[@]}" -n unf-system wait --for=delete pod \
    -l app.kubernetes.io/name=unf-controller --timeout=120s
"${kc[@]}" -n unf-system delete pod "${source_agent}" --wait=true >/dev/null

recovered_egress_agent=
for _ in {1..60}; do
    recovered_egress_agent=$("${kc[@]}" -n unf-system get pods \
        -l app.kubernetes.io/name=unf-agent \
        -o jsonpath="{range .items[?(@.spec.nodeName=='${source_node}')]}{.metadata.name}{'\n'}{end}" \
        | grep -v "^${source_agent}$" | head -n 1 || true)
    if [[ -n ${recovered_egress_agent} ]] && "${kc[@]}" -n unf-system wait \
        --for=condition=Ready "pod/${recovered_egress_agent}" --timeout=2s \
        >/dev/null 2>&1; then
        break
    fi
    recovered_egress_agent=
    sleep 1
done
if [[ -z ${recovered_egress_agent} ]]; then
    echo "source-node agent did not recover populated egress maps offline" >&2
    exit 1
fi
recovered_egress_status=$(agent_status "${recovered_egress_agent}")
if [[ $(json_number applied_policy_revision <<<"${recovered_egress_status}") \
        != "${egress_recovery_revision}" ]]; then
    echo "source-node agent recovered the wrong egress policy revision" >&2
    exit 1
fi
recovered_egress_logs=$("${kc[@]}" -n unf-system logs "${recovered_egress_agent}")
if ! grep -q 'validated pinned last-known-good dataplane' <<<"${recovered_egress_logs}" \
    || ! grep -Eq '"egress_ipv4_entries":[1-9][0-9]*' \
        <<<"${recovered_egress_logs}" \
    || ! grep -Eq '"egress_ipv6_entries":[1-9][0-9]*' \
        <<<"${recovered_egress_logs}"; then
    echo "source-node agent did not validate populated dual-stack egress maps" >&2
    exit 1
fi
for endpoint in \
    "http://${server_ipv4}:8080" \
    "http://[${server_ipv6}]:8080"; do
    if [[ $("${kc[@]}" exec -n frontend client -- \
        wget -T 2 -t 1 -qO- "${endpoint}") != unf-demo-ok ]]; then
        echo "offline egress recovery lost allow forwarding for ${endpoint}" >&2
        exit 1
    fi
done
if "${kc[@]}" exec -n frontend client -- \
    wget -T 2 -t 1 -qO- "http://${server_ipv4}:9090" \
    >/dev/null 2>&1; then
    echo "offline egress recovery opened a denied destination port" >&2
    exit 1
fi

"${kc[@]}" -n unf-system scale deployment/unf-controller --replicas=1 >/dev/null
controller_scaled_down=false
"${kc[@]}" -n unf-system rollout status deployment/unf-controller --timeout=120s
if [[ -n ${controller_forward_pid} ]]; then
    kill "${controller_forward_pid}" 2>/dev/null || true
    wait "${controller_forward_pid}" 2>/dev/null || true
    controller_forward_pid=
fi
if ! start_controller_forward; then
    echo "controller port-forward did not recover after egress restart test" >&2
    exit 1
fi
mapfile -t agent_pods < <("${kc[@]}" -n unf-system get pods \
    -l app.kubernetes.io/name=unf-agent -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}')
if ! wait_for_aggregated_agent_convergence "${#agent_pods[@]}"; then
    echo "agents did not reconverge after populated egress recovery" >&2
    exit 1
fi
"${kc[@]}" -n frontend delete networkpolicy offline-egress-recovery >/dev/null
egress_recovery_policy_created=false
if ! wait_for_policy_batch_convergence "${egress_recovery_revision}"; then
    echo "egress recovery policy cleanup did not converge" >&2
    exit 1
fi

"${kc[@]}" -n kube-system rollout status daemonset/kindnet --timeout=120s
if "${kc[@]}" -n kube-system get pods -l app=kindnet \
    -o jsonpath='{range .items[*]}{.status.containerStatuses[0].restartCount}{"\n"}{end}' \
    | grep -vq '^0$'; then
    echo "kindnet restarted during dual-stack verification" >&2
    exit 1
fi

echo "kind verification passed: split public/internal TLS routing with dedicated CA trust and Pod-bound TokenReview authentication, anonymous/invalid/cross-Node rejection, scoped dry-run/refusal/execution cleanup of stale v1 state with v3 preservation, isolated partial-pin/active-config/inactive-stage fault rejection, physical inactive-bank pressure rollback and retry, continuous deny enforcement across atomic TC attachment handoff, controller-aggregated two-node agent convergence, pinned last-known-good agent restart recovery with the controller offline including populated dual-stack source-selected egress maps, dual-stack upstream exact/protocol-only UDP isolation, multi-destination and nonexistent named ports, target match-label/expression lifecycle, overlapping selectors, remote target-specific exceptions, same-object update recovery, multi-value Pod/Namespace selector AND, homogeneous PodSelector peer OR, source-label lifecycle, exact-name/NotIn Namespace selection, and peer-selector-expression/multi-rule recovery, bounded IPv6 extension-header allow/deny, dual-stack identity maps, native/NetworkPolicy IPv6 enforcement and history, IPv4/IPv6 ipBlock exceptions, upstream-aligned dual-stack ingress matrix, named/protocol-only SCTP and namespace-wide/default-TCP conformance, EndpointSlice readiness, direction-aware native/NetworkPolicy what-if simulation, topology v3, authenticated direction-aware flow export v3, bounded ranges, lifecycle recovery, shadow mode, transactional activation, and provenance"
