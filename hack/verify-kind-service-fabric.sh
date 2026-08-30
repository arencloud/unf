#!/usr/bin/env bash
set -Eeuo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
kubeconfig=${KUBECONFIG:-"${project_root}/.tools/kind-unf-service-dev.kubeconfig"}
context=${KUBE_CONTEXT:-kind-unf-service-dev}
container_runtime=${KIND_PROVIDER:-podman}
artifact=${UNF_SERVICE_KIND_EVIDENCE:-"${project_root}/.artifacts/phase4-service-kind.json"}
controller_port=${UNF_SERVICE_KIND_CONTROLLER_PORT:-19966}
unfctl=${UNFCTL:-"${project_root}/target/debug/unfctl"}
namespace=unf-service-qualification
kc=(kubectl --kubeconfig "${kubeconfig}" --context "${context}")
temporary_dir=$(mktemp -d)
forward_pid=
controller_scaled_down=false
qualification_stage=initialization

report_failure() {
    local status=$?
    local line=${BASH_LINENO[0]:-unknown}
    echo "service-fabric Kind qualification failed during ${qualification_stage} at line ${line}: ${BASH_COMMAND}" >&2
    return "${status}"
}

cleanup() {
    if [[ -n ${forward_pid} ]]; then
        kill "${forward_pid}" >/dev/null 2>&1 || true
        wait "${forward_pid}" >/dev/null 2>&1 || true
    fi
    if [[ ${controller_scaled_down} == true ]]; then
        "${kc[@]}" -n unf-system scale deployment/unf-controller --replicas=1 \
            >/dev/null 2>&1 || true
    fi
    rm -rf "${temporary_dir}"
}
trap report_failure ERR
trap cleanup EXIT

if [[ ${context} != kind-* ]] || [[ $("${kc[@]}" config current-context) != "${context}" ]]; then
    echo "refusing service qualification outside exact Kind context ${context}" >&2
    exit 1
fi

mapfile -t workers < <("${kc[@]}" get nodes -l '!node-role.kubernetes.io/control-plane' \
    -o name | sed 's|node/||' | sort)
control_plane=$("${kc[@]}" get nodes -l node-role.kubernetes.io/control-plane \
    -o jsonpath='{.items[0].metadata.name}')
if (( ${#workers[@]} != 2 )) || [[ -z ${control_plane} ]]; then
    echo "service qualification requires one control-plane and exactly two workers" >&2
    exit 1
fi
client_node=${workers[0]}
server_node=${workers[1]}
mapfile -t nodes < <(printf '%s\n' "${control_plane}" "${workers[@]}" | sort)

controller_raw() {
    local path=$1
    local pod
    pod=$("${kc[@]}" -n unf-system get pods -l app.kubernetes.io/name=unf-controller \
        -o json | jq -r '.items[] | select(.metadata.deletionTimestamp == null and .status.phase == "Running") | .metadata.name' \
        | head -n 1)
    [[ -n ${pod} ]]
    "${kc[@]}" get --raw \
        "/api/v1/namespaces/unf-system/pods/${pod}:9962/proxy${path}"
}

agent_raw() {
    local pod=$1
    local path=$2
    "${kc[@]}" get --raw \
        "/api/v1/namespaces/unf-system/pods/${pod}:9963/proxy${path}"
}

wait_for_convergence() {
    local snapshot=
    for _ in $(seq 1 180); do
        snapshot=$(controller_raw /v1/state/agents 2>/dev/null || true)
        if jq -e --argjson expected "${#nodes[@]}" '
            .schema_version == 4
            and .expected_agents == $expected
            and .reporting_agents == $expected
            and .missing_agents == 0
            and .stale_agents == 0
            and .converged_agents == $expected
            and .unexpected_agents == 0
            and .all_converged == true
            and all(.nodes[];
                .fresh and .converged and .report.ready and .report.bpf_loaded
                and .report.desired_service_revision > 0
                and .report.applied_service_revision == .report.desired_service_revision)
        ' <<<"${snapshot}" >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    echo "service-fabric agents did not converge" >&2
    jq . <<<"${snapshot}" >&2 || true
    return 1
}

wait_for_service_shape() {
    local expected_services=$1
    local expected_frontends=$2
    local expected_backends=$3
    local status=
    for _ in $(seq 1 120); do
        status=$(controller_raw /v1/status 2>/dev/null || true)
        if jq -e \
            --argjson services "${expected_services}" \
            --argjson frontends "${expected_frontends}" \
            --argjson backends "${expected_backends}" '
                .compiled_services == $services
                and .compiled_service_frontends == $frontends
                and .compiled_service_backends == $backends
                and .service_compilation_error == null
                and .agents.all_converged == true
                and all(.agents.nodes[];
                    .report.service_count == $services
                    and .report.service_frontend_count == $frontends
                    and .report.service_backend_count == $backends)
            ' <<<"${status}" >/dev/null 2>&1; then
            printf '%s\n' "${status}"
            return 0
        fi
        sleep 1
    done
    echo "service shape did not converge to ${expected_services}/${expected_frontends}/${expected_backends}" >&2
    jq . <<<"${status}" >&2 || true
    return 1
}

attachment_count() {
    local node=$1
    sudo "${container_runtime}" exec "${node}" sh -ec '
        path=/var/lib/unf/cni/v1/attachments.json
        if [ -f "$path" ]; then jq ".attachments | length" "$path"; else echo 0; fi
    '
}

attachment_names() {
    local node=$1
    sudo "${container_runtime}" exec "${node}" sh -ec '
        path=/var/lib/unf/cni/v1/attachments.json
        if [ -f "$path" ]; then jq -r ".attachments[].hostInterface" "$path" | sort; fi
    '
}

tcp_probe() {
    local address=$1
    "${kc[@]}" -n "${namespace}" exec client -- \
        wget -T 4 -t 1 -qO- "http://${address}:8080/health" | grep -qx ok
}

udp_probe() {
    local family=$1
    local address=$2
    local target
    if [[ ${family} == 4 ]]; then
        target="UDP4:${address}:5353"
    else
        target="UDP6:[${address}]:5353"
    fi
    "${kc[@]}" -n "${namespace}" exec client -- sh -ec \
        "printf udp-ok | socat -T 4 - '${target}'" | grep -qx udp-ok
}

service_probe_matrix() {
    tcp_probe "${service_v4}"
    tcp_probe "[${service_v6}]"
    udp_probe 4 "${service_v4}"
    udp_probe 6 "${service_v6}"
}

expect_service_matrix_blocked() {
    local succeeded=false
    if tcp_probe "${service_v4}" >/dev/null 2>&1; then succeeded=true; fi
    if tcp_probe "[${service_v6}]" >/dev/null 2>&1; then succeeded=true; fi
    if udp_probe 4 "${service_v4}" >/dev/null 2>&1; then succeeded=true; fi
    if udp_probe 6 "${service_v6}" >/dev/null 2>&1; then succeeded=true; fi
    if [[ ${succeeded} == true ]]; then
        echo "backendless Service unexpectedly forwarded traffic" >&2
        return 1
    fi
}

apply_server() {
    "${kc[@]}" apply -f - >/dev/null <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: server
  namespace: ${namespace}
  labels:
    app: service-server
spec:
  nodeSelector:
    kubernetes.io/hostname: ${server_node}
  terminationGracePeriodSeconds: 30
  containers:
    - name: server
      image: localhost/unf-test-tools:ipv6-ext-v1
      imagePullPolicy: Never
      command: [sh, -ec]
      args:
        - |
          socat UDP4-RECVFROM:5353,reuseaddr,fork EXEC:/bin/cat &
          socat UDP6-RECVFROM:5353,reuseaddr,fork,ipv6-v6only=1 EXEC:/bin/cat &
          exec /usr/local/bin/unf-flow-receiver 8080
      readinessProbe:
        exec:
          command: [sh, -ec, "test ! -e /tmp/unready && wget -T 1 -qO- http://127.0.0.1:8080/health | grep -qx ok"]
        periodSeconds: 1
        failureThreshold: 1
      livenessProbe:
        httpGet:
          path: /health
          port: 8080
        periodSeconds: 2
        failureThreshold: 3
      lifecycle:
        preStop:
          exec:
            command: [sh, -ec, "sleep 20"]
EOF
}

qualification_stage=kube-proxy-free-preflight
"${kc[@]}" wait --for=condition=Ready nodes --all --timeout=180s >/dev/null
if "${kc[@]}" -n kube-system get daemonset kube-proxy >/dev/null 2>&1 \
    || "${kc[@]}" -n kube-system get pods -l k8s-app=kube-proxy -o name | grep -q .; then
    echo "dedicated Service fixture unexpectedly contains kube-proxy" >&2
    exit 1
fi
[[ $("${kc[@]}" -n unf-system get service unf-controller -o jsonpath='{.spec.clusterIP}') == None ]]
for node in "${nodes[@]}"; do
    sudo "${container_runtime}" exec "${node}" sh -ec '
        ! iptables-save 2>/dev/null | grep -q "^-A KUBE-SVC"
        if command -v ip6tables-save >/dev/null 2>&1; then
            ! ip6tables-save 2>/dev/null | grep -q "^-A KUBE-SVC"
        fi
        test "$(find /etc/cni/net.d -mindepth 1 -maxdepth 1 -type f | wc -l)" -eq 1
        test -f /etc/cni/net.d/10-unf.conflist
        test -S /run/unf/cni.sock
    '
done
wait_for_convergence

"${kc[@]}" delete namespace "${namespace}" --ignore-not-found --wait=true \
    --timeout=120s >/dev/null
wait_for_convergence

baseline_status=$(controller_raw /v1/status)
baseline_services=$(jq -r .compiled_services <<<"${baseline_status}")
baseline_frontends=$(jq -r .compiled_service_frontends <<<"${baseline_status}")
baseline_backends=$(jq -r .compiled_service_backends <<<"${baseline_status}")
client_attachment_baseline=$(attachment_count "${client_node}")
server_attachment_baseline=$(attachment_count "${server_node}")
client_names_before=$(attachment_names "${client_node}")
server_names_before=$(attachment_names "${server_node}")

qualification_stage=dual-stack-service-creation
"${kc[@]}" create namespace "${namespace}" >/dev/null
apply_server
"${kc[@]}" apply -f - >/dev/null <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: client
  namespace: ${namespace}
spec:
  nodeSelector:
    kubernetes.io/hostname: ${client_node}
  containers:
    - name: client
      image: localhost/unf-test-tools:ipv6-ext-v1
      imagePullPolicy: Never
      command: [sh, -ec, "sleep infinity"]
---
apiVersion: v1
kind: Service
metadata:
  name: server
  namespace: ${namespace}
spec:
  ipFamilyPolicy: RequireDualStack
  ipFamilies: [IPv4, IPv6]
  selector:
    app: service-server
  ports:
    - name: http
      protocol: TCP
      port: 8080
      targetPort: 8080
    - name: echo
      protocol: UDP
      port: 5353
      targetPort: 5353
EOF
"${kc[@]}" -n "${namespace}" wait --for=condition=Ready pod/client pod/server \
    --timeout=180s >/dev/null
wait_for_convergence

server_json=$("${kc[@]}" -n "${namespace}" get pod server -o json)
server_v4=$(jq -r '.status.podIPs[].ip | select(contains("."))' <<<"${server_json}")
server_v6=$(jq -r '.status.podIPs[].ip | select(contains(":"))' <<<"${server_json}")
mapfile -t service_ips < <("${kc[@]}" -n "${namespace}" get service server \
    -o json | jq -r '.spec.clusterIPs[]')
service_v4=${service_ips[0]}
service_v6=${service_ips[1]}

client_names_after=$(attachment_names "${client_node}")
server_names_after=$(attachment_names "${server_node}")
client_link=$(comm -13 <(printf '%s\n' "${client_names_before}") \
    <(printf '%s\n' "${client_names_after}"))
server_link=$(comm -13 <(printf '%s\n' "${server_names_before}") \
    <(printf '%s\n' "${server_names_after}"))
[[ -n ${client_link} && ${client_link} != *$'\n'* ]]
[[ -n ${server_link} && ${server_link} != *$'\n'* ]]

expected_services=$((baseline_services + 1))
expected_frontends=$((baseline_frontends + 4))
expected_backends=$((baseline_backends + 4))
active_status=$(wait_for_service_shape \
    "${expected_services}" "${expected_frontends}" "${expected_backends}")
active_revision=$(jq -r .compiled_service_revision <<<"${active_status}")

qualification_stage=direct-and-clusterip-forwarding
tcp_probe "${server_v4}"
tcp_probe "[${server_v6}]"
udp_probe 4 "${server_v4}"
udp_probe 6 "${server_v6}"
for _ in $(seq 1 8); do
    service_probe_matrix
done

qualification_stage=dns-continuity
service_resolution=$("${kc[@]}" -n "${namespace}" exec client -- getent ahosts server)
grep -q "${service_v4}" <<<"${service_resolution}"
grep -q "${service_v6}" <<<"${service_resolution}"
dns_service_ip=$("${kc[@]}" -n kube-system get service kube-dns -o jsonpath='{.spec.clusterIP}')
[[ -n ${dns_service_ip} && ${dns_service_ip} != None ]]

qualification_stage=service-observability
history=
for _ in $(seq 1 90); do
    history=$(controller_raw /v1/flows 2>/dev/null || true)
    if jq -e --arg v4 "${service_v4}" --arg v6 "${service_v6}" '
        .schema_version == 5
        and any(.entries[]; .key.destination_ipv4 == $v4 and .key.protocol == 6 and .service.action == 1)
        and any(.entries[]; .key.destination_ipv4 == $v4 and .key.protocol == 17 and .service.action == 1)
        and any(.entries[]; .key.destination_ipv6 == $v6 and .key.protocol == 6 and .service.action == 1)
        and any(.entries[]; .key.destination_ipv6 == $v6 and .key.protocol == 17 and .service.action == 1)
    ' <<<"${history}" >/dev/null 2>&1; then
        break
    fi
    sleep 1
done
jq -e --arg v4 "${service_v4}" --arg v6 "${service_v6}" '
    any(.entries[]; .key.destination_ipv4 == $v4 and .service.action == 1)
    and any(.entries[]; .key.destination_ipv6 == $v6 and .service.action == 1)
' <<<"${history}" >/dev/null
service_id=$(jq -r --arg v4 "${service_v4}" \
    '[.entries[] | select(.key.destination_ipv4 == $v4 and .service.action == 1)][0].service.service_id' \
    <<<"${history}")
[[ ${service_id} =~ ^[1-9][0-9]*$ ]]
agent_snapshot=$(controller_raw /v1/state/agents)
jq -e --arg client_node "${client_node}" '
    all(.nodes[]; .report.invalid_service_events == 0)
    and any(.nodes[];
        .node_name == $client_node
        and .report.service_dataplane_events > 0
        and .report.service_translations > 0)
' <<<"${agent_snapshot}" >/dev/null

controller_pod=$("${kc[@]}" -n unf-system get pods -l app.kubernetes.io/name=unf-controller \
    -o jsonpath='{.items[0].metadata.name}')
"${kc[@]}" -n unf-system port-forward "pod/${controller_pod}" \
    "${controller_port}:9962" >"${temporary_dir}/port-forward.log" 2>&1 &
forward_pid=$!
for _ in $(seq 1 30); do
    if "${unfctl}" --controller-url "http://127.0.0.1:${controller_port}" \
        --output json status >/dev/null 2>&1; then
        break
    fi
    sleep 1
done
kill -0 "${forward_pid}"
explanation=$("${unfctl}" --controller-url "http://127.0.0.1:${controller_port}" \
    --output json service-explain --service-id "${service_id}" --last 15m --limit 100)
jq -e --argjson service_id "${service_id}" '
    .schema_version == 1
    and .service_id == $service_id
    and .current_service.namespace == "unf-service-qualification"
    and .current_service.name == "server"
    and .matched_outcomes >= 4
    and .matched_observations >= 4
    and any(.outcomes[]; .service.action == 1 and .service.backend_id > 0)
' <<<"${explanation}" >/dev/null

qualification_stage=readiness-withdrawal
"${kc[@]}" -n "${namespace}" exec server -- touch /tmp/unready
"${kc[@]}" -n "${namespace}" wait --for=condition=Ready=false pod/server --timeout=60s >/dev/null
for _ in $(seq 1 90); do
    if "${kc[@]}" -n "${namespace}" get endpointslice \
        -l kubernetes.io/service-name=server -o json \
        | jq -e 'all(.items[] | (.endpoints // [])[]; .conditions.ready == false)' >/dev/null; then
        break
    fi
    sleep 1
done
wait_for_convergence
expect_service_matrix_blocked
for _ in $(seq 1 90); do
    history=$(controller_raw /v1/flows 2>/dev/null || true)
    if jq -e --argjson service_id "${service_id}" '
        any(.entries[];
            .service.service_id == $service_id
            and .service.action == 2
            and .service.reason == 3
            and .service.backend_id == null)
    ' <<<"${history}" >/dev/null 2>&1; then
        break
    fi
    sleep 1
done
jq -e --argjson service_id "${service_id}" '
    any(.entries[]; .service.service_id == $service_id and .service.action == 2 and .service.reason == 3)
' <<<"${history}" >/dev/null
"${kc[@]}" -n "${namespace}" exec server -- rm -f /tmp/unready
"${kc[@]}" -n "${namespace}" wait --for=condition=Ready pod/server --timeout=60s >/dev/null
wait_for_convergence
service_probe_matrix

qualification_stage=termination-and-deletion
"${kc[@]}" -n "${namespace}" delete pod server --wait=false >/dev/null
for _ in $(seq 1 60); do
    if "${kc[@]}" -n "${namespace}" get endpointslice \
        -l kubernetes.io/service-name=server -o json \
        | jq -e 'any(.items[] | (.endpoints // [])[]; .conditions.terminating == true)' >/dev/null; then
        break
    fi
    sleep 1
done
"${kc[@]}" -n "${namespace}" get endpointslice \
    -l kubernetes.io/service-name=server -o json \
    | jq -e 'any(.items[] | (.endpoints // [])[]; .conditions.terminating == true)' >/dev/null
wait_for_convergence
expect_service_matrix_blocked
"${kc[@]}" -n "${namespace}" wait --for=delete pod/server --timeout=90s >/dev/null
for _ in $(seq 1 90); do
    endpoint_count=$("${kc[@]}" -n "${namespace}" get endpointslice \
        -l kubernetes.io/service-name=server -o json \
        | jq '[.items[] | (.endpoints // [])[]] | length')
    [[ ${endpoint_count} -eq 0 ]] && break
    sleep 1
done
[[ ${endpoint_count} -eq 0 ]]
wait_for_convergence
expect_service_matrix_blocked

qualification_stage=backend-recovery
apply_server
"${kc[@]}" -n "${namespace}" wait --for=condition=Ready pod/server --timeout=180s >/dev/null
recovered_status=$(wait_for_service_shape \
    "${expected_services}" "${expected_frontends}" "${expected_backends}")
recovered_revision=$(jq -r .compiled_service_revision <<<"${recovered_status}")
(( recovered_revision > active_revision ))
service_probe_matrix

qualification_stage=controller-outage-agent-recovery
"${kc[@]}" -n unf-system scale deployment/unf-controller --replicas=0 >/dev/null
controller_scaled_down=true
"${kc[@]}" -n unf-system wait --for=delete pod \
    -l app.kubernetes.io/name=unf-controller --timeout=90s >/dev/null
for replacement_node in "${client_node}" "${server_node}"; do
    probe_log="${temporary_dir}/probe-${replacement_node}.log"
    (
        for _ in $(seq 1 30); do
            service_probe_matrix
        done
    ) >"${probe_log}" 2>&1 &
    probe_pid=$!
    old_agent=$("${kc[@]}" -n unf-system get pod -l app.kubernetes.io/name=unf-agent \
        --field-selector spec.nodeName="${replacement_node}" -o jsonpath='{.items[0].metadata.name}')
    "${kc[@]}" -n unf-system delete pod "${old_agent}" --wait=false >/dev/null
    "${kc[@]}" -n unf-system rollout status daemonset/unf-agent --timeout=180s >/dev/null
    wait "${probe_pid}"
    new_agent=$("${kc[@]}" -n unf-system get pod -l app.kubernetes.io/name=unf-agent \
        --field-selector spec.nodeName="${replacement_node}" -o jsonpath='{.items[0].metadata.name}')
    [[ ${new_agent} != "${old_agent}" ]]
    recovered_agent_status=$(agent_raw "${new_agent}" /v1/status)
    jq -e '
        .schema_version == 4
        and .ready and .bpf_loaded
        and .desired_service_revision > 0
        and .applied_service_revision == .desired_service_revision
        and .applied_service_epoch == .desired_service_epoch
        and .service_count > 0
        and .service_frontend_count > 0
        and .service_backend_count > 0
        and has("service_last_error")
        and (.service_last_error == null
            or .service_last_error == "request controller service snapshot")
    ' <<<"${recovered_agent_status}" >/dev/null
    sudo "${container_runtime}" exec "${replacement_node}" sh -ec '
        snapshot=/var/lib/unf/cni/v1/service-snapshot.json
        test -f "$snapshot"
        test "$(stat -c %a "$snapshot")" = 600
        jq -e ".schemaVersion == 1 and .revision > 0 and (.services | length) > 0" "$snapshot" >/dev/null
        test -e /sys/fs/bpf/unf/v5/SERVICE_CONFIG
        test -e /sys/fs/bpf/unf/v5/SERVICE_FRONTENDS_V4
        test -e /sys/fs/bpf/unf/v5/SERVICE_FRONTENDS_V6
        test -e /sys/fs/bpf/unf/v5/SERVICE_BACKENDS_V4
        test -e /sys/fs/bpf/unf/v5/SERVICE_BACKENDS_V6
        test -e /sys/fs/bpf/unf/v5/NODE_PORT_CONFIG
        test -e /sys/fs/bpf/unf/v5/NODE_PORT_FRONTENDS_V4
        test -e /sys/fs/bpf/unf/v5/NODE_PORT_FRONTENDS_V6
    '
done
"${kc[@]}" -n unf-system scale deployment/unf-controller --replicas=1 >/dev/null
controller_scaled_down=false
"${kc[@]}" -n unf-system rollout status deployment/unf-controller --timeout=180s >/dev/null
wait_for_convergence
service_probe_matrix

qualification_stage=fixture-cleanup
"${kc[@]}" delete namespace "${namespace}" --wait=true --timeout=180s >/dev/null
for _ in $(seq 1 120); do
    client_count=$(attachment_count "${client_node}")
    server_count=$(attachment_count "${server_node}")
    if [[ ${client_count} -eq ${client_attachment_baseline} \
        && ${server_count} -eq ${server_attachment_baseline} ]]; then
        break
    fi
    sleep 1
done
[[ ${client_count} -eq ${client_attachment_baseline} ]]
[[ ${server_count} -eq ${server_attachment_baseline} ]]
sudo "${container_runtime}" exec "${client_node}" sh -ec \
    "! ip link show '${client_link}' >/dev/null 2>&1"
sudo "${container_runtime}" exec "${server_node}" sh -ec \
    "! ip link show '${server_link}' >/dev/null 2>&1"
wait_for_service_shape "${baseline_services}" "${baseline_frontends}" "${baseline_backends}" \
    >/dev/null

qualification_stage=evidence
mkdir -p "$(dirname "${artifact}")"
release_revision=$(controller_raw /v1/version | jq -er '
    select(.schema_version == 2 and .component == "unf-controller") | .build_revision
')
[[ ${release_revision} =~ ^[0-9a-f]{40}$ ]]
git -C "${project_root}" merge-base --is-ancestor "${release_revision}" HEAD
while read -r agent_pod; do
    agent_revision=$(agent_raw "${agent_pod}" /v1/version | jq -er '
        select(.schema_version == 2 and .component == "unf-agent") | .build_revision
    ')
    [[ ${agent_revision} == "${release_revision}" ]]
done < <("${kc[@]}" -n unf-system get pods -l app.kubernetes.io/name=unf-agent \
    -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}')
node_evidence=$("${kc[@]}" get nodes -o json | jq \
    '[.items[] | {name:.metadata.name,podCIDRs:.spec.podCIDRs,internalIPs:[.status.addresses[] | select(.type=="InternalIP") | .address]}]')
final_agents=$(controller_raw /v1/state/agents)
jq -n \
    --arg generatedAt "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --arg revision "${release_revision}" \
    --arg context "${context}" \
    --arg kubernetesVersion "$("${kc[@]}" version -o json | jq -r .serverVersion.gitVersion)" \
    --arg serviceIPv4 "${service_v4}" \
    --arg serviceIPv6 "${service_v6}" \
    --argjson serviceId "${service_id}" \
    --argjson activeRevision "${active_revision}" \
    --argjson recoveredRevision "${recovered_revision}" \
    --argjson nodes "${node_evidence}" \
    --argjson agents "${final_agents}" \
    '{schemaVersion:1,generatedAt:$generatedAt,revision:$revision,context:$context,kubernetesVersion:$kubernetesVersion,kubeProxyPresent:false,service:{id:$serviceId,ipv4:$serviceIPv4,ipv6:$serviceIPv6,activeRevision:$activeRevision,recoveredRevision:$recoveredRevision},nodes:$nodes,agents:$agents,verified:["exclusive UNF primary CNI","kube-proxy absent","headless controller bootstrap","direct dual-stack Pod forwarding","IPv4 and IPv6 TCP ClusterIP","IPv4 and IPv6 UDP ClusterIP","DNS continuity through UNF Service translation","stable repeated connection translation","readiness withdrawal","terminating endpoint exclusion","backend deletion and recovery","no-backend drop provenance","metrics and agent status","durable flow history","unfctl service explanation","controller-outage source and destination agent replacement","last-known-good service recovery","desired service-map cleanup","CNI attachment and veth cleanup"]}' \
    >"${artifact}"

qualification_stage=exact-platform-rollback
KUBECONFIG="${kubeconfig}" KUBE_CONTEXT="${context}" KIND_PROVIDER="${container_runtime}" \
    "${project_root}/hack/rollback-kind-primary-cni.sh"
jq '.verified += ["scoped ABI-v4 BPF cleanup","exact remote-route deletion","fingerprinted CNI artifact removal","CoreDNS bootstrap restoration","no-CNI baseline restoration"]' \
    "${artifact}" >"${artifact}.tmp"
mv -f "${artifact}.tmp" "${artifact}"

trap - ERR EXIT
echo "kube-proxy-free dual-stack service-fabric qualification passed; evidence: ${artifact}"
