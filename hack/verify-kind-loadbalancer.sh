#!/usr/bin/env bash
set -Eeuo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
kubeconfig=${KUBECONFIG:-"${project_root}/.tools/kind-unf-service-dev.kubeconfig"}
context=${KUBE_CONTEXT:-kind-unf-service-dev}
container_runtime=${KIND_PROVIDER:-podman}
artifact=${UNF_LOADBALANCER_KIND_EVIDENCE:-"${project_root}/.artifacts/phase6-loadbalancer-kind.json"}
skip_rollback=${UNF_LOADBALANCER_SKIP_ROLLBACK:-false}
if [[ ${skip_rollback} != true && ${skip_rollback} != false ]]; then
    echo "UNF_LOADBALANCER_SKIP_ROLLBACK must be true or false" >&2
    exit 1
fi
controller_port=${UNF_LOADBALANCER_KIND_CONTROLLER_PORT:-19967}
unfctl=${UNFCTL:-"${project_root}/target/debug/unfctl"}
namespace=unf-loadbalancer-qualification
allowed_client=unf-loadbalancer-allowed-client
denied_client=unf-loadbalancer-denied-client
map_audit_label=qualification.unf.io/loadbalancer-map-audit
kc=(kubectl --kubeconfig "${kubeconfig}" --context "${context}")
temporary_dir=$(mktemp -d)
forward_pid=
controller_scaled_down=false
qualification_stage=initialization
started_unix_seconds=$(date +%s)

report_failure() {
    local status=$?
    local line=${BASH_LINENO[0]:-unknown}
    echo "LoadBalancer Kind qualification failed during ${qualification_stage} at line ${line}: ${BASH_COMMAND}" >&2
    return "${status}"
}

remove_external_clients() {
    sudo "${container_runtime}" rm -f "${allowed_client}" "${denied_client}" >/dev/null 2>&1 || true
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
    "${kc[@]}" -n unf-system delete pod -l "${map_audit_label}=true" \
        --ignore-not-found --wait=false >/dev/null 2>&1 || true
    remove_external_clients
    rm -rf "${temporary_dir}"
}
trap report_failure ERR
trap cleanup EXIT

if [[ ${context} != kind-* ]] || [[ $("${kc[@]}" config current-context) != "${context}" ]]; then
    echo "refusing LoadBalancer qualification outside exact Kind context ${context}" >&2
    exit 1
fi

mapfile -t workers < <("${kc[@]}" get nodes -l '!node-role.kubernetes.io/control-plane' \
    -o name | sed 's|node/||' | sort)
control_plane=$("${kc[@]}" get nodes -l node-role.kubernetes.io/control-plane \
    -o jsonpath='{.items[0].metadata.name}')
if (( ${#workers[@]} != 2 )) || [[ -z ${control_plane} ]]; then
    echo "LoadBalancer qualification requires one control-plane and exactly two workers" >&2
    exit 1
fi
client_node=${workers[0]}
server_node=${workers[1]}
mapfile -t nodes < <(printf '%s\n' "${control_plane}" "${workers[@]}" | sort)

node_address() {
    local node=$1 family=$2
    if [[ ${family} == 4 ]]; then
        "${kc[@]}" get node "${node}" -o json \
            | jq -er '[.status.addresses[] | select(.type == "InternalIP") | .address | select(contains("."))][0]'
    else
        "${kc[@]}" get node "${node}" -o json \
            | jq -er '[.status.addresses[] | select(.type == "InternalIP") | .address | select(contains(":"))][0]'
    fi
}

client_node_v4=$(node_address "${client_node}" 4)
client_node_v6=$(node_address "${client_node}" 6)
server_node_v4=$(node_address "${server_node}" 4)
server_node_v6=$(node_address "${server_node}" 6)

controller_raw() {
    local path=$1 pod
    pod=$("${kc[@]}" -n unf-system get pods -l app.kubernetes.io/name=unf-controller \
        -o json | jq -r '.items[] | select(.metadata.deletionTimestamp == null and .status.phase == "Running") | .metadata.name' \
        | head -n 1)
    [[ -n ${pod} ]]
    "${kc[@]}" get --raw \
        "/api/v1/namespaces/unf-system/pods/${pod}:9962/proxy${path}"
}

agent_raw() {
    local pod=$1 path=$2
    "${kc[@]}" get --raw \
        "/api/v1/namespaces/unf-system/pods/${pod}:9963/proxy${path}"
}

wait_for_convergence() {
    local snapshot=
    for _ in $(seq 1 180); do
        snapshot=$(controller_raw /v1/state/agents 2>/dev/null || true)
        if jq -e --argjson expected "${#nodes[@]}" '
            .schema_version == 8
            and .expected_agents == $expected
            and .reporting_agents == $expected
            and .missing_agents == 0 and .stale_agents == 0
            and .converged_agents == $expected and .unexpected_agents == 0
            and .all_converged == true
            and all(.nodes[];
                .fresh and .converged and .report.ready and .report.bpf_loaded)
        ' <<<"${snapshot}" >/dev/null 2>&1; then
            printf '%s\n' "${snapshot}"
            return 0
        fi
        sleep 1
    done
    echo "LoadBalancer agents did not converge" >&2
    jq . <<<"${snapshot}" >&2 || true
    return 1
}

wait_for_load_balancer_shape() {
    local frontends=$1 cluster=$2 local_count=$3 snapshot=
    for _ in $(seq 1 180); do
        snapshot=$(controller_raw /v1/state/agents 2>/dev/null || true)
        if jq -e \
            --argjson expected "${#nodes[@]}" \
            --argjson frontends "${frontends}" \
            --argjson cluster "${cluster}" \
            --argjson local_count "${local_count}" '
            .schema_version == 8 and .expected_agents == $expected
            and .converged_agents == $expected and .all_converged == true
            and all(.nodes[];
                .fresh and .converged
                and .report.load_balancer_frontend_count == $frontends
                and .report.load_balancer_cluster_frontend_count == $cluster
                and .report.load_balancer_local_frontend_count == $local_count
                and .report.applied_load_balancer_revision == .report.desired_load_balancer_revision
                and .report.applied_load_balancer_allocation_revision == .report.desired_load_balancer_allocation_revision
                and .report.load_balancer_last_error == null)
        ' <<<"${snapshot}" >/dev/null 2>&1; then
            printf '%s\n' "${snapshot}"
            return 0
        fi
        sleep 1
    done
    echo "LoadBalancer shape did not converge to ${frontends}/${cluster}/${local_count}" >&2
    jq . <<<"${snapshot}" >&2 || true
    return 1
}

wait_for_service_shape() {
    local services=$1 frontends=$2 backends=$3 status=
    for _ in $(seq 1 180); do
        status=$(controller_raw /v1/status 2>/dev/null || true)
        if jq -e \
            --argjson services "${services}" \
            --argjson frontends "${frontends}" \
            --argjson backends "${backends}" '
            .compiled_services == $services
            and .compiled_service_frontends == $frontends
            and .compiled_service_backends == $backends
            and .service_compilation_error == null
            and .agents.all_converged == true
        ' <<<"${status}" >/dev/null 2>&1; then
            printf '%s\n' "${status}"
            return 0
        fi
        sleep 1
    done
    echo "Service shape did not converge to ${services}/${frontends}/${backends}" >&2
    jq . <<<"${status}" >&2 || true
    return 1
}

load_balancer_state() {
    "${kc[@]}" -n unf-system get configmap unf-load-balancer-control-plane -o json \
        | jq -er '.data["state.json"] | fromjson'
}

stable_allocation_projection() {
    jq -Sc '{
        pools: .allocation.pools,
        leases: [.allocation.leases[] | {
            owner, pool, poolUid, provider, families, requestedIps, addresses
        }]
    }'
}

wait_for_leases() {
    local state=
    for _ in $(seq 1 180); do
        state=$(load_balancer_state 2>/dev/null || true)
        if jq -e '
            .schemaVersion == 1
            and .allocation.schemaVersion == 2
            and (.allocation.leases | length) == 2
            and all(.allocation.leases[];
                .pool == "qualification"
                and .poolUid == "kind-loadbalancer-pool-v1"
                and .provider.name == "direct-node"
                and .provider.instance == "kind-direct-node-v1"
                and .provider.mode == "directNode"
                and (.addresses | length) == 2)
        ' <<<"${state}" >/dev/null 2>&1; then
            printf '%s\n' "${state}"
            return 0
        fi
        sleep 1
    done
    echo "durable dual-stack LoadBalancer leases did not converge" >&2
    jq . <<<"${state}" >&2 || true
    return 1
}

lease_address() {
    local state=$1 service=$2 family=$3
    if [[ ${family} == 4 ]]; then
        jq -er --arg service "${service}" '
            [.allocation.leases[] | select(.owner.name == $service) | .addresses[] | select(contains("."))][0]
        ' <<<"${state}"
    else
        jq -er --arg service "${service}" '
            [.allocation.leases[] | select(.owner.name == $service) | .addresses[] | select(contains(":"))][0]
        ' <<<"${state}"
    fi
}

lease_service_id() {
    local state=$1 service=$2
    jq -er --arg service "${service}" '
        [.allocation.leases[] | select(.owner.name == $service)][0].owner.serviceId
    ' <<<"${state}"
}

external_address() {
    local container=$1 family=$2
    if [[ ${family} == 4 ]]; then
        sudo "${container_runtime}" inspect "${container}" \
            | jq -er --arg network "${kind_network}" '.[0].NetworkSettings.Networks[$network].IPAddress'
    else
        sudo "${container_runtime}" inspect "${container}" \
            | jq -er --arg network "${kind_network}" '.[0].NetworkSettings.Networks[$network].GlobalIPv6Address'
    fi
}

route_external_client() {
    local container=$1 target_v4=$2 target_v6=$3
    sudo "${container_runtime}" exec "${container}" \
        ip -4 route replace "${cluster_v4}/32" via "${target_v4}" dev eth0
    sudo "${container_runtime}" exec "${container}" \
        ip -6 route replace "${cluster_v6}/128" via "${target_v6}" dev eth0
    sudo "${container_runtime}" exec "${container}" \
        ip -4 route replace "${local_v4}/32" via "${target_v4}" dev eth0
    sudo "${container_runtime}" exec "${container}" \
        ip -6 route replace "${local_v6}/128" via "${target_v6}" dev eth0
}

external_tcp_probe() {
    local container=$1 family=$2 address=$3 port=${4:-8080} target
    if [[ ${family} == 4 ]]; then target="http://${address}:${port}/health"; else target="http://[${address}]:${port}/health"; fi
    sudo "${container_runtime}" exec "${container}" \
        wget -T 4 -t 1 -qO- "${target}" | grep -qx ok
}

external_udp_probe() {
    local container=$1 family=$2 address=$3 port=${4:-5353} target
    if [[ ${family} == 4 ]]; then target="UDP4:${address}:${port}"; else target="UDP6:[${address}]:${port}"; fi
    sudo "${container_runtime}" exec "${container}" sh -ec \
        "printf lb-udp | socat -T 4 - '${target}'" | grep -qx lb-udp
}

external_source_probe() {
    local container=$1 family=$2 address=$3 target observed
    if [[ ${family} == 4 ]]; then target="TCP4:${address}:8081"; else target="TCP6:[${address}]:8081"; fi
    observed=$(sudo "${container_runtime}" exec "${container}" sh -ec \
        "printf probe | socat -T 4 - '${target}'" | tr -d '\r\n')
    if [[ ${family} == 6 ]]; then
        observed=${observed#\[}
        observed=${observed%\]}
        ip -6 route get "${observed}" | awk 'NR == 1 {print $1}'
    else
        printf '%s\n' "${observed}"
    fi
}

expect_external_blocked() {
    local container=$1 address_v4=$2 address_v6=$3 succeeded=false
    if external_tcp_probe "${container}" 4 "${address_v4}" >/dev/null 2>&1; then succeeded=true; fi
    if external_tcp_probe "${container}" 6 "${address_v6}" >/dev/null 2>&1; then succeeded=true; fi
    if external_udp_probe "${container}" 4 "${address_v4}" >/dev/null 2>&1; then succeeded=true; fi
    if external_udp_probe "${container}" 6 "${address_v6}" >/dev/null 2>&1; then succeeded=true; fi
    if [[ ${succeeded} == true ]]; then
        echo "blocked external LoadBalancer path unexpectedly forwarded" >&2
        return 1
    fi
}

host_tcp_probe() {
    local pod=$1 family=$2 address=$3 target
    if [[ ${family} == 4 ]]; then target="http://${address}:8080/health"; else target="http://[${address}]:8080/health"; fi
    "${kc[@]}" -n "${namespace}" exec "${pod}" -- \
        wget -T 4 -t 1 -qO- "${target}" | grep -qx ok
}

health_status() {
    local container=$1 family=$2 address=$3 target
    if [[ ${family} == 4 ]]; then target="http://${address}:32080/healthz"; else target="http://[${address}]:32080/healthz"; fi
    sudo "${container_runtime}" exec "${container}" sh -ec \
        "wget -T 4 -t 1 -S -O /dev/null '${target}' 2>&1 || true" \
        | awk '/HTTP\// && status == "" {status = $2} END {print status}'
}

apply_server() {
    "${kc[@]}" apply -f - >/dev/null <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: server
  namespace: ${namespace}
  labels:
    app: loadbalancer-server
spec:
  nodeSelector:
    kubernetes.io/hostname: ${server_node}
  terminationGracePeriodSeconds: 20
  containers:
    - name: server
      image: localhost/unf-test-tools:ipv6-ext-v1
      imagePullPolicy: Never
      command: [sh, -ec]
      args:
        - |
          /usr/local/bin/unf-udp-echo 4 5353 &
          /usr/local/bin/unf-udp-echo 6 5353 &
          socat TCP4-LISTEN:8081,reuseaddr,fork 'SYSTEM:echo \$SOCAT_PEERADDR' &
          socat TCP6-LISTEN:8081,reuseaddr,fork,ipv6-v6only=1 'SYSTEM:echo \$SOCAT_PEERADDR' &
          exec /usr/local/bin/unf-flow-receiver 8080
      readinessProbe:
        exec:
          command: [sh, -ec, "test ! -e /tmp/unready && wget -T 1 -qO- http://127.0.0.1:8080/health | grep -qx ok"]
        periodSeconds: 1
        failureThreshold: 1
EOF
}

qualification_stage=kube-proxy-free-preflight
"${kc[@]}" wait --for=condition=Ready nodes --all --timeout=180s >/dev/null
if "${kc[@]}" -n kube-system get daemonset kube-proxy >/dev/null 2>&1 \
    || "${kc[@]}" -n kube-system get pods -l k8s-app=kube-proxy -o name | grep -q .; then
    echo "dedicated LoadBalancer fixture unexpectedly contains kube-proxy" >&2
    exit 1
fi
[[ $("${kc[@]}" -n unf-system get service unf-controller -o jsonpath='{.spec.clusterIP}') == None ]]
controller_env=$("${kc[@]}" -n unf-system get deployment unf-controller -o json)
jq -e '
    [.spec.template.spec.containers[] | select(.name == "controller") | .env[]] as $env
    | any($env[]; .name == "UNF_CONTROLLER_LOAD_BALANCER_POOL_UID" and .value == "kind-loadbalancer-pool-v1")
    and any($env[]; .name == "UNF_CONTROLLER_LOAD_BALANCER_PROVIDER_INSTANCE" and .value == "kind-direct-node-v1")
' <<<"${controller_env}" >/dev/null
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
wait_for_convergence >/dev/null
"${kc[@]}" delete namespace "${namespace}" --ignore-not-found --wait=true \
    --timeout=120s >/dev/null

baseline_status=$(controller_raw /v1/status)
baseline_services=$(jq -er .compiled_services <<<"${baseline_status}")
baseline_frontends=$(jq -er .compiled_service_frontends <<<"${baseline_status}")
baseline_backends=$(jq -er .compiled_service_backends <<<"${baseline_status}")

qualification_stage=external-client-creation
kind_network=$(sudo "${container_runtime}" inspect "${client_node}" \
    | jq -er '.[0].NetworkSettings.Networks | keys[0]')
remove_external_clients
for external_client in "${allowed_client}" "${denied_client}"; do
    sudo "${container_runtime}" run -d --name "${external_client}" \
        --network "${kind_network}" --cap-add NET_ADMIN --pull never \
        --entrypoint /bin/sh localhost/unf-test-tools:ipv6-ext-v1 \
        -c 'sleep infinity' >/dev/null
done
allowed_v4=$(external_address "${allowed_client}" 4)
allowed_v6=$(external_address "${allowed_client}" 6)
denied_v4=$(external_address "${denied_client}" 4)
denied_v6=$(external_address "${denied_client}" 6)
[[ -n ${allowed_v4} && -n ${allowed_v6} && -n ${denied_v4} && -n ${denied_v6} ]]

source_ranges="    - ${allowed_v4}/32"$'\n'"    - ${allowed_v6}/128"
for node in "${nodes[@]}"; do
    source_ranges+=$'\n'"    - $(node_address "${node}" 4)/32"
    source_ranges+=$'\n'"    - $(node_address "${node}" 6)/128"
done

qualification_stage=dual-stack-loadbalancer-creation
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
  name: server-cluster
  namespace: ${namespace}
spec:
  type: LoadBalancer
  loadBalancerClass: network.unf.io/load-balancer
  allocateLoadBalancerNodePorts: false
  externalTrafficPolicy: Cluster
  ipFamilyPolicy: RequireDualStack
  ipFamilies: [IPv4, IPv6]
  selector:
    app: loadbalancer-server
  ports:
    - {name: http, protocol: TCP, port: 8080, targetPort: 8080}
    - {name: echo, protocol: UDP, port: 5353, targetPort: 5353}
    - {name: source, protocol: TCP, port: 8081, targetPort: 8081}
---
apiVersion: v1
kind: Service
metadata:
  name: server-local
  namespace: ${namespace}
spec:
  type: LoadBalancer
  loadBalancerClass: network.unf.io/load-balancer
  allocateLoadBalancerNodePorts: false
  externalTrafficPolicy: Local
  healthCheckNodePort: 32080
  ipFamilyPolicy: RequireDualStack
  ipFamilies: [IPv4, IPv6]
  loadBalancerSourceRanges:
${source_ranges}
  selector:
    app: loadbalancer-server
  ports:
    - {name: http, protocol: TCP, port: 8080, targetPort: 8080}
    - {name: echo, protocol: UDP, port: 5353, targetPort: 5353}
    - {name: source, protocol: TCP, port: 8081, targetPort: 8081}
EOF

host_clients=()
server_host_client=
host_index=0
for node in "${nodes[@]}"; do
    host_client="host-client-${host_index}"
    host_clients+=("${host_client}")
    if [[ ${node} == "${server_node}" ]]; then server_host_client=${host_client}; fi
    "${kc[@]}" apply -f - >/dev/null <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: ${host_client}
  namespace: ${namespace}
  labels:
    qualification.unf.io/role: host-client
spec:
  nodeName: ${node}
  hostNetwork: true
  dnsPolicy: ClusterFirstWithHostNet
  automountServiceAccountToken: false
  restartPolicy: Never
  tolerations:
    - operator: Exists
  containers:
    - name: client
      image: localhost/unf-test-tools:ipv6-ext-v1
      imagePullPolicy: Never
      command: [sh, -ec, "sleep infinity"]
EOF
    host_index=$((host_index + 1))
done
[[ -n ${server_host_client} ]]
"${kc[@]}" -n "${namespace}" wait --for=condition=Ready pod/client pod/server \
    --timeout=180s >/dev/null
"${kc[@]}" -n "${namespace}" wait --for=condition=Ready pod \
    -l qualification.unf.io/role=host-client --timeout=180s >/dev/null

expected_services=$((baseline_services + 2))
expected_frontends=$((baseline_frontends + 12))
expected_backends=$((baseline_backends + 12))
active_status=$(wait_for_service_shape \
    "${expected_services}" "${expected_frontends}" "${expected_backends}")
active_service_revision=$(jq -er .compiled_service_revision <<<"${active_status}")
lease_state=$(wait_for_leases)
cluster_v4=$(lease_address "${lease_state}" server-cluster 4)
cluster_v6=$(lease_address "${lease_state}" server-cluster 6)
local_v4=$(lease_address "${lease_state}" server-local 4)
local_v6=$(lease_address "${lease_state}" server-local 6)
cluster_service_id=$(lease_service_id "${lease_state}" server-cluster)
local_service_id=$(lease_service_id "${lease_state}" server-local)
active_agents=$(wait_for_load_balancer_shape 12 6 6)
jq -e --arg server "${server_node}" '
    all(.nodes[];
        .report.load_balancer_source_range_count > 0
        and .report.load_balancer_health_check_count == 1)
    and any(.nodes[]; .node_name == $server and .report.load_balancer_health_check_ready_count == 1)
    and all(.nodes[]; .node_name == $server or .report.load_balancer_health_check_ready_count == 0)
' <<<"${active_agents}" >/dev/null

for service_name in server-cluster server-local; do
    service_json=$("${kc[@]}" -n "${namespace}" get service "${service_name}" -o json)
    jq -e '
        .spec.allocateLoadBalancerNodePorts == false
        and all(.spec.ports[]; (.nodePort // 0) == 0)
        and ((.status.loadBalancer.ingress // []) | length) == 0
        and (.metadata.finalizers | index("network.unf.io/load-balancer-protection")) != null
    ' <<<"${service_json}" >/dev/null
done

qualification_stage=external-cluster-and-local-forwarding
for target in \
    "${client_node_v4} ${client_node_v6}" \
    "${server_node_v4} ${server_node_v6}"; do
    read -r target_v4 target_v6 <<<"${target}"
    route_external_client "${allowed_client}" "${target_v4}" "${target_v6}"
    external_tcp_probe "${allowed_client}" 4 "${cluster_v4}"
    external_tcp_probe "${allowed_client}" 6 "${cluster_v6}"
    external_udp_probe "${allowed_client}" 4 "${cluster_v4}"
    external_udp_probe "${allowed_client}" 6 "${cluster_v6}"
done
route_external_client "${allowed_client}" "${server_node_v4}" "${server_node_v6}"
external_tcp_probe "${allowed_client}" 4 "${local_v4}"
external_tcp_probe "${allowed_client}" 6 "${local_v6}"
external_udp_probe "${allowed_client}" 4 "${local_v4}"
external_udp_probe "${allowed_client}" 6 "${local_v6}"
[[ $(external_source_probe "${allowed_client}" 4 "${cluster_v4}") == "${server_node_v4}" ]]
[[ $(external_source_probe "${allowed_client}" 6 "${cluster_v6}") == "${server_node_v6}" ]]
[[ $(external_source_probe "${allowed_client}" 4 "${local_v4}") == "${allowed_v4}" ]]
[[ $(external_source_probe "${allowed_client}" 6 "${local_v6}") == "${allowed_v6}" ]]

qualification_stage=local-placement-and-source-range-denial
route_external_client "${allowed_client}" "${client_node_v4}" "${client_node_v6}"
expect_external_blocked "${allowed_client}" "${local_v4}" "${local_v6}"
route_external_client "${denied_client}" "${server_node_v4}" "${server_node_v6}"
expect_external_blocked "${denied_client}" "${local_v4}" "${local_v6}"
route_external_client "${allowed_client}" "${server_node_v4}" "${server_node_v6}"
[[ $(health_status "${allowed_client}" 4 "${server_node_v4}") == 200 ]]
[[ $(health_status "${allowed_client}" 6 "${server_node_v6}") == 200 ]]
[[ $(health_status "${allowed_client}" 4 "${client_node_v4}") == 503 ]]
[[ $(health_status "${allowed_client}" 6 "${client_node_v6}") == 503 ]]

qualification_stage=host-origin-forwarding
for host_client in "${host_clients[@]}"; do
    host_tcp_probe "${host_client}" 4 "${cluster_v4}"
    host_tcp_probe "${host_client}" 6 "${cluster_v6}"
done
host_tcp_probe "${server_host_client}" 4 "${local_v4}"
host_tcp_probe "${server_host_client}" 6 "${local_v6}"

qualification_stage=operations-and-simulation
history=
for _ in $(seq 1 120); do
    history=$(controller_raw /v1/flows 2>/dev/null || true)
    if jq -e \
        --arg cluster_v4 "${cluster_v4}" --arg cluster_v6 "${cluster_v6}" \
        --arg local_v4 "${local_v4}" --arg local_v6 "${local_v6}" '
        .schema_version == 7
        and any(.entries[]; .key.destination_ipv4 == $cluster_v4 and .service.frontend_kind == "load_balancer_cluster" and .service.action == 1)
        and any(.entries[]; .key.destination_ipv6 == $cluster_v6 and .service.frontend_kind == "load_balancer_cluster" and .service.action == 1)
        and any(.entries[]; .key.destination_ipv4 == $local_v4 and .service.frontend_kind == "load_balancer_local" and .service.action == 1)
        and any(.entries[]; .key.destination_ipv6 == $local_v6 and .service.frontend_kind == "load_balancer_local" and .service.action == 1)
        and any(.entries[]; .service.frontend_kind == "load_balancer_local" and .service.action == 2 and .service.reason == 12)
    ' <<<"${history}" >/dev/null 2>&1; then
        break
    fi
    sleep 1
done
jq -e '
    any(.entries[]; .service.frontend_kind == "load_balancer_cluster" and .service.action == 1)
    and any(.entries[]; .service.frontend_kind == "load_balancer_local" and .service.action == 1)
    and any(.entries[]; .service.frontend_kind == "load_balancer_local" and .service.reason == 12)
' <<<"${history}" >/dev/null

while read -r agent_pod; do
    metrics=$(agent_raw "${agent_pod}" /metrics)
    grep -Eq '^unf_loadbalancer_frontend_count 12(\.0)?$' <<<"${metrics}"
    grep -Eq '^unf_loadbalancer_cluster_frontend_count 6(\.0)?$' <<<"${metrics}"
    grep -Eq '^unf_loadbalancer_local_frontend_count 6(\.0)?$' <<<"${metrics}"
    grep -q '^unf_loadbalancer_cluster_translations_total' <<<"${metrics}"
    grep -q '^unf_loadbalancer_local_translations_total' <<<"${metrics}"
    grep -q '^unf_loadbalancer_source_range_drops_total' <<<"${metrics}"
done < <("${kc[@]}" -n unf-system get pods -l app.kubernetes.io/name=unf-agent \
    -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}')

controller_pod=$("${kc[@]}" -n unf-system get pods -l app.kubernetes.io/name=unf-controller \
    -o jsonpath='{.items[0].metadata.name}')
"${kc[@]}" -n unf-system port-forward "pod/${controller_pod}" \
    "${controller_port}:9962" >"${temporary_dir}/port-forward.log" 2>&1 &
forward_pid=$!
for _ in $(seq 1 30); do
    if "${unfctl}" --controller-url "http://127.0.0.1:${controller_port}" \
        --output json status >/dev/null 2>&1; then break; fi
    sleep 1
done
kill -0 "${forward_pid}"
cluster_explanation=$("${unfctl}" --controller-url "http://127.0.0.1:${controller_port}" \
    --output json service-explain --service-id "${cluster_service_id}" \
    --frontend-kind load-balancer-cluster --last 15m --limit 100)
local_explanation=$("${unfctl}" --controller-url "http://127.0.0.1:${controller_port}" \
    --output json service-explain --service-id "${local_service_id}" \
    --frontend-kind load-balancer-local --last 15m --limit 100)
jq -e '
    .current_service.name == "server-cluster"
    and .frontend_kind == "load_balancer_cluster"
    and .load_balancer.allocation.pool == "qualification"
    and .load_balancer.provider.instance == "kind-direct-node-v1"
    and (.load_balancer.reachable_nodes | length) == 3
    and (.load_balancer.converged_nodes | length) == 3
    and any(.outcomes[]; .service.action == 1)
' <<<"${cluster_explanation}" >/dev/null
jq -e '
    .current_service.name == "server-local"
    and .frontend_kind == "load_balancer_local"
    and .load_balancer.allocation.poolUid == "kind-loadbalancer-pool-v1"
    and any(.outcomes[]; .service.action == 1)
    and any(.outcomes[]; .service.action == 2 and .service.reason == 12)
' <<<"${local_explanation}" >/dev/null

simulation_revision_before=$(controller_raw /v1/status | jq -er .compiled_service_revision)
cluster_simulation=$("${unfctl}" --controller-url "http://127.0.0.1:${controller_port}" \
    --output json load-balancer-simulate --node "${client_node}" \
    --address "${cluster_v4}" --source-address "${allowed_v4}" --port 8080 --protocol tcp)
local_simulation=$("${unfctl}" --controller-url "http://127.0.0.1:${controller_port}" \
    --output json load-balancer-simulate --node "${server_node}" \
    --address "${local_v6}" --source-address "${allowed_v6}" --port 8080 --protocol tcp)
denied_simulation=$("${unfctl}" --controller-url "http://127.0.0.1:${controller_port}" \
    --output json load-balancer-simulate --node "${server_node}" \
    --address "${local_v4}" --source-address "${denied_v4}" --port 8080 --protocol tcp)
jq -e '.decision == "translate" and .frontend_kind == "load_balancer_cluster" and .source_preserved == false' \
    <<<"${cluster_simulation}" >/dev/null
jq -e '.decision == "translate" and .frontend_kind == "load_balancer_local" and .source_preserved == true and .source_allowed == true' \
    <<<"${local_simulation}" >/dev/null
jq -e '.decision == "drop_source_range" and .frontend_kind == "load_balancer_local" and .source_allowed == false' \
    <<<"${denied_simulation}" >/dev/null
[[ $(controller_raw /v1/status | jq -er .compiled_service_revision) == "${simulation_revision_before}" ]]

qualification_stage=readiness-health-and-no-backend
"${kc[@]}" -n "${namespace}" exec server -- touch /tmp/unready
"${kc[@]}" -n "${namespace}" wait --for=condition=Ready=false pod/server --timeout=60s >/dev/null
wait_for_convergence >/dev/null
expect_external_blocked "${allowed_client}" "${cluster_v4}" "${cluster_v6}"
expect_external_blocked "${allowed_client}" "${local_v4}" "${local_v6}"
[[ $(health_status "${allowed_client}" 4 "${server_node_v4}") == 503 ]]
no_backend_simulation=$("${unfctl}" --controller-url "http://127.0.0.1:${controller_port}" \
    --output json load-balancer-simulate --node "${server_node}" \
    --address "${local_v4}" --source-address "${allowed_v4}" --port 8080 --protocol tcp)
jq -e '.decision == "drop_no_backend" and (.eligible_backend_ids | length) == 0' \
    <<<"${no_backend_simulation}" >/dev/null
"${kc[@]}" -n "${namespace}" exec server -- rm -f /tmp/unready
"${kc[@]}" -n "${namespace}" wait --for=condition=Ready pod/server --timeout=60s >/dev/null
wait_for_convergence >/dev/null
external_tcp_probe "${allowed_client}" 4 "${cluster_v4}"
external_tcp_probe "${allowed_client}" 6 "${local_v6}"
[[ $(health_status "${allowed_client}" 4 "${server_node_v4}") == 200 ]]

qualification_stage=controller-provider-and-agent-recovery
durable_before=$(load_balancer_state)
stable_allocation_before=$(stable_allocation_projection <<<"${durable_before}")
stable_allocation_digest=$(printf '%s' "${stable_allocation_before}" | sha256sum | cut -d ' ' -f 1)
allocation_revision_before=$(jq -er .allocation.revision <<<"${durable_before}")
reachability_revision_before=$(jq -er .reachabilityRevision <<<"${durable_before}")
old_controller=${controller_pod}
"${kc[@]}" -n unf-system scale deployment/unf-controller --replicas=0 >/dev/null
controller_scaled_down=true
"${kc[@]}" -n unf-system wait --for=delete pod \
    -l app.kubernetes.io/name=unf-controller --timeout=90s >/dev/null
kill "${forward_pid}" >/dev/null 2>&1 || true
wait "${forward_pid}" >/dev/null 2>&1 || true
forward_pid=
for replacement_node in "${client_node}" "${server_node}"; do
    probe_log="${temporary_dir}/probe-${replacement_node}.log"
    (
        for _ in $(seq 1 20); do
            route_external_client "${allowed_client}" "${server_node_v4}" "${server_node_v6}"
            external_tcp_probe "${allowed_client}" 4 "${cluster_v4}"
            external_udp_probe "${allowed_client}" 6 "${local_v6}"
        done
    ) >"${probe_log}" 2>&1 &
    probe_pid=$!
    old_agent=$("${kc[@]}" -n unf-system get pod -l app.kubernetes.io/name=unf-agent \
        --field-selector spec.nodeName="${replacement_node}" -o jsonpath='{.items[0].metadata.name}')
    "${kc[@]}" -n unf-system delete pod "${old_agent}" --wait=false >/dev/null
    "${kc[@]}" -n unf-system wait --for=delete pod "${old_agent}" --timeout=180s >/dev/null
    "${kc[@]}" -n unf-system rollout status daemonset/unf-agent --timeout=180s >/dev/null
    if ! wait "${probe_pid}"; then
        echo "continuous LoadBalancer probes failed while replacing the agent on ${replacement_node}" >&2
        sed 's/^/probe: /' "${probe_log}" >&2
        exit 1
    fi
    new_agent=$("${kc[@]}" -n unf-system get pod -l app.kubernetes.io/name=unf-agent \
        --field-selector spec.nodeName="${replacement_node}" -o jsonpath='{.items[0].metadata.name}')
    [[ ${new_agent} != "${old_agent}" ]]
    recovered_agent=$(agent_raw "${new_agent}" /v1/status)
    jq -e '
        .schema_version == 8 and .ready and .bpf_loaded
        and .applied_service_revision == .desired_service_revision
        and .applied_load_balancer_revision == .desired_load_balancer_revision
        and .applied_load_balancer_allocation_revision == .desired_load_balancer_allocation_revision
        and .load_balancer_frontend_count == 12
        and .load_balancer_source_range_count > 0
        and (.load_balancer_last_error == null
            or .load_balancer_last_error == "request controller LoadBalancer reachability")
    ' <<<"${recovered_agent}" >/dev/null
    sudo "${container_runtime}" exec "${replacement_node}" sh -ec '
        state=/var/lib/unf/cni/v1/load-balancer-reachability.json
        test -f "$state" && test "$(stat -c %a "$state")" = 600
        jq -e ".schemaVersion == 1 and .applied.schemaVersion == 1 and .applied.revision > 0 and .applied.allocationRevision > 0 and (.applied.targets | length) > 0" "$state" >/dev/null
        test -e /sys/fs/bpf/unf/v11/LOAD_BALANCER_CONFIG
        test -e /sys/fs/bpf/unf/v11/LOAD_BALANCER_FRONTENDS_V4
        test -e /sys/fs/bpf/unf/v11/LOAD_BALANCER_FRONTENDS_V6
        test ! -e /sys/fs/bpf/unf/v11/LOAD_BALANCER_SOURCE_RANGES_V4
        test ! -e /sys/fs/bpf/unf/v11/LOAD_BALANCER_SOURCE_RANGES_V6
    '
done
"${kc[@]}" -n unf-system scale deployment/unf-controller --replicas=1 >/dev/null
controller_scaled_down=false
"${kc[@]}" -n unf-system rollout status deployment/unf-controller --timeout=180s >/dev/null
wait_for_convergence >/dev/null
wait_for_load_balancer_shape 12 6 6 >/dev/null
new_controller=$("${kc[@]}" -n unf-system get pods -l app.kubernetes.io/name=unf-controller \
    -o jsonpath='{.items[0].metadata.name}')
[[ ${new_controller} != "${old_controller}" ]]
durable_after=$(load_balancer_state)
durable_after_digest=$(printf '%s' "${durable_after}" | sha256sum | cut -d ' ' -f 1)
stable_allocation_after=$(stable_allocation_projection <<<"${durable_after}")
[[ ${stable_allocation_after} == "${stable_allocation_before}" ]]
allocation_revision_after=$(jq -er .allocation.revision <<<"${durable_after}")
reachability_revision_after=$(jq -er .reachabilityRevision <<<"${durable_after}")
(( allocation_revision_after >= allocation_revision_before ))
(( reachability_revision_after >= reachability_revision_before ))
[[ $(lease_address "${durable_after}" server-cluster 4) == "${cluster_v4}" ]]
[[ $(lease_address "${durable_after}" server-local 6) == "${local_v6}" ]]
external_tcp_probe "${allowed_client}" 4 "${cluster_v4}"
external_udp_probe "${allowed_client}" 6 "${local_v6}"

qualification_stage=fixture-cleanup
"${kc[@]}" delete namespace "${namespace}" --wait=true --timeout=180s >/dev/null
wait_for_service_shape "${baseline_services}" "${baseline_frontends}" "${baseline_backends}" >/dev/null
cleanup_agents=$(wait_for_load_balancer_shape 0 0 0)
jq -e 'all(.nodes[];
    .report.load_balancer_source_range_count == 0
    and .report.load_balancer_health_check_count == 0
    and .report.load_balancer_health_check_ready_count == 0)
' <<<"${cleanup_agents}" >/dev/null
for _ in $(seq 1 120); do
    cleanup_state=$(load_balancer_state 2>/dev/null || true)
    if jq -e '(.allocation.leases | length) == 0' <<<"${cleanup_state}" >/dev/null 2>&1; then break; fi
    sleep 1
done
jq -e '(.allocation.leases | length) == 0' <<<"${cleanup_state}" >/dev/null
for node in "${nodes[@]}"; do
    sudo "${container_runtime}" exec "${node}" sh -ec '
        test ! -e /sys/fs/bpf/unf/v11/LOAD_BALANCER_SOURCE_RANGES_V4
        test ! -e /sys/fs/bpf/unf/v11/LOAD_BALANCER_SOURCE_RANGES_V6
        state=/var/lib/unf/cni/v1/load-balancer-reachability.json
        test -f "$state" && jq -e ".schemaVersion == 1 and .applied.schemaVersion == 1 and (.applied.targets | length) == 0" "$state" >/dev/null
    '
    audit_pod="loadbalancer-map-audit-${node##*-}"
    "${kc[@]}" -n unf-system apply -f - >/dev/null <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: ${audit_pod}
  labels:
    ${map_audit_label}: "true"
spec:
  nodeName: ${node}
  hostNetwork: true
  restartPolicy: Never
  automountServiceAccountToken: false
  tolerations:
    - operator: Exists
  containers:
    - name: audit
      image: localhost/unf-test-tools:ipv6-ext-v1
      imagePullPolicy: Never
      command: [sh, -ec]
      args:
        - |
          for map in LOAD_BALANCER_FRONTENDS_V4 LOAD_BALANCER_FRONTENDS_V6; do
            test "\$(bpftool -j map dump pinned /sys/fs/bpf/unf/v11/\$map | jq length)" -eq 0
          done
          echo loadbalancer-maps-empty
      securityContext:
        privileged: true
      volumeMounts:
        - name: bpffs
          mountPath: /sys/fs/bpf
          readOnly: true
  volumes:
    - name: bpffs
      hostPath:
        path: /sys/fs/bpf
        type: Directory
EOF
    "${kc[@]}" -n unf-system wait --for=jsonpath='{.status.phase}'=Succeeded \
        "pod/${audit_pod}" --timeout=90s >/dev/null
    grep -qx loadbalancer-maps-empty < <("${kc[@]}" -n unf-system logs "${audit_pod}")
done
"${kc[@]}" -n unf-system delete pod -l "${map_audit_label}=true" \
    --wait=true --timeout=90s >/dev/null
remove_external_clients
for external_client in "${allowed_client}" "${denied_client}"; do
    ! sudo "${container_runtime}" container exists "${external_client}"
done

qualification_stage=evidence
release_revision=$(controller_raw /v1/version | jq -er '
    select(.schema_version == 2 and .component == "unf-controller") | .build_revision
')
[[ ${release_revision} =~ ^[0-9a-f]{40}$ ]]
git -C "${project_root}" merge-base --is-ancestor "${release_revision}" HEAD
qualification_revision=$(git -C "${project_root}" rev-parse HEAD)
[[ ${qualification_revision} =~ ^[0-9a-f]{40}$ ]]
node_evidence=$("${kc[@]}" get nodes -o json | jq '
    [.items[] | {name:.metadata.name,podCIDRs:.spec.podCIDRs,
    internalIPs:[.status.addresses[] | select(.type=="InternalIP") | .address],
    kernelVersion:.status.nodeInfo.kernelVersion,
    containerRuntimeVersion:.status.nodeInfo.containerRuntimeVersion,
    osImage:.status.nodeInfo.osImage}]')
image_evidence=$("${kc[@]}" -n unf-system get pods \
    -l 'app.kubernetes.io/name in (unf-controller,unf-agent)' -o json | jq '
    [.items[] | {pod:.metadata.name,node:.spec.nodeName,
    containers:[.status.containerStatuses[] | {name,image,imageID}]}]')
final_agents=$(controller_raw /v1/state/agents)
mkdir -p "$(dirname "${artifact}")"
jq -n \
    --arg generatedAt "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --arg revision "${release_revision}" \
    --arg qualificationRevision "${qualification_revision}" \
    --arg context "${context}" \
    --arg kubernetesVersion "$("${kc[@]}" version -o json | jq -r .serverVersion.gitVersion)" \
    --argjson durationSeconds "$(( $(date +%s) - started_unix_seconds ))" \
    --arg clusterIPv4 "${cluster_v4}" --arg clusterIPv6 "${cluster_v6}" \
    --arg localIPv4 "${local_v4}" --arg localIPv6 "${local_v6}" \
    --arg allowedIPv4 "${allowed_v4}" --arg allowedIPv6 "${allowed_v6}" \
    --arg deniedIPv4 "${denied_v4}" --arg deniedIPv6 "${denied_v6}" \
    --argjson clusterServiceId "${cluster_service_id}" \
    --argjson localServiceId "${local_service_id}" \
    --argjson activeServiceRevision "${active_service_revision}" \
    --arg durableDigest "${durable_after_digest}" \
    --arg stableAllocationDigest "${stable_allocation_digest}" \
    --argjson allocationRevisionBefore "${allocation_revision_before}" \
    --argjson allocationRevisionAfter "${allocation_revision_after}" \
    --argjson reachabilityRevisionBefore "${reachability_revision_before}" \
    --argjson reachabilityRevisionAfter "${reachability_revision_after}" \
    --argjson nodes "${node_evidence}" --argjson images "${image_evidence}" \
    --argjson agents "${final_agents}" '
    {
      schemaVersion:1,phase:"6.8",generatedAt:$generatedAt,
      revision:$revision,qualificationRevision:$qualificationRevision,
      context:$context,kubernetesVersion:$kubernetesVersion,
      durationSeconds:$durationSeconds,kubeProxyPresent:false,
      provider:{name:"direct-node",instance:"kind-direct-node-v1",pool:"qualification",poolUid:"kind-loadbalancer-pool-v1"},
      loadBalancers:{
        cluster:{serviceId:$clusterServiceId,ipv4:$clusterIPv4,ipv6:$clusterIPv6},
        local:{serviceId:$localServiceId,ipv4:$localIPv4,ipv6:$localIPv6,healthCheckNodePort:32080}
      },
      externalClients:{allowed:{ipv4:$allowedIPv4,ipv6:$allowedIPv6},denied:{ipv4:$deniedIPv4,ipv6:$deniedIPv6}},
      activeServiceRevision:$activeServiceRevision,durableStateSha256:$durableDigest,
      recovery:{stableAllocationSha256:$stableAllocationDigest,
        allocationRevisionBefore:$allocationRevisionBefore,
        allocationRevisionAfter:$allocationRevisionAfter,
        reachabilityRevisionBefore:$reachabilityRevisionBefore,
        reachabilityRevisionAfter:$reachabilityRevisionAfter},
      nodes:$nodes,images:$images,agents:$agents,
      verified:[
        "exclusive UNF primary CNI and kube-proxy absence",
        "explicit network.unf.io/load-balancer ownership",
        "durable conflict-safe dual-stack allocation and direct-node provenance",
        "external-container IPv4 and IPv6 TCP/UDP Cluster traffic through both workers",
        "external-container IPv4 and IPv6 TCP/UDP Local traffic through the backend worker",
        "Cluster VIP source translation and Local external source preservation",
        "Local non-backend Node fail-closed behavior",
        "dual-stack loadBalancerSourceRanges allow and deny",
        "all-Node host-origin Cluster and backend-Node host-origin Local traffic",
        "dual-stack healthCheckNodePort 200/503 placement and readiness lifecycle",
        "readiness withdrawal, no-backend behavior, and recovery",
        "fixed-cardinality metrics, validated status, durable history, explanation, and read-only simulation",
        "controller/direct-node provider restart with stable allocation identity and monotonic intent fencing",
        "controller-offline source and destination agent replacement from last-known-good state",
        "zero traffic NodePorts and intentionally withheld Kubernetes ingress status",
        "exact lease, frontend map, runtime source-range trie, health listener, external client, and fixture cleanup"
      ],
      excluded:[
        "OpenShift","production BGP, EVPN, ECMP, and BFD","cloud-provider adapters",
        "classless LoadBalancer ownership","session affinity","internalTrafficPolicy",
        "topology-aware hints","Maglev","DSR","SCTP Service forwarding",
        "fragments","generic NAT RELATED tracking","production availability and scale"
      ]
    }' >"${artifact}"

qualification_stage=exact-platform-rollback
if [[ ${skip_rollback} == false ]]; then
    KUBECONFIG="${kubeconfig}" KUBE_CONTEXT="${context}" KIND_PROVIDER="${container_runtime}" \
        "${project_root}/hack/rollback-kind-primary-cni.sh"
    jq '.verified += [
        "scoped ABI-v11 LoadBalancer and shared BPF cleanup",
        "exact remote-route deletion",
        "fingerprinted CNI artifact removal",
        "CoreDNS bootstrap restoration",
        "no-CNI baseline restoration"
    ]' "${artifact}" >"${artifact}.tmp"
    mv -f "${artifact}.tmp" "${artifact}"
else
    jq '.handoff = {
        primaryCniActive:true,
        reason:"Phase 7 qualification requested an explicit live-cluster handoff"
    }' "${artifact}" >"${artifact}.tmp"
    mv -f "${artifact}.tmp" "${artifact}"
fi

trap - ERR EXIT
echo "kube-proxy-free dual-stack LoadBalancer qualification passed; evidence: ${artifact}"
