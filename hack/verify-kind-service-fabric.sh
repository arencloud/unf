#!/usr/bin/env bash
set -Eeuo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
kubeconfig=${KUBECONFIG:-"${project_root}/.tools/kind-unf-service-dev.kubeconfig"}
context=${KUBE_CONTEXT:-kind-unf-service-dev}
container_runtime=${KIND_PROVIDER:-podman}
node_port_mode=${UNF_NODEPORT_KIND:-false}
if [[ ${node_port_mode} != true && ${node_port_mode} != false ]]; then
    echo "UNF_NODEPORT_KIND must be true or false" >&2
    exit 1
fi
if [[ ${node_port_mode} == true ]]; then
    default_artifact="${project_root}/.artifacts/phase5-nodeport-kind.json"
else
    default_artifact="${project_root}/.artifacts/phase4-service-kind.json"
fi
artifact=${UNF_SERVICE_KIND_EVIDENCE:-"${default_artifact}"}
controller_port=${UNF_SERVICE_KIND_CONTROLLER_PORT:-19966}
unfctl=${UNFCTL:-"${project_root}/target/debug/unfctl"}
namespace=unf-service-qualification
kc=(kubectl --kubeconfig "${kubeconfig}" --context "${context}")
temporary_dir=$(mktemp -d)
forward_pid=
controller_scaled_down=false
qualification_stage=initialization
started_unix_seconds=$(date +%s)

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
client_node_json=$("${kc[@]}" get node "${client_node}" -o json)
server_node_json=$("${kc[@]}" get node "${server_node}" -o json)
client_node_v4=$(jq -er '[.status.addresses[] | select(.type == "InternalIP") | .address | select(contains("."))][0]' <<<"${client_node_json}")
client_node_v6=$(jq -er '[.status.addresses[] | select(.type == "InternalIP") | .address | select(contains(":"))][0]' <<<"${client_node_json}")
server_node_v4=$(jq -er '[.status.addresses[] | select(.type == "InternalIP") | .address | select(contains("."))][0]' <<<"${server_node_json}")
server_node_v6=$(jq -er '[.status.addresses[] | select(.type == "InternalIP") | .address | select(contains(":"))][0]' <<<"${server_node_json}")

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
            .schema_version == 5
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
    local expected_node_ports=${4:--1}
    local status=
    for _ in $(seq 1 120); do
        status=$(controller_raw /v1/status 2>/dev/null || true)
        if jq -e \
            --argjson services "${expected_services}" \
            --argjson frontends "${expected_frontends}" \
            --argjson backends "${expected_backends}" \
            --argjson node_ports "${expected_node_ports}" '
                .compiled_services == $services
                and .compiled_service_frontends == $frontends
                and .compiled_service_backends == $backends
                and .service_compilation_error == null
                and .agents.all_converged == true
                and all(.agents.nodes[];
                    .report.service_count == $services
                    and .report.service_frontend_count == $frontends
                    and .report.service_backend_count == $backends
                    and ($node_ports < 0 or (
                        .report.desired_node_port_frontend_count == $node_ports
                        and .report.applied_node_port_frontend_count == $node_ports
                        and .report.node_port_cluster_frontend_count == ($node_ports / 2)
                        and .report.node_port_local_frontend_count == ($node_ports / 2))))
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
    local port=${2:-8080}
    "${kc[@]}" -n "${namespace}" exec client -- \
        wget -T 4 -t 1 -qO- "http://${address}:${port}/health" | grep -qx ok
}

udp_probe_once() {
    local family=$1
    local address=$2
    local port=${3:-5353}
    local checksum source_port target
    checksum=$(printf '%s' "${family}|${address}|${port}" | cksum | awk '{print $1}')
    source_port=$((43000 + checksum % 10000))
    if [[ ${family} == 4 ]]; then
        target="UDP4:${address}:${port},sourceport=${source_port},reuseaddr"
    else
        target="UDP6:[${address}]:${port},sourceport=${source_port},reuseaddr"
    fi
    "${kc[@]}" -n "${namespace}" exec client -- sh -ec \
        "printf udp-ok | socat -T 4 - '${target}'" | grep -qx udp-ok
}

host_service_matrix() {
    local pod=$1 family target source_port success
    for family in 4 6; do
        if [[ ${family} == 4 ]]; then target="http://${service_v4}:8080/health"; else target="http://[${service_v6}]:8080/health"; fi
        success=false
        for _ in $(seq 1 3); do
            if "${kc[@]}" -n "${namespace}" exec "${pod}" -- \
                wget -T 4 -t 1 -qO- "${target}" | grep -qx ok; then success=true; break; fi
            sleep 0.2
        done
        [[ ${success} == true ]] || {
            echo "host-origin TCP ClusterIP failed from ${pod} over IPv${family}" >&2
            return 1
        }
    done
    for family in 4 6; do
        if [[ ${family} == 4 ]]; then
            source_port=$(qualification_source_port 32000 host 4 "${service_v4}" 5353)
            target="UDP4:${service_v4}:5353,sourceport=${source_port},reuseaddr"
        else
            source_port=$(qualification_source_port 32000 host 6 "${service_v6}" 5353)
            target="UDP6:[${service_v6}]:5353,sourceport=${source_port},reuseaddr"
        fi
        success=false
        for _ in $(seq 1 3); do
            if "${kc[@]}" -n "${namespace}" exec "${pod}" -- sh -ec \
                "printf host-udp | socat -T 4 - '${target}'" | grep -qx host-udp; then success=true; break; fi
            sleep 0.2
        done
        [[ ${success} == true ]] || {
            echo "host-origin UDP ClusterIP failed from ${pod} over IPv${family}" >&2
            return 1
        }
    done
}

qualification_source_port() {
    local base=$1
    local salt=$2
    local family=$3
    local address=$4
    local port=$5
    local checksum
    checksum=$(printf '%s' "${salt}|${family}|${address}|${port}" | cksum | awk '{print $1}')
    printf '%s\n' "$((base + checksum % 10000))"
}

fresh_tcp_probe() {
    local family=$1
    local address=$2
    local port=${3:-8080}
    local source_port target
    source_port=$(qualification_source_port 20000 negative "${family}" "${address}" "${port}")
    if [[ ${family} == 4 ]]; then
        target="TCP4:${address}:${port},sourceport=${source_port},reuseaddr,connect-timeout=1"
    else
        target="TCP6:[${address}]:${port},sourceport=${source_port},reuseaddr,connect-timeout=1"
    fi
    "${kc[@]}" -n "${namespace}" exec client -- sh -ec \
        "printf 'GET /health HTTP/1.0\\r\\nHost: qualification\\r\\n\\r\\n' | socat -T 1 - '${target}'" \
        | tr -d '\r' | grep -qx ok
}

fresh_udp_probe() {
    local family=$1
    local address=$2
    local port=${3:-5353}
    local source_port target
    source_port=$(qualification_source_port 20000 negative "${family}" "${address}" "${port}")
    if [[ ${family} == 4 ]]; then
        target="UDP4:${address}:${port},sourceport=${source_port},reuseaddr"
    else
        target="UDP6:[${address}]:${port},sourceport=${source_port},reuseaddr"
    fi
    "${kc[@]}" -n "${namespace}" exec client -- sh -ec \
        "printf udp-ok | socat -T 1 - '${target}'" | grep -qx udp-ok
}

udp_probe() {
    local family=$1
    local address=$2
    local port=${3:-5353}
    for _ in $(seq 1 3); do
        if udp_probe_once "${family}" "${address}" "${port}"; then
            return 0
        fi
        sleep 0.2
    done
    return 1
}

udp_probe_with_source_port() {
    local family=$1
    local address=$2
    local port=$3
    local source_port=$4
    local target
    if [[ ${family} == 4 ]]; then
        target="UDP4:${address}:${port},sourceport=${source_port},reuseaddr"
    else
        target="UDP6:[${address}]:${port},sourceport=${source_port},reuseaddr"
    fi
    for _ in $(seq 1 3); do
        if "${kc[@]}" -n "${namespace}" exec client -- sh -ec \
            "printf retained | socat -T 4 - '${target}'" | grep -qx retained; then
            return 0
        fi
        sleep 0.2
    done
    return 1
}

retained_node_port_matrix() {
    [[ ${node_port_mode} == true ]] || return 0
    udp_probe_with_source_port 4 "${client_node_v4}" 30053 42001
    udp_probe_with_source_port 6 "${client_node_v6}" 30053 42002
    udp_probe_with_source_port 4 "${server_node_v4}" 31053 42003
    udp_probe_with_source_port 6 "${server_node_v6}" 31053 42004
}

source_probe() {
    local family=$1
    local address=$2
    local port=$3
    local target
    if [[ ${family} == 4 ]]; then
        target="TCP4:${address}:${port}"
    else
        target="TCP6:[${address}]:${port}"
    fi
    "${kc[@]}" -n "${namespace}" exec client -- sh -ec \
        "printf probe | socat -T 4 - '${target}'" | tr -d '\r\n'
}

canonical_ip() {
    python3 -c 'import ipaddress,sys; print(ipaddress.ip_address(sys.argv[1].strip("[]")))' "$1"
}

verify_node_port_sources() {
    [[ ${node_port_mode} == true ]] || return 0
    [[ $(canonical_ip "$(source_probe 4 "${client_node_v4}" 30081)") == $(canonical_ip "${client_node_v4}") ]]
    [[ $(canonical_ip "$(source_probe 6 "${client_node_v6}" 30081)") == $(canonical_ip "${client_node_v6}") ]]
    [[ $(canonical_ip "$(source_probe 4 "${server_node_v4}" 30081)") == $(canonical_ip "${server_node_v4}") ]]
    [[ $(canonical_ip "$(source_probe 6 "${server_node_v6}" 30081)") == $(canonical_ip "${server_node_v6}") ]]
    [[ $(canonical_ip "$(source_probe 4 "${server_node_v4}" 31081)") == $(canonical_ip "${client_v4}") ]]
    [[ $(canonical_ip "$(source_probe 6 "${server_node_v6}" 31081)") == $(canonical_ip "${client_v6}") ]]
}

service_probe_matrix() {
    tcp_probe "${service_v4}"
    tcp_probe "[${service_v6}]"
    udp_probe 4 "${service_v4}"
    udp_probe 6 "${service_v6}"
}

node_port_probe_matrix() {
    [[ ${node_port_mode} == true ]] || return 0
    tcp_probe "${client_node_v4}" 30080
    tcp_probe "[${client_node_v6}]" 30080
    tcp_probe "${server_node_v4}" 30080
    tcp_probe "[${server_node_v6}]" 30080
    udp_probe 4 "${client_node_v4}" 30053
    udp_probe 6 "${client_node_v6}" 30053
    udp_probe 4 "${server_node_v4}" 30053
    udp_probe 6 "${server_node_v6}" 30053

    tcp_probe "${server_node_v4}" 31080
    tcp_probe "[${server_node_v6}]" 31080
    udp_probe 4 "${server_node_v4}" 31053
    udp_probe 6 "${server_node_v6}" 31053
    expect_local_node_port_blocked
}

expect_local_node_port_blocked() {
    local succeeded=false
    if fresh_tcp_probe 4 "${client_node_v4}" 31080 >/dev/null 2>&1; then succeeded=true; fi
    if fresh_tcp_probe 6 "${client_node_v6}" 31080 >/dev/null 2>&1; then succeeded=true; fi
    if fresh_udp_probe 4 "${client_node_v4}" 31053 >/dev/null 2>&1; then succeeded=true; fi
    if fresh_udp_probe 6 "${client_node_v6}" 31053 >/dev/null 2>&1; then succeeded=true; fi
    if [[ ${succeeded} == true ]]; then
        echo "Local NodePort unexpectedly forwarded without a local backend" >&2
        return 1
    fi
}

active_probe_matrix() {
    service_probe_matrix
    node_port_probe_matrix
}

expect_service_matrix_blocked() {
    local succeeded=false
    if fresh_tcp_probe 4 "${service_v4}" >/dev/null 2>&1; then succeeded=true; fi
    if fresh_tcp_probe 6 "${service_v6}" >/dev/null 2>&1; then succeeded=true; fi
    if fresh_udp_probe 4 "${service_v4}" >/dev/null 2>&1; then succeeded=true; fi
    if fresh_udp_probe 6 "${service_v6}" >/dev/null 2>&1; then succeeded=true; fi
    if [[ ${succeeded} == true ]]; then
        echo "backendless Service unexpectedly forwarded traffic" >&2
        return 1
    fi
}

expect_all_service_frontends_blocked() {
    expect_service_matrix_blocked
    [[ ${node_port_mode} == true ]] || return 0
    local succeeded=false
    for endpoint in \
        "4 ${client_node_v4} 30080 tcp" "6 ${client_node_v6} 30080 tcp" \
        "4 ${server_node_v4} 30080 tcp" "6 ${server_node_v6} 30080 tcp" \
        "4 ${client_node_v4} 31080 tcp" "6 ${client_node_v6} 31080 tcp" \
        "4 ${server_node_v4} 31080 tcp" "6 ${server_node_v6} 31080 tcp" \
        "4 ${client_node_v4} 30053 udp" "6 ${client_node_v6} 30053 udp" \
        "4 ${server_node_v4} 30053 udp" "6 ${server_node_v6} 30053 udp" \
        "4 ${client_node_v4} 31053 udp" "6 ${client_node_v6} 31053 udp" \
        "4 ${server_node_v4} 31053 udp" "6 ${server_node_v6} 31053 udp"; do
        read -r family address port protocol <<<"${endpoint}"
        if [[ ${protocol} == tcp ]]; then
            if fresh_tcp_probe "${family}" "${address}" "${port}" >/dev/null 2>&1; then succeeded=true; fi
        elif fresh_udp_probe "${family}" "${address}" "${port}" >/dev/null 2>&1; then
            succeeded=true
        fi
    done
    if [[ ${succeeded} == true ]]; then
        echo "backendless NodePort unexpectedly forwarded traffic" >&2
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
          socat TCP4-LISTEN:8081,reuseaddr,fork 'SYSTEM:echo \$SOCAT_PEERADDR' &
          socat TCP6-LISTEN:8081,reuseaddr,fork,ipv6-v6only=1 'SYSTEM:echo \$SOCAT_PEERADDR' &
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
  labels:
    app: service-client
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
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: isolate-client-ingress
  namespace: ${namespace}
spec:
  podSelector:
    matchLabels:
      app: service-client
  policyTypes: [Ingress]
EOF
if [[ ${node_port_mode} == true ]]; then
    "${kc[@]}" apply -f - >/dev/null <<EOF
apiVersion: v1
kind: Service
metadata:
  name: server-cluster
  namespace: ${namespace}
spec:
  type: NodePort
  externalTrafficPolicy: Cluster
  ipFamilyPolicy: RequireDualStack
  ipFamilies: [IPv4, IPv6]
  selector:
    app: service-server
  ports:
    - name: http
      protocol: TCP
      port: 8080
      targetPort: 8080
      nodePort: 30080
    - name: echo
      protocol: UDP
      port: 5353
      targetPort: 5353
      nodePort: 30053
    - name: source
      protocol: TCP
      port: 8081
      targetPort: 8081
      nodePort: 30081
---
apiVersion: v1
kind: Service
metadata:
  name: server-local
  namespace: ${namespace}
spec:
  type: NodePort
  externalTrafficPolicy: Local
  ipFamilyPolicy: RequireDualStack
  ipFamilies: [IPv4, IPv6]
  selector:
    app: service-server
  ports:
    - name: http
      protocol: TCP
      port: 8080
      targetPort: 8080
      nodePort: 31080
    - name: echo
      protocol: UDP
      port: 5353
      targetPort: 5353
      nodePort: 31053
    - name: source
      protocol: TCP
      port: 8081
      targetPort: 8081
      nodePort: 31081
EOF
fi
host_clients=()
host_client_index=0
for node in "${nodes[@]}"; do
    host_client="host-client-${host_client_index}"
    host_clients+=("${host_client}")
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
    host_client_index=$((host_client_index + 1))
done
"${kc[@]}" -n "${namespace}" wait --for=condition=Ready pod/client pod/server \
    --timeout=180s >/dev/null
"${kc[@]}" -n "${namespace}" wait --for=condition=Ready pod \
    -l qualification.unf.io/role=host-client --timeout=180s >/dev/null
wait_for_convergence

server_json=$("${kc[@]}" -n "${namespace}" get pod server -o json)
server_v4=$(jq -r '.status.podIPs[].ip | select(contains("."))' <<<"${server_json}")
server_v6=$(jq -r '.status.podIPs[].ip | select(contains(":"))' <<<"${server_json}")
client_json=$("${kc[@]}" -n "${namespace}" get pod client -o json)
client_v4=$(jq -r '.status.podIPs[].ip | select(contains("."))' <<<"${client_json}")
client_v6=$(jq -r '.status.podIPs[].ip | select(contains(":"))' <<<"${client_json}")
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

if [[ ${node_port_mode} == true ]]; then
    expected_services=$((baseline_services + 3))
    expected_frontends=$((baseline_frontends + 16))
    expected_backends=$((baseline_backends + 16))
    expected_node_ports=12
else
    expected_services=$((baseline_services + 1))
    expected_frontends=$((baseline_frontends + 4))
    expected_backends=$((baseline_backends + 4))
    expected_node_ports=-1
fi
active_status=$(wait_for_service_shape \
    "${expected_services}" "${expected_frontends}" "${expected_backends}" \
    "${expected_node_ports}")
active_revision=$(jq -r .compiled_service_revision <<<"${active_status}")

qualification_stage=direct-and-clusterip-forwarding
tcp_probe "${server_v4}"
tcp_probe "[${server_v6}]"
udp_probe 4 "${server_v4}"
udp_probe 6 "${server_v6}"
for _ in $(seq 1 8); do
    active_probe_matrix
done
qualification_stage=host-origin-clusterip-forwarding
for host_client in "${host_clients[@]}"; do
    host_service_matrix "${host_client}"
done
verify_node_port_sources

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
        .schema_version == 6
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

if [[ ${node_port_mode} == true ]]; then
    qualification_stage=nodeport-observability-and-simulation
    for _ in $(seq 1 90); do
        history=$(controller_raw /v1/flows 2>/dev/null || true)
        if jq -e \
            --arg client_v4 "${client_node_v4}" --arg client_v6 "${client_node_v6}" \
            --arg server_v4 "${server_node_v4}" --arg server_v6 "${server_node_v6}" '
            .schema_version == 6
            and any(.entries[];
                .key.destination_ipv4 == $client_v4 and .key.destination_port == 30080
                and .key.protocol == 6 and .service.frontend_kind == "node_port_cluster"
                and .service.action == 1)
            and any(.entries[];
                .key.destination_ipv6 == $client_v6 and .key.destination_port == 30053
                and .key.protocol == 17 and .service.frontend_kind == "node_port_cluster"
                and .service.action == 1)
            and any(.entries[];
                .key.destination_ipv4 == $server_v4 and .key.destination_port == 31080
                and .key.protocol == 6 and .service.frontend_kind == "node_port_local"
                and .service.action == 1)
            and any(.entries[];
                .key.destination_ipv6 == $server_v6 and .key.destination_port == 31053
                and .key.protocol == 17 and .service.frontend_kind == "node_port_local"
                and .service.action == 1)
            and any(.entries[];
                .key.destination_ipv4 == $client_v4 and .key.destination_port == 31080
                and .service.frontend_kind == "node_port_local"
                and .service.action == 2 and .service.reason == 3)
        ' <<<"${history}" >/dev/null 2>&1; then
            break
        fi
        sleep 1
    done
    cluster_service_id=$(jq -r --arg address "${client_node_v4}" '
        [.entries[] | select(
            .key.destination_ipv4 == $address
            and .service.frontend_kind == "node_port_cluster"
            and .service.action == 1)][0].service.service_id
    ' <<<"${history}")
    local_service_id=$(jq -r --arg address "${server_node_v4}" '
        [.entries[] | select(
            .key.destination_ipv4 == $address
            and .service.frontend_kind == "node_port_local"
            and .service.action == 1)][0].service.service_id
    ' <<<"${history}")
    [[ ${cluster_service_id} =~ ^[1-9][0-9]*$ ]]
    [[ ${local_service_id} =~ ^[1-9][0-9]*$ ]]

    agent_snapshot=$(controller_raw /v1/state/agents)
    jq -e --arg client_node "${client_node}" --arg server_node "${server_node}" '
        all(.nodes[];
            .report.invalid_service_events == 0
            and .report.desired_node_port_frontend_count == 12
            and .report.applied_node_port_frontend_count == 12
            and .report.node_port_cluster_frontend_count == 6
            and .report.node_port_local_frontend_count == 6)
        and any(.nodes[];
            .node_name == $client_node
            and .report.node_port_cluster_translations > 0
            and .report.node_port_no_backend_drops > 0)
        and any(.nodes[];
            .node_name == $server_node
            and .report.node_port_cluster_translations > 0
            and .report.node_port_local_translations > 0)
    ' <<<"${agent_snapshot}" >/dev/null
    while read -r agent_pod; do
        metrics=$(agent_raw "${agent_pod}" /metrics)
        grep -Eq '^unf_nodeport_frontend_count 12(\.0)?$' <<<"${metrics}"
        grep -Eq '^unf_nodeport_cluster_frontend_count 6(\.0)?$' <<<"${metrics}"
        grep -Eq '^unf_nodeport_local_frontend_count 6(\.0)?$' <<<"${metrics}"
        grep -q '^unf_nodeport_cluster_translations' <<<"${metrics}"
        grep -q '^unf_nodeport_local_translations' <<<"${metrics}"
        grep -q '^unf_nodeport_no_backend_drops' <<<"${metrics}"
    done < <("${kc[@]}" -n unf-system get pods -l app.kubernetes.io/name=unf-agent \
        -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}')

    cluster_explanation=$("${unfctl}" --controller-url "http://127.0.0.1:${controller_port}" \
        --output json service-explain --service-id "${cluster_service_id}" \
        --frontend-kind node-port-cluster --last 15m --limit 100)
    local_explanation=$("${unfctl}" --controller-url "http://127.0.0.1:${controller_port}" \
        --output json service-explain --service-id "${local_service_id}" \
        --frontend-kind node-port-local --last 15m --limit 100)
    jq -e --argjson service_id "${cluster_service_id}" '
        .schema_version == 1 and .service_id == $service_id
        and .frontend_kind == "node_port_cluster"
        and .current_service.name == "server-cluster"
        and any(.outcomes[]; .service.action == 1)
    ' <<<"${cluster_explanation}" >/dev/null
    jq -e --argjson service_id "${local_service_id}" '
        .schema_version == 1 and .service_id == $service_id
        and .frontend_kind == "node_port_local"
        and .current_service.name == "server-local"
        and any(.outcomes[]; .service.action == 1)
        and any(.outcomes[]; .service.action == 2 and .service.reason == 3)
    ' <<<"${local_explanation}" >/dev/null

    simulation_revision_before=$(controller_raw /v1/status | jq -er .compiled_service_revision)
    cluster_simulation=$("${unfctl}" --controller-url "http://127.0.0.1:${controller_port}" \
        --output json service-simulate --node "${client_node}" \
        --address "${client_node_v4}" --port 30080 --protocol tcp)
    local_simulation=$("${unfctl}" --controller-url "http://127.0.0.1:${controller_port}" \
        --output json service-simulate --node "${server_node}" \
        --address "${server_node_v6}" --port 31080 --protocol tcp)
    blocked_simulation=$("${unfctl}" --controller-url "http://127.0.0.1:${controller_port}" \
        --output json service-simulate --node "${client_node}" \
        --address "${client_node_v4}" --port 31080 --protocol tcp)
    jq -e '
        .schema_version == 1 and .name == "server-cluster"
        and .frontend_kind == "node_port_cluster"
        and .traffic_policy == "cluster" and .source_preserved == false
        and .decision == "translate" and (.eligible_backend_ids | length) > 0
    ' <<<"${cluster_simulation}" >/dev/null
    jq -e '
        .schema_version == 1 and .name == "server-local"
        and .frontend_kind == "node_port_local"
        and .traffic_policy == "local" and .source_preserved == true
        and .decision == "translate" and (.eligible_backend_ids | length) > 0
    ' <<<"${local_simulation}" >/dev/null
    jq -e '
        .schema_version == 1 and .name == "server-local"
        and .frontend_kind == "node_port_local"
        and .traffic_policy == "local" and .source_preserved == true
        and .decision == "drop_no_backend" and (.eligible_backend_ids | length) == 0
    ' <<<"${blocked_simulation}" >/dev/null
    [[ $(controller_raw /v1/status | jq -er .compiled_service_revision) == "${simulation_revision_before}" ]]
fi

qualification_stage=readiness-withdrawal
retained_node_port_matrix
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
# Reuse the established UDP tuples before the exhaustive negative matrix can
# legitimately age them beyond the protocol's bounded idle lifetime.
retained_node_port_matrix
expect_all_service_frontends_blocked
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
active_probe_matrix

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
expect_all_service_frontends_blocked
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
expect_all_service_frontends_blocked

qualification_stage=backend-recovery
apply_server
"${kc[@]}" -n "${namespace}" wait --for=condition=Ready pod/server --timeout=180s >/dev/null
recovered_status=$(wait_for_service_shape \
    "${expected_services}" "${expected_frontends}" "${expected_backends}" \
    "${expected_node_ports}")
recovered_revision=$(jq -r .compiled_service_revision <<<"${recovered_status}")
(( recovered_revision > active_revision ))
active_probe_matrix

qualification_stage=controller-outage-agent-recovery
"${kc[@]}" -n unf-system scale deployment/unf-controller --replicas=0 >/dev/null
controller_scaled_down=true
"${kc[@]}" -n unf-system wait --for=delete pod \
    -l app.kubernetes.io/name=unf-controller --timeout=90s >/dev/null
for replacement_node in "${client_node}" "${server_node}"; do
    probe_log="${temporary_dir}/probe-${replacement_node}.log"
    (
        for _ in $(seq 1 30); do
            active_probe_matrix
        done
    ) >"${probe_log}" 2>&1 &
    probe_pid=$!
    old_agent=$("${kc[@]}" -n unf-system get pod -l app.kubernetes.io/name=unf-agent \
        --field-selector spec.nodeName="${replacement_node}" -o jsonpath='{.items[0].metadata.name}')
    "${kc[@]}" -n unf-system delete pod "${old_agent}" --wait=false >/dev/null
    "${kc[@]}" -n unf-system rollout status daemonset/unf-agent --timeout=180s >/dev/null
    if ! wait "${probe_pid}"; then
        echo "continuous NodePort probes failed while replacing the agent on ${replacement_node}" >&2
        sed 's/^/probe: /' "${probe_log}" >&2
        exit 1
    fi
    new_agent=$("${kc[@]}" -n unf-system get pod -l app.kubernetes.io/name=unf-agent \
        --field-selector spec.nodeName="${replacement_node}" -o jsonpath='{.items[0].metadata.name}')
    [[ ${new_agent} != "${old_agent}" ]]
    recovered_agent_status=$(agent_raw "${new_agent}" /v1/status)
    jq -e '
        .schema_version == 5
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
        jq -e "if has(\"service\") then .schemaVersion == 1 and .service.schemaVersion == 2 and .service.revision > 0 and (.service.services | length) > 0 and .nodePortNode.schemaVersion == 1 else .schemaVersion == 1 and .revision > 0 and (.services | length) > 0 end" "$snapshot" >/dev/null
        test -e /sys/fs/bpf/unf/v7/SERVICE_CONFIG
        test -e /sys/fs/bpf/unf/v7/SERVICE_FRONTENDS_V4
        test -e /sys/fs/bpf/unf/v7/SERVICE_FRONTENDS_V6
        test -e /sys/fs/bpf/unf/v7/SERVICE_BACKENDS_V4
        test -e /sys/fs/bpf/unf/v7/SERVICE_BACKENDS_V6
        test -e /sys/fs/bpf/unf/v7/NODE_PORT_CONFIG
        test -e /sys/fs/bpf/unf/v7/NODE_PORT_FRONTENDS_V4
        test -e /sys/fs/bpf/unf/v7/NODE_PORT_FRONTENDS_V6
    '
done
"${kc[@]}" -n unf-system scale deployment/unf-controller --replicas=1 >/dev/null
controller_scaled_down=false
"${kc[@]}" -n unf-system rollout status deployment/unf-controller --timeout=180s >/dev/null
wait_for_convergence
active_probe_matrix

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
if [[ ${node_port_mode} == true ]]; then cleanup_node_ports=0; else cleanup_node_ports=-1; fi
wait_for_service_shape "${baseline_services}" "${baseline_frontends}" "${baseline_backends}" \
    "${cleanup_node_ports}" \
    >/dev/null
if [[ ${node_port_mode} == true ]]; then
    map_audit_label=qualification.unf.io/nodeport-map-audit
    for node in "${nodes[@]}"; do
        audit_pod="unf-nodeport-map-audit-${node##*-}"
        "${kc[@]}" -n unf-system delete pod "${audit_pod}" \
            --ignore-not-found --wait=true >/dev/null
        "${kc[@]}" apply -f - >/dev/null <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: ${audit_pod}
  namespace: unf-system
  labels:
    qualification.unf.io/nodeport-map-audit: "true"
spec:
  nodeName: ${node}
  hostNetwork: true
  restartPolicy: Never
  tolerations:
    - operator: Exists
  containers:
    - name: audit
      image: localhost/unf-test-tools:ipv6-ext-v1
      imagePullPolicy: Never
      command: [sh, -ec]
      args:
        - |
          test "\$(bpftool -j map dump pinned /sys/fs/bpf/unf/v7/NODE_PORT_FRONTENDS_V4 | jq length)" -eq 0
          test "\$(bpftool -j map dump pinned /sys/fs/bpf/unf/v7/NODE_PORT_FRONTENDS_V6 | jq length)" -eq 0
          snapshot=/var/lib/unf/cni/v1/service-snapshot.json
          jq -e '.schemaVersion == 1 and has("service") == false and (.services | all(.nodePorts | length == 0))' "\$snapshot" >/dev/null
      securityContext:
        privileged: true
      volumeMounts:
        - name: bpffs
          mountPath: /sys/fs/bpf
        - name: state
          mountPath: /var/lib/unf
  volumes:
    - name: bpffs
      hostPath:
        path: /sys/fs/bpf
        type: Directory
    - name: state
      hostPath:
        path: /var/lib/unf
        type: Directory
EOF
        "${kc[@]}" -n unf-system wait --for=jsonpath='{.status.phase}'=Succeeded \
            "pod/${audit_pod}" --timeout=60s >/dev/null
    done
    "${kc[@]}" -n unf-system delete pods -l "${map_audit_label}=true" \
        --wait=true --timeout=60s >/dev/null
fi

qualification_stage=evidence
mkdir -p "$(dirname "${artifact}")"
release_revision=$(controller_raw /v1/version | jq -er '
    select(.schema_version == 2 and .component == "unf-controller") | .build_revision
')
[[ ${release_revision} =~ ^[0-9a-f]{40}$ ]]
git -C "${project_root}" merge-base --is-ancestor "${release_revision}" HEAD
qualification_revision=$(git -C "${project_root}" rev-parse HEAD)
[[ ${qualification_revision} =~ ^[0-9a-f]{40}$ ]]
while read -r agent_pod; do
    agent_revision=$(agent_raw "${agent_pod}" /v1/version | jq -er '
        select(.schema_version == 2 and .component == "unf-agent") | .build_revision
    ')
    [[ ${agent_revision} == "${release_revision}" ]]
done < <("${kc[@]}" -n unf-system get pods -l app.kubernetes.io/name=unf-agent \
    -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}')
node_evidence=$("${kc[@]}" get nodes -o json | jq \
    '[.items[] | {name:.metadata.name,podCIDRs:.spec.podCIDRs,internalIPs:[.status.addresses[] | select(.type=="InternalIP") | .address],kernelVersion:.status.nodeInfo.kernelVersion,containerRuntimeVersion:.status.nodeInfo.containerRuntimeVersion,osImage:.status.nodeInfo.osImage}]')
image_evidence=$("${kc[@]}" -n unf-system get pods -l 'app.kubernetes.io/name in (unf-controller,unf-agent)' -o json | jq \
    '[.items[] | {pod:.metadata.name,node:.spec.nodeName,containers:[.status.containerStatuses[] | {name,image,imageID}]}]')
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
    --argjson images "${image_evidence}" \
    --argjson agents "${final_agents}" \
    '{schemaVersion:1,generatedAt:$generatedAt,revision:$revision,context:$context,kubernetesVersion:$kubernetesVersion,kubeProxyPresent:false,service:{id:$serviceId,ipv4:$serviceIPv4,ipv6:$serviceIPv6,activeRevision:$activeRevision,recoveredRevision:$recoveredRevision},nodes:$nodes,images:$images,agents:$agents,verified:["exclusive UNF primary CNI","kube-proxy absent","headless controller bootstrap","direct dual-stack Pod forwarding","IPv4 and IPv6 TCP ClusterIP","IPv4 and IPv6 UDP ClusterIP","Service reply restoration into an ingress-isolated client","all-node IPv4 and IPv6 TCP/UDP host-origin ClusterIP","DNS continuity through UNF Service translation","stable repeated connection translation","readiness withdrawal","terminating endpoint exclusion","backend deletion and recovery","no-backend drop provenance","metrics and agent status","durable flow history","unfctl service explanation","controller-outage source and destination agent replacement","last-known-good service recovery","desired service-map cleanup","CNI attachment and veth cleanup"]}' \
    >"${artifact}"
if [[ ${node_port_mode} == true ]]; then
    jq \
        --argjson durationSeconds "$(( $(date +%s) - started_unix_seconds ))" \
        --arg qualificationRevision "${qualification_revision}" \
        --arg clientNode "${client_node}" --arg serverNode "${server_node}" \
        --arg clientNodeIPv4 "${client_node_v4}" --arg clientNodeIPv6 "${client_node_v6}" \
        --arg serverNodeIPv4 "${server_node_v4}" --arg serverNodeIPv6 "${server_node_v6}" \
        --argjson clusterServiceId "${cluster_service_id}" \
        --argjson localServiceId "${local_service_id}" '
        .schemaVersion = 2
        | .phase = "5.7"
        | .qualificationRevision = $qualificationRevision
        | .durationSeconds = $durationSeconds
        | .nodePort = {
            clusterServiceId:$clusterServiceId,
            localServiceId:$localServiceId,
            clientNode:{name:$clientNode,ipv4:$clientNodeIPv4,ipv6:$clientNodeIPv6},
            serverNode:{name:$serverNode,ipv4:$serverNodeIPv4,ipv6:$serverNodeIPv6},
            clusterPorts:{tcp:30080,udp:30053,source:30081},
            localPorts:{tcp:31080,udp:31053,source:31081}
        }
        | .verified += [
            "IPv4 and IPv6 TCP/UDP NodePort Cluster through both workers",
            "IPv4 and IPv6 TCP/UDP NodePort Local through the backend worker",
            "Local no-backend fail-closed behavior on the non-backend worker",
            "Cluster Node source translation",
            "Local client source preservation",
            "reverse NodePort tuple restoration",
            "established UDP NodePort retention across readiness withdrawal",
            "NodePort readiness, termination, deletion, and recovery",
            "NodePort classified metrics, status, history, and explanation",
            "read-only exact NodePort simulation",
            "controller-outage source and destination agent replacement with composite checkpoint",
            "empty NodePort maps and legacy-format checkpoint after fixture cleanup",
            "exact IPv4 NodePort host sysctl restoration"
        ]
        | .excluded = [
            "SCTP","LoadBalancer","session affinity","topology-aware hints",
            "Maglev","DSR","host-origin NodePort clients","fragments",
            "generic NAT RELATED tracking","production availability and scale"
        ]
    ' "${artifact}" >"${artifact}.tmp"
    mv -f "${artifact}.tmp" "${artifact}"
fi

qualification_stage=exact-platform-rollback
KUBECONFIG="${kubeconfig}" KUBE_CONTEXT="${context}" KIND_PROVIDER="${container_runtime}" \
    "${project_root}/hack/rollback-kind-primary-cni.sh"
jq '.verified += ["scoped ABI-v5 BPF cleanup","exact remote-route deletion","fingerprinted CNI artifact removal","CoreDNS bootstrap restoration","no-CNI baseline restoration"]' \
    "${artifact}" >"${artifact}.tmp"
mv -f "${artifact}.tmp" "${artifact}"

trap - ERR EXIT
echo "kube-proxy-free dual-stack service-fabric qualification passed; evidence: ${artifact}"
