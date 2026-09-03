#!/usr/bin/env bash
set -Eeuo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
kubeconfig=${KUBECONFIG:-"${project_root}/.tools/cl02-audit.kubeconfig"}
context=${KUBE_CONTEXT:-}
expected_infrastructure=${UNF_OPENSHIFT_SERVICE_EXPECTED_INFRASTRUCTURE:-}
acknowledgement=${UNF_OPENSHIFT_SERVICE_ACKNOWLEDGE_DISPOSABLE:-}
release_record=${UNF_OPENSHIFT_SERVICE_RELEASE_RECORD:-"${project_root}/deploy/openshift-primary-cni/runtime/nodeport-release.json"}
deploy_evidence=${UNF_OPENSHIFT_SERVICE_DEPLOY_EVIDENCE:-"${project_root}/.artifacts/phase5-nodeport-openshift-deploy.json"}
artifact=${UNF_OPENSHIFT_SERVICE_EVIDENCE:-"${project_root}/.artifacts/phase5-nodeport-openshift.json"}
namespace=unf-service-qualification
map_audit_label=qualification.unf.io/nodeport-map-audit
stage=initialization
temporary_dir=$(mktemp -d)
probe_pid=
controller_scaled_down=false
namespace_created=false
map_audit_pods_created=false
artifact_tmp=
started_unix=$(date +%s)

failure() {
    local status=$?
    echo "OpenShift service-fabric qualification failed during ${stage} at line ${BASH_LINENO[0]}: ${BASH_COMMAND}" >&2
    return "${status}"
}

cleanup() {
    local status=$?
    trap - ERR EXIT
    set +e
    if [[ -n ${probe_pid} ]]; then
        kill "${probe_pid}" >/dev/null 2>&1 || true
        wait "${probe_pid}" >/dev/null 2>&1 || true
    fi
    if [[ ${controller_scaled_down} == true ]]; then
        "${kc[@]}" -n unf-system scale deployment/unf-controller --replicas=1 >/dev/null 2>&1 || true
    fi
    if [[ ${namespace_created} == true ]]; then
        "${kc[@]}" delete namespace "${namespace}" --ignore-not-found --wait=true \
            --timeout=180s >/dev/null 2>&1 || true
    fi
    if [[ ${map_audit_pods_created} == true ]]; then
        "${kc[@]}" -n unf-system delete pods -l "${map_audit_label}=true" \
            --ignore-not-found --wait=false >/dev/null 2>&1 || true
    fi
    [[ -z ${artifact_tmp} ]] || rm -f -- "${artifact_tmp}"
    rm -rf -- "${temporary_dir}"
    exit "${status}"
}
trap failure ERR
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

for command in git jq oc python3 stat timeout; do
    command -v "${command}" >/dev/null || {
        echo "OpenShift service-fabric qualification prerequisite is missing: ${command}" >&2
        exit 1
    }
done
if [[ ! -s ${kubeconfig} || $(stat -c '%a' "${kubeconfig}") != 600 ]]; then
    echo "qualification requires a non-empty mode-0600 kubeconfig: ${kubeconfig}" >&2
    exit 1
fi
if [[ ! -s ${release_record} || ! -s ${deploy_evidence} ]]; then
    echo "qualification requires the release record and successful staged-deployment evidence" >&2
    exit 1
fi
if [[ -n $(git -C "${project_root}" status --porcelain) ]]; then
    echo "qualification requires a clean committed worktree" >&2
    exit 1
fi
qualification_revision=$(git -C "${project_root}" rev-parse HEAD)
[[ ${qualification_revision} =~ ^[0-9a-f]{40}$ ]]

source_revision=$(jq -er .sourceRevision "${release_record}")
controller_image=$(jq -er .images.controller "${release_record}")
agent_image=$(jq -er .images.agent "${release_record}")
test_tools_image=$(jq -er .images.testTools "${release_record}")
for image in "${controller_image}" "${agent_image}" "${test_tools_image}"; do
    [[ ${image} =~ ^quay\.io/arencloud/unf-[a-z-]+-dev@sha256:[0-9a-f]{64}$ ]]
done
git -C "${project_root}" merge-base --is-ancestor "${source_revision}" HEAD

if [[ -z ${context} ]]; then
    context=$(oc --kubeconfig "${kubeconfig}" config current-context)
fi
kc=(oc --kubeconfig "${kubeconfig}" --context "${context}")
infrastructure=$("${kc[@]}" get infrastructure cluster -o jsonpath='{.status.infrastructureName}')
if [[ -z ${expected_infrastructure} || ${expected_infrastructure} != "${infrastructure}" \
    || ${acknowledgement} != "${infrastructure}" ]]; then
    echo "refusing qualification: both service-fabric infrastructure acknowledgements must equal ${infrastructure}" >&2
    exit 1
fi
jq -e --arg context "${context}" --arg infrastructure "${infrastructure}" \
    --arg revision "${source_revision}" '
    .schemaVersion == 1 and .stage == "abi-v5-nodeport-staged-deployment"
    and .context == $context and .infrastructure == $infrastructure
    and .sourceRevision == $revision and .kubeProxyPresent == false
    and .agents.all_converged == true
' "${deploy_evidence}" >/dev/null

controller_pod() {
    "${kc[@]}" -n unf-system get pods -l app.kubernetes.io/name=unf-controller -o json \
        | jq -r '.items[] | select(.metadata.deletionTimestamp == null and .status.phase == "Running") | .metadata.name' \
        | head -n 1
}

controller_raw() {
    local path=$1 pod
    pod=$(controller_pod)
    [[ -n ${pod} ]]
    timeout 15 "${kc[@]}" get --raw "/api/v1/namespaces/unf-system/pods/${pod}:9962/proxy${path}"
}

agent_pod_on_node() {
    local node=$1
    "${kc[@]}" -n unf-system get pods -l app.kubernetes.io/name=unf-agent -o json \
        | jq -r --arg node "${node}" '
            .items[] | select(.spec.nodeName == $node and .metadata.deletionTimestamp == null)
            | .metadata.name
        ' | head -n 1
}

agent_raw() {
    local node=$1 path=$2 pod
    pod=$(agent_pod_on_node "${node}")
    [[ -n ${pod} ]]
    timeout 15 "${kc[@]}" get --raw "/api/v1/namespaces/unf-system/pods/${pod}:9963/proxy${path}"
}

host_exec() {
    local node=$1 script=$2 output=
    for _ in $(seq 1 3); do
        if output=$("${kc[@]}" debug "node/${node}" --quiet -- \
            chroot /host sh -euc "${script}" 2>&1); then
            printf '%s\n' "${output}"
            return 0
        fi
        sleep 1
    done
    printf '%s\n' "${output}" >&2
    echo "host inspection failed after three attempts on ${node}" >&2
    return 1
}

unhealthy_operators() {
    "${kc[@]}" get clusteroperators -o json | jq -c '[
        .items[] | select(
            ([.status.conditions[] | select(.type == "Available")][0].status) != "True"
            or ([.status.conditions[] | select(.type == "Degraded")][0].status) == "True"
            or ([.status.conditions[] | select(.type == "Progressing")][0].status) == "True"
        ) | .metadata.name
    ] | sort'
}

wait_for_convergence() {
    local snapshot=
    for _ in $(seq 1 300); do
        snapshot=$(controller_raw /v1/state/agents 2>/dev/null || true)
        if jq -e --argjson expected "${#nodes[@]}" '
            .schema_version == 5 and .expected_agents == $expected
            and .reporting_agents == $expected and .missing_agents == 0
            and .stale_agents == 0 and .converged_agents == $expected
            and .unexpected_agents == 0 and .all_converged == true
            and all(.nodes[]; .fresh and .converged and .report.ready and .report.bpf_loaded
                and .report.desired_service_revision > 0
                and .report.applied_service_revision == .report.desired_service_revision
                and .report.service_last_error == null)
        ' <<<"${snapshot}" >/dev/null 2>&1; then
            printf '%s\n' "${snapshot}"
            return 0
        fi
        sleep 1
    done
    echo "service-fabric agents did not converge during ${stage}" >&2
    jq . <<<"${snapshot}" >&2 || true
    return 1
}

wait_for_service() {
    local expected_ready_backends=$1 pod= snapshot=
    for _ in $(seq 1 180); do
        pod=$(agent_pod_on_node "${client_node}")
        snapshot=$(timeout 15 "${kc[@]}" -n unf-system exec "${pod}" -c agent -- \
            cat /var/lib/unf/cni/v1/service-snapshot.json 2>/dev/null || true)
        if jq -e --arg namespace "${namespace}" --argjson backends "${expected_ready_backends}" '
            (.service // .) as $service
            | $service.schemaVersion == 2
            and any($service.services[];
                .namespace == $namespace and .name == "server"
                and (.frontends | length) == 4
                and ([.backends[] | select(.ready == true and .terminating == false)] | length) == $backends)
        ' <<<"${snapshot}" >/dev/null 2>&1; then
            jq -c '.service // .' <<<"${snapshot}"
            return 0
        fi
        sleep 1
    done
    echo "qualification Service did not reach ${expected_ready_backends} eligible compiled backends" >&2
    jq . <<<"${snapshot}" >&2 || true
    return 1
}

attachment_count() {
    local node=$1 output
    output=$(host_exec "${node}" '
        path=/var/lib/unf/cni/v1/attachments.json
        if test -f "$path"; then jq ".attachments | length" "$path"; else echo 0; fi
    ' 2>&1)
    grep -E '^[0-9]+$' <<<"${output}" | tail -n 1
}

tcp_probe_once() {
    local address=$1 port=${2:-8080}
    "${kc[@]}" -n "${namespace}" exec client -- \
        wget -T 4 -t 1 -qO- "http://${address}:${port}/health" | grep -qx ok
}

tcp_probe() {
    local address=$1 port=${2:-8080}
    for _ in $(seq 1 3); do
        if tcp_probe_once "${address}" "${port}"; then return 0; fi
        sleep 0.2
    done
    echo "TCP service probe failed for ${address}:${port}" >&2
    return 1
}

udp_probe_once() {
    local family=$1 address=$2 port=${3:-5353} checksum source_port target
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

udp_probe() {
    local family=$1 address=$2 port=${3:-5353}
    for _ in $(seq 1 3); do
        if udp_probe_once "${family}" "${address}" "${port}"; then return 0; fi
        sleep 0.2
    done
    return 1
}

qualification_source_port() {
    local base=$1 salt=$2 family=$3 address=$4 port=$5 checksum
    checksum=$(printf '%s' "${salt}|${family}|${address}|${port}" | cksum | awk '{print $1}')
    printf '%s\n' "$((base + checksum % 10000))"
}

fresh_tcp_probe() {
    local family=$1 address=$2 port=${3:-8080} source_port target
    source_port=$(qualification_source_port 20000 negative "${family}" "${address}" "${port}")
    if [[ ${family} == 4 ]]; then
        target="TCP4:${address}:${port},sourceport=${source_port},reuseaddr,connect-timeout=1"
    else
        target="TCP6:[${address}]:${port},sourceport=${source_port},reuseaddr,connect-timeout=1"
    fi
    "${kc[@]}" -n "${namespace}" exec client -- sh -ec \
        "printf 'GET /health HTTP/1.0\r\nHost: qualification\r\n\r\n' | socat -T 1 - '${target}'" \
        | tr -d '\r' | grep -qx ok
}

fresh_udp_probe() {
    local family=$1 address=$2 port=${3:-5353} source_port target
    source_port=$(qualification_source_port 20000 negative "${family}" "${address}" "${port}")
    if [[ ${family} == 4 ]]; then
        target="UDP4:${address}:${port},sourceport=${source_port},reuseaddr"
    else
        target="UDP6:[${address}]:${port},sourceport=${source_port},reuseaddr"
    fi
    "${kc[@]}" -n "${namespace}" exec client -- sh -ec \
        "printf udp-ok | socat -T 1 - '${target}'" | grep -qx udp-ok
}

udp_probe_with_source_port() {
    local family=$1 address=$2 port=$3 source_port=$4 target
    if [[ ${family} == 4 ]]; then
        target="UDP4:${address}:${port},sourceport=${source_port},reuseaddr"
    else
        target="UDP6:[${address}]:${port},sourceport=${source_port},reuseaddr"
    fi
    for _ in $(seq 1 3); do
        if "${kc[@]}" -n "${namespace}" exec client -- sh -ec \
            "printf retained | socat -T 4 - '${target}'" | grep -qx retained; then return 0; fi
        sleep 0.2
    done
    return 1
}

retained_node_port_matrix() {
    udp_probe_with_source_port 4 "${client_node_v4}" 30053 42001
    udp_probe_with_source_port 6 "${client_node_v6}" 30053 42002
    udp_probe_with_source_port 4 "${server_node_v4}" 31053 42003
    udp_probe_with_source_port 6 "${server_node_v6}" 31053 42004
}

source_probe() {
    local family=$1 address=$2 port=$3 target
    if [[ ${family} == 4 ]]; then target="TCP4:${address}:${port}"; else target="TCP6:[${address}]:${port}"; fi
    "${kc[@]}" -n "${namespace}" exec client -- sh -ec \
        "printf probe | socat -T 4 - '${target}'" | tr -d '\r\n'
}

canonical_ip() {
    python3 -c 'import ipaddress,sys; print(ipaddress.ip_address(sys.argv[1].strip("[]")))' "$1"
}

verify_node_port_sources() {
    [[ $(canonical_ip "$(source_probe 4 "${client_node_v4}" 30081)") == $(canonical_ip "${client_node_v4}") ]]
    [[ $(canonical_ip "$(source_probe 6 "${client_node_v6}" 30081)") == $(canonical_ip "${client_node_v6}") ]]
    [[ $(canonical_ip "$(source_probe 4 "${server_node_v4}" 31081)") == $(canonical_ip "${client_v4}") ]]
    [[ $(canonical_ip "$(source_probe 6 "${server_node_v6}" 31081)") == $(canonical_ip "${client_v6}") ]]
}

service_matrix() {
    tcp_probe "${service_v4}"
    tcp_probe "[${service_v6}]"
    udp_probe 4 "${service_v4}"
    udp_probe 6 "${service_v6}"
}

host_service_matrix() {
    local pod=$1 target source_port success
    for family in 4 6; do
        if [[ ${family} == 4 ]]; then target="http://${service_v4}:8080/health"; else target="http://[${service_v6}]:8080/health"; fi
        success=false
        for _ in $(seq 1 3); do
            if "${kc[@]}" -n "${namespace}" exec "${pod}" -- \
                wget -T 4 -t 1 -qO- "${target}" | grep -qx ok; then success=true; break; fi
            sleep 0.2
        done
        if [[ ${success} != true ]]; then
            echo "host-origin TCP ClusterIP failed from ${pod} over IPv${family}" >&2
            return 1
        fi
    done
    source_port=$(qualification_source_port 32000 host 4 "${service_v4}" 5353)
    target="UDP4:${service_v4}:5353,sourceport=${source_port},reuseaddr"
    success=false
    for _ in $(seq 1 3); do
        if "${kc[@]}" -n "${namespace}" exec "${pod}" -- sh -ec \
            "printf host-udp | socat -T 4 - '${target}'" | grep -qx host-udp; then success=true; break; fi
        sleep 0.2
    done
    if [[ ${success} != true ]]; then
        echo "host-origin UDP ClusterIP failed from ${pod} over IPv4" >&2
        return 1
    fi
    source_port=$(qualification_source_port 32000 host 6 "${service_v6}" 5353)
    target="UDP6:[${service_v6}]:5353,sourceport=${source_port},reuseaddr"
    success=false
    for _ in $(seq 1 3); do
        if "${kc[@]}" -n "${namespace}" exec "${pod}" -- sh -ec \
            "printf host-udp | socat -T 4 - '${target}'" | grep -qx host-udp; then success=true; break; fi
        sleep 0.2
    done
    if [[ ${success} != true ]]; then
        echo "host-origin UDP ClusterIP failed from ${pod} over IPv6" >&2
        return 1
    fi
}

node_port_matrix() {
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

active_matrix() {
    service_matrix
    node_port_matrix
}

expect_local_node_port_blocked() {
    local passed=false
    fresh_tcp_probe 4 "${client_node_v4}" 31080 >/dev/null 2>&1 && passed=true
    fresh_tcp_probe 6 "${client_node_v6}" 31080 >/dev/null 2>&1 && passed=true
    fresh_udp_probe 4 "${client_node_v4}" 31053 >/dev/null 2>&1 && passed=true
    fresh_udp_probe 6 "${client_node_v6}" 31053 >/dev/null 2>&1 && passed=true
    [[ ${passed} == false ]]
}

expect_service_blocked() {
    local passed=false
    fresh_tcp_probe 4 "${service_v4}" >/dev/null 2>&1 && passed=true
    fresh_tcp_probe 6 "${service_v6}" >/dev/null 2>&1 && passed=true
    fresh_udp_probe 4 "${service_v4}" >/dev/null 2>&1 && passed=true
    fresh_udp_probe 6 "${service_v6}" >/dev/null 2>&1 && passed=true
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
            fresh_tcp_probe "${family}" "${address}" "${port}" >/dev/null 2>&1 && passed=true
        else
            fresh_udp_probe "${family}" "${address}" "${port}" >/dev/null 2>&1 && passed=true
        fi
    done
    [[ ${passed} == false ]]
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
  terminationGracePeriodSeconds: 20
  automountServiceAccountToken: false
  securityContext:
    runAsNonRoot: true
    seccompProfile:
      type: RuntimeDefault
  containers:
    - name: server
      image: ${test_tools_image}
      imagePullPolicy: IfNotPresent
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
      lifecycle:
        preStop:
          exec:
            command: [sh, -ec, "sleep 12"]
      securityContext:
        allowPrivilegeEscalation: false
        capabilities:
          drop: ["ALL"]
EOF
}

wait_for_agent_replacement() {
    local node=$1 old_uid=$2 pod_json=
    for _ in $(seq 1 300); do
        pod_json=$("${kc[@]}" -n unf-system get pods -l app.kubernetes.io/name=unf-agent -o json 2>/dev/null || true)
        if jq -e --arg node "${node}" --arg uid "${old_uid}" --arg image "${agent_image}" '
            any(.items[]; .spec.nodeName == $node and .metadata.uid != $uid
                and .metadata.deletionTimestamp == null and .status.phase == "Running"
                and (.spec.containers | all(.image == $image))
                and (.status.containerStatuses | all(.ready == true)))
        ' <<<"${pod_json}" >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    echo "offline replacement agent on ${node} did not become Ready" >&2
    return 1
}

wait_for_agent_service_state() {
    local node=$1 allow_controller_outage=${2:-false} status=
    for _ in $(seq 1 300); do
        status=$(agent_raw "${node}" /v1/status 2>/dev/null || true)
        if jq -e --argjson allow_controller_outage "${allow_controller_outage}" '
            .schema_version == 5 and .ready and .bpf_loaded
            and .desired_service_revision > 0
            and .applied_service_revision == .desired_service_revision
            and .applied_service_epoch == .desired_service_epoch
            and .service_count > 0 and .service_frontend_count > 0
            and .service_backend_count > 0
            and .desired_node_port_frontend_count == 12
            and .applied_node_port_frontend_count == 12
            and has("service_last_error")
            and (.service_last_error == null or ($allow_controller_outage
                and .service_last_error == "request controller service snapshot"))
        ' <<<"${status}" >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    echo "replacement agent on ${node} did not recover healthy service state" >&2
    jq . <<<"${status}" >&2 || true
    return 1
}

replace_agent_with_traffic() {
    local node=$1 old_pod old_uid log
    log="${temporary_dir}/traffic-${node}.log"
    (
        for _ in $(seq 1 30); do active_matrix; done
    ) >"${log}" 2>&1 &
    probe_pid=$!
    old_pod=$(agent_pod_on_node "${node}")
    old_uid=$("${kc[@]}" -n unf-system get pod "${old_pod}" -o jsonpath='{.metadata.uid}')
    "${kc[@]}" -n unf-system delete pod "${old_pod}" --wait=false >/dev/null
    wait_for_agent_replacement "${node}" "${old_uid}"
    if ! wait "${probe_pid}"; then
        cat "${log}" >&2
        probe_pid=
        return 1
    fi
    probe_pid=
    wait_for_agent_service_state "${node}" true
}

stage=preflight
network=$("${kc[@]}" get network.config.openshift.io cluster -o json)
jq -e '
    .spec.networkType == "None"
    and ([.spec.clusterNetwork[].cidr | contains(":")] | any)
    and ([.spec.clusterNetwork[].cidr | contains(":") | not] | any)
    and ([.spec.serviceNetwork[] | contains(":")] | any)
    and ([.spec.serviceNetwork[] | contains(":") | not] | any)
' <<<"${network}" >/dev/null
[[ $("${kc[@]}" get network.operator.openshift.io cluster -o jsonpath='{.spec.deployKubeProxy}') == false ]]
mapfile -t nodes < <("${kc[@]}" get nodes -l network.unf.io/primary-cni=enabled \
    -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' | sort)
mapfile -t workers < <("${kc[@]}" get nodes -l node-role.kubernetes.io/worker \
    -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' | sort)
[[ ${#nodes[@]} -ge 3 && ${#workers[@]} -eq 2 ]]
client_node=${workers[0]}
server_node=${workers[1]}
for node in "${nodes[@]}"; do
    [[ $("${kc[@]}" get node "${node}" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}') == True ]]
    [[ $("${kc[@]}" -n unf-system get pod "$(agent_pod_on_node "${node}")" -o jsonpath='{.spec.containers[0].image}') == "${agent_image}" ]]
    host_check=$(host_exec "${node}" '
        test "$(getenforce)" = Enforcing
        test -d /sys/fs/bpf/unf/v13
        test -e /sys/fs/bpf/unf/v13/NODE_PORT_CONFIG
        test -e /sys/fs/bpf/unf/v13/NODE_PORT_FRONTENDS_V4
        test -e /sys/fs/bpf/unf/v13/NODE_PORT_FRONTENDS_V6
        for key in all default; do
            test "$(cat /proc/sys/net/ipv4/conf/${key}/rp_filter)" -eq 0
            test "$(cat /proc/sys/net/ipv4/conf/${key}/accept_local)" -eq 1
        done
        test "$(find /etc/kubernetes/cni/net.d -mindepth 1 -maxdepth 1 -type f -printf "%f\n")" = 10-unf.conflist
        echo host-ready
    ' 2>&1)
    grep -q '^host-ready$' <<<"${host_check}"
done
baseline_unhealthy=$(unhealthy_operators)
wait_for_convergence >/dev/null

stage=fixture-create
"${kc[@]}" delete namespace "${namespace}" --ignore-not-found --wait=true --timeout=180s >/dev/null
client_attachment_baseline=$(attachment_count "${client_node}")
server_attachment_baseline=$(attachment_count "${server_node}")
"${kc[@]}" create namespace "${namespace}" >/dev/null
namespace_created=true
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
  automountServiceAccountToken: false
  securityContext:
    runAsNonRoot: true
    seccompProfile:
      type: RuntimeDefault
  containers:
    - name: client
      image: ${test_tools_image}
      imagePullPolicy: IfNotPresent
      command: [sh, -ec, "sleep infinity"]
      securityContext:
        allowPrivilegeEscalation: false
        capabilities:
          drop: ["ALL"]
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
"${kc[@]}" -n "${namespace}" wait --for=condition=Ready pod/client pod/server --timeout=240s >/dev/null
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
  tolerations:
    - operator: Exists
  securityContext:
    runAsNonRoot: true
    seccompProfile:
      type: RuntimeDefault
  containers:
    - name: client
      image: ${test_tools_image}
      imagePullPolicy: IfNotPresent
      command: [sh, -ec, "sleep infinity"]
      securityContext:
        allowPrivilegeEscalation: false
        capabilities:
          drop: ["ALL"]
EOF
    host_client_index=$((host_client_index + 1))
done
"${kc[@]}" -n "${namespace}" wait --for=condition=Ready pod \
    -l qualification.unf.io/role=host-client --timeout=240s >/dev/null
service_snapshot=$(wait_for_service 4)
service_id=$(jq -r --arg namespace "${namespace}" \
    '.services[] | select(.namespace == $namespace and .name == "server") | .id' <<<"${service_snapshot}")
cluster_service_id=$(jq -r --arg namespace "${namespace}" \
    '.services[] | select(.namespace == $namespace and .name == "server-cluster") | .id' <<<"${service_snapshot}")
local_service_id=$(jq -r --arg namespace "${namespace}" \
    '.services[] | select(.namespace == $namespace and .name == "server-local") | .id' <<<"${service_snapshot}")
for id in "${service_id}" "${cluster_service_id}" "${local_service_id}"; do
    [[ ${id} =~ ^[1-9][0-9]*$ ]]
done
mapfile -t service_ips < <("${kc[@]}" -n "${namespace}" get service server -o json | jq -r '.spec.clusterIPs[]')
service_v4=${service_ips[0]}
service_v6=${service_ips[1]}
client_json=$("${kc[@]}" -n "${namespace}" get pod client -o json)
client_v4=$(jq -r '.status.podIPs[].ip | select(contains("."))' <<<"${client_json}")
client_v6=$(jq -r '.status.podIPs[].ip | select(contains(":"))' <<<"${client_json}")
client_node_json=$("${kc[@]}" get node "${client_node}" -o json)
server_node_json=$("${kc[@]}" get node "${server_node}" -o json)
client_node_v4=$(jq -r '.status.addresses[] | select(.type == "InternalIP" and (.address | contains("."))) | .address' <<<"${client_node_json}")
client_node_v6=$(jq -r '.status.addresses[] | select(.type == "InternalIP" and (.address | contains(":"))) | .address' <<<"${client_node_json}")
server_node_v4=$(jq -r '.status.addresses[] | select(.type == "InternalIP" and (.address | contains("."))) | .address' <<<"${server_node_json}")
server_node_v6=$(jq -r '.status.addresses[] | select(.type == "InternalIP" and (.address | contains(":"))) | .address' <<<"${server_node_json}")
for address in "${client_v4}" "${client_v6}" "${client_node_v4}" "${client_node_v6}" \
    "${server_node_v4}" "${server_node_v6}"; do [[ -n ${address} ]]; done
wait_for_convergence >/dev/null

stage=host-origin-service-proof
for host_client in "${host_clients[@]}"; do
    host_service_matrix "${host_client}"
done

stage=pre-removal-service-proof
for _ in $(seq 1 8); do active_matrix; done
verify_node_port_sources
resolution=$("${kc[@]}" -n "${namespace}" exec client -- getent ahosts server)
grep -Fq "${service_v4}" <<<"${resolution}"
grep -Fq "${service_v6}" <<<"${resolution}"
history=
for _ in $(seq 1 90); do
    history=$(controller_raw /v1/flows 2>/dev/null || true)
    if jq -e --arg v4 "${service_v4}" --arg v6 "${service_v6}" '
        .schema_version == 6
        and any(.entries[]; .key.destination_ipv4 == $v4 and .key.protocol == 6 and .service.action == 1)
        and any(.entries[]; .key.destination_ipv4 == $v4 and .key.protocol == 17 and .service.action == 1)
        and any(.entries[]; .key.destination_ipv6 == $v6 and .key.protocol == 6 and .service.action == 1)
        and any(.entries[]; .key.destination_ipv6 == $v6 and .key.protocol == 17 and .service.action == 1)
    ' <<<"${history}" >/dev/null 2>&1; then break; fi
    sleep 1
done
jq -e --arg v4 "${service_v4}" --arg v6 "${service_v6}" '
    any(.entries[]; .key.destination_ipv4 == $v4 and .service.action == 1)
    and any(.entries[]; .key.destination_ipv6 == $v6 and .service.action == 1)
' <<<"${history}" >/dev/null

stage=kube-proxy-absence
for _ in $(seq 1 300); do
    daemonset_count=$("${kc[@]}" -n openshift-kube-proxy get daemonsets -o json 2>/dev/null \
        | jq '.items | length' || echo 0)
    pod_count=$("${kc[@]}" -n openshift-kube-proxy get pods -o json 2>/dev/null \
        | jq '.items | length' || echo 0)
    network_progressing=$("${kc[@]}" get clusteroperator network -o json \
        | jq -r '.status.conditions[] | select(.type == "Progressing") | .status')
    [[ ${daemonset_count} -eq 0 && ${pod_count} -eq 0 && ${network_progressing} == False ]] && break
    sleep 2
done
[[ ${daemonset_count} -eq 0 && ${pod_count} -eq 0 && ${network_progressing} == False ]]
for node in "${nodes[@]}"; do
    proxy_check=$(host_exec "${node}" '
        ! iptables-save 2>/dev/null | grep -q "KUBE-SVC"
        if command -v ip6tables-save >/dev/null 2>&1; then
            ! ip6tables-save 2>/dev/null | grep -q "KUBE-SVC"
        fi
        echo proxy-state-absent
    ' 2>&1)
    grep -q '^proxy-state-absent$' <<<"${proxy_check}"
done

stage=kube-proxy-free-forwarding
for _ in $(seq 1 16); do active_matrix; done
resolution=$("${kc[@]}" -n "${namespace}" exec client -- getent ahosts server)
grep -Fq "${service_v4}" <<<"${resolution}"
grep -Fq "${service_v6}" <<<"${resolution}"

stage=readiness-withdrawal
retained_node_port_matrix
"${kc[@]}" -n "${namespace}" exec server -- touch /tmp/unready
"${kc[@]}" -n "${namespace}" wait --for=condition=Ready=false pod/server --timeout=90s >/dev/null
wait_for_service 0 >/dev/null
wait_for_convergence >/dev/null
retained_node_port_matrix
expect_service_blocked
"${kc[@]}" -n "${namespace}" exec server -- rm -f /tmp/unready
"${kc[@]}" -n "${namespace}" wait --for=condition=Ready pod/server --timeout=90s >/dev/null
wait_for_service 4 >/dev/null
wait_for_convergence >/dev/null
active_matrix

stage=terminating-and-deleted-endpoint
"${kc[@]}" -n "${namespace}" delete pod server --wait=false >/dev/null
for _ in $(seq 1 60); do
    slices=$("${kc[@]}" -n "${namespace}" get endpointslice \
        -l kubernetes.io/service-name=server -o json)
    jq -e 'any(.items[] | (.endpoints // [])[]; .conditions.terminating == true)' \
        <<<"${slices}" >/dev/null 2>&1 && break
    sleep 1
done
jq -e 'any(.items[] | (.endpoints // [])[]; .conditions.terminating == true)' <<<"${slices}" >/dev/null
wait_for_service 0 >/dev/null
wait_for_convergence >/dev/null
expect_service_blocked
"${kc[@]}" -n "${namespace}" wait --for=delete pod/server --timeout=120s >/dev/null
wait_for_service 0 >/dev/null
expect_service_blocked

stage=backend-recovery
apply_server
"${kc[@]}" -n "${namespace}" wait --for=condition=Ready pod/server --timeout=240s >/dev/null
wait_for_service 4 >/dev/null
wait_for_convergence >/dev/null
active_matrix

stage=controller-outage-agent-recovery
"${kc[@]}" -n unf-system scale deployment/unf-controller --replicas=0 >/dev/null
controller_scaled_down=true
"${kc[@]}" -n unf-system wait --for=delete pod \
    -l app.kubernetes.io/name=unf-controller --timeout=120s >/dev/null
replace_agent_with_traffic "${client_node}"
replace_agent_with_traffic "${server_node}"
"${kc[@]}" -n unf-system scale deployment/unf-controller --replicas=1 >/dev/null
controller_scaled_down=false
"${kc[@]}" -n unf-system rollout status deployment/unf-controller --timeout=10m >/dev/null
wait_for_convergence >/dev/null
active_matrix

stage=observability-and-explanation
"${kc[@]}" -n "${namespace}" exec server -- touch /tmp/unready
"${kc[@]}" -n "${namespace}" wait --for=condition=Ready=false pod/server --timeout=90s >/dev/null
wait_for_service 0 >/dev/null
wait_for_convergence >/dev/null
expect_service_blocked
"${kc[@]}" -n "${namespace}" exec server -- rm -f /tmp/unready
"${kc[@]}" -n "${namespace}" wait --for=condition=Ready pod/server --timeout=90s >/dev/null
wait_for_service 4 >/dev/null
wait_for_convergence >/dev/null
active_matrix
history=
for _ in $(seq 1 90); do
    history=$(controller_raw /v1/flows 2>/dev/null || true)
    if jq -e --argjson service_id "${service_id}" '
        .schema_version == 6
        and any(.entries[]; .service.service_id == $service_id and .service.action == 1 and .service.backend_id > 0)
        and any(.entries[]; .service.service_id == $service_id and .service.action == 2 and .service.reason == 3)
    ' <<<"${history}" >/dev/null 2>&1; then break; fi
    sleep 1
done
jq -e --argjson service_id "${service_id}" '
    .schema_version == 6
    and any(.entries[]; .service.service_id == $service_id and .service.action == 1 and .service.backend_id > 0)
    and any(.entries[]; .service.service_id == $service_id and .service.action == 2 and .service.reason == 3)
' <<<"${history}" >/dev/null
explanation=$(controller_raw "/v1/services/explain?service_id=${service_id}&limit=100")
jq -e --argjson service_id "${service_id}" '
    .schema_version == 1 and .service_id == $service_id
    and .current_service.namespace == "unf-service-qualification"
    and .current_service.name == "server"
    and .matched_outcomes > 0 and .matched_observations > 0
' <<<"${explanation}" >/dev/null

stage=nodeport-observability-and-simulation
for _ in $(seq 1 90); do
    history=$(controller_raw /v1/flows 2>/dev/null || true)
    if jq -e \
        --arg client_v4 "${client_node_v4}" --arg client_v6 "${client_node_v6}" \
        --arg server_v4 "${server_node_v4}" --arg server_v6 "${server_node_v6}" '
        .schema_version == 6
        and any(.entries[]; .key.destination_ipv4 == $client_v4 and .key.destination_port == 30080
            and .service.frontend_kind == "node_port_cluster" and .service.action == 1)
        and any(.entries[]; .key.destination_ipv6 == $client_v6 and .key.destination_port == 30053
            and .service.frontend_kind == "node_port_cluster" and .service.action == 1)
        and any(.entries[]; .key.destination_ipv4 == $server_v4 and .key.destination_port == 31080
            and .service.frontend_kind == "node_port_local" and .service.action == 1)
        and any(.entries[]; .key.destination_ipv6 == $server_v6 and .key.destination_port == 31053
            and .service.frontend_kind == "node_port_local" and .service.action == 1)
        and any(.entries[]; .key.destination_ipv4 == $client_v4 and .key.destination_port == 31080
            and .service.frontend_kind == "node_port_local" and .service.action == 2 and .service.reason == 3)
    ' <<<"${history}" >/dev/null 2>&1; then break; fi
    sleep 1
done
jq -e --argjson cluster "${cluster_service_id}" --argjson local "${local_service_id}" '
    any(.entries[]; .service.service_id == $cluster and .service.frontend_kind == "node_port_cluster" and .service.action == 1)
    and any(.entries[]; .service.service_id == $local and .service.frontend_kind == "node_port_local" and .service.action == 1)
    and any(.entries[]; .service.service_id == $local and .service.frontend_kind == "node_port_local" and .service.action == 2 and .service.reason == 3)
' <<<"${history}" >/dev/null
agents_now=$(controller_raw /v1/state/agents)
jq -e --arg client "${client_node}" --arg server "${server_node}" '
    all(.nodes[]; .report.invalid_service_events == 0
        and .report.desired_node_port_frontend_count == 12
        and .report.applied_node_port_frontend_count == 12
        and .report.node_port_cluster_frontend_count == 6
        and .report.node_port_local_frontend_count == 6)
    and any(.nodes[]; .node_name == $client and .report.node_port_cluster_translations > 0
        and .report.node_port_no_backend_drops > 0)
    and any(.nodes[]; .node_name == $server and .report.node_port_cluster_translations > 0
        and .report.node_port_local_translations > 0)
' <<<"${agents_now}" >/dev/null
cluster_explanation=$(controller_raw "/v1/services/explain?service_id=${cluster_service_id}&frontend_kind=node_port_cluster&limit=100")
local_explanation=$(controller_raw "/v1/services/explain?service_id=${local_service_id}&frontend_kind=node_port_local&limit=100")
jq -e '.frontend_kind == "node_port_cluster" and .current_service.name == "server-cluster" and any(.outcomes[]; .service.action == 1)' <<<"${cluster_explanation}" >/dev/null
jq -e '.frontend_kind == "node_port_local" and .current_service.name == "server-local" and any(.outcomes[]; .service.action == 1) and any(.outcomes[]; .service.action == 2 and .service.reason == 3)' <<<"${local_explanation}" >/dev/null
simulation_revision_before=$(controller_raw /v1/status | jq -er .compiled_service_revision)
cluster_simulation=$(controller_raw "/v1/services/nodeport/simulate?node_name=${client_node}&address=${client_node_v4}&port=30080&protocol=tcp")
local_simulation=$(controller_raw "/v1/services/nodeport/simulate?node_name=${server_node}&address=${server_node_v4}&port=31080&protocol=tcp")
blocked_simulation=$(controller_raw "/v1/services/nodeport/simulate?node_name=${client_node}&address=${client_node_v4}&port=31080&protocol=tcp")
jq -e '.frontend_kind == "node_port_cluster" and .traffic_policy == "cluster" and .source_preserved == false and .decision == "translate" and (.eligible_backend_ids | length) > 0' <<<"${cluster_simulation}" >/dev/null
jq -e '.frontend_kind == "node_port_local" and .traffic_policy == "local" and .source_preserved == true and .decision == "translate" and (.eligible_backend_ids | length) > 0' <<<"${local_simulation}" >/dev/null
jq -e '.frontend_kind == "node_port_local" and .traffic_policy == "local" and .source_preserved == true and .decision == "drop_no_backend" and (.eligible_backend_ids | length) == 0' <<<"${blocked_simulation}" >/dev/null
[[ $(controller_raw /v1/status | jq -er .compiled_service_revision) == "${simulation_revision_before}" ]]

stage=fixture-cleanup
"${kc[@]}" delete namespace "${namespace}" --wait=true --timeout=180s >/dev/null
namespace_created=false
for _ in $(seq 1 120); do
    client_count=$(attachment_count "${client_node}")
    server_count=$(attachment_count "${server_node}")
    [[ ${client_count} -eq ${client_attachment_baseline} \
        && ${server_count} -eq ${server_attachment_baseline} ]] && break
    sleep 1
done
[[ ${client_count} -eq ${client_attachment_baseline} ]]
[[ ${server_count} -eq ${server_attachment_baseline} ]]
wait_for_convergence >/dev/null
map_audit_pods_created=true
"${kc[@]}" -n unf-system delete pods -l "${map_audit_label}=true" \
    --ignore-not-found --wait=true --timeout=60s >/dev/null
map_audit_index=0
for node in "${nodes[@]}"; do
    audit_pod="unf-nodeport-map-audit-${map_audit_index}"
    "${kc[@]}" apply -f - >/dev/null <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: ${audit_pod}
  namespace: unf-system
  labels:
    ${map_audit_label}: "true"
spec:
  nodeName: ${node}
  hostNetwork: true
  restartPolicy: Never
  tolerations:
    - operator: Exists
  containers:
    - name: audit
      image: ${test_tools_image}
      imagePullPolicy: IfNotPresent
      command: [sh, -ec]
      args:
        - |
          test "\$(bpftool -j map dump pinned /sys/fs/bpf/unf/v13/NODE_PORT_FRONTENDS_V4 | jq length)" -eq 0
          test "\$(bpftool -j map dump pinned /sys/fs/bpf/unf/v13/NODE_PORT_FRONTENDS_V6 | jq length)" -eq 0
          snapshot=/var/lib/unf/cni/v1/service-snapshot.json
          jq -e '.schemaVersion == 1 and has("service") == false and (.services | all(.nodePorts | length == 0))' "\$snapshot" >/dev/null
          echo nodeport-state-empty
      securityContext:
        privileged: true
      volumeMounts:
        - name: bpffs
          mountPath: /sys/fs/bpf
          readOnly: true
        - name: state
          mountPath: /var/lib/unf
          readOnly: true
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
    if ! "${kc[@]}" -n unf-system wait --for=jsonpath='{.status.phase}'=Succeeded \
        "pod/${audit_pod}" --timeout=90s >/dev/null; then
        "${kc[@]}" -n unf-system logs "${audit_pod}" >&2 || true
        exit 1
    fi
    grep -qx nodeport-state-empty < <("${kc[@]}" -n unf-system logs "${audit_pod}")
    map_audit_index=$((map_audit_index + 1))
done
"${kc[@]}" -n unf-system delete pods -l "${map_audit_label}=true" \
    --wait=true --timeout=60s >/dev/null
map_audit_pods_created=false

stage=retire-abi-v4-pins
retired_abi4_nodes='[]'
rebuild_abi4_nodes='[]'
for node in "${nodes[@]}"; do
    pod=$(agent_pod_on_node "${node}")
    if host_exec "${node}" 'test -d /sys/fs/bpf/unf/v4' >/dev/null 2>&1; then
        plan=$("${kc[@]}" -n unf-system exec "${pod}" -- \
            /usr/local/bin/unf-component cleanup --bpf-root /sys/fs/bpf/unf --abi-version 4)
        grep -Fq 'UNF cleanup plan (dry-run)' <<<"${plan}"
        grep -Fq 'ABI directory: /sys/fs/bpf/unf/v4' <<<"${plan}"
        if grep -Fq 'legacy attachment' <<<"${plan}"; then
            echo "ABI-v4 map retirement unexpectedly included live TC attachments" >&2
            exit 1
        fi
        output=$("${kc[@]}" -n unf-system exec "${pod}" -- \
            /usr/local/bin/unf-component cleanup --bpf-root /sys/fs/bpf/unf \
            --abi-version 4 --execute)
        grep -Fq 'UNF cleanup completed' <<<"${output}"
        retired_abi4_nodes=$(jq -c --arg node "${node}" '. + [$node]' <<<"${retired_abi4_nodes}")
    else
        rebuild_abi4_nodes=$(jq -c --arg node "${node}" '. + [$node]' <<<"${rebuild_abi4_nodes}")
    fi
    host_check=$(host_exec "${node}" '
        test ! -e /sys/fs/bpf/unf/v4
        test -d /sys/fs/bpf/unf/v13
        test -e /sys/fs/bpf/unf/v13/SERVICE_CONFIG
        test -e /sys/fs/bpf/unf/v13/NODE_PORT_CONFIG
        echo abi-retired
    ' 2>&1)
    grep -q '^abi-retired$' <<<"${host_check}"
done
service_matrix_output=passed

stage=final-platform-health
[[ $("${kc[@]}" get network.operator.openshift.io cluster -o jsonpath='{.spec.deployKubeProxy}') == false ]]
final_unhealthy=$(unhealthy_operators)
[[ ${final_unhealthy} == "${baseline_unhealthy}" ]]
"${kc[@]}" wait --for=condition=Ready nodes --all --timeout=10m >/dev/null
agents=$(wait_for_convergence)

stage=evidence
mkdir -p "$(dirname "${artifact}")"
artifact_tmp="${artifact}.tmp.$$"
node_evidence=$("${kc[@]}" get nodes -o json | jq '[.items[] | {
    name:.metadata.name, operatingSystem:.status.nodeInfo.operatingSystem,
    osImage:.status.nodeInfo.osImage, kernelVersion:.status.nodeInfo.kernelVersion,
    containerRuntime:.status.nodeInfo.containerRuntimeVersion, podCIDRs:.spec.podCIDRs,
    internalIPs:[.status.addresses[] | select(.type == "InternalIP") | .address]
}]')
jq -n --arg generatedAt "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --arg context "${context}" --arg infrastructure "${infrastructure}" \
    --arg sourceRevision "${source_revision}" --arg qualificationRevision "${qualification_revision}" \
    --arg controllerImage "${controller_image}" \
    --arg agentImage "${agent_image}" --arg testToolsImage "${test_tools_image}" \
    --arg openshiftVersion "$("${kc[@]}" get clusterversion version -o jsonpath='{.status.desired.version}')" \
    --arg kubernetesVersion "$("${kc[@]}" version -o json | jq -r .serverVersion.gitVersion)" \
    --arg serviceIPv4 "${service_v4}" --arg serviceIPv6 "${service_v6}" \
    --arg clientNode "${client_node}" --arg serverNode "${server_node}" \
    --arg clientNodeIPv4 "${client_node_v4}" --arg clientNodeIPv6 "${client_node_v6}" \
    --arg serverNodeIPv4 "${server_node_v4}" --arg serverNodeIPv6 "${server_node_v6}" \
    --argjson serviceId "${service_id}" --argjson clusterServiceId "${cluster_service_id}" \
    --argjson localServiceId "${local_service_id}" \
    --argjson retiredAbi4Nodes "${retired_abi4_nodes}" \
    --argjson rebuildAbi4Nodes "${rebuild_abi4_nodes}" \
    --argjson durationSeconds "$(( $(date +%s) - started_unix ))" --argjson nodes "${node_evidence}" \
    --argjson agents "${agents}" --argjson baselineUnhealthy "${baseline_unhealthy}" \
    --argjson finalUnhealthy "${final_unhealthy}" '
    {
      schemaVersion:2, generatedAt:$generatedAt, phase:"5.8", result:"passed",
      context:$context, infrastructure:$infrastructure, sourceRevision:$sourceRevision,
      qualificationRevision:$qualificationRevision,
      openshiftVersion:$openshiftVersion, kubernetesVersion:$kubernetesVersion,
      durationSeconds:$durationSeconds,
      images:{controller:$controllerImage,agent:$agentImage,testTools:$testToolsImage},
      kubeProxyPresent:false, persistentBpfAbis:[5],
      baselineUnhealthyOperators:$baselineUnhealthy, finalUnhealthyOperators:$finalUnhealthy,
      rollbackAbi4:{retiredNodes:$retiredAbi4Nodes,rebuildRequiredNodes:$rebuildAbi4Nodes},
      service:{id:$serviceId,ipv4:$serviceIPv4,ipv6:$serviceIPv6}, nodes:$nodes, agents:$agents,
      nodePort:{clusterServiceId:$clusterServiceId,localServiceId:$localServiceId,
        clientNode:{name:$clientNode,ipv4:$clientNodeIPv4,ipv6:$clientNodeIPv6},
        serverNode:{name:$serverNode,ipv4:$serverNodeIPv4,ipv6:$serverNodeIPv6},
        clusterPorts:{tcp:30080,udp:30053,source:30081},
        localPorts:{tcp:31080,udp:31053,source:31081}},
      verified:["digest-pinned staged ABI-v4 to ABI-v5 transition","RHCOS and SELinux enforcement",
        "CRI-O primary-CNI lifecycle","kube-proxy and KUBE-SVC absence",
        "IPv4 and IPv6 TCP ClusterIP","IPv4 and IPv6 UDP ClusterIP",
        "five-node IPv4 and IPv6 TCP/UDP host-origin ClusterIP",
        "DNS continuity","IPv4 and IPv6 TCP/UDP NodePort Cluster through both workers",
        "IPv4 and IPv6 TCP/UDP NodePort Local through the backend worker",
        "Local no-backend fail-closed behavior on the non-backend worker",
        "Cluster Node source translation","Local client source preservation",
        "reverse NodePort tuple restoration","established UDP NodePort retention",
        "NodePort metrics, history, explanation, and read-only simulation",
        "readiness withdrawal","terminating endpoint exclusion",
        "backend deletion and recovery","translation and no-backend provenance",
        "service explanation","controller-outage source and destination agent replacement",
        "durable composite service recovery","empty NodePort maps and legacy checkpoint after cleanup",
        "persistent IPv4 NodePort host sysctls","exact qualification cleanup",
        "scoped retained ABI-v4 retirement and reboot-cleared ABI-v4 rebuild classification",
        "five-node convergence","no new unhealthy ClusterOperators"],
      excluded:["LoadBalancer","session affinity","topology hints","Maglev","DSR",
        "host-origin NodePort clients","SCTP","fragments","generic NAT RELATED tracking",
        "production availability and scale"]
    }
' >"${artifact_tmp}"
chmod 0600 "${artifact_tmp}"
mv -f "${artifact_tmp}" "${artifact}"
artifact_tmp=

trap - ERR EXIT
rm -rf -- "${temporary_dir}"
echo "OpenShift cl02 kube-proxy-free dual-stack NodePort qualification passed; evidence: ${artifact}"
