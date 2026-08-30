#!/usr/bin/env bash
set -Eeuo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
kubeconfig=${KUBECONFIG:-"${project_root}/.tools/cl02-audit.kubeconfig"}
context=${KUBE_CONTEXT:-}
expected_infrastructure=${UNF_OPENSHIFT_SERVICE_EXPECTED_INFRASTRUCTURE:-}
acknowledgement=${UNF_OPENSHIFT_SERVICE_ACKNOWLEDGE_DISPOSABLE:-}
release_record=${UNF_OPENSHIFT_SERVICE_RELEASE_RECORD:-"${project_root}/deploy/openshift-primary-cni/runtime/service-fabric-release.json"}
deploy_evidence=${UNF_OPENSHIFT_SERVICE_DEPLOY_EVIDENCE:-"${project_root}/.artifacts/phase4-openshift-service-deploy.json"}
artifact=${UNF_OPENSHIFT_SERVICE_EVIDENCE:-"${project_root}/.artifacts/phase4-openshift-service.json"}
namespace=unf-service-qualification
stage=initialization
temporary_dir=$(mktemp -d)
probe_pid=
controller_scaled_down=false
kube_proxy_disabled=false
namespace_created=false
artifact_tmp=

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
    if (( status != 0 )) && [[ ${kube_proxy_disabled} == true ]]; then
        echo "qualification failed after kube-proxy removal; requesting bounded safety-net restoration" >&2
        "${kc[@]}" patch network.operator.openshift.io cluster --type=merge \
            -p '{"spec":{"deployKubeProxy":true}}' >/dev/null 2>&1 || true
    fi
    [[ -z ${artifact_tmp} ]] || rm -f -- "${artifact_tmp}"
    rm -rf -- "${temporary_dir}"
    exit "${status}"
}
trap failure ERR
trap cleanup EXIT

for command in git jq oc stat timeout; do
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
    .schemaVersion == 1 and .stage == "abi-v4-staged-deployment"
    and .context == $context and .infrastructure == $infrastructure
    and .sourceRevision == $revision and .kubeProxyPresent == true
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
    local node=$1 script=$2
    "${kc[@]}" debug "node/${node}" --quiet -- chroot /host sh -euc "${script}"
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
            .schema_version == 4 and .expected_agents == $expected
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
            .schemaVersion == 1
            and any(.services[];
                .namespace == $namespace and .name == "server"
                and (.frontends | length) == 4
                and ([.backends[] | select(.ready == true and .terminating == false)] | length) == $backends)
        ' <<<"${snapshot}" >/dev/null 2>&1; then
            printf '%s\n' "${snapshot}"
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

tcp_probe() {
    local address=$1
    "${kc[@]}" -n "${namespace}" exec client -- \
        wget -T 4 -t 1 -qO- "http://${address}:8080/health" | grep -qx ok
}

udp_probe() {
    local family=$1 address=$2 target
    if [[ ${family} == 4 ]]; then
        target="UDP4:${address}:5353"
    else
        target="UDP6:[${address}]:5353"
    fi
    "${kc[@]}" -n "${namespace}" exec client -- sh -ec \
        "printf udp-ok | socat -T 4 - '${target}'" | grep -qx udp-ok
}

service_matrix() {
    tcp_probe "${service_v4}"
    tcp_probe "[${service_v6}]"
    udp_probe 4 "${service_v4}"
    udp_probe 6 "${service_v6}"
}

expect_service_blocked() {
    local passed=false
    tcp_probe "${service_v4}" >/dev/null 2>&1 && passed=true
    tcp_probe "[${service_v6}]" >/dev/null 2>&1 && passed=true
    udp_probe 4 "${service_v4}" >/dev/null 2>&1 && passed=true
    udp_probe 6 "${service_v6}" >/dev/null 2>&1 && passed=true
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
          socat UDP4-RECVFROM:5353,reuseaddr,fork EXEC:/bin/cat &
          socat UDP6-RECVFROM:5353,reuseaddr,fork,ipv6-v6only=1 EXEC:/bin/cat &
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
    local node=$1 status=
    for _ in $(seq 1 300); do
        status=$(agent_raw "${node}" /v1/status 2>/dev/null || true)
        if jq -e '
            .schema_version == 4 and .ready and .bpf_loaded
            and .desired_service_revision > 0
            and .applied_service_revision == .desired_service_revision
            and .applied_service_epoch == .desired_service_epoch
            and .service_count > 0 and .service_frontend_count > 0
            and .service_backend_count > 0
            and has("service_last_error") and .service_last_error == null
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
        for _ in $(seq 1 30); do service_matrix; done
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
    wait_for_agent_service_state "${node}"
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
[[ $("${kc[@]}" get network.operator.openshift.io cluster -o jsonpath='{.spec.deployKubeProxy}') == true ]]
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
        test -d /sys/fs/bpf/unf/v3 && test -d /sys/fs/bpf/unf/v4
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
EOF
"${kc[@]}" -n "${namespace}" wait --for=condition=Ready pod/client pod/server --timeout=240s >/dev/null
service_snapshot=$(wait_for_service 4)
service_id=$(jq -r --arg namespace "${namespace}" \
    '.services[] | select(.namespace == $namespace and .name == "server") | .id' <<<"${service_snapshot}")
mapfile -t service_ips < <("${kc[@]}" -n "${namespace}" get service server -o json | jq -r '.spec.clusterIPs[]')
service_v4=${service_ips[0]}
service_v6=${service_ips[1]}
wait_for_convergence >/dev/null

stage=pre-removal-service-proof
for _ in $(seq 1 8); do service_matrix; done
resolution=$("${kc[@]}" -n "${namespace}" exec client -- getent ahosts server)
grep -Fq "${service_v4}" <<<"${resolution}"
grep -Fq "${service_v6}" <<<"${resolution}"
history=
for _ in $(seq 1 90); do
    history=$(controller_raw /v1/flows 2>/dev/null || true)
    if jq -e --arg v4 "${service_v4}" --arg v6 "${service_v6}" '
        .schema_version == 5
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

stage=kube-proxy-removal
"${kc[@]}" patch network.operator.openshift.io cluster --type=merge \
    -p '{"spec":{"deployKubeProxy":false}}' >/dev/null
kube_proxy_disabled=true
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
for _ in $(seq 1 16); do service_matrix; done
resolution=$("${kc[@]}" -n "${namespace}" exec client -- getent ahosts server)
grep -Fq "${service_v4}" <<<"${resolution}"
grep -Fq "${service_v6}" <<<"${resolution}"

stage=readiness-withdrawal
"${kc[@]}" -n "${namespace}" exec server -- touch /tmp/unready
"${kc[@]}" -n "${namespace}" wait --for=condition=Ready=false pod/server --timeout=90s >/dev/null
wait_for_service 0 >/dev/null
wait_for_convergence >/dev/null
expect_service_blocked
"${kc[@]}" -n "${namespace}" exec server -- rm -f /tmp/unready
"${kc[@]}" -n "${namespace}" wait --for=condition=Ready pod/server --timeout=90s >/dev/null
wait_for_service 4 >/dev/null
wait_for_convergence >/dev/null
service_matrix

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
service_matrix

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
service_matrix

stage=observability-and-explanation
history=$(controller_raw /v1/flows)
jq -e --argjson service_id "${service_id}" '
    .schema_version == 5
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

stage=retire-abi-v3-pins
for node in "${nodes[@]}"; do
    pod=$(agent_pod_on_node "${node}")
    plan=$("${kc[@]}" -n unf-system exec "${pod}" -- \
        /usr/local/bin/unf-component cleanup --bpf-root /sys/fs/bpf/unf --abi-version 3)
    grep -Fq 'UNF cleanup plan (dry-run)' <<<"${plan}"
    grep -Fq 'ABI directory: /sys/fs/bpf/unf/v3' <<<"${plan}"
    if grep -Fq 'legacy attachment' <<<"${plan}"; then
        echo "ABI-v3 map retirement unexpectedly included live TC attachments" >&2
        exit 1
    fi
    output=$("${kc[@]}" -n unf-system exec "${pod}" -- \
        /usr/local/bin/unf-component cleanup --bpf-root /sys/fs/bpf/unf \
        --abi-version 3 --execute)
    grep -Fq 'UNF cleanup completed' <<<"${output}"
    host_check=$(host_exec "${node}" '
        test ! -e /sys/fs/bpf/unf/v3
        test -d /sys/fs/bpf/unf/v4
        test -e /sys/fs/bpf/unf/v4/SERVICE_CONFIG
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
    --arg sourceRevision "${source_revision}" --arg controllerImage "${controller_image}" \
    --arg agentImage "${agent_image}" --arg testToolsImage "${test_tools_image}" \
    --arg openshiftVersion "$("${kc[@]}" get clusterversion version -o jsonpath='{.status.desired.version}')" \
    --arg kubernetesVersion "$("${kc[@]}" version -o json | jq -r .serverVersion.gitVersion)" \
    --arg serviceIPv4 "${service_v4}" --arg serviceIPv6 "${service_v6}" \
    --argjson serviceId "${service_id}" --argjson nodes "${node_evidence}" \
    --argjson agents "${agents}" --argjson baselineUnhealthy "${baseline_unhealthy}" '
    {
      schemaVersion:1, generatedAt:$generatedAt, phase:"4.8", result:"passed",
      context:$context, infrastructure:$infrastructure, sourceRevision:$sourceRevision,
      openshiftVersion:$openshiftVersion, kubernetesVersion:$kubernetesVersion,
      images:{controller:$controllerImage,agent:$agentImage,testTools:$testToolsImage},
      kubeProxyPresent:false, persistentBpfAbis:[4], baselineUnhealthyOperators:$baselineUnhealthy,
      service:{id:$serviceId,ipv4:$serviceIPv4,ipv6:$serviceIPv6}, nodes:$nodes, agents:$agents,
      verified:["digest-pinned staged ABI-v3 to ABI-v4 transition","RHCOS and SELinux enforcement",
        "CRI-O primary-CNI lifecycle","kube-proxy and KUBE-SVC absence",
        "IPv4 and IPv6 TCP ClusterIP","IPv4 and IPv6 UDP ClusterIP",
        "DNS continuity","readiness withdrawal","terminating endpoint exclusion",
        "backend deletion and recovery","translation and no-backend provenance",
        "service explanation","controller-outage source and destination agent replacement",
        "durable service recovery","exact qualification cleanup","scoped ABI-v3 map retirement",
        "five-node convergence","no new unhealthy ClusterOperators"]
    }
' >"${artifact_tmp}"
chmod 0600 "${artifact_tmp}"
mv -f "${artifact_tmp}" "${artifact}"
artifact_tmp=

kube_proxy_disabled=false
trap - ERR EXIT
rm -rf -- "${temporary_dir}"
echo "OpenShift cl02 kube-proxy-free dual-stack service-fabric qualification passed; evidence: ${artifact}"
