#!/usr/bin/env bash
set -Eeuo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
kubeconfig=${KUBECONFIG:-"${project_root}/.tools/cl02-audit.kubeconfig"}
context=${KUBE_CONTEXT:-}
expected_infrastructure=${UNF_OPENSHIFT_LOADBALANCER_EXPECTED_INFRASTRUCTURE:-}
acknowledgement=${UNF_OPENSHIFT_LOADBALANCER_ACKNOWLEDGE_DISPOSABLE:-}
release_record=${UNF_OPENSHIFT_LOADBALANCER_RELEASE_RECORD:-"${project_root}/deploy/openshift-primary-cni/loadbalancer/release.json"}
deploy_evidence=${UNF_OPENSHIFT_LOADBALANCER_DEPLOY_EVIDENCE:-"${project_root}/.artifacts/phase6-loadbalancer-openshift-deploy.json"}
artifact=${UNF_OPENSHIFT_LOADBALANCER_EVIDENCE:-"${project_root}/.artifacts/phase6-loadbalancer-openshift.json"}
unfctl=${UNFCTL:-"${project_root}/target/debug/unfctl"}
controller_port=${UNF_OPENSHIFT_LOADBALANCER_CONTROLLER_PORT:-29967}
namespace=unf-loadbalancer-qualification
advertiser_label=qualification.unf.io/loadbalancer-advertiser
stage=initialization
started_unix=$(date +%s)
temporary_dir=$(mktemp -d)
controller_scaled_down=false
namespace_created=false
advertisers_created=false
forward_pid=
probe_pid=
artifact_tmp=

failure() {
    local status=$?
    echo "OpenShift LoadBalancer qualification failed during ${stage} at line ${BASH_LINENO[0]}: ${BASH_COMMAND}" >&2
    return "${status}"
}

cleanup() {
    local status=$?
    trap - ERR EXIT
    set +e
    [[ -z ${probe_pid} ]] || { kill "${probe_pid}" >/dev/null 2>&1 || true; wait "${probe_pid}" >/dev/null 2>&1 || true; }
    [[ -z ${forward_pid} ]] || { kill "${forward_pid}" >/dev/null 2>&1 || true; wait "${forward_pid}" >/dev/null 2>&1 || true; }
    if [[ ${controller_scaled_down} == true ]]; then
        "${kc[@]}" -n unf-system scale deployment/unf-controller --replicas=1 >/dev/null 2>&1 || true
    fi
    if [[ ${advertisers_created} == true ]]; then
        for pod in $("${kc[@]}" -n unf-system get pods -l "${advertiser_label}=true" -o name 2>/dev/null); do
            "${kc[@]}" -n unf-system exec "${pod}" -- sh -euc '
                for address in "$@"; do
                    ip address del "$address" dev br-ex >/dev/null 2>&1 || true
                done
            ' sh \
                "${cluster_v4:-}/32" "${cluster_v6:-}/128" \
                "${local_v4:-}/32" "${local_v6:-}/128" \
                "${peer_cluster_v4:-}/32" "${peer_cluster_v6:-}/128" \
                "${peer_local_v4:-}/32" "${peer_local_v6:-}/128" >/dev/null 2>&1 || true
        done
        "${kc[@]}" -n unf-system delete pods -l "${advertiser_label}=true" \
            --ignore-not-found --wait=false >/dev/null 2>&1 || true
    fi
    if [[ ${namespace_created} == true ]]; then
        "${kc[@]}" delete namespace "${namespace}" --ignore-not-found --wait=false >/dev/null 2>&1 || true
    fi
    [[ -z ${artifact_tmp} ]] || rm -f -- "${artifact_tmp}"
    rm -rf -- "${temporary_dir}"
    exit "${status}"
}
trap failure ERR
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

for command in curl git ip jq oc sed socat stat timeout; do
    command -v "${command}" >/dev/null || {
        echo "OpenShift LoadBalancer qualification prerequisite is missing: ${command}" >&2
        exit 1
    }
done
if [[ ! -s ${kubeconfig} || $(stat -c '%a' "${kubeconfig}") != 600 ]]; then
    echo "qualification requires a non-empty mode-0600 kubeconfig: ${kubeconfig}" >&2
    exit 1
fi
if [[ -n $(git -C "${project_root}" status --porcelain) ]]; then
    echo "qualification requires a clean committed worktree" >&2
    exit 1
fi
if [[ ! -s ${release_record} || ! -s ${deploy_evidence} ]] || ! jq -e '
    .schemaVersion == 1 and .phase == "6.9"
    and (.sourceRevision | test("^[0-9a-f]{40}$"))
    and .kindQualification.phase == "6.8" and .kindQualification.result == "passed"
    and .contracts.persistentBpfStateAbiVersion == 7
    and .contracts.serviceSnapshotSchemaVersion == 3
    and .contracts.agentStatusSchemaVersion == 6
    and all(.images[]; test("^quay\\.io/arencloud/unf-[a-z-]+-dev@sha256:[0-9a-f]{64}$"))
' "${release_record}" >/dev/null; then
    echo "Phase 6.9 release record or staged evidence is missing or invalid" >&2
    exit 1
fi

source_revision=$(jq -er .sourceRevision "${release_record}")
controller_image=$(jq -er .images.controller "${release_record}")
agent_image=$(jq -er .images.agent "${release_record}")
test_tools_image=$(jq -er .images.testTools "${release_record}")
qualification_revision=$(git -C "${project_root}" rev-parse HEAD)
git -C "${project_root}" merge-base --is-ancestor "${source_revision}" HEAD

if [[ -z ${context} ]]; then context=$(oc --kubeconfig "${kubeconfig}" config current-context); fi
kc=(oc --kubeconfig "${kubeconfig}" --context "${context}")
infrastructure=$("${kc[@]}" get infrastructure cluster -o jsonpath='{.status.infrastructureName}')
if [[ -z ${expected_infrastructure} || ${expected_infrastructure} != "${infrastructure}" \
    || ${acknowledgement} != "${infrastructure}" ]]; then
    echo "refusing qualification: both LoadBalancer infrastructure acknowledgements must equal ${infrastructure}" >&2
    exit 1
fi
jq -e --arg context "${context}" --arg infrastructure "${infrastructure}" \
    --arg revision "${source_revision}" '
    .schemaVersion == 1 and .phase == "6.9"
    and .stage == "abi-v7-loadbalancer-staged-deployment"
    and .context == $context and .infrastructure == $infrastructure
    and .sourceRevision == $revision and .kubeProxyPresent == false
    and .persistentBpfAbi == 7 and .serviceSnapshotSchemaVersion == 3
    and .agentStatusSchemaVersion == 6 and .agents.all_converged == true
' "${deploy_evidence}" >/dev/null

controller_pod() {
    "${kc[@]}" -n unf-system get pods -l app.kubernetes.io/name=unf-controller -o json \
        | jq -r '.items[] | select(.metadata.deletionTimestamp == null and .status.phase == "Running") | .metadata.name' \
        | head -n 1
}

controller_raw() {
    local pod path=$1
    pod=$(controller_pod)
    [[ -n ${pod} ]]
    timeout 20 "${kc[@]}" get --raw "/api/v1/namespaces/unf-system/pods/${pod}:9962/proxy${path}"
}

agent_pod_on_node() {
    local node=$1
    "${kc[@]}" -n unf-system get pods -l app.kubernetes.io/name=unf-agent -o json \
        | jq -r --arg node "${node}" '.items[] | select(.spec.nodeName == $node and .metadata.deletionTimestamp == null) | .metadata.name' \
        | head -n 1
}

agent_raw() {
    local node=$1 path=$2 pod
    pod=$(agent_pod_on_node "${node}")
    [[ -n ${pod} ]]
    timeout 20 "${kc[@]}" get --raw "/api/v1/namespaces/unf-system/pods/${pod}:9963/proxy${path}"
}

node_address() {
    local node=$1 family=$2
    "${kc[@]}" get node "${node}" -o json | jq -er --arg family "${family}" '
        [.status.addresses[] | select(.type == "InternalIP") | .address
         | select(if $family == "4" then contains(".") else contains(":") end)][0]'
}

wait_for_convergence() {
    local snapshot=
    for _ in $(seq 1 900); do
        snapshot=$(controller_raw /v1/state/agents 2>/dev/null || true)
        if jq -e --argjson expected "${#nodes[@]}" '
            .schema_version == 6 and .expected_agents == $expected
            and .reporting_agents == $expected and .missing_agents == 0
            and .stale_agents == 0 and .converged_agents == $expected
            and .unexpected_agents == 0 and .all_converged == true
            and all(.nodes[]; .fresh and .converged and .report.ready and .report.bpf_loaded
                and .report.service_snapshot_schema_version == 3
                and .report.load_balancer_last_error == null)
        ' <<<"${snapshot}" >/dev/null 2>&1; then
            printf '%s\n' "${snapshot}"
            return 0
        fi
        sleep 1
    done
    echo "five OpenShift LoadBalancer agents did not converge" >&2
    jq . <<<"${snapshot}" >&2 || true
    return 1
}

wait_for_load_balancer_shape() {
    local frontends=$1 cluster=$2 local_count=$3 snapshot=
    for _ in $(seq 1 900); do
        snapshot=$(controller_raw /v1/state/agents 2>/dev/null || true)
        if jq -e --argjson expected "${#nodes[@]}" --argjson frontends "${frontends}" \
            --argjson cluster "${cluster}" --argjson local_count "${local_count}" '
            .schema_version == 6 and .expected_agents == $expected
            and .converged_agents == $expected and .all_converged == true
            and all(.nodes[]; .fresh and .converged
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
    echo "OpenShift LoadBalancer shape did not converge to ${frontends}/${cluster}/${local_count}" >&2
    jq . <<<"${snapshot}" >&2 || true
    return 1
}

load_balancer_state() {
    "${kc[@]}" -n unf-system get configmap unf-load-balancer-control-plane -o json \
        | jq -er '.data["state.json"] | fromjson'
}

stable_allocation_projection() {
    jq -Sc '{pools:.allocation.pools,leases:[.allocation.leases[] | {owner,pool,poolUid,provider,families,requestedIps,addresses}]}'
}

wait_for_leases() {
    local state=
    for _ in $(seq 1 900); do
        state=$(load_balancer_state 2>/dev/null || true)
        if jq -e '
            .schemaVersion == 1 and .allocation.schemaVersion == 2
            and (.allocation.leases | length) == 4
            and all(.allocation.leases[];
                .pool == "qualification" and .poolUid == "openshift-loadbalancer-pool-v1"
                and .provider.name == "direct-node"
                and .provider.instance == "openshift-direct-node-v1"
                and .provider.mode == "directNode" and (.addresses | length) == 2)
        ' <<<"${state}" >/dev/null 2>&1; then
            printf '%s\n' "${state}"
            return 0
        fi
        sleep 1
    done
    echo "durable OpenShift dual-stack LoadBalancer leases did not converge" >&2
    jq . <<<"${state}" >&2 || true
    return 1
}

lease_address() {
    local state=$1 service=$2 family=$3
    jq -er --arg service "${service}" --arg family "${family}" '
        [.allocation.leases[] | select(.owner.name == $service) | .addresses[]
         | select(if $family == "4" then contains(".") else contains(":") end)][0]' <<<"${state}"
}

lease_service_id() {
    jq -er --arg service "$2" '[.allocation.leases[] | select(.owner.name == $service)][0].owner.serviceId' <<<"$1"
}

advertiser_pod_on_node() {
    local node=$1
    "${kc[@]}" -n unf-system get pods -l "${advertiser_label}=true" -o json \
        | jq -r --arg node "${node}" '.items[] | select(.spec.nodeName == $node) | .metadata.name' | head -1
}

withdraw_vips() {
    local pod
    [[ ${advertisers_created} == true ]] || return 0
    while read -r pod; do
        [[ -n ${pod} ]] || continue
        "${kc[@]}" -n unf-system exec "${pod}" -- sh -euc '
            for address in "$@"; do ip address del "$address" dev br-ex >/dev/null 2>&1 || true; done
        ' sh "${cluster_v4}/32" "${cluster_v6}/128" "${local_v4}/32" "${local_v6}/128" \
            "${peer_cluster_v4}/32" "${peer_cluster_v6}/128" \
            "${peer_local_v4}/32" "${peer_local_v6}/128" >/dev/null
    done < <("${kc[@]}" -n unf-system get pods -l "${advertiser_label}=true" -o name)
}

advertise_vips() {
    local node=$1 first_v4=$2 first_v6=$3 second_v4=$4 second_v6=$5 pod
    pod=$(advertiser_pod_on_node "${node}")
    [[ -n ${pod} ]]
    "${kc[@]}" -n unf-system exec "${pod}" -- sh -euc '
        ip -4 address add "$1/32" dev br-ex
        ip -6 address add "$2/128" dev br-ex
        ip -4 address add "$3/32" dev br-ex
        ip -6 address add "$4/128" dev br-ex
        for address in "$2" "$4"; do
            for _ in $(seq 1 20); do
                ! ip -6 -o address show dev br-ex to "$address/128" | grep -q tentative && break
                sleep 1
            done
            ! ip -6 -o address show dev br-ex to "$address/128" | grep -q tentative
        done
        # Some routed lab gateways learn only from unsolicited ARP replies;
        # send both update forms so a VIP moved by a previous failed run cannot
        # remain pinned to the old worker while this gate exercises the new one.
        chroot /host arping -U -c 3 -I br-ex "$1" >/dev/null
        chroot /host arping -A -c 3 -I br-ex "$1" >/dev/null
        chroot /host arping -U -c 3 -I br-ex "$3" >/dev/null
        chroot /host arping -A -c 3 -I br-ex "$3" >/dev/null
    ' sh "${first_v4}" "${first_v6}" "${second_v4}" "${second_v6}"
}

external_tcp_probe() {
    local family=$1 address=$2 port=${3:-8080} target
    if [[ ${family} == 4 ]]; then target="http://${address}:${port}/health"; else target="http://[${address}]:${port}/health"; fi
    curl "-${family}" --fail --silent --connect-timeout 5 --max-time 10 "${target}" | grep -qx ok
}

wait_for_external_tcp() {
    local family=$1 address=$2
    for _ in $(seq 1 30); do
        if external_tcp_probe "${family}" "${address}" >/dev/null 2>&1; then return 0; fi
        sleep 1
    done
    echo "external IPv${family} VIP ${address} did not become reachable after advertisement" >&2
    return 1
}

external_udp_probe() {
    local family=$1 address=$2 target
    if [[ ${family} == 4 ]]; then target="UDP4:${address}:5353"; else target="UDP6:[${address}]:5353"; fi
    printf lb-udp | socat -T 5 - "${target}" | grep -qx lb-udp
}

wait_for_external_udp() {
    local family=$1 address=$2
    for _ in $(seq 1 30); do
        if external_udp_probe "${family}" "${address}" >/dev/null 2>&1; then return 0; fi
        sleep 1
    done
    echo "external IPv${family} UDP VIP ${address} did not become reachable after advertisement" >&2
    return 1
}

probe_external_udp_bounded() {
    local family=$1 address=$2
    for _ in 1 2 3; do
        if external_udp_probe "${family}" "${address}"; then return 0; fi
        sleep 0.2
    done
    echo "external IPv${family} UDP VIP ${address} lost three consecutive recovery probes" >&2
    return 1
}

external_source_probe() {
    local family=$1 address=$2 target observed
    if [[ ${family} == 4 ]]; then target="TCP4:${address}:8081"; else target="TCP6:[${address}]:8081"; fi
    observed=$(printf probe | socat -T 5 - "${target}" | tr -d '\r\n')
    observed=${observed#\[}; observed=${observed%\]}
    if [[ ${family} == 6 ]]; then
        ip -6 route get "${observed}" | awk 'NR == 1 {print ($1 == "local" ? $2 : $1)}'
    else
        printf '%s\n' "${observed}"
    fi
}

assert_external_source() {
    local family=$1 address=$2 expected=$3 description=$4 observed
    observed=$(external_source_probe "${family}" "${address}")
    if [[ ${observed} != "${expected}" ]]; then
        echo "${description} IPv${family} source mismatch: expected ${expected}, observed ${observed}" >&2
        return 1
    fi
}

expect_external_blocked() {
    local address_v4=$1 address_v6=$2 succeeded=false
    external_tcp_probe 4 "${address_v4}" >/dev/null 2>&1 && succeeded=true
    external_tcp_probe 6 "${address_v6}" >/dev/null 2>&1 && succeeded=true
    external_udp_probe 4 "${address_v4}" >/dev/null 2>&1 && succeeded=true
    external_udp_probe 6 "${address_v6}" >/dev/null 2>&1 && succeeded=true
    [[ ${succeeded} == false ]]
}

health_status() {
    local family=$1 address=$2 port=${3:-32080} target
    if [[ ${family} == 4 ]]; then target="http://${address}:${port}/healthz"; else target="http://[${address}]:${port}/healthz"; fi
    curl "-${family}" --silent --output /dev/null --connect-timeout 5 --max-time 10 --write-out '%{http_code}' "${target}" || true
}

unhealthy_operators() {
    "${kc[@]}" get clusteroperators -o json | jq -c '[.items[]
        | select(any(.status.conditions[];
            (.type == "Available" and .status != "True")
            or (.type == "Degraded" and .status == "True")))
        | .metadata.name] | sort'
}

stage=platform-preflight
network=$("${kc[@]}" get network.config.openshift.io cluster -o json)
operator_network=$("${kc[@]}" get network.operator.openshift.io cluster -o json)
jq -e '.spec.networkType == "None"
    and ([.spec.clusterNetwork[].cidr | contains(":")] | any)
    and ([.spec.clusterNetwork[].cidr | contains(":") | not] | any)
    and ([.spec.serviceNetwork[] | contains(":")] | any)
    and ([.spec.serviceNetwork[] | contains(":") | not] | any)' <<<"${network}" >/dev/null
jq -e '.spec.defaultNetwork.type == "None" and .spec.deployKubeProxy == false' <<<"${operator_network}" >/dev/null
mapfile -t nodes < <("${kc[@]}" get nodes -l network.unf.io/primary-cni=enabled -o name | sed 's|node/||' | sort)
mapfile -t workers < <("${kc[@]}" get nodes -l 'node-role.kubernetes.io/worker,!node-role.kubernetes.io/master' -o name | sed 's|node/||' | sort)
[[ ${#nodes[@]} -eq 5 && ${#workers[@]} -eq 2 ]]
client_node=${workers[0]}; server_node=${workers[1]}
client_node_v4=$(node_address "${client_node}" 4); client_node_v6=$(node_address "${client_node}" 6)
server_node_v4=$(node_address "${server_node}" 4); server_node_v6=$(node_address "${server_node}" 6)
allowed_v4=$(ip -4 route get "${server_node_v4}" | awk '{for(i=1;i<=NF;i++) if($i=="src") {print $(i+1); exit}}')
allowed_v6=$(ip -6 route get "${server_node_v6}" | awk '{for(i=1;i<=NF;i++) if($i=="src") {print $(i+1); exit}}')
[[ -n ${allowed_v4} && -n ${allowed_v6} ]]
denied_v4=192.0.2.1; denied_v6=2001:db8::1
baseline_unhealthy=$(unhealthy_operators)
[[ $("${kc[@]}" -n openshift-kube-proxy get daemonsets -o json | jq '.items | length') -eq 0 ]]
"${kc[@]}" wait --for=condition=Ready nodes --all --timeout=10m >/dev/null
wait_for_convergence >/dev/null
for node in "${nodes[@]}"; do
    pod=$(agent_pod_on_node "${node}")
    [[ $("${kc[@]}" -n unf-system get pod "${pod}" -o jsonpath='{.spec.containers[0].image}') == "${agent_image}" ]]
done
[[ $("${kc[@]}" -n unf-system get deploy/unf-controller -o jsonpath='{.spec.template.spec.containers[0].image}') == "${controller_image}" ]]

stage=fixture-creation
"${kc[@]}" delete namespace "${namespace}" --ignore-not-found --wait=true --timeout=300s >/dev/null
"${kc[@]}" create namespace "${namespace}" >/dev/null
namespace_created=true
source_ranges="    - ${allowed_v4}/32"$'\n'"    - ${allowed_v6}/128"
for node in "${nodes[@]}"; do
    source_ranges+=$'\n'"    - $(node_address "${node}" 4)/32"
    source_ranges+=$'\n'"    - $(node_address "${node}" 6)/128"
done
create_qualification_service() {
    local name=$1 policy=$2 health_port=$3 include_source_ranges=$4
    local health_line= source_range_block=
    if [[ ${health_port} != 0 ]]; then
        health_line="  healthCheckNodePort: ${health_port}"
    fi
    if [[ ${include_source_ranges} == true ]]; then
        source_range_block="  loadBalancerSourceRanges:"$'\n'"${source_ranges}"
    fi
    "${kc[@]}" apply -f - >/dev/null <<EOF
apiVersion: v1
kind: Service
metadata: {name: ${name}, namespace: ${namespace}}
spec:
  type: LoadBalancer
  loadBalancerClass: network.unf.io/load-balancer
  allocateLoadBalancerNodePorts: false
  externalTrafficPolicy: ${policy}
${health_line}
  ipFamilyPolicy: RequireDualStack
  ipFamilies: [IPv4, IPv6]
${source_range_block}
  selector: {app: loadbalancer-server}
  ports:
    - {name: http, protocol: TCP, port: 8080, targetPort: 8080}
    - {name: echo, protocol: UDP, port: 5353, targetPort: 5353}
    - {name: source, protocol: TCP, port: 8081, targetPort: 8081}
EOF
}
"${kc[@]}" apply -f - >/dev/null <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: server
  namespace: ${namespace}
  labels: {app: loadbalancer-server}
spec:
  nodeSelector: {kubernetes.io/hostname: ${server_node}}
  terminationGracePeriodSeconds: 20
  securityContext: {runAsNonRoot: true, seccompProfile: {type: RuntimeDefault}}
  containers:
    - name: server
      image: ${test_tools_image}
      imagePullPolicy: IfNotPresent
      securityContext: {allowPrivilegeEscalation: false, capabilities: {drop: [ALL]}}
      command: [sh, -ec]
      args:
        - |
          /usr/local/bin/unf-udp-echo 4 5353 &
          /usr/local/bin/unf-udp-echo 6 5353 &
          socat TCP4-LISTEN:8081,reuseaddr,fork 'SYSTEM:echo \$SOCAT_PEERADDR' &
          socat TCP6-LISTEN:8081,reuseaddr,fork,ipv6-v6only=1 'SYSTEM:echo \$SOCAT_PEERADDR' &
          exec /usr/local/bin/unf-flow-receiver 8080
      readinessProbe:
        exec: {command: [sh, -ec, "test ! -e /tmp/unready && wget -T 1 -qO- http://127.0.0.1:8080/health | grep -qx ok"]}
        periodSeconds: 1
        failureThreshold: 1
EOF
"${kc[@]}" -n "${namespace}" wait --for=condition=Ready pod/server --timeout=180s >/dev/null
# Make allocation order explicit. Kubernetes watch delivery for one multi-object
# apply is not ordered, while this routed qualification requires each stable VIP
# to retain the same advertising Node across retries and failed-run cleanup.
expected_leases=0
for service in server-cluster server-local peer-cluster peer-local; do
    case ${service} in
        server-cluster) create_qualification_service "${service}" Cluster 0 false ;;
        server-local) create_qualification_service "${service}" Local 32080 true ;;
        peer-cluster) create_qualification_service "${service}" Cluster 0 false ;;
        peer-local) create_qualification_service "${service}" Local 32081 true ;;
    esac
    expected_leases=$((expected_leases + 1))
    for _ in $(seq 1 900); do
        allocation=$(load_balancer_state 2>/dev/null || true)
        if jq -e --arg namespace "${namespace}" --arg service "${service}" \
            --argjson expected "${expected_leases}" '
            ([.allocation.leases[] | select(.owner.namespace == $namespace)] | length) == $expected
            and any(.allocation.leases[];
                .owner.namespace == $namespace and .owner.name == $service)
        ' <<<"${allocation}" >/dev/null 2>&1; then
            break
        fi
        sleep 1
    done
    jq -e --arg namespace "${namespace}" --arg service "${service}" \
        --argjson expected "${expected_leases}" '
        ([.allocation.leases[] | select(.owner.namespace == $namespace)] | length) == $expected
        and any(.allocation.leases[];
            .owner.namespace == $namespace and .owner.name == $service)
    ' <<<"${allocation}" >/dev/null
done
lease_state=$(wait_for_leases)
cluster_v4=$(lease_address "${lease_state}" server-cluster 4); cluster_v6=$(lease_address "${lease_state}" server-cluster 6)
local_v4=$(lease_address "${lease_state}" server-local 4); local_v6=$(lease_address "${lease_state}" server-local 6)
peer_cluster_v4=$(lease_address "${lease_state}" peer-cluster 4); peer_cluster_v6=$(lease_address "${lease_state}" peer-cluster 6)
peer_local_v4=$(lease_address "${lease_state}" peer-local 4); peer_local_v6=$(lease_address "${lease_state}" peer-local 6)
cluster_service_id=$(lease_service_id "${lease_state}" server-cluster)
local_service_id=$(lease_service_id "${lease_state}" server-local)
peer_cluster_service_id=$(lease_service_id "${lease_state}" peer-cluster)
peer_local_service_id=$(lease_service_id "${lease_state}" peer-local)
for address in "${cluster_v4}" "${local_v4}" "${peer_cluster_v4}" "${peer_local_v4}"; do
    [[ ${address} == 10.50.60.24[1-9] || ${address} == 10.50.60.25[0-4] ]]
done
for address in "${cluster_v6}" "${local_v6}" "${peer_cluster_v6}" "${peer_local_v6}"; do
    [[ ${address} == 2a02:abcd:1234:5600::f* ]]
done
active_agents=$(wait_for_load_balancer_shape 24 12 12)
active_service_revision=$(controller_raw /v1/status | jq -er .compiled_service_revision)
for service in server-cluster server-local peer-cluster peer-local; do
    "${kc[@]}" -n "${namespace}" get service "${service}" -o json | jq -e '
        .spec.allocateLoadBalancerNodePorts == false and all(.spec.ports[]; (.nodePort // 0) == 0)
        and ((.status.loadBalancer.ingress // []) | length) == 0
        and (.metadata.finalizers | index("network.unf.io/load-balancer-protection")) != null' >/dev/null
done

stage=advertiser-creation
for node in "${nodes[@]}"; do
    index=${node##*-}
    "${kc[@]}" -n unf-system apply -f - >/dev/null <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: unf-loadbalancer-advertiser-${index}
  labels: {${advertiser_label}: "true"}
spec:
  nodeName: ${node}
  hostNetwork: true
  restartPolicy: Never
  tolerations: [{operator: Exists}]
  containers:
    - name: advertiser
      image: ${test_tools_image}
      imagePullPolicy: IfNotPresent
      command: [sh, -ec, "sleep infinity"]
      securityContext: {privileged: true}
      volumeMounts:
        - {name: bpffs, mountPath: /sys/fs/bpf}
        - {name: state, mountPath: /var/lib/unf}
        - {name: host, mountPath: /host, readOnly: true}
  volumes:
    - name: bpffs
      hostPath: {path: /sys/fs/bpf, type: Directory}
    - name: state
      hostPath: {path: /var/lib/unf, type: Directory}
    - name: host
      hostPath: {path: /, type: Directory}
EOF
done
advertisers_created=true
"${kc[@]}" -n unf-system wait --for=condition=Ready pod -l "${advertiser_label}=true" --timeout=180s >/dev/null
for worker in "${workers[@]}"; do
    pod=$(advertiser_pod_on_node "${worker}")
    "${kc[@]}" -n unf-system exec "${pod}" -- sh -euc '
        for address in "$@"; do ! ip -o address show dev br-ex | grep -F "$address"; done
    ' sh "${cluster_v4}/32" "${cluster_v6}/128" "${local_v4}/32" "${local_v6}/128" \
        "${peer_cluster_v4}/32" "${peer_cluster_v6}/128" "${peer_local_v4}/32" "${peer_local_v6}/128"
done

stage=external-cluster-and-local-traffic
advertise_vips "${server_node}" "${cluster_v4}" "${cluster_v6}" "${local_v4}" "${local_v6}"
advertise_vips "${client_node}" "${peer_cluster_v4}" "${peer_cluster_v6}" "${peer_local_v4}" "${peer_local_v6}"
for family_and_address in \
    "4 ${cluster_v4}" "6 ${cluster_v6}" \
    "4 ${peer_cluster_v4}" "6 ${peer_cluster_v6}"; do
    read -r family address <<<"${family_and_address}"
    wait_for_external_tcp "${family}" "${address}"
    wait_for_external_udp "${family}" "${address}"
done
wait_for_external_tcp 4 "${local_v4}"
wait_for_external_tcp 6 "${local_v6}"
wait_for_external_udp 4 "${local_v4}"
wait_for_external_udp 6 "${local_v6}"
assert_external_source 4 "${cluster_v4}" "${server_node_v4}" Cluster
assert_external_source 6 "${cluster_v6}" "${server_node_v6}" Cluster
assert_external_source 4 "${peer_cluster_v4}" "${client_node_v4}" peer-Cluster
assert_external_source 6 "${peer_cluster_v6}" "${client_node_v6}" peer-Cluster
assert_external_source 4 "${local_v4}" "${allowed_v4}" Local
assert_external_source 6 "${local_v6}" "${allowed_v6}" Local
[[ $(health_status 4 "${server_node_v4}") == 200 ]]
[[ $(health_status 6 "${server_node_v6}") == 200 ]]
[[ $(health_status 4 "${client_node_v4}") == 503 ]]
[[ $(health_status 6 "${client_node_v6}") == 503 ]]
[[ $(health_status 4 "${server_node_v4}" 32081) == 200 ]]
[[ $(health_status 6 "${server_node_v6}" 32081) == 200 ]]
[[ $(health_status 4 "${client_node_v4}" 32081) == 503 ]]
[[ $(health_status 6 "${client_node_v6}" 32081) == 503 ]]
expect_external_blocked "${peer_local_v4}" "${peer_local_v6}"

stage=source-range-denial-and-recovery
"${kc[@]}" -n "${namespace}" patch service server-local --type=merge -p \
    '{"spec":{"loadBalancerSourceRanges":["192.0.2.1/32","2001:db8::1/128"]}}' >/dev/null
wait_for_convergence >/dev/null
expect_external_blocked "${local_v4}" "${local_v6}"
"${kc[@]}" -n "${namespace}" patch service server-local --type=merge -p \
    "{\"spec\":{\"loadBalancerSourceRanges\":[\"${allowed_v4}/32\",\"${allowed_v6}/128\"]}}" >/dev/null
wait_for_convergence >/dev/null
wait_for_external_tcp 4 "${local_v4}"
wait_for_external_tcp 6 "${local_v6}"

stage=operations-and-simulation
history=
for _ in $(seq 1 300); do
    history=$(controller_raw /v1/flows 2>/dev/null || true)
    if jq -e --arg cluster "${cluster_v4}" --arg local "${local_v4}" '
        .schema_version == 6
        and any(.entries[]; .key.destination_ipv4 == $cluster and .service.frontend_kind == "load_balancer_cluster" and .service.action == 1)
        and any(.entries[]; .key.destination_ipv4 == $local and .service.frontend_kind == "load_balancer_local" and .service.action == 1)
        and any(.entries[]; .key.destination_ipv4 == $local and .service.frontend_kind == "load_balancer_local" and .service.action == 2)
    ' <<<"${history}" >/dev/null 2>&1; then break; fi
    sleep 1
done
jq -e 'any(.entries[]; .service.frontend_kind == "load_balancer_cluster")
    and any(.entries[]; .service.frontend_kind == "load_balancer_local")' <<<"${history}" >/dev/null
for node in "${nodes[@]}"; do
    metrics=$(agent_raw "${node}" /metrics)
    grep -Eq '^unf_loadbalancer_frontend_count 24(\.0)?$' <<<"${metrics}"
    grep -q '^unf_loadbalancer_cluster_translations_total' <<<"${metrics}"
    grep -q '^unf_loadbalancer_local_translations_total' <<<"${metrics}"
    grep -q '^unf_loadbalancer_source_range_drops_total' <<<"${metrics}"
done
cpod=$(controller_pod)
"${kc[@]}" -n unf-system port-forward "pod/${cpod}" "${controller_port}:9962" >"${temporary_dir}/port-forward.log" 2>&1 &
forward_pid=$!
for _ in $(seq 1 60); do
    "${unfctl}" --controller-url "http://127.0.0.1:${controller_port}" --output json status >/dev/null 2>&1 && break
    sleep 1
done
kill -0 "${forward_pid}"
cluster_explanation=$("${unfctl}" --controller-url "http://127.0.0.1:${controller_port}" --output json \
    service-explain --service-id "${cluster_service_id}" --frontend-kind load-balancer-cluster --last 30m --limit 100)
local_explanation=$("${unfctl}" --controller-url "http://127.0.0.1:${controller_port}" --output json \
    service-explain --service-id "${local_service_id}" --frontend-kind load-balancer-local --last 30m --limit 100)
jq -e '.current_service.name == "server-cluster"
    and .load_balancer.provider.instance == "openshift-direct-node-v1"
    and (.load_balancer.reachable_nodes | length) == 5 and any(.outcomes[]; .service.action == 1)' <<<"${cluster_explanation}" >/dev/null
jq -e '.current_service.name == "server-local" and .load_balancer.allocation.poolUid == "openshift-loadbalancer-pool-v1"
    and any(.outcomes[]; .service.action == 1) and any(.outcomes[]; .service.action == 2)' <<<"${local_explanation}" >/dev/null
simulation_revision=$(controller_raw /v1/status | jq -er .compiled_service_revision)
cluster_simulation=$("${unfctl}" --controller-url "http://127.0.0.1:${controller_port}" --output json \
    load-balancer-simulate --node "${client_node}" --address "${cluster_v4}" --source-address "${allowed_v4}" --port 8080 --protocol tcp)
local_simulation=$("${unfctl}" --controller-url "http://127.0.0.1:${controller_port}" --output json \
    load-balancer-simulate --node "${server_node}" --address "${local_v6}" --source-address "${allowed_v6}" --port 8080 --protocol tcp)
denied_simulation=$("${unfctl}" --controller-url "http://127.0.0.1:${controller_port}" --output json \
    load-balancer-simulate --node "${server_node}" --address "${local_v4}" --source-address "${denied_v4}" --port 8080 --protocol tcp)
jq -e '.decision == "translate" and .source_preserved == false' <<<"${cluster_simulation}" >/dev/null
jq -e '.decision == "translate" and .source_preserved == true and .source_allowed == true' <<<"${local_simulation}" >/dev/null
jq -e '.decision == "drop_source_range" and .source_allowed == false' <<<"${denied_simulation}" >/dev/null
[[ $(controller_raw /v1/status | jq -er .compiled_service_revision) == "${simulation_revision}" ]]

stage=readiness-health-and-recovery
"${kc[@]}" -n "${namespace}" exec server -- touch /tmp/unready
"${kc[@]}" -n "${namespace}" wait --for=condition=Ready=false pod/server --timeout=90s >/dev/null
wait_for_convergence >/dev/null
expect_external_blocked "${cluster_v4}" "${cluster_v6}"
expect_external_blocked "${local_v4}" "${local_v6}"
expect_external_blocked "${peer_cluster_v4}" "${peer_cluster_v6}"
expect_external_blocked "${peer_local_v4}" "${peer_local_v6}"
[[ $(health_status 4 "${server_node_v4}") == 503 ]]
[[ $(health_status 4 "${server_node_v4}" 32081) == 503 ]]
"${kc[@]}" -n "${namespace}" exec server -- rm -f /tmp/unready
"${kc[@]}" -n "${namespace}" wait --for=condition=Ready pod/server --timeout=90s >/dev/null
wait_for_convergence >/dev/null
wait_for_external_tcp 4 "${cluster_v4}"
wait_for_external_tcp 6 "${local_v6}"
wait_for_external_tcp 4 "${peer_cluster_v4}"
[[ $(health_status 4 "${server_node_v4}") == 200 ]]
[[ $(health_status 4 "${server_node_v4}" 32081) == 200 ]]

stage=controller-provider-and-agent-recovery
durable_before=$(load_balancer_state)
stable_before=$(stable_allocation_projection <<<"${durable_before}")
stable_digest=$(printf '%s' "${stable_before}" | sha256sum | cut -d ' ' -f 1)
allocation_before=$(jq -er .allocation.revision <<<"${durable_before}")
reachability_before=$(jq -er .reachabilityRevision <<<"${durable_before}")
old_controller=$(controller_pod)
"${kc[@]}" -n unf-system scale deployment/unf-controller --replicas=0 >/dev/null
controller_scaled_down=true
"${kc[@]}" -n unf-system wait --for=delete pod -l app.kubernetes.io/name=unf-controller --timeout=180s >/dev/null
kill "${forward_pid}" >/dev/null 2>&1 || true; wait "${forward_pid}" >/dev/null 2>&1 || true; forward_pid=
for replacement_node in "${client_node}" "${server_node}"; do
    probe_log="${temporary_dir}/probe-${replacement_node}.log"
    if [[ ${replacement_node} == "${client_node}" ]]; then
        recovery_cluster_v4=${peer_cluster_v4}; recovery_udp_v6=${peer_cluster_v6}
    else
        recovery_cluster_v4=${cluster_v4}; recovery_udp_v6=${local_v6}
    fi
    (
        for _ in $(seq 1 120); do
            external_tcp_probe 4 "${recovery_cluster_v4}"
            probe_external_udp_bounded 6 "${recovery_udp_v6}"
            sleep 1
        done
    ) >"${probe_log}" 2>&1 &
    probe_pid=$!
    old_agent=$(agent_pod_on_node "${replacement_node}")
    "${kc[@]}" -n unf-system delete pod "${old_agent}" --wait=false >/dev/null
    for _ in $(seq 1 900); do
        new_agent=$(agent_pod_on_node "${replacement_node}")
        if [[ -n ${new_agent} && ${new_agent} != "${old_agent}" ]] \
            && [[ $("${kc[@]}" -n unf-system get pod "${new_agent}" -o jsonpath='{.status.containerStatuses[0].ready}' 2>/dev/null) == true ]]; then break; fi
        sleep 1
    done
    [[ -n ${new_agent} && ${new_agent} != "${old_agent}" ]]
    recovered=$(agent_raw "${replacement_node}" /v1/status)
    jq -e '.schema_version == 6 and .ready and .bpf_loaded
        and .applied_service_revision == .desired_service_revision
        and .applied_load_balancer_revision == .desired_load_balancer_revision
        and .applied_load_balancer_allocation_revision == .desired_load_balancer_allocation_revision
        and .load_balancer_frontend_count == 24 and .load_balancer_source_range_count > 0
        and .load_balancer_last_error == null' <<<"${recovered}" >/dev/null
    pod=$(advertiser_pod_on_node "${replacement_node}")
    "${kc[@]}" -n unf-system exec "${pod}" -- sh -euc '
        state=/var/lib/unf/cni/v1/load-balancer-reachability.json
        test -f "$state" && test "$(stat -c %a "$state")" = 600
        jq -e ".schemaVersion == 1 and .applied.schemaVersion == 1 and .applied.revision > 0
          and .applied.allocationRevision > 0 and (.applied.targets | length) > 0" "$state" >/dev/null
        test -e /sys/fs/bpf/unf/v8/LOAD_BALANCER_CONFIG
        test -e /sys/fs/bpf/unf/v8/LOAD_BALANCER_FRONTENDS_V4
        test -e /sys/fs/bpf/unf/v8/LOAD_BALANCER_FRONTENDS_V6
        test ! -e /sys/fs/bpf/unf/v8/LOAD_BALANCER_SOURCE_RANGES_V4
        test ! -e /sys/fs/bpf/unf/v8/LOAD_BALANCER_SOURCE_RANGES_V6
    '
    if ! wait "${probe_pid}"; then sed 's/^/probe: /' "${probe_log}" >&2; exit 1; fi
    probe_pid=
done
"${kc[@]}" -n unf-system scale deployment/unf-controller --replicas=1 >/dev/null
controller_scaled_down=false
"${kc[@]}" -n unf-system rollout status deployment/unf-controller --timeout=10m >/dev/null
wait_for_convergence >/dev/null
new_controller=$(controller_pod); [[ ${new_controller} != "${old_controller}" ]]
durable_after=$(load_balancer_state)
stable_after=$(stable_allocation_projection <<<"${durable_after}"); [[ ${stable_after} == "${stable_before}" ]]
allocation_after=$(jq -er .allocation.revision <<<"${durable_after}")
reachability_after=$(jq -er .reachabilityRevision <<<"${durable_after}")
(( allocation_after >= allocation_before && reachability_after >= reachability_before ))
[[ $(lease_address "${durable_after}" server-cluster 4) == "${cluster_v4}" ]]
[[ $(lease_address "${durable_after}" server-local 6) == "${local_v6}" ]]
[[ $(lease_address "${durable_after}" peer-cluster 4) == "${peer_cluster_v4}" ]]
[[ $(lease_address "${durable_after}" peer-local 6) == "${peer_local_v6}" ]]
wait_for_external_tcp 4 "${cluster_v4}"
wait_for_external_udp 6 "${local_v6}"

stage=exact-fixture-cleanup
withdraw_vips
for worker in "${workers[@]}"; do
    pod=$(advertiser_pod_on_node "${worker}")
    "${kc[@]}" -n unf-system exec "${pod}" -- sh -euc '
        for address in "$@"; do ! ip -o address show dev br-ex | grep -F "$address"; done
    ' sh "${cluster_v4}/32" "${cluster_v6}/128" "${local_v4}/32" "${local_v6}/128" \
        "${peer_cluster_v4}/32" "${peer_cluster_v6}/128" "${peer_local_v4}/32" "${peer_local_v6}/128"
done
"${kc[@]}" delete namespace "${namespace}" --wait=true --timeout=15m >/dev/null
namespace_created=false
cleanup_agents=$(wait_for_load_balancer_shape 0 0 0)
for _ in $(seq 1 900); do
    cleanup_state=$(load_balancer_state 2>/dev/null || true)
    jq -e '(.allocation.leases | length) == 0' <<<"${cleanup_state}" >/dev/null 2>&1 && break
    sleep 1
done
jq -e '(.allocation.leases | length) == 0' <<<"${cleanup_state}" >/dev/null
for node in "${nodes[@]}"; do
    pod=$(advertiser_pod_on_node "${node}")
    "${kc[@]}" -n unf-system exec "${pod}" -- sh -euc '
        test ! -e /sys/fs/bpf/unf/v8/LOAD_BALANCER_SOURCE_RANGES_V4
        test ! -e /sys/fs/bpf/unf/v8/LOAD_BALANCER_SOURCE_RANGES_V6
        state=/var/lib/unf/cni/v1/load-balancer-reachability.json
        test -f "$state"
        jq -e ".schemaVersion == 1 and .applied.schemaVersion == 1 and (.applied.targets | length) == 0" "$state" >/dev/null
    '
done
for worker in "${workers[@]}"; do
    pod=$(advertiser_pod_on_node "${worker}")
    "${kc[@]}" -n unf-system exec "${pod}" -- sh -euc '
        for map in LOAD_BALANCER_FRONTENDS_V4 LOAD_BALANCER_FRONTENDS_V6; do
            test "$(bpftool -j map dump pinned /sys/fs/bpf/unf/v8/$map | jq length)" -eq 0
        done
    '
done
"${kc[@]}" -n unf-system delete pods -l "${advertiser_label}=true" --wait=true --timeout=180s >/dev/null
advertisers_created=false
final_agents=$(wait_for_convergence)
final_unhealthy=$(unhealthy_operators)
[[ ${final_unhealthy} == "${baseline_unhealthy}" ]]
"${kc[@]}" wait --for=condition=Ready nodes --all --timeout=10m >/dev/null

stage=evidence
node_evidence=$("${kc[@]}" get nodes -o json | jq '[.items[] | {
    name:.metadata.name,osImage:.status.nodeInfo.osImage,kernelVersion:.status.nodeInfo.kernelVersion,
    containerRuntime:.status.nodeInfo.containerRuntimeVersion,podCIDRs:.spec.podCIDRs,
    internalIPs:[.status.addresses[] | select(.type == "InternalIP") | .address]}]')
image_evidence=$("${kc[@]}" -n unf-system get pods -l 'app.kubernetes.io/name in (unf-controller,unf-agent)' -o json \
    | jq '[.items[] | {pod:.metadata.name,node:.spec.nodeName,containers:[.status.containerStatuses[] | {name,image,imageID}]}]')
mkdir -p "$(dirname "${artifact}")"
artifact_tmp="${artifact}.tmp.$$"
jq -n \
    --arg generatedAt "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --arg context "${context}" \
    --arg infrastructure "${infrastructure}" --arg sourceRevision "${source_revision}" \
    --arg qualificationRevision "${qualification_revision}" \
    --arg openshiftVersion "$("${kc[@]}" get clusterversion version -o jsonpath='{.status.desired.version}')" \
    --arg kubernetesVersion "$("${kc[@]}" version -o json | jq -r .serverVersion.gitVersion)" \
    --arg controllerImage "${controller_image}" --arg agentImage "${agent_image}" --arg testToolsImage "${test_tools_image}" \
    --arg clusterIPv4 "${cluster_v4}" --arg clusterIPv6 "${cluster_v6}" \
    --arg localIPv4 "${local_v4}" --arg localIPv6 "${local_v6}" \
    --arg peerClusterIPv4 "${peer_cluster_v4}" --arg peerClusterIPv6 "${peer_cluster_v6}" \
    --arg peerLocalIPv4 "${peer_local_v4}" --arg peerLocalIPv6 "${peer_local_v6}" \
    --arg allowedIPv4 "${allowed_v4}" --arg allowedIPv6 "${allowed_v6}" \
    --argjson clusterServiceId "${cluster_service_id}" --argjson localServiceId "${local_service_id}" \
    --argjson peerClusterServiceId "${peer_cluster_service_id}" --argjson peerLocalServiceId "${peer_local_service_id}" \
    --argjson activeServiceRevision "${active_service_revision}" --arg stableAllocationDigest "${stable_digest}" \
    --argjson allocationRevisionBefore "${allocation_before}" --argjson allocationRevisionAfter "${allocation_after}" \
    --argjson reachabilityRevisionBefore "${reachability_before}" --argjson reachabilityRevisionAfter "${reachability_after}" \
    --argjson durationSeconds "$(( $(date +%s) - started_unix ))" --argjson nodes "${node_evidence}" \
    --argjson images "${image_evidence}" --argjson agents "${final_agents}" \
    --argjson baselineUnhealthy "${baseline_unhealthy}" --argjson finalUnhealthy "${final_unhealthy}" '
    {
      schemaVersion:1,generatedAt:$generatedAt,phase:"6.9",result:"passed",
      context:$context,infrastructure:$infrastructure,sourceRevision:$sourceRevision,
      qualificationRevision:$qualificationRevision,openshiftVersion:$openshiftVersion,
      kubernetesVersion:$kubernetesVersion,durationSeconds:$durationSeconds,
      images:{controller:$controllerImage,agent:$agentImage,testTools:$testToolsImage},
      kubeProxyPresent:false,persistentBpfAbi:7,
      baselineUnhealthyOperators:$baselineUnhealthy,finalUnhealthyOperators:$finalUnhealthy,
      provider:{name:"direct-node",instance:"openshift-direct-node-v1",pool:"qualification",poolUid:"openshift-loadbalancer-pool-v1",
        advertisementFixture:"exact temporary br-ex /32 and /128 ownership"},
      loadBalancers:{cluster:{serviceId:$clusterServiceId,ipv4:$clusterIPv4,ipv6:$clusterIPv6},
        local:{serviceId:$localServiceId,ipv4:$localIPv4,ipv6:$localIPv6,healthCheckNodePort:32080},
        peerCluster:{serviceId:$peerClusterServiceId,ipv4:$peerClusterIPv4,ipv6:$peerClusterIPv6},
        peerLocal:{serviceId:$peerLocalServiceId,ipv4:$peerLocalIPv4,ipv6:$peerLocalIPv6,healthCheckNodePort:32081}},
      externalClient:{ipv4:$allowedIPv4,ipv6:$allowedIPv6},activeServiceRevision:$activeServiceRevision,
      recovery:{stableAllocationSha256:$stableAllocationDigest,
        allocationRevisionBefore:$allocationRevisionBefore,allocationRevisionAfter:$allocationRevisionAfter,
        reachabilityRevisionBefore:$reachabilityRevisionBefore,reachabilityRevisionAfter:$reachabilityRevisionAfter},
      nodes:$nodes,imagesObserved:$images,agents:$agents,
      verified:["digest-pinned controller-first five-node rollout","RHCOS SELinux and CRI-O",
        "UNF primary CNI with kube-proxy absent","explicit LoadBalancer class and zero traffic NodePorts",
        "conflict-safe dual-stack allocation and direct-node provenance",
        "stable per-worker temporary br-ex advertisement ownership and exact withdrawal",
        "workstation IPv4 and IPv6 TCP/UDP Cluster traffic through both workers using distinct VIPs",
        "workstation IPv4 and IPv6 TCP/UDP Local traffic through the backend worker",
        "Cluster receiving-node source translation and Local client source preservation",
        "Local non-backend fail-closed behavior","dual-stack source-range allow and deny",
        "dual-stack healthCheckNodePort 200/503 placement and readiness lifecycle",
        "readiness withdrawal, no-backend behavior, and recovery",
        "metrics, validated status, durable history, explanation, and read-only simulation",
        "controller/provider restart with stable allocation identity and monotonic fencing",
        "controller-offline replacement of both worker agents from last-known-good state",
        "current-schema checkpoint and exact ABI-v7 LoadBalancer map audit",
        "exact lease, frontend map, runtime source trie, health listener, address, Pod, and Namespace cleanup",
        "five-node final convergence and no new unhealthy ClusterOperators"],
      excluded:["production BGP, EVPN, ECMP, and BFD","cloud-provider adapters","classless ownership",
        "session affinity","internalTrafficPolicy","topology-aware hints","Maglev","DSR",
        "SCTP Service forwarding","fragments","generic NAT RELATED tracking","production availability and scale"]
    }
' >"${artifact_tmp}"
chmod 0600 "${artifact_tmp}"
mv -f "${artifact_tmp}" "${artifact}"
artifact_tmp=

trap - ERR EXIT
rm -rf -- "${temporary_dir}"
echo "OpenShift cl02 kube-proxy-free dual-stack LoadBalancer qualification passed; evidence: ${artifact}"
