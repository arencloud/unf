#!/usr/bin/env bash
set -Eeuo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
kubeconfig=${KUBECONFIG:-"${project_root}/.tools/kind-unf-service-dev.kubeconfig"}
context=${KUBE_CONTEXT:-kind-unf-service-dev}
container_runtime=${KIND_PROVIDER:-podman}
artifact=${UNF_SERVICE_SELECTION_KIND_EVIDENCE:-"${project_root}/.artifacts/phase7-service-selection-kind.json"}
phase6_artifact=${UNF_LOADBALANCER_KIND_EVIDENCE:-"${project_root}/.artifacts/phase6-loadbalancer-kind.json"}
namespace=unf-service-selection-qualification
external_client=unf-service-selection-external-client
kc=(kubectl --kubeconfig "${kubeconfig}" --context "${context}")
temporary_dir=$(mktemp -d)
controller_scaled_down=false
qualification_stage=initialization
started_unix_seconds=$(date +%s)
# Reverse connection keys intentionally omit the frontend VIP. Use a bounded
# per-run source-port window so repeated qualification against persistent maps
# cannot collide with an unexpired flow from an earlier ClusterIP allocation.
affinity_probe_port_base=$((40000 + started_unix_seconds % 20000))
maglev_probe_port_base=$((affinity_probe_port_base + 100))
stable_hash_probe_port_base=$((affinity_probe_port_base + 200))

report_failure() {
    local status=$? line=${BASH_LINENO[0]:-unknown}
    echo "service-selection Kind qualification failed during ${qualification_stage} at line ${line}: ${BASH_COMMAND}" >&2
    return "${status}"
}

cleanup() {
    if [[ ${controller_scaled_down} == true ]]; then
        "${kc[@]}" -n unf-system scale deployment/unf-controller --replicas=1 >/dev/null 2>&1 || true
    fi
    sudo "${container_runtime}" rm -f "${external_client}" >/dev/null 2>&1 || true
    "${kc[@]}" delete namespace "${namespace}" --ignore-not-found --wait=true \
        --timeout=120s >/dev/null 2>&1 || true
    for node in "${nodes[@]:-}"; do
        "${kc[@]}" label node "${node}" topology.kubernetes.io/zone- >/dev/null 2>&1 || true
    done
    rm -rf "${temporary_dir}"
}
trap report_failure ERR
trap cleanup EXIT

if [[ ${context} != kind-* ]] || [[ $("${kc[@]}" config current-context) != "${context}" ]]; then
    echo "refusing service-selection qualification outside exact Kind context ${context}" >&2
    exit 1
fi

qualification_stage=prior-fixture-cleanup
"${kc[@]}" delete namespace "${namespace}" --ignore-not-found --wait=true \
    --timeout=120s >/dev/null

qualification_stage=phase6-regression-and-live-handoff
KUBECONFIG="${kubeconfig}" KUBE_CONTEXT="${context}" KIND_PROVIDER="${container_runtime}" \
UNF_LOADBALANCER_KIND_EVIDENCE="${phase6_artifact}" UNF_LOADBALANCER_SKIP_ROLLBACK=true \
    "${project_root}/hack/verify-kind-loadbalancer.sh"
jq -e '.phase == "6.8" and .handoff.primaryCniActive == true' "${phase6_artifact}" >/dev/null

mapfile -t workers < <("${kc[@]}" get nodes -l '!node-role.kubernetes.io/control-plane' \
    -o name | sed 's|node/||' | sort)
control_plane=$("${kc[@]}" get nodes -l node-role.kubernetes.io/control-plane \
    -o jsonpath='{.items[0].metadata.name}')
if (( ${#workers[@]} != 2 )) || [[ -z ${control_plane} ]]; then
    echo "service-selection qualification requires one control-plane and exactly two workers" >&2
    exit 1
fi
client_node=${workers[0]}
remote_node=${workers[1]}
same_zone_node=${control_plane}
nodes=("${control_plane}" "${workers[@]}")

controller_raw() {
    local path=$1 pod
    pod=$("${kc[@]}" -n unf-system get pods -l app.kubernetes.io/name=unf-controller -o json \
        | jq -r '.items[] | select(.metadata.deletionTimestamp == null and .status.phase == "Running") | .metadata.name' \
        | head -n 1)
    [[ -n ${pod} ]]
    "${kc[@]}" get --raw "/api/v1/namespaces/unf-system/pods/${pod}:9962/proxy${path}"
}

agent_raw() {
    local pod=$1 path=$2
    "${kc[@]}" get --raw "/api/v1/namespaces/unf-system/pods/${pod}:9963/proxy${path}"
}

wait_for_convergence() {
    local snapshot=
    for _ in $(seq 1 180); do
        snapshot=$(controller_raw /v1/state/agents 2>/dev/null || true)
        if jq -e --argjson expected "${#nodes[@]}" '
            .schema_version == 8 and .expected_agents == $expected
            and .reporting_agents == $expected and .missing_agents == 0
            and .stale_agents == 0 and .converged_agents == $expected
            and .unexpected_agents == 0 and .all_converged
            and all(.nodes[];
                .fresh and .converged and .report.ready and .report.bpf_loaded
                and .report.applied_selection_contract_revision == .report.desired_selection_contract_revision
                and .report.applied_selection_contract_digest == .report.desired_selection_contract_digest)
        ' <<<"${snapshot}" >/dev/null 2>&1; then
            printf '%s\n' "${snapshot}"
            return 0
        fi
        sleep 1
    done
    echo "service-selection agents did not converge" >&2
    jq . <<<"${snapshot}" >&2 || true
    return 1
}

wait_for_operations_provenance() {
    local snapshot=
    for _ in $(seq 1 180); do
        snapshot=$(controller_raw /v1/state/agents 2>/dev/null || true)
        if jq -e --argjson expected "${#nodes[@]}" '
            .schema_version == 8 and .expected_agents == $expected
            and .reporting_agents == $expected and .missing_agents == 0
            and .stale_agents == 0 and .converged_agents == $expected
            and .unexpected_agents == 0 and .all_converged
            and all(.nodes[];
                .fresh and .converged and .report.ready and .report.bpf_loaded
                and .report.schema_version == 8
                and .report.invalid_service_events == 0
                and .report.applied_selection_contract_revision > 0
                and .report.applied_selection_contract_revision == .report.desired_selection_contract_revision
                and .report.applied_selection_contract_digest != null
                and .report.applied_selection_contract_digest == .report.desired_selection_contract_digest)
            and any(.nodes[]; .report.service_same_node_selections > 0)
            and any(.nodes[]; .report.service_same_zone_selections > 0)
            and any(.nodes[]; .report.service_cluster_selections > 0)
            and any(.nodes[]; .report.service_affinity_creations > 0)
            and any(.nodes[]; .report.service_affinity_reuses > 0)
            and any(.nodes[]; .report.service_affinity_reselections > 0)
            and any(.nodes[]; .report.service_maglev_selections > 0)
            and any(.nodes[]; .report.service_stable_hash_selections > 0)
            and any(.nodes[]; .report.service_nat_forwards > 0)
            and any(.nodes[]; .report.service_dsr_forwards > 0)
        ' <<<"${snapshot}" >/dev/null 2>&1; then
            printf '%s\n' "${snapshot}"
            return 0
        fi
        sleep 1
    done
    echo "service-selection operations provenance did not become complete" >&2
    jq . <<<"${snapshot}" >&2 || true
    return 1
}

wait_for_service() {
    local name=$1 address port protocol snapshot=
    address=$("${kc[@]}" -n "${namespace}" get service "${name}" -o json \
        | jq -er '[.spec.clusterIPs[] | select(contains("."))][0]')
    port=$("${kc[@]}" -n "${namespace}" get service "${name}" -o json \
        | jq -er '.spec.ports[0].port')
    protocol=$("${kc[@]}" -n "${namespace}" get service "${name}" -o json \
        | jq -er '.spec.ports[0].protocol | ascii_downcase')
    for _ in $(seq 1 180); do
        snapshot=$(cluster_simulation "${address}" "${protocol}" "${port}" 2>/dev/null || true)
        if jq -e --arg namespace "${namespace}" --arg name "${name}" '
            .schema_version == 1 and .namespace == $namespace and .name == $name
            and .selection_contract_revision > 0
        ' <<<"${snapshot}" >/dev/null 2>&1; then
            wait_for_convergence >/dev/null
            return 0
        fi
        sleep 1
    done
    echo "Service ${namespace}/${name} did not compile" >&2
    jq . <<<"${snapshot}" >&2 || true
    return 1
}

node_address() {
    local node=$1 family=$2
    "${kc[@]}" get node "${node}" -o json | jq -er --arg family "${family}" '
        [.status.addresses[] | select(.type == "InternalIP") | .address
        | select(if $family == "4" then contains(".") else contains(":") end)][0]'
}

pod_addresses() {
    local pod=$1
    "${kc[@]}" -n "${namespace}" get pod "${pod}" -o json \
        | jq -r '.status.podIPs[].ip'
}

service_addresses() {
    local service=$1
    "${kc[@]}" -n "${namespace}" get service "${service}" -o json \
        | jq -r '.spec.clusterIPs[]'
}

cluster_simulation() {
    local address=$1 protocol=$2 port=$3
    controller_raw "/v1/services/clusterip/simulate?node_name=${client_node}&address=${address}&port=${port}&protocol=${protocol}"
}

tcp_probe() {
    local address=$1 target
    if [[ ${address} == *:* ]]; then target="http://[${address}]:8080/health"; else target="http://${address}:8080/health"; fi
    "${kc[@]}" -n "${namespace}" exec client -- wget -T 4 -t 1 -qO- "${target}" | grep -qx ok
}

udp_probe() {
    local family=$1 address=$2 source_port=$3 target output=
    if [[ ${family} == 4 ]]; then target="UDP4:${address}:5353"; else target="UDP6:[${address}]:5353"; fi
    for _ in $(seq 1 10); do
        output=$("${kc[@]}" -n "${namespace}" exec client -- sh -ec \
            "printf selection-${source_port} | socat -T 2 - '${target},sourceport=${source_port}'" \
            2>/dev/null || true)
        if grep -qx "selection-${source_port}" <<<"${output}"; then
            return 0
        fi
        sleep 1
    done
    echo "UDP probe to ${target} from source port ${source_port} did not echo" >&2
    return 1
}

wait_for_history() {
    local address=$1 jq_assertion=$2 history=
    for _ in $(seq 1 120); do
        history=$(controller_raw /v1/flows 2>/dev/null || true)
        if jq -e --arg address "${address}" ".schema_version == 7 and (${jq_assertion})" \
            <<<"${history}" >/dev/null 2>&1; then
            printf '%s\n' "${history}"
            return 0
        fi
        sleep 1
    done
    echo "advanced service history assertion timed out: ${jq_assertion}" >&2
    jq . <<<"${history}" >&2 || true
    return 1
}

replace_endpoint_condition() {
    local slice=$1 address=$2 ready=$3 serving=$4 terminating=$5
    "${kc[@]}" -n "${namespace}" get endpointslice "${slice}" -o json \
        | jq --arg address "${address}" --argjson ready "${ready}" \
            --argjson serving "${serving}" --argjson terminating "${terminating}" '
            .endpoints |= map(if .addresses[0] == $address then
                .conditions = {ready:$ready,serving:$serving,terminating:$terminating}
            else . end)
            | del(.metadata.resourceVersion,.metadata.uid,.metadata.creationTimestamp,.metadata.generation,.metadata.managedFields)
        ' | "${kc[@]}" replace -f - >/dev/null
}

apply_backend() {
    local name=$1 node=$2 tolerate=${3:-false} security=
    if [[ ${tolerate} == true ]]; then
        security=$'  tolerations:\n    - operator: Exists'
    fi
    "${kc[@]}" apply -f - >/dev/null <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: ${name}
  namespace: ${namespace}
spec:
  nodeSelector:
    kubernetes.io/hostname: ${node}
${security}
  containers:
    - name: server
      image: localhost/unf-test-tools:ipv6-ext-v1
      imagePullPolicy: Never
      securityContext:
        capabilities:
          add: [NET_ADMIN]
      command: [sh, -ec]
      args:
        - |
          /usr/local/bin/unf-udp-echo 4 5353 &
          /usr/local/bin/unf-udp-echo 6 5353 &
          exec /usr/local/bin/unf-flow-receiver 8080
EOF
}

qualification_stage=advanced-fixture-preflight
"${kc[@]}" wait --for=condition=Ready nodes --all --timeout=180s >/dev/null
if "${kc[@]}" -n kube-system get daemonset kube-proxy >/dev/null 2>&1; then
    echo "kube-proxy unexpectedly exists" >&2
    exit 1
fi
for node in "${nodes[@]}"; do
    "${kc[@]}" label node "${node}" topology.kubernetes.io/zone=zone-b --overwrite >/dev/null
done
"${kc[@]}" label node "${client_node}" topology.kubernetes.io/zone=zone-a --overwrite >/dev/null
"${kc[@]}" label node "${same_zone_node}" topology.kubernetes.io/zone=zone-a --overwrite >/dev/null
"${kc[@]}" delete namespace "${namespace}" --ignore-not-found --wait=true --timeout=120s >/dev/null
baseline_status=$(controller_raw /v1/status)
baseline_services=$(jq -er .compiled_services <<<"${baseline_status}")
baseline_frontends=$(jq -er .compiled_service_frontends <<<"${baseline_status}")
baseline_backends=$(jq -er .compiled_service_backends <<<"${baseline_status}")

qualification_stage=locality-affinity-fixture
"${kc[@]}" create namespace "${namespace}" >/dev/null
apply_backend backend-node "${client_node}"
apply_backend backend-zone "${same_zone_node}" true
apply_backend backend-remote "${remote_node}"
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
  name: selection
  namespace: ${namespace}
  annotations:
    network.unf.io/service-selection-algorithm: maglev
spec:
  ipFamilyPolicy: RequireDualStack
  ipFamilies: [IPv4, IPv6]
  internalTrafficPolicy: Cluster
  trafficDistribution: PreferSameNode
  sessionAffinity: ClientIP
  sessionAffinityConfig:
    clientIP:
      timeoutSeconds: 3
  ports:
    - {name: http, protocol: TCP, port: 8080, targetPort: 8080}
    - {name: echo, protocol: UDP, port: 5353, targetPort: 5353}
EOF
"${kc[@]}" -n "${namespace}" wait --for=condition=Ready pod --all --timeout=180s >/dev/null
mapfile -t node_ips < <(pod_addresses backend-node)
mapfile -t zone_ips < <(pod_addresses backend-zone)
mapfile -t remote_ips < <(pod_addresses backend-remote)
node_v4=${node_ips[0]}; node_v6=${node_ips[1]}
zone_v4=${zone_ips[0]}; zone_v6=${zone_ips[1]}
remote_v4=${remote_ips[0]}; remote_v6=${remote_ips[1]}
"${kc[@]}" apply -f - >/dev/null <<EOF
apiVersion: discovery.k8s.io/v1
kind: EndpointSlice
metadata:
  name: selection-v4
  namespace: ${namespace}
  labels:
    kubernetes.io/service-name: selection
addressType: IPv4
ports:
  - {name: http, protocol: TCP, port: 8080}
  - {name: echo, protocol: UDP, port: 5353}
endpoints:
  - {addresses: [${node_v4}], nodeName: ${client_node}, zone: zone-a, conditions: {ready: true, serving: true, terminating: false}}
  - {addresses: [${zone_v4}], nodeName: ${same_zone_node}, zone: zone-a, conditions: {ready: true, serving: true, terminating: false}}
  - {addresses: [${remote_v4}], nodeName: ${remote_node}, zone: zone-b, conditions: {ready: true, serving: true, terminating: false}}
---
apiVersion: discovery.k8s.io/v1
kind: EndpointSlice
metadata:
  name: selection-v6
  namespace: ${namespace}
  labels:
    kubernetes.io/service-name: selection
addressType: IPv6
ports:
  - {name: http, protocol: TCP, port: 8080}
  - {name: echo, protocol: UDP, port: 5353}
endpoints:
  - {addresses: [${node_v6}], nodeName: ${client_node}, zone: zone-a, conditions: {ready: true, serving: true, terminating: false}}
  - {addresses: [${zone_v6}], nodeName: ${same_zone_node}, zone: zone-a, conditions: {ready: true, serving: true, terminating: false}}
  - {addresses: [${remote_v6}], nodeName: ${remote_node}, zone: zone-b, conditions: {ready: true, serving: true, terminating: false}}
EOF
wait_for_service selection
mapfile -t selection_vips < <(service_addresses selection)
selection_v4=${selection_vips[0]}; selection_v6=${selection_vips[1]}

qualification_stage=strict-same-node-and-affinity
same_node_simulation=$(cluster_simulation "${selection_v4}" udp 5353)
jq -e --arg backend "${node_v4}" '
    .decision == "translate" and .selection_tier == "sameNode"
    and .selection_algorithm == "maglev" and .session_affinity.mode == "clientIp"
    and .session_affinity.timeoutSeconds == 3
    and .forwarding_mode == "nat"
    and any(.eligible_backends[]; .address == $backend)
' <<<"${same_node_simulation}" >/dev/null
tcp_probe "${selection_v4}"; tcp_probe "${selection_v6}"
udp_probe 4 "${selection_v4}" "$((affinity_probe_port_base + 1))"
udp_probe 4 "${selection_v4}" "$((affinity_probe_port_base + 2))"
same_node_history=$(wait_for_history "${selection_v4}" '
    any(.entries[]; .key.destination_ipv4 == $address and .service.selection_tier == "same_node"
        and .service.affinity_outcome == "created" and .service.forwarding_mode == "nat")
    and any(.entries[]; .key.destination_ipv4 == $address and .service.selection_tier == "same_node"
        and .service.affinity_outcome == "reused")')

qualification_stage=graceful-withdrawal-and-topology-fallback
replace_endpoint_condition selection-v4 "${node_v4}" false false true
replace_endpoint_condition selection-v6 "${node_v6}" false false true
wait_for_convergence >/dev/null
same_zone_simulation=$(cluster_simulation "${selection_v4}" udp 5353)
jq -e --arg backend "${zone_v4}" '
    .decision == "translate" and .selection_tier == "sameZone"
    and any(.eligible_backends[]; .address == $backend)
' <<<"${same_zone_simulation}" >/dev/null
udp_probe 4 "${selection_v4}" "$((affinity_probe_port_base + 3))"
wait_for_history "${selection_v4}" '
    any(.entries[]; .key.destination_ipv4 == $address and .service.selection_tier == "same_zone"
        and .service.affinity_outcome == "reselected")' >/dev/null
sleep 4
udp_probe 4 "${selection_v4}" "$((affinity_probe_port_base + 4))"
replace_endpoint_condition selection-v4 "${zone_v4}" false false true
replace_endpoint_condition selection-v6 "${zone_v6}" false false true
wait_for_convergence >/dev/null
cluster_fallback_simulation=$(cluster_simulation "${selection_v6}" tcp 8080)
jq -e --arg backend "${remote_v6}" '
    .decision == "translate" and .selection_tier == "cluster"
    and any(.eligible_backends[]; .address == $backend)
' <<<"${cluster_fallback_simulation}" >/dev/null
tcp_probe "${selection_v4}"; tcp_probe "${selection_v6}"
cluster_history=$(wait_for_history "${selection_v4}" '
    any(.entries[]; .key.destination_ipv4 == $address and .service.selection_tier == "cluster")')

qualification_stage=measured-maglev-and-stable-hash
replace_endpoint_condition selection-v4 "${node_v4}" true true false
replace_endpoint_condition selection-v6 "${node_v6}" true true false
replace_endpoint_condition selection-v4 "${zone_v4}" true true false
replace_endpoint_condition selection-v6 "${zone_v6}" true true false
"${kc[@]}" -n "${namespace}" patch service selection --type=json -p='[
  {"op":"remove","path":"/spec/trafficDistribution"},
  {"op":"replace","path":"/spec/sessionAffinity","value":"None"},
  {"op":"remove","path":"/spec/sessionAffinityConfig"}
]' >/dev/null
wait_for_convergence >/dev/null
maglev_simulation=$(cluster_simulation "${selection_v4}" udp 5353)
jq -e '.selection_tier == "cluster" and .selection_algorithm == "maglev"
    and (.eligible_backend_ids | length) == 3' <<<"${maglev_simulation}" >/dev/null
for offset in $(seq 0 31); do
    udp_probe 4 "${selection_v4}" "$((maglev_probe_port_base + offset))"
done
maglev_history=$(wait_for_history "${selection_v4}" '
    any(.entries[]; .key.destination_ipv4 == $address
        and .service.selection_algorithm == "maglev" and .service.affinity_outcome == "none")')
"${kc[@]}" -n "${namespace}" annotate service selection \
    network.unf.io/service-selection-algorithm=stable-hash --overwrite >/dev/null
wait_for_convergence >/dev/null
stable_simulation=$(cluster_simulation "${selection_v6}" udp 5353)
jq -e '.selection_tier == "cluster" and .selection_algorithm == "stableHash"
    and (.eligible_backend_ids | length) == 3' <<<"${stable_simulation}" >/dev/null
for offset in $(seq 0 15); do
    udp_probe 6 "${selection_v6}" "$((stable_hash_probe_port_base + offset))"
done
stable_history=$(wait_for_history "${selection_v6}" '
    any(.entries[]; .key.destination_ipv6 == $address
        and .service.selection_algorithm == "stable_hash")')

qualification_stage=acknowledged-dual-stack-dsr
"${kc[@]}" apply -f - >/dev/null <<EOF
apiVersion: v1
kind: Service
metadata:
  name: dsr
  namespace: ${namespace}
  annotations:
    network.unf.io/service-forwarding-mode: dsr
    network.unf.io/dsr-backend-vip-ownership: acknowledged
spec:
  type: LoadBalancer
  loadBalancerClass: network.unf.io/load-balancer
  allocateLoadBalancerNodePorts: false
  ipFamilyPolicy: RequireDualStack
  ipFamilies: [IPv4, IPv6]
  ports:
    - {name: http, protocol: TCP, port: 8080, targetPort: 8080}
---
apiVersion: discovery.k8s.io/v1
kind: EndpointSlice
metadata:
  name: dsr-v4
  namespace: ${namespace}
  labels:
    kubernetes.io/service-name: dsr
addressType: IPv4
ports:
  - {name: http, protocol: TCP, port: 8080}
endpoints:
  - {addresses: [${remote_v4}], nodeName: ${remote_node}, zone: zone-b, conditions: {ready: true, serving: true, terminating: false}}
---
apiVersion: discovery.k8s.io/v1
kind: EndpointSlice
metadata:
  name: dsr-v6
  namespace: ${namespace}
  labels:
    kubernetes.io/service-name: dsr
addressType: IPv6
ports:
  - {name: http, protocol: TCP, port: 8080}
endpoints:
  - {addresses: [${remote_v6}], nodeName: ${remote_node}, zone: zone-b, conditions: {ready: true, serving: true, terminating: false}}
EOF
for _ in $(seq 1 180); do
    mapfile -t dsr_vips < <("${kc[@]}" -n "${namespace}" get service dsr -o json \
        | jq -r '.status.loadBalancer.ingress[]?.ip' 2>/dev/null || true)
    if (( ${#dsr_vips[@]} == 2 )); then break; fi
    sleep 1
done
(( ${#dsr_vips[@]} == 2 ))
dsr_v4=${dsr_vips[0]}; dsr_v6=${dsr_vips[1]}
wait_for_service dsr
dsr_simulation=$(controller_raw "/v1/services/loadbalancer/simulate?node_name=${client_node}&address=${dsr_v4}&source_address=${node_v4}&port=8080&protocol=tcp")
jq -e '.decision == "translate" and .forwarding_mode == "dsr"
    and .frontend_kind == "load_balancer_cluster"' \
    <<<"${dsr_simulation}" >/dev/null
"${kc[@]}" -n "${namespace}" exec backend-remote -- ip address add "${dsr_v4}/32" dev lo
"${kc[@]}" -n "${namespace}" exec backend-remote -- ip -6 address add "${dsr_v6}/128" dev lo
sudo "${container_runtime}" exec "${remote_node}" ip -4 route replace "${dsr_v4}/32" via "${remote_v4}"
sudo "${container_runtime}" exec "${remote_node}" ip -6 route replace "${dsr_v6}/128" via "${remote_v6}"
kind_network=$(sudo "${container_runtime}" inspect "${client_node}" \
    | jq -er '.[0].NetworkSettings.Networks | keys[0]')
sudo "${container_runtime}" rm -f "${external_client}" >/dev/null 2>&1 || true
sudo "${container_runtime}" run -d --name "${external_client}" --network "${kind_network}" \
    --cap-add NET_ADMIN --pull never --entrypoint /bin/sh localhost/unf-test-tools:ipv6-ext-v1 \
    -c 'sleep infinity' >/dev/null
client_node_v4=$(node_address "${client_node}" 4); client_node_v6=$(node_address "${client_node}" 6)
sudo "${container_runtime}" exec "${external_client}" ip -4 route replace "${dsr_v4}/32" via "${client_node_v4}"
sudo "${container_runtime}" exec "${external_client}" ip -6 route replace "${dsr_v6}/128" via "${client_node_v6}"
sudo "${container_runtime}" exec "${external_client}" wget -T 5 -t 1 -qO- \
    "http://${dsr_v4}:8080/health" | grep -qx ok
sudo "${container_runtime}" exec "${external_client}" wget -T 5 -t 1 -qO- \
    "http://[${dsr_v6}]:8080/health" | grep -qx ok
dsr_history=$(wait_for_history "${dsr_v4}" '
    any(.entries[]; .key.destination_ipv4 == $address
        and .service.frontend_kind == "load_balancer_cluster"
        and .service.forwarding_mode == "dsr" and .service.action == 1)')

qualification_stage=operations-provenance
advanced_agents=$(wait_for_operations_provenance)
while read -r agent_pod; do
    metrics=$(agent_raw "${agent_pod}" /metrics)
    for metric in \
        unf_service_selection_same_node_total unf_service_selection_same_zone_total \
        unf_service_selection_cluster_total unf_service_selection_stable_hash_total \
        unf_service_selection_maglev_total unf_service_affinity_reused_total \
        unf_service_affinity_created_total unf_service_affinity_reselected_total \
        unf_service_forwarding_nat_total unf_service_forwarding_dsr_total; do
        grep -q "^${metric} " <<<"${metrics}"
    done
done < <("${kc[@]}" -n unf-system get pods -l app.kubernetes.io/name=unf-agent \
    -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}')

qualification_stage=controller-offline-selection-recovery
old_controller=$("${kc[@]}" -n unf-system get pods -l app.kubernetes.io/name=unf-controller \
    -o jsonpath='{.items[0].metadata.name}')
"${kc[@]}" -n unf-system scale deployment/unf-controller --replicas=0 >/dev/null
controller_scaled_down=true
"${kc[@]}" -n unf-system wait --for=delete pod -l app.kubernetes.io/name=unf-controller \
    --timeout=90s >/dev/null
for replacement_node in "${client_node}" "${remote_node}"; do
    old_agent=$("${kc[@]}" -n unf-system get pod -l app.kubernetes.io/name=unf-agent \
        --field-selector spec.nodeName="${replacement_node}" -o jsonpath='{.items[0].metadata.name}')
    "${kc[@]}" -n unf-system delete pod "${old_agent}" --wait=false >/dev/null
    "${kc[@]}" -n unf-system rollout status daemonset/unf-agent --timeout=180s >/dev/null
    # DaemonSet rollout status can become successful as soon as the replacement
    # is Ready while the deleted Pod still has a terminating API object. Fence
    # that object before resolving the sole agent for this Node.
    "${kc[@]}" -n unf-system wait --for=delete pod "${old_agent}" --timeout=90s >/dev/null
    new_agent=$("${kc[@]}" -n unf-system get pod -l app.kubernetes.io/name=unf-agent \
        --field-selector spec.nodeName="${replacement_node}" -o jsonpath='{.items[0].metadata.name}')
    [[ ${new_agent} != "${old_agent}" ]]
    recovered=
    for _ in $(seq 1 90); do
        recovered=$(agent_raw "${new_agent}" /v1/status 2>/dev/null || true)
        if jq -e '.schema_version == 8 and .ready and .bpf_loaded
            and .applied_selection_contract_revision > 0
            and .applied_selection_contract_revision == .desired_selection_contract_revision
            and .applied_selection_contract_digest == .desired_selection_contract_digest' \
            <<<"${recovered}" >/dev/null 2>&1; then
            break
        fi
        sleep 1
    done
    jq -e '.schema_version == 8 and .ready and .bpf_loaded
        and .applied_selection_contract_revision > 0
        and .applied_selection_contract_revision == .desired_selection_contract_revision
        and .applied_selection_contract_digest == .desired_selection_contract_digest' \
        <<<"${recovered}" >/dev/null
    sudo "${container_runtime}" exec "${replacement_node}" sh -ec '
        checkpoint=/var/lib/unf/cni/v1/service-snapshot.json.selection
        test -f "$checkpoint" && test "$(stat -c %a "$checkpoint")" = 600
        jq -e ".schemaVersion == 1 and .contract.schemaVersion == 1 and .contract.contractRevision > 0 and (.contract.contractDigest | length) == 64" "$checkpoint" >/dev/null
        test -e /sys/fs/bpf/unf/v14/SERVICE_CONFIG
        test -e /sys/fs/bpf/unf/v14/SERVICE_AFFINITY
        test -e /sys/fs/bpf/unf/v14/SERVICE_BACKEND_SLOTS
    '
    tcp_probe "${selection_v4}"
done
"${kc[@]}" -n unf-system scale deployment/unf-controller --replicas=1 >/dev/null
controller_scaled_down=false
"${kc[@]}" -n unf-system rollout status deployment/unf-controller --timeout=180s >/dev/null
wait_for_convergence >/dev/null
new_controller=$("${kc[@]}" -n unf-system get pods -l app.kubernetes.io/name=unf-controller \
    -o jsonpath='{.items[0].metadata.name}')
[[ ${new_controller} != "${old_controller}" ]]

qualification_stage=exact-fixture-cleanup
"${kc[@]}" -n "${namespace}" exec backend-remote -- ip address del "${dsr_v4}/32" dev lo
"${kc[@]}" -n "${namespace}" exec backend-remote -- ip -6 address del "${dsr_v6}/128" dev lo
sudo "${container_runtime}" exec "${remote_node}" ip -4 route del "${dsr_v4}/32"
sudo "${container_runtime}" exec "${remote_node}" ip -6 route del "${dsr_v6}/128"
sudo "${container_runtime}" rm -f "${external_client}" >/dev/null
"${kc[@]}" delete namespace "${namespace}" --wait=true --timeout=180s >/dev/null
for _ in $(seq 1 180); do
    cleanup_status=$(controller_raw /v1/status 2>/dev/null || true)
    if jq -e --argjson services "${baseline_services}" --argjson frontends "${baseline_frontends}" \
        --argjson backends "${baseline_backends}" '
        .compiled_services == $services and .compiled_service_frontends == $frontends
        and .compiled_service_backends == $backends and .service_compilation_error == null
        and .agents.all_converged' <<<"${cleanup_status}" >/dev/null 2>&1; then break; fi
    sleep 1
done
jq -e --argjson services "${baseline_services}" --argjson frontends "${baseline_frontends}" \
    --argjson backends "${baseline_backends}" '
    .compiled_services == $services and .compiled_service_frontends == $frontends
    and .compiled_service_backends == $backends' <<<"${cleanup_status}" >/dev/null
for node in "${nodes[@]}"; do
    "${kc[@]}" label node "${node}" topology.kubernetes.io/zone- >/dev/null
done

qualification_stage=evidence
release_revision=$(controller_raw /v1/version | jq -er '.build_revision')
[[ ${release_revision} =~ ^[0-9a-f]{40}$ ]]
git -C "${project_root}" merge-base --is-ancestor "${release_revision}" HEAD
qualification_revision=$(git -C "${project_root}" rev-parse HEAD)
node_evidence=$("${kc[@]}" get nodes -o json | jq '[.items[] | {
    name:.metadata.name,podCIDRs:.spec.podCIDRs,
    internalIPs:[.status.addresses[] | select(.type=="InternalIP") | .address],
    kernelVersion:.status.nodeInfo.kernelVersion,osImage:.status.nodeInfo.osImage}]')
image_evidence=$("${kc[@]}" -n unf-system get pods \
    -l 'app.kubernetes.io/name in (unf-controller,unf-agent)' -o json | jq '[.items[] | {
    pod:.metadata.name,node:.spec.nodeName,
    containers:[.status.containerStatuses[] | {name,image,imageID}]}]')
mkdir -p "$(dirname "${artifact}")"
jq -n \
    --arg generatedAt "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --arg revision "${release_revision}" --arg qualificationRevision "${qualification_revision}" \
    --arg context "${context}" \
    --arg kubernetesVersion "$("${kc[@]}" version -o json | jq -r .serverVersion.gitVersion)" \
    --argjson durationSeconds "$(( $(date +%s) - started_unix_seconds ))" \
    --arg phase6Evidence "${phase6_artifact}" \
    --arg selectionIPv4 "${selection_v4}" --arg selectionIPv6 "${selection_v6}" \
    --arg dsrIPv4 "${dsr_v4}" --arg dsrIPv6 "${dsr_v6}" \
    --argjson sameNodeSimulation "${same_node_simulation}" \
    --argjson sameZoneSimulation "${same_zone_simulation}" \
    --argjson clusterSimulation "${cluster_fallback_simulation}" \
    --argjson maglevSimulation "${maglev_simulation}" \
    --argjson stableSimulation "${stable_simulation}" \
    --argjson dsrSimulation "${dsr_simulation}" \
    --argjson nodes "${node_evidence}" --argjson images "${image_evidence}" '
    {
      schemaVersion:1,phase:"7.9",generatedAt:$generatedAt,
      revision:$revision,qualificationRevision:$qualificationRevision,
      context:$context,kubernetesVersion:$kubernetesVersion,durationSeconds:$durationSeconds,
      kubeProxyPresent:false,phase6Evidence:$phase6Evidence,
      services:{selection:{ipv4:$selectionIPv4,ipv6:$selectionIPv6},dsr:{ipv4:$dsrIPv4,ipv6:$dsrIPv6}},
      simulations:{sameNode:$sameNodeSimulation,sameZone:$sameZoneSimulation,
        clusterFallback:$clusterSimulation,maglev:$maglevSimulation,
        stableHash:$stableSimulation,dsr:$dsrSimulation},
      nodes:$nodes,images:$images,
      verified:[
        "complete Phase 6 three-Node dual-stack external, Pod, host, lifecycle, operations, and recovery regression",
        "strict SameNode, SameZone, and Cluster fallback on IPv4 and IPv6",
        "ClientIP affinity creation, reuse, timeout, and ineligible-backend reselection",
        "graceful ready/serving/terminating endpoint withdrawal",
        "measured Maglev and stable-hash packet-path provenance with three eligible backends",
        "explicit acknowledged dual-stack LoadBalancer DSR with installed backend VIP ownership and direct return",
        "status-v8, history-v7, fixed-cardinality metrics, and digest-bound simulations",
        "controller-offline agent replacement from private service-selection checkpoints",
        "controller recovery, exact fixture cleanup, and zero leaked LoadBalancer ownership"
      ],
      excluded:["OpenShift","production availability and scale","SCTP","fragments"]
    }' >"${artifact}"

qualification_stage=exact-platform-rollback
KUBECONFIG="${kubeconfig}" KUBE_CONTEXT="${context}" KIND_PROVIDER="${container_runtime}" \
    "${project_root}/hack/rollback-kind-primary-cni.sh"
jq '.verified += [
    "scoped ABI-v11 BPF cleanup",
    "exact remote-route deletion",
    "fingerprinted CNI artifact removal",
    "CoreDNS bootstrap restoration",
    "no-CNI baseline restoration"
]' "${artifact}" >"${artifact}.tmp"
mv -f "${artifact}.tmp" "${artifact}"

trap - ERR EXIT
echo "kube-proxy-free dual-stack service-selection qualification passed; evidence: ${artifact}"
