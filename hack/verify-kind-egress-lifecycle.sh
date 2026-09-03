#!/usr/bin/env bash
set -Eeuo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
kubeconfig=${KUBECONFIG:-"${project_root}/.tools/kind-unf-service-dev.kubeconfig"}
context=${KUBE_CONTEXT:-kind-unf-service-dev}
container_runtime=${KIND_PROVIDER:-podman}
test_tools_image=${UNF_TEST_TOOLS_IMAGE:-localhost/unf-test-tools:ipv6-ext-v1}
artifact=${UNF_EGRESS_KIND_EVIDENCE:-"${project_root}/.artifacts/phase8-egress-kind.json"}
namespace=unf-egress-lifecycle-qualification
pool=unf-egress-lifecycle
policy=unf-egress-lifecycle
external_container=unf-egress-lifecycle-external
gateway_label=network.unf.io/egress-gateway
started_unix_seconds=$(date +%s)
diagnostics_dir=${UNF_EGRESS_KIND_DIAGNOSTICS:-"${project_root}/.artifacts/phase8-egress-kind-${started_unix_seconds}"}
qualification_stage=preflight
resources_created=false
diagnostics_collected=false
kc=(kubectl --kubeconfig "${kubeconfig}" --context "${context}")
runtime=(sudo "${container_runtime}")

collect_diagnostics() {
    [[ ${diagnostics_collected} == false ]] || return 0
    diagnostics_collected=true
    mkdir -p "${diagnostics_dir}"
    "${kc[@]}" get nodes -o json >"${diagnostics_dir}/nodes.json" 2>/dev/null || true
    "${kc[@]}" get egresspools.network.unf.io,egresspolicies.network.unf.io -o yaml \
        >"${diagnostics_dir}/egress-resources.yaml" 2>/dev/null || true
    "${kc[@]}" -n unf-system get pods -o wide \
        >"${diagnostics_dir}/unf-pods.txt" 2>/dev/null || true
    "${kc[@]}" -n unf-system logs deployment/unf-controller --all-pods=true \
        >"${diagnostics_dir}/controller.log" 2>&1 || true
    "${kc[@]}" -n unf-system logs daemonset/unf-agent --all-pods=true --prefix \
        >"${diagnostics_dir}/agents.log" 2>&1 || true
    "${kc[@]}" -n unf-system get configmap unf-egress-control-plane \
        -o jsonpath='{.data.state\.json}' >"${diagnostics_dir}/control-plane.json" 2>/dev/null || true
    if [[ -n ${gateway_node:-} ]]; then
        "${runtime[@]}" exec "${gateway_node}" ip address show \
            >"${diagnostics_dir}/gateway-addresses.txt" 2>&1 || true
        "${runtime[@]}" exec "${gateway_node}" ip -6 neigh show proxy \
            >"${diagnostics_dir}/gateway-proxies.txt" 2>&1 || true
    fi
    "${runtime[@]}" inspect "${external_container}" \
        >"${diagnostics_dir}/external-container.json" 2>/dev/null || true
}

report_failure() {
    local status=$?
    local line=${BASH_LINENO[0]:-unknown}
    collect_diagnostics
    echo "Phase 8.5 Kind egress lifecycle failed during ${qualification_stage} at line ${line}: ${BASH_COMMAND}" >&2
    echo "diagnostics: ${diagnostics_dir}" >&2
    return "${status}"
}

cleanup() {
    if [[ ${resources_created} == true ]]; then
        "${kc[@]}" delete egresspolicy.network.unf.io "${policy}" --ignore-not-found \
            --wait=false >/dev/null 2>&1 || true
        "${kc[@]}" delete egresspool.network.unf.io "${pool}" --ignore-not-found \
            --wait=false >/dev/null 2>&1 || true
        "${kc[@]}" delete namespace "${namespace}" --ignore-not-found \
            --wait=false >/dev/null 2>&1 || true
        "${kc[@]}" label node "${gateway_node}" "${gateway_label}-" \
            >/dev/null 2>&1 || true
    fi
    "${runtime[@]}" rm -f "${external_container}" >/dev/null 2>&1 || true
}

trap report_failure ERR
trap cleanup EXIT

for command in kubectl jq rg sudo "${container_runtime}"; do
    command -v "${command}" >/dev/null 2>&1 || {
        echo "${command} is required for Phase 8.5 Kind egress qualification" >&2
        exit 1
    }
done
if [[ ${context} != kind-* ]] || [[ $("${kc[@]}" config current-context) != "${context}" ]]; then
    echo "refusing egress qualification outside exact Kind context ${context}" >&2
    exit 1
fi
if "${kc[@]}" -n kube-system get daemonset kube-proxy >/dev/null 2>&1; then
    echo "egress qualification requires kube-proxy-free Kind" >&2
    exit 1
fi
if "${kc[@]}" get namespace "${namespace}" >/dev/null 2>&1 \
    || "${kc[@]}" get egresspool.network.unf.io "${pool}" >/dev/null 2>&1 \
    || "${kc[@]}" get egresspolicy.network.unf.io "${policy}" >/dev/null 2>&1 \
    || "${runtime[@]}" container exists "${external_container}"; then
    echo "dedicated egress qualification resources already exist; refusing to adopt them" >&2
    exit 1
fi
if [[ $("${kc[@]}" get egresspolicies.network.unf.io -o json | jq '.items | length') != 0 ]] \
    || [[ $("${kc[@]}" get egresspools.network.unf.io -o json | jq '.items | length') != 0 ]]; then
    echo "egress qualification requires a dedicated cluster with no existing egress intent" >&2
    exit 1
fi
if [[ -n $("${kc[@]}" get nodes -l "${gateway_label}" -o name) ]]; then
    echo "egress qualification requires no pre-existing explicit gateway labels" >&2
    exit 1
fi
"${runtime[@]}" image exists "${test_tools_image}" || {
    echo "test-tools image ${test_tools_image} is unavailable to ${container_runtime}" >&2
    exit 1
}

mapfile -t workers < <("${kc[@]}" get nodes -l '!node-role.kubernetes.io/control-plane' \
    -o name | sed 's|node/||' | sort)
source_node=$("${kc[@]}" get nodes -l node-role.kubernetes.io/control-plane \
    -o jsonpath='{.items[0].metadata.name}')
if (( ${#workers[@]} != 2 )) || [[ -z ${source_node} ]]; then
    echo "egress qualification requires one control-plane and exactly two workers" >&2
    exit 1
fi
gateway_node=${workers[1]}
nodes_json=$("${kc[@]}" get nodes -o json)
if ! jq -e 'all(.items[]; any(.status.conditions[]; .type == "Ready" and .status == "True"))' \
    <<<"${nodes_json}" >/dev/null; then
    echo "every qualification Node must be Ready" >&2
    exit 1
fi
if ! jq -e 'all(.items[]; .metadata.labels["network.unf.io/primary-cni"] == "enabled")' \
    <<<"${nodes_json}" >/dev/null; then
    echo "every qualification Node must run the exclusive UNF primary CNI" >&2
    exit 1
fi

source_node_json=$(jq -c --arg node "${source_node}" \
    '.items[] | select(.metadata.name == $node)' <<<"${nodes_json}")
source_node_v4=$(jq -er '[.status.addresses[] | select(.type == "InternalIP" and (.address | contains(".")))][0].address' \
    <<<"${source_node_json}")
source_node_v6=$(jq -er '[.status.addresses[] | select(.type == "InternalIP" and (.address | contains(":")))][0].address' \
    <<<"${source_node_json}")
[[ ${source_node_v6} == *::* ]] || {
    echo "Kind IPv6 InternalIP must use the expected compressed /64 form" >&2
    exit 1
}
ipv4_prefix=${source_node_v4%.*}
ipv6_prefix=${source_node_v6%::*}
external_v4=${ipv4_prefix}.223
egress_v4=${ipv4_prefix}.240
external_v6=${ipv6_prefix}::df
egress_v6=${ipv6_prefix}::f0

qualification_stage=external-fixture
"${runtime[@]}" run -d --name "${external_container}" --network kind \
    --ip "${external_v4}" --ip6 "${external_v6}" --mac-address 02:55:4e:46:08:05 \
    --cap-add NET_ADMIN \
    --entrypoint /bin/sh "${test_tools_image}" -ec \
    '/usr/local/bin/unf-flow-receiver 18080 & exec /usr/bin/socat UDP6-RECVFROM:18081,ipv6only=0,reuseaddr,fork EXEC:/bin/cat' \
    >/dev/null
while read -r node; do
    "${runtime[@]}" exec "${node}" ip neigh del "${external_v4}" dev eth0 \
        >/dev/null 2>&1 || true
    "${runtime[@]}" exec "${node}" ip -6 neigh del "${external_v6}" dev eth0 \
        >/dev/null 2>&1 || true
done < <(jq -r '.items[].metadata.name' <<<"${nodes_json}")
while IFS=$'\t' read -r node_v4 node_v6 pod_v4 pod_v6; do
    "${runtime[@]}" exec "${external_container}" ip route replace "${pod_v4}" via "${node_v4}"
    "${runtime[@]}" exec "${external_container}" ip -6 route replace "${pod_v6}" via "${node_v6}"
done < <(jq -r '.items[] |
    ([.status.addresses[] | select(.type == "InternalIP" and (.address | contains(".")))][0].address) as $v4 |
    ([.status.addresses[] | select(.type == "InternalIP" and (.address | contains(":")) )][0].address) as $v6 |
    ([.spec.podCIDRs[] | select(contains("."))][0]) as $pod4 |
    ([.spec.podCIDRs[] | select(contains(":"))][0]) as $pod6 |
    [$v4,$v6,$pod4,$pod6] | @tsv' <<<"${nodes_json}")
"${runtime[@]}" exec "${external_container}" wget -T 2 -qO- \
    "http://127.0.0.1:18080/health" | grep -qx ok

qualification_stage=watched-intent
"${kc[@]}" label node "${gateway_node}" "${gateway_label}=enabled" --overwrite >/dev/null
resources_created=true
"${kc[@]}" apply -f - >/dev/null <<EOF
apiVersion: v1
kind: Namespace
metadata:
  name: ${namespace}
---
apiVersion: v1
kind: Pod
metadata:
  name: managed
  namespace: ${namespace}
  labels:
    app: managed
spec:
  nodeSelector:
    kubernetes.io/hostname: ${source_node}
  tolerations:
    - operator: Exists
  containers:
    - name: client
      image: ${test_tools_image}
      imagePullPolicy: Never
      command: [sh, -ec, "sleep infinity"]
---
apiVersion: v1
kind: Pod
metadata:
  name: native
  namespace: ${namespace}
  labels:
    app: native
spec:
  nodeSelector:
    kubernetes.io/hostname: ${source_node}
  tolerations:
    - operator: Exists
  containers:
    - name: client
      image: ${test_tools_image}
      imagePullPolicy: Never
      command: [sh, -ec, "sleep infinity"]
---
apiVersion: network.unf.io/v1alpha1
kind: EgressPool
metadata:
  name: ${pool}
spec:
  provider:
    name: static
    instance: kind
  prefixes:
    - ${egress_v4}/32
    - ${egress_v6}/128
---
apiVersion: network.unf.io/v1alpha1
kind: EgressPolicy
metadata:
  name: ${policy}
spec:
  priority: 100
  target:
    namespaceSelector:
      matchLabels:
        kubernetes.io/metadata.name: ${namespace}
    workloadSelector:
      matchLabels:
        app: managed
    serviceAccounts: [default]
  destinations:
    networks:
      - ${external_v4}/32
      - ${external_v6}/128
  egress:
    pool: ${pool}
    families: [IPv4, IPv6]
    addressesPerFamily: 1
EOF
"${kc[@]}" -n "${namespace}" wait --for=condition=Ready pod/managed pod/native --timeout=120s
managed_v4=$("${kc[@]}" -n "${namespace}" get pod managed \
    -o json | jq -er '[.status.podIPs[].ip | select(contains("."))][0]')
managed_v6=$("${kc[@]}" -n "${namespace}" get pod managed \
    -o json | jq -er '[.status.podIPs[].ip | select(contains(":"))][0]')
native_v4=$("${kc[@]}" -n "${namespace}" get pod native \
    -o json | jq -er '[.status.podIPs[].ip | select(contains("."))][0]')
native_v6=$("${kc[@]}" -n "${namespace}" get pod native \
    -o json | jq -er '[.status.podIPs[].ip | select(contains(":"))][0]')

controller_raw() {
    local path=$1 pod
    pod=$("${kc[@]}" -n unf-system get pods -l app.kubernetes.io/name=unf-controller \
        -o json | jq -r '.items[] | select(.metadata.deletionTimestamp == null and .status.phase == "Running") | .metadata.name' \
        | head -n 1)
    [[ -n ${pod} ]]
    "${kc[@]}" get --raw "/api/v1/namespaces/unf-system/pods/${pod}:9962/proxy${path}"
}

gateway_agent() {
    "${kc[@]}" -n unf-system get pods --field-selector "spec.nodeName=${gateway_node}" \
        -o json | jq -r '.items[] | select(.metadata.name | startswith("unf-agent-")) | .metadata.name' \
        | head -n 1
}

wait_for_activation() {
    local status=
    for _ in $(seq 1 180); do
        status=$(controller_raw /v1/status 2>/dev/null || true)
        if jq -e '
            .egress_source_applications == 1
            and .egress_gateway_applications >= 1
            and .egress_activation_ready_sources == 1
            and .agents.all_converged == true
        ' <<<"${status}" >/dev/null 2>&1; then
            printf '%s\n' "${status}"
            return 0
        fi
        sleep 1
    done
    echo "watched egress intent did not reach bilateral activation" >&2
    jq . <<<"${status}" >&2 || true
    return 1
}

assert_gateway_ownership() {
    "${runtime[@]}" exec "${gateway_node}" ip -o address show dev unf-egress0 \
        | rg --fixed-strings --quiet "${egress_v4}/32"
    "${runtime[@]}" exec "${gateway_node}" ip -o -6 address show dev unf-egress0 \
        | rg --fixed-strings --quiet "${egress_v6}/128"
    [[ $("${runtime[@]}" exec "${gateway_node}" \
        cat /proc/sys/net/ipv6/conf/eth0/proxy_ndp) == 1 ]]
    "${runtime[@]}" exec "${gateway_node}" ip -6 neigh show proxy \
        | rg --fixed-strings --quiet "${egress_v6} dev eth0 proxy"
}

native_peer_matrix() {
    local observed= success=false
    for _ in $(seq 1 5); do
        observed=$("${kc[@]}" -n "${namespace}" exec native -- \
            wget -T 4 -t 1 -qO- "http://${external_v4}:18080/peer" 2>/dev/null || true)
        if [[ ${observed} == "${native_v4}" ]]; then success=true; break; fi
        sleep 1
    done
    [[ ${success} == true ]]
    success=false
    for _ in $(seq 1 5); do
        observed=$("${kc[@]}" -n "${namespace}" exec native -- \
            wget -T 4 -t 1 -qO- "http://[${external_v6}]:18080/peer" 2>/dev/null || true)
        if [[ ${observed} == "${native_v6}" ]]; then success=true; break; fi
        sleep 1
    done
    [[ ${success} == true ]]
}

managed_udp_matrix() {
    local suffix=$1
    local observed= success=false
    for _ in $(seq 1 5); do
        observed=$("${kc[@]}" -n "${namespace}" exec managed -- sh -ec \
            "printf 'managed-v4-${suffix}' | socat -T 4 - UDP4:${external_v4}:18081" \
            2>/dev/null || true)
        if [[ ${observed} == "managed-v4-${suffix}" ]]; then success=true; break; fi
        sleep 1
    done
    [[ ${success} == true ]]
    success=false
    for _ in $(seq 1 5); do
        observed=$("${kc[@]}" -n "${namespace}" exec managed -- sh -ec \
            "printf 'managed-v6-${suffix}' | socat -T 4 - UDP6:[${external_v6}]:18081" \
            2>/dev/null || true)
        if [[ ${observed} == "managed-v6-${suffix}" ]]; then success=true; break; fi
        sleep 1
    done
    [[ ${success} == true ]]
}

control_plane_state() {
    "${kc[@]}" -n unf-system get configmap unf-egress-control-plane \
        -o json | jq -er '.data["state.json"] | fromjson'
}

wait_for_release() {
    local state=
    for _ in $(seq 1 90); do
        native_peer_matrix
        state=$(control_plane_state)
        if jq -e '
            (.allocation.leases | length) == 0
            and (.gateways.records | length) == 0
            and (.retirements | length) == 0
        ' <<<"${state}" >/dev/null \
            && ! "${runtime[@]}" exec "${gateway_node}" ip -o address show dev unf-egress0 \
                | rg --fixed-strings --quiet "${egress_v4}" \
            && ! "${runtime[@]}" exec "${gateway_node}" ip -o -6 address show dev unf-egress0 \
                | rg --fixed-strings --quiet "${egress_v6}" \
            && ! "${runtime[@]}" exec "${gateway_node}" ip -6 neigh show proxy \
                | rg --fixed-strings --quiet "${egress_v6}"; then
            printf '%s\n' "${state}"
            return 0
        fi
        sleep 2
    done
    echo "egress retirement did not reach safe host release" >&2
    jq . <<<"${state}" >&2 || true
    return 1
}

qualification_stage=bilateral-traffic
initial_status=$(wait_for_activation)
assert_gateway_ownership
initial_state=$(control_plane_state)
initial_epoch=$(jq -er '.allocation.leases[0].leaseEpoch' <<<"${initial_state}")
traffic_since=$(date -u +%Y-%m-%dT%H:%M:%SZ)
native_peer_matrix
managed_udp_matrix initial
gateway_pod=$(gateway_agent)
for _ in $(seq 1 30); do
    gateway_logs=$("${kc[@]}" -n unf-system logs "${gateway_pod}" --since-time="${traffic_since}" 2>/dev/null || true)
    if rg --fixed-strings --quiet '"message":"egress NAT lifecycle outcome"' <<<"${gateway_logs}" \
        && rg --fixed-strings --quiet "${egress_v4}" <<<"${gateway_logs}" \
        && rg --fixed-strings --quiet "${egress_v6}" <<<"${gateway_logs}"; then
        break
    fi
    sleep 1
done
rg --fixed-strings --quiet "${egress_v4}" <<<"${gateway_logs}"
rg --fixed-strings --quiet "${egress_v6}" <<<"${gateway_logs}"

qualification_stage=restart-recovery
"${kc[@]}" -n unf-system rollout restart deployment/unf-controller >/dev/null
"${kc[@]}" -n unf-system rollout status deployment/unf-controller --timeout=180s
restart_status=$(wait_for_activation)
assert_gateway_ownership
native_peer_matrix
managed_udp_matrix controller-restart
"${kc[@]}" -n unf-system rollout restart daemonset/unf-agent >/dev/null
"${kc[@]}" -n unf-system rollout status daemonset/unf-agent --timeout=180s
agent_restart_status=$(wait_for_activation)
assert_gateway_ownership
native_peer_matrix
managed_udp_matrix agent-restart

qualification_stage=withdrawal-and-safe-release
"${kc[@]}" delete egresspolicy.network.unf.io "${policy}" --wait=true >/dev/null
released_state=$(wait_for_release)

qualification_stage=safe-reuse
"${kc[@]}" apply -f - >/dev/null <<EOF
apiVersion: network.unf.io/v1alpha1
kind: EgressPolicy
metadata:
  name: ${policy}
spec:
  priority: 100
  target:
    namespaceSelector:
      matchLabels:
        kubernetes.io/metadata.name: ${namespace}
    workloadSelector:
      matchLabels:
        app: managed
    serviceAccounts: [default]
  destinations:
    networks: [${external_v4}/32, ${external_v6}/128]
  egress:
    pool: ${pool}
    families: [IPv4, IPv6]
    addressesPerFamily: 1
EOF
reused_status=$(wait_for_activation)
assert_gateway_ownership
reused_state=$(control_plane_state)
reused_epoch=$(jq -er '.allocation.leases[0].leaseEpoch' <<<"${reused_state}")
(( reused_epoch > initial_epoch ))
jq -e --arg v4 "${egress_v4}" --arg v6 "${egress_v6}" '
    .allocation.leases[0].addresses == [$v4, $v6]
' <<<"${reused_state}" >/dev/null
native_peer_matrix
managed_udp_matrix safe-reuse

qualification_stage=final-release
"${kc[@]}" delete egresspolicy.network.unf.io "${policy}" --wait=true >/dev/null
final_state=$(wait_for_release)
"${kc[@]}" delete egresspool.network.unf.io "${pool}" --wait=true >/dev/null
"${kc[@]}" delete namespace "${namespace}" --wait=true --timeout=120s >/dev/null
"${kc[@]}" label node "${gateway_node}" "${gateway_label}-" >/dev/null
resources_created=false

qualification_stage=evidence
collect_diagnostics
mkdir -p "$(dirname "${artifact}")"
revision=$(git -C "${project_root}" rev-parse HEAD)
kubernetes_version=$("${kc[@]}" version -o json | jq -r '.serverVersion.gitVersion')
images=$("${kc[@]}" -n unf-system get pods \
    -l 'app.kubernetes.io/name in (unf-controller,unf-agent)' -o json | jq \
    '[.items[] | {name:.metadata.name,node:(.spec.nodeName // null),image:.spec.containers[0].image,imageID:(.status.containerStatuses[0].imageID // null)}]')
jq -n \
    --arg generatedAt "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --arg revision "${revision}" \
    --arg context "${context}" \
    --arg kubernetesVersion "${kubernetes_version}" \
    --arg sourceNode "${source_node}" \
    --arg gatewayNode "${gateway_node}" \
    --arg externalIPv4 "${external_v4}" \
    --arg externalIPv6 "${external_v6}" \
    --arg egressIPv4 "${egress_v4}" \
    --arg egressIPv6 "${egress_v6}" \
    --arg diagnostics "${diagnostics_dir}" \
    --argjson initialEpoch "${initial_epoch}" \
    --argjson reusedEpoch "${reused_epoch}" \
    --argjson images "${images}" \
    --argjson initialStatus "${initial_status}" \
    --argjson controllerRestartStatus "${restart_status}" \
    --argjson agentRestartStatus "${agent_restart_status}" \
    --argjson reusedStatus "${reused_status}" \
    '{schemaVersion:1,generatedAt:$generatedAt,revision:$revision,context:$context,
      kubernetesVersion:$kubernetesVersion,kubeProxyPresent:false,
      topology:{sourceNode:$sourceNode,gatewayNode:$gatewayNode},
      fixture:{externalIPv4:$externalIPv4,externalIPv6:$externalIPv6,
        egressIPv4:$egressIPv4,egressIPv6:$egressIPv6},
      lifecycle:{initialLeaseEpoch:$initialEpoch,reusedLeaseEpoch:$reusedEpoch,
        safeReuseMonotonic:($reusedEpoch > $initialEpoch),finalReleaseComplete:true},
      status:{initial:$initialStatus,controllerRestart:$controllerRestartStatus,
        agentRestart:$agentRestartStatus,reused:$reusedStatus},
      images:$images,diagnostics:$diagnostics,
      verified:["exclusive UNF primary CNI","watched dual-stack EgressPool and EgressPolicy",
        "explicit Ready gateway selection","exact Node-UID-bound address ownership",
        "proxy-NDP IPv6 ownership","bilateral source and gateway activation",
        "policy-first dual-stack source steering","IPv4 and IPv6 UDP gateway NAT and reverse traffic",
        "exact sparse NAT witnesses","unrelated native egress source preservation",
        "controller restart recovery","agent restart and address readback recovery",
        "source fencing","lease-specific NAT drain","reachability withdrawal",
        "host address and proxy removal","Proof of Safe Forgetting release",
        "same-address reuse under a monotonic lease epoch","final clean release"]}' \
    >"${artifact}.tmp"
mv "${artifact}.tmp" "${artifact}"

"${runtime[@]}" rm -f "${external_container}" >/dev/null
trap - ERR EXIT
echo "Phase 8.5 dual-stack Kind egress lifecycle passed; evidence: ${artifact}; diagnostics: ${diagnostics_dir}"
