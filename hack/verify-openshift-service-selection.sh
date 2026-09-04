#!/usr/bin/env bash
set -Eeuo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
kubeconfig=${KUBECONFIG:-"${project_root}/.tools/cl02-audit.kubeconfig"}
context=${KUBE_CONTEXT:-}
expected_infrastructure=${UNF_OPENSHIFT_SERVICE_SELECTION_EXPECTED_INFRASTRUCTURE:-}
acknowledgement=${UNF_OPENSHIFT_SERVICE_SELECTION_ACKNOWLEDGE_DISPOSABLE:-}
release_record=${UNF_OPENSHIFT_SERVICE_SELECTION_RELEASE_RECORD:-"${project_root}/deploy/openshift-primary-cni/service-selection/release.json"}
deploy_evidence=${UNF_OPENSHIFT_SERVICE_SELECTION_DEPLOY_EVIDENCE:-"${project_root}/.artifacts/phase7-service-selection-openshift-deploy.json"}
regression_evidence=${UNF_OPENSHIFT_SERVICE_SELECTION_REGRESSION_EVIDENCE:-"${project_root}/.artifacts/phase7-service-selection-openshift-loadbalancer.json"}
artifact=${UNF_OPENSHIFT_SERVICE_SELECTION_EVIDENCE:-"${project_root}/.artifacts/phase7-service-selection-openshift.json"}
namespace=unf-service-selection-qualification
advertiser_label=qualification.unf.io/service-selection-advertiser
stage=initialization
started_unix=$(date +%s)
controller_scaled_down=false
namespace_created=false
advertiser_created=false
dsr_routes_created=false
zones_changed=false
artifact_tmp=
probe_pid=

failure() {
    local status=$?
    echo "OpenShift service-selection qualification failed during ${stage} at line ${BASH_LINENO[0]}: ${BASH_COMMAND}" >&2
    return "${status}"
}

restore_zones() {
    [[ ${zones_changed} == true ]] || return 0
    while IFS=$'\t' read -r node present value; do
        if [[ ${present} == true ]]; then
            "${kc[@]}" label node "${node}" "topology.kubernetes.io/zone=${value}" --overwrite >/dev/null 2>&1 || true
        else
            "${kc[@]}" label node "${node}" topology.kubernetes.io/zone- >/dev/null 2>&1 || true
        fi
    done < <(jq -r '.[] | [.name,(.present|tostring),.value] | @tsv' <<<"${original_zones:-[]}")
    zones_changed=false
}

cleanup() {
    local status=$?
    trap - ERR EXIT
    set +e
    [[ -z ${probe_pid} ]] || { kill "${probe_pid}" >/dev/null 2>&1 || true; wait "${probe_pid}" >/dev/null 2>&1 || true; }
    if [[ ${controller_scaled_down} == true ]]; then
        "${kc[@]}" -n unf-system scale deployment/unf-controller --replicas=1 >/dev/null 2>&1 || true
    fi
    if [[ ${advertiser_created} == true ]]; then
        advertiser=$("${kc[@]}" -n "${namespace}" get pod -l "${advertiser_label}=true" -o name 2>/dev/null | head -1)
        if [[ -n ${advertiser} ]]; then
            "${kc[@]}" -n "${namespace}" exec "${advertiser}" -- sh -euc '
                ip -4 address del "$1/32" dev br-ex >/dev/null 2>&1 || true
                ip -6 address del "$2/128" dev br-ex >/dev/null 2>&1 || true
            ' sh "${dsr_v4:-}" "${dsr_v6:-}" >/dev/null 2>&1 || true
        fi
    fi
    if [[ ${dsr_routes_created} == true ]]; then
        "${kc[@]}" debug "node/${remote_node}" --quiet -- chroot /host sh -euc '
            ip -4 route del "$1/32" via "$2" >/dev/null 2>&1 || true
            ip -6 route del "$3/128" via "$4" >/dev/null 2>&1 || true
        ' sh "${dsr_v4:-}" "${remote_v4:-}" "${dsr_v6:-}" "${remote_v6:-}" >/dev/null 2>&1 || true
    fi
    if [[ ${namespace_created} == true ]]; then
        "${kc[@]}" delete namespace "${namespace}" --ignore-not-found --wait=false >/dev/null 2>&1 || true
    fi
    restore_zones
    [[ -z ${artifact_tmp} ]] || rm -f -- "${artifact_tmp}"
    exit "${status}"
}
trap failure ERR
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

for command in curl git ip jq oc python3 sed socat stat timeout; do
    command -v "${command}" >/dev/null || {
        echo "OpenShift service-selection prerequisite is missing: ${command}" >&2
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
if ! jq -e '
    .schemaVersion == 1 and .phase == "7.10"
    and (.sourceRevision | test("^[0-9a-f]{40}$"))
    and .kindQualification.phase == "7.9" and .kindQualification.result == "passed"
    and .contracts.persistentBpfStateAbiVersion == 11
    and .contracts.serviceSnapshotSchemaVersion == 4
    and .contracts.selectionContractSchemaVersion == 1
    and .contracts.agentStatusSchemaVersion == 8
    and .contracts.flowExportSchemaVersion == 6
    and all(.images[]; test("^quay\\.io/arencloud/unf-[a-z-]+-dev@sha256:[0-9a-f]{64}$"))
' "${release_record}" >/dev/null; then
    echo "Phase 7.10 release record is missing or invalid" >&2
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
    echo "refusing qualification: both service-selection acknowledgements must equal ${infrastructure}" >&2
    exit 1
fi
jq -e --arg context "${context}" --arg infrastructure "${infrastructure}" --arg revision "${source_revision}" '
    .schemaVersion == 1 and .phase == "7.10" and .stage == "abi-v11-service-selection-staged-deployment"
    and .context == $context and .infrastructure == $infrastructure and .sourceRevision == $revision
    and .kubeProxyPresent == false and .persistentBpfAbi == 11
    and .serviceSnapshotSchemaVersion == 4 and .selectionContractSchemaVersion == 1
    and .agentStatusSchemaVersion == 8 and .agents.all_converged == true
' "${deploy_evidence}" >/dev/null

stage=phase6-loadbalancer-regression
UNF_OPENSHIFT_LOADBALANCER_EXPECTED_INFRASTRUCTURE="${infrastructure}" \
UNF_OPENSHIFT_LOADBALANCER_ACKNOWLEDGE_DISPOSABLE="${infrastructure}" \
UNF_OPENSHIFT_LOADBALANCER_RELEASE_RECORD="${release_record}" \
UNF_OPENSHIFT_LOADBALANCER_DEPLOY_EVIDENCE="${deploy_evidence}" \
UNF_OPENSHIFT_LOADBALANCER_EVIDENCE="${regression_evidence}" \
KUBECONFIG="${kubeconfig}" KUBE_CONTEXT="${context}" \
    "${project_root}/hack/verify-openshift-loadbalancer.sh"
jq -e --arg revision "${source_revision}" '
    .phase == "7.10" and .scope == "loadbalancer-regression" and .result == "passed"
    and .sourceRevision == $revision and .persistentBpfAbi == 11
    and .kubeProxyPresent == false and .agents.all_converged == true
' "${regression_evidence}" >/dev/null

controller_pod() {
    "${kc[@]}" -n unf-system get pods -l app.kubernetes.io/name=unf-controller -o json \
        | jq -r '.items[] | select(.metadata.deletionTimestamp == null and .status.phase == "Running") | .metadata.name' \
        | head -1
}

controller_raw() {
    local path=$1 pod
    pod=$(controller_pod); [[ -n ${pod} ]]
    timeout 20 "${kc[@]}" get --raw "/api/v1/namespaces/unf-system/pods/${pod}:9962/proxy${path}"
}

agent_pod_on_node() {
    local node=$1
    "${kc[@]}" -n unf-system get pods -l app.kubernetes.io/name=unf-agent -o json \
        | jq -r --arg node "${node}" '.items[] | select(.spec.nodeName == $node and .metadata.deletionTimestamp == null) | .metadata.name' \
        | head -1
}

agent_raw() {
    local node=$1 path=$2 pod response=
    for _ in $(seq 1 10); do
        pod=$(agent_pod_on_node "${node}" 2>/dev/null || true)
        if [[ -n ${pod} ]] && response=$(timeout 20 "${kc[@]}" get --raw \
            "/api/v1/namespaces/unf-system/pods/${pod}:9963/proxy${path}" 2>/dev/null); then
            printf '%s\n' "${response}"
            return 0
        fi
        sleep 1
    done
    echo "agent proxy ${node}${path} did not recover from API transport errors" >&2
    return 1
}

node_address() {
    local node=$1 family=$2
    "${kc[@]}" get node "${node}" -o json | jq -er --arg family "${family}" '
        [.status.addresses[] | select(.type == "InternalIP") | .address
         | select(if $family == "4" then contains(".") else contains(":") end)][0]'
}

unhealthy_operators() {
    "${kc[@]}" get clusteroperators -o json | jq -c '[.items[]
        | select(any(.status.conditions[];
            (.type == "Available" and .status != "True")
            or (.type == "Degraded" and .status == "True")))
        | .metadata.name] | sort'
}

wait_for_convergence() {
    local snapshot=
    for _ in $(seq 1 900); do
        snapshot=$(controller_raw /v1/state/agents 2>/dev/null || true)
        if jq -e --argjson expected "${#nodes[@]}" '
            .schema_version == 8 and .expected_agents == $expected
            and .reporting_agents == $expected and .missing_agents == 0
            and .stale_agents == 0 and .converged_agents == $expected
            and .unexpected_agents == 0 and .all_converged
            and all(.nodes[]; .fresh and .converged and .report.ready and .report.bpf_loaded
                and .report.service_snapshot_schema_version == 4
                and .report.selection_contract_schema_version == 1
                and .report.applied_selection_contract_revision == .report.desired_selection_contract_revision
                and .report.applied_selection_contract_digest == .report.desired_selection_contract_digest)
        ' <<<"${snapshot}" >/dev/null 2>&1; then
            printf '%s\n' "${snapshot}"
            return 0
        fi
        sleep 1
    done
    echo "five OpenShift service-selection agents did not converge" >&2
    jq . <<<"${snapshot}" >&2 || true
    return 1
}

service_addresses() {
    "${kc[@]}" -n "${namespace}" get service "$1" -o json | jq -r '.spec.clusterIPs[]'
}

pod_addresses() {
    "${kc[@]}" -n "${namespace}" get pod "$1" -o json | jq -r '.status.podIPs[].ip'
}

canonical_ip() {
    python3 -c 'import ipaddress,sys; print(ipaddress.ip_address(sys.argv[1].strip("[]")))' "$1"
}

cluster_simulation() {
    controller_raw "/v1/services/clusterip/simulate?node_name=${client_node}&address=$1&port=$3&protocol=$2"
}

wait_for_service() {
    local name=$1 address port protocol snapshot=
    address=$("${kc[@]}" -n "${namespace}" get service "${name}" -o json | jq -er '[.spec.clusterIPs[] | select(contains("."))][0]')
    port=$("${kc[@]}" -n "${namespace}" get service "${name}" -o json | jq -er '.spec.ports[0].port')
    protocol=$("${kc[@]}" -n "${namespace}" get service "${name}" -o json | jq -er '.spec.ports[0].protocol | ascii_downcase')
    for _ in $(seq 1 300); do
        snapshot=$(cluster_simulation "${address}" "${protocol}" "${port}" 2>/dev/null || true)
        if jq -e --arg namespace "${namespace}" --arg name "${name}" '
            .schema_version == 1 and .namespace == $namespace and .name == $name
            and .selection_contract_revision > 0' <<<"${snapshot}" >/dev/null 2>&1; then
            wait_for_convergence >/dev/null
            return 0
        fi
        sleep 1
    done
    echo "Service ${namespace}/${name} did not compile" >&2
    return 1
}

tcp_probe() {
    local address=$1 target
    if [[ ${address} == *:* ]]; then target="http://[${address}]:8080/health"; else target="http://${address}:8080/health"; fi
    "${kc[@]}" -n "${namespace}" exec client -- wget -T 5 -t 1 -qO- "${target}" | grep -qx ok
}

udp_probe() {
    local family=$1 address=$2 source_port=$3 target output=
    if [[ ${family} == 4 ]]; then target="UDP4:${address}:5353"; else target="UDP6:[${address}]:5353"; fi
    for _ in $(seq 1 10); do
        output=$("${kc[@]}" -n "${namespace}" exec client -- sh -ec \
            "printf selection-${source_port} | socat -T 2 - '${target},sourceport=${source_port}'" 2>/dev/null || true)
        [[ ${output} == "selection-${source_port}" ]] && return 0
        sleep 1
    done
    echo "UDP probe to ${target} from source port ${source_port} did not echo" >&2
    return 1
}

wait_for_history() {
    local address=$1 assertion=$2 history=
    local since_ms=$((started_unix * 1000))
    for _ in $(seq 1 300); do
        # cl02 produces enough background Service traffic to evict a
        # qualification flow from the API's default history window before
        # the proxied request completes. Query the full bounded run window so
        # locality and affinity evidence is retained without accepting stale
        # entries from an earlier qualification.
        history=$(controller_raw "/v1/flows?since_unix_ms=${since_ms}&limit=4096" 2>/dev/null || true)
        if jq -e --arg address "${address}" ".schema_version == 7 and (${assertion})" \
            <<<"${history}" >/dev/null 2>&1; then
            printf '%s\n' "${history}"
            return 0
        fi
        sleep 1
    done
    echo "advanced service history assertion timed out: ${assertion}" >&2
    return 1
}

wait_for_algorithm_history() {
    local address=$1 family=$2 algorithm=$3 source_port=$4 history=
    local since_ms=$((started_unix * 1000)) attempt
    for attempt in $(seq 1 120); do
        # A busy OpenShift cluster can evict a one-shot selection event before
        # the API proxy returns it. Use a new tuple immediately before each
        # bounded query so the dataplane algorithm is observed directly.
        udp_probe "${family}" "${address}" "$((source_port + attempt))"
        history=$(controller_raw "/v1/flows?since_unix_ms=${since_ms}&limit=4096" 2>/dev/null || true)
        if jq -e --arg address "${address}" --arg algorithm "${algorithm}" '
            .schema_version == 7
            and any(.entries[]; .key.destination_ipv4 == $address
                and .service.selection_algorithm == $algorithm)
        ' <<<"${history}" >/dev/null 2>&1; then
            printf '%s\n' "${history}"
            return 0
        fi
    done
    echo "advanced service algorithm history assertion timed out: ${algorithm}" >&2
    return 1
}

wait_for_dsr_history() {
    local address=$1 history= since_ms=$((started_unix * 1000))
    for _ in $(seq 1 120); do
        # cl02 has enough background Service traffic to evict a one-shot event
        # quickly. Generate a fresh DSR flow immediately before the bounded
        # time-window query so history integration is observed, not inferred.
        "${kc[@]}" -n "${namespace}" exec selection-external -- \
            wget -T 10 -t 1 -qO- "http://${address}:8080/health" >/dev/null 2>&1 || true
        history=$(controller_raw "/v1/flows?since_unix_ms=${since_ms}&limit=4096" 2>/dev/null || true)
        if jq -e --arg address "${address}" '
            any(.entries[]; .key.destination_ipv4 == $address
                and .service.forwarding_mode == "dsr" and .service.action == 1)
        ' <<<"${history}" >/dev/null 2>&1; then
            printf '%s\n' "${history}"
            return 0
        fi
        sleep 1
    done
    echo "fresh DSR flow did not appear in bounded history" >&2
    return 1
}

replace_endpoint_condition() {
    local slice=$1 address=$2 ready=$3 serving=$4 terminating=$5
    "${kc[@]}" -n "${namespace}" get endpointslice "${slice}" -o json \
        | jq --arg address "${address}" --argjson ready "${ready}" --argjson serving "${serving}" \
            --argjson terminating "${terminating}" '
            .endpoints |= map(if .addresses[0] == $address then
                .conditions = {ready:$ready,serving:$serving,terminating:$terminating}
            else . end)
            | del(.metadata.resourceVersion,.metadata.uid,.metadata.creationTimestamp,.metadata.generation,.metadata.managedFields)
        ' | "${kc[@]}" replace -f - >/dev/null
}

apply_backend() {
    local name=$1 node=$2 privileged=${3:-false} toleration= security= account= pod_security=
    [[ ${node} == "${same_zone_node}" ]] && toleration=$'  tolerations:\n    - operator: Exists'
    if [[ ${privileged} == true ]]; then
        account='  serviceAccountName: selection-privileged'
        security='      securityContext: {privileged: true}'
        pod_security='  securityContext: {runAsNonRoot: false, seccompProfile: {type: RuntimeDefault}}'
    else
        security='      securityContext: {allowPrivilegeEscalation: false, capabilities: {drop: [ALL]}}'
        pod_security='  securityContext: {runAsNonRoot: true, seccompProfile: {type: RuntimeDefault}}'
    fi
    "${kc[@]}" apply -f - >/dev/null <<EOF
apiVersion: v1
kind: Pod
metadata: {name: ${name}, namespace: ${namespace}}
spec:
${account}
  nodeSelector: {kubernetes.io/hostname: ${node}}
${toleration}
${pod_security}
  containers:
    - name: server
      image: ${test_tools_image}
      imagePullPolicy: IfNotPresent
${security}
      command: [sh, -ec]
      args:
        - |
          /usr/local/bin/unf-udp-echo 4 5353 &
          /usr/local/bin/unf-udp-echo 6 5353 &
          socat TCP4-LISTEN:8081,reuseaddr,fork 'SYSTEM:echo \$SOCAT_PEERADDR' &
          socat TCP6-LISTEN:8081,reuseaddr,fork,ipv6-v6only=1 'SYSTEM:echo \$SOCAT_PEERADDR' &
          exec /usr/local/bin/unf-flow-receiver 8080
EOF
}

stage=platform-and-topology-preflight
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
mapfile -t masters < <("${kc[@]}" get nodes -l node-role.kubernetes.io/master -o name | sed 's|node/||' | sort)
[[ ${#nodes[@]} -eq 5 && ${#workers[@]} -eq 2 && ${#masters[@]} -eq 3 ]]
client_node=${workers[0]}; remote_node=${workers[1]}; same_zone_node=${masters[0]}
baseline_unhealthy=$(unhealthy_operators)
baseline_status=$(controller_raw /v1/status)
baseline_services=$(jq -er .compiled_services <<<"${baseline_status}")
baseline_frontends=$(jq -er .compiled_service_frontends <<<"${baseline_status}")
baseline_backends=$(jq -er .compiled_service_backends <<<"${baseline_status}")
original_zones=$("${kc[@]}" get nodes -o json | jq '[.items[] | {
    name:.metadata.name,present:(.metadata.labels | has("topology.kubernetes.io/zone")),
    value:(.metadata.labels["topology.kubernetes.io/zone"] // "")}]')
zones_changed=true
for node in "${nodes[@]}"; do "${kc[@]}" label node "${node}" topology.kubernetes.io/zone=zone-b --overwrite >/dev/null; done
"${kc[@]}" label node "${client_node}" topology.kubernetes.io/zone=zone-a --overwrite >/dev/null
"${kc[@]}" label node "${same_zone_node}" topology.kubernetes.io/zone=zone-a --overwrite >/dev/null
wait_for_convergence >/dev/null

stage=advanced-fixture-creation
"${kc[@]}" delete namespace "${namespace}" --ignore-not-found --wait=true --timeout=300s >/dev/null
"${kc[@]}" create namespace "${namespace}" >/dev/null
namespace_created=true
"${kc[@]}" -n "${namespace}" create serviceaccount selection-privileged >/dev/null
"${kc[@]}" -n "${namespace}" create rolebinding selection-privileged-scc \
    --clusterrole=system:openshift:scc:privileged --serviceaccount="${namespace}:selection-privileged" >/dev/null
apply_backend backend-node "${client_node}"
apply_backend backend-zone "${same_zone_node}"
apply_backend backend-remote "${remote_node}" true
"${kc[@]}" apply -f - >/dev/null <<EOF
apiVersion: v1
kind: Pod
metadata: {name: client, namespace: ${namespace}}
spec:
  nodeSelector: {kubernetes.io/hostname: ${client_node}}
  securityContext: {runAsNonRoot: true, seccompProfile: {type: RuntimeDefault}}
  containers:
    - name: client
      image: ${test_tools_image}
      imagePullPolicy: IfNotPresent
      securityContext: {allowPrivilegeEscalation: false, capabilities: {drop: [ALL]}}
      command: [sh, -ec, "sleep infinity"]
---
apiVersion: v1
kind: Service
metadata:
  name: selection
  namespace: ${namespace}
  annotations: {network.unf.io/service-selection-algorithm: maglev}
spec:
  ipFamilyPolicy: RequireDualStack
  ipFamilies: [IPv4, IPv6]
  internalTrafficPolicy: Cluster
  trafficDistribution: PreferSameNode
  sessionAffinity: ClientIP
  sessionAffinityConfig: {clientIP: {timeoutSeconds: 3}}
  ports:
    - {name: http, protocol: TCP, port: 8080, targetPort: 8080}
    - {name: echo, protocol: UDP, port: 5353, targetPort: 5353}
EOF
"${kc[@]}" -n "${namespace}" wait --for=condition=Ready pod --all --timeout=300s >/dev/null
mapfile -t node_ips < <(pod_addresses backend-node); node_v4=${node_ips[0]}; node_v6=${node_ips[1]}
mapfile -t zone_ips < <(pod_addresses backend-zone); zone_v4=${zone_ips[0]}; zone_v6=${zone_ips[1]}
mapfile -t remote_ips < <(pod_addresses backend-remote); remote_v4=${remote_ips[0]}; remote_v6=${remote_ips[1]}
"${kc[@]}" apply -f - >/dev/null <<EOF
apiVersion: discovery.k8s.io/v1
kind: EndpointSlice
metadata: {name: selection-v4, namespace: ${namespace}, labels: {kubernetes.io/service-name: selection}}
addressType: IPv4
ports: [{name: http, protocol: TCP, port: 8080}, {name: echo, protocol: UDP, port: 5353}]
endpoints:
  - {addresses: [${node_v4}], nodeName: ${client_node}, zone: zone-a, conditions: {ready: true, serving: true, terminating: false}}
  - {addresses: [${zone_v4}], nodeName: ${same_zone_node}, zone: zone-a, conditions: {ready: true, serving: true, terminating: false}}
  - {addresses: [${remote_v4}], nodeName: ${remote_node}, zone: zone-b, conditions: {ready: true, serving: true, terminating: false}}
---
apiVersion: discovery.k8s.io/v1
kind: EndpointSlice
metadata: {name: selection-v6, namespace: ${namespace}, labels: {kubernetes.io/service-name: selection}}
addressType: IPv6
ports: [{name: http, protocol: TCP, port: 8080}, {name: echo, protocol: UDP, port: 5353}]
endpoints:
  - {addresses: [${node_v6}], nodeName: ${client_node}, zone: zone-a, conditions: {ready: true, serving: true, terminating: false}}
  - {addresses: [${zone_v6}], nodeName: ${same_zone_node}, zone: zone-a, conditions: {ready: true, serving: true, terminating: false}}
  - {addresses: [${remote_v6}], nodeName: ${remote_node}, zone: zone-b, conditions: {ready: true, serving: true, terminating: false}}
EOF
wait_for_service selection
mapfile -t selection_vips < <(service_addresses selection); selection_v4=${selection_vips[0]}; selection_v6=${selection_vips[1]}

stage=locality-affinity-and-draining
same_node_simulation=$(cluster_simulation "${selection_v4}" udp 5353)
jq -e --arg backend "${node_v4}" '.decision == "translate" and .selection_tier == "sameNode"
    and .selection_algorithm == "maglev" and .session_affinity.mode == "clientIp"
    and .session_affinity.timeoutSeconds == 3 and .forwarding_mode == "nat"
    and any(.eligible_backends[]; .address == $backend)' <<<"${same_node_simulation}" >/dev/null
tcp_probe "${selection_v4}"; tcp_probe "${selection_v6}"
probe_base=$((40000 + $(date +%s) % 15000))
udp_probe 4 "${selection_v4}" "$((probe_base + 1))"
udp_probe 4 "${selection_v4}" "$((probe_base + 2))"
wait_for_history "${selection_v4}" 'any(.entries[]; .key.destination_ipv4 == $address
    and .service.selection_tier == "same_node" and .service.affinity_outcome == "created")
    and any(.entries[]; .key.destination_ipv4 == $address and .service.affinity_outcome == "reused")' >/dev/null
replace_endpoint_condition selection-v4 "${node_v4}" false false true
replace_endpoint_condition selection-v6 "${node_v6}" false false true
wait_for_convergence >/dev/null
same_zone_simulation=$(cluster_simulation "${selection_v4}" udp 5353)
jq -e --arg backend "${zone_v4}" '.decision == "translate" and .selection_tier == "sameZone"
    and any(.eligible_backends[]; .address == $backend)' <<<"${same_zone_simulation}" >/dev/null
udp_probe 4 "${selection_v4}" "$((probe_base + 3))"
wait_for_history "${selection_v4}" 'any(.entries[]; .key.destination_ipv4 == $address
    and .service.selection_tier == "same_zone" and .service.affinity_outcome == "reselected")' >/dev/null
sleep 4
replace_endpoint_condition selection-v4 "${zone_v4}" false false true
replace_endpoint_condition selection-v6 "${zone_v6}" false false true
wait_for_convergence >/dev/null
cluster_simulation_result=$(cluster_simulation "${selection_v6}" tcp 8080)
jq -e --arg backend "${remote_v6}" '.decision == "translate" and .selection_tier == "cluster"
    and any(.eligible_backends[]; .address == $backend)' <<<"${cluster_simulation_result}" >/dev/null
tcp_probe "${selection_v4}"; tcp_probe "${selection_v6}"

stage=maglev-stable-hash-and-provenance
for tuple in "selection-v4 ${node_v4}" "selection-v6 ${node_v6}" "selection-v4 ${zone_v4}" "selection-v6 ${zone_v6}"; do
    read -r slice address <<<"${tuple}"; replace_endpoint_condition "${slice}" "${address}" true true false
done
"${kc[@]}" -n "${namespace}" patch service selection --type=json -p='[
  {"op":"remove","path":"/spec/trafficDistribution"},
  {"op":"replace","path":"/spec/sessionAffinity","value":"None"},
  {"op":"remove","path":"/spec/sessionAffinityConfig"}
]' >/dev/null
wait_for_convergence >/dev/null
maglev_simulation=$(cluster_simulation "${selection_v4}" udp 5353)
jq -e '.selection_tier == "cluster" and .selection_algorithm == "maglev"
    and (.eligible_backend_ids | length) == 3' <<<"${maglev_simulation}" >/dev/null
for offset in $(seq 10 25); do udp_probe 4 "${selection_v4}" "$((probe_base + offset))"; done
wait_for_algorithm_history "${selection_v4}" 4 maglev "$((probe_base + 100))" >/dev/null
"${kc[@]}" -n "${namespace}" annotate service selection \
    network.unf.io/service-selection-algorithm=stable-hash --overwrite >/dev/null
wait_for_convergence >/dev/null
stable_simulation=$(cluster_simulation "${selection_v6}" udp 5353)
jq -e '.selection_tier == "cluster" and .selection_algorithm == "stableHash"
    and (.eligible_backend_ids | length) == 3' <<<"${stable_simulation}" >/dev/null
for offset in $(seq 30 37); do udp_probe 6 "${selection_v6}" "$((probe_base + offset))"; done

stage=acknowledged-cross-worker-dsr
"${kc[@]}" -n "${namespace}" apply -f - >/dev/null <<EOF
apiVersion: v1
kind: Pod
metadata: {name: selection-external, namespace: ${namespace}}
spec:
  nodeName: ${same_zone_node}
  restartPolicy: Never
  tolerations: [{operator: Exists}]
  containers:
    - name: client
      image: ${test_tools_image}
      imagePullPolicy: IfNotPresent
      command: [sh, -ec, "sleep infinity"]
EOF
"${kc[@]}" -n "${namespace}" wait --for=condition=Ready pod/selection-external --timeout=180s >/dev/null
mapfile -t external_ips < <(pod_addresses selection-external)
allowed_v4=$(printf '%s\n' "${external_ips[@]}" | grep -F '.')
allowed_v6=$(printf '%s\n' "${external_ips[@]}" | grep -F ':')
[[ -n ${allowed_v4} && -n ${allowed_v6} ]]
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
  loadBalancerSourceRanges: [${allowed_v4}/32, ${allowed_v6}/128]
  ports:
    - {name: http, protocol: TCP, port: 8080, targetPort: 8080}
    - {name: source, protocol: TCP, port: 8081, targetPort: 8081}
---
apiVersion: discovery.k8s.io/v1
kind: EndpointSlice
metadata: {name: dsr-v4, namespace: ${namespace}, labels: {kubernetes.io/service-name: dsr}}
addressType: IPv4
ports: [{name: http, protocol: TCP, port: 8080}, {name: source, protocol: TCP, port: 8081}]
endpoints: [{addresses: [${remote_v4}], nodeName: ${remote_node}, zone: zone-b, conditions: {ready: true, serving: true, terminating: false}}]
---
apiVersion: discovery.k8s.io/v1
kind: EndpointSlice
metadata: {name: dsr-v6, namespace: ${namespace}, labels: {kubernetes.io/service-name: dsr}}
addressType: IPv6
ports: [{name: http, protocol: TCP, port: 8080}, {name: source, protocol: TCP, port: 8081}]
endpoints: [{addresses: [${remote_v6}], nodeName: ${remote_node}, zone: zone-b, conditions: {ready: true, serving: true, terminating: false}}]
EOF
dsr_service=
for _ in $(seq 1 900); do
    dsr_service=$("${kc[@]}" -n "${namespace}" get service dsr -o json 2>/dev/null || true)
    mapfile -t dsr_vips < <(jq -r '.status.loadBalancer.ingress[]?.ip' <<<"${dsr_service}" 2>/dev/null || true)
    (( ${#dsr_vips[@]} == 2 )) && break
    sleep 1
done
(( ${#dsr_vips[@]} == 2 )); dsr_v4=${dsr_vips[0]}; dsr_v6=${dsr_vips[1]}
wait_for_service dsr
dsr_simulation=$(controller_raw "/v1/services/loadbalancer/simulate?node_name=${client_node}&address=${dsr_v4}&source_address=${allowed_v4}&port=8080&protocol=tcp")
jq -e '.decision == "translate" and .forwarding_mode == "dsr"
    and .frontend_kind == "load_balancer_cluster"' <<<"${dsr_simulation}" >/dev/null
"${kc[@]}" -n "${namespace}" exec backend-remote -- ip -4 address add "${dsr_v4}/32" dev lo
"${kc[@]}" -n "${namespace}" exec backend-remote -- ip -6 address add "${dsr_v6}/128" dev lo
"${kc[@]}" debug "node/${remote_node}" --quiet -- chroot /host sh -euc '
    ip -4 route replace "$1/32" via "$2"
    ip -6 route replace "$3/128" via "$4"
' sh "${dsr_v4}" "${remote_v4}" "${dsr_v6}" "${remote_v6}" >/dev/null
dsr_routes_created=true
"${kc[@]}" apply -f - >/dev/null <<EOF
apiVersion: v1
kind: Pod
metadata: {name: selection-advertiser, namespace: ${namespace}, labels: {${advertiser_label}: "true"}}
spec:
  serviceAccountName: selection-privileged
  nodeName: ${client_node}
  hostNetwork: true
  restartPolicy: Never
  tolerations: [{operator: Exists}]
  containers:
    - name: advertiser
      image: ${test_tools_image}
      imagePullPolicy: IfNotPresent
      securityContext: {privileged: true}
      command: [sh, -ec, "sleep infinity"]
      volumeMounts:
        - {name: host, mountPath: /host, readOnly: true}
  volumes:
    - name: host
      hostPath: {path: /, type: Directory}
EOF
"${kc[@]}" -n "${namespace}" wait --for=condition=Ready pod/selection-advertiser --timeout=180s >/dev/null
advertiser_created=true
"${kc[@]}" -n "${namespace}" exec selection-advertiser -- sh -euc '
    ip -4 address add "$1/32" dev br-ex
    ip -6 address add "$2/128" dev br-ex
    for _ in $(seq 1 30); do
        ! ip -6 -o address show dev br-ex to "$2/128" | grep -q tentative && break
        sleep 1
    done
    ! ip -6 -o address show dev br-ex to "$2/128" | grep -q tentative
    chroot /host arping -U -c 3 -I br-ex "$1" >/dev/null
    chroot /host arping -A -c 3 -I br-ex "$1" >/dev/null
' sh "${dsr_v4}" "${dsr_v6}"
for target in "http://${dsr_v4}:8080/health" "http://[${dsr_v6}]:8080/health"; do
    for _ in $(seq 1 60); do "${kc[@]}" -n "${namespace}" exec selection-external -- wget -T 10 -t 1 -qO- "${target}" | grep -qx ok && break; sleep 1; done
    "${kc[@]}" -n "${namespace}" exec selection-external -- wget -T 10 -t 1 -qO- "${target}" | grep -qx ok
done
observed_v4=$("${kc[@]}" -n "${namespace}" exec selection-external -- sh -ec "printf probe | socat -T 10 - TCP4:${dsr_v4}:8081" | tr -d '\r\n')
observed_v6=$("${kc[@]}" -n "${namespace}" exec selection-external -- sh -ec "printf probe | socat -T 10 - 'TCP6:[${dsr_v6}]:8081'" | tr -d '\r\n'); observed_v6=${observed_v6#[}; observed_v6=${observed_v6%]}
[[ $(canonical_ip "${observed_v4}") == $(canonical_ip "${allowed_v4}") ]] || {
    echo "DSR changed the IPv4 source tuple: expected ${allowed_v4}, observed ${observed_v4}" >&2
    exit 1
}
[[ $(canonical_ip "${observed_v6}") == $(canonical_ip "${allowed_v6}") ]] || {
    echo "DSR changed the IPv6 source tuple: expected ${allowed_v6}, observed ${observed_v6}" >&2
    exit 1
}
wait_for_dsr_history "${dsr_v4}" >/dev/null
"${kc[@]}" -n "${namespace}" patch service dsr --type=merge -p \
    '{"spec":{"loadBalancerSourceRanges":["192.0.2.1/32","2001:db8::1/128"]}}' >/dev/null
wait_for_convergence >/dev/null
! "${kc[@]}" -n "${namespace}" exec selection-external -- wget -T 5 -t 1 -qO- "http://${dsr_v4}:8080/health" >/dev/null 2>&1
! "${kc[@]}" -n "${namespace}" exec selection-external -- wget -T 5 -t 1 -qO- "http://[${dsr_v6}]:8080/health" >/dev/null 2>&1
"${kc[@]}" -n "${namespace}" patch service dsr --type=merge -p \
    "{\"spec\":{\"loadBalancerSourceRanges\":[\"${allowed_v4}/32\",\"${allowed_v6}/128\"]}}" >/dev/null
wait_for_convergence >/dev/null
"${kc[@]}" -n "${namespace}" exec selection-external -- wget -T 10 -t 1 -qO- "http://${dsr_v4}:8080/health" | grep -qx ok

stage=operations-and-controller-offline-recovery
advanced_agents=$(wait_for_convergence)
jq -e 'all(.nodes[]; .report.schema_version == 8 and .report.invalid_service_events == 0
        and .report.applied_selection_contract_revision > 0
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
    and any(.nodes[]; .report.service_dsr_forwards > 0)' <<<"${advanced_agents}" >/dev/null
for node in "${nodes[@]}"; do
    metrics=$(agent_raw "${node}" /metrics)
    for metric in unf_service_selection_same_node_total unf_service_selection_same_zone_total \
        unf_service_selection_cluster_total unf_service_selection_stable_hash_total \
        unf_service_selection_maglev_total unf_service_affinity_reused_total \
        unf_service_affinity_created_total unf_service_affinity_reselected_total \
        unf_service_forwarding_nat_total unf_service_forwarding_dsr_total; do
        grep -q "^${metric} " <<<"${metrics}"
    done
done
old_controller=$(controller_pod)
"${kc[@]}" -n unf-system scale deployment/unf-controller --replicas=0 >/dev/null
controller_scaled_down=true
"${kc[@]}" -n unf-system wait --for=delete pod -l app.kubernetes.io/name=unf-controller --timeout=180s >/dev/null
for replacement_node in "${client_node}" "${remote_node}"; do
    old_agent=$(agent_pod_on_node "${replacement_node}")
    "${kc[@]}" -n unf-system delete pod "${old_agent}" --wait=false >/dev/null
    "${kc[@]}" -n unf-system wait --for=delete pod "${old_agent}" --timeout=180s >/dev/null
    for _ in $(seq 1 900); do
        new_agent=$(agent_pod_on_node "${replacement_node}")
        if [[ -n ${new_agent} && ${new_agent} != "${old_agent}" ]] \
            && [[ $("${kc[@]}" -n unf-system get pod "${new_agent}" -o jsonpath='{.status.containerStatuses[0].ready}' 2>/dev/null) == true ]]; then break; fi
        sleep 1
    done
    [[ -n ${new_agent} && ${new_agent} != "${old_agent}" ]]
    recovered=$(agent_raw "${replacement_node}" /v1/status)
    jq -e '.schema_version == 8 and .ready and .bpf_loaded
        and .applied_selection_contract_revision > 0
        and .applied_selection_contract_revision == .desired_selection_contract_revision
        and .applied_selection_contract_digest == .desired_selection_contract_digest' <<<"${recovered}" >/dev/null
    "${kc[@]}" debug "node/${replacement_node}" --quiet -- chroot /host sh -euc '
        checkpoint=/var/lib/unf/cni/v1/service-snapshot.json.selection
        test -f "$checkpoint" && test "$(stat -c %a "$checkpoint")" = 600
        jq -e ".schemaVersion == 1 and .contract.schemaVersion == 1 and .contract.contractRevision > 0 and (.contract.contractDigest | length) == 64" "$checkpoint" >/dev/null
        for map in SERVICE_CONFIG SERVICE_AFFINITY SERVICE_BACKEND_SLOTS; do test -e "/sys/fs/bpf/unf/v15/$map"; done
    '
    tcp_probe "${selection_v4}"
    "${kc[@]}" -n "${namespace}" exec selection-external -- wget -T 10 -t 1 -qO- "http://${dsr_v4}:8080/health" | grep -qx ok
done
"${kc[@]}" -n unf-system scale deployment/unf-controller --replicas=1 >/dev/null
controller_scaled_down=false
"${kc[@]}" -n unf-system rollout status deployment/unf-controller --timeout=10m >/dev/null
wait_for_convergence >/dev/null
new_controller=$(controller_pod); [[ ${new_controller} != "${old_controller}" ]]

stage=exact-fixture-and-state-cleanup
"${kc[@]}" debug "node/${remote_node}" --quiet -- chroot /host sh -euc '
    ip -4 route del "$1/32" via "$2"
    ip -6 route del "$3/128" via "$4"
' sh "${dsr_v4}" "${remote_v4}" "${dsr_v6}" "${remote_v6}" >/dev/null
dsr_routes_created=false
"${kc[@]}" -n "${namespace}" exec backend-remote -- ip -4 address del "${dsr_v4}/32" dev lo
"${kc[@]}" -n "${namespace}" exec backend-remote -- ip -6 address del "${dsr_v6}/128" dev lo
"${kc[@]}" -n "${namespace}" exec selection-advertiser -- sh -euc '
    ip -4 address del "$1/32" dev br-ex
    ip -6 address del "$2/128" dev br-ex
' sh "${dsr_v4}" "${dsr_v6}"
advertiser_created=false
"${kc[@]}" delete namespace "${namespace}" --wait=true --timeout=15m >/dev/null
namespace_created=false
for _ in $(seq 1 900); do
    cleanup_status=$(controller_raw /v1/status 2>/dev/null || true)
    lb_state=$("${kc[@]}" -n unf-system get configmap unf-load-balancer-control-plane -o json 2>/dev/null \
        | jq -er '.data["state.json"] | fromjson' 2>/dev/null || true)
    if jq -e --argjson services "${baseline_services}" --argjson frontends "${baseline_frontends}" \
        --argjson backends "${baseline_backends}" '.compiled_services == $services
        and .compiled_service_frontends == $frontends and .compiled_service_backends == $backends
        and .service_compilation_error == null and .agents.all_converged' <<<"${cleanup_status}" >/dev/null 2>&1 \
        && jq -e '([.allocation.leases[] | select(.owner.namespace == "unf-service-selection-qualification")] | length) == 0' \
            <<<"${lb_state}" >/dev/null 2>&1; then break; fi
    sleep 1
done
jq -e --argjson services "${baseline_services}" --argjson frontends "${baseline_frontends}" \
    --argjson backends "${baseline_backends}" '.compiled_services == $services
    and .compiled_service_frontends == $frontends and .compiled_service_backends == $backends
    and .agents.all_converged' <<<"${cleanup_status}" >/dev/null
restore_zones
final_agents=$(wait_for_convergence)
final_unhealthy=$(unhealthy_operators); [[ ${final_unhealthy} == "${baseline_unhealthy}" ]]
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
jq -n --arg generatedAt "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --arg context "${context}" \
    --arg infrastructure "${infrastructure}" --arg sourceRevision "${source_revision}" \
    --arg qualificationRevision "${qualification_revision}" \
    --arg openshiftVersion "$("${kc[@]}" get clusterversion version -o jsonpath='{.status.desired.version}')" \
    --arg kubernetesVersion "$("${kc[@]}" version -o json | jq -r .serverVersion.gitVersion)" \
    --arg controllerImage "${controller_image}" --arg agentImage "${agent_image}" --arg testToolsImage "${test_tools_image}" \
    --arg regressionEvidence "${regression_evidence}" --arg selectionIPv4 "${selection_v4}" --arg selectionIPv6 "${selection_v6}" \
    --arg dsrIPv4 "${dsr_v4}" --arg dsrIPv6 "${dsr_v6}" --arg dsrClientNode "${same_zone_node}" \
    --arg allowedIPv4 "${allowed_v4}" --arg allowedIPv6 "${allowed_v6}" \
    --argjson durationSeconds "$(( $(date +%s) - started_unix ))" --argjson nodes "${node_evidence}" \
    --argjson images "${image_evidence}" --argjson agents "${final_agents}" \
    --argjson sameNode "${same_node_simulation}" --argjson sameZone "${same_zone_simulation}" \
    --argjson cluster "${cluster_simulation_result}" --argjson maglev "${maglev_simulation}" \
    --argjson stableHash "${stable_simulation}" --argjson dsr "${dsr_simulation}" \
    --argjson baselineUnhealthy "${baseline_unhealthy}" --argjson finalUnhealthy "${final_unhealthy}" '
    {schemaVersion:1,phase:"7.10",result:"passed",generatedAt:$generatedAt,
      context:$context,infrastructure:$infrastructure,sourceRevision:$sourceRevision,
      qualificationRevision:$qualificationRevision,openshiftVersion:$openshiftVersion,
      kubernetesVersion:$kubernetesVersion,durationSeconds:$durationSeconds,
      images:{controller:$controllerImage,agent:$agentImage,testTools:$testToolsImage},
      kubeProxyPresent:false,persistentBpfAbi:11,serviceSnapshotSchemaVersion:4,
      selectionContractSchemaVersion:1,agentStatusSchemaVersion:8,
      loadBalancerRegressionEvidence:$regressionEvidence,
      services:{selection:{ipv4:$selectionIPv4,ipv6:$selectionIPv6},
        dsr:{ipv4:$dsrIPv4,ipv6:$dsrIPv6}},
      dsrClient:{scope:"podNetwork",node:$dsrClientNode,ipv4:$allowedIPv4,ipv6:$allowedIPv6},
      simulations:{sameNode:$sameNode,sameZone:$sameZone,clusterFallback:$cluster,
        maglev:$maglev,stableHash:$stableHash,dsr:$dsr},
      baselineUnhealthyOperators:$baselineUnhealthy,finalUnhealthyOperators:$finalUnhealthy,
      nodes:$nodes,imagesObserved:$images,agents:$agents,
      verified:[
        "complete Phase 6 five-Node dual-stack LoadBalancer regression on the Phase 7 tuple",
        "RHCOS SELinux enforcing, CRI-O, UNF primary CNI, and kube-proxy absence",
        "cross-worker and cross-zone IPv4/IPv6 SameNode, SameZone, and Cluster fallback",
        "ClientIP affinity creation, reuse, timeout, ineligible-backend reselection, and graceful draining",
        "Maglev and stable-hash packet-path provenance with three eligible backends",
        "acknowledged cross-worker dual-stack DSR from a third-Node Pod client with explicit backend VIP ownership",
        "DSR original-source preservation, VIP return tuple, source-range denial, and recovery",
        "status-v8, history-v7, fixed-cardinality metrics, and digest-bound simulations",
        "controller-offline replacement of both worker agents from ABI-v11 private checkpoints",
        "controller recovery, exact VIP/address/lease/fixture cleanup, and five-agent convergence",
        "no newly unhealthy ClusterOperator beyond the recorded baseline"],
      excluded:["production availability and scale","production BGP, EVPN, ECMP, and BFD",
        "cloud-provider adapters","weighted or feedback-driven selection","SCTP","fragments"]}
' >"${artifact_tmp}"
chmod 0600 "${artifact_tmp}"
mv -f "${artifact_tmp}" "${artifact}"
artifact_tmp=

trap - ERR EXIT
echo "OpenShift cl02 advanced service-selection qualification passed; evidence: ${artifact}"
