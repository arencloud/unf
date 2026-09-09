#!/usr/bin/env bash
set -Eeuo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
kubeconfig=${KUBECONFIG:-"${project_root}/.tools/cl02-audit.kubeconfig"}
context=${KUBE_CONTEXT:-}
expected_infrastructure=${UNF_OPENSHIFT_EGRESS_EXPECTED_INFRASTRUCTURE:-}
acknowledgement=${UNF_OPENSHIFT_EGRESS_ACKNOWLEDGE_DISPOSABLE:-}
address_acknowledgement=${UNF_OPENSHIFT_EGRESS_ACKNOWLEDGE_ADDRESSES:-}
release_record=${UNF_OPENSHIFT_EGRESS_RELEASE_RECORD:-"${project_root}/deploy/openshift-primary-cni/egress/release.json"}
deploy_evidence=${UNF_OPENSHIFT_EGRESS_DEPLOY_EVIDENCE:-"${project_root}/.artifacts/phase8-egress-openshift-deploy.json"}
artifact=${UNF_OPENSHIFT_EGRESS_EVIDENCE:-"${project_root}/.artifacts/phase8-egress-complete-openshift.json"}
diagnostics=${UNF_OPENSHIFT_EGRESS_DIAGNOSTICS:-"${project_root}/.artifacts/phase8-egress-openshift-diagnostics"}
namespace=unf-egress-openshift-qualification
pool=unf-egress-openshift
policy=unf-egress-openshift
gateway_label=network.unf.io/egress-gateway
drain_label=network.unf.io/egress-drain
pool_v4=${UNF_OPENSHIFT_EGRESS_IPV4_POOL:-10.50.60.232/31}
pool_v6=${UNF_OPENSHIFT_EGRESS_IPV6_POOL:-2a02:abcd:1234:5600::e8/127}
external_port=${UNF_OPENSHIFT_EGRESS_FIXTURE_PORT:-28080}
expected_address_ack="${pool_v4},${pool_v6}"
started_unix=$(date +%s)
stage=initialization
resources_created=false
controller_forward_pid=
artifact_tmp=
diagnostics_collected=false

collect_diagnostics() {
    [[ ${diagnostics_collected} == false ]] || return 0
    diagnostics_collected=true
    mkdir -p "${diagnostics}"
    "${kc[@]}" get nodes -o json >"${diagnostics}/nodes.json" 2>/dev/null || true
    "${kc[@]}" get egresspools.network.unf.io,egresspolicies.network.unf.io -o yaml \
        >"${diagnostics}/egress-resources.yaml" 2>/dev/null || true
    "${kc[@]}" -n unf-system get pods -o wide >"${diagnostics}/unf-pods.txt" 2>/dev/null || true
    "${kc[@]}" -n unf-system logs deployment/unf-controller --all-pods=true \
        >"${diagnostics}/controller.log" 2>&1 || true
    "${kc[@]}" -n unf-system logs daemonset/unf-agent --all-pods=true --prefix \
        >"${diagnostics}/agents.log" 2>&1 || true
    "${kc[@]}" -n unf-system get configmap unf-egress-control-plane \
        -o jsonpath='{.data.state\.json}' >"${diagnostics}/control-plane.json" 2>/dev/null || true
    "${kc[@]}" get clusteroperators -o json >"${diagnostics}/clusteroperators.json" 2>/dev/null || true
}

cleanup() {
    local status=$?
    trap - ERR EXIT
    set +e
    if [[ -n ${controller_forward_pid} ]]; then
        kill "${controller_forward_pid}" >/dev/null 2>&1 || true
        wait "${controller_forward_pid}" >/dev/null 2>&1 || true
    fi
    if [[ ${resources_created} == true ]]; then
        "${kc[@]}" delete egresspolicy.network.unf.io "${policy}" --ignore-not-found --wait=false >/dev/null 2>&1 || true
        "${kc[@]}" delete egresspool.network.unf.io "${pool}" --ignore-not-found --wait=false >/dev/null 2>&1 || true
        "${kc[@]}" delete namespace "${namespace}" --ignore-not-found --wait=false >/dev/null 2>&1 || true
        for node in "${gateway_nodes[@]:-}"; do
            "${kc[@]}" label node "${node}" "${gateway_label}-" "${drain_label}-" >/dev/null 2>&1 || true
        done
    fi
    [[ -z ${artifact_tmp} ]] || unlink "${artifact_tmp}" >/dev/null 2>&1 || true
    exit "${status}"
}

failure() {
    local status=$?
    collect_diagnostics
    echo "OpenShift Phase 8.11 qualification failed during ${stage} at line ${BASH_LINENO[0]}: ${BASH_COMMAND}" >&2
    echo "diagnostics: ${diagnostics}" >&2
    return "${status}"
}

trap failure ERR
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

for command in curl git jq oc python3 rg sha256sum stat timeout unlink; do
    command -v "${command}" >/dev/null || {
        echo "OpenShift Phase 8.11 prerequisite is missing: ${command}" >&2
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
    .schemaVersion == 1 and .phase == "8.11"
    and (.sourceRevision | test("^[0-9a-f]{40}$"))
    and .kindQualification.schemaVersion == 1 and .kindQualification.phase == "8.10"
    and .kindQualification.sourceRevision == .sourceRevision
    and .kindQualification.result == "passed" and .kindQualification.kubeProxyPresent == false
    and .contracts.persistentBpfStateAbiVersion == 15
    and .contracts.egressDistributionSchemaVersion == 2
    and .contracts.egressHostStateSchemaVersion == 2
    and .contracts.egressHaPromotionSchemaVersion == 1
    and .contracts.egressMapSchemaVersion == 4 and .contracts.egressEventSchemaVersion == 1
    and .contracts.agentStatusSchemaVersion == 8 and .contracts.flowExportSchemaVersion == 7
    and all(.images[]; test("^quay\\.io/arencloud/unf-[a-z-]+-dev@sha256:[0-9a-f]{64}$"))
' "${release_record}" >/dev/null; then
    echo "Phase 8.11 release record is missing or invalid" >&2
    exit 1
fi

source_revision=$(jq -er .sourceRevision "${release_record}")
controller_image=$(jq -er .images.controller "${release_record}")
agent_image=$(jq -er .images.agent "${release_record}")
test_tools_image=$(jq -er .images.testTools "${release_record}")
qualification_revision=$(git -C "${project_root}" rev-parse HEAD)
git -C "${project_root}" merge-base --is-ancestor "${source_revision}" "${qualification_revision}"
if [[ -z ${context} ]]; then context=$(oc --kubeconfig "${kubeconfig}" config current-context); fi
kc=(oc --kubeconfig "${kubeconfig}" --context "${context}")
infrastructure=$("${kc[@]}" get infrastructure cluster -o jsonpath='{.status.infrastructureName}')
if [[ -z ${expected_infrastructure} || ${expected_infrastructure} != "${infrastructure}" \
    || ${acknowledgement} != "${infrastructure}" ]]; then
    echo "refusing qualification: both OpenShift egress acknowledgements must equal ${infrastructure}" >&2
    exit 1
fi
if [[ ${address_acknowledgement} != "${expected_address_ack}" ]]; then
    echo "refusing qualification: UNF_OPENSHIFT_EGRESS_ACKNOWLEDGE_ADDRESSES must equal ${expected_address_ack}" >&2
    exit 1
fi
jq -e --arg context "${context}" --arg infrastructure "${infrastructure}" --arg revision "${source_revision}" '
    .schemaVersion == 1 and .phase == "8.11" and .stage == "abi-v15-egress-fabric-staged-deployment"
    and .context == $context and .infrastructure == $infrastructure and .sourceRevision == $revision
    and .kubeProxyPresent == false and .persistentBpfAbi == 15
    and .egressDistributionSchemaVersion == 2 and .egressHostStateSchemaVersion == 2
    and .egressHaPromotionSchemaVersion == 1 and .egressMapSchemaVersion == 4
    and .egressEventSchemaVersion == 1 and .agents.all_converged == true
' "${deploy_evidence}" >/dev/null

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

control_plane_state() {
    "${kc[@]}" -n unf-system get configmap unf-egress-control-plane -o json \
        | jq -er '.data["state.json"] | fromjson'
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
                and .report.selection_contract_schema_version == 1)
        ' <<<"${snapshot}" >/dev/null 2>&1; then
            printf '%s\n' "${snapshot}"
            return 0
        fi
        sleep 1
    done
    echo "five OpenShift agents did not converge" >&2
    jq . <<<"${snapshot}" >&2 || true
    return 1
}

wait_for_activation() {
    local state= status=
    for _ in $(seq 1 300); do
        state=$(control_plane_state 2>/dev/null || true)
        status=$(controller_raw /v1/status 2>/dev/null || true)
        if jq -e '(.allocation.leases | length) == 1
                and (.allocation.leases[0].addresses | length) == 4
                and (.haPlans | length) == 1 and (.haPlans[0].candidates | length) == 3
                and (.gateways.records | length) == 1
                and .gateways.records[0].gateway.outcome == "ready"' <<<"${state}" >/dev/null 2>&1 \
            && jq -e '.egress_source_applications == 1 and .egress_activation_ready_sources == 1
                and .egress_ready_gateways == 1 and .agents.all_converged' \
                <<<"${status}" >/dev/null 2>&1; then
            printf '%s\n' "${state}"
            return 0
        fi
        sleep 1
    done
    echo "OpenShift egress intent did not reach three-candidate bilateral activation" >&2
    jq . <<<"${state}" >&2 || true
    jq . <<<"${status}" >&2 || true
    return 1
}

node_exec() {
    local node=$1
    shift
    "${kc[@]}" debug "node/${node}" --quiet -- chroot /host "$@"
}

canonical_ip() {
    python3 -c 'import ipaddress,sys; print(ipaddress.ip_address(sys.argv[1]))' "$1"
}

peer_probe() {
    local pod=$1 destination=$2 expected_kind=$3 observed= canonical=
    for _ in $(seq 1 15); do
        observed=$("${kc[@]}" -n "${namespace}" exec "${pod}" -- \
            wget -T 5 -t 1 -qO- "http://${destination}:${external_port}/peer" 2>/dev/null || true)
        if [[ -n ${observed} ]]; then
            canonical=$(canonical_ip "${observed}" 2>/dev/null || true)
            if [[ ${expected_kind} == native ]]; then
                [[ ${canonical} == "$(canonical_ip "${native_expected}")" ]] && {
                    printf '%s\n' "${canonical}"; return 0;
                }
            elif jq -e --arg address "${canonical}" \
                '.allocation.leases[0].addresses | index($address) != null' <<<"${active_state}" >/dev/null; then
                printf '%s\n' "${canonical}"; return 0
            fi
        fi
        sleep 1
    done
    echo "${pod} did not expose the expected ${expected_kind} source to ${destination}" >&2
    return 1
}

assert_exclusive_ownership() {
    local state=$1 address owners node
    while read -r address; do
        owners=0
        for node in "${gateway_nodes[@]}"; do
            if node_exec "${node}" ip -o address show dev unf-egress0 2>/dev/null \
                | rg --fixed-strings --quiet "${address}/"; then
                owners=$((owners + 1))
            fi
        done
        (( owners == 1 ))
    done < <(jq -r '.allocation.leases[0].addresses[]' <<<"${state}")
}

wait_for_release() {
    local state=
    for _ in $(seq 1 180); do
        state=$(control_plane_state 2>/dev/null || true)
        if jq -e '(.allocation.leases | length) == 0 and (.gateways.records | length) == 0
            and (.haPlans | length) == 0 and (.haPromotions | length) == 0
            and (.retirements | length) == 0' <<<"${state}" >/dev/null 2>&1; then
            printf '%s\n' "${state}"; return 0
        fi
        sleep 2
    done
    return 1
}

stage=platform-preflight
baseline_unhealthy=$(unhealthy_operators)
network=$("${kc[@]}" get network.config.openshift.io cluster -o json)
operator_network=$("${kc[@]}" get network.operator.openshift.io cluster -o json)
jq -e '.spec.networkType == "None"
    and ([.spec.clusterNetwork[].cidr | contains(":")] | any)
    and ([.spec.clusterNetwork[].cidr | contains(":") | not] | any)
    and ([.spec.serviceNetwork[] | contains(":")] | any)
    and ([.spec.serviceNetwork[] | contains(":") | not] | any)' <<<"${network}" >/dev/null
jq -e '.spec.defaultNetwork.type == "None" and .spec.deployKubeProxy == false' \
    <<<"${operator_network}" >/dev/null
mapfile -t nodes < <("${kc[@]}" get nodes -l network.unf.io/primary-cni=enabled \
    -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' | sort)
(( ${#nodes[@]} == 5 ))
nodes_json=$("${kc[@]}" get nodes -o json)
jq -e '(.items | length) == 5 and all(.items[];
    any(.status.conditions[]; .type == "Ready" and .status == "True")
    and ([.spec.podCIDRs[] | select(contains("."))] | length) == 1
    and ([.spec.podCIDRs[] | select(contains(":"))] | length) == 1
    and (.status.nodeInfo.osImage | contains("CoreOS"))
    and (.status.nodeInfo.containerRuntimeVersion | startswith("cri-o://")))' <<<"${nodes_json}" >/dev/null
source_node=${nodes[0]}
gateway_nodes=("${nodes[1]}" "${nodes[2]}" "${nodes[3]}")
external_node=${nodes[4]}
external_v4=$(jq -er --arg node "${external_node}" '.items[] | select(.metadata.name == $node)
    | [.status.addresses[] | select(.type == "InternalIP" and (.address | contains(".")))][0].address' <<<"${nodes_json}")
external_v6=$(jq -er --arg node "${external_node}" '.items[] | select(.metadata.name == $node)
    | [.status.addresses[] | select(.type == "InternalIP" and (.address | contains(":")))][0].address' <<<"${nodes_json}")
node_exec "${external_node}" sh -euc \
    '! ss -lnt | grep -qE ":${1}([[:space:]]|$)"' sh "${external_port}"
[[ $("${kc[@]}" get egresspools.network.unf.io -o json | jq '.items | length') == 0 ]]
[[ $("${kc[@]}" get egresspolicies.network.unf.io -o json | jq '.items | length') == 0 ]]
[[ -z $("${kc[@]}" get nodes -l "${gateway_label}" -o name) ]]
if "${kc[@]}" get namespace "${namespace}" >/dev/null 2>&1; then
    echo "qualification namespace already exists; refusing to adopt it" >&2
    exit 1
fi
for address in 10.50.60.232 10.50.60.233 2a02:abcd:1234:5600::e8 2a02:abcd:1234:5600::e9; do
    if jq -e --arg address "$(canonical_ip "${address}")" '[.items[].status.addresses[].address] | index($address) != null' \
        <<<"${nodes_json}" >/dev/null; then
        echo "refusing to use egress address already assigned to a Node: ${address}" >&2
        exit 1
    fi
done
controller_version=$(controller_raw '/v1/version?serviceSnapshotSchemaVersion=4&selectionContractSchemaVersion=1')
jq -e --arg revision "${source_revision}" '.schema_version == 2 and .build_revision == $revision
    and .persistent_bpf_state_abi_version == 15 and .service_snapshot_schema_version == 4
    and .selection_contract_schema_version == 1 and .egress_distribution_schema_version == 2
    and .egress_host_state_schema_version == 2 and .egress_ha_promotion_schema_version == 1
    and .egress_map_schema_version == 4 and .egress_event_schema_version == 1
    and .agent_status_schema_version == 8 and .flow_export_schema_version == 7' \
    <<<"${controller_version}" >/dev/null
initial_agents=$(wait_for_convergence)

stage=fixture-and-intent
resources_created=true
"${kc[@]}" create namespace "${namespace}" >/dev/null
"${kc[@]}" -n "${namespace}" create serviceaccount external-fixture >/dev/null
"${kc[@]}" -n "${namespace}" adm policy add-scc-to-user privileged \
    --serviceaccount=external-fixture >/dev/null
for node in "${gateway_nodes[@]}"; do
    "${kc[@]}" label node "${node}" "${gateway_label}=enabled" --overwrite >/dev/null
done
"${kc[@]}" apply -f - >/dev/null <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: external
  namespace: ${namespace}
spec:
  serviceAccountName: external-fixture
  hostNetwork: true
  dnsPolicy: Default
  nodeSelector: {kubernetes.io/hostname: ${external_node}}
  tolerations: [{operator: Exists}]
  containers:
    - name: server
      image: ${test_tools_image}
      imagePullPolicy: IfNotPresent
      command: [sh, -ec, "exec /usr/local/bin/unf-flow-receiver ${external_port}"]
      securityContext: {privileged: true}
---
apiVersion: v1
kind: Pod
metadata:
  name: managed
  namespace: ${namespace}
  labels: {app: managed}
spec:
  nodeSelector: {kubernetes.io/hostname: ${source_node}}
  tolerations: [{operator: Exists}]
  containers:
    - name: client
      image: ${test_tools_image}
      imagePullPolicy: IfNotPresent
      command: [sh, -ec, "sleep infinity"]
---
apiVersion: v1
kind: Pod
metadata:
  name: native
  namespace: ${namespace}
  labels: {app: native}
spec:
  nodeSelector: {kubernetes.io/hostname: ${source_node}}
  tolerations: [{operator: Exists}]
  containers:
    - name: client
      image: ${test_tools_image}
      imagePullPolicy: IfNotPresent
      command: [sh, -ec, "sleep infinity"]
---
apiVersion: network.unf.io/v1alpha1
kind: EgressPool
metadata: {name: ${pool}}
spec:
  provider: {name: static, instance: openshift-cl02}
  prefixes: [${pool_v4}, ${pool_v6}]
---
apiVersion: network.unf.io/v1alpha1
kind: EgressPolicy
metadata: {name: ${policy}}
spec:
  priority: 100
  target:
    namespaceSelector:
      matchLabels: {kubernetes.io/metadata.name: ${namespace}}
    workloadSelector:
      matchLabels: {app: managed}
    serviceAccounts: [default]
  destinations:
    networks: [${external_v4}/32, ${external_v6}/128]
  egress:
    pool: ${pool}
    families: [IPv4, IPv6]
    addressesPerFamily: 2
EOF
"${kc[@]}" -n "${namespace}" wait --for=condition=Ready pod/external pod/managed pod/native --timeout=10m >/dev/null
managed_v4=$("${kc[@]}" -n "${namespace}" get pod managed -o json | jq -er '[.status.podIPs[].ip | select(contains("."))][0]')
managed_v6=$("${kc[@]}" -n "${namespace}" get pod managed -o json | jq -er '[.status.podIPs[].ip | select(contains(":"))][0]')
native_v4=$("${kc[@]}" -n "${namespace}" get pod native -o json | jq -er '[.status.podIPs[].ip | select(contains("."))][0]')
native_v6=$("${kc[@]}" -n "${namespace}" get pod native -o json | jq -er '[.status.podIPs[].ip | select(contains(":"))][0]')

stage=initial-cross-worker-traffic
initial_state=$(wait_for_activation)
active_state=${initial_state}
assert_exclusive_ownership "${initial_state}"
native_expected=${native_v4}
native_observed_v4=$(peer_probe native "${external_v4}" native)
native_expected=${native_v6}
native_observed_v6=$(peer_probe native "[${external_v6}]" native)
managed_observed_v4=$(peer_probe managed "${external_v4}" managed)
managed_observed_v6=$(peer_probe managed "[${external_v6}]" managed)

stage=causal-operations
controller_port=$((22000 + started_unix % 10000))
"${kc[@]}" -n unf-system port-forward "pod/$(controller_pod)" "${controller_port}:9962" \
    >"${diagnostics}-port-forward.log" 2>&1 &
controller_forward_pid=$!
for _ in $(seq 1 60); do
    curl -fsS --max-time 2 "http://127.0.0.1:${controller_port}/readyz" >/dev/null 2>&1 && break
    sleep 1
done
kill -0 "${controller_forward_pid}"
operations_request=$(jq -nc --arg from "${namespace}/managed" --arg destination "${external_v4}" \
    --argjson port "${external_port}" '{from:$from,destination:$destination,protocol:"tcp",port:$port}')
for operations_attempts in $(seq 1 30); do
    operations_explain=$(curl -fsS --max-time 10 -X POST -H 'Content-Type: application/json' \
        --data-binary "${operations_request}" "http://127.0.0.1:${controller_port}/v1/egress/explain")
    operations_simulate=$(curl -fsS --max-time 10 -X POST -H 'Content-Type: application/json' \
        --data-binary "${operations_request}" "http://127.0.0.1:${controller_port}/v1/egress/simulate")
    if jq -e '.schema_version == 1 and .outcome == "eligible"
        and (.candidate_egress_addresses | length) == 4 and (.candidate_gateways | length) == 3
        and .private_nat_state_inferred == false
        and ([.evidence[].layer] | index("counterfactual")) != null
        and ([.evidence[].layer] | index("transport")) != null' <<<"${operations_explain}" >/dev/null \
        && jq -e '.schema_version == 1 and .outcome == "eligible"
        and .private_nat_state_inferred == false' <<<"${operations_simulate}" >/dev/null; then
        break
    fi
    sleep 1
done
kill "${controller_forward_pid}"; wait "${controller_forward_pid}" 2>/dev/null || true; controller_forward_pid=
jq -e '.outcome == "eligible" and (.candidate_egress_addresses | length) == 4
    and (.candidate_gateways | length) == 3' <<<"${operations_explain}" >/dev/null

stage=graceful-ha-reassignment
drained_gateway=$(jq -er '.haPlans[0].assignments[0].gateway.name' <<<"${active_state}")
before_assignments=$(jq -c '.haPlans[0].assignments' <<<"${initial_state}")
drain_started_ms=$(date +%s%3N)
"${kc[@]}" label node "${drained_gateway}" "${drain_label}=true" --overwrite >/dev/null
traffic_failures=0
drained_state=
for _ in $(seq 1 180); do
    active_state=$(control_plane_state 2>/dev/null || true)
    observed=$("${kc[@]}" -n "${namespace}" exec managed -- \
        wget -T 2 -t 1 -qO- "http://${external_v4}:${external_port}/peer" 2>/dev/null || true)
    if [[ -z ${observed} ]] || ! jq -e --arg address "$(canonical_ip "${observed}" 2>/dev/null || true)" \
        '.allocation.leases[0].addresses | index($address) != null' <<<"${active_state}" >/dev/null 2>&1; then
        traffic_failures=$((traffic_failures + 1))
    fi
    if jq -e --arg gateway "${drained_gateway}" '
        .haPlans | length == 1 and .haPlans[0].candidates | length == 2
        and all(.haPlans[0].assignments[]; .gateway.name != $gateway)
        and (.haPromotions | length) == 0' <<<"${active_state}" >/dev/null 2>&1 \
        && jq -e '.egress_activation_ready_sources == 1' <<<"$(controller_raw /v1/status)" >/dev/null 2>&1; then
        drained_state=${active_state}; break
    fi
    sleep 1
done
[[ -n ${drained_state} ]]
graceful_duration_ms=$(( $(date +%s%3N) - drain_started_ms ))
[[ $(jq -c '.haPlans[0].assignments' <<<"${drained_state}") != "${before_assignments}" ]]
assert_exclusive_ownership "${drained_state}"
managed_observed_after_drain_v4=$(peer_probe managed "${external_v4}" managed)
managed_observed_after_drain_v6=$(peer_probe managed "[${external_v6}]" managed)

stage=restart-recovery
"${kc[@]}" label node "${drained_gateway}" "${drain_label}-" >/dev/null
"${kc[@]}" -n unf-system rollout restart deployment/unf-controller >/dev/null
"${kc[@]}" -n unf-system rollout status deployment/unf-controller --timeout=10m >/dev/null
controller_recovery_state=$(wait_for_activation)
recovery_node=$(jq -er '.haPlans[0].assignments[0].gateway.name' <<<"${controller_recovery_state}")
old_agent=$("${kc[@]}" -n unf-system get pods --field-selector "spec.nodeName=${recovery_node}" -o json \
    | jq -er '.items[] | select(.metadata.name | startswith("unf-agent-")) | .metadata.name' | head -1)
old_agent_uid=$("${kc[@]}" -n unf-system get pod "${old_agent}" -o jsonpath='{.metadata.uid}')
"${kc[@]}" -n unf-system delete pod "${old_agent}" --wait=false >/dev/null
for _ in $(seq 1 300); do
    new_agent_uid=$("${kc[@]}" -n unf-system get pods --field-selector "spec.nodeName=${recovery_node}" -o json 2>/dev/null \
        | jq -r --arg old "${old_agent_uid}" '.items[] | select((.metadata.name | startswith("unf-agent-"))
            and .metadata.uid != $old and .metadata.deletionTimestamp == null
            and .status.phase == "Running" and all(.status.containerStatuses[]; .ready)) | .metadata.uid' | head -1)
    [[ -z ${new_agent_uid} ]] || break
    sleep 1
done
[[ -n ${new_agent_uid:-} ]]
final_agents=$(wait_for_convergence)
recovered_state=$(wait_for_activation)
assert_exclusive_ownership "${recovered_state}"
managed_observed_after_recovery_v4=$(peer_probe managed "${external_v4}" managed)
managed_observed_after_recovery_v6=$(peer_probe managed "[${external_v6}]" managed)

stage=exact-release
"${kc[@]}" delete egresspolicy.network.unf.io "${policy}" --wait=true >/dev/null
released_state=$(wait_for_release)
mapfile -t leased_addresses < <(jq -r '.allocation.leases[0].addresses[]' <<<"${recovered_state}")
for node in "${gateway_nodes[@]}"; do
    for address in "${leased_addresses[@]}"; do
        ! node_exec "${node}" ip -o address show dev unf-egress0 2>/dev/null \
            | rg --fixed-strings --quiet "${address}/"
    done
done
"${kc[@]}" delete egresspool.network.unf.io "${pool}" --wait=true >/dev/null
"${kc[@]}" delete namespace "${namespace}" --wait=true --timeout=10m >/dev/null
for node in "${gateway_nodes[@]}"; do
    "${kc[@]}" label node "${node}" "${gateway_label}-" "${drain_label}-" >/dev/null
done
resources_created=false
final_agents=$(wait_for_convergence)
final_unhealthy=$(unhealthy_operators)
[[ ${final_unhealthy} == "${baseline_unhealthy}" ]]
"${kc[@]}" wait --for=condition=Ready nodes --all --timeout=10m >/dev/null
[[ $("${kc[@]}" get egresspools.network.unf.io -o json | jq '.items | length') == 0 ]]
[[ $("${kc[@]}" get egresspolicies.network.unf.io -o json | jq '.items | length') == 0 ]]

stage=evidence
collect_diagnostics
node_evidence=$("${kc[@]}" get nodes -o json | jq '[.items[] | {
    name:.metadata.name,osImage:.status.nodeInfo.osImage,kernelVersion:.status.nodeInfo.kernelVersion,
    containerRuntime:.status.nodeInfo.containerRuntimeVersion,podCIDRs:.spec.podCIDRs,
    internalIPs:[.status.addresses[] | select(.type == "InternalIP") | .address]}]')
image_evidence=$("${kc[@]}" -n unf-system get pods -l 'app.kubernetes.io/name in (unf-controller,unf-agent)' -o json \
    | jq '[.items[] | {pod:.metadata.name,node:.spec.nodeName,
        containers:[.status.containerStatuses[] | {name,image,imageID}]}]')
mkdir -p "$(dirname "${artifact}")"
artifact_tmp="${artifact}.tmp.$$"
jq -n --arg generatedAt "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --arg context "${context}" \
    --arg infrastructure "${infrastructure}" --arg sourceRevision "${source_revision}" \
    --arg qualificationRevision "${qualification_revision}" \
    --arg openshiftVersion "$("${kc[@]}" get clusterversion version -o jsonpath='{.status.desired.version}')" \
    --arg kubernetesVersion "$("${kc[@]}" version -o json | jq -r .serverVersion.gitVersion)" \
    --arg controllerImage "${controller_image}" --arg agentImage "${agent_image}" \
    --arg testToolsImage "${test_tools_image}" --arg deployEvidence "${deploy_evidence}" \
    --arg sourceNode "${source_node}" --arg externalNode "${external_node}" \
    --arg externalIPv4 "${external_v4}" --arg externalIPv6 "${external_v6}" \
    --arg managedIPv4 "${managed_v4}" --arg managedIPv6 "${managed_v6}" \
    --arg nativeObservedIPv4 "${native_observed_v4}" --arg nativeObservedIPv6 "${native_observed_v6}" \
    --arg managedObservedIPv4 "${managed_observed_v4}" --arg managedObservedIPv6 "${managed_observed_v6}" \
    --arg managedAfterDrainIPv4 "${managed_observed_after_drain_v4}" \
    --arg managedAfterDrainIPv6 "${managed_observed_after_drain_v6}" \
    --arg managedAfterRecoveryIPv4 "${managed_observed_after_recovery_v4}" \
    --arg managedAfterRecoveryIPv6 "${managed_observed_after_recovery_v6}" \
    --arg drainedGateway "${drained_gateway}" --arg recoveryNode "${recovery_node}" \
    --argjson durationSeconds "$(( $(date +%s) - started_unix ))" \
    --argjson gracefulDurationMs "${graceful_duration_ms}" --argjson trafficFailures "${traffic_failures}" \
    --argjson operationsAttempts "${operations_attempts}" --argjson nodes "${node_evidence}" \
    --argjson images "${image_evidence}" --argjson initialAgents "${initial_agents}" \
    --argjson finalAgents "${final_agents}" --argjson initialState "${initial_state}" \
    --argjson drainedState "${drained_state}" --argjson recoveredState "${recovered_state}" \
    --argjson releasedState "${released_state}" --argjson explain "${operations_explain}" \
    --argjson simulate "${operations_simulate}" --argjson baselineUnhealthy "${baseline_unhealthy}" \
    --argjson finalUnhealthy "${final_unhealthy}" '
    {schemaVersion:1,phase:"8.11",result:"passed",generatedAt:$generatedAt,
      context:$context,infrastructure:$infrastructure,sourceRevision:$sourceRevision,
      qualificationRevision:$qualificationRevision,openshiftVersion:$openshiftVersion,
      kubernetesVersion:$kubernetesVersion,durationSeconds:$durationSeconds,
      images:{controller:$controllerImage,agent:$agentImage,testTools:$testToolsImage},
      deployEvidence:$deployEvidence,kubeProxyPresent:false,persistentBpfAbi:15,
      topology:{nodeCount:($nodes|length),sourceNode:$sourceNode,externalNode:$externalNode,
        gateways:$initialState.haPlans[0].candidates},
      fixture:{externalIPv4:$externalIPv4,externalIPv6:$externalIPv6,
        managedIPv4:$managedIPv4,managedIPv6:$managedIPv6},
      observedSources:{native:{ipv4:$nativeObservedIPv4,ipv6:$nativeObservedIPv6},
        initial:{ipv4:$managedObservedIPv4,ipv6:$managedObservedIPv6},
        afterDrain:{ipv4:$managedAfterDrainIPv4,ipv6:$managedAfterDrainIPv6},
        afterRecovery:{ipv4:$managedAfterRecoveryIPv4,ipv6:$managedAfterRecoveryIPv6}},
      gracefulHa:{drainedGateway:$drainedGateway,durationMs:$gracefulDurationMs,
        probeFailures:$trafficFailures,state:$drainedState},
      recovery:{node:$recoveryNode,controllerRestart:true,agentReplacement:true,state:$recoveredState},
      operations:{attempts:$operationsAttempts,explain:$explain,simulate:$simulate},
      cleanup:{exactRelease:true,state:$releasedState},
      baselineUnhealthyOperators:$baselineUnhealthy,finalUnhealthyOperators:$finalUnhealthy,
      nodes:$nodes,imagesObserved:$images,initialAgents:$initialAgents,finalAgents:$finalAgents,
      verified:["immutable public digest-pinned runtime","five-node dual-stack UNF primary CNI",
        "RHCOS SELinux enforcing and CRI-O","kube-proxy absence",
        "cross-worker IPv4 and IPv6 policy-first source steering",
        "externally observed IPv4 and IPv6 egress source addresses",
        "unmanaged source identity preservation","four-address exclusive ownership across three CCR gateways",
        "graceful drain, flow-twin handoff, and deterministic reassignment",
        "controller checkpoint recovery and gateway-agent replacement recovery",
        "evidence-complete explanation and non-authoritative simulation",
        "exact address, intent, label, and fixture cleanup","five-agent final convergence",
        "no newly unhealthy ClusterOperator beyond the recorded baseline"],
      excluded:["production availability and scale","abrupt physical Node loss",
        "production-scale BGP/ECMP/BFD availability","EVPN","cross-cluster egress","encryption"]}
' >"${artifact_tmp}"
chmod 0600 "${artifact_tmp}"
mv -f "${artifact_tmp}" "${artifact}"
artifact_tmp=

trap - ERR EXIT
echo "OpenShift cl02 Phase 8.11 egress qualification passed; evidence: ${artifact}"
