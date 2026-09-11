#!/usr/bin/env bash
set -Eeuo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
kubeconfig=${KUBECONFIG:-"${project_root}/.tools/cl02-audit.kubeconfig"}
context=${KUBE_CONTEXT:-}
expected_infrastructure=${UNF_OPENSHIFT_ENCRYPTION_EXPECTED_INFRASTRUCTURE:-}
disposable_ack=${UNF_OPENSHIFT_ENCRYPTION_ACKNOWLEDGE_DISPOSABLE:-}
migration_ack=${UNF_OPENSHIFT_ENCRYPTION_ACKNOWLEDGE_MIGRATION:-}
release_record=${UNF_OPENSHIFT_ENCRYPTION_RELEASE_RECORD:-"${project_root}/deploy/openshift-primary-cni/encryption-phase9/release.json"}
deploy_evidence=${UNF_OPENSHIFT_ENCRYPTION_DEPLOY_EVIDENCE:-"${project_root}/.artifacts/phase9-encryption-openshift-deploy.json"}
artifact=${UNF_OPENSHIFT_ENCRYPTION_EVIDENCE:-"${project_root}/.artifacts/phase9-encryption-openshift.json"}
capture_artifact=${UNF_OPENSHIFT_ENCRYPTION_CAPTURE:-"${project_root}/.artifacts/phase9-encryption-openshift.pcap"}
diagnostics=${UNF_OPENSHIFT_ENCRYPTION_DIAGNOSTICS:-"${project_root}/.artifacts/phase9-encryption-openshift-diagnostics"}
namespace=unf-encryption-openshift-qualification
host_probe_namespace=unf-encryption-openshift-host-probe
policy=required-pair
capture_pod=underlay-capture
capture_container_path=/capture/unf-phase9-encryption.pcap
stage=initialization
started_unix=$(date +%s)
resources_created=false
host_probe_created=false
baseline_changed=false
link_lowered=false
source_interface=
artifact_tmp=
diagnostics_collected=false

collect_diagnostics() {
    [[ ${diagnostics_collected} == false ]] || return 0
    diagnostics_collected=true
    mkdir -p "${diagnostics}"
    "${kc[@]}" get nodes -o wide >"${diagnostics}/nodes.txt" 2>&1 || true
    "${kc[@]}" -n unf-system get pods -o wide >"${diagnostics}/unf-pods.txt" 2>&1 || true
    "${kc[@]}" -n unf-system logs deployment/unf-controller --all-pods=true \
        >"${diagnostics}/controller.log" 2>&1 || true
    "${kc[@]}" -n unf-system logs daemonset/unf-agent --all-pods=true --prefix \
        >"${diagnostics}/agents.log" 2>&1 || true
    "${kc[@]}" -n "${namespace}" get all,encryptionpolicy.network.unf.io -o yaml \
        >"${diagnostics}/fixture.yaml" 2>&1 || true
    "${kc[@]}" get clusteroperators -o json >"${diagnostics}/clusteroperators.json" 2>/dev/null || true
}

cleanup() {
    local status=$?
    trap - ERR EXIT
    set +e
    if [[ ${link_lowered} == true && -n ${source_node:-} && -n ${source_interface} ]]; then
        node_exec "${source_node}" ip link set dev "${source_interface}" up >/dev/null 2>&1 || true
    fi
    if [[ ${baseline_changed} == true ]]; then
        "${kc[@]}" -n unf-system set env deployment/unf-controller \
            UNF_ENCRYPTION_BASELINE=native >/dev/null 2>&1 || true
    fi
    if [[ ${resources_created} == true ]]; then
        "${kc[@]}" delete namespace "${namespace}" --ignore-not-found --wait=false >/dev/null 2>&1 || true
    fi
    if [[ ${host_probe_created} == true ]]; then
        "${kc[@]}" delete namespace "${host_probe_namespace}" --ignore-not-found --wait=false \
            >/dev/null 2>&1 || true
    fi
    [[ -z ${artifact_tmp} ]] || unlink "${artifact_tmp}" >/dev/null 2>&1 || true
    exit "${status}"
}

failure() {
    local status=$?
    collect_diagnostics
    echo "OpenShift Phase 9.9 qualification failed during ${stage} at line ${BASH_LINENO[0]}: ${BASH_COMMAND}" >&2
    echo "diagnostics: ${diagnostics}" >&2
    return "${status}"
}

trap failure ERR
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

for command in git jq oc rg sha256sum stat tcpdump timeout unlink; do
    command -v "${command}" >/dev/null || {
        echo "OpenShift Phase 9.9 prerequisite is missing: ${command}" >&2
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
    .schemaVersion == 1 and .phase == "9.9"
    and (.sourceRevision | test("^[0-9a-f]{40}$"))
    and .kindQualification.schemaVersion == 1 and .kindQualification.milestone == "9.8"
    and .kindQualification.runtimeRevision == .sourceRevision
    and (.kindQualification.qualificationRevision | test("^[0-9a-f]{40}$"))
    and (.kindQualification.evidenceSha256 | test("^[0-9a-f]{64}$"))
    and (.kindQualification.captureSha256 | test("^[0-9a-f]{64}$"))
    and .kindQualification.result == "passed" and .kindQualification.kubeProxyPresent == false
    and .contracts.persistentBpfStateAbiVersion == 15
    and .contracts.encryptionModelSchemaVersion == 1
    and .contracts.encryptionPlanSchemaVersion == 2
    and .contracts.encryptionPathProofSchemaVersion == 2
    and .contracts.encryptionOperationsSchemaVersion == 1
    and .contracts.encryptionMapAbiVersion == 2
    and all(.images[]; test("^quay\\.io/arencloud/unf-[a-z-]+-dev@sha256:[0-9a-f]{64}$"))
' "${release_record}" >/dev/null; then
    echo "Phase 9.9 release record is missing or invalid" >&2
    exit 1
fi

source_revision=$(jq -er .sourceRevision "${release_record}")
controller_image=$(jq -er .images.controller "${release_record}")
agent_image=$(jq -er .images.agent "${release_record}")
test_tools_image=$(jq -er .images.testTools "${release_record}")
qualification_revision=$(git -C "${project_root}" rev-parse HEAD)
git -C "${project_root}" merge-base --is-ancestor "${source_revision}" "${qualification_revision}"
if [[ -z ${context} ]]; then context=$(oc --kubeconfig "${kubeconfig}" config current-context); fi
[[ $(oc --kubeconfig "${kubeconfig}" config current-context) == "${context}" ]]
kc=(oc --kubeconfig "${kubeconfig}" --context "${context}")

oc_read() {
    local attempt output
    for attempt in $(seq 1 15); do
        if output=$("${kc[@]}" "$@" 2>/dev/null); then
            printf '%s\n' "${output}"
            return 0
        fi
        sleep 2
    done
    "${kc[@]}" "$@"
}

node_exec() {
    local node=$1 pod
    shift
    pod=$("${kc[@]}" -n "${host_probe_namespace}" get pods \
        -l app.kubernetes.io/name=unf-encryption-host-probe \
        --field-selector "spec.nodeName=${node}" -o json | jq -er '
          .items[] | select(.metadata.deletionTimestamp == null
            and .status.phase == "Running"
            and any(.status.containerStatuses[]; .name == "host-probe" and .ready))
          | .metadata.name' | head -n 1)
    [[ -n ${pod} ]]
    "${kc[@]}" -n "${host_probe_namespace}" exec "${pod}" -c host-probe -- chroot /host "$@"
}

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

unhealthy_operators() {
    oc_read get clusteroperators -o json | jq -c '[.items[]
        | select(any(.status.conditions[];
            (.type == "Available" and .status != "True")
            or (.type == "Degraded" and .status == "True")))
        | .metadata.name] | sort'
}

generation_snapshot() {
    local node
    for node in "${nodes[@]}"; do
        node_exec "${node}" jq -cer --arg node "${node}" '
            {node:$node,
             generation:.active.fact.checkpoint.transaction.desired.published.generation,
             policyRevision:.active.fact.checkpoint.transaction.desired.published.policyRevision,
             serviceRevision:.active.fact.checkpoint.transaction.desired.published.serviceRevision,
             egressRevision:.active.fact.checkpoint.transaction.desired.published.egressRevision,
             pending:(if .pending == null then null else
                .pending.fact.checkpoint.transaction.desired.published.generation end),
             epochs:[.active.plans[].epoch] | sort}' \
            /var/lib/unf/cni/v1/encryption-generation.json.recovery-plan
    done | jq -sc 'sort_by(.node)'
}

current_revision_cut() {
    local agents egress_revision
    agents=$(controller_raw /v1/state/agents)
    egress_revision=$(oc_read -n unf-system get configmap unf-egress-control-plane -o json \
        | jq -er '.data["state.json"] | fromjson | .desiredRevision')
    jq -cen --argjson agents "${agents}" --argjson expected "${#nodes[@]}" \
        --argjson egress "${egress_revision}" '
        $agents.schema_version == 8
        and $agents.expected_agents == $expected
        and $agents.reporting_agents == $expected
        and $agents.all_converged
        and ($agents.nodes | length) == $expected
        and all($agents.nodes[];
            .fresh and .converged and .report.ready and .report.bpf_loaded
            and .report.desired_policy_revision == .report.applied_policy_revision
            and .report.desired_service_revision == .report.applied_service_revision)
        and ([$agents.nodes[].report.desired_policy_revision] | unique | length) == 1
        and ([$agents.nodes[].report.desired_service_revision] | unique | length) == 1
        | select(.)
        | {policyRevision:$agents.nodes[0].report.desired_policy_revision,
           serviceRevision:$agents.nodes[0].report.desired_service_revision,
           egressRevision:$egress}'
}

generation_matches_current_cut() {
    local snapshot=$1 cut=$2
    jq -e --argjson expected "${#nodes[@]}" --argjson cut "${cut}" '
        length == $expected
        and all(.[];
            .pending == null and .generation != null
            and .policyRevision == $cut.policyRevision
            and .serviceRevision == $cut.serviceRevision
            and .egressRevision == $cut.egressRevision)
        and ([.[].generation] | unique | length) == 1
        and ([.[].policyRevision] | unique | length) == 1
        and ([.[].serviceRevision] | unique | length) == 1
        and ([.[].egressRevision] | unique | length) == 1
    ' <<<"${snapshot}" >/dev/null 2>&1
}

wait_generation() {
    local snapshot= cut=
    for _ in $(seq 1 360); do
        cut=$(current_revision_cut 2>/dev/null || true)
        snapshot=$(generation_snapshot 2>/dev/null || true)
        if [[ -n ${cut} ]] && generation_matches_current_cut "${snapshot}" "${cut}"; then
            printf '%s\n' "${snapshot}"
            return 0
        fi
        sleep 1
    done
    echo "five-Node encryption generation did not converge" >&2
    jq . <<<"${snapshot}" >&2 || true
    return 1
}

wait_generation_after() {
    local predecessor=$1 snapshot= generation= cut=
    for _ in $(seq 1 360); do
        cut=$(current_revision_cut 2>/dev/null || true)
        snapshot=$(generation_snapshot 2>/dev/null || true)
        generation=$(jq -r '.[0].generation // empty' <<<"${snapshot}" 2>/dev/null || true)
        if [[ -n ${cut} ]] && generation_matches_current_cut "${snapshot}" "${cut}" \
            && [[ ${generation} =~ ^[0-9]+$ ]] && (( generation > predecessor )); then
            printf '%s\n' "${snapshot}"
            return 0
        fi
        sleep 1
    done
    echo "encryption generation did not advance beyond ${predecessor}" >&2
    return 1
}

wait_for_convergence() {
    local snapshot=
    for _ in $(seq 1 360); do
        snapshot=$(controller_raw /v1/state/agents 2>/dev/null || true)
        if jq -e --argjson expected "${#nodes[@]}" '
            .schema_version == 8 and .expected_agents == $expected
            and .reporting_agents == $expected and .missing_agents == 0
            and .stale_agents == 0 and .converged_agents == $expected
            and .unexpected_agents == 0 and .all_converged
            and all(.nodes[]; .fresh and .converged and .report.ready and .report.bpf_loaded)
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

set_baseline() {
    local value=$1
    if [[ ${value} == native ]]; then
        baseline_changed=false
    else
        baseline_changed=true
    fi
    "${kc[@]}" -n unf-system set env deployment/unf-controller \
        "UNF_ENCRYPTION_BASELINE=${value}" >/dev/null
    "${kc[@]}" -n unf-system rollout status deployment/unf-controller --timeout=10m >/dev/null
}

http_probe_once() {
    local pod=$1 address=$2 port=$3 target
    if [[ ${address} == *:* ]]; then target="http://[${address}]:${port}/health"; else target="http://${address}:${port}/health"; fi
    "${kc[@]}" -n "${namespace}" exec "${pod}" -- wget -T 3 -t 1 -qO- "${target}" | rg -qx ok
}

http_probe() {
    local pod=$1 address=$2 port=$3
    for _ in $(seq 1 30); do
        if http_probe_once "${pod}" "${address}" "${port}" >/dev/null 2>&1; then return 0; fi
        sleep 1
    done
    echo "HTTP probe failed from ${pod} to ${address}:${port}" >&2
    return 1
}

traffic_matrix() {
    local client=$1 pod4=$2 pod6=$3 service4=$4 service6=$5 port=$6
    http_probe "${client}" "${pod4}" "${port}"
    http_probe "${client}" "${pod6}" "${port}"
    http_probe "${client}" "${service4}" "${port}"
    http_probe "${client}" "${service6}" "${port}"
}

wait_epoch_change() {
    local initial_epoch=$1 snapshot= epoch= cut=
    for _ in $(seq 1 360); do
        cut=$(current_revision_cut 2>/dev/null || true)
        snapshot=$(generation_snapshot 2>/dev/null || true)
        epoch=$(jq -r --arg node "${source_node}" '
            .[] | select(.node == $node) | .epochs | max // empty
        ' <<<"${snapshot}" 2>/dev/null || true)
        if [[ -n ${cut} ]] && generation_matches_current_cut "${snapshot}" "${cut}" \
            && [[ ${epoch} =~ ^[0-9]+$ ]] && (( epoch > initial_epoch )); then
            printf '%s\n' "${snapshot}"
            return 0
        fi
        sleep 1
    done
    echo "automatic encryption epoch rotation did not complete" >&2
    return 1
}

stage=guarded-platform-preflight
infrastructure=$(oc_read get infrastructure cluster -o jsonpath='{.status.infrastructureName}')
if [[ -z ${expected_infrastructure} || ${expected_infrastructure} != "${infrastructure}" \
    || ${disposable_ack} != "${infrastructure}" || ${migration_ack} != "${infrastructure}" ]]; then
    echo "refusing qualification: infrastructure, disposable, and encryption-migration acknowledgements must equal ${infrastructure}" >&2
    exit 1
fi
jq -e --arg context "${context}" --arg infrastructure "${infrastructure}" --arg revision "${source_revision}" '
    .schemaVersion == 1 and .phase == "9.9" and .stage == "abi-v15-encryption-v2-staged-deployment"
    and .context == $context and .infrastructure == $infrastructure and .sourceRevision == $revision
    and .kubeProxyPresent == false and .persistentBpfAbi == 15
    and .encryptionModelSchemaVersion == 1 and .encryptionPlanSchemaVersion == 2
    and .encryptionPathProofSchemaVersion == 2 and .encryptionOperationsSchemaVersion == 1
    and .encryptionMapAbiVersion == 2 and .agents.all_converged == true
' "${deploy_evidence}" >/dev/null

baseline_unhealthy=$(unhealthy_operators)
network=$(oc_read get network.config.openshift.io cluster -o json)
operator_network=$(oc_read get network.operator.openshift.io cluster -o json)
jq -e '.spec.networkType == "None"
    and ([.spec.clusterNetwork[].cidr | contains(":")] | any)
    and ([.spec.clusterNetwork[].cidr | contains(":") | not] | any)
    and ([.spec.serviceNetwork[] | contains(":")] | any)
    and ([.spec.serviceNetwork[] | contains(":") | not] | any)' <<<"${network}" >/dev/null
jq -e '.spec.defaultNetwork.type == "None" and .spec.deployKubeProxy == false' \
    <<<"${operator_network}" >/dev/null
[[ $("${kc[@]}" -n openshift-kube-proxy get daemonsets -o json | jq '.items | length') == 0 ]]
nodes_json=$(oc_read get nodes -o json)
jq -e '(.items | length) == 5 and all(.items[];
    .metadata.labels["network.unf.io/primary-cni"] == "enabled"
    and any(.status.conditions[]; .type == "Ready" and .status == "True")
    and ([.spec.podCIDRs[] | select(contains("."))] | length) == 1
    and ([.spec.podCIDRs[] | select(contains(":"))] | length) == 1
    and (.status.nodeInfo.osImage | contains("CoreOS"))
    and (.status.nodeInfo.containerRuntimeVersion | startswith("cri-o://")))' <<<"${nodes_json}" >/dev/null
mapfile -t nodes < <(jq -r '.items[].metadata.name' <<<"${nodes_json}" | sort)
mapfile -t workers < <(jq -r '.items[] | select(.metadata.labels | has("node-role.kubernetes.io/worker")) | .metadata.name' <<<"${nodes_json}" | sort)
(( ${#workers[@]} == 2 ))
source_node=${workers[0]}
destination_node=${workers[1]}
[[ $("${kc[@]}" get encryptionpolicies.network.unf.io -A -o json | jq '.items | length') == 0 ]]
for reserved_namespace in "${namespace}" "${host_probe_namespace}"; do
    if "${kc[@]}" get namespace "${reserved_namespace}" >/dev/null 2>&1; then
        echo "qualification namespace ${reserved_namespace} already exists; refusing to adopt it" >&2
        exit 1
    fi
done

# One stable, host-networked executor per Node makes host evidence
# non-perturbing. Repeated `oc debug node` calls create and delete Pods, which
# are themselves encryption inputs and can prevent the generation being
# observed from ever becoming quiescent.
"${kc[@]}" create namespace "${host_probe_namespace}" >/dev/null
host_probe_created=true
"${kc[@]}" -n "${host_probe_namespace}" create serviceaccount host-probe >/dev/null
"${kc[@]}" -n "${host_probe_namespace}" adm policy add-scc-to-user privileged \
    --serviceaccount=host-probe >/dev/null
"${kc[@]}" apply -f - >/dev/null <<EOF
apiVersion: apps/v1
kind: DaemonSet
metadata: {name: host-probe, namespace: ${host_probe_namespace}}
spec:
  selector: {matchLabels: {app.kubernetes.io/name: unf-encryption-host-probe}}
  template:
    metadata: {labels: {app.kubernetes.io/name: unf-encryption-host-probe}}
    spec:
      serviceAccountName: host-probe
      hostNetwork: true
      hostPID: true
      nodeSelector: {network.unf.io/primary-cni: enabled}
      tolerations: [{operator: Exists}]
      containers:
      - name: host-probe
        image: ${test_tools_image}
        imagePullPolicy: IfNotPresent
        command: [/bin/sh, -ec, "trap : TERM INT; sleep infinity & wait"]
        securityContext: {privileged: true}
        volumeMounts: [{name: host-root, mountPath: /host}]
      volumes:
      - name: host-root
        hostPath: {path: /, type: Directory}
EOF
"${kc[@]}" -n "${host_probe_namespace}" rollout status daemonset/host-probe \
    --timeout=10m >/dev/null
for node in "${nodes[@]}"; do
    host_facts=$(node_exec "${node}" sh -euc '
        test "$(getenforce)" = Enforcing
        test -S /run/unf/cni.sock
        test -f /etc/kubernetes/cni/net.d/10-unf.conflist
        ! iptables-save 2>/dev/null | grep -q "^-A KUBE-SVC"
        ! ip6tables-save 2>/dev/null | grep -q "^-A KUBE-SVC"
        echo host-ready')
    rg -qx host-ready <<<"${host_facts}"
done

stage=immutable-runtime
"${kc[@]}" -n unf-system rollout status deployment/unf-controller --timeout=10m >/dev/null
initial_agents=$(wait_for_convergence)
controller_version=$(controller_raw /v1/version)
jq -e --arg revision "${source_revision}" '
    .component == "unf-controller" and .build_revision == $revision
    and .encryption_model_schema_version == 1 and .encryption_plan_schema_version == 2
    and .encryption_path_proof_schema_version == 2
    and .encryption_operations_schema_version == 1 and .encryption_map_abi_version == 2
' <<<"${controller_version}" >/dev/null
agent_versions='[]'
while read -r agent_pod; do
    agent_version=$("${kc[@]}" get --raw "/api/v1/namespaces/unf-system/pods/${agent_pod}:9963/proxy/v1/version")
    jq -e --arg revision "${source_revision}" '
        .component == "unf-agent" and .build_revision == $revision
        and .encryption_model_schema_version == 1 and .encryption_plan_schema_version == 2
        and .encryption_path_proof_schema_version == 2
        and .encryption_operations_schema_version == 1 and .encryption_map_abi_version == 2
    ' <<<"${agent_version}" >/dev/null
    agent_versions=$(jq -c --argjson version "${agent_version}" '. + [$version]' <<<"${agent_versions}")
done < <("${kc[@]}" -n unf-system get pods -l app.kubernetes.io/name=unf-agent -o name | sed 's|pod/||' | sort)
jq -e 'length == 5' <<<"${agent_versions}" >/dev/null
images_json=$("${kc[@]}" -n unf-system get pods -o json | jq -c '
    [.items[]
     | select(.metadata.labels["app.kubernetes.io/name"] == "unf-agent"
         or .metadata.labels["app.kubernetes.io/name"] == "unf-controller")
     | .metadata.name as $pod | .spec.nodeName as $node | .spec.containers[] as $spec
     | .status.containerStatuses[]
     | select(.name == $spec.name and (.name == "agent" or .name == "controller"))
     | {pod:$pod,node:$node,component:.name,image:$spec.image,imageID:.imageID,ready:.ready,restarts:.restartCount}]
    | sort_by(.component,.node)')
jq -e --arg controller "${controller_image}" --arg agent "${agent_image}" '
    length == 6 and all(.[]; .ready == true and .restarts == 0)
    and ([.[] | select(.component == "controller" and .image == $controller)] | length) == 1
    and ([.[] | select(.component == "agent" and .image == $agent)] | length) == 5
' <<<"${images_json}" >/dev/null

stage=explicitly-acknowledged-required-migration
native_generation=$(wait_generation)
native_generation_id=$(jq -r '.[0].generation' <<<"${native_generation}")
set_baseline required
required_baseline_generation=$(wait_generation_after "${native_generation_id}")

stage=fixture
resources_created=true
"${kc[@]}" create namespace "${namespace}" >/dev/null
"${kc[@]}" -n "${namespace}" create serviceaccount capture >/dev/null
"${kc[@]}" -n "${namespace}" adm policy add-scc-to-user privileged --serviceaccount=capture >/dev/null
"${kc[@]}" apply -f - >/dev/null <<EOF
apiVersion: v1
kind: Pod
metadata: {name: required-client, namespace: ${namespace}, labels: {app: required-client}}
spec:
  nodeSelector: {kubernetes.io/hostname: ${source_node}}
  containers:
  - name: client
    image: ${test_tools_image}
    imagePullPolicy: IfNotPresent
    command: [sh, -ec, "sleep infinity"]
---
apiVersion: v1
kind: Pod
metadata: {name: native-client, namespace: ${namespace}, labels: {app: native-client}}
spec:
  nodeSelector: {kubernetes.io/hostname: ${source_node}}
  containers:
  - name: client
    image: ${test_tools_image}
    imagePullPolicy: IfNotPresent
    command: [sh, -ec, "sleep infinity"]
---
apiVersion: v1
kind: Pod
metadata: {name: required-server, namespace: ${namespace}, labels: {app: required-server}}
spec:
  nodeSelector: {kubernetes.io/hostname: ${destination_node}}
  containers:
  - name: server
    image: ${test_tools_image}
    imagePullPolicy: IfNotPresent
    command: [/usr/local/bin/unf-flow-receiver, "8080"]
---
apiVersion: v1
kind: Pod
metadata: {name: native-server, namespace: ${namespace}, labels: {app: native-server}}
spec:
  nodeSelector: {kubernetes.io/hostname: ${destination_node}}
  containers:
  - name: server
    image: ${test_tools_image}
    imagePullPolicy: IfNotPresent
    command: [/usr/local/bin/unf-flow-receiver, "8081"]
---
apiVersion: v1
kind: Service
metadata: {name: required-server, namespace: ${namespace}}
spec:
  ipFamilyPolicy: RequireDualStack
  selector: {app: required-server}
  ports: [{name: http, port: 8080, targetPort: 8080}]
---
apiVersion: v1
kind: Service
metadata: {name: native-server, namespace: ${namespace}}
spec:
  ipFamilyPolicy: RequireDualStack
  selector: {app: native-server}
  ports: [{name: http, port: 8081, targetPort: 8081}]
EOF
"${kc[@]}" -n "${namespace}" wait --for=condition=Ready pods --all --timeout=10m >/dev/null
pre_fixture_generation=$(jq -r '.[0].generation' <<<"${required_baseline_generation}")
default_generation=$(wait_generation_after "${pre_fixture_generation}")
required_pod4=$("${kc[@]}" -n "${namespace}" get pod required-server -o json | jq -er '.status.podIPs[].ip | select(contains("."))')
required_pod6=$("${kc[@]}" -n "${namespace}" get pod required-server -o json | jq -er '.status.podIPs[].ip | select(contains(":"))')
native_pod4=$("${kc[@]}" -n "${namespace}" get pod native-server -o json | jq -er '.status.podIPs[].ip | select(contains("."))')
native_pod6=$("${kc[@]}" -n "${namespace}" get pod native-server -o json | jq -er '.status.podIPs[].ip | select(contains(":"))')
required_service4=$("${kc[@]}" -n "${namespace}" get service required-server -o json | jq -er '.spec.clusterIPs[] | select(contains("."))')
required_service6=$("${kc[@]}" -n "${namespace}" get service required-server -o json | jq -er '.spec.clusterIPs[] | select(contains(":"))')
native_service4=$("${kc[@]}" -n "${namespace}" get service native-server -o json | jq -er '.spec.clusterIPs[] | select(contains("."))')
native_service6=$("${kc[@]}" -n "${namespace}" get service native-server -o json | jq -er '.spec.clusterIPs[] | select(contains(":"))')
traffic_matrix required-client "${required_pod4}" "${required_pod6}" "${required_service4}" "${required_service6}" 8080
traffic_matrix native-client "${native_pod4}" "${native_pod6}" "${native_service4}" "${native_service6}" 8081

stage=selective-native-exception
set_baseline native
pre_selective_generation=$(jq -r '.[0].generation' <<<"${default_generation}")
"${kc[@]}" apply -f - >/dev/null <<EOF
apiVersion: network.unf.io/v1alpha1
kind: EncryptionPolicy
metadata: {name: ${policy}, namespace: ${namespace}}
spec:
  priority: 1000
  bidirectional: true
  sources: {matchLabels: {app: required-client}}
  destinations: {matchLabels: {app: required-server}}
EOF
selective_generation=$(wait_generation_after "${pre_selective_generation}")
traffic_matrix required-client "${required_pod4}" "${required_pod6}" "${required_service4}" "${required_service6}" 8080
traffic_matrix native-client "${native_pod4}" "${native_pod6}" "${native_service4}" "${native_service6}" 8081

stage=ciphertext-and-fail-closed
source_interface=$(node_exec "${source_node}" jq -er '.active.plans[0].interfaceName' \
    /var/lib/unf/cni/v1/encryption-generation.json.recovery-plan)
source_alias=$(node_exec "${source_node}" ip -j -details link show dev "${source_interface}" | jq -er '.[0].ifalias')
[[ ${source_alias} == unf:encryption:* ]] || {
    echo "refusing to operate an encryption link without the exact UNF ownership alias" >&2
    exit 1
}
"${kc[@]}" apply -f - >/dev/null <<EOF
apiVersion: v1
kind: Pod
metadata: {name: ${capture_pod}, namespace: ${namespace}}
spec:
  serviceAccountName: capture
  nodeName: ${source_node}
  hostNetwork: true
  dnsPolicy: Default
  restartPolicy: Never
  volumes: [{name: capture, emptyDir: {}}]
  containers:
  - name: tcpdump
    image: ${test_tools_image}
    imagePullPolicy: IfNotPresent
    command: [/usr/bin/timeout]
    args: ["--signal=INT", "60", "/usr/bin/tcpdump", "-U", "-ni", "br-ex", "-w", "${capture_container_path}"]
    securityContext: {privileged: true}
    volumeMounts: [{name: capture, mountPath: /capture}]
  - name: keeper
    image: ${test_tools_image}
    imagePullPolicy: IfNotPresent
    command: [/bin/sh, -ec, "trap : TERM INT; sleep infinity & wait"]
    securityContext: {privileged: true}
    volumeMounts: [{name: capture, mountPath: /capture}]
EOF
"${kc[@]}" -n "${namespace}" wait --for=condition=Ready "pod/${capture_pod}" --timeout=3m >/dev/null
sleep 2
for _ in $(seq 1 4); do
    traffic_matrix required-client "${required_pod4}" "${required_pod6}" "${required_service4}" "${required_service6}" 8080
    traffic_matrix native-client "${native_pod4}" "${native_pod6}" "${native_service4}" "${native_service6}" 8081
done
node_exec "${source_node}" ip link set dev "${source_interface}" down >/dev/null
link_lowered=true
required_blocked=0
native_succeeded=0
for family in 4 6 4 6 4 6 4 6; do
    if [[ ${family} == 4 ]]; then
        required_target=${required_pod4}; native_target=${native_pod4}
    else
        required_target=${required_pod6}; native_target=${native_pod6}
    fi
    if ! http_probe_once required-client "${required_target}" 8080 >/dev/null 2>&1; then
        required_blocked=$((required_blocked + 1))
    fi
    if http_probe native-client "${native_target}" 8081 >/dev/null 2>&1; then
        native_succeeded=$((native_succeeded + 1))
    fi
done
[[ ${required_blocked} == 8 && ${native_succeeded} == 8 ]]
node_exec "${source_node}" ip link set dev "${source_interface}" up >/dev/null
link_lowered=false
capture_exit=
for _ in $(seq 1 90); do
    capture_exit=$("${kc[@]}" -n "${namespace}" get pod "${capture_pod}" -o json | jq -r '
        [.status.containerStatuses[] | select(.name == "tcpdump") | .state.terminated.exitCode][0] // empty')
    [[ -n ${capture_exit} ]] && break
    sleep 1
done
[[ ${capture_exit} == 0 || ${capture_exit} == 124 ]]
temporary_capture=$(mktemp)
"${kc[@]}" -n "${namespace}" cp -c keeper \
    "${capture_pod}:${capture_container_path}" "${temporary_capture}"
capture_sha256=$(sha256sum "${temporary_capture}" | awk '{print $1}')
wireguard_frames=$(tcpdump -nn -r "${temporary_capture}" 'udp and (port 51820 or port 51821)' 2>/dev/null | wc -l)
required_plaintext_frames=$(tcpdump -nn -r "${temporary_capture}" \
    "(host ${required_pod4} or host ${required_pod6}) and tcp port 8080" 2>/dev/null | wc -l)
native_plaintext_frames=$(tcpdump -nn -r "${temporary_capture}" \
    "(host ${native_pod4} or host ${native_pod6}) and tcp port 8081" 2>/dev/null | wc -l)
required_http_markers=$(tcpdump -A -nn -r "${temporary_capture}" \
    "(host ${required_pod4} or host ${required_pod6}) and tcp port 8080" 2>/dev/null \
    | rg -c '/health|HTTP/1' || true)
(( wireguard_frames > 0 && required_plaintext_frames == 0 \
    && required_http_markers == 0 && native_plaintext_frames > 0 ))

stage=recovery-and-rotation
pre_agent_recovery_generation=$(wait_generation)
old_agent_json=$("${kc[@]}" -n unf-system get pods -l app.kubernetes.io/name=unf-agent \
    --field-selector "spec.nodeName=${source_node}" -o json)
old_agent=$(jq -er '.items[] | select(.metadata.deletionTimestamp == null) | .metadata.name' <<<"${old_agent_json}" | head -1)
old_agent_uid=$(jq -er --arg pod "${old_agent}" '.items[] | select(.metadata.name == $pod) | .metadata.uid' <<<"${old_agent_json}")
"${kc[@]}" -n unf-system delete pod "${old_agent}" --wait=false >/dev/null
replacement_agent_uid=
for _ in $(seq 1 360); do
    replacement_agent_uid=$("${kc[@]}" -n unf-system get pods -l app.kubernetes.io/name=unf-agent \
        --field-selector "spec.nodeName=${source_node}" -o json 2>/dev/null | jq -r --arg old "${old_agent_uid}" '
        .items[] | select(.metadata.uid != $old and .metadata.deletionTimestamp == null
            and .status.phase == "Running"
            and any(.status.containerStatuses[]; .name == "agent" and .ready)) | .metadata.uid' | head -1)
    [[ -n ${replacement_agent_uid} ]] && break
    sleep 1
done
[[ -n ${replacement_agent_uid} ]]
recovered_generation=$(wait_generation)
jq -e --argjson recovered "${recovered_generation}" '
    length == ($recovered | length)
    and all(.[]; . as $before | any($recovered[]; .node == $before.node))
    and ($recovered[0].generation >= .[0].generation)' <<<"${pre_agent_recovery_generation}" >/dev/null
traffic_matrix required-client "${required_pod4}" "${required_pod6}" "${required_service4}" "${required_service6}" 8080
initial_epoch=$(jq -r --arg node "${source_node}" '.[] | select(.node == $node) | .epochs | max' <<<"${recovered_generation}")
rotated_generation=$(wait_epoch_change "${initial_epoch}")
traffic_matrix required-client "${required_pod4}" "${required_pod6}" "${required_service4}" "${required_service6}" 8080
pre_restart_generation=$(jq -r '.[0].generation' <<<"${rotated_generation}")
"${kc[@]}" -n unf-system rollout restart deployment/unf-controller >/dev/null
"${kc[@]}" -n unf-system rollout status deployment/unf-controller --timeout=10m >/dev/null
restart_generation=$(wait_generation_after "${pre_restart_generation}")

stage=operations-and-convergence
operations_status=$(controller_raw /v1/encryption/status)
operations_history=$(controller_raw /v1/encryption/history)
jq -e '.schemaVersion == 1 and .generation > 0 and .lossAffected == false
    and .completeThroughSequence > 0 and .retainedRecords > 0' <<<"${operations_status}" >/dev/null
jq -e '.schemaVersion == 1 and (.records | length) > 0' <<<"${operations_history}" >/dev/null
final_agents=$(wait_for_convergence)
traffic_matrix required-client "${required_pod4}" "${required_pod6}" "${required_service4}" "${required_service6}" 8080
traffic_matrix native-client "${native_pod4}" "${native_pod6}" "${native_service4}" "${native_service6}" 8081

stage=exact-cleanup
set_baseline native
"${kc[@]}" delete namespace "${namespace}" --wait=true --timeout=10m >/dev/null
resources_created=false
owned_state_absent=false
for _ in $(seq 1 360); do
    owned_state_absent=true
    for node in "${nodes[@]}"; do
        if node_exec "${node}" sh -euc \
            'ip -o link show | grep -q "unfwg" || ip rule show | grep -q "lookup 2000[12]"' >/dev/null 2>&1; then
            owned_state_absent=false
            break
        fi
    done
    [[ ${owned_state_absent} == true ]] && break
    sleep 1
done
[[ ${owned_state_absent} == true ]]
[[ $("${kc[@]}" get encryptionpolicies.network.unf.io -A -o json | jq '.items | length') == 0 ]]
"${kc[@]}" delete namespace "${host_probe_namespace}" --wait=true --timeout=10m >/dev/null
host_probe_created=false
final_agents=$(wait_for_convergence)
"${kc[@]}" wait --for=condition=Ready nodes --all --timeout=10m >/dev/null
final_unhealthy=$(unhealthy_operators)
new_unhealthy=$(jq -cn --argjson baseline "${baseline_unhealthy}" \
    --argjson final "${final_unhealthy}" '$final - $baseline')
jq -e 'length == 0' <<<"${new_unhealthy}" >/dev/null

stage=evidence
mkdir -p "$(dirname "${artifact}")" "$(dirname "${capture_artifact}")"
install -m 0600 "${temporary_capture}" "${capture_artifact}"
rm -f "${temporary_capture}"
capture_size=$(stat -c %s "${capture_artifact}")
node_evidence=$(oc_read get nodes -o json | jq '[.items[] | {
    name:.metadata.name,osImage:.status.nodeInfo.osImage,kernelVersion:.status.nodeInfo.kernelVersion,
    containerRuntime:.status.nodeInfo.containerRuntimeVersion,podCIDRs:.spec.podCIDRs,
    internalIPs:[.status.addresses[] | select(.type == "InternalIP") | .address]}]')
images_observed=$("${kc[@]}" -n unf-system get pods -l 'app.kubernetes.io/name in (unf-controller,unf-agent)' -o json \
    | jq '[.items[] | {pod:.metadata.name,node:.spec.nodeName,phase:(.status.phase // "Unknown"),
        containers:[(.status.containerStatuses // [])[] | {name,image,imageID}]}]')
artifact_tmp="${artifact}.tmp.$$"
jq -n \
    --arg generatedAt "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --arg context "${context}" \
    --arg infrastructure "${infrastructure}" --arg runtimeRevision "${source_revision}" \
    --arg qualificationRevision "${qualification_revision}" \
    --arg openshiftVersion "$("${kc[@]}" get clusterversion version -o jsonpath='{.status.desired.version}')" \
    --arg kubernetesVersion "$("${kc[@]}" version -o json | jq -r .serverVersion.gitVersion)" \
    --arg controllerImage "${controller_image}" --arg agentImage "${agent_image}" \
    --arg testToolsImage "${test_tools_image}" --arg deployEvidence "${deploy_evidence}" \
    --arg sourceNode "${source_node}" --arg destinationNode "${destination_node}" \
    --arg capturePath "${capture_artifact}" --arg captureSha256 "${capture_sha256}" \
    --argjson captureBytes "${capture_size}" --argjson wireguardFrames "${wireguard_frames}" \
    --argjson requiredPlaintextFrames "${required_plaintext_frames}" \
    --argjson nativePlaintextFrames "${native_plaintext_frames}" \
    --argjson requiredBlocked "${required_blocked}" --argjson nativeSucceeded "${native_succeeded}" \
    --argjson durationSeconds "$(( $(date +%s) - started_unix ))" \
    --argjson nodes "${node_evidence}" --argjson images "${images_observed}" \
    --argjson controllerVersion "${controller_version}" --argjson agentVersions "${agent_versions}" \
    --argjson requiredGeneration "${default_generation}" --argjson selectiveGeneration "${selective_generation}" \
    --argjson recoveredGeneration "${recovered_generation}" --argjson rotatedGeneration "${rotated_generation}" \
    --argjson restartGeneration "${restart_generation}" --argjson operations "${operations_status}" \
    --argjson initialAgents "${initial_agents}" --argjson finalAgents "${final_agents}" \
    --argjson baselineUnhealthy "${baseline_unhealthy}" --argjson finalUnhealthy "${final_unhealthy}" \
    --argjson newUnhealthy "${new_unhealthy}" '
    {schemaVersion:1,milestone:"9.9",result:"passed",generatedAt:$generatedAt,
      context:$context,infrastructure:$infrastructure,runtimeRevision:$runtimeRevision,
      qualificationRevision:$qualificationRevision,openshiftVersion:$openshiftVersion,
      kubernetesVersion:$kubernetesVersion,durationSeconds:$durationSeconds,kubeProxyPresent:false,
      images:{controller:$controllerImage,agent:$agentImage,testTools:$testToolsImage},
      deployEvidence:$deployEvidence,topology:{nodeCount:($nodes|length),sourceNode:$sourceNode,
        destinationNode:$destinationNode},nodes:$nodes,imagesObserved:$images,
      componentVersions:{controller:$controllerVersion,agents:$agentVersions},
      migration:{explicitlyAcknowledged:true,defaultRequired:"passed",generations:$requiredGeneration},
      selective:{result:"passed",generations:$selectiveGeneration},
      traffic:{directDualStack:"passed",serviceDualStack:"passed"},
      capture:{path:$capturePath,sha256:$captureSha256,bytes:$captureBytes,
        wireguardFrames:$wireguardFrames,requiredPlaintextFrames:$requiredPlaintextFrames,
        nativePlaintextFrames:$nativePlaintextFrames},
      failClosed:{requiredBlocked:$requiredBlocked,nativeSucceeded:$nativeSucceeded},
      recovery:{agent:$recoveredGeneration,controller:$restartGeneration},
      rotation:{result:"passed",generations:$rotatedGeneration},
      operations:{result:"passed",generation:$operations.generation,
        completeThroughSequence:$operations.completeThroughSequence,
        retainedRecords:$operations.retainedRecords,lossAffected:$operations.lossAffected},
      cleanup:"passed",initialAgents:$initialAgents,finalAgents:$finalAgents,
      baselineUnhealthyOperators:$baselineUnhealthy,finalUnhealthyOperators:$finalUnhealthy,
      newlyUnhealthyOperators:$newUnhealthy,
      verified:["exact Kind-qualified public image digests","five-node dual-stack UNF primary CNI",
        "OpenShift RHCOS, enforcing SELinux, and CRI-O","kube-proxy absence",
        "explicitly acknowledged Native-to-Required migration","cross-worker IPv4 and IPv6 PodIP and ClusterIP",
        "WireGuard-positive Required-plaintext-negative underlay capture",
        "Required fail-closed with simultaneous Native exception","natural two-epoch rotation",
        "controlled agent replacement and separate controller replacement","loss-free causal operations",
        "exact intent, link, route, and fixture cleanup","five-agent final convergence",
        "no newly unhealthy ClusterOperator beyond the recorded baseline"],
      excluded:["production availability and scale","simultaneous replacement of every encrypted endpoint",
        "transparent host-network or control-plane encryption","cross-cluster encryption",
        "overlapping CIDRs","post-quantum cryptography","hardware or TPM attestation"]}
' >"${artifact_tmp}"
chmod 0600 "${artifact_tmp}"
mv -f "${artifact_tmp}" "${artifact}"
artifact_tmp=

trap - ERR EXIT
echo "OpenShift cl02 Phase 9.9 encryption qualification passed"
echo "evidence: ${artifact}"
