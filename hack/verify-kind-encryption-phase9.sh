#!/usr/bin/env bash
set -Eeuo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
kubeconfig=${KUBECONFIG:-"${project_root}/.tools/kind-unf-service-dev.kubeconfig"}
context=${KUBE_CONTEXT:-kind-unf-service-dev}
container_runtime=${KIND_PROVIDER:-podman}
test_tools_image=${UNF_TEST_TOOLS_IMAGE:-localhost/unf-test-tools:ipv6-ext-v1}
artifact=${UNF_PHASE9_KIND_EVIDENCE:-"${project_root}/.artifacts/phase9-encryption-kind.json"}
capture_artifact=${UNF_PHASE9_KIND_CAPTURE:-"${project_root}/.artifacts/phase9-encryption-kind.pcap"}
expected_runtime_revision=${UNF_PHASE9_RUNTIME_REVISION:-}
run_egress=${UNF_PHASE9_RUN_EGRESS:-true}
run_rollback=${UNF_PHASE9_RUN_ROLLBACK:-true}
namespace=unf-encryption-phase9-qualification
policy=required-pair
capture_container_path=/tmp/unf-phase9-encryption.pcap
started_unix_seconds=$(date +%s)
diagnostics_dir=${UNF_PHASE9_KIND_DIAGNOSTICS:-"${project_root}/.artifacts/phase9-kind-${started_unix_seconds}"}
temporary_dir=$(mktemp -d)
capture_host_path=${temporary_dir}/underlay.pcap
qualification_stage=preflight
resources_created=false
link_lowered=false
capture_pid=
capture_node=
kc=(kubectl --kubeconfig "${kubeconfig}" --context "${context}")
runtime=(sudo "${container_runtime}")

bool() {
    [[ $1 == true || $1 == false ]] || {
        echo "$2 must be true or false" >&2
        exit 1
    }
}

bool "${run_egress}" UNF_PHASE9_RUN_EGRESS
bool "${run_rollback}" UNF_PHASE9_RUN_ROLLBACK

collect_diagnostics() {
    mkdir -p "${diagnostics_dir}"
    "${kc[@]}" get nodes -o wide >"${diagnostics_dir}/nodes.txt" 2>&1 || true
    "${kc[@]}" -n unf-system get pods -o wide >"${diagnostics_dir}/unf-pods.txt" 2>&1 || true
    "${kc[@]}" -n unf-system logs deployment/unf-controller --all-pods=true \
        >"${diagnostics_dir}/controller.log" 2>&1 || true
    "${kc[@]}" -n unf-system logs daemonset/unf-agent --all-pods=true --prefix \
        >"${diagnostics_dir}/agents.log" 2>&1 || true
    "${kc[@]}" -n "${namespace}" get all,encryptionpolicy.network.unf.io -o yaml \
        >"${diagnostics_dir}/fixture.yaml" 2>&1 || true
    for node in "${nodes[@]:-}"; do
        "${runtime[@]}" exec "${node}" sh -ec \
            'ip -details link show; ip -4 route show table all; ip -6 route show table all; ip rule show' \
            >"${diagnostics_dir}/${node}-network.txt" 2>&1 || true
    done
}

report_failure() {
    local status=$?
    local line=${BASH_LINENO[0]:-unknown}
    collect_diagnostics
    echo "Phase 9.8 Kind qualification failed during ${qualification_stage} at line ${line}: ${BASH_COMMAND}" >&2
    echo "diagnostics: ${diagnostics_dir}" >&2
    return "${status}"
}

cleanup() {
    if [[ -n ${capture_pid} && -n ${capture_node} ]]; then
        "${runtime[@]}" exec "${capture_node}" kill -INT "${capture_pid}" >/dev/null 2>&1 || true
    fi
    if [[ ${link_lowered} == true && -n ${source_node:-} && -n ${source_interface:-} ]]; then
        "${runtime[@]}" exec "${source_node}" ip link set dev "${source_interface}" up \
            >/dev/null 2>&1 || true
    fi
    if [[ ${resources_created} == true ]]; then
        "${kc[@]}" delete namespace "${namespace}" --ignore-not-found --wait=false \
            >/dev/null 2>&1 || true
    fi
    rm -rf "${temporary_dir}"
}

trap report_failure ERR
trap cleanup EXIT

for command in awk curl git jq kubectl rg sha256sum sudo tcpdump "${container_runtime}"; do
    command -v "${command}" >/dev/null 2>&1 || {
        echo "${command} is required for Phase 9.8 Kind qualification" >&2
        exit 1
    }
done
[[ ${context} == kind-* ]] || {
    echo "refusing Phase 9.8 qualification outside a Kind context" >&2
    exit 1
}
[[ $("${kc[@]}" config current-context) == "${context}" ]] || {
    echo "kubeconfig current context is not exact qualification context ${context}" >&2
    exit 1
}
git -C "${project_root}" diff --quiet
git -C "${project_root}" diff --cached --quiet
qualification_revision=$(git -C "${project_root}" rev-parse HEAD)
if "${kc[@]}" -n kube-system get daemonset kube-proxy >/dev/null 2>&1 \
    || "${kc[@]}" -n kube-system get pods -l k8s-app=kube-proxy -o name | rg -q .; then
    echo "Phase 9.8 requires kube-proxy-free Kind" >&2
    exit 1
fi
if "${kc[@]}" get namespace "${namespace}" >/dev/null 2>&1; then
    echo "dedicated Phase 9 namespace already exists; refusing to adopt it" >&2
    exit 1
fi
if [[ $("${kc[@]}" get encryptionpolicies.network.unf.io -A -o json | jq '.items | length') != 0 ]]; then
    echo "Phase 9.8 requires a dedicated cluster with no existing encryption intent" >&2
    exit 1
fi

mapfile -t workers < <("${kc[@]}" get nodes -l '!node-role.kubernetes.io/control-plane' \
    -o name | sed 's|node/||' | sort)
control_plane=$("${kc[@]}" get nodes -l node-role.kubernetes.io/control-plane \
    -o jsonpath='{.items[0].metadata.name}')
(( ${#workers[@]} == 2 )) && [[ -n ${control_plane} ]] || {
    echo "Phase 9.8 requires one control-plane and exactly two workers" >&2
    exit 1
}
source_node=${workers[0]}
destination_node=${workers[1]}
nodes=("${control_plane}" "${workers[@]}")
nodes_json=$("${kc[@]}" get nodes -o json)
jq -e '(.items | length) == 3
    and all(.items[];
        .metadata.labels["network.unf.io/primary-cni"] == "enabled"
        and any(.status.conditions[]; .type == "Ready" and .status == "True")
        and ([.spec.podCIDRs[] | select(contains("."))] | length) == 1
        and ([.spec.podCIDRs[] | select(contains(":"))] | length) == 1)' \
    <<<"${nodes_json}" >/dev/null || {
    echo "all three Nodes must be Ready, dual-stack, and owned by the UNF primary CNI" >&2
    exit 1
}
for node in "${nodes[@]}"; do
    "${runtime[@]}" exec "${node}" sh -ec '
        test "$(find /etc/cni/net.d -mindepth 1 -maxdepth 1 -type f | wc -l)" -eq 1
        test -f /etc/cni/net.d/10-unf.conflist
        test -S /run/unf/cni.sock
        ! iptables-save 2>/dev/null | grep -q "^-A KUBE-SVC"
        ! ip6tables-save 2>/dev/null | grep -q "^-A KUBE-SVC"
    '
done

controller_raw() {
    local path=$1 pod
    pod=$("${kc[@]}" -n unf-system get pods -l app.kubernetes.io/name=unf-controller -o json |
        jq -r '.items[] | select(.metadata.deletionTimestamp == null and .status.phase == "Running") | .metadata.name' |
        head -n 1)
    [[ -n ${pod} ]]
    "${kc[@]}" get --raw "/api/v1/namespaces/unf-system/pods/${pod}:9962/proxy${path}"
}

generation_snapshot() {
    local node
    for node in "${nodes[@]}"; do
        "${runtime[@]}" exec "${node}" jq -cer --arg node "${node}" '
            {
                node: $node,
                generation: .active.fact.checkpoint.transaction.desired.published.generation,
                pending: (if .pending == null then null else
                    .pending.fact.checkpoint.transaction.desired.published.generation end),
                epochs: [.active.plans[].epoch] | sort
            }
        ' /var/lib/unf/cni/v1/encryption-generation.json.recovery-plan
    done | jq -sc 'sort_by(.node)'
}

wait_generation() {
    local require_generation=${1:-true} snapshot=
    for _ in $(seq 1 240); do
        snapshot=$(generation_snapshot 2>/dev/null || true)
        if jq -e --argjson required "${require_generation}" '
            length == 3
            and all(.[]; .pending == null)
            and (if $required then
                (.[0].generation != null and ([.[].generation] | unique | length) == 1)
            else true end)
        ' <<<"${snapshot}" >/dev/null 2>&1; then
            printf '%s\n' "${snapshot}"
            return 0
        fi
        sleep 1
    done
    echo "encryption generations did not converge" >&2
    jq . <<<"${snapshot}" >&2 || true
    return 1
}

wait_generation_after() {
    local predecessor=$1 snapshot= generation=
    for _ in $(seq 1 240); do
        snapshot=$(wait_generation true)
        generation=$(jq -r '.[0].generation' <<<"${snapshot}")
        if [[ ${generation} =~ ^[0-9]+$ ]] && (( generation > predecessor )); then
            printf '%s\n' "${snapshot}"
            return 0
        fi
        sleep 1
    done
    echo "encryption generation did not advance beyond ${predecessor}" >&2
    return 1
}

set_baseline() {
    local value=$1
    "${kc[@]}" -n unf-system set env deployment/unf-controller \
        "UNF_ENCRYPTION_BASELINE=${value}" >/dev/null
    "${kc[@]}" -n unf-system rollout status deployment/unf-controller --timeout=180s >/dev/null
}

http_probe_once() {
    local pod=$1 address=$2 port=$3 target
    if [[ ${address} == *:* ]]; then target="http://[${address}]:${port}/health"; else target="http://${address}:${port}/health"; fi
    "${kc[@]}" -n "${namespace}" exec "${pod}" -- wget -T 3 -t 1 -qO- "${target}" | rg -qx ok
}

http_probe() {
    local pod=$1 address=$2 port=$3
    for _ in $(seq 1 30); do
        if http_probe_once "${pod}" "${address}" "${port}" >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    echo "HTTP readiness probe failed from ${pod} to ${address}:${port}" >&2
    return 1
}

http_probe_fails() {
    ! http_probe_once "$@" >/dev/null 2>&1
}

traffic_matrix() {
    local client=$1 pod4=$2 pod6=$3 service4=$4 service6=$5 port=$6
    http_probe "${client}" "${pod4}" "${port}"
    http_probe "${client}" "${pod6}" "${port}"
    http_probe "${client}" "${service4}" "${port}"
    http_probe "${client}" "${service6}" "${port}"
}

wait_epoch_change() {
    local initial_epoch=$1 snapshot= epoch=
    for _ in $(seq 1 240); do
        snapshot=$(wait_generation true)
        epoch=$(jq -r --arg node "${source_node}" '.[] | select(.node == $node) | .epochs | max' <<<"${snapshot}")
        if [[ ${epoch} =~ ^[0-9]+$ ]] && (( epoch > initial_epoch )); then
            printf '%s\n' "${snapshot}"
            return 0
        fi
        sleep 1
    done
    echo "automatic encryption epoch rotation did not complete" >&2
    return 1
}

qualification_stage=immutable-provenance
"${kc[@]}" -n unf-system rollout status deployment/unf-controller --timeout=180s >/dev/null
"${kc[@]}" -n unf-system rollout status daemonset/unf-agent --timeout=180s >/dev/null
controller_version=$(controller_raw /v1/version)
runtime_revision=$(jq -er '.build_revision' <<<"${controller_version}")
[[ ${runtime_revision} =~ ^[0-9a-f]{40}$ ]] || {
    echo "controller does not expose a full immutable build revision" >&2
    exit 1
}
git -C "${project_root}" merge-base --is-ancestor "${runtime_revision}" "${qualification_revision}"
if [[ -n ${expected_runtime_revision} && ${runtime_revision} != "${expected_runtime_revision}" ]]; then
    echo "runtime revision ${runtime_revision} does not match expected ${expected_runtime_revision}" >&2
    exit 1
fi
agent_versions='[]'
while read -r agent_pod; do
    agent_version=$("${kc[@]}" get --raw \
        "/api/v1/namespaces/unf-system/pods/${agent_pod}:9963/proxy/v1/version")
    jq -e --arg revision "${runtime_revision}" '
        .component == "unf-agent" and .build_revision == $revision
        and .encryption_model_schema_version > 0
        and .encryption_map_abi_version > 0
        and .encryption_operations_schema_version > 0
    ' <<<"${agent_version}" >/dev/null
    agent_versions=$(jq -c --argjson version "${agent_version}" '. + [$version]' <<<"${agent_versions}")
done < <("${kc[@]}" -n unf-system get pods -l app.kubernetes.io/name=unf-agent \
    -o name | sed 's|pod/||' | sort)
jq -e 'length == 3' <<<"${agent_versions}" >/dev/null
# Runtime image IDs come from status, not the declarative PodSpec.
images_json=$("${kc[@]}" -n unf-system get pods -o json | jq -c '
    [.items[]
     | select(.metadata.labels["app.kubernetes.io/name"] == "unf-agent"
         or .metadata.labels["app.kubernetes.io/name"] == "unf-controller")
     | .metadata.name as $pod
     | .spec.nodeName as $node
     | .spec.containers[] as $spec
     | .status.containerStatuses[]
     | select(.name == $spec.name and (.name == "agent" or .name == "controller"))
     | {pod:$pod,node:$node,component:.name,image:$spec.image,imageID:.imageID,ready:.ready,restarts:.restartCount}]
    | sort_by(.component,.node)')
jq -e 'length == 4 and all(.[];
    .ready == true and .restarts == 0
    and (.image | test("@sha256:|:[A-Za-z0-9._-]+$"))
    and (.imageID | startswith("sha256:")))' <<<"${images_json}" >/dev/null || {
    echo "controller/agent Pods do not expose one healthy immutable runtime tuple" >&2
    exit 1
}

qualification_stage=default-required
set_baseline required
pre_fixture_generation=$(wait_generation true)
pre_fixture_generation=$(jq -r '.[0].generation' <<<"${pre_fixture_generation}")
"${kc[@]}" apply -f - >/dev/null <<EOF
apiVersion: v1
kind: Namespace
metadata:
  name: ${namespace}
---
apiVersion: v1
kind: Pod
metadata:
  name: required-client
  namespace: ${namespace}
  labels: {app: required-client}
spec:
  nodeSelector: {kubernetes.io/hostname: ${source_node}}
  containers:
    - name: client
      image: ${test_tools_image}
      imagePullPolicy: Never
      command: [sh, -ec, "sleep infinity"]
---
apiVersion: v1
kind: Pod
metadata:
  name: native-client
  namespace: ${namespace}
  labels: {app: native-client}
spec:
  nodeSelector: {kubernetes.io/hostname: ${source_node}}
  containers:
    - name: client
      image: ${test_tools_image}
      imagePullPolicy: Never
      command: [sh, -ec, "sleep infinity"]
---
apiVersion: v1
kind: Pod
metadata:
  name: required-server
  namespace: ${namespace}
  labels: {app: required-server}
spec:
  nodeSelector: {kubernetes.io/hostname: ${destination_node}}
  containers:
    - name: server
      image: ${test_tools_image}
      imagePullPolicy: Never
      command: [/usr/local/bin/unf-flow-receiver, "8080"]
---
apiVersion: v1
kind: Pod
metadata:
  name: native-server
  namespace: ${namespace}
  labels: {app: native-server}
spec:
  nodeSelector: {kubernetes.io/hostname: ${destination_node}}
  containers:
    - name: server
      image: ${test_tools_image}
      imagePullPolicy: Never
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
resources_created=true
"${kc[@]}" -n "${namespace}" wait --for=condition=Ready pods --all --timeout=180s >/dev/null
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

qualification_stage=selective-native-exception
set_baseline native
pre_selective_generation=$(jq -r '.[0].generation' <<<"${default_generation}")
"${kc[@]}" apply -f - >/dev/null <<EOF
apiVersion: network.unf.io/v1alpha1
kind: EncryptionPolicy
metadata:
  name: ${policy}
  namespace: ${namespace}
spec:
  priority: 1000
  bidirectional: true
  sources:
    matchLabels: {app: required-client}
  destinations:
    matchLabels: {app: required-server}
EOF
selective_generation=$(wait_generation_after "${pre_selective_generation}")
traffic_matrix required-client "${required_pod4}" "${required_pod6}" "${required_service4}" "${required_service6}" 8080
traffic_matrix native-client "${native_pod4}" "${native_pod6}" "${native_service4}" "${native_service6}" 8081

qualification_stage=ciphertext-and-fail-closed
source_interface=$("${runtime[@]}" exec "${source_node}" jq -er '.active.plans[0].interfaceName' \
    /var/lib/unf/cni/v1/encryption-generation.json.recovery-plan)
source_alias=$("${runtime[@]}" exec "${source_node}" ip -j -details link show dev "${source_interface}" |
    jq -er '.[0].ifalias')
[[ ${source_alias} == unf:encryption:* ]] || {
    echo "refusing to operate an encryption link without the exact UNF ownership alias" >&2
    exit 1
}
capture_node=${source_node}
"${runtime[@]}" exec "${capture_node}" rm -f "${capture_container_path}"
"${runtime[@]}" exec "${capture_node}" sh -ec \
    "tcpdump -U -ni eth0 -w '${capture_container_path}' >/tmp/unf-phase9-tcpdump.log 2>&1 & echo \$!" \
    >"${temporary_dir}/capture.pid"
capture_pid=$(<"${temporary_dir}/capture.pid")
sleep 1
for _ in $(seq 1 4); do
    traffic_matrix required-client "${required_pod4}" "${required_pod6}" "${required_service4}" "${required_service6}" 8080
    traffic_matrix native-client "${native_pod4}" "${native_pod6}" "${native_service4}" "${native_service6}" 8081
done
"${runtime[@]}" exec "${source_node}" ip link set dev "${source_interface}" down
link_lowered=true
required_blocked=0
native_succeeded=0
for family in 4 6 4 6 4 6 4 6; do
    if [[ ${family} == 4 ]]; then required_target=${required_pod4}; native_target=${native_pod4}; else required_target=${required_pod6}; native_target=${native_pod6}; fi
    http_probe_fails required-client "${required_target}" 8080 && required_blocked=$((required_blocked + 1))
    http_probe native-client "${native_target}" 8081 && native_succeeded=$((native_succeeded + 1))
done
[[ ${required_blocked} == 8 && ${native_succeeded} == 8 ]]
"${runtime[@]}" exec "${source_node}" ip link set dev "${source_interface}" up
link_lowered=false
"${runtime[@]}" exec "${capture_node}" kill -INT "${capture_pid}" >/dev/null 2>&1 || true
for _ in $(seq 1 20); do
    "${runtime[@]}" exec "${capture_node}" test ! -d "/proc/${capture_pid}" && break
    sleep 0.2
done
capture_pid=
"${runtime[@]}" cp "${capture_node}:${capture_container_path}" "${capture_host_path}"
capture_sha256=$(sha256sum "${capture_host_path}" | awk '{print $1}')
wireguard_frames=$(tcpdump -nn -r "${capture_host_path}" 'udp and (port 51820 or port 51821)' 2>/dev/null | wc -l)
required_plaintext_frames=$(tcpdump -nn -r "${capture_host_path}" \
    "(host ${required_pod4} or host ${required_pod6}) and tcp port 8080" 2>/dev/null | wc -l)
native_plaintext_frames=$(tcpdump -nn -r "${capture_host_path}" \
    "(host ${native_pod4} or host ${native_pod6}) and tcp port 8081" 2>/dev/null | wc -l)
required_http_markers=$(tcpdump -A -nn -r "${capture_host_path}" \
    "(host ${required_pod4} or host ${required_pod6}) and tcp port 8080" 2>/dev/null |
    rg -c '/health|HTTP/1' || true)
(( wireguard_frames > 0 && required_plaintext_frames == 0 && required_http_markers == 0 && native_plaintext_frames > 0 ))

qualification_stage=recovery-and-rotation
old_agent=$("${kc[@]}" -n unf-system get pods -l app.kubernetes.io/name=unf-agent \
    --field-selector "spec.nodeName=${source_node}" -o jsonpath='{.items[0].metadata.name}')
"${kc[@]}" -n unf-system delete pod "${old_agent}" --wait=false >/dev/null
"${kc[@]}" -n unf-system rollout status daemonset/unf-agent --timeout=180s >/dev/null
recovered_generation=$(wait_generation true)
traffic_matrix required-client "${required_pod4}" "${required_pod6}" "${required_service4}" "${required_service6}" 8080
initial_epoch=$(jq -r --arg node "${source_node}" '.[] | select(.node == $node) | .epochs | max' <<<"${recovered_generation}")
rotated_generation=$(wait_epoch_change "${initial_epoch}")
traffic_matrix required-client "${required_pod4}" "${required_pod6}" "${required_service4}" "${required_service6}" 8080
"${kc[@]}" -n unf-system rollout restart deployment/unf-controller >/dev/null
"${kc[@]}" -n unf-system rollout status deployment/unf-controller --timeout=180s >/dev/null
restart_generation=$(wait_generation true)

qualification_stage=operations-and-performance
operations_status=$(controller_raw /v1/encryption/status)
operations_history=$(controller_raw /v1/encryption/history)
jq -e '.schemaVersion == 1 and .generation > 0 and .lossAffected == false
    and .completeThroughSequence > 0 and .retainedRecords > 0' <<<"${operations_status}" >/dev/null
jq -e '.schemaVersion == 1 and (.records | length) > 0' <<<"${operations_history}" >/dev/null
"${project_root}/hack/verify-encryption-performance.sh" >/dev/null
performance_started=$(date +%s%N)
for _ in $(seq 1 16); do
    http_probe required-client "${required_service4}" 8080
    http_probe required-client "${required_service6}" 8080
done
performance_elapsed_ns=$(( $(date +%s%N) - performance_started ))

qualification_stage=egress-coexistence
egress_result=skipped
if [[ ${run_egress} == true ]]; then
    KUBECONFIG="${kubeconfig}" KUBE_CONTEXT="${context}" KIND_PROVIDER="${container_runtime}" \
        UNF_TEST_TOOLS_IMAGE="${test_tools_image}" \
        "${project_root}/hack/verify-kind-egress-lifecycle.sh"
    egress_result=passed
fi

qualification_stage=exact-cleanup
"${kc[@]}" delete namespace "${namespace}" --wait=true --timeout=180s >/dev/null
resources_created=false
for _ in $(seq 1 180); do
    absent=true
    for node in "${nodes[@]}"; do
        if "${runtime[@]}" exec "${node}" sh -ec \
            'ip -o link show | grep -q "unfwg" || ip rule show | grep -q "lookup 2000[12]"'; then
            absent=false
            break
        fi
    done
    [[ ${absent} == true ]] && break
    sleep 1
done
[[ ${absent} == true ]] || {
    echo "owned encryption links or route rules remained after the bounded drain" >&2
    exit 1
}

mkdir -p "$(dirname "${artifact}")" "$(dirname "${capture_artifact}")"
install -m 0600 "${capture_host_path}" "${capture_artifact}"
artifact_tmp=${artifact}.tmp.$$
jq -n \
    --arg revision "${runtime_revision}" \
    --arg qualificationRevision "${qualification_revision}" \
    --arg context "${context}" \
    --argjson images "${images_json}" \
    --argjson controllerVersion "${controller_version}" \
    --argjson agentVersions "${agent_versions}" \
    --argjson nodes "${nodes_json}" \
    --argjson defaultGeneration "${default_generation}" \
    --argjson selectiveGeneration "${selective_generation}" \
    --argjson recoveredGeneration "${recovered_generation}" \
    --argjson rotatedGeneration "${rotated_generation}" \
    --argjson restartGeneration "${restart_generation}" \
    --arg captureSha256 "${capture_sha256}" \
    --arg capturePath "${capture_artifact}" \
    --argjson wireguardFrames "${wireguard_frames}" \
    --argjson requiredPlaintextFrames "${required_plaintext_frames}" \
    --argjson nativePlaintextFrames "${native_plaintext_frames}" \
    --argjson requiredBlocked "${required_blocked}" \
    --argjson nativeSucceeded "${native_succeeded}" \
    --argjson performanceElapsedNs "${performance_elapsed_ns}" \
    --arg egress "${egress_result}" \
    --arg rollback "$(if [[ ${run_rollback} == true ]]; then printf pending; else printf skipped; fi)" \
    --argjson operations "${operations_status}" '
    {
      schemaVersion: 1,
      milestone: "9.8",
      runtimeRevision: $revision,
      qualificationRevision: $qualificationRevision,
      context: $context,
      platform: [$nodes.items[] | {name:.metadata.name, osImage:.status.nodeInfo.osImage,
        kernel:.status.nodeInfo.kernelVersion, runtime:.status.nodeInfo.containerRuntimeVersion}],
      images: $images,
      componentVersions: {controller:$controllerVersion, agents:$agentVersions},
      defaultRequired: {result:"passed", generations:$defaultGeneration},
      explicitSelective: {result:"passed", generations:$selectiveGeneration},
      traffic: {directDualStack:"passed", serviceDualStack:"passed"},
      capture: {path:$capturePath, sha256:$captureSha256, wireguardFrames:$wireguardFrames,
        requiredPlaintextFrames:$requiredPlaintextFrames,
        nativePlaintextFrames:$nativePlaintextFrames},
      failClosed: {requiredBlocked:$requiredBlocked, nativeSucceeded:$nativeSucceeded},
      recovery: {agent:$recoveredGeneration, controller:$restartGeneration},
      rotation: {result:"passed", generations:$rotatedGeneration},
      operations: {result:"passed", generation:$operations.generation,
        completeThroughSequence:$operations.completeThroughSequence,
        retainedRecords:$operations.retainedRecords, lossAffected:$operations.lossAffected},
      performance: {result:"passed", requests:32, elapsedNanoseconds:$performanceElapsedNs,
        committedLedger:"docs/benchmarks/phase9-encryption-performance.json"},
      egressCoexistence: $egress,
      cleanup: "passed",
      rollback: $rollback
    }' >"${artifact_tmp}"
mv "${artifact_tmp}" "${artifact}"

if [[ ${run_rollback} == true ]]; then
    qualification_stage=no-cni-rollback
    KUBECONFIG="${kubeconfig}" KUBE_CONTEXT="${context}" KIND_PROVIDER="${container_runtime}" \
        "${project_root}/hack/rollback-kind-primary-cni.sh"
    jq '.rollback = "passed"' "${artifact}" >"${artifact_tmp}"
    mv "${artifact_tmp}" "${artifact}"
fi

trap - ERR
echo "Phase 9.8 kube-proxy-free dual-stack Kind qualification passed"
echo "evidence: ${artifact}"
