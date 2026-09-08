#!/usr/bin/env bash
set -Eeuo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
kubeconfig=${KUBECONFIG:-"${project_root}/.tools/kind-unf-service-dev.kubeconfig"}
context=${KUBE_CONTEXT:-kind-unf-service-dev}
container_runtime=${KIND_PROVIDER:-podman}
test_tools_image=${UNF_TEST_TOOLS_IMAGE:-localhost/unf-test-tools:ipv6-ext-v1}
artifact=${UNF_PHASE8_KIND_EVIDENCE:-"${project_root}/.artifacts/phase8-egress-complete-kind.json"}
expected_runtime_revision=${UNF_PHASE8_RUNTIME_REVISION:-}
started_unix_seconds=$(date +%s)
component_dir=${UNF_PHASE8_KIND_COMPONENT_DIR:-"${project_root}/.artifacts/phase8-egress-kind-components-${started_unix_seconds}"}
qualification_stage=preflight
kc=(kubectl --kubeconfig "${kubeconfig}" --context "${context}")

report_failure() {
    local status=$?
    trap - ERR
    echo "Phase 8.10 Kind qualification failed during ${qualification_stage}: ${BASH_COMMAND}" >&2
    echo "component evidence: ${component_dir}" >&2
    exit "${status}"
}
trap report_failure ERR

for command in git jq kubectl sha256sum sudo "${container_runtime}"; do
    command -v "${command}" >/dev/null
done
if [[ ${context} != kind-* ]] || [[ $("${kc[@]}" config current-context) != "${context}" ]]; then
    echo "refusing Phase 8.10 qualification outside exact Kind context ${context}" >&2
    exit 1
fi
git -C "${project_root}" diff --quiet
git -C "${project_root}" diff --cached --quiet
qualification_revision=$(git -C "${project_root}" rev-parse HEAD)
if "${kc[@]}" -n kube-system get daemonset kube-proxy >/dev/null 2>&1; then
    echo "Phase 8.10 requires a kube-proxy-free cluster" >&2
    exit 1
fi

mapfile -t nodes < <("${kc[@]}" get nodes -o name | sed 's|node/||' | sort)
(( ${#nodes[@]} == 3 ))
nodes_json=$("${kc[@]}" get nodes -o json)
jq -e '
  (.items | length) == 3
  and all(.items[];
    any(.status.conditions[]; .type == "Ready" and .status == "True")
    and ([.spec.podCIDRs[] | select(contains("."))] | length) == 1
    and ([.spec.podCIDRs[] | select(contains(":"))] | length) == 1
    and ([.status.addresses[] | select(.type == "InternalIP" and (.address | contains(".")))] | length) == 1
    and ([.status.addresses[] | select(.type == "InternalIP" and (.address | contains(":")))] | length) == 1
    and .metadata.labels["network.unf.io/primary-cni"] == "enabled")
' <<<"${nodes_json}" >/dev/null

controller_pod=$("${kc[@]}" -n unf-system get pods \
    -l app.kubernetes.io/name=unf-controller -o json \
    | jq -er '.items[] | select(.metadata.deletionTimestamp == null and .status.phase == "Running") | .metadata.name' \
    | head -n1)
controller_version=$("${kc[@]}" get --raw \
    "/api/v1/namespaces/unf-system/pods/${controller_pod}:9962/proxy/v1/version")
runtime_revision=$(jq -er '.build_revision' <<<"${controller_version}")
[[ ${runtime_revision} =~ ^[0-9a-f]{40}$ ]]
git -C "${project_root}" merge-base --is-ancestor "${runtime_revision}" "${qualification_revision}"
if [[ -n ${expected_runtime_revision} && ${runtime_revision} != "${expected_runtime_revision}" ]]; then
    echo "runtime revision ${runtime_revision} does not match expected ${expected_runtime_revision}" >&2
    exit 1
fi
jq -e '
  .schema_version == 2 and .persistent_bpf_state_abi_version == 15
  and .egress_distribution_schema_version > 0
  and .egress_host_state_schema_version > 0
  and .egress_ha_promotion_schema_version > 0
  and .egress_map_schema_version > 0
  and .egress_event_schema_version > 0
' <<<"${controller_version}" >/dev/null

agent_versions='[]'
while read -r agent_pod; do
    agent_version=$("${kc[@]}" get --raw \
        "/api/v1/namespaces/unf-system/pods/${agent_pod}:9963/proxy/v1/version")
    jq -e --arg revision "${runtime_revision}" --argjson controller "${controller_version}" '
      .component == "unf-agent" and .build_revision == $revision
      and .persistent_bpf_state_abi_version == $controller.persistent_bpf_state_abi_version
      and .egress_distribution_schema_version == $controller.egress_distribution_schema_version
      and .egress_host_state_schema_version == $controller.egress_host_state_schema_version
      and .egress_ha_promotion_schema_version == $controller.egress_ha_promotion_schema_version
      and .egress_map_schema_version == $controller.egress_map_schema_version
      and .egress_event_schema_version == $controller.egress_event_schema_version
    ' <<<"${agent_version}" >/dev/null
    agent_versions=$(jq -c --arg pod "${agent_pod}" --argjson version "${agent_version}" \
        '. + [{pod:$pod,version:$version}]' <<<"${agent_versions}")
done < <("${kc[@]}" -n unf-system get pods -l app.kubernetes.io/name=unf-agent \
    -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' | sort)
[[ $(jq 'length' <<<"${agent_versions}") == 3 ]]

mkdir -p "${component_dir}" "$(dirname "${artifact}")"
components='[]'

run_component() {
    local name=$1 evidence_variable=$2 script=$3
    local evidence="${component_dir}/${name}.json" started completed duration hash relative
    qualification_stage="${name}"
    started=$(date +%s)
    env KUBECONFIG="${kubeconfig}" KUBE_CONTEXT="${context}" \
        KIND_PROVIDER="${container_runtime}" UNF_TEST_TOOLS_IMAGE="${test_tools_image}" \
        "${evidence_variable}=${evidence}" "${project_root}/${script}"
    completed=$(date +%s)
    duration=$((completed - started))
    jq -e --arg revision "${qualification_revision}" --arg context "${context}" '
      .schemaVersion == 1 and .revision == $revision and .context == $context
    ' "${evidence}" >/dev/null
    hash=$(sha256sum "${evidence}" | cut -d ' ' -f1)
    relative=${evidence#"${project_root}/"}
    components=$(jq -c --arg name "${name}" --arg evidence "${relative}" \
        --arg sha256 "${hash}" --argjson durationSeconds "${duration}" \
        '. + [{name:$name,evidence:$evidence,sha256:$sha256,durationSeconds:$durationSeconds}]' \
        <<<"${components}")
}

run_component watched-lifecycle UNF_EGRESS_KIND_EVIDENCE hack/verify-kind-egress-lifecycle.sh
run_component measured-ha UNF_EGRESS_HA_KIND_EVIDENCE hack/verify-kind-egress-ha.sh
run_component fqdn-authority UNF_EGRESS_FQDN_KIND_EVIDENCE hack/verify-kind-egress-fqdn-lifecycle.sh
run_component internet-authority UNF_EGRESS_INTERNET_KIND_EVIDENCE hack/verify-kind-egress-internet-lifecycle.sh
run_component diversity-quorum UNF_EGRESS_REACHABILITY_KIND_EVIDENCE hack/verify-kind-egress-reachability-lifecycle.sh
run_component native-reference UNF_EGRESS_NATIVE_KIND_EVIDENCE hack/verify-kind-egress-native-reachability.sh

qualification_stage=aggregate-evidence
controller_pod=$("${kc[@]}" -n unf-system get pods \
    -l app.kubernetes.io/name=unf-controller -o jsonpath='{.items[0].metadata.name}')
final_controller_version=$("${kc[@]}" get --raw \
    "/api/v1/namespaces/unf-system/pods/${controller_pod}:9962/proxy/v1/version")
[[ $(jq -er '.build_revision' <<<"${final_controller_version}") == "${runtime_revision}" ]]
final_status=$("${kc[@]}" get --raw \
    "/api/v1/namespaces/unf-system/pods/${controller_pod}:9962/proxy/v1/status")
jq -e '.ready and .healthy and .agents.all_converged
    and .egress_source_applications == 0 and .egress_activation_ready_sources == 0' \
    <<<"${final_status}" >/dev/null
[[ $("${kc[@]}" get egresspools.network.unf.io -o json | jq '.items | length') == 0 ]]
[[ $("${kc[@]}" get egresspolicies.network.unf.io -o json | jq '.items | length') == 0 ]]

images=$("${kc[@]}" -n unf-system get pods \
    -l 'app.kubernetes.io/name in (unf-controller,unf-agent)' -o json | jq \
    '[.items[] | {pod:.metadata.name,node:.spec.nodeName,
      containers:[.status.containerStatuses[] | {name,image,imageID}]}]')
jq -n \
    --arg generatedAt "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --arg revision "${runtime_revision}" \
    --arg qualificationRevision "${qualification_revision}" \
    --arg context "${context}" \
    --arg kubernetesVersion "$("${kc[@]}" version -o json | jq -r '.serverVersion.gitVersion')" \
    --argjson durationSeconds "$(( $(date +%s) - started_unix_seconds ))" \
    --argjson nodes "${nodes_json}" --argjson images "${images}" \
    --argjson controllerVersion "${controller_version}" \
    --argjson agentVersions "${agent_versions}" \
    --argjson components "${components}" --argjson finalStatus "${final_status}" '
    {schemaVersion:1,phase:"8.10",result:"passed",generatedAt:$generatedAt,
      revision:$revision,qualificationRevision:$qualificationRevision,
      context:$context,kubernetesVersion:$kubernetesVersion,durationSeconds:$durationSeconds,
      kubeProxyPresent:false,topology:{nodeCount:($nodes.items|length),nodes:$nodes.items},
      compatibility:{controller:$controllerVersion,agents:$agentVersions},images:$images,
      componentEvidence:$components,finalStatus:$finalStatus,
      verified:[
        "exclusive kube-proxy-free UNF primary CNI on a three-Node dual-stack cluster",
        "watched policy, deterministic multiple-address allocation, bilateral activation, source steering, gateway NAT, provenance, safe reuse, and clean release",
        "evidence-complete dual-stack explanation and non-authoritative simulation plus loss-explicit NAT Chronicle",
        "measured three-gateway graceful drain and abrupt-failure fencing without Kubernetes-health promotion authority",
        "quorum-gated FQDN discovery, Internet classification, and autonomous temporal denial/recovery",
        "durable diversity-quorum reachability and live native provider/fabric route evidence",
        "controller and agent restart recovery with exact component compatibility",
        "component-scoped cleanup with zero leaked egress intent"
      ],
      rollback:{completed:false},
      excluded:["OpenShift platform behavior","production availability and scale","cross-cluster egress","encryption","EVPN","TCP-AO/MD5 secret delivery"]}
    ' >"${artifact}.tmp"
mv "${artifact}.tmp" "${artifact}"

qualification_stage=exact-platform-rollback
KUBECONFIG="${kubeconfig}" KUBE_CONTEXT="${context}" KIND_PROVIDER="${container_runtime}" \
    "${project_root}/hack/rollback-kind-primary-cni.sh"
jq '.rollback = {completed:true,scope:"current ABI-v15 plus primary-CNI owned state"}
    | .verified += [
      "scoped ABI-v15 map, program, and link cleanup",
      "exact route, CNI artifact, checkpoint, and bootstrap-state removal",
      "CoreDNS restoration and no-CNI baseline recovery"
    ]' "${artifact}" >"${artifact}.tmp"
mv "${artifact}.tmp" "${artifact}"

trap - ERR
echo "Phase 8.10 complete dual-stack Kind qualification passed; evidence: ${artifact}"
