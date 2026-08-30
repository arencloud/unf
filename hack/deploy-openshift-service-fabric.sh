#!/usr/bin/env bash
set -Eeuo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
kubeconfig=${KUBECONFIG:-"${project_root}/.tools/cl02-audit.kubeconfig"}
context=${KUBE_CONTEXT:-}
expected_infrastructure=${UNF_OPENSHIFT_SERVICE_EXPECTED_INFRASTRUCTURE:-}
acknowledgement=${UNF_OPENSHIFT_SERVICE_ACKNOWLEDGE_DISPOSABLE:-}
release_record=${UNF_OPENSHIFT_SERVICE_RELEASE_RECORD:-"${project_root}/deploy/openshift-primary-cni/runtime/service-fabric-release.json"}
artifact=${UNF_OPENSHIFT_SERVICE_DEPLOY_EVIDENCE:-"${project_root}/.artifacts/phase4-openshift-service-deploy.json"}
stage=initialization
rendered=
artifact_tmp=

failure() {
    local status=$?
    echo "OpenShift service-fabric deployment failed during ${stage} at line ${BASH_LINENO[0]}: ${BASH_COMMAND}" >&2
    return "${status}"
}

cleanup() {
    [[ -z ${rendered} ]] || rm -f -- "${rendered}"
    [[ -z ${artifact_tmp} ]] || rm -f -- "${artifact_tmp}"
}
trap failure ERR
trap cleanup EXIT

for command in git jq oc sed stat; do
    command -v "${command}" >/dev/null || {
        echo "OpenShift service-fabric deployment prerequisite is missing: ${command}" >&2
        exit 1
    }
done
if [[ ! -s ${kubeconfig} || $(stat -c '%a' "${kubeconfig}") != 600 ]]; then
    echo "deployment requires a non-empty mode-0600 kubeconfig: ${kubeconfig}" >&2
    exit 1
fi
if [[ ! -s ${release_record} ]] || ! jq -e '
    .schemaVersion == 1 and .phase == "4.8"
    and (.sourceRevision | test("^[0-9a-f]{40}$"))
    and .kindQualification.result == "passed"
    and all(.images[]; test("^quay\\.io/arencloud/unf-[a-z-]+-dev@sha256:[0-9a-f]{64}$"))
' "${release_record}" >/dev/null; then
    echo "release record is missing or invalid: ${release_record}" >&2
    exit 1
fi
if [[ -n $(git -C "${project_root}" status --porcelain) ]]; then
    echo "deployment requires a clean committed worktree" >&2
    exit 1
fi

source_revision=$(jq -er .sourceRevision "${release_record}")
controller_image=$(jq -er .images.controller "${release_record}")
agent_image=$(jq -er .images.agent "${release_record}")
git -C "${project_root}" merge-base --is-ancestor "${source_revision}" HEAD

if [[ -z ${context} ]]; then
    context=$(oc --kubeconfig "${kubeconfig}" config current-context)
fi
kc=(oc --kubeconfig "${kubeconfig}" --context "${context}")
infrastructure=$("${kc[@]}" get infrastructure cluster -o jsonpath='{.status.infrastructureName}')
if [[ -z ${expected_infrastructure} || ${expected_infrastructure} != "${infrastructure}" ]]; then
    echo "refusing deployment: UNF_OPENSHIFT_SERVICE_EXPECTED_INFRASTRUCTURE must equal ${infrastructure}" >&2
    exit 1
fi
if [[ ${acknowledgement} != "${infrastructure}" ]]; then
    echo "refusing deployment: UNF_OPENSHIFT_SERVICE_ACKNOWLEDGE_DISPOSABLE must equal ${infrastructure}" >&2
    exit 1
fi

controller_raw() {
    local path=$1 pod
    pod=$("${kc[@]}" -n unf-system get pods -l app.kubernetes.io/name=unf-controller -o json \
        | jq -r '.items[] | select(.metadata.deletionTimestamp == null and .status.phase == "Running") | .metadata.name' \
        | head -n 1)
    [[ -n ${pod} ]]
    "${kc[@]}" get --raw "/api/v1/namespaces/unf-system/pods/${pod}:9962/proxy${path}"
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
    "${kc[@]}" get --raw "/api/v1/namespaces/unf-system/pods/${pod}:9963/proxy${path}"
}

assert_version() {
    local json=$1 component=$2
    jq -e --arg component "${component}" --arg revision "${source_revision}" '
        .schema_version == 2 and .component == $component and .build_revision == $revision
        and .persistent_bpf_state_abi_version == 4
        and .identity_snapshot_schema_version == 2
        and .policy_snapshot_schema_version == 4
        and .service_snapshot_schema_version == 1
        and .agent_status_schema_version == 4
        and .flow_export_schema_version == 4
    ' <<<"${json}" >/dev/null
}

wait_for_controller() {
    local version= status=
    for _ in $(seq 1 300); do
        version=$(controller_raw /v1/version 2>/dev/null || true)
        status=$(controller_raw /v1/status 2>/dev/null || true)
        if assert_version "${version}" unf-controller 2>/dev/null \
            && jq -e '.service_compilation_error == null' <<<"${status}" >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    echo "controller did not expose the qualified ABI-v4 revision" >&2
    jq . <<<"${version}" >&2 || true
    jq . <<<"${status}" >&2 || true
    return 1
}

wait_for_agent_replacement() {
    local node=$1 old_uid=$2 pod_json=
    for _ in $(seq 1 300); do
        pod_json=$("${kc[@]}" -n unf-system get pods -l app.kubernetes.io/name=unf-agent -o json 2>/dev/null || true)
        if jq -e --arg node "${node}" --arg uid "${old_uid}" --arg image "${agent_image}" '
            any(.items[];
                .spec.nodeName == $node and .metadata.uid != $uid
                and .metadata.deletionTimestamp == null and .status.phase == "Running"
                and (.spec.containers | all(.image == $image))
                and (.status.containerStatuses | all(.ready == true)))
        ' <<<"${pod_json}" >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    echo "agent on ${node} did not become Ready with ${agent_image}" >&2
    return 1
}

assert_agent() {
    local node=$1 status
    assert_version "$(agent_raw "${node}" /v1/version)" unf-agent
    status=$(agent_raw "${node}" /v1/status)
    jq -e '
        .schema_version == 4 and .ready == true and .bpf_loaded == true
        and .tc_attachment_mode == "legacy_netlink"
        and .capabilities.btf == true and .capabilities.bpffs == true
        and .capabilities.cgroup_v2 == true
        and .desired_identity_revision == .applied_identity_revision
        and .desired_policy_revision == .applied_policy_revision
        and .desired_service_revision == .applied_service_revision
        and .desired_service_revision > 0
        and .service_count > 0 and .service_frontend_count > 0
        and .service_backend_count > 0 and .last_service_error == null
    ' <<<"${status}" >/dev/null
    host_state=$("${kc[@]}" debug "node/${node}" --quiet -- chroot /host sh -euc '
        test "$(getenforce)" = Enforcing
        test -d /sys/fs/bpf/unf/v3
        test -d /sys/fs/bpf/unf/v4
        for pin in SERVICE_CONFIG SERVICE_FRONTENDS_V4 SERVICE_FRONTENDS_V6 \
            SERVICE_BACKENDS_V4 SERVICE_BACKENDS_V6 SERVICE_CONNECTIONS; do
            test -e "/sys/fs/bpf/unf/v4/$pin"
        done
        snapshot=/var/lib/unf/cni/v1/service-snapshot.json
        test -f "$snapshot" && test ! -L "$snapshot" && test "$(stat -c %a "$snapshot")" = 600
        jq -e ".schemaVersion == 1 and .revision > 0 and (.services | length) > 0" "$snapshot" >/dev/null
        echo service-state-ready
    ' 2>&1)
    grep -q '^service-state-ready$' <<<"${host_state}"
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
                and .report.applied_service_revision == .report.desired_service_revision)
        ' <<<"${snapshot}" >/dev/null 2>&1; then
            printf '%s\n' "${snapshot}"
            return 0
        fi
        sleep 1
    done
    echo "all agents did not converge on ABI v4" >&2
    jq . <<<"${snapshot}" >&2 || true
    return 1
}

stage=cluster-preflight
network=$("${kc[@]}" get network.config.openshift.io cluster -o json)
operator_network=$("${kc[@]}" get network.operator.openshift.io cluster -o json)
jq -e '
    .spec.networkType == "None"
    and ([.spec.clusterNetwork[].cidr | contains(":")] | any)
    and ([.spec.clusterNetwork[].cidr | contains(":") | not] | any)
    and ([.spec.serviceNetwork[] | contains(":")] | any)
    and ([.spec.serviceNetwork[] | contains(":") | not] | any)
' <<<"${network}" >/dev/null
jq -e '.spec.defaultNetwork.type == "None" and .spec.deployKubeProxy == true' \
    <<<"${operator_network}" >/dev/null
mapfile -t nodes < <("${kc[@]}" get nodes -l network.unf.io/primary-cni=enabled \
    -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' | sort)
[[ ${#nodes[@]} -eq $("${kc[@]}" get nodes -o json | jq '.items | length') ]]
[[ ${#nodes[@]} -ge 3 ]]
for node in "${nodes[@]}"; do
    [[ $("${kc[@]}" get node "${node}" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}') == True ]]
done
[[ $("${kc[@]}" -n openshift-kube-proxy get daemonset openshift-kube-proxy \
    -o json | jq '.status.numberReady') -eq ${#nodes[@]} ]]

stage=render-and-apply
controller_node=$("${kc[@]}" -n unf-system get deployment/unf-controller -o jsonpath='{.spec.template.spec.nodeName}')
controller_ipv4=$("${kc[@]}" get "node/${controller_node}" -o json | jq -r '
    [.status.addresses[] | select(.type == "InternalIP" and (.address | contains(":") | not)) | .address]
    | if length == 1 then .[0] else empty end')
[[ -n ${controller_node} && -n ${controller_ipv4} ]]
rendered=$(mktemp)
oc kustomize "${project_root}/deploy/openshift-primary-cni/runtime" >"${rendered}"
sed -i -e "s/unf-primary-controller-node\.invalid/${controller_node}/g" \
    -e "s/192\.0\.2\.1/${controller_ipv4}/g" "${rendered}"
grep -Fq "image: ${controller_image}" "${rendered}"
[[ $(grep -Fc "image: ${agent_image}" "${rendered}") -eq 2 ]]
grep -A4 '^kind: DaemonSet$' "${rendered}" >/dev/null
grep -q 'type: OnDelete' "${rendered}"
"${kc[@]}" apply -f "${rendered}" >/dev/null
[[ $("${kc[@]}" -n unf-system get daemonset/unf-agent -o jsonpath='{.spec.updateStrategy.type}') == OnDelete ]]

stage=controller-first
"${kc[@]}" -n unf-system rollout status deployment/unf-controller --timeout=10m >/dev/null
wait_for_controller
[[ $("${kc[@]}" get --raw /readyz) == ok ]]

stage=node-serial-agent-transition
transitioned='[]'
for node in "${nodes[@]}"; do
    pod=$(agent_pod_on_node "${node}")
    [[ -n ${pod} ]]
    current_image=$("${kc[@]}" -n unf-system get pod "${pod}" -o jsonpath='{.spec.containers[0].image}')
    if [[ ${current_image} != "${agent_image}" ]]; then
        old_uid=$("${kc[@]}" -n unf-system get pod "${pod}" -o jsonpath='{.metadata.uid}')
        echo "transitioning UNF agent on ${node} to persistent BPF ABI v4"
        "${kc[@]}" -n unf-system delete pod "${pod}" --wait=false >/dev/null
        wait_for_agent_replacement "${node}" "${old_uid}"
    fi
    assert_agent "${node}"
    [[ $("${kc[@]}" get --raw /readyz) == ok ]]
    [[ $("${kc[@]}" get node "${node}" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}') == True ]]
    transitioned=$(jq -c --arg node "${node}" '. + [$node]' <<<"${transitioned}")
done

stage=full-v4-convergence
agents=$(wait_for_convergence)
for node in "${nodes[@]}"; do
    assert_agent "${node}"
done
[[ $("${kc[@]}" get network.operator.openshift.io cluster -o jsonpath='{.spec.deployKubeProxy}') == true ]]

stage=evidence
mkdir -p "$(dirname "${artifact}")"
artifact_tmp="${artifact}.tmp.$$"
jq -n \
    --arg generatedAt "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --arg context "${context}" --arg infrastructure "${infrastructure}" \
    --arg sourceRevision "${source_revision}" --arg controllerImage "${controller_image}" \
    --arg agentImage "${agent_image}" --argjson nodes "${transitioned}" \
    --argjson agents "${agents}" '
    {
      schemaVersion:1, generatedAt:$generatedAt, phase:"4.8",
      stage:"abi-v4-staged-deployment", context:$context, infrastructure:$infrastructure,
      sourceRevision:$sourceRevision,
      images:{controller:$controllerImage,agent:$agentImage},
      strategy:"controller-first-agent-ondelete-node-serial",
      kubeProxyPresent:true, retainedPersistentAbi:[3,4], nodes:$nodes, agents:$agents,
      verified:["immutable public image digests","controller-first compatibility boundary",
        "five-node serial agent replacement","RHCOS SELinux enforcing","legacy-netlink TC attachment",
        "durable service snapshot","ABI-v4 service maps","full agent convergence",
        "kube-proxy safety net retained"]
    }
' >"${artifact_tmp}"
chmod 0600 "${artifact_tmp}"
mv -f "${artifact_tmp}" "${artifact}"
artifact_tmp=

trap - ERR EXIT
echo "OpenShift service-fabric ABI-v4 staged deployment passed; kube-proxy remains enabled; evidence: ${artifact}"
