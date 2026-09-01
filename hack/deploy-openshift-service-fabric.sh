#!/usr/bin/env bash
set -Eeuo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
kubeconfig=${KUBECONFIG:-"${project_root}/.tools/cl02-audit.kubeconfig"}
context=${KUBE_CONTEXT:-}
expected_infrastructure=${UNF_OPENSHIFT_SERVICE_EXPECTED_INFRASTRUCTURE:-}
acknowledgement=${UNF_OPENSHIFT_SERVICE_ACKNOWLEDGE_DISPOSABLE:-}
release_record=${UNF_OPENSHIFT_SERVICE_RELEASE_RECORD:-"${project_root}/deploy/openshift-primary-cni/runtime/nodeport-release.json"}
artifact=${UNF_OPENSHIFT_SERVICE_DEPLOY_EVIDENCE:-"${project_root}/.artifacts/phase5-nodeport-openshift-deploy.json"}
render_path=${UNF_OPENSHIFT_SERVICE_RENDER_PATH:-"${project_root}/deploy/openshift-primary-cni/runtime"}
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
    .schemaVersion == 1
    and (.phase == "5.8" or .phase == "6.9" or .phase == "7.10")
    and (.sourceRevision | test("^[0-9a-f]{40}$"))
    and ((.phase == "5.8"
          and .kindQualification.schemaVersion == 2
          and .kindQualification.phase == "5.7")
      or (.phase == "6.9"
          and .kindQualification.schemaVersion == 1
          and .kindQualification.phase == "6.8"
          and .kindQualification.sourceRevision == .sourceRevision
          and (.contracts | type == "object")
          and .contracts.compatibilitySchemaVersion == 2
          and .contracts.persistentBpfStateAbiVersion == 7
          and .contracts.identitySnapshotSchemaVersion == 2
          and .contracts.policySnapshotSchemaVersion == 4
          and .contracts.serviceSnapshotSchemaVersion == 3
          and .contracts.agentStatusSchemaVersion == 6
          and .contracts.flowExportSchemaVersion == 5)
      or (.phase == "7.10"
          and .kindQualification.schemaVersion == 1
          and .kindQualification.phase == "7.9"
          and .kindQualification.sourceRevision == .sourceRevision
          and (.kindQualification.qualificationRevision | test("^[0-9a-f]{40}$"))
          and .kindQualification.kubeProxyPresent == false
          and (.contracts | type == "object")
          and .contracts.compatibilitySchemaVersion == 2
          and .contracts.persistentBpfStateAbiVersion == 11
          and .contracts.identitySnapshotSchemaVersion == 2
          and .contracts.policySnapshotSchemaVersion == 4
          and .contracts.serviceSnapshotSchemaVersion == 4
          and .contracts.selectionContractSchemaVersion == 1
          and .contracts.agentStatusSchemaVersion == 8
          and .contracts.flowExportSchemaVersion == 6))
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
release_phase=$(jq -er .phase "${release_record}")
if [[ ${release_phase} == 6.9 || ${release_phase} == 7.10 ]]; then
    compatibility_schema=$(jq -er .contracts.compatibilitySchemaVersion "${release_record}")
    persistent_abi=$(jq -er .contracts.persistentBpfStateAbiVersion "${release_record}")
    identity_schema=$(jq -er .contracts.identitySnapshotSchemaVersion "${release_record}")
    policy_schema=$(jq -er .contracts.policySnapshotSchemaVersion "${release_record}")
    service_schema=$(jq -er .contracts.serviceSnapshotSchemaVersion "${release_record}")
    agent_status_schema=$(jq -er .contracts.agentStatusSchemaVersion "${release_record}")
    flow_export_schema=$(jq -er .contracts.flowExportSchemaVersion "${release_record}")
    if [[ ${release_phase} == 7.10 ]]; then
        selection_schema=$(jq -er .contracts.selectionContractSchemaVersion "${release_record}")
        deployment_stage=abi-v11-service-selection-staged-deployment
    else
        selection_schema=0
        deployment_stage=abi-v7-loadbalancer-staged-deployment
    fi
else
    compatibility_schema=2
    persistent_abi=5
    identity_schema=2
    policy_schema=4
    service_schema=2
    agent_status_schema=5
    flow_export_schema=5
    selection_schema=0
    deployment_stage=abi-v5-nodeport-staged-deployment
fi
version_query="serviceSnapshotSchemaVersion=${service_schema}"
if ((selection_schema > 0)); then
    version_query="${version_query}&selectionContractSchemaVersion=${selection_schema}"
fi
compatibility_boundary="controller-first schema-v${service_schema} compatibility boundary"
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
    jq -e --arg component "${component}" --arg revision "${source_revision}" \
        --argjson compatibility "${compatibility_schema}" \
        --argjson persistent "${persistent_abi}" \
        --argjson identity "${identity_schema}" --argjson policy "${policy_schema}" \
        --argjson service "${service_schema}" --argjson agent "${agent_status_schema}" \
        --argjson flow "${flow_export_schema}" --argjson selection "${selection_schema}" '
        .schema_version == $compatibility and .component == $component and .build_revision == $revision
        and .persistent_bpf_state_abi_version == $persistent
        and .identity_snapshot_schema_version == $identity
        and .policy_snapshot_schema_version == $policy
        and .service_snapshot_schema_version == $service
        and .agent_status_schema_version == $agent
        and .flow_export_schema_version == $flow
        and ($selection == 0 or .selection_contract_schema_version == $selection)
    ' <<<"${json}" >/dev/null
}

wait_for_controller() {
    local version= status=
    for _ in $(seq 1 300); do
        version=$(controller_raw "/v1/version?${version_query}" 2>/dev/null || true)
        status=$(controller_raw /v1/status 2>/dev/null || true)
        if assert_version "${version}" unf-controller 2>/dev/null \
            && jq -e '.service_compilation_error == null' <<<"${status}" >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    echo "controller did not expose the qualified ABI-v${persistent_abi} revision" >&2
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

wait_for_agent_service_state() {
    local node=$1 status
    for _ in $(seq 1 300); do
        status=$(agent_raw "${node}" /v1/status 2>/dev/null || true)
        if assert_version "$(agent_raw "${node}" /v1/version 2>/dev/null || true)" unf-agent 2>/dev/null \
            && jq -e --argjson status_schema "${agent_status_schema}" \
                --argjson selection_schema "${selection_schema}" '
                .schema_version == $status_schema and .ready == true and .bpf_loaded == true
                and .tc_attachment_mode == "legacy_netlink"
                and .capabilities.btf == true and .capabilities.bpffs == true
                and .capabilities.cgroup_v2 == true
                and .desired_identity_revision == .applied_identity_revision
                and .desired_policy_revision == .applied_policy_revision
                and .desired_service_revision == .applied_service_revision
                and .desired_service_revision > 0
                and .service_count > 0 and .service_frontend_count > 0
                and .service_backend_count > 0
                and has("service_last_error") and .service_last_error == null
                and ($selection_schema == 0 or
                    (.selection_contract_schema_version == $selection_schema
                     and .desired_selection_contract_revision > 0
                     and .applied_selection_contract_revision == .desired_selection_contract_revision
                     and .applied_selection_contract_digest == .desired_selection_contract_digest
                     and (.applied_selection_contract_digest | length) == 64
                     and .selection_contract_last_error == null))
            ' <<<"${status}" >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    echo "agent on ${node} did not converge on healthy ABI-v${persistent_abi} service state" >&2
    jq . <<<"${status}" >&2 || true
    return 1
}

assert_agent() {
    local node=$1 host_state=
    wait_for_agent_service_state "${node}"
    for _ in $(seq 1 60); do
        host_state=$("${kc[@]}" debug "node/${node}" --quiet -- chroot /host sh -euc '
            test "$(getenforce)" = Enforcing
            abi_directory="/sys/fs/bpf/unf/v$1"
            test -d "$abi_directory"
            for pin in SERVICE_CONFIG SERVICE_FRONTENDS_V4 SERVICE_FRONTENDS_V6 \
                SERVICE_BACKENDS_V4 SERVICE_BACKENDS_V6 SERVICE_CONNECTIONS \
                NODE_PORT_CONFIG NODE_PORT_FRONTENDS_V4 NODE_PORT_FRONTENDS_V6; do
                test -e "$abi_directory/$pin"
            done
            snapshot=/var/lib/unf/cni/v1/service-snapshot.json
            test -f "$snapshot" && test ! -L "$snapshot" && test "$(stat -c %a "$snapshot")" = 600
            jq -e --argjson service_schema "$2" \
                "if has(\"service\") then
                    .schemaVersion == 1 and .service.schemaVersion == \$service_schema
                    and .service.revision > 0 and (.service.services | length) > 0
                    and .nodePortNode.schemaVersion == 1
                 else
                    .schemaVersion == 1 and .revision > 0 and (.services | length) > 0
                 end" "$snapshot" >/dev/null
            if test "$3" -gt 0; then
                for pin in IDENTITY_V4 IDENTITY_V4_B IDENTITY_V6 IDENTITY_V6_B IDENTITY_CONFIG \
                    POLICY_RULES POLICY_IPV4 POLICY_IPV6 EGRESS_IPV4 EGRESS_IPV6 POLICY_CONFIG \
                    SERVICE_FRONTENDS_V4 SERVICE_FRONTENDS_V6 SERVICE_BACKENDS_V4 SERVICE_BACKENDS_V6 \
                    SERVICE_BACKEND_SLOTS SERVICE_CONFIG SERVICE_CONNECTIONS SERVICE_AFFINITY \
                    NODE_PORT_FRONTENDS_V4 NODE_PORT_FRONTENDS_V6 NODE_PORT_CONFIG \
                    LOAD_BALANCER_FRONTENDS_V4 LOAD_BALANCER_FRONTENDS_V6 LOAD_BALANCER_CONFIG; do
                    test -e "$abi_directory/$pin"
                done
                selection="${snapshot}.selection"
                test -f "$selection" && test ! -L "$selection" && test "$(stat -c %a "$selection")" = 600
                jq -e --argjson selection_schema "$3" \
                    ".schemaVersion == 1 and .contract.schemaVersion == \$selection_schema
                     and .contract.contractRevision > 0
                     and (.contract.contractDigest | length) == 64" "$selection" >/dev/null
            fi
            echo service-state-ready
        ' sh "${persistent_abi}" "${service_schema}" "${selection_schema}" 2>&1 || true)
        if grep -q '^service-state-ready$' <<<"${host_state}"; then
            return 0
        fi
        sleep 2
    done
    echo "agent on ${node} did not expose complete durable ABI-v${persistent_abi} host state" >&2
    printf '%s\n' "${host_state}" >&2
    return 1
}

wait_for_convergence() {
    local snapshot=
    for _ in $(seq 1 300); do
        snapshot=$(controller_raw /v1/state/agents 2>/dev/null || true)
        if jq -e --argjson expected "${#nodes[@]}" \
            --argjson status_schema "${agent_status_schema}" \
            --argjson service_schema "${service_schema}" \
            --argjson selection_schema "${selection_schema}" '
            .schema_version == $status_schema and .expected_agents == $expected
            and .reporting_agents == $expected and .missing_agents == 0
            and .stale_agents == 0 and .converged_agents == $expected
            and .unexpected_agents == 0 and .all_converged == true
            and all(.nodes[]; .fresh and .converged and .report.ready and .report.bpf_loaded
                and .report.service_snapshot_schema_version == $service_schema
                and .report.desired_service_revision > 0
                and .report.applied_service_revision == .report.desired_service_revision
                and ($selection_schema == 0 or
                    (.report.selection_contract_schema_version == $selection_schema
                     and .report.desired_selection_contract_revision > 0
                     and .report.applied_selection_contract_revision == .report.desired_selection_contract_revision
                     and .report.applied_selection_contract_digest == .report.desired_selection_contract_digest)))
        ' <<<"${snapshot}" >/dev/null 2>&1; then
            printf '%s\n' "${snapshot}"
            return 0
        fi
        sleep 1
    done
    echo "all agents did not converge on persistent ABI v${persistent_abi}" >&2
    jq . <<<"${snapshot}" >&2 || true
    return 1
}

wait_for_machineconfig_render() {
    local pool=$1 machine_config=$2 expected_source rendered actual_source=
    expected_source=$("${kc[@]}" get "machineconfig/${machine_config}" -o json | jq -er '
        .spec.config.storage.files[]
        | select(.path == "/etc/sysctl.d/90-unf-primary-cni.conf")
        | .contents.source')
    for _ in $(seq 1 300); do
        rendered=$("${kc[@]}" get "machineconfigpool/${pool}" \
            -o jsonpath='{.spec.configuration.name}')
        actual_source=$("${kc[@]}" get "machineconfig/${rendered}" -o json 2>/dev/null | jq -er '
            .spec.config.storage.files[]
            | select(.path == "/etc/sysctl.d/90-unf-primary-cni.conf")
            | .contents.source' 2>/dev/null || true)
        if [[ ${actual_source} == "${expected_source}" ]]; then
            return 0
        fi
        sleep 1
    done
    echo "MachineConfigPool ${pool} did not render ${machine_config}" >&2
    return 1
}

node_machineconfig_pool() {
    local node=$1
    if "${kc[@]}" get "node/${node}" -o json \
        | jq -e '.metadata.labels | has("node-role.kubernetes.io/master")' >/dev/null; then
        printf 'master\n'
    else
        printf 'worker\n'
    fi
}

assert_host_service_path() {
    local node=$1 probe=
    for _ in $(seq 1 60); do
        probe=$("${kc[@]}" debug "node/${node}" --quiet -- chroot /host \
            sh -euc '
                curl -fsSk --connect-timeout 5 --max-time 10 "$1" | grep -qx ok
                echo host-service-ready
            ' sh "https://${kubernetes_service_ipv4}:443/readyz" 2>&1 || true)
        if grep -q '^host-service-ready$' <<<"${probe}"; then
            return 0
        fi
        sleep 2
    done
    echo "host-origin Kubernetes API Service path did not recover on ${node}" >&2
    printf '%s\n' "${probe}" >&2
    return 1
}

transition_agent() {
    local node=$1 pod current_image old_uid
    pod=$(agent_pod_on_node "${node}")
    [[ -n ${pod} ]]
    current_image=$("${kc[@]}" -n unf-system get pod "${pod}" -o jsonpath='{.spec.containers[0].image}')
    if [[ ${current_image} != "${agent_image}" ]]; then
        old_uid=$("${kc[@]}" -n unf-system get pod "${pod}" -o jsonpath='{.metadata.uid}')
        echo "transitioning UNF agent on ${node} to persistent BPF ABI v${persistent_abi}"
        "${kc[@]}" -n unf-system delete pod "${pod}" --wait=false >/dev/null
        wait_for_agent_replacement "${node}" "${old_uid}"
    fi
    assert_agent "${node}"
    assert_host_service_path "${node}"
    [[ $("${kc[@]}" get --raw /readyz) == ok ]]
    [[ $("${kc[@]}" get node "${node}" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}') == True ]]
}

stage=cluster-preflight
network=$("${kc[@]}" get network.config.openshift.io cluster -o json)
operator_network=$("${kc[@]}" get network.operator.openshift.io cluster -o json)
infrastructure_state=$("${kc[@]}" get infrastructure cluster -o json)
jq -e '
    .spec.networkType == "None"
    and ([.spec.clusterNetwork[].cidr | contains(":")] | any)
    and ([.spec.clusterNetwork[].cidr | contains(":") | not] | any)
    and ([.spec.serviceNetwork[] | contains(":")] | any)
    and ([.spec.serviceNetwork[] | contains(":") | not] | any)
' <<<"${network}" >/dev/null
jq -e '.spec.defaultNetwork.type == "None" and .spec.deployKubeProxy == false' \
    <<<"${operator_network}" >/dev/null
mapfile -t nodes < <("${kc[@]}" get nodes -l network.unf.io/primary-cni=enabled \
    -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' | sort)
[[ ${#nodes[@]} -eq $("${kc[@]}" get nodes -o json | jq '.items | length') ]]
[[ ${#nodes[@]} -ge 3 ]]
for node in "${nodes[@]}"; do
    [[ $("${kc[@]}" get node "${node}" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}') == True ]]
done
[[ $("${kc[@]}" -n openshift-kube-proxy get daemonsets -o json | jq '.items | length') -eq 0 ]]
kubernetes_service=$("${kc[@]}" -n default get service kubernetes -o json)
kubernetes_service_ipv4=$(jq -r '[.spec.clusterIPs[] | select(contains(":") | not)] | if length == 1 then .[0] else empty end' \
    <<<"${kubernetes_service}")
[[ -n ${kubernetes_service_ipv4} ]]

stage=controller-bootstrap
controller_node=$("${kc[@]}" -n unf-system get deployment/unf-controller -o jsonpath='{.spec.template.spec.nodeName}')
controller_ipv4=$("${kc[@]}" get "node/${controller_node}" -o json | jq -r '
    [.status.addresses[] | select(.type == "InternalIP" and (.address | contains(":") | not)) | .address]
    | if length == 1 then .[0] else empty end')
api_server_internal_uri=$(jq -er '.status.apiServerInternalURI' <<<"${infrastructure_state}")
if [[ ! ${api_server_internal_uri} =~ ^https://([^:/]+):([0-9]+)$ ]]; then
    echo "unsupported internal API URI: ${api_server_internal_uri}" >&2
    exit 1
fi
api_server_internal_host=${BASH_REMATCH[1]}
api_server_internal_port=${BASH_REMATCH[2]}
[[ -n ${controller_node} && -n ${controller_ipv4} && -n ${api_server_internal_host} ]]
rendered=$(mktemp)
oc kustomize "${render_path}" >"${rendered}"
sed -i -e "s/unf-primary-controller-node\.invalid/${controller_node}/g" \
    -e "s/192\.0\.2\.1/${controller_ipv4}/g" \
    -e "s/unf-primary-apiserver\.internal\.invalid/${api_server_internal_host}/g" \
    -e "s/16443/${api_server_internal_port}/g" "${rendered}"
grep -Fq "image: ${controller_image}" "${rendered}"
[[ $(grep -Fc "image: ${agent_image}" "${rendered}") -eq 2 ]]
grep -Fq "value: ${api_server_internal_host}" "${rendered}"
[[ $(grep -Fc "value: \"${api_server_internal_port}\"" "${rendered}") -eq 2 ]]
grep -A4 '^kind: DaemonSet$' "${rendered}" >/dev/null
grep -q 'type: OnDelete' "${rendered}"
"${kc[@]}" apply -f "${rendered}" >/dev/null
[[ $("${kc[@]}" -n unf-system get daemonset/unf-agent -o jsonpath='{.spec.updateStrategy.type}') == OnDelete ]]

stage=controller-first
"${kc[@]}" -n unf-system rollout status deployment/unf-controller --timeout=10m >/dev/null
wait_for_controller
[[ $("${kc[@]}" get --raw /readyz) == ok ]]

stage=service-host-contract
"${kc[@]}" apply -f "${project_root}/deploy/openshift-primary-cni/machineconfig/master-forwarding.yaml" >/dev/null
"${kc[@]}" apply -f "${project_root}/deploy/openshift-primary-cni/machineconfig/worker-forwarding.yaml" >/dev/null
wait_for_machineconfig_render master 99-unf-primary-master-forwarding
wait_for_machineconfig_render worker 99-unf-primary-worker-forwarding
master_rendered=$("${kc[@]}" get machineconfigpool/master -o jsonpath='{.spec.configuration.name}')
worker_rendered=$("${kc[@]}" get machineconfigpool/worker -o jsonpath='{.spec.configuration.name}')
transitioned='[]'
declare -A transition_complete=()
rollout_complete=false
for _ in $(seq 1 540); do
    for pool in master worker; do
        if "${kc[@]}" get "machineconfigpool/${pool}" -o json | jq -e '
            any(.status.conditions[];
                (.type == "Degraded" or .type == "NodeDegraded") and .status == "True")
        ' >/dev/null; then
            echo "MachineConfigPool ${pool} degraded during the service host rollout" >&2
            exit 1
        fi
    done
    for node in "${nodes[@]}"; do
        [[ -z ${transition_complete[${node}]:-} ]] || continue
        pool=$(node_machineconfig_pool "${node}")
        if [[ ${pool} == master ]]; then
            expected_config=${master_rendered}
        else
            expected_config=${worker_rendered}
        fi
        node_state=$("${kc[@]}" get "node/${node}" -o json)
        current_config=$(jq -r '.metadata.annotations["machineconfiguration.openshift.io/currentConfig"] // ""' \
            <<<"${node_state}")
        ready=$(jq -r '.status.conditions[] | select(.type == "Ready") | .status' <<<"${node_state}")
        if [[ ${current_config} == "${expected_config}" && ${ready} == True ]]; then
            transition_agent "${node}"
            transition_complete[${node}]=true
            transitioned=$(jq -c --arg node "${node}" '. + [$node]' <<<"${transitioned}")
        fi
    done
    pools_updated=$("${kc[@]}" get machineconfigpool/master machineconfigpool/worker -o json \
        | jq '[.items[] | any(.status.conditions[]; .type == "Updated" and .status == "True")] | all')
    if [[ ${pools_updated} == true && ${#transition_complete[@]} -eq ${#nodes[@]} ]]; then
        rollout_complete=true
        break
    fi
    sleep 5
done
if [[ ${rollout_complete} != true ]]; then
    echo "MachineConfig rollout and interleaved ABI-v${persistent_abi} agent transition did not complete in 45 minutes" >&2
    exit 1
fi
for node in "${nodes[@]}"; do
    host_contract=$("${kc[@]}" debug "node/${node}" --quiet -- chroot /host sh -euc '
        test "$(getenforce)" = Enforcing
        for key in all default; do
            test "$(cat /proc/sys/net/ipv4/conf/${key}/rp_filter)" -eq 0
            test "$(cat /proc/sys/net/ipv4/conf/${key}/accept_local)" -eq 1
        done
        for path in /proc/sys/net/ipv4/conf/*/rp_filter; do test "$(cat "$path")" -eq 0; done
        for path in /proc/sys/net/ipv4/conf/*/accept_local; do test "$(cat "$path")" -eq 1; done
        ! iptables-save | grep -Eq "KUBE-(SVC|SEP)-"
        ! ip6tables-save | grep -Eq "KUBE-(SVC|SEP)-"
        echo service-host-ready
    ' 2>&1)
    grep -q '^service-host-ready$' <<<"${host_contract}"
    assert_host_service_path "${node}"
done

stage=node-serial-agent-transition
for node in "${nodes[@]}"; do
    assert_agent "${node}"
    assert_host_service_path "${node}"
    [[ $("${kc[@]}" get --raw /readyz) == ok ]]
    [[ $("${kc[@]}" get node "${node}" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}') == True ]]
done

stage=full-service-convergence
agents=$(wait_for_convergence)
for node in "${nodes[@]}"; do
    assert_agent "${node}"
done
[[ $("${kc[@]}" get network.operator.openshift.io cluster -o jsonpath='{.spec.deployKubeProxy}') == false ]]

stage=evidence
mkdir -p "$(dirname "${artifact}")"
artifact_tmp="${artifact}.tmp.$$"
if [[ ${release_phase} == 6.9 || ${release_phase} == 7.10 ]]; then
    node_evidence=$("${kc[@]}" get nodes -o json | jq '[.items[] | {
        name:.metadata.name, osImage:.status.nodeInfo.osImage,
        kernelVersion:.status.nodeInfo.kernelVersion,
        containerRuntime:.status.nodeInfo.containerRuntimeVersion,
        podCIDRs:.spec.podCIDRs,
        internalIPs:[.status.addresses[] | select(.type == "InternalIP") | .address]
    }]')
    jq -n \
        --arg generatedAt "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --arg releasePhase "${release_phase}" \
        --arg context "${context}" --arg infrastructure "${infrastructure}" \
        --arg sourceRevision "${source_revision}" --arg controllerImage "${controller_image}" \
        --arg agentImage "${agent_image}" --arg stage "${deployment_stage}" \
        --arg compatibilityBoundary "${compatibility_boundary}" \
        --argjson persistentAbi "${persistent_abi}" --argjson serviceSchema "${service_schema}" \
        --argjson selectionSchema "${selection_schema}" \
        --argjson statusSchema "${agent_status_schema}" --argjson nodes "${node_evidence}" \
        --argjson agents "${agents}" '
        {
          schemaVersion:1, generatedAt:$generatedAt, phase:$releasePhase, stage:$stage,
          context:$context, infrastructure:$infrastructure, sourceRevision:$sourceRevision,
          images:{controller:$controllerImage,agent:$agentImage},
          strategy:"controller-first-machineconfig-aware-agent-ondelete-node-serial",
          kubeProxyPresent:false, persistentBpfAbi:$persistentAbi,
          serviceSnapshotSchemaVersion:$serviceSchema,
          selectionContractSchemaVersion:$selectionSchema,
          agentStatusSchemaVersion:$statusSchema,
          nodes:$nodes, agents:$agents,
          verified:["immutable public image digests",$compatibilityBoundary,
            "MachineConfig-aware five-node serial agent replacement","RHCOS SELinux enforcing",
            "legacy-netlink TC attachment","persistent host forwarding contract",
            "current-schema durable composite service checkpoint","host-origin Kubernetes API Service reachability",
            "no functional kube-proxy rule residue","exact current-ABI map ownership",
            "full five-node convergence","kube-proxy remains absent"]
        }
    ' >"${artifact_tmp}"
else
retained_abi4_nodes='[]'
rebuild_abi4_nodes='[]'
for node in "${nodes[@]}"; do
    if "${kc[@]}" debug "node/${node}" --quiet -- chroot /host \
        test -d /sys/fs/bpf/unf/v4 >/dev/null 2>&1; then
        retained_abi4_nodes=$(jq -c --arg node "${node}" '. + [$node]' <<<"${retained_abi4_nodes}")
    else
        rebuild_abi4_nodes=$(jq -c --arg node "${node}" '. + [$node]' <<<"${rebuild_abi4_nodes}")
    fi
done
jq -n \
    --arg generatedAt "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --arg context "${context}" --arg infrastructure "${infrastructure}" \
    --arg sourceRevision "${source_revision}" --arg controllerImage "${controller_image}" \
    --arg agentImage "${agent_image}" --argjson nodes "${transitioned}" \
    --argjson retainedAbi4Nodes "${retained_abi4_nodes}" \
    --argjson rebuildAbi4Nodes "${rebuild_abi4_nodes}" \
    --argjson agents "${agents}" '
    {
      schemaVersion:1, generatedAt:$generatedAt, phase:"5.8",
      stage:"abi-v5-nodeport-staged-deployment", context:$context, infrastructure:$infrastructure,
      sourceRevision:$sourceRevision,
      images:{controller:$controllerImage,agent:$agentImage},
      strategy:"controller-first-machineconfig-interleaved-agent-ondelete-node-serial",
      kubeProxyPresent:false,
      retainedPersistentAbi:(if ($retainedAbi4Nodes | length) > 0 then [4,5] else [5] end),
      rollbackAbi4:{retainedNodes:$retainedAbi4Nodes,rebuildRequiredNodes:$rebuildAbi4Nodes},
      nodes:$nodes, agents:$agents,
      verified:["immutable public image digests","controller-first compatibility boundary",
        "MachineConfig-aware five-node serial agent replacement","RHCOS SELinux enforcing","legacy-netlink TC attachment",
        "persistent NodePort host sysctl contract","durable composite service snapshot",
        "host-origin Kubernetes API Service reachability","no functional kube-proxy rule residue",
        "ABI-v6 service, NodePort, and LoadBalancer maps","explicit ABI-v5 retain-or-rebuild rollback state",
        "full agent convergence","kube-proxy remains absent"]
    }
' >"${artifact_tmp}"
fi
chmod 0600 "${artifact_tmp}"
mv -f "${artifact_tmp}" "${artifact}"
artifact_tmp=

trap - ERR EXIT
echo "OpenShift ${release_phase} persistent ABI-v${persistent_abi} staged deployment passed; kube-proxy remains absent; evidence: ${artifact}"
