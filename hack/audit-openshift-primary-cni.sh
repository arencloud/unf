#!/usr/bin/env bash
set -euo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
kubeconfig=${KUBECONFIG:-"${project_root}/.tools/cl02-audit.kubeconfig"}
artifact=${UNF_OPENSHIFT_PRIMARY_AUDIT_ARTIFACT:-"${project_root}/.artifacts/phase3-openshift-primary-cni-audit.json"}
require_eligible=${UNF_OPENSHIFT_PRIMARY_REQUIRE_ELIGIBLE:-false}

for command in jq kubectl oc; do
    if ! command -v "${command}" >/dev/null 2>&1; then
        echo "OpenShift primary-CNI audit prerequisite is missing: ${command}" >&2
        exit 1
    fi
done
if [[ ! -f ${kubeconfig} ]]; then
    echo "OpenShift primary-CNI audit kubeconfig does not exist: ${kubeconfig}" >&2
    exit 1
fi
if [[ $(stat -c '%a' "${kubeconfig}") != 600 ]]; then
    echo "OpenShift primary-CNI audit requires a mode-0600 kubeconfig" >&2
    exit 1
fi

context=$(kubectl --kubeconfig "${kubeconfig}" config current-context)
if [[ -z ${context} ]]; then
    echo "OpenShift primary-CNI audit requires an explicit current context" >&2
    exit 1
fi
kc=(kubectl --kubeconfig "${kubeconfig}" --context "${context}")
oc_cli=(oc --kubeconfig "${kubeconfig}" --context "${context}")

version=$("${kc[@]}" get clusterversion version -o json)
infrastructure=$("${kc[@]}" get infrastructure cluster -o json)
network_config=$("${kc[@]}" get network.config.openshift.io cluster -o json)
network_operator=$("${kc[@]}" get network.operator.openshift.io cluster -o json)
nodes=$("${kc[@]}" get nodes -o json)
machine_pools=$("${kc[@]}" get machineconfigpools -o json)
operators=$("${kc[@]}" get clusteroperators -o json)

mapfile -t workers < <(jq -r '.items[] | select(.metadata.labels["node-role.kubernetes.io/worker"] != null) | .metadata.name' <<<"${nodes}" | sort)
if (( ${#workers[@]} == 0 )); then
    echo "OpenShift primary-CNI audit requires at least one worker" >&2
    exit 1
fi

host_rows='[]'
for node in "${workers[@]}"; do
    row=''
    for attempt in 1 2 3; do
        output=$("${oc_cli[@]}" debug "node/${node}" --quiet -- chroot /host sh -uc '
            config_dir=/etc/kubernetes/cni/net.d
            binary_dir=/var/lib/cni/bin
            configs=""
            if [ -d "$config_dir" ]; then
                configs=$(find "$config_dir" -mindepth 1 -maxdepth 1 -type f -printf "%f\n" | sort | paste -sd, -)
            fi
            jq -nc \
                --arg selinux "$(getenforce)" \
                --arg configDir "$config_dir" \
                --arg binaryDir "$binary_dir" \
                --arg configs "$configs" \
                --arg rootFs "$(findmnt -n -o FSTYPE /)" \
                --argjson unfBinary "$([ -f "$binary_dir/unf" ] && echo true || echo false)" \
                --argjson unfConfig "$([ -f "$config_dir/10-unf.conflist" ] && echo true || echo false)" \
                --argjson unfState "$([ -e /var/lib/unf/cni ] && echo true || echo false)" \
                --argjson unfSocket "$([ -S /run/unf/cni.sock ] && echo true || echo false)" \
                --argjson protocol196v4 "$(ip -j -4 route show proto 196 | jq length)" \
                --argjson protocol196v6 "$(ip -j -6 route show proto 196 | jq length)" \
                "{selinux:\$selinux,configDir:\$configDir,binaryDir:\$binaryDir,configs:(\$configs | split(\",\") | map(select(length > 0))),rootFs:\$rootFs,unfBinary:\$unfBinary,unfConfig:\$unfConfig,unfState:\$unfState,unfSocket:\$unfSocket,protocol196Routes:{ipv4:\$protocol196v4,ipv6:\$protocol196v6}}"
        ' 2>&1) || true
        row=$(sed -n '/^{.*}$/p' <<<"${output}" | tail -1)
        [[ -n ${row} ]] && break
        sleep 1
    done
    if [[ -z ${row} ]] || ! jq -e . >/dev/null 2>&1 <<<"${row}"; then
        row=$(jq -nc --arg error "host inspection failed after three attempts" '{inspectionError:$error}')
    fi
    host_rows=$(jq -c --arg node "${node}" --argjson row "${row}" '. + [({node:$node} + $row)]' <<<"${host_rows}")
done

spec_network_type=$(jq -r '.spec.networkType // ""' <<<"${network_config}")
status_network_type=$(jq -r '.status.networkType // ""' <<<"${network_config}")
operator_network_type=$(jq -r '.spec.defaultNetwork.type // ""' <<<"${network_operator}")
deploy_kube_proxy=$(jq -r '.spec.deployKubeProxy // false' <<<"${network_operator}")
disable_multi_network=$(jq -r '.spec.disableMultiNetwork // false' <<<"${network_operator}")
cluster_families=$(jq -c '[.spec.clusterNetwork[].cidr | if contains(":") then "ipv6" else "ipv4" end] | unique' <<<"${network_config}")
service_families=$(jq -c '[.spec.serviceNetwork[] | if contains(":") then "ipv6" else "ipv4" end] | unique' <<<"${network_config}")
worker_ready=$(jq '[.items[] | select(.metadata.labels["node-role.kubernetes.io/worker"] != null) | any(.status.conditions[]; .type == "Ready" and .status == "True")] | all' <<<"${nodes}")
all_nodes_have_dual_pod_cidrs=$(jq '[.items[] | (.spec.podCIDRs // []) as $cidrs | (($cidrs | map(select(contains(":") | not)) | length) == 1 and ($cidrs | map(select(contains(":"))) | length) == 1)] | all' <<<"${nodes}")
machine_pools_healthy=$(jq '[.items[] | (.status.machineCount == .status.readyMachineCount and .status.machineCount == .status.updatedMachineCount and (.status.degradedMachineCount // 0) == 0 and (.spec.paused // false) == false)] | all' <<<"${machine_pools}")
cluster_operators_healthy=$(jq '[.items[] | ((.status.conditions[] | select(.type == "Available") | .status) == "True" and (.status.conditions[] | select(.type == "Progressing") | .status) == "False" and (.status.conditions[] | select(.type == "Degraded") | .status) == "False")] | all' <<<"${operators}")
ovn_operands=$("${kc[@]}" -n openshift-ovn-kubernetes get daemonsets -o json 2>/dev/null | jq '[.items[].metadata.name]' || echo '[]')

reasons='[]'
add_reason() {
    reasons=$(jq -c --arg value "$1" '. + [$value]' <<<"${reasons}")
}
if [[ ${spec_network_type} != None && ${spec_network_type} != UNF ]]; then
    add_reason "cluster was installed with networkType ${spec_network_type}; UNF qualification requires the installation-time custom-CNI/None path"
fi
if [[ ${status_network_type} != "${spec_network_type}" || ${operator_network_type} != "${spec_network_type}" ]]; then
    add_reason "config, status, and Network Operator network types are not converged"
fi
if [[ ${cluster_families} != '["ipv4","ipv6"]' || ${service_families} != '["ipv4","ipv6"]' ]]; then
    add_reason "cluster and Service networks must both be dual-stack"
fi
if (( ${#workers[@]} < 2 )); then
    add_reason "qualification requires at least two worker Nodes"
fi
if [[ ${machine_pools_healthy} != true ]]; then
    add_reason "MachineConfigPools are not fully updated and healthy"
fi
if [[ ${deploy_kube_proxy} != true ]]; then
    add_reason "standalone kube-proxy is not enabled for the custom CNI"
fi
if [[ ${disable_multi_network} != true ]]; then
    add_reason "Multus must be disabled for the bounded first primary-CNI qualification"
fi
if [[ $(jq 'length' <<<"${ovn_operands}") -ne 0 ]]; then
    add_reason "OVN-Kubernetes operands still own the cluster network"
fi
if [[ ${all_nodes_have_dual_pod_cidrs} != true ]]; then
    add_reason "every opted-in primary-CNI Node requires exactly one IPv4 and one IPv6 spec.podCIDR"
fi
if jq -e 'any(.[]; .inspectionError != null)' >/dev/null <<<"${host_rows}"; then
    add_reason "one or more worker host inspections failed"
fi
if jq -e 'any(.[]; (.configs // []) | any(. != "10-unf.conflist"))' >/dev/null <<<"${host_rows}"; then
    add_reason "worker CNI directories contain foreign configuration"
fi

eligible=$(jq -n --argjson reasons "${reasons}" '$reasons | length == 0')
mkdir -p "$(dirname "${artifact}")"
tmp="${artifact}.tmp.$$"
trap 'rm -f "${tmp}"' EXIT
jq -n \
    --arg observedAt "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --arg context "${context}" \
    --arg infrastructureName "$(jq -r '.status.infrastructureName // ""' <<<"${infrastructure}")" \
    --arg platform "$(jq -r '.status.platformStatus.type // ""' <<<"${infrastructure}")" \
    --arg openshiftVersion "$(jq -r '.status.desired.version // ""' <<<"${version}")" \
    --arg specNetworkType "${spec_network_type}" \
    --arg statusNetworkType "${status_network_type}" \
    --arg operatorNetworkType "${operator_network_type}" \
    --argjson eligible "${eligible}" \
    --argjson reasons "${reasons}" \
    --argjson clusterNetworks "$(jq '.spec.clusterNetwork' <<<"${network_config}")" \
    --argjson serviceNetworks "$(jq '.spec.serviceNetwork' <<<"${network_config}")" \
    --argjson workerCount "${#workers[@]}" \
    --argjson workerReady "${worker_ready}" \
    --argjson allNodesHaveDualPodCIDRs "${all_nodes_have_dual_pod_cidrs}" \
    --argjson machinePoolsHealthy "${machine_pools_healthy}" \
    --argjson clusterOperatorsHealthy "${cluster_operators_healthy}" \
    --argjson deployKubeProxy "${deploy_kube_proxy}" \
    --argjson disableMultiNetwork "${disable_multi_network}" \
    --argjson ovnOperands "${ovn_operands}" \
    --argjson hosts "${host_rows}" \
    '{schemaVersion:1,observedAt:$observedAt,context:$context,infrastructureName:$infrastructureName,platform:$platform,openshiftVersion:$openshiftVersion,classification:(if $eligible then "eligible" else "requires-installation-time-reprovision" end),eligible:$eligible,reasons:$reasons,network:{specType:$specNetworkType,statusType:$statusNetworkType,operatorType:$operatorNetworkType,clusterNetworks:$clusterNetworks,serviceNetworks:$serviceNetworks,deployKubeProxy:$deployKubeProxy,disableMultiNetwork:$disableMultiNetwork,ovnOperands:$ovnOperands},nodes:{workerCount:$workerCount,workersReady:$workerReady,allNodesHaveDualPodCIDRs:$allNodesHaveDualPodCIDRs},platformHealth:{machinePoolsHealthy:$machinePoolsHealthy,clusterOperatorsHealthy:$clusterOperatorsHealthy},hosts:$hosts}' \
    >"${tmp}"
chmod 0600 "${tmp}"
mv -f "${tmp}" "${artifact}"
trap - EXIT

if [[ ${eligible} == true ]]; then
    echo "OpenShift primary-CNI preflight passed for ${context}; evidence: ${artifact}"
else
    echo "OpenShift primary-CNI audit classified ${context} as requiring installation-time reprovisioning; evidence: ${artifact}"
    jq -r '.[] | "- " + .' <<<"${reasons}"
    if [[ ${require_eligible} == true ]]; then
        exit 2
    fi
fi
