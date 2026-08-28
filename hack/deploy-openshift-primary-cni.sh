#!/usr/bin/env bash
set -euo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
kubeconfig=${KUBECONFIG:-"${project_root}/.tools/cl02-audit.kubeconfig"}
expected_infrastructure=${UNF_OPENSHIFT_PRIMARY_EXPECTED_INFRASTRUCTURE:-}
acknowledgement=${UNF_OPENSHIFT_PRIMARY_ACKNOWLEDGE_DISPOSABLE:-}
artifact=${UNF_OPENSHIFT_PRIMARY_DEPLOY_ARTIFACT:-"${project_root}/.artifacts/phase3-openshift-primary-cni-deploy.json"}

for command in jq kubectl oc openssl; do
    command -v "${command}" >/dev/null || {
        echo "OpenShift primary-CNI deployment prerequisite is missing: ${command}" >&2
        exit 1
    }
done
if [[ ! -s ${kubeconfig} || $(stat -c '%a' "${kubeconfig}") != 600 ]]; then
    echo "OpenShift primary-CNI deployment requires a non-empty mode-0600 kubeconfig: ${kubeconfig}" >&2
    exit 1
fi

context=$(kubectl --kubeconfig "${kubeconfig}" config current-context)
kc=(kubectl --kubeconfig "${kubeconfig}" --context "${context}")
infrastructure=$("${kc[@]}" get infrastructure cluster -o jsonpath='{.status.infrastructureName}')
if [[ -z ${expected_infrastructure} || ${infrastructure} != "${expected_infrastructure}" ]]; then
    echo "refusing deployment: expected infrastructure must exactly equal ${infrastructure}" >&2
    exit 1
fi
if [[ ${acknowledgement} != "${infrastructure}" ]]; then
    echo "refusing deployment: UNF_OPENSHIFT_PRIMARY_ACKNOWLEDGE_DISPOSABLE must equal ${infrastructure}" >&2
    exit 1
fi

pre_assignment_audit=$(mktemp)
rendered=
artifact_tmp=
cleanup() {
    rm -f "${pre_assignment_audit}"
    [[ -z ${rendered} ]] || rm -f "${rendered}"
    [[ -z ${artifact_tmp} ]] || rm -f "${artifact_tmp}"
}
trap cleanup EXIT
KUBECONFIG="${kubeconfig}" KUBE_CONTEXT="${context}" \
    UNF_OPENSHIFT_PRIMARY_AUDIT_ARTIFACT="${pre_assignment_audit}" \
    "${project_root}/hack/audit-openshift-primary-cni.sh"
pod_cidr_reason='every opted-in primary-CNI Node requires exactly one IPv4 and one IPv6 spec.podCIDR'
if ! jq -e --arg allowed "${pod_cidr_reason}" \
    '.reasons | all(. == $allowed)' "${pre_assignment_audit}" >/dev/null; then
    echo "refusing Node-block assignment because the candidate has non-PodCIDR blockers" >&2
    exit 1
fi
KUBECONFIG="${kubeconfig}" KUBE_CONTEXT="${context}" \
    UNF_OPENSHIFT_PRIMARY_EXPECTED_INFRASTRUCTURE="${expected_infrastructure}" \
    UNF_OPENSHIFT_PRIMARY_ACKNOWLEDGE_DISPOSABLE="${acknowledgement}" \
    "${project_root}/hack/configure-openshift-primary-cni-node-blocks.sh"
KUBECONFIG="${kubeconfig}" KUBE_CONTEXT="${context}" \
    UNF_OPENSHIFT_PRIMARY_REQUIRE_ELIGIBLE=true \
    "${project_root}/hack/audit-openshift-primary-cni.sh"

agent_patch=${project_root}/deploy/openshift-primary-cni/runtime/agent-patch.yaml
ipv4_uplink=$(awk '/- --cni-native-ipv4-uplink/{getline; sub(/^[[:space:]]*- /, ""); print; exit}' "${agent_patch}")
ipv6_uplink=$(awk '/- --cni-native-ipv6-uplink/{getline; sub(/^[[:space:]]*- /, ""); print; exit}' "${agent_patch}")
if [[ -z ${ipv4_uplink} || -z ${ipv6_uplink} ]]; then
    echo "refusing deployment without explicit native IPv4 and IPv6 uplinks" >&2
    exit 1
fi

mapfile -t nodes < <("${kc[@]}" get nodes -o name | sed 's|node/||' | sort)
for node in "${nodes[@]}"; do
    uplink_check=$(oc --kubeconfig "${kubeconfig}" --context "${context}" \
        debug "node/${node}" --quiet -- chroot /host sh -euc '
            expected4=$1
            expected6=$2
            actual4=$(ip -j -4 route show default | jq -r "map(select(.dst == \"default\"))[0].dev // empty")
            actual6=$(ip -j -6 route show default | jq -r "map(select(.dst == \"default\"))[0].dev // empty")
            test "$actual4" = "$expected4"
            test "$actual6" = "$expected6"
            test "$(cat "/sys/class/net/$expected4/mtu")" -ge 1500
            test "$(cat "/sys/class/net/$expected6/mtu")" -ge 1500
            echo uplinks-ready
        ' sh "${ipv4_uplink}" "${ipv6_uplink}" 2>&1)
    grep -q '^uplinks-ready$' <<<"${uplink_check}"
done

rendered=$(mktemp)
kubectl kustomize "${project_root}/deploy/openshift-primary-cni/runtime" >"${rendered}"
if grep -Eq 'image: .*:dev([[:space:]]|$)' "${rendered}"; then
    echo "refusing mutable primary-CNI image reference" >&2
    exit 1
fi

controller_node=$("${kc[@]}" get nodes -l node-role.kubernetes.io/control-plane \
    -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' | sort | head -1)
controller_ipv4=$("${kc[@]}" get "node/${controller_node}" -o json | jq -r \
    '[.status.addresses[] | select(.type == "InternalIP" and (.address | contains(":") | not)) | .address] | if length == 1 then .[0] else empty end')
if [[ -z ${controller_node} || -z ${controller_ipv4} ]]; then
    echo "refusing deployment without one selected control-plane Node and IPv4 InternalIP" >&2
    exit 1
fi
sed -i \
    -e "s/unf-primary-controller-node\.invalid/${controller_node}/g" \
    -e "s/192\.0\.2\.1/${controller_ipv4}/g" \
    "${rendered}"
if grep -Eq 'unf-primary-controller-node\.invalid|192\.0\.2\.1' "${rendered}"; then
    echo "refusing unresolved primary-CNI bootstrap placeholders" >&2
    exit 1
fi

declare -A previous_pool_configuration
declare -A machineconfig_preexisting
for pool in master worker; do
    previous_pool_configuration[${pool}]=$("${kc[@]}" get "machineconfigpool/${pool}" \
        -o jsonpath='{.status.configuration.name}')
    machineconfig_preexisting[${pool}]=false
    "${kc[@]}" get "machineconfig/99-unf-primary-${pool}-forwarding" >/dev/null 2>&1 \
        && machineconfig_preexisting[${pool}]=true
done
"${kc[@]}" apply -k "${project_root}/deploy/openshift-primary-cni/machineconfig"
for pool in master worker; do
    converged=false
    for _ in $(seq 1 360); do
        pool_json=$("${kc[@]}" get "machineconfigpool/${pool}" -o json)
        current_configuration=$(jq -r '.status.configuration.name // ""' <<<"${pool_json}")
        machine_count=$(jq -r '.status.machineCount // 0' <<<"${pool_json}")
        ready_count=$(jq -r '.status.readyMachineCount // 0' <<<"${pool_json}")
        updated_count=$(jq -r '.status.updatedMachineCount // 0' <<<"${pool_json}")
        degraded_count=$(jq -r '.status.degradedMachineCount // 0' <<<"${pool_json}")
        configuration_advanced=true
        if [[ ${machineconfig_preexisting[${pool}]} == false \
            && ${current_configuration} == "${previous_pool_configuration[${pool}]}" ]]; then
            configuration_advanced=false
        fi
        if [[ ${configuration_advanced} == true && ${machine_count} -gt 0 \
            && ${machine_count} -eq ${ready_count} \
            && ${machine_count} -eq ${updated_count} && ${degraded_count} -eq 0 ]]; then
            converged=true
            break
        fi
        sleep 5
    done
    if [[ ${converged} != true ]]; then
        echo "MachineConfigPool ${pool} did not converge to the forwarding configuration" >&2
        exit 1
    fi
done

for node in "${nodes[@]}"; do
    verification=$(oc --kubeconfig "${kubeconfig}" --context "${context}" \
        debug "node/${node}" --quiet -- chroot /host sh -euc '
            test "$(getenforce)" = Enforcing
            test "$(sysctl -n net.ipv4.ip_forward)" = 1
            test "$(sysctl -n net.ipv6.conf.all.forwarding)" = 1
            test "$(sysctl -n net.ipv6.conf.default.forwarding)" = 1
            test -f /etc/sysctl.d/90-unf-primary-cni.conf
            test ! -L /etc/sysctl.d/90-unf-primary-cni.conf
            echo forwarding-ready
        ' 2>&1)
    grep -q '^forwarding-ready$' <<<"${verification}"
done

KUBECONFIG="${kubeconfig}" KUBE_CONTEXT="${context}" \
    UNF_INTERNAL_TLS_DIR="${project_root}/.tools/openshift-primary-cni-internal-tls" \
    "${project_root}/hack/configure-internal-tls.sh"
"${kc[@]}" label nodes --all network.unf.io/primary-cni=enabled --overwrite
"${kc[@]}" apply -f "${rendered}"
"${kc[@]}" -n unf-system rollout status deployment/unf-controller --timeout=10m
"${kc[@]}" -n unf-system rollout status daemonset/unf-agent --timeout=10m
"${kc[@]}" wait --for=condition=Ready nodes --all --timeout=10m

host_evidence='[]'
for node in "${nodes[@]}"; do
    row=$(oc --kubeconfig "${kubeconfig}" --context "${context}" \
        debug "node/${node}" --quiet -- chroot /host sh -euc '
            marker=/var/lib/unf/cni/v1/install.env
            binary=/var/lib/cni/bin/unf
            config=/etc/kubernetes/cni/net.d/10-unf.conflist
            test -f "$marker" && test ! -L "$marker" && test "$(stat -c %a "$marker")" = 600
            test "$(sed -n "s/^schema=//p" "$marker")" = 1
            test "$(sed -n "s/^platform=//p" "$marker")" = openshift
            binary_sha=$(sed -n "s/^binary_sha256=//p" "$marker")
            config_sha=$(sed -n "s/^config_sha256=//p" "$marker")
            test "$(sha256sum "$binary" | cut -d " " -f 1)" = "$binary_sha"
            test "$(sha256sum "$config" | cut -d " " -f 1)" = "$config_sha"
            test "$(find /etc/kubernetes/cni/net.d -mindepth 1 -maxdepth 1 -type f | wc -l)" = 1
            jq -nc --arg binarySha "$binary_sha" --arg configSha "$config_sha" \
                --arg selinux "$(getenforce)" \
                '{binarySha256:$binarySha,configSha256:$configSha,selinux:$selinux}'
        ' 2>&1)
    row=$(sed -n '/^{.*}$/p' <<<"${row}" | tail -1)
    jq -e . >/dev/null <<<"${row}"
    host_evidence=$(jq -c --arg node "${node}" --argjson row "${row}" \
        '. + [({node:$node} + $row)]' <<<"${host_evidence}")
done

mkdir -p "$(dirname "${artifact}")"
artifact_tmp="${artifact}.tmp.$$"
jq -n \
    --arg observedAt "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --arg context "${context}" \
    --arg infrastructure "${infrastructure}" \
    --arg controllerImage "$(sed -n 's/^[[:space:]]*image: \(quay.io\/arencloud\/unf-controller-dev@sha256:[0-9a-f]*\)$/\1/p' "${rendered}" | head -1)" \
    --arg agentImage "$(sed -n 's/^[[:space:]]*image: \(quay.io\/arencloud\/unf-agent-dev@sha256:[0-9a-f]*\)$/\1/p' "${rendered}" | head -1)" \
    --argjson hosts "${host_evidence}" \
    '{schemaVersion:1,observedAt:$observedAt,context:$context,infrastructure:$infrastructure,controllerImage:$controllerImage,agentImage:$agentImage,hosts:$hosts}' \
    >"${artifact_tmp}"
chmod 0600 "${artifact_tmp}"
mv -f "${artifact_tmp}" "${artifact}"
artifact_tmp=

echo "deployed digest-pinned OpenShift primary CNI to ${context}; evidence: ${artifact}"
