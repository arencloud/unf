#!/usr/bin/env bash
set -euo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
kubeconfig=${OPENSHIFT_KUBECONFIG:-${KUBECONFIG:-}}
node=${UNF_PRIMARY_CNI_FAULT_NODE:-}
namespace=${UNF_PRIMARY_CNI_FAULT_NAMESPACE:-unf-primary-cni-runtime-fault}
image=${UNF_TEST_TOOLS_IMAGE:-quay.io/arencloud/unf-test-tools-dev@sha256:f57a7ee9668d6b87f4e00c4e8df9240b8889c6ee50f817ea1e884732b2f42b13}
artifact=${UNF_PRIMARY_CNI_FAULT_EVIDENCE:-${project_root}/.artifacts/phase3-openshift-primary-cni-runtime-fault.json}
confirmation=${UNF_PRIMARY_CNI_FAULT_CONFIRM:-}

for command in jq oc; do
    command -v "${command}" >/dev/null || {
        echo "OpenShift primary-CNI runtime-fault prerequisite is missing: ${command}" >&2
        exit 1
    }
done
[[ -n ${kubeconfig} && -f ${kubeconfig} ]] || {
    echo "set OPENSHIFT_KUBECONFIG to the target cluster kubeconfig" >&2
    exit 1
}
[[ ${node} =~ ^[a-z0-9]([-a-z0-9]*[a-z0-9])?$ ]] || {
    echo "set UNF_PRIMARY_CNI_FAULT_NODE to one exact Node name" >&2
    exit 1
}
[[ ${namespace} =~ ^[a-z0-9]([-a-z0-9]*[a-z0-9])?$ ]] || {
    echo "invalid fault qualification Namespace: ${namespace}" >&2
    exit 1
}

kc=(oc --kubeconfig "${kubeconfig}")
context=$("${kc[@]}" config current-context)
expected_confirmation=${context}:${node}
if [[ ${confirmation} != "${expected_confirmation}" ]]; then
    echo "refusing runtime fault injection without UNF_PRIMARY_CNI_FAULT_CONFIRM=${expected_confirmation}" >&2
    exit 1
fi

socket_displaced=false
namespace_created=false
artifact_tmp=

host_exec() {
    "${kc[@]}" debug "node/${node}" --quiet -- chroot /host sh -ec "$1"
}

restore_socket() {
    if [[ ${socket_displaced} == true ]]; then
        host_exec '
            if test -S /run/unf/cni.sock && test ! -e /run/unf/cni.sock.unf-runtime-fault; then
                exit 0
            fi
            test ! -e /run/unf/cni.sock && test -S /run/unf/cni.sock.unf-runtime-fault
            mv /run/unf/cni.sock.unf-runtime-fault /run/unf/cni.sock
            test -S /run/unf/cni.sock
            test "$(stat -c %a /run/unf/cni.sock)" = 600
        '
        socket_displaced=false
    fi
}

cleanup() {
    set +e
    restore_socket
    if [[ ${namespace_created} == true ]]; then
        "${kc[@]}" delete namespace "${namespace}" --ignore-not-found --wait=true --timeout=120s >/dev/null
    fi
    if [[ -n ${artifact_tmp} && -f ${artifact_tmp} ]]; then
        rm -f -- "${artifact_tmp}"
    fi
}
trap cleanup EXIT

snapshot() {
    host_exec '
        journal=/var/lib/unf/cni/v1/attachments.json
        attachments=$(jq ".attachments | length" "$journal")
        caches=$(find /var/lib/cni/results -maxdepth 1 -type f -name "unf-primary-*-eth0" | wc -l)
        links=$(ip -o link show | grep -Ec "^[0-9]+: unf[0-9a-f]+")
        pending=$(find /var/lib/unf/cni/v1/pending-deletes -type f -name "*.json" | wc -l)
        printf "%s\t%s\t%s\t%s\n" "$attachments" "$caches" "$links" "$pending"
    ' | tail -n 1
}

wait_snapshot() {
    local expected=$1
    local observed=
    for _ in $(seq 1 30); do
        observed=$(snapshot)
        if [[ ${observed} == "${expected}" ]]; then
            printf '%s\n' "${observed}"
            return 0
        fi
        sleep 2
    done
    echo "state did not reach ${expected}; last observation: ${observed}" >&2
    return 1
}

wait_for_convergence() {
    local expected=$1
    local controller snapshot=
    for _ in $(seq 1 120); do
        controller=$("${kc[@]}" -n unf-system get pods \
            -l app.kubernetes.io/name=unf-controller -o json \
            | jq -r '.items[] | select(.metadata.deletionTimestamp == null and
                .status.phase == "Running") | .metadata.name' | head -n 1)
        if [[ -n ${controller} ]]; then
            snapshot=$("${kc[@]}" get --raw \
                "/api/v1/namespaces/unf-system/pods/${controller}:9962/proxy/v1/state/agents" \
                2>/dev/null || true)
        fi
        if jq -e --argjson expected "${expected}" '
            .expected_agents == $expected and .reporting_agents == $expected and
            .missing_agents == 0 and .stale_agents == 0 and
            .converged_agents == $expected and .unexpected_agents == 0 and
            .all_converged == true and
            all(.nodes[]; .fresh and .converged and .report.ready and .report.bpf_loaded)
          ' <<<"${snapshot}" >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    echo "agents did not return to exact convergence after runtime fault cleanup" >&2
    jq . <<<"${snapshot}" >&2 || true
    return 1
}

wait_pod_ready() {
    local name=$1
    "${kc[@]}" -n "${namespace}" wait --for=condition=Ready "pod/${name}" --timeout=180s >/dev/null
}

cni_container_for_pod() {
    local name=$1
    local uid id
    uid=$("${kc[@]}" -n "${namespace}" get pod "${name}" -o jsonpath='{.metadata.uid}')
    [[ ${uid} =~ ^[0-9a-f-]{36}$ ]]
    id=$(host_exec "
        for cache in /var/lib/cni/results/unf-primary-*-eth0; do
            test -f \"\$cache\" || continue
            jq -er --arg uid '${uid}' \
                'select(any(.cniArgs[]; .[0] == \"K8S_POD_UID\" and .[1] == \$uid)) | .containerId' \
                \"\$cache\" 2>/dev/null || true
        done
    " | tail -n 1)
    [[ ${id} =~ ^[0-9a-f]{64}$ ]] || {
        echo "Pod ${name} returned an invalid CRI-O sandbox ID" >&2
        return 1
    }
    printf '%s\n' "${id}"
}

apply_pod() {
    local name=$1
    "${kc[@]}" apply -f - >/dev/null <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: ${name}
  namespace: ${namespace}
  labels:
    app.kubernetes.io/name: unf-primary-cni-runtime-fault
spec:
  nodeName: ${node}
  restartPolicy: Never
  terminationGracePeriodSeconds: 0
  automountServiceAccountToken: false
  securityContext:
    runAsNonRoot: true
    seccompProfile:
      type: RuntimeDefault
  containers:
    - name: hold
      image: ${image}
      imagePullPolicy: IfNotPresent
      command: ["sh", "-c", "sleep infinity"]
      securityContext:
        allowPrivilegeEscalation: false
        capabilities:
          drop: ["ALL"]
EOF
}

attachment() {
    local container_id=$1
    host_exec "jq -r --arg id '${container_id}' \
        '.attachments[] | select(.spec.key.containerId == \$id) | \
        [.hostInterface, .lease.ipv4.address, .lease.ipv6.address, .phase] | @tsv' \
        /var/lib/unf/cni/v1/attachments.json" | tail -n 1
}

run_check() {
    local container_id=$1
    host_exec "
        trap 'rm -f /run/unf/runtime-fault-check.json' EXIT
        cache=/var/lib/cni/results/unf-primary-${container_id}-eth0
        test -f \"\$cache\"
        cni_args=\$(jq -r '[.cniArgs[] | \"\(.[0])=\(.[1])\"] | join(\";\")' \"\$cache\")
        netns=\$(jq -r .netns \"\$cache\")
        prev=\$(jq -c .result \"\$cache\")
        jq -r .config \"\$cache\" | base64 -d | \
            jq -c --argjson prev \"\$prev\" \
                '.plugins[0] + {cniVersion: .cniVersion, name: .name, prevResult: \$prev}' \
                >/run/unf/runtime-fault-check.json
        env CNI_COMMAND=CHECK CNI_CONTAINERID='${container_id}' \
            CNI_NETNS=\"\$netns\" CNI_IFNAME=eth0 CNI_ARGS=\"\$cni_args\" \
            CNI_PATH=/var/lib/cni/bin /var/lib/cni/bin/unf \
            </run/unf/runtime-fault-check.json
        rm -f /run/unf/runtime-fault-check.json
    "
}

"${kc[@]}" get node "${node}" -o json | jq -e '
    .metadata.labels["network.unf.io/primary-cni"] == "enabled" and
    any(.status.conditions[]; .type == "Ready" and .status == "True")
  ' >/dev/null
[[ $("${kc[@]}" get network.config.openshift.io cluster -o jsonpath='{.spec.networkType}') == None ]]
[[ $("${kc[@]}" -n unf-system get pod -l app.kubernetes.io/name=unf-agent \
    --field-selector "spec.nodeName=${node}" -o json \
    | jq '[.items[] | select(.status.phase == "Running" and all(.status.containerStatuses[]; .ready))] | length') -eq 1 ]]
expected_agents=$("${kc[@]}" get nodes -l network.unf.io/primary-cni=enabled -o json \
    | jq '.items | length')
[[ ${expected_agents} -gt 0 ]]
if existing_namespace=$("${kc[@]}" get namespace "${namespace}" -o json 2>/dev/null); then
    if [[ $(jq -r '.metadata.deletionTimestamp // ""' <<<"${existing_namespace}") != "" ]]; then
        "${kc[@]}" wait --for=delete "namespace/${namespace}" --timeout=120s >/dev/null
    else
        echo "refusing to reuse existing Namespace ${namespace}" >&2
        exit 1
    fi
fi

host_exec '
    test -S /run/unf/cni.sock
    test "$(stat -c %a /run/unf/cni.sock)" = 600
    test ! -e /run/unf/cni.sock.unf-runtime-fault
    test "$(find /var/lib/unf/cni/v1/pending-deletes -type f -name "*.json" | wc -l)" -eq 0
'

baseline=$(snapshot)
IFS=$'\t' read -r baseline_attachments baseline_caches baseline_links baseline_pending <<<"${baseline}"
[[ ${baseline_attachments} -eq ${baseline_caches} ]]
[[ ${baseline_attachments} -eq ${baseline_links} ]]
[[ ${baseline_pending} -eq 0 ]]

"${kc[@]}" create namespace "${namespace}" >/dev/null
namespace_created=true
apply_pod unf-runtime-fault-old
wait_pod_ready unf-runtime-fault-old
old_container=$(cni_container_for_pod unf-runtime-fault-old)
old_state=$(wait_snapshot "$((baseline_attachments + 1))"$'\t'"$((baseline_caches + 1))"$'\t'"$((baseline_links + 1))"$'\t'0)
old_attachment=$(attachment "${old_container}")
IFS=$'\t' read -r old_link old_ipv4 old_ipv6 old_phase <<<"${old_attachment}"
[[ ${old_link} =~ ^unf[0-9a-f]+$ && ${old_phase} == ready ]]
run_check "${old_container}"

socket_displaced=true
host_exec '
    test -S /run/unf/cni.sock
    test ! -e /run/unf/cni.sock.unf-runtime-fault
    mv /run/unf/cni.sock /run/unf/cni.sock.unf-runtime-fault
    test ! -e /run/unf/cni.sock
    test -S /run/unf/cni.sock.unf-runtime-fault
'

"${kc[@]}" -n "${namespace}" delete pod unf-runtime-fault-old --wait=true --timeout=120s >/dev/null
offline_state=$(wait_snapshot "$((baseline_attachments + 1))"$'\t'"${baseline_caches}"$'\t'"${baseline_links}"$'\t'1)
host_exec "
    record=\$(find /var/lib/unf/cni/v1/pending-deletes -type f -name '*.json')
    test -n \"\$record\"
    test \"\$(stat -c %a \"\$record\")\" = 600
    jq -e --arg id '${old_container}' \
        '.schemaVersion == 1 and .key.network == \"unf-primary\" and \
         .key.containerId == \$id and .key.ifname == \"eth0\"' \"\$record\" >/dev/null
"

restore_socket
apply_pod unf-runtime-fault-recovery
wait_pod_ready unf-runtime-fault-recovery
new_container=$(cni_container_for_pod unf-runtime-fault-recovery)
recovery_state=$(wait_snapshot "$((baseline_attachments + 1))"$'\t'"$((baseline_caches + 1))"$'\t'"$((baseline_links + 1))"$'\t'0)
new_attachment=$(attachment "${new_container}")
IFS=$'\t' read -r new_link new_ipv4 new_ipv6 new_phase <<<"${new_attachment}"
[[ ${new_link} =~ ^unf[0-9a-f]+$ && ${new_phase} == ready ]]
[[ ${new_ipv4} == "${old_ipv4}" && ${new_ipv6} == "${old_ipv6}" ]]
host_exec "
    ! jq -e --arg id '${old_container}' \
        '.attachments[] | select(.spec.key.containerId == \$id)' \
        /var/lib/unf/cni/v1/attachments.json >/dev/null
    ! ip link show '${old_link}' >/dev/null 2>&1
"
run_check "${new_container}"

"${kc[@]}" -n "${namespace}" delete pod unf-runtime-fault-recovery --wait=true --timeout=120s >/dev/null
final_state=$(wait_snapshot "${baseline}")
"${kc[@]}" delete namespace "${namespace}" --wait=true --timeout=120s >/dev/null
namespace_created=false
wait_for_convergence "${expected_agents}"

mkdir -p "$(dirname "${artifact}")"
artifact_tmp=$(mktemp "${artifact}.tmp.XXXXXX")
umask 077
jq -n \
    --arg context "${context}" \
    --arg node "${node}" \
    --arg image "${image}" \
    --arg old_container "${old_container}" \
    --arg new_container "${new_container}" \
    --arg old_ipv4 "${old_ipv4}" \
    --arg old_ipv6 "${old_ipv6}" \
    --arg baseline "${baseline}" \
    --arg after_add "${old_state}" \
    --arg socket_offline "${offline_state}" \
    --arg after_drain "${recovery_state}" \
    --arg final "${final_state}" '
    {
      schema_version: 1,
      scenario: "openshift-primary-cni-runtime-fault",
      context: $context,
      node: $node,
      image: $image,
      old_container_id: $old_container,
      recovery_container_id: $new_container,
      reused_lease: {ipv4: $old_ipv4, ipv6: $old_ipv6},
      state_columns: ["attachments", "crio_caches", "host_links", "pending_deletes"],
      states: {
        baseline: $baseline,
        after_add: $after_add,
        socket_offline_after_delete: $socket_offline,
        after_serialized_drain: $after_drain,
        final: $final
      },
      checks: {
        pre_fault_check: "passed",
        exact_deferred_delete: "passed",
        old_attachment_and_link_cleanup: "passed",
        dual_stack_lease_reuse: "passed",
        post_recovery_check: "passed",
        exact_final_cleanup: "passed",
        controller_convergence: "passed"
      }
    }
  ' >"${artifact_tmp}"
mv "${artifact_tmp}" "${artifact}"
artifact_tmp=

echo "OpenShift primary-CNI runtime fault qualification passed: ${artifact}"
