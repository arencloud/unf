#!/usr/bin/env bash
set -euo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
kubeconfig=${KUBECONFIG:-"${project_root}/.tools/cl02-audit.kubeconfig"}
context=${KUBE_CONTEXT:-$(oc --kubeconfig "${kubeconfig}" config current-context)}
kc=(oc --kubeconfig "${kubeconfig}" --context "${context}")
execute=false
confirm_context=
delete_namespace=false
delete_crd=false
confirm_crd_data_loss=false

usage() {
    cat <<'EOF'
Usage: hack/uninstall-openshift.sh [options]

Plans a coordinated UNF host cleanup and OpenShift uninstall by default.

Options:
  --execute                    Apply the reviewed plan.
  --confirm-context CONTEXT    Exact current context required with --execute.
  --delete-namespace           Delete the dedicated unf-system Namespace.
  --delete-crd                 Delete the SecurityPolicy CRD after cleanup.
  --confirm-crd-data-loss      Permit --delete-crd when SecurityPolicy objects exist.
  -h, --help                   Show this help.
EOF
}

while [[ $# -gt 0 ]]; do
    case $1 in
        --execute)
            execute=true
            shift
            ;;
        --confirm-context)
            [[ $# -ge 2 ]] || {
                echo "--confirm-context requires a value" >&2
                exit 2
            }
            confirm_context=$2
            shift 2
            ;;
        --delete-namespace)
            delete_namespace=true
            shift
            ;;
        --delete-crd)
            delete_crd=true
            shift
            ;;
        --confirm-crd-data-loss)
            confirm_crd_data_loss=true
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "unknown argument: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

for command in oc jq; do
    command -v "${command}" >/dev/null
done
[[ -s ${kubeconfig} ]] || {
    echo "OpenShift kubeconfig not found: ${kubeconfig}" >&2
    exit 1
}
if ${execute} && [[ ${confirm_context} != "${context}" ]]; then
    echo "refusing execution: --confirm-context must exactly match ${context}" >&2
    exit 1
fi
if ${confirm_crd_data_loss} && ! ${delete_crd}; then
    echo "--confirm-crd-data-loss is valid only with --delete-crd" >&2
    exit 2
fi

"${kc[@]}" get clusterversion version >/dev/null
"${kc[@]}" get namespace unf-system >/dev/null
daemonset=$("${kc[@]}" -n unf-system get daemonset unf-agent -o json)
desired=$(jq '.status.desiredNumberScheduled // 0' <<<"${daemonset}")
ready=$(jq '.status.numberReady // 0' <<<"${daemonset}")
[[ ${desired} -gt 0 && ${ready} -eq ${desired} ]] || {
    echo "refusing uninstall: unf-agent must be Ready on every selected node" >&2
    exit 1
}

agents=$("${kc[@]}" -n unf-system get pod \
    -l app.kubernetes.io/name=unf-agent -o json)
mapfile -t agent_records < <(jq -r '
    [.items[] |
        select(.metadata.deletionTimestamp == null and .status.phase == "Running") |
        select(any(.status.conditions[]?; .type == "Ready" and .status == "True")) |
        [.spec.nodeName, .metadata.name] | @tsv] | sort | .[]
' <<<"${agents}")
[[ ${#agent_records[@]} -eq ${desired} ]] || {
    echo "refusing uninstall: expected ${desired} Ready agent Pods, found ${#agent_records[@]}" >&2
    exit 1
}

security_policy_count=0
if "${kc[@]}" get customresourcedefinition \
    securitypolicies.network.unf.io >/dev/null 2>&1; then
    security_policy_count=$("${kc[@]}" get securitypolicies.network.unf.io \
        --all-namespaces -o json | jq '.items | length')
fi
if ${execute} && ${delete_crd} && [[ ${security_policy_count} -gt 0 ]] \
    && ! ${confirm_crd_data_loss}; then
    echo "refusing CRD deletion: ${security_policy_count} SecurityPolicy objects exist; add --confirm-crd-data-loss" >&2
    exit 1
fi

echo "UNF coordinated uninstall plan ($(if ${execute}; then echo execute; else echo dry-run; fi))"
echo "context: ${context}"
echo "selected nodes: ${desired}"

mapfile -t nodes < <(printf '%s\n' "${agent_records[@]}" | cut -f1)
mapfile -t pods < <(printf '%s\n' "${agent_records[@]}" | cut -f2)
for index in "${!nodes[@]}"; do
    node=${nodes[${index}]}
    pod=${pods[${index}]}
    echo "node cleanup: ${node} via ${pod}"
    cleanup_plan=$("${kc[@]}" -n unf-system exec "${pod}" -- \
        /usr/local/bin/unf-component cleanup \
        --abi-version 3 --allow-current-abi \
        --legacy-attachments --all-interfaces --legacy-direction both)
    grep -q 'UNF cleanup plan (dry-run)' <<<"${cleanup_plan}"
    grep -q 'dry run only' <<<"${cleanup_plan}"
    grep -q 'ABI directory: /sys/fs/bpf/unf/v3' <<<"${cleanup_plan}"
    [[ $(grep -c 'remove map pin: /sys/fs/bpf/unf/v3/' <<<"${cleanup_plan}") -eq 11 ]]
    sed 's/^/  /' <<<"${cleanup_plan}"
done

echo "cluster cleanup:"
echo "  stop DaemonSet unf-system/unf-agent before host mutation"
echo "  run one constrained cleanup Job on each selected node"
echo "  verify /sys/fs/bpf/unf/v3 and UNF legacy filters are absent"
if ${delete_namespace}; then
    echo "  delete dedicated Namespace unf-system"
else
    echo "  delete exact UNF namespaced workloads, Services, state, credentials, and service accounts"
    echo "  preserve Namespace unf-system"
fi
echo "  delete exact UNF admission, SCC, and RBAC objects"
if ${delete_crd}; then
    echo "  delete SecurityPolicy CRD and ${security_policy_count} existing custom resources"
else
    echo "  preserve SecurityPolicy CRD and ${security_policy_count} existing custom resources"
fi

if ! ${execute}; then
    printf 'dry run only; rerun with --execute --confirm-context '
    printf '%q' "${context}"
    printf ' to apply this scope\n'
    exit 0
fi

image=$(jq -r '.spec.template.spec.containers[] | select(.name == "agent").image' \
    <<<"${daemonset}")
image_pull_policy=$(jq -r '.spec.template.spec.containers[] |
    select(.name == "agent").imagePullPolicy // "IfNotPresent"' <<<"${daemonset}")
security_context=$(jq -c '.spec.template.spec.containers[] |
    select(.name == "agent").securityContext' <<<"${daemonset}")
volume_mounts=$(jq -c '[.spec.template.spec.containers[] |
    select(.name == "agent").volumeMounts[] |
    select(.name == "bpffs" or .name == "btf" or .name == "cni-state")]' <<<"${daemonset}")
volumes=$(jq -c '[.spec.template.spec.volumes[] |
    select(.name == "bpffs" or .name == "btf" or .name == "cni-state")]' <<<"${daemonset}")

"${kc[@]}" -n unf-system delete daemonset unf-agent \
    --cascade=foreground --wait=true --timeout=180s
for _ in {1..60}; do
    remaining=$("${kc[@]}" -n unf-system get pod \
        -l app.kubernetes.io/name=unf-agent -o json | jq '.items | length')
    [[ ${remaining} -eq 0 ]] && break
    sleep 1
done
[[ ${remaining} -eq 0 ]] || {
    echo "agent Pods remained after DaemonSet shutdown" >&2
    exit 1
}

job_names=()
for index in "${!nodes[@]}"; do
    node=${nodes[${index}]}
    job_name="unf-agent-cleanup-$((index + 1))"
    job_names+=("${job_name}")
    "${kc[@]}" -n unf-system delete job "${job_name}" \
        --ignore-not-found --wait=true >/dev/null
    job=$(jq -n \
        --arg name "${job_name}" \
        --arg node "${node}" \
        --arg image "${image}" \
        --arg image_pull_policy "${image_pull_policy}" \
        --argjson security_context "${security_context}" \
        --argjson volume_mounts "${volume_mounts}" \
        --argjson volumes "${volumes}" '
        {
            apiVersion: "batch/v1",
            kind: "Job",
            metadata: {
                name: $name,
                namespace: "unf-system",
                labels: {"app.kubernetes.io/name": "unf-agent-cleanup"}
            },
            spec: {
                backoffLimit: 0,
                template: {
                    metadata: {
                        labels: {"app.kubernetes.io/name": "unf-agent-cleanup"}
                    },
                    spec: {
                        nodeName: $node,
                        serviceAccountName: "unf-agent",
                        automountServiceAccountToken: false,
                        hostNetwork: true,
                        dnsPolicy: "ClusterFirstWithHostNet",
                        restartPolicy: "Never",
                        tolerations: [{operator: "Exists"}],
                        containers: [{
                            name: "agent",
                            image: $image,
                            imagePullPolicy: $image_pull_policy,
                            args: [
                                "cleanup",
                                "--abi-version", "3",
                                "--allow-current-abi",
                                "--legacy-attachments",
                                "--all-interfaces",
                                "--legacy-direction", "both",
                                "--execute"
                            ],
                            securityContext: $security_context,
                            volumeMounts: $volume_mounts
                        }],
                        volumes: $volumes
                    }
                }
            }
        }
    ')
    "${kc[@]}" create -f - <<<"${job}" >/dev/null
done

for job_name in "${job_names[@]}"; do
    "${kc[@]}" -n unf-system wait --for=condition=complete \
        "job/${job_name}" --timeout=180s >/dev/null
    logs=$("${kc[@]}" -n unf-system logs "job/${job_name}")
    grep -q 'UNF cleanup plan (execute)' <<<"${logs}"
    grep -q 'UNF cleanup completed' <<<"${logs}"
done

for node in "${nodes[@]}"; do
    verification=$("${kc[@]}" debug "node/${node}" --quiet -- \
        chroot /host sh -eu -c '
            test ! -e /sys/fs/bpf/unf/v3
            for path in /sys/class/net/*; do
                interface=${path##*/}
                [ "${interface}" = lo ] && continue
                for direction in ingress egress; do
                    filters=$(tc filter show dev "${interface}" "${direction}" 2>/dev/null || true)
                    if printf "%s\n" "${filters}" \
                        | grep -Eq "unf_observe_(ingress|egress)|handle 0x554e000[12] "; then
                        echo "UNF filter remained: ${interface} ${direction}" >&2
                        exit 1
                    fi
                done
            done
            echo host-clean
        ' 2>&1)
    grep -q 'host-clean' <<<"${verification}"
done

"${kc[@]}" -n unf-system delete job "${job_names[@]}" \
    --ignore-not-found --wait=true >/dev/null
if ${delete_namespace}; then
    "${kc[@]}" delete namespace unf-system --wait=true --timeout=180s >/dev/null
else
    "${kc[@]}" -n unf-system delete deployment unf-controller \
        --ignore-not-found --wait=true >/dev/null
    "${kc[@]}" -n unf-system delete service unf-controller \
        --ignore-not-found >/dev/null
    "${kc[@]}" -n unf-system delete configmap \
        unf-agent-acknowledgements unf-flow-history unf-topology-history unf-internal-ca \
        --ignore-not-found >/dev/null
    # Retain cleanup compatibility with deployments created before public-image
    # pulls stopped installing a namespaced Quay credential.
    "${kc[@]}" -n unf-system delete secret \
        unf-internal-tls unf-quay-pull --ignore-not-found >/dev/null
    "${kc[@]}" -n unf-system delete serviceaccount \
        unf-agent unf-controller --ignore-not-found >/dev/null
fi

"${kc[@]}" delete validatingadmissionpolicybinding \
    unf-agent-daemonset-host-mounts unf-agent-pod-host-mounts \
    --ignore-not-found >/dev/null
"${kc[@]}" delete validatingadmissionpolicy \
    unf-agent-daemonset-host-mounts unf-agent-pod-host-mounts \
    --ignore-not-found >/dev/null
"${kc[@]}" delete clusterrolebinding \
    unf-agent-scc-use unf-controller --ignore-not-found >/dev/null
"${kc[@]}" delete clusterrole \
    unf-agent-scc-use unf-controller --ignore-not-found >/dev/null
"${kc[@]}" delete securitycontextconstraints unf-agent \
    --ignore-not-found >/dev/null
if ${delete_crd}; then
    "${kc[@]}" delete customresourcedefinition \
        securitypolicies.network.unf.io --ignore-not-found --wait=true >/dev/null
fi

echo "UNF coordinated uninstall completed on ${context}; host state and exact product resources removed"
