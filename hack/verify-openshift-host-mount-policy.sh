#!/usr/bin/env bash
set -euo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
kubeconfig=${KUBECONFIG:-"${project_root}/.tools/cl02-audit.kubeconfig"}
context=${KUBE_CONTEXT:-$(oc --kubeconfig "${kubeconfig}" config current-context)}
kc=(oc --kubeconfig "${kubeconfig}" --context "${context}")

for command in oc jq; do
    command -v "${command}" >/dev/null
done
[[ -s ${kubeconfig} ]] || {
    echo "OpenShift kubeconfig not found: ${kubeconfig}" >&2
    exit 1
}

expect_replace_denied() {
    local manifest=$1
    local message=$2
    local description=$3
    local output
    if output=$("${kc[@]}" replace --dry-run=server -f - <<<"${manifest}" 2>&1); then
        echo "${description} was admitted" >&2
        exit 1
    fi
    grep -q "${message}" <<<"${output}" || {
        echo "${description} was rejected without the expected UNF policy message" >&2
        printf '%s\n' "${output}" >&2
        exit 1
    }
}

"${kc[@]}" get clusterversion version >/dev/null
policies=$("${kc[@]}" get validatingadmissionpolicy \
    unf-agent-daemonset-host-mounts unf-agent-pod-host-mounts -o json)
jq -e '
    (.items | length) == 2
    and all(.items[];
        .spec.failurePolicy == "Fail"
        and .spec.matchConstraints.namespaceSelector.matchLabels["kubernetes.io/metadata.name"] == "unf-system"
        and (if .metadata.name == "unf-agent-daemonset-host-mounts" then
            .spec.matchConditions == [{
                "name": "unf-agent-daemonset-or-service-account",
                "expression": "object.metadata.name == '\''unf-agent'\'' || object.spec.template.spec.serviceAccountName == '\''unf-agent'\''"
            }]
        else
            .spec.matchConditions == [{
                "name": "unf-agent-service-account",
                "expression": "object.spec.serviceAccountName == '\''unf-agent'\''"
            }]
        end)
        and .status.observedGeneration == .metadata.generation
        and ((.status.typeChecking.expressionWarnings // []) | length) == 0)
' <<<"${policies}" >/dev/null

bindings=$("${kc[@]}" get validatingadmissionpolicybinding \
    unf-agent-daemonset-host-mounts unf-agent-pod-host-mounts -o json)
jq -e '
    (.items | length) == 2
    and all(.items[];
        .spec.policyName == .metadata.name
        and .spec.validationActions == ["Deny"])
' <<<"${bindings}" >/dev/null

daemonset=$("${kc[@]}" -n unf-system get daemonset unf-agent -o json)
"${kc[@]}" replace --dry-run=server -f - <<<"${daemonset}" >/dev/null

changed_service_account=$(jq '
    .spec.template.spec.serviceAccountName = "default"
' <<<"${daemonset}")
expect_replace_denied "${changed_service_account}" \
    'must retain the unf-agent service account' \
    'unf-agent DaemonSet service-account replacement'

unsafe_path=$(jq '
    (.spec.template.spec.volumes[] | select(.name == "bpffs").hostPath.path) = "/etc"
' <<<"${daemonset}")
expect_replace_denied "${unsafe_path}" \
    'must use exactly bpffs, BTF, and the durable UNF state directory' \
    'unsafe DaemonSet host path'

unsafe_type=$(jq '
    (.spec.template.spec.volumes[] | select(.name == "btf").hostPath.type) = "DirectoryOrCreate"
' <<<"${daemonset}")
expect_replace_denied "${unsafe_type}" \
    'must use exactly bpffs, BTF, and the durable UNF state directory' \
    'host-path creation request'

writable_btf=$(jq '
    (.spec.template.spec.containers[] | select(.name == "agent").volumeMounts[]
        | select(.name == "btf").readOnly) = false
' <<<"${daemonset}")
expect_replace_denied "${writable_btf}" \
    'BTF read-only' \
    'writable BTF mount'

readonly_bpffs=$(jq '
    (.spec.template.spec.containers[] | select(.name == "agent").volumeMounts[]
        | select(.name == "bpffs").readOnly) = true
' <<<"${daemonset}")
expect_replace_denied "${readonly_bpffs}" \
    'mount bpffs read/write' \
    'read-only bpffs mount'

subpath_bpffs=$(jq '
    (.spec.template.spec.containers[] | select(.name == "agent").volumeMounts[]
        | select(.name == "bpffs").subPath) = "unf"
' <<<"${daemonset}")
expect_replace_denied "${subpath_bpffs}" \
    'without subpaths or mount propagation' \
    'bpffs subPath mount'

propagated_bpffs=$(jq '
    (.spec.template.spec.containers[] | select(.name == "agent").volumeMounts[]
        | select(.name == "bpffs").mountPropagation) = "HostToContainer"
' <<<"${daemonset}")
expect_replace_denied "${propagated_bpffs}" \
    'without subpaths or mount propagation' \
    'bpffs mount-propagation request'

sidecar_mount=$(jq '
    .spec.template.spec.containers += [{
        "name": "host-reader",
        "image": "docker.io/library/busybox:1.37.0",
        "command": ["sleep", "60"],
        "volumeMounts": [{
            "name": "btf",
            "mountPath": "/tmp/btf",
            "readOnly": true
        }]
    }]
' <<<"${daemonset}")
expect_replace_denied "${sidecar_mount}" \
    'only the agent container may mount' \
    'sidecar host-volume mount'

init_mount=$(jq '
    .spec.template.spec.initContainers = [{
        "name": "host-reader",
        "image": "docker.io/library/busybox:1.37.0",
        "command": ["true"],
        "volumeMounts": [{
            "name": "btf",
            "mountPath": "/tmp/btf",
            "readOnly": true
        }]
    }]
' <<<"${daemonset}")
expect_replace_denied "${init_mount}" \
    'only the agent container may mount' \
    'init-container host-volume mount'

unsafe_pod=$("${kc[@]}" run unf-host-mount-negative -n unf-system \
    --image=docker.io/library/busybox:1.37.0 --restart=Never \
    --dry-run=client -o json -- sleep 60 | jq '
        .spec.serviceAccountName = "unf-agent"
        | .spec.containers[0].name = "agent"
        | .spec.containers[0].volumeMounts = [
            {"name": "bpffs", "mountPath": "/sys/fs/bpf"},
            {"name": "btf", "mountPath": "/sys/kernel/btf", "readOnly": true}
        ]
        | .spec.volumes = [
            {"name": "bpffs", "hostPath": {"path": "/etc", "type": "Directory"}},
            {"name": "btf", "hostPath": {"path": "/sys/kernel/btf", "type": "Directory"}}
        ]
    ')
if output=$("${kc[@]}" create --dry-run=server -f - <<<"${unsafe_pod}" 2>&1); then
    echo "unsafe direct agent Pod host path was admitted" >&2
    exit 1
fi
grep -q 'must use exactly bpffs, BTF, and the durable UNF state directory' <<<"${output}"

unrelated_pod=$("${kc[@]}" run unf-host-mount-unrelated -n unf-system \
    --image=docker.io/library/busybox:1.37.0 --restart=Never \
    --dry-run=client -o json -- sleep 60)
"${kc[@]}" create --dry-run=server -f - <<<"${unrelated_pod}" >/dev/null

agents=$("${kc[@]}" -n unf-system get pod \
    -l app.kubernetes.io/name=unf-agent -o json)
jq -e '
    (.items | length) > 0
    and all(.items[];
        ([.spec.volumes[] | select(has("hostPath")) |
            [.name, .hostPath.path, .hostPath.type]] | sort) == [
                ["bpffs", "/sys/fs/bpf", "Directory"],
                ["btf", "/sys/kernel/btf", "Directory"],
                ["cni-state", "/var/lib/unf/cni", "DirectoryOrCreate"]
            ]
        and (.spec.containers | length) == 1
        and .spec.containers[0].name == "agent"
        and ([.spec.containers[0].volumeMounts[] |
            select(.name == "bpffs" or .name == "btf" or .name == "cni-state") |
            [.name, .mountPath, (.readOnly // false)]] | sort) == [
                ["bpffs", "/sys/fs/bpf", false],
                ["btf", "/sys/kernel/btf", true],
                ["cni-state", "/var/lib/unf/cni", false]
            ])
' <<<"${agents}" >/dev/null

agent=$(jq -r '[.items[] | select(.metadata.deletionTimestamp == null) |
    .metadata.name][0] // empty' <<<"${agents}")
[[ -n ${agent} ]]
ephemeral_patch='{"spec":{"ephemeralContainers":[{"name":"host-reader","image":"docker.io/library/busybox:1.37.0","command":["sleep","60"],"targetContainerName":"agent","volumeMounts":[{"name":"btf","mountPath":"/tmp/btf","readOnly":true}]}]}}'
if output=$("${kc[@]}" -n unf-system patch pod "${agent}" \
    --subresource=ephemeralcontainers --type=merge --patch "${ephemeral_patch}" \
    --dry-run=server 2>&1); then
    echo "ephemeral-container host-volume mount was admitted" >&2
    exit 1
fi
grep -q 'only the agent container may mount' <<<"${output}"

echo "OpenShift host-mount admission qualification passed: exact bpffs/BTF/durable-state volumes admitted; service-account replacement, alternate paths/types/modes, subPath/propagation, sidecar/init/direct-Pod/ephemeral host mounts denied"
