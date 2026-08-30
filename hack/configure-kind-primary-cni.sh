#!/usr/bin/env bash
set -euo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
kubeconfig=${KUBECONFIG:-"${project_root}/.tools/kind-unf-cni-dev.kubeconfig"}
context=${KUBE_CONTEXT:-kind-unf-cni-dev}
container_runtime=${KIND_PROVIDER:-podman}
kc=(kubectl --kubeconfig "${kubeconfig}" --context "${context}")

mapfile -t kind_nodes < <("${kc[@]}" get nodes -o name | sed 's|node/||')
if (( ${#kind_nodes[@]} < 3 )); then
    echo "primary-CNI qualification requires one control-plane and two worker nodes" >&2
    exit 1
fi

capture_nodeport_sysctls() {
    local node node_values state='{}'
    for node in "${kind_nodes[@]}"; do
        node_values=$(sudo "${container_runtime}" exec "${node}" sh -ec '
            for parameter in rp_filter accept_local; do
                for path in /proc/sys/net/ipv4/conf/*/${parameter}; do
                    key=${path#/proc/sys/net/ipv4/conf/}
                    printf "%s\t%s\n" "$key" "$(cat "$path")"
                done
            done
        ' | jq -Rn '
            reduce inputs as $line ({};
                ($line | split("\t")) as $columns
                | .[$columns[0]] = ($columns[1] | tonumber))
        ')
        state=$(jq -cn --argjson state "${state}" --arg node "${node}" \
            --argjson values "${node_values}" '$state + {($node):$values}')
    done
    printf '%s\n' "${state}"
}

# Primary-CNI agents need service discovery before ordinary Pods can obtain an
# interface. Bootstrap CoreDNS on host networking; the fixture restores the
# original deployment during its rollback proof.
if ! "${kc[@]}" -n kube-system get configmap unf-primary-cni-bootstrap-backup >/dev/null 2>&1; then
    coredns_template_spec=$("${kc[@]}" -n kube-system get deployment coredns -o json \
        | jq -c '.spec.template.spec')
    coredns_corefile=$("${kc[@]}" -n kube-system get configmap coredns \
        -o jsonpath='{.data.Corefile}')
    nodeport_sysctls=$(capture_nodeport_sysctls)
    "${kc[@]}" -n kube-system create configmap unf-primary-cni-bootstrap-backup \
        --from-literal=coredns-template-spec="${coredns_template_spec}" \
        --from-literal=coredns-corefile="${coredns_corefile}" \
        --from-literal=nodeport-sysctls="${nodeport_sysctls}" >/dev/null
else
    # Migrate a bootstrap backup created before the kube-proxy-free fixture
    # also needed to restore the Corefile or NodePort host sysctls. Capture
    # each value only once so repeated deploys cannot replace the baseline.
    if [[ -z $("${kc[@]}" -n kube-system get configmap unf-primary-cni-bootstrap-backup \
        -o jsonpath='{.data.coredns-corefile}') ]]; then
        coredns_corefile=$("${kc[@]}" -n kube-system get configmap coredns \
            -o jsonpath='{.data.Corefile}')
        corefile_patch=$(jq -cn --arg corefile "${coredns_corefile}" \
            '{data:{"coredns-corefile":$corefile}}')
        "${kc[@]}" -n kube-system patch configmap unf-primary-cni-bootstrap-backup \
            --type=merge --patch "${corefile_patch}" >/dev/null
    fi
    if [[ -z $("${kc[@]}" -n kube-system get configmap unf-primary-cni-bootstrap-backup \
        -o jsonpath='{.data.nodeport-sysctls}') ]]; then
        nodeport_sysctls=$(capture_nodeport_sysctls)
        sysctl_patch=$(jq -cn --arg sysctls "${nodeport_sysctls}" \
            '{data:{"nodeport-sysctls":$sysctls}}')
        "${kc[@]}" -n kube-system patch configmap unf-primary-cni-bootstrap-backup \
            --type=merge --patch "${sysctl_patch}" >/dev/null
    fi
fi

for node in "${kind_nodes[@]}"; do
    sudo "${container_runtime}" exec "${node}" sh -ec '
        mountpoint -q /sys/fs/bpf || mount -t bpf bpf /sys/fs/bpf
        sysctl -q -w net.ipv4.ip_forward=1
        sysctl -q -w net.ipv6.conf.all.forwarding=1
        for path in /proc/sys/net/ipv4/conf/*/rp_filter; do
            printf 0 >"$path"
        done
        for path in /proc/sys/net/ipv4/conf/*/accept_local; do
            printf 1 >"$path"
        done
        test "$(cat /proc/sys/net/ipv4/conf/all/rp_filter)" = 0
        test "$(cat /proc/sys/net/ipv4/conf/default/rp_filter)" = 0
        test "$(cat /proc/sys/net/ipv4/conf/all/accept_local)" = 1
        test "$(cat /proc/sys/net/ipv4/conf/default/accept_local)" = 1
        test -d /etc/cni/net.d
        if find /etc/cni/net.d -mindepth 1 -maxdepth 1 -type f | grep -q .; then
            echo "default-CNI-disabled node unexpectedly contains CNI configuration" >&2
            exit 1
        fi
    '
done

"${kc[@]}" label nodes --all network.unf.io/primary-cni=enabled --overwrite >/dev/null

if ! "${kc[@]}" -n kube-system get daemonset kube-proxy >/dev/null 2>&1; then
    control_plane_ipv4=$("${kc[@]}" get nodes -l node-role.kubernetes.io/control-plane \
        -o json | jq -r '.items[0].status.addresses[] | select(.type == "InternalIP" and (.address | contains("."))) | .address')
    original_corefile=$("${kc[@]}" -n kube-system get configmap \
        unf-primary-cni-bootstrap-backup -o jsonpath='{.data.coredns-corefile}')
    corefile_patch=$(jq -cn --arg corefile "${original_corefile}" \
        '{data:{Corefile:$corefile}}')
    "${kc[@]}" -n kube-system patch configmap coredns --type=merge \
        --patch "${corefile_patch}" >/dev/null
    coredns_deployment_patch=$(jq -cn --arg host "${control_plane_ipv4}" '
        {spec:{template:{spec:{
            hostNetwork:true,
            dnsPolicy:"Default",
            tolerations:[{operator:"Exists"}],
            containers:[{name:"coredns",env:[
                {name:"KUBERNETES_SERVICE_HOST",value:$host},
                {name:"KUBERNETES_SERVICE_PORT",value:"6443"}
            ]}]
        }}}}')
else
    coredns_deployment_patch='{"spec":{"template":{"spec":{"hostNetwork":true,"dnsPolicy":"Default","tolerations":[{"operator":"Exists"}]}}}}'
fi
"${kc[@]}" -n kube-system patch deployment coredns --type=strategic --patch \
    "${coredns_deployment_patch}" >/dev/null
"${kc[@]}" -n kube-system rollout status deployment/coredns --timeout=180s

echo "configured isolated primary-CNI prerequisites for ${context}"
