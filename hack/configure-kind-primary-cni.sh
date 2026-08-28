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

for node in "${kind_nodes[@]}"; do
    sudo "${container_runtime}" exec "${node}" sh -ec '
        mountpoint -q /sys/fs/bpf || mount -t bpf bpf /sys/fs/bpf
        sysctl -q -w net.ipv4.ip_forward=1
        sysctl -q -w net.ipv6.conf.all.forwarding=1
        test -d /etc/cni/net.d
        if find /etc/cni/net.d -mindepth 1 -maxdepth 1 -type f | grep -q .; then
            echo "default-CNI-disabled node unexpectedly contains CNI configuration" >&2
            exit 1
        fi
    '
done

"${kc[@]}" label nodes --all network.unf.io/primary-cni=enabled --overwrite >/dev/null

# Primary-CNI agents need service discovery before ordinary Pods can obtain an
# interface. Bootstrap CoreDNS on host networking; the fixture restores the
# original deployment during its rollback proof.
if ! "${kc[@]}" -n kube-system get configmap unf-primary-cni-bootstrap-backup >/dev/null 2>&1; then
    coredns_template_spec=$("${kc[@]}" -n kube-system get deployment coredns -o json \
        | jq -c '.spec.template.spec')
    "${kc[@]}" -n kube-system create configmap unf-primary-cni-bootstrap-backup \
        --from-literal=coredns-template-spec="${coredns_template_spec}" >/dev/null
fi
"${kc[@]}" -n kube-system patch deployment coredns --type=strategic --patch \
    '{"spec":{"template":{"spec":{"hostNetwork":true,"dnsPolicy":"Default","tolerations":[{"operator":"Exists"}]}}}}' >/dev/null
"${kc[@]}" -n kube-system rollout status deployment/coredns --timeout=180s

echo "configured isolated primary-CNI prerequisites for ${context}"
