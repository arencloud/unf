#!/usr/bin/env bash
set -euo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
kubeconfig=${KUBECONFIG:-"${project_root}/.tools/kind-unf-dev.kubeconfig"}
context=${KUBE_CONTEXT:-kind-unf-dev}

kc=(kubectl --kubeconfig "${kubeconfig}" --context "${context}")
container_runtime=${KIND_PROVIDER:-podman}

# kind's node image leaves /sys/fs/bpf as an unmounted sysfs directory. The
# production DaemonSet expects the host to provide bpffs, so reproduce that
# node prerequisite explicitly in the disposable fixture.
mapfile -t kind_nodes < <("${kc[@]}" get nodes -o name | sed 's|node/||')
for node in "${kind_nodes[@]}"; do
    sudo "${container_runtime}" exec "${node}" sh -c \
        'mountpoint -q /sys/fs/bpf || mount -t bpf bpf /sys/fs/bpf'
done

# The pinned kind node image selects legacy ip6tables inside kindnet, while
# some development kernels expose the IPv6 NAT table only through nftables.
# Select the equivalent nft frontend inside each disposable kindnet container.
# kindnet's startup probe can restore the image default, so reassert the symlink
# during its first ten seconds.
"${kc[@]}" -n kube-system patch daemonset kindnet --type=strategic --patch \
    '{"spec":{"template":{"spec":{"containers":[{"name":"kindnet-cni","command":["/bin/sh","-c"],"args":["(for delay in 1 2 3 4 5 6 7 8 9 10; do sleep 1; ln -sf /usr/sbin/ip6tables-nft /usr/sbin/ip6tables; done) & exec /bin/kindnetd"]}]}}}}' \
    >/dev/null
"${kc[@]}" -n kube-system rollout status daemonset/kindnet --timeout=120s
