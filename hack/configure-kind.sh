#!/usr/bin/env bash
set -euo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
kubeconfig=${KUBECONFIG:-"${project_root}/.tools/kind-unf-dev.kubeconfig"}
context=${KUBE_CONTEXT:-kind-unf-dev}

kc=(kubectl --kubeconfig "${kubeconfig}" --context "${context}")

# The pinned kind node image selects legacy ip6tables inside kindnet, while
# some development kernels expose the IPv6 NAT table only through nftables.
# Select the equivalent nft frontend inside each disposable kindnet container.
# kindnet's startup probe can restore the image default, so reassert the symlink
# during its first ten seconds.
"${kc[@]}" -n kube-system patch daemonset kindnet --type=strategic --patch \
    '{"spec":{"template":{"spec":{"containers":[{"name":"kindnet-cni","command":["/bin/sh","-c"],"args":["(for delay in 1 2 3 4 5 6 7 8 9 10; do sleep 1; ln -sf /usr/sbin/ip6tables-nft /usr/sbin/ip6tables; done) & exec /bin/kindnetd"]}]}}}}' \
    >/dev/null
"${kc[@]}" -n kube-system rollout status daemonset/kindnet --timeout=120s
