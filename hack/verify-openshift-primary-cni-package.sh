#!/usr/bin/env bash
set -euo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
runtime=${project_root}/deploy/openshift-primary-cni/runtime
machineconfig=${project_root}/deploy/openshift-primary-cni/machineconfig
temporary_dir=$(mktemp -d)
trap 'rm -rf "${temporary_dir}"' EXIT

for script in \
    "${project_root}/hack/audit-openshift-primary-cni.sh" \
    "${project_root}/hack/configure-openshift-primary-cni-node-blocks.sh" \
    "${project_root}/hack/deploy-openshift-primary-cni.sh"; do
    bash -n "${script}"
done
sh -n "${runtime}/install.sh"

kubectl kustomize "${runtime}" >"${temporary_dir}/runtime.yaml"
kubectl kustomize "${machineconfig}" >"${temporary_dir}/machineconfig.yaml"

[[ $(grep -c 'quay.io/arencloud/unf-controller-dev@sha256:' "${temporary_dir}/runtime.yaml") -eq 1 ]]
[[ $(grep -c 'quay.io/arencloud/unf-agent-dev@sha256:' "${temporary_dir}/runtime.yaml") -eq 2 ]]
! grep -Eq 'image: .*:dev([[:space:]]|$)' "${temporary_dir}/runtime.yaml"
grep -q 'nodeName: unf-primary-controller-node.invalid' "${temporary_dir}/runtime.yaml"
grep -q 'ip: 192.0.2.1' "${temporary_dir}/runtime.yaml"
grep -q 'https://unf-primary-controller.internal:9964' "${temporary_dir}/runtime.yaml"
[[ $(grep -c 'path: /etc/sysctl.d/90-unf-primary-cni.conf' "${temporary_dir}/machineconfig.yaml") -eq 2 ]]
grep -q 'networkType: None' "${project_root}/deploy/openshift-primary-cni/install-config-networking.yaml"
grep -q 'type: None' "${project_root}/deploy/openshift-primary-cni/manifests/cluster-network-03-config.yaml"
jq -e '.schemaVersion == 1 and (.nodes | length) == 5 and
  ([.nodes[].podCIDRs | length] | all(. == 2))' \
  "${project_root}/deploy/openshift-primary-cni/node-blocks.json" >/dev/null
python3 - "${project_root}/deploy/openshift-primary-cni/node-blocks.json" <<'PY'
import ipaddress
import json
import sys

with open(sys.argv[1], encoding="utf-8") as stream:
    config = json.load(stream)
pools = {
    ipaddress.ip_network(entry["cidr"], strict=True): entry["hostPrefix"]
    for entry in config["clusterNetworks"]
}
seen = []
for node in config["nodes"]:
    blocks = [ipaddress.ip_network(value, strict=True) for value in node["podCIDRs"]]
    if {block.version for block in blocks} != {4, 6}:
        raise SystemExit(f'{node["name"]} does not have one block per family')
    for block in blocks:
        if not any(block.version == pool.version and block.subnet_of(pool)
                   and block.prefixlen == prefix for pool, prefix in pools.items()):
            raise SystemExit(f'{node["name"]} block is outside its exact pool')
        if any(block.overlaps(previous) for previous in seen):
            raise SystemExit(f'{node["name"]} block overlaps another Node')
        seen.append(block)
PY

jq -e '
  .cniVersion == "1.1.0" and
  .name == "unf-primary" and
  (.plugins | length) == 1 and
  .plugins[0].type == "unf" and
  .plugins[0].mode == "primary" and
  .plugins[0].agentSocket == "/run/unf/cni.sock" and
  .plugins[0].mtu == 1500
' "${runtime}/10-unf.conflist" >/dev/null

for exact_path in \
    /host/var/lib/cni/bin/unf \
    /host/etc/kubernetes/cni/net.d/10-unf.conflist \
    /host/var/lib/unf/cni/v1 \
    /host/run/unf/cni.sock; do
    grep -q "${exact_path}" "${runtime}/install.sh"
done

echo "OpenShift primary-CNI reinstall package passed static safety and render checks"
"${project_root}/hack/verify-openshift-primary-cni-installer.sh"
