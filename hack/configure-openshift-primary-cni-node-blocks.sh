#!/usr/bin/env bash
set -euo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
kubeconfig=${KUBECONFIG:-"${project_root}/.tools/cl02-audit.kubeconfig"}
config=${UNF_OPENSHIFT_PRIMARY_NODE_BLOCKS:-"${project_root}/deploy/openshift-primary-cni/node-blocks.json"}
expected_infrastructure=${UNF_OPENSHIFT_PRIMARY_EXPECTED_INFRASTRUCTURE:-}
acknowledgement=${UNF_OPENSHIFT_PRIMARY_ACKNOWLEDGE_DISPOSABLE:-}
dry_run=${UNF_OPENSHIFT_PRIMARY_NODE_BLOCK_DRY_RUN:-false}

for command in jq kubectl python3; do
    command -v "${command}" >/dev/null || {
        echo "OpenShift primary-CNI node-block prerequisite is missing: ${command}" >&2
        exit 1
    }
done
if [[ ! -f ${config} ]] || ! jq -e '.schemaVersion == 1' "${config}" >/dev/null; then
    echo "OpenShift primary-CNI node-block configuration is missing or incompatible" >&2
    exit 1
fi

context=$(kubectl --kubeconfig "${kubeconfig}" config current-context)
kc=(kubectl --kubeconfig "${kubeconfig}" --context "${context}")
infrastructure=$("${kc[@]}" get infrastructure cluster -o jsonpath='{.status.infrastructureName}')
if [[ -z ${expected_infrastructure} || ${expected_infrastructure} != "${infrastructure}" \
    || ${acknowledgement} != "${infrastructure}" ]]; then
    echo "refusing Node-block assignment without exact infrastructure and disposable acknowledgement" >&2
    exit 1
fi

temporary_dir=$(mktemp -d)
trap 'find "${temporary_dir}" -depth -delete' EXIT
"${kc[@]}" get nodes -o json >"${temporary_dir}/nodes.json"
"${kc[@]}" get network.config.openshift.io cluster -o json \
    >"${temporary_dir}/network.json"

python3 - "${config}" "${temporary_dir}/nodes.json" "${temporary_dir}/network.json" \
    >"${temporary_dir}/assignments.tsv" <<'PY'
import ipaddress
import json
import sys

config_path, nodes_path, network_path = sys.argv[1:]
with open(config_path, encoding="utf-8") as stream:
    config = json.load(stream)
with open(nodes_path, encoding="utf-8") as stream:
    nodes = json.load(stream)
with open(network_path, encoding="utf-8") as stream:
    network = json.load(stream)

if config.get("schemaVersion") != 1:
    raise SystemExit("node-block schema must be 1")
expected_networks = {
    (str(ipaddress.ip_network(entry["cidr"], strict=True)), entry["hostPrefix"])
    for entry in network["spec"]["clusterNetwork"]
}
configured_networks = {
    (str(ipaddress.ip_network(entry["cidr"], strict=True)), entry["hostPrefix"])
    for entry in config["clusterNetworks"]
}
if configured_networks != expected_networks:
    raise SystemExit("configured cluster networks do not exactly match OpenShift")

actual_names = sorted(item["metadata"]["name"] for item in nodes["items"])
configured_names = sorted(item["name"] for item in config["nodes"])
if actual_names != configured_names or len(configured_names) != len(set(configured_names)):
    raise SystemExit("configured and actual Node sets do not match exactly")

pools = {
    ipaddress.ip_network(cidr): prefix for cidr, prefix in configured_networks
}
assigned = []
for item in config["nodes"]:
    blocks = [ipaddress.ip_network(value, strict=True) for value in item["podCIDRs"]]
    if len(blocks) != 2 or {block.version for block in blocks} != {4, 6}:
        raise SystemExit(f'{item["name"]} must have one IPv4 and one IPv6 block')
    ordered = sorted(blocks, key=lambda block: block.version)
    for block in ordered:
        matches = [pool for pool, prefix in pools.items()
                   if pool.version == block.version and block.subnet_of(pool)
                   and block.prefixlen == prefix]
        if len(matches) != 1:
            raise SystemExit(f'{item["name"]} block {block} is outside its exact pool')
        if any(block.overlaps(previous) for previous in assigned):
            raise SystemExit(f'{item["name"]} block {block} overlaps another assignment')
        assigned.append(block)
    print(item["name"], str(ordered[0]), str(ordered[1]), sep="\t")
PY

while IFS=$'\t' read -r node ipv4_block ipv6_block; do
    current=$("${kc[@]}" get "node/${node}" -o json)
    current_primary=$(jq -r '.spec.podCIDR // ""' <<<"${current}")
    current_cidrs=$(jq -c '.spec.podCIDRs // []' <<<"${current}")
    desired_cidrs=$(jq -nc --arg ipv4 "${ipv4_block}" --arg ipv6 "${ipv6_block}" \
        '[$ipv4, $ipv6]')
    if [[ -n ${current_primary} && ${current_primary} != "${ipv4_block}" ]]; then
        echo "refusing to replace foreign primary Node PodCIDR on ${node}: ${current_primary}" >&2
        exit 1
    fi
    if [[ ${current_cidrs} != '[]' && ${current_cidrs} != "${desired_cidrs}" ]]; then
        echo "refusing to replace foreign Node PodCIDRs on ${node}: ${current_cidrs}" >&2
        exit 1
    fi
    patch=$(jq -nc --arg ipv4 "${ipv4_block}" --arg ipv6 "${ipv6_block}" \
        '{spec:{podCIDR:$ipv4,podCIDRs:[$ipv4,$ipv6]}}')
    if [[ ${dry_run} == true ]]; then
        observed=$("${kc[@]}" patch "node/${node}" --type=merge \
            --dry-run=server --patch "${patch}" -o json | jq -c '.spec.podCIDRs')
    else
        "${kc[@]}" patch "node/${node}" --type=merge --patch "${patch}" >/dev/null
        observed=$("${kc[@]}" get "node/${node}" -o json | jq -c '.spec.podCIDRs')
    fi
    if [[ ${observed} != "${desired_cidrs}" ]]; then
        echo "Node-block assignment did not read back exactly on ${node}" >&2
        exit 1
    fi
done <"${temporary_dir}/assignments.tsv"

if [[ ${dry_run} == true ]]; then
    echo "validated exact dual-stack OpenShift primary-CNI Node blocks for ${context} without mutation"
else
    echo "configured exact dual-stack OpenShift primary-CNI Node blocks for ${context}"
fi
