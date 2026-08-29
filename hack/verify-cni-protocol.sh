#!/usr/bin/env bash
set -euo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
binary=${UNF_CNI_BINARY:-"${project_root}/target/debug/unf-cni"}
deferred_root=$(mktemp -d)
trap 'rm -rf -- "${deferred_root}"' EXIT
config=$(jq -cn --arg directory "${deferred_root}/pending" '
    {
        cniVersion:"1.1.0",
        name:"unf-test",
        type:"unf",
        agentSocket:($directory + "/missing.sock"),
        deferredDeleteDirectory:$directory,
        ipam:{type:"unf"}
    }
')

for command in cargo jq mktemp stat; do
    command -v "${command}" >/dev/null
done

cargo build --manifest-path "${project_root}/Cargo.toml" -p unf-cni >/dev/null

version_output=$(printf '%s' '{"cniVersion":"1.1.0"}' \
    | env CNI_COMMAND=VERSION "${binary}")
jq -e '
    .cniVersion == "1.1.0"
    and .supportedVersions == ["1.0.0", "1.1.0"]
' <<<"${version_output}" >/dev/null

set +e
add_output=$(printf '%s' "${config}" | env \
    CNI_COMMAND=ADD \
    CNI_CONTAINERID=container-1 \
    CNI_NETNS=/run/netns/pod-1 \
    CNI_IFNAME=eth0 \
    "${binary}")
add_exit=$?
set -e
[[ ${add_exit} -ne 0 ]]
jq -e '
    .cniVersion == "1.1.0"
    and .code == 11
    and .msg == "Try again later"
    and (.details | contains("unf-agent"))
' <<<"${add_output}" >/dev/null

set +e
status_output=$(printf '%s' "${config}" | env CNI_COMMAND=STATUS "${binary}")
status_exit=$?
set -e
[[ ${status_exit} -ne 0 ]]
jq -e '.cniVersion == "1.1.0" and .code == 50' \
    <<<"${status_output}" >/dev/null

delete_output=$(printf '%s' "${config}" | env \
    CNI_COMMAND=DEL \
    CNI_CONTAINERID=container-1 \
    CNI_IFNAME=eth0 \
    "${binary}")
delete_exit=$?
[[ ${delete_exit} -eq 0 && -z ${delete_output} ]]
deferred_record="${deferred_root}/pending/unf-test/container-1/eth0.json"
[[ -f ${deferred_record} && ! -L ${deferred_record} ]]
[[ $(stat -c '%a' "${deferred_record}") == 600 ]]
jq -e '
    .schemaVersion == 1
    and .key == {
        network:"unf-test",
        containerId:"container-1",
        ifname:"eth0"
    }
' "${deferred_record}" >/dev/null
set +e
deferred_add=$(printf '%s' "${config}" | env \
    CNI_COMMAND=ADD \
    CNI_CONTAINERID=container-new \
    CNI_NETNS=/run/netns/pod-new \
    CNI_IFNAME=eth0 \
    "${binary}")
deferred_add_exit=$?
set -e
[[ ${deferred_add_exit} -ne 0 ]]
jq -e '.code == 11 and (.details | contains("unf-agent"))' \
    <<<"${deferred_add}" >/dev/null
[[ -f ${deferred_record} ]]

set +e
gc_output=$(printf '%s' "${config}" | env \
    CNI_COMMAND=GC \
    CNI_PATH=/opt/cni/bin \
    "${binary}")
gc_exit=$?
set -e
[[ ${gc_exit} -ne 0 ]]
jq -e '.cniVersion == "1.1.0" and .code == 11' \
    <<<"${gc_output}" >/dev/null

echo "UNF CNI protocol passed: VERSION, bounded fail-closed operations, and durable offline DEL fencing"
