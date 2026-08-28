#!/usr/bin/env bash
set -euo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
test_id="${BASHPID}"
host_namespace="unf-ch-${test_id}"
pod_namespace="unf-cp-${test_id}"
pod_namespace_path="/run/netns/${pod_namespace}"
state_directory=$(mktemp -d)
state_path="${state_directory}/attachments.json"
lifecycle="${project_root}/target/debug/examples/disposable_lifecycle"
veth="${project_root}/target/debug/examples/veth_lifecycle"
config='{"cniVersion":"1.1.0","name":"unf-lifecycle-test","type":"unf","mtu":1400,"ipam":{"type":"unf"}}'
route_protocol=196

for command in cargo diff grep ip jq mktemp sudo; do
    command -v "${command}" >/dev/null
done
sudo -n true

cleanup() {
    sudo -n ip netns del "${pod_namespace}" >/dev/null 2>&1 || true
    sudo -n ip netns del "${host_namespace}" >/dev/null 2>&1 || true
    rm -rf -- "${state_directory}"
}
trap cleanup EXIT

cargo build --manifest-path "${project_root}/Cargo.toml" \
    -p unf-cni --example disposable_lifecycle \
    -p unf-link --example veth_lifecycle >/dev/null

sudo -n ip netns add "${host_namespace}"
sudo -n ip netns add "${pod_namespace}"

run_cni() {
    local command=$1
    local input=$2
    shift 2
    printf '%s' "${input}" | sudo -n ip netns exec "${host_namespace}" env \
        UNF_CNI_TEST_STATE_PATH="${state_path}" \
        UNF_CNI_TEST_IPV4_BLOCK=10.244.44.0/24 \
        UNF_CNI_TEST_IPV6_BLOCK=fd44:0:0:44::/120 \
        CNI_COMMAND="${command}" \
        CNI_CONTAINERID=container-1 \
        CNI_IFNAME=eth0 \
        "$@" \
        "${lifecycle}"
}

prepare_only() {
    sudo -n ip netns exec "${host_namespace}" env \
        UNF_CNI_TEST_STATE_PATH="${state_path}" \
        UNF_CNI_TEST_IPV4_BLOCK=10.244.44.0/24 \
        UNF_CNI_TEST_IPV6_BLOCK=fd44:0:0:44::/120 \
        UNF_CNI_TEST_PREPARE_ONLY=1 \
        CNI_CONTAINERID=container-1 \
        CNI_NETNS="${pod_namespace_path}" \
        CNI_IFNAME=eth0 \
        "${lifecycle}"
}

prepare_only
sudo -n jq -e '.attachments | length == 1 and .[0].phase == "preparing"' \
    "${state_path}" >/dev/null

add_output=$(run_cni ADD "${config}" CNI_NETNS="${pod_namespace_path}")
jq -e '
    .cniVersion == "1.1.0"
    and (.interfaces | length == 2)
    and .interfaces[1].name == "eth0"
    and .interfaces[1].sandbox == $netns
    and (.ips | length == 2)
    and .ips[0].address == "10.244.44.2/32"
    and .ips[1].address == "fd44:0:0:44::2/128"
    and .routes == [
        {"dst":"0.0.0.0/0","gw":"10.244.44.1"},
        {"dst":"::/0","gw":"fd44:0:0:44::1"}
    ]
' --arg netns "${pod_namespace_path}" <<<"${add_output}" >/dev/null
host_interface=$(jq -r '.interfaces[0].name' <<<"${add_output}")
sudo -n jq -e '.attachments | length == 1 and .[0].phase == "ready"' \
    "${state_path}" >/dev/null

replay_output=$(run_cni ADD "${config}" CNI_NETNS="${pod_namespace_path}")
diff -u <(jq -S . <<<"${add_output}") <(jq -S . <<<"${replay_output}")

check_config=$(jq -cn --argjson previous "${add_output}" '
    {
        cniVersion:"1.1.0",
        name:"unf-lifecycle-test",
        type:"unf",
        mtu:1400,
        ipam:{type:"unf"},
        prevResult:$previous
    }
')
[[ -z $(run_cni CHECK "${check_config}" CNI_NETNS="${pod_namespace_path}") ]]
sudo -n ip -n "${host_namespace}" link set dev "${host_interface}" mtu 1399
set +e
drift_output=$(run_cni CHECK "${check_config}" CNI_NETNS="${pod_namespace_path}")
drift_exit=$?
set -e
[[ ${drift_exit} -ne 0 ]]
jq -e '.code == 11 and (.details | contains("read back veth"))' \
    <<<"${drift_output}" >/dev/null
sudo -n ip -n "${host_namespace}" link set dev "${host_interface}" mtu 1400

[[ -z $(run_cni DEL "${config}") ]]
[[ -z $(run_cni DEL "${config}") ]]
sudo -n jq -e '.attachments == []' "${state_path}" >/dev/null
! sudo -n ip -n "${host_namespace}" link show dev "${host_interface}" >/dev/null 2>&1
[[ -z $(sudo -n ip -n "${host_namespace}" route show protocol "${route_protocol}") ]]
[[ -z $(sudo -n ip -n "${host_namespace}" -6 route show protocol "${route_protocol}") ]]

prepare_only
host_interface=$(sudo -n jq -r '.attachments[0].hostInterface' "${state_path}")
sudo -n ip netns exec "${host_namespace}" \
    "${veth}" apply "${host_interface}" "${pod_namespace_path}"
sudo -n ip -n "${pod_namespace}" route add default dev eth0 metric 777
set +e
conflict_output=$(run_cni ADD "${config}" CNI_NETNS="${pod_namespace_path}")
conflict_exit=$?
set -e
[[ ${conflict_exit} -ne 0 ]]
jq -e '.code == 11 and (.details | contains("rollback remains pending"))' \
    <<<"${conflict_output}" >/dev/null
sudo -n jq -e '.attachments | length == 1 and .[0].phase == "aborting"' \
    "${state_path}" >/dev/null
sudo -n ip -n "${pod_namespace}" route show default | grep -q 'metric 777'
sudo -n ip -n "${host_namespace}" link show dev "${host_interface}" >/dev/null

sudo -n ip -n "${pod_namespace}" route del default dev eth0 metric 777
recovered_output=$(run_cni ADD "${config}" CNI_NETNS="${pod_namespace_path}")
jq -e '.ips[0].address == "10.244.44.2/32"' <<<"${recovered_output}" >/dev/null
sudo -n jq -e '.attachments | length == 1 and .[0].phase == "ready"' \
    "${state_path}" >/dev/null
[[ -z $(run_cni DEL "${config}") ]]
sudo -n jq -e '.attachments == []' "${state_path}" >/dev/null

prepare_only
sudo -n ip netns del "${pod_namespace}"
[[ -z $(run_cni DEL "${config}") ]]
sudo -n jq -e '.attachments == []' "${state_path}" >/dev/null

echo "UNF atomic CNI lifecycle passed: preparing recovery, ADD replay/result, CHECK drift, durable/missing-netns DEL, conflict preservation, abort retention, and recovery"
