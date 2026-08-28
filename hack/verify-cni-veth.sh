#!/usr/bin/env bash
set -euo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
test_id="${BASHPID}"
namespace="unf-veth-${test_id}"
host_interface="unfvt${test_id}"
host_interface=${host_interface:0:15}
namespace_path="/run/netns/${namespace}"
example="${project_root}/target/debug/examples/veth_lifecycle"

for command in cargo ip sudo; do
    command -v "${command}" >/dev/null
done
sudo -n true

cleanup() {
    sudo -n ip link del "${host_interface}" >/dev/null 2>&1 || true
    sudo -n ip netns del "${namespace}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

cargo build --manifest-path "${project_root}/Cargo.toml" \
    -p unf-link --example veth_lifecycle >/dev/null
sudo -n ip netns add "${namespace}"

sudo -n "${example}" apply "${host_interface}" "${namespace_path}"
sudo -n ip link set dev "${host_interface}" alias ""
sudo -n ip -n "${namespace}" link set dev eth0 alias ""
sudo -n "${example}" delete "${host_interface}" "${namespace_path}"

sudo -n "${example}" apply "${host_interface}" "${namespace_path}"
sudo -n ip -n "${namespace}" address del 10.244.44.2/32 dev eth0
sudo -n ip -n "${namespace}" address del fd44:0:0:44::2/128 dev eth0
sudo -n ip link set dev "${host_interface}" down alias ""
sudo -n ip -n "${namespace}" link set dev eth0 down alias ""
sudo -n "${example}" apply "${host_interface}" "${namespace_path}"
sudo -n "${example}" readback "${host_interface}" "${namespace_path}"
sudo -n "${example}" delete "${host_interface}" "${namespace_path}"

sudo -n "${example}" exercise "${host_interface}" "${namespace_path}"
if sudo -n ip link show dev "${host_interface}" >/dev/null 2>&1; then
    echo "owned host interface survived lifecycle deletion" >&2
    exit 1
fi
if sudo -n ip -n "${namespace}" link show dev eth0 >/dev/null 2>&1; then
    echo "owned container interface survived lifecycle deletion" >&2
    exit 1
fi

sudo -n ip link add name "${host_interface}" type dummy
if sudo -n "${example}" apply "${host_interface}" "${namespace_path}" >/dev/null 2>&1; then
    echo "apply accepted a foreign same-named host interface" >&2
    exit 1
fi
if sudo -n "${example}" delete "${host_interface}" "${namespace_path}" >/dev/null 2>&1; then
    echo "delete accepted a foreign same-named host interface" >&2
    exit 1
fi
sudo -n ip -details link show dev "${host_interface}" | grep -q ' dummy '

echo "UNF portable veth lifecycle passed: dual-stack apply, partial-state recovery, replay, readback, exact cleanup, and foreign-link preservation"
