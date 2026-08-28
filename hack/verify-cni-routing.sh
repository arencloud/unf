#!/usr/bin/env bash
set -euo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
test_id="${BASHPID}"
host_namespace="unf-rh-${test_id}"
pod_namespace="unf-rp-${test_id}"
remote_namespace="unf-rr-${test_id}"
host_interface="unfrt${test_id}"
host_interface=${host_interface:0:15}
pod_namespace_path="/run/netns/${pod_namespace}"
host_uplink="uh${test_id}"
host_uplink=${host_uplink:0:15}
remote_uplink="ur${test_id}"
remote_uplink=${remote_uplink:0:15}
example="${project_root}/target/debug/examples/native_route_lifecycle"
route_protocol=196

for command in cargo grep ip jq ping sudo; do
    command -v "${command}" >/dev/null
done
sudo -n true

cleanup() {
    sudo -n ip netns del "${pod_namespace}" >/dev/null 2>&1 || true
    sudo -n ip netns del "${remote_namespace}" >/dev/null 2>&1 || true
    sudo -n ip netns del "${host_namespace}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

cargo build --manifest-path "${project_root}/Cargo.toml" \
    -p unf-route --example native_route_lifecycle >/dev/null

sudo -n ip netns add "${host_namespace}"
sudo -n ip netns add "${pod_namespace}"
sudo -n ip netns add "${remote_namespace}"

test_binary=$(cargo test --manifest-path "${project_root}/Cargo.toml" \
    -p unf-route --no-run --message-format=json 2>/dev/null \
    | jq -r 'select(
        .reason == "compiler-artifact"
        and .target.name == "unf_route"
        and .profile.test == true
        and .executable != null
    ) | .executable' \
    | tail -n 1)
[[ -n ${test_binary} && -x ${test_binary} ]]
sudo -n ip netns exec "${host_namespace}" env \
    UNF_ROUTE_TEST_NETNS="${pod_namespace_path}" \
    UNF_ROUTE_TEST_HOST_IF="${host_interface}" \
    "${test_binary}" \
    kernel::tests::privileged_failure_after_container_rolls_back_exact_state \
    --exact --ignored >/dev/null

sudo -n ip link add "${host_uplink}" type veth peer name "${remote_uplink}"
sudo -n ip link set "${host_uplink}" netns "${host_namespace}"
sudo -n ip link set "${remote_uplink}" netns "${remote_namespace}"
sudo -n ip -n "${host_namespace}" address add 192.0.2.1/24 dev "${host_uplink}"
sudo -n ip -n "${host_namespace}" -6 address add fd00:44::1/64 dev "${host_uplink}"
sudo -n ip -n "${remote_namespace}" address add 192.0.2.2/24 dev "${remote_uplink}"
sudo -n ip -n "${remote_namespace}" -6 address add fd00:44::2/64 dev "${remote_uplink}"
sudo -n ip -n "${host_namespace}" link set "${host_uplink}" mtu 1400
sudo -n ip -n "${remote_namespace}" link set "${remote_uplink}" mtu 1400
sudo -n ip -n "${host_namespace}" link set "${host_uplink}" up
sudo -n ip -n "${remote_namespace}" link set "${remote_uplink}" up
sudo -n ip netns exec "${host_namespace}" sysctl -q -w net.ipv4.ip_forward=1
sudo -n ip netns exec "${host_namespace}" sysctl -q -w net.ipv6.conf.all.forwarding=1
sudo -n ip -n "${remote_namespace}" route add 10.244.44.2/32 via 192.0.2.1
sudo -n ip -n "${remote_namespace}" -6 route add fd44:0:0:44::2/128 via fd00:44::1

run_example() {
    sudo -n ip netns exec "${host_namespace}" \
        "${example}" "$1" "${host_interface}" "${pod_namespace_path}"
}

run_example setup
run_example route-apply
run_example route-readback
sudo -n ip -n "${host_namespace}" link set dev "${host_interface}" mtu 1399
if run_example route-readback >/dev/null 2>&1; then
    echo "route readback accepted host MTU drift" >&2
    exit 1
fi
sudo -n ip -n "${host_namespace}" link set dev "${host_interface}" mtu 1400
sudo -n ip -n "${pod_namespace}" link set dev eth0 mtu 1399
if run_example route-readback >/dev/null 2>&1; then
    echo "route readback accepted container MTU drift" >&2
    exit 1
fi
sudo -n ip -n "${pod_namespace}" link set dev eth0 mtu 1400
run_example route-readback
sudo -n ip -n "${host_namespace}" route show protocol "${route_protocol}" \
    | grep -q '10.244.44.2.*dev'
sudo -n ip -n "${host_namespace}" -6 route show protocol "${route_protocol}" \
    | grep -q 'fd44:0:0:44::2.*dev'
sudo -n ip -n "${pod_namespace}" route show protocol "${route_protocol}" | grep -q '^default via 10.244.44.1'
sudo -n ip -n "${pod_namespace}" -6 route show protocol "${route_protocol}" \
    | grep -q '^default via fd44:0:0:44::1'
for _ in {1..50}; do
    if ! sudo -n ip -n "${pod_namespace}" -6 address show tentative | grep -q tentative \
        && ! sudo -n ip -n "${remote_namespace}" -6 address show tentative | grep -q tentative; then
        break
    fi
    sleep 0.1
done
if sudo -n ip -n "${pod_namespace}" -6 address show tentative | grep -q tentative \
    || sudo -n ip -n "${remote_namespace}" -6 address show tentative | grep -q tentative; then
    echo "IPv6 duplicate-address detection did not settle" >&2
    exit 1
fi
sudo -n ip netns exec "${pod_namespace}" ping -c 2 -W 2 192.0.2.2 >/dev/null
sudo -n ip netns exec "${pod_namespace}" ping -6 -c 2 -W 2 fd00:44::2 >/dev/null
sudo -n ip netns exec "${pod_namespace}" ping -c 1 -W 2 -M do -s 1372 192.0.2.2 >/dev/null
if sudo -n ip netns exec "${pod_namespace}" \
    ping -c 1 -W 1 -M do -s 1373 192.0.2.2 >/dev/null 2>&1; then
    echo "IPv4 DF probe exceeded the 1400-byte workload MTU" >&2
    exit 1
fi
sudo -n ip netns exec "${pod_namespace}" ping -c 1 -W 2 -s 1472 192.0.2.2 >/dev/null
sudo -n ip netns exec "${pod_namespace}" ping -6 -c 1 -W 2 -M do -s 1352 fd00:44::2 >/dev/null
if sudo -n ip netns exec "${pod_namespace}" \
    ping -6 -c 1 -W 1 -M do -s 1353 fd00:44::2 >/dev/null 2>&1; then
    echo "IPv6 no-fragment probe exceeded the 1400-byte workload MTU" >&2
    exit 1
fi
sudo -n ip netns exec "${pod_namespace}" \
    ping -6 -c 1 -W 2 -M dont -s 1452 fd00:44::2 >/dev/null

run_example route-delete
run_example route-delete
[[ -z $(sudo -n ip -n "${host_namespace}" route show protocol "${route_protocol}") ]]
[[ -z $(sudo -n ip -n "${host_namespace}" -6 route show protocol "${route_protocol}") ]]
[[ -z $(sudo -n ip -n "${pod_namespace}" route show protocol "${route_protocol}") ]]
[[ -z $(sudo -n ip -n "${pod_namespace}" -6 route show protocol "${route_protocol}") ]]
[[ -z $(sudo -n ip -n "${host_namespace}" neighbor show to 10.244.44.2) ]]
[[ -z $(sudo -n ip -n "${host_namespace}" -6 neighbor show to fd44:0:0:44::2) ]]
[[ -z $(sudo -n ip -n "${pod_namespace}" neighbor show to 10.244.44.1) ]]
[[ -z $(sudo -n ip -n "${pod_namespace}" -6 neighbor show to fd44:0:0:44::1) ]]

sudo -n ip -n "${pod_namespace}" route add default dev eth0 metric 777
if run_example route-apply >/dev/null 2>&1; then
    echo "route apply accepted a foreign default route" >&2
    exit 1
fi
if run_example route-delete >/dev/null 2>&1; then
    echo "route delete accepted a foreign default route" >&2
    exit 1
fi
sudo -n ip -n "${pod_namespace}" route show default | grep -q 'metric 777'
[[ -z $(sudo -n ip -n "${host_namespace}" route show protocol "${route_protocol}") ]]
[[ -z $(sudo -n ip -n "${pod_namespace}" route show protocol "${route_protocol}") ]]
sudo -n ip -n "${pod_namespace}" route del default dev eth0 metric 777

sudo -n ip -n "${pod_namespace}" neighbor add 10.244.44.1 \
    lladdr 02:de:ad:be:ef:01 nud permanent dev eth0
if run_example route-apply >/dev/null 2>&1; then
    echo "route apply accepted a foreign gateway neighbor" >&2
    exit 1
fi
if run_example route-delete >/dev/null 2>&1; then
    echo "route delete accepted a foreign gateway neighbor" >&2
    exit 1
fi
sudo -n ip -n "${pod_namespace}" neighbor show to 10.244.44.1 \
    | grep -q '02:de:ad:be:ef:01.*PERMANENT'
[[ -z $(sudo -n ip -n "${host_namespace}" route show protocol "${route_protocol}") ]]
sudo -n ip -n "${pod_namespace}" neighbor del 10.244.44.1 dev eth0
run_example link-delete

echo "UNF native routing lifecycle passed: dual-stack forwarding/MTU boundaries, fragmentation, rollback, replay/readback, exact cleanup, and foreign route/neighbor preservation"
