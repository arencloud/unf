#!/usr/bin/env bash
set -euo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
test_id="${BASHPID}"
local_namespace="unf-rl-${test_id}"
remote_namespace="unf-rr-${test_id}"
local_uplink="ul${test_id}"
local_uplink=${local_uplink:0:15}
remote_uplink="ur${test_id}"
remote_uplink=${remote_uplink:0:15}
remote_pod="up${test_id}"
remote_pod=${remote_pod:0:15}
example="${project_root}/target/debug/examples/remote_route_lifecycle"
route_protocol=196

for command in cargo grep ip jq ping sudo; do
    command -v "${command}" >/dev/null
done
sudo -n true

cleanup() {
    sudo -n ip netns del "${remote_namespace}" >/dev/null 2>&1 || true
    sudo -n ip netns del "${local_namespace}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

cargo build --manifest-path "${project_root}/Cargo.toml" \
    -p unf-route --example remote_route_lifecycle >/dev/null

sudo -n ip netns add "${local_namespace}"
sudo -n ip netns add "${remote_namespace}"
sudo -n ip link add "${local_uplink}" type veth peer name "${remote_uplink}"
sudo -n ip link set "${local_uplink}" netns "${local_namespace}"
sudo -n ip link set "${remote_uplink}" netns "${remote_namespace}"
sudo -n ip -n "${local_namespace}" address add 192.0.2.1/24 dev "${local_uplink}"
sudo -n ip -n "${local_namespace}" -6 address add fdff::1/64 dev "${local_uplink}"
sudo -n ip -n "${remote_namespace}" address add 192.0.2.2/24 dev "${remote_uplink}"
sudo -n ip -n "${remote_namespace}" -6 address add fdff::2/64 dev "${remote_uplink}"
sudo -n ip -n "${remote_namespace}" address add 192.0.2.3/24 dev "${remote_uplink}"
sudo -n ip -n "${remote_namespace}" -6 address add fdff::3/64 dev "${remote_uplink}"
sudo -n ip -n "${local_namespace}" link set "${local_uplink}" up
sudo -n ip -n "${remote_namespace}" link set "${remote_uplink}" up
sudo -n ip -n "${remote_namespace}" link add "${remote_pod}" type dummy
sudo -n ip -n "${remote_namespace}" address add 10.43.0.2/24 dev "${remote_pod}"
sudo -n ip -n "${remote_namespace}" -6 address add fd00:43::2/64 dev "${remote_pod}"
sudo -n ip -n "${remote_namespace}" link set "${remote_pod}" up

output_interface=$(sudo -n ip -j -n "${local_namespace}" link show "${local_uplink}" \
    | jq -er '.[0].ifindex')

run_example() {
    sudo -n ip netns exec "${local_namespace}" \
        "${example}" "$1" "${output_interface}"
}

run_example rollback
[[ -z $(sudo -n ip -n "${local_namespace}" route show protocol "${route_protocol}") ]]
[[ -z $(sudo -n ip -n "${local_namespace}" -6 route show protocol "${route_protocol}") ]]

run_example reconcile
sudo -n ip -n "${local_namespace}" route show protocol "${route_protocol}" \
    | grep -q '^10.43.0.0/24 via 192.0.2.3'
sudo -n ip -n "${local_namespace}" route show protocol "${route_protocol}" \
    | grep -q '^10.44.0.0/24 via 192.0.2.2'
sudo -n ip -n "${local_namespace}" -6 route show protocol "${route_protocol}" \
    | grep -q '^fd00:43::/64 via fdff::3'
sudo -n ip -n "${local_namespace}" -6 route show protocol "${route_protocol}" \
    | grep -q '^fd00:44::/64 via fdff::2'
run_example retire
[[ -z $(sudo -n ip -n "${local_namespace}" route show protocol "${route_protocol}") ]]
[[ -z $(sudo -n ip -n "${local_namespace}" -6 route show protocol "${route_protocol}") ]]

run_example reconcile-rollback
sudo -n ip -n "${local_namespace}" route show protocol "${route_protocol}" \
    | grep -q '^10.43.0.0/24 via 192.0.2.2'
sudo -n ip -n "${local_namespace}" -6 route show protocol "${route_protocol}" \
    | grep -q '^fd00:43::/64 via fdff::2'
run_example delete

sudo -n ip -n "${local_namespace}" route add 10.43.0.0/24 \
    via 192.0.2.2 dev "${local_uplink}" protocol "${route_protocol}"
run_example rollback
sudo -n ip -n "${local_namespace}" route show protocol "${route_protocol}" \
    | grep -q '^10.43.0.0/24 via 192.0.2.2'
sudo -n ip -n "${local_namespace}" route del 10.43.0.0/24 \
    via 192.0.2.2 dev "${local_uplink}" protocol "${route_protocol}"

run_example apply
run_example readback
sudo -n ip -n "${local_namespace}" route show protocol "${route_protocol}" \
    | grep -q '^10.43.0.0/24 via 192.0.2.2'
sudo -n ip -n "${local_namespace}" -6 route show protocol "${route_protocol}" \
    | grep -q '^fd00:43::/64 via fdff::2'
for _ in {1..50}; do
    if ! sudo -n ip -n "${local_namespace}" -6 address show tentative | grep -q tentative \
        && ! sudo -n ip -n "${remote_namespace}" -6 address show tentative | grep -q tentative; then
        break
    fi
    sleep 0.1
done
sudo -n ip netns exec "${local_namespace}" ping -c 2 -W 2 10.43.0.2 >/dev/null
sudo -n ip netns exec "${local_namespace}" ping -6 -c 2 -W 2 fd00:43::2 >/dev/null
sudo -n ip -n "${local_namespace}" -6 route del fd00:43::/64 \
    via fdff::2 dev "${local_uplink}" protocol "${route_protocol}"
if run_example readback >/dev/null 2>&1; then
    echo "remote route readback accepted a missing IPv6 route" >&2
    exit 1
fi
run_example apply
run_example readback
sudo -n ip -n "${local_namespace}" -6 route show protocol "${route_protocol}" \
    | grep -q '^fd00:43::/64 via fdff::2'
run_example delete
run_example delete
[[ -z $(sudo -n ip -n "${local_namespace}" route show protocol "${route_protocol}") ]]
[[ -z $(sudo -n ip -n "${local_namespace}" -6 route show protocol "${route_protocol}") ]]

sudo -n ip -n "${local_namespace}" route add 10.43.0.0/24 \
    via 192.0.2.2 dev "${local_uplink}" metric 777
if run_example apply >/dev/null 2>&1; then
    echo "remote route apply accepted a foreign destination/table key" >&2
    exit 1
fi
if run_example delete >/dev/null 2>&1; then
    echo "remote route delete accepted a foreign destination/table key" >&2
    exit 1
fi
sudo -n ip -n "${local_namespace}" route show 10.43.0.0/24 \
    | grep -q 'metric 777'
[[ -z $(sudo -n ip -n "${local_namespace}" -6 route show protocol "${route_protocol}") ]]

echo "UNF remote native routing passed: deterministic dual-stack block routes, forwarding, replay/readback/repair, atomic snapshot replacement, stale retirement, scoped rollback, exact cleanup, and foreign-route preservation"
