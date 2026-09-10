#!/usr/bin/env bash
set -Eeuo pipefail

ns_a="unf-wg-a-${BASHPID}"
ns_b="unf-wg-b-${BASHPID}"
veth_a="uwa${BASHPID}"
veth_b="uwb${BASHPID}"
work_dir=$(mktemp -d -t unf-wg-live.XXXXXX)
pcap_file="${work_dir}/underlay.pcap"
capture_pid=

for command in ip wg ping tcpdump timeout; do
    command -v "${command}" >/dev/null 2>&1 || {
        echo "${command} is required for the live ciphertext gate" >&2
        exit 1
    }
done
sudo -n true >/dev/null || {
    echo "passwordless sudo with network namespace access is required" >&2
    exit 1
}

cleanup() {
    if [[ -n ${capture_pid} ]]; then
        sudo -n kill "${capture_pid}" >/dev/null 2>&1 || true
        wait "${capture_pid}" >/dev/null 2>&1 || true
    fi
    sudo -n ip netns del "${ns_a}" >/dev/null 2>&1 || true
    sudo -n ip netns del "${ns_b}" >/dev/null 2>&1 || true
    rm -rf -- "${work_dir}"
}
trap cleanup EXIT

umask 077
wg genkey >"${work_dir}/a.key"
wg pubkey <"${work_dir}/a.key" >"${work_dir}/a.pub"
wg genkey >"${work_dir}/b.key"
wg pubkey <"${work_dir}/b.key" >"${work_dir}/b.pub"
pub_a=$(<"${work_dir}/a.pub")
pub_b=$(<"${work_dir}/b.pub")

sudo -n ip netns add "${ns_a}"
sudo -n ip netns add "${ns_b}"
sudo -n ip link add "${veth_a}" type veth peer name "${veth_b}"
sudo -n ip link set "${veth_a}" netns "${ns_a}" name underlay0
sudo -n ip link set "${veth_b}" netns "${ns_b}" name underlay0

for ns in "${ns_a}" "${ns_b}"; do
    sudo -n ip -n "${ns}" link set lo up
    sudo -n ip -n "${ns}" link set underlay0 up
    sudo -n ip -n "${ns}" link add unfwg0 type wireguard
done
sudo -n ip -n "${ns_a}" address add 192.0.2.1/30 dev underlay0
sudo -n ip -n "${ns_b}" address add 192.0.2.2/30 dev underlay0
sudo -n ip -n "${ns_a}" address add 10.250.0.1/32 dev unfwg0
sudo -n ip -n "${ns_a}" address add fd00:250::1/128 dev unfwg0
sudo -n ip -n "${ns_b}" address add 10.250.0.2/32 dev unfwg0
sudo -n ip -n "${ns_b}" address add fd00:250::2/128 dev unfwg0

sudo -n ip netns exec "${ns_a}" wg set unfwg0 \
    private-key "${work_dir}/a.key" listen-port 51820 \
    peer "${pub_b}" endpoint 192.0.2.2:51821 \
    allowed-ips 10.250.0.2/32,fd00:250::2/128 persistent-keepalive 1
sudo -n ip netns exec "${ns_b}" wg set unfwg0 \
    private-key "${work_dir}/b.key" listen-port 51821 \
    peer "${pub_a}" endpoint 192.0.2.1:51820 \
    allowed-ips 10.250.0.1/32,fd00:250::1/128 persistent-keepalive 1
for ns in "${ns_a}" "${ns_b}"; do
    sudo -n ip -n "${ns}" link set unfwg0 up
done
sudo -n ip -n "${ns_a}" route add 10.250.0.2/32 dev unfwg0
sudo -n ip -n "${ns_a}" -6 route add fd00:250::2/128 dev unfwg0
sudo -n ip -n "${ns_b}" route add 10.250.0.1/32 dev unfwg0
sudo -n ip -n "${ns_b}" -6 route add fd00:250::1/128 dev unfwg0

# Observe only the underlay device. The pcap is independently inspected for
# WireGuard UDP and for accidental exposure of any inner source/destination.
sudo -n ip netns exec "${ns_a}" timeout --signal=INT 5 \
    tcpdump -U -ni underlay0 -w "${pcap_file}" >/dev/null 2>&1 &
capture_pid=$!
sleep 0.5
sudo -n ip netns exec "${ns_a}" ping -q -c 3 -W 2 -I 10.250.0.1 10.250.0.2
sudo -n ip netns exec "${ns_a}" ping -6 -q -c 3 -W 2 -I fd00:250::1 fd00:250::2
wait "${capture_pid}" || [[ $? -eq 124 ]]
capture_pid=

encrypted_packets=$(sudo -n tcpdump -nn -r "${pcap_file}" \
    'udp and (port 51820 or port 51821)' 2>/dev/null | wc -l)
plaintext_packets=$(sudo -n tcpdump -nn -r "${pcap_file}" \
    'host 10.250.0.1 or host 10.250.0.2 or host fd00:250::1 or host fd00:250::2' \
    2>/dev/null | wc -l)
[[ ${encrypted_packets} -gt 0 ]] || {
    echo "no WireGuard ciphertext was observed on the underlay" >&2
    exit 1
}
[[ ${plaintext_packets} -eq 0 ]] || {
    echo "inner workload addresses leaked onto the underlay" >&2
    exit 1
}

read -r received sent < <(
    sudo -n ip netns exec "${ns_a}" wg show unfwg0 transfer |
        awk -v peer="${pub_b}" '$1 == peer { print $2, $3 }'
)
[[ ${received:-0} -gt 0 && ${sent:-0} -gt 0 ]] || {
    echo "WireGuard transfer counters did not prove bidirectional delivery" >&2
    exit 1
}

# Removing authenticated peer authority leaves the inner route pointing only
# at WireGuard. Delivery must stop; plaintext fallback is structurally absent.
sudo -n ip netns exec "${ns_a}" wg set unfwg0 peer "${pub_b}" remove
if sudo -n ip netns exec "${ns_a}" ping -q -c 1 -W 1 -I 10.250.0.1 10.250.0.2; then
    echo "traffic survived removal of WireGuard peer authority" >&2
    exit 1
fi

# Restore the exact peer and prove retry-safe recovery for both inner families.
sudo -n ip netns exec "${ns_a}" wg set unfwg0 \
    peer "${pub_b}" endpoint 192.0.2.2:51821 \
    allowed-ips 10.250.0.2/32,fd00:250::2/128 persistent-keepalive 1
sudo -n ip netns exec "${ns_a}" ping -q -c 1 -W 2 -I 10.250.0.1 10.250.0.2
sudo -n ip netns exec "${ns_a}" ping -6 -q -c 1 -W 2 -I fd00:250::1 fd00:250::2

echo "Phase 9.5 live ciphertext passed: dual-stack inner traffic crossed WireGuard as UDP-only underlay ciphertext, peer removal denied closed, and exact recovery succeeded"
