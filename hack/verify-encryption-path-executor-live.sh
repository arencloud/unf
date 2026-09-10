#!/usr/bin/env bash
set -Eeuo pipefail

ns_a="unf-proof-a-${BASHPID}"
ns_b="unf-proof-b-${BASHPID}"
veth_a="upa${BASHPID}"
veth_b="upb${BASHPID}"
work_dir=$(mktemp -d -t unf-proof-live.XXXXXX)
pcap_file="${work_dir}/underlay.pcap"
probe_mark=0x00ab1200
route_table=181
capture_pid=
endpoint_pids=()

for command in cargo ip realpath sysctl tcpdump timeout wg; do
    command -v "${command}" >/dev/null 2>&1 || {
        echo "${command} is required for the live path-executor gate" >&2
        exit 1
    }
done
sudo -n true >/dev/null || {
    echo "passwordless sudo with network namespace access is required" >&2
    exit 1
}

cleanup() {
    for pid in "${endpoint_pids[@]}"; do
        sudo -n kill "${pid}" >/dev/null 2>&1 || true
        wait "${pid}" >/dev/null 2>&1 || true
    done
    if [[ -n ${capture_pid} ]]; then
        sudo -n kill "${capture_pid}" >/dev/null 2>&1 || true
        wait "${capture_pid}" >/dev/null 2>&1 || true
    fi
    sudo -n ip netns del "${ns_a}" >/dev/null 2>&1 || true
    sudo -n ip netns del "${ns_b}" >/dev/null 2>&1 || true
    rm -rf -- "${work_dir}"
}
trap cleanup EXIT

cargo test -p unf-agent \
    privileged_dual_stack_path_probe_wire_engine_is_duplex_and_mark_routed \
    --no-run >/dev/null
test_binary=$(find target/debug/deps -maxdepth 1 -type f -executable \
    -name 'unf_agent-*' -printf '%T@ %p\n' | sort -nr | head -1 | cut -d' ' -f2-)
[[ -x ${test_binary} ]] || {
    echo "could not resolve the compiled unf-agent test binary" >&2
    exit 1
}
test_binary=$(realpath "${test_binary}")

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
    sudo -n ip netns exec "${ns}" sysctl -q -w net.ipv4.conf.all.rp_filter=0
    sudo -n ip netns exec "${ns}" sysctl -q -w net.ipv4.conf.default.rp_filter=0
    sudo -n ip netns exec "${ns}" sysctl -q -w net.ipv4.conf.unfwg0.rp_filter=0
done
sudo -n ip -n "${ns_a}" address add 192.0.2.1/30 dev underlay0
sudo -n ip -n "${ns_b}" address add 192.0.2.2/30 dev underlay0
sudo -n ip -n "${ns_a}" address add 10.250.1.254/32 dev unfwg0
sudo -n ip -n "${ns_a}" address add fd00:250:1::/128 dev unfwg0
sudo -n ip -n "${ns_b}" address add 10.250.2.254/32 dev unfwg0
sudo -n ip -n "${ns_b}" address add fd00:250:2::/128 dev unfwg0

sudo -n ip netns exec "${ns_a}" wg set unfwg0 \
    private-key "${work_dir}/a.key" listen-port 51820 fwmark 0xca6c \
    peer "${pub_b}" endpoint 192.0.2.2:51821 \
    allowed-ips 10.250.2.0/24,fd00:250:2::/64
sudo -n ip netns exec "${ns_b}" wg set unfwg0 \
    private-key "${work_dir}/b.key" listen-port 51821 fwmark 0xca6c \
    peer "${pub_a}" endpoint 192.0.2.1:51820 \
    allowed-ips 10.250.1.0/24,fd00:250:1::/64
for ns in "${ns_a}" "${ns_b}"; do
    sudo -n ip -n "${ns}" link set unfwg0 up
    sudo -n ip -n "${ns}" rule add priority 18100 fwmark "${probe_mark}" lookup "${route_table}"
    sudo -n ip -n "${ns}" -6 rule add priority 18100 fwmark "${probe_mark}" lookup "${route_table}"
done
sudo -n ip -n "${ns_a}" route add table "${route_table}" 10.250.2.0/24 dev unfwg0
sudo -n ip -n "${ns_a}" -6 route add table "${route_table}" fd00:250:2::/64 dev unfwg0
sudo -n ip -n "${ns_b}" route add table "${route_table}" 10.250.1.0/24 dev unfwg0
sudo -n ip -n "${ns_b}" -6 route add table "${route_table}" fd00:250:1::/64 dev unfwg0

for route_check in \
    "${ns_a}|10.250.2.254|10.250.1.254" \
    "${ns_b}|10.250.1.254|10.250.2.254" \
    "${ns_a}|fd00:250:2::|fd00:250:1::" \
    "${ns_b}|fd00:250:1::|fd00:250:2::"; do
    IFS='|' read -r namespace destination source <<<"${route_check}"
    route=$(sudo -n ip -n "${namespace}" route get "${destination}" from "${source}" mark "${probe_mark}")
    [[ ${route} == *"dev unfwg0"* ]] || {
        echo "marked proof route did not select WireGuard: ${route}" >&2
        exit 1
    }
done

run_endpoint() {
    local namespace=$1 role=$2 round=$3 expectation=${4:-success}
    local -a environment=(
        "UNF_PATH_PROBE_LIVE_ROLE=${role}"
        "UNF_PATH_PROBE_LIVE_MARK=${probe_mark}"
        "UNF_PATH_PROBE_LIVE_ROUND=${round}"
    )
    if [[ ${expectation} == timeout ]]; then
        environment+=("UNF_PATH_PROBE_EXPECT_TIMEOUT=1")
    fi
    sudo -n ip netns exec "${namespace}" env "${environment[@]}" \
        "${test_binary}" --exact \
        tests::privileged_dual_stack_path_probe_wire_engine_is_duplex_and_mark_routed \
        --ignored --nocapture
}

run_pair() {
    local round=$1
    run_endpoint "${ns_a}" a "${round}" >"${work_dir}/a-${round}.log" 2>&1 &
    endpoint_pids+=("$!")
    local pid_a=$!
    run_endpoint "${ns_b}" b "${round}" >"${work_dir}/b-${round}.log" 2>&1 &
    endpoint_pids+=("$!")
    local pid_b=$!
    wait "${pid_a}" || {
        cat "${work_dir}/a-${round}.log" >&2
        cat "${work_dir}/b-${round}.log" >&2
        sudo -n ip netns exec "${ns_a}" wg show unfwg0 >&2
        sudo -n ip netns exec "${ns_b}" wg show unfwg0 >&2
        exit 1
    }
    wait "${pid_b}" || {
        cat "${work_dir}/b-${round}.log" >&2
        exit 1
    }
    endpoint_pids=()
}

sudo -n ip netns exec "${ns_a}" timeout --signal=INT 12 \
    tcpdump -U -ni underlay0 -w "${pcap_file}" >/dev/null 2>&1 &
capture_pid=$!
sleep 0.4

run_pair 31

read -r received_before sent_before < <(
    sudo -n ip netns exec "${ns_a}" wg show unfwg0 transfer |
        awk -v peer="${pub_b}" '$1 == peer { print $2, $3 }'
)
[[ ${received_before:-0} -gt 0 && ${sent_before:-0} -gt 0 ]] || {
    echo "initial duplex nonce round did not move both WireGuard counters" >&2
    exit 1
}

# The exact route remains but authenticated peer authority disappears. The
# production socket engine must close with a bounded error, never plaintext.
sudo -n ip netns exec "${ns_a}" wg set unfwg0 peer "${pub_b}" remove
run_endpoint "${ns_a}" a 32 timeout >"${work_dir}/denied.log" 2>&1

# Restore the peer and use a distinct nonce/round byte. Both independent
# endpoints must rendezvous again without retaining reusable proof authority.
sudo -n ip netns exec "${ns_a}" wg set unfwg0 \
    peer "${pub_b}" endpoint 192.0.2.2:51821 \
    allowed-ips 10.250.2.0/24,fd00:250:2::/64
read -r recovery_received_before recovery_sent_before < <(
    sudo -n ip netns exec "${ns_a}" wg show unfwg0 transfer |
        awk -v peer="${pub_b}" '$1 == peer { print $2, $3 }'
)
run_pair 33

read -r received_after sent_after < <(
    sudo -n ip netns exec "${ns_a}" wg show unfwg0 transfer |
        awk -v peer="${pub_b}" '$1 == peer { print $2, $3 }'
)
[[ ${received_after:-0} -gt ${recovery_received_before:-0} && ${sent_after:-0} -gt ${recovery_sent_before:-0} ]] || {
    echo "fresh recovery round did not advance both WireGuard counters" >&2
    exit 1
}

wait "${capture_pid}" || [[ $? -eq 124 ]]
capture_pid=
encrypted_packets=$(sudo -n tcpdump -nn -r "${pcap_file}" 'udp and (port 51820 or port 51821)' 2>/dev/null | wc -l)
plaintext_packets=$(sudo -n tcpdump -nn -r "${pcap_file}" \
    'host 10.250.1.254 or host 10.250.2.254 or host fd00:250:1:: or host fd00:250:2::' \
    2>/dev/null | wc -l)
[[ ${encrypted_packets} -gt 0 ]] || {
    echo "no WireGuard ciphertext was observed for live nonce rounds" >&2
    exit 1
}
[[ ${plaintext_packets} -eq 0 ]] || {
    echo "a proof beacon leaked onto the underlay" >&2
    exit 1
}

echo "Phase 9.6 live executor passed: two production wire engines completed dual-stack marked nonce rounds through WireGuard, peer loss denied closed, a fresh round recovered, counters advanced, and the underlay exposed ciphertext only"
