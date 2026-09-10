#!/usr/bin/env bash
set -Eeuo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
output=${1:-${project_root}/docs/benchmarks/phase9-encryption-performance.json}
duration=${UNF_ENCRYPTION_BENCHMARK_SECONDS:-3}
ping_count=${UNF_ENCRYPTION_BENCHMARK_PINGS:-200}
ns_a="unf-perf-a-${BASHPID}"
ns_b="unf-perf-b-${BASHPID}"
veth_a="uea${BASHPID}"
veth_b="ueb${BASHPID}"
work_dir=$(mktemp -d -t unf-encryption-performance.XXXXXX)
capture_pid=
rotation_pid=

for command in awk cargo git ip iperf3 jq ping realpath sort sudo tcpdump wg; do
    command -v "${command}" >/dev/null 2>&1 || {
        echo "${command} is required for the encryption performance fixture" >&2
        exit 1
    }
done
sudo -n true >/dev/null || {
    echo 'passwordless sudo with network namespace access is required' >&2
    exit 1
}
[[ ${duration} =~ ^[1-9][0-9]*$ && ${ping_count} =~ ^[1-9][0-9]*$ ]] || {
    echo 'benchmark duration and ping count must be positive integers' >&2
    exit 1
}

cleanup() {
    if [[ -n ${rotation_pid} ]]; then
        sudo -n kill "${rotation_pid}" >/dev/null 2>&1 || true
        wait "${rotation_pid}" >/dev/null 2>&1 || true
    fi
    if [[ -n ${capture_pid} ]]; then
        sudo -n kill "${capture_pid}" >/dev/null 2>&1 || true
        wait "${capture_pid}" >/dev/null 2>&1 || true
    fi
    sudo -n ip netns exec "${ns_a}" pkill -x iperf3 >/dev/null 2>&1 || true
    sudo -n ip netns exec "${ns_b}" pkill -x iperf3 >/dev/null 2>&1 || true
    sudo -n ip netns del "${ns_a}" >/dev/null 2>&1 || true
    sudo -n ip netns del "${ns_b}" >/dev/null 2>&1 || true
    rm -rf -- "${work_dir}"
}
trap cleanup EXIT

ns() {
    local namespace=$1
    shift
    sudo -n ip netns exec "${namespace}" "$@"
}

percentile() {
    local file=$1 fraction=$2
    awk -v fraction="${fraction}" '
        { values[++count] = $1 }
        END {
            if (count == 0) exit 1
            position = int((count - 1) * fraction) + 1
            printf "%.6f", values[position]
        }
    ' "${file}"
}

measure_latency() {
    local mode=$1 family=$2 address=$3 source=$4
    local log="${work_dir}/${mode}-${family}-ping.log"
    local samples="${work_dir}/${mode}-${family}-samples.txt"
    ns "${ns_a}" ping -n -I "${source}" -c "${ping_count}" -i 0.02 -W 1 "${address}" >"${log}"
    rg -o 'time=[0-9.]+' "${log}" | cut -d= -f2 | sort -n >"${samples}"
    local received loss
    received=$(wc -l <"${samples}" | tr -d ' ')
    loss=$(awk -F', ' '/packet loss/ { gsub(/% packet loss/, "", $3); print $3 }' "${log}")
    jq -n \
        --argjson sent "${ping_count}" \
        --argjson received "${received}" \
        --argjson lossPercent "${loss}" \
        --argjson p50 "$(percentile "${samples}" 0.50)" \
        --argjson p95 "$(percentile "${samples}" 0.95)" \
        --argjson p99 "$(percentile "${samples}" 0.99)" \
        '{sent:$sent,received:$received,lossPercent:$lossPercent,p50Ms:$p50,p95Ms:$p95,p99Ms:$p99}' \
        >"${work_dir}/${mode}-${family}-latency.json"
}

measure_throughput() {
    local mode=$1 family=$2 address=$3 port=$4
    local raw="${work_dir}/${mode}-${family}-iperf.json"
    local resource="${work_dir}/${mode}-${family}-resource.txt"
    ns "${ns_a}" /usr/bin/time -v -o "${resource}" \
        iperf3 -c "${address}" -p "${port}" -P 4 -t "${duration}" -O 1 --json >"${raw}"
    sudo -n chmod 0644 "${resource}"
    local rss
    rss=$(awk -F: '/Maximum resident set size/ { gsub(/[[:space:]]/, "", $2); print $2 }' "${resource}")
    jq --argjson maxResidentSetKiB "${rss}" '{
        throughputBitsPerSecond:.end.sum_received.bits_per_second,
        retransmits:(.end.sum_sent.retransmits // 0),
        senderCpuPercent:.end.cpu_utilization_percent.host_total,
        receiverCpuPercent:.end.cpu_utilization_percent.remote_total,
        maxResidentSetKiB:$maxResidentSetKiB
    }' "${raw}" >"${work_dir}/${mode}-${family}-throughput.json"
}

mtu_probe() {
    local family=$1 address=$2 source=$3 accepted_payload=$4 rejected_payload=$5
    local accepted=false rejected=false
    if ns "${ns_a}" ping -n -I "${source}" -M do -c 1 -W 1 -s "${accepted_payload}" "${address}" >/dev/null; then
        accepted=true
    fi
    if ! ns "${ns_a}" ping -n -I "${source}" -M do -c 1 -W 1 -s "${rejected_payload}" "${address}" >/dev/null 2>&1; then
        rejected=true
    fi
    jq -n \
        --argjson acceptedPayloadBytes "${accepted_payload}" \
        --argjson rejectedPayloadBytes "${rejected_payload}" \
        --argjson accepted "${accepted}" \
        --argjson rejected "${rejected}" \
        '{acceptedPayloadBytes:$acceptedPayloadBytes,rejectedPayloadBytes:$rejectedPayloadBytes,accepted:$accepted,rejected:$rejected}'
}

sudo -n ip netns add "${ns_a}"
sudo -n ip netns add "${ns_b}"
sudo -n ip link add "${veth_a}" mtu 1500 type veth peer name "${veth_b}"
sudo -n ip link set "${veth_a}" netns "${ns_a}" name underlay0
sudo -n ip link set "${veth_b}" netns "${ns_b}" name underlay0
for namespace in "${ns_a}" "${ns_b}"; do
    sudo -n ip -n "${namespace}" link set lo up
    sudo -n ip -n "${namespace}" link set underlay0 up
done
sudo -n ip -n "${ns_a}" address add 192.0.2.1/30 dev underlay0
sudo -n ip -n "${ns_b}" address add 192.0.2.2/30 dev underlay0
sudo -n ip -n "${ns_a}" -6 address add fd00:192::1/64 dev underlay0
sudo -n ip -n "${ns_b}" -6 address add fd00:192::2/64 dev underlay0
sudo -n ip -n "${ns_a}" address add 10.250.1.2/32 dev lo
sudo -n ip -n "${ns_b}" address add 10.250.2.2/32 dev lo
sudo -n ip -n "${ns_a}" -6 address add fd00:250:1::2/128 dev lo
sudo -n ip -n "${ns_b}" -6 address add fd00:250:2::2/128 dev lo

sudo -n ip -n "${ns_a}" route add 10.250.2.2/32 via 192.0.2.2 dev underlay0
sudo -n ip -n "${ns_b}" route add 10.250.1.2/32 via 192.0.2.1 dev underlay0
sudo -n ip -n "${ns_a}" -6 route add fd00:250:2::2/128 via fd00:192::2 dev underlay0
sudo -n ip -n "${ns_b}" -6 route add fd00:250:1::2/128 via fd00:192::1 dev underlay0

ns "${ns_b}" iperf3 -s -D -B 10.250.2.2 -p 5201
ns "${ns_b}" iperf3 -s -D -B fd00:250:2::2 -p 5202
measure_latency native ipv4 10.250.2.2 10.250.1.2
sleep 0.5
measure_latency native ipv6 fd00:250:2::2 fd00:250:1::2
measure_throughput native ipv4 10.250.2.2 5201
measure_throughput native ipv6 fd00:250:2::2 5202
mtu_probe ipv4 10.250.2.2 10.250.1.2 1472 1473 >"${work_dir}/native-ipv4-mtu.json"
mtu_probe ipv6 fd00:250:2::2 fd00:250:1::2 1452 1453 >"${work_dir}/native-ipv6-mtu.json"

umask 077
for epoch in a0 b0 a1 b1; do
    wg genkey >"${work_dir}/${epoch}.key"
    wg pubkey <"${work_dir}/${epoch}.key" >"${work_dir}/${epoch}.pub"
done
pub_a0=$(<"${work_dir}/a0.pub")
pub_b0=$(<"${work_dir}/b0.pub")
for namespace in "${ns_a}" "${ns_b}"; do
    sudo -n ip -n "${namespace}" link add unfwg0 mtu 1420 type wireguard
done
ns "${ns_a}" wg set unfwg0 private-key "${work_dir}/a0.key" listen-port 51820 \
    peer "${pub_b0}" endpoint 192.0.2.2:51821 allowed-ips 10.250.2.0/24,fd00:250:2::/64
ns "${ns_b}" wg set unfwg0 private-key "${work_dir}/b0.key" listen-port 51821 \
    peer "${pub_a0}" endpoint 192.0.2.1:51820 allowed-ips 10.250.1.0/24,fd00:250:1::/64
sudo -n ip -n "${ns_a}" link set unfwg0 up
sudo -n ip -n "${ns_b}" link set unfwg0 up
sudo -n ip -n "${ns_a}" route replace 10.250.2.2/32 dev unfwg0
sudo -n ip -n "${ns_b}" route replace 10.250.1.2/32 dev unfwg0
sudo -n ip -n "${ns_a}" -6 route replace fd00:250:2::2/128 dev unfwg0
sudo -n ip -n "${ns_b}" -6 route replace fd00:250:1::2/128 dev unfwg0

handshake_start=$(date +%s%N)
ns "${ns_a}" ping -n -I 10.250.1.2 -c 1 -W 2 10.250.2.2 >/dev/null
ns "${ns_a}" ping -n -I fd00:250:1::2 -c 1 -W 2 fd00:250:2::2 >/dev/null
handshake_millis=$(( ($(date +%s%N) - handshake_start) / 1000000 ))
latest_handshake=$(ns "${ns_a}" wg show unfwg0 latest-handshakes | awk '{print $2}')
[[ ${latest_handshake:-0} -gt 0 ]] || {
    echo 'WireGuard handshake did not become observable' >&2
    exit 1
}

pcap="${work_dir}/encrypted-underlay.pcap"
ns "${ns_a}" timeout --signal=INT 20 tcpdump -U -ni underlay0 -w "${pcap}" >/dev/null 2>&1 &
capture_pid=$!
sleep 0.3
measure_latency encrypted ipv4 10.250.2.2 10.250.1.2
sleep 0.5
measure_latency encrypted ipv6 fd00:250:2::2 fd00:250:1::2
measure_throughput encrypted ipv4 10.250.2.2 5201
measure_throughput encrypted ipv6 fd00:250:2::2 5202
mtu_probe ipv4 10.250.2.2 10.250.1.2 1392 1393 >"${work_dir}/encrypted-ipv4-mtu.json"
mtu_probe ipv6 fd00:250:2::2 fd00:250:1::2 1372 1373 >"${work_dir}/encrypted-ipv6-mtu.json"
wait "${capture_pid}" || [[ $? -eq 124 ]]
capture_pid=
ciphertext_packets=$(sudo -n tcpdump -nn -r "${pcap}" 'udp and (port 51820 or port 51821)' 2>/dev/null | wc -l)
plaintext_packets=$(sudo -n tcpdump -nn -r "${pcap}" \
    'host 10.250.1.2 or host 10.250.2.2 or host fd00:250:1::2 or host fd00:250:2::2' \
    2>/dev/null | wc -l)
[[ ${ciphertext_packets} -gt 0 && ${plaintext_packets} -eq 0 ]] || {
    echo 'encrypted performance capture did not prove ciphertext-only underlay transport' >&2
    exit 1
}

pub_a1=$(<"${work_dir}/a1.pub")
pub_b1=$(<"${work_dir}/b1.pub")
for namespace in "${ns_a}" "${ns_b}"; do
    sudo -n ip -n "${namespace}" link add unfwg1 mtu 1420 type wireguard
done
ns "${ns_a}" wg set unfwg1 private-key "${work_dir}/a1.key" listen-port 51830 \
    peer "${pub_b1}" endpoint 192.0.2.2:51831 allowed-ips 10.250.2.0/24,fd00:250:2::/64
ns "${ns_b}" wg set unfwg1 private-key "${work_dir}/b1.key" listen-port 51831 \
    peer "${pub_a1}" endpoint 192.0.2.1:51830 allowed-ips 10.250.1.0/24,fd00:250:1::/64
sudo -n ip -n "${ns_a}" link set unfwg1 up
sudo -n ip -n "${ns_b}" link set unfwg1 up
# Prewarm the prepared epoch in both directions, then restore the active epoch
# before observing the later four-route cutover.
sudo -n ip -n "${ns_b}" route replace 10.250.1.2/32 dev unfwg1
sudo -n ip -n "${ns_b}" -6 route replace fd00:250:1::2/128 dev unfwg1
sudo -n ip -n "${ns_a}" route replace 10.250.2.2/32 dev unfwg1
sudo -n ip -n "${ns_a}" -6 route replace fd00:250:2::2/128 dev unfwg1
ns "${ns_a}" ping -n -I 10.250.1.2 -c 1 -W 2 10.250.2.2 >/dev/null
ns "${ns_b}" ping -n -I 10.250.2.2 -c 1 -W 2 10.250.1.2 >/dev/null
sudo -n ip -n "${ns_b}" route replace 10.250.1.2/32 dev unfwg0
sudo -n ip -n "${ns_b}" -6 route replace fd00:250:1::2/128 dev unfwg0
sudo -n ip -n "${ns_a}" route replace 10.250.2.2/32 dev unfwg0
sudo -n ip -n "${ns_a}" -6 route replace fd00:250:2::2/128 dev unfwg0

rotation_log="${work_dir}/rotation.log"
ns "${ns_a}" ping -n -I 10.250.1.2 -c 400 -i 0.01 -W 1 10.250.2.2 >"${rotation_log}" &
rotation_pid=$!
sleep 0.5
switch_start=$(date +%s%N)
sudo -n ip -n "${ns_b}" route replace 10.250.1.2/32 dev unfwg1
sudo -n ip -n "${ns_b}" -6 route replace fd00:250:1::2/128 dev unfwg1
sudo -n ip -n "${ns_a}" route replace 10.250.2.2/32 dev unfwg1
sudo -n ip -n "${ns_a}" -6 route replace fd00:250:2::2/128 dev unfwg1
switch_micros=$(( ($(date +%s%N) - switch_start) / 1000 ))
wait "${rotation_pid}"
rotation_pid=
rotation_received=$(rg -c 'bytes from' "${rotation_log}")
rotation_loss=$((400 - rotation_received))
max_missing=$(rg -o 'icmp_seq=[0-9]+' "${rotation_log}" | cut -d= -f2 |
    awk -v total=400 'BEGIN { previous=0; max=0 } { gap=$1-previous-1; if (gap>max) max=gap; previous=$1 } END { gap=total-previous; if (gap>max) max=gap; print max }')

scale_results="${work_dir}/peer-scale.jsonl"
for index in $(seq 1 128); do
    wg genkey >"${work_dir}/peer-${index}.key"
    wg pubkey <"${work_dir}/peer-${index}.key" >"${work_dir}/peer-${index}.pub"
done
for count in 1 16 64 128; do
    sudo -n ip -n "${ns_a}" link del scale0 >/dev/null 2>&1 || true
    sudo -n ip -n "${ns_a}" link add scale0 type wireguard
    ns "${ns_a}" wg set scale0 private-key "${work_dir}/a1.key"
    scale_start=$(date +%s%N)
    for index in $(seq 1 "${count}"); do
        third=$(( (index - 1) / 254 ))
        fourth=$(( (index - 1) % 254 + 1 ))
        ns "${ns_a}" wg set scale0 peer "$(<"${work_dir}/peer-${index}.pub")" \
            allowed-ips "10.200.${third}.${fourth}/32"
    done
    scale_micros=$(( ($(date +%s%N) - scale_start) / 1000 ))
    observed=$(ns "${ns_a}" wg show scale0 peers | wc -w)
    [[ ${observed} -eq ${count} ]] || exit 1
    jq -cn --argjson peers "${count}" --argjson configureAndReadbackMicros "${scale_micros}" \
        '{peers:$peers,configureAndReadbackMicros:$configureAndReadbackMicros}' >>"${scale_results}"
done

mkdir -p "$(dirname "${output}")"
jq -n \
    --arg generatedAt "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --arg revision "$(git -C "${project_root}" rev-parse HEAD)" \
    --arg kernel "$(uname -r)" \
    --arg iperfVersion "$(iperf3 --version | head -1)" \
    --argjson durationSeconds "${duration}" \
    --argjson handshakeConvergenceMs "${handshake_millis}" \
    --argjson ciphertextPackets "${ciphertext_packets}" \
    --argjson plaintextInnerPackets "${plaintext_packets}" \
    --argjson rotationSwitchMicros "${switch_micros}" \
    --argjson rotationLostSamples "${rotation_loss}" \
    --argjson rotationMaxMissingSamples "${max_missing}" \
    --slurpfile native4Latency "${work_dir}/native-ipv4-latency.json" \
    --slurpfile native6Latency "${work_dir}/native-ipv6-latency.json" \
    --slurpfile native4Throughput "${work_dir}/native-ipv4-throughput.json" \
    --slurpfile native6Throughput "${work_dir}/native-ipv6-throughput.json" \
    --slurpfile native4Mtu "${work_dir}/native-ipv4-mtu.json" \
    --slurpfile native6Mtu "${work_dir}/native-ipv6-mtu.json" \
    --slurpfile encrypted4Latency "${work_dir}/encrypted-ipv4-latency.json" \
    --slurpfile encrypted6Latency "${work_dir}/encrypted-ipv6-latency.json" \
    --slurpfile encrypted4Throughput "${work_dir}/encrypted-ipv4-throughput.json" \
    --slurpfile encrypted6Throughput "${work_dir}/encrypted-ipv6-throughput.json" \
    --slurpfile encrypted4Mtu "${work_dir}/encrypted-ipv4-mtu.json" \
    --slurpfile encrypted6Mtu "${work_dir}/encrypted-ipv6-mtu.json" \
    --slurpfile peerScale "${scale_results}" \
    '{
      schemaVersion:1,generatedAt:$generatedAt,revision:$revision,
      environment:{kernel:$kernel,iperf3:$iperfVersion,durationSeconds:$durationSeconds,topology:"two isolated namespaces over one veth pair"},
      native:{ipv4:{latency:$native4Latency[0],throughput:$native4Throughput[0],mtu:$native4Mtu[0]},ipv6:{latency:$native6Latency[0],throughput:$native6Throughput[0],mtu:$native6Mtu[0]}},
      encrypted:{provider:"Linux kernel WireGuard",mtu:1420,handshakeConvergenceMs:$handshakeConvergenceMs,capture:{ciphertextPackets:$ciphertextPackets,plaintextInnerPackets:$plaintextInnerPackets},ipv4:{latency:$encrypted4Latency[0],throughput:$encrypted4Throughput[0],mtu:$encrypted4Mtu[0]},ipv6:{latency:$encrypted6Latency[0],throughput:$encrypted6Throughput[0],mtu:$encrypted6Mtu[0]}},
      rotation:{strategy:"prewarmed parallel epoch then route replacement",samples:400,intervalMs:10,lostSamples:$rotationLostSamples,maxConsecutiveMissingSamples:$rotationMaxMissingSamples,routeSwitchMicros:$rotationSwitchMicros},
      peerScale:$peerScale,
      mapActivity:{source:"verifier-qualified TC program plus live Aya quiescent-recovery gate",newDirectFlow:{lookups:4,writes:1},newAddressBoundFlow:{lookups:5,writes:1},establishedFlow:{lookups:3,writes:1},quiescentRecoveryMutations:0,note:"counts include config, connection, decision, optional path, and transport maps; per-CPU scratch is excluded"},
      limitations:["single-host namespace microbenchmark; not a production capacity claim","CPU percentages and RSS are iperf3 process observations; kernel WireGuard memory is not isolated","Kind and OpenShift qualification independently repeat end-to-end workload measurements"]
    }' >"${output}"

jq -e '
    .native.ipv4.latency.p99Ms > 0 and .native.ipv6.latency.p99Ms > 0 and
    .encrypted.ipv4.latency.p99Ms > 0 and .encrypted.ipv6.latency.p99Ms > 0 and
    .native.ipv4.latency.lossPercent <= 1 and .native.ipv6.latency.lossPercent <= 1 and
    .encrypted.ipv4.latency.lossPercent <= 1 and .encrypted.ipv6.latency.lossPercent <= 1 and
    .native.ipv4.throughput.throughputBitsPerSecond > 0 and
    .native.ipv6.throughput.throughputBitsPerSecond > 0 and
    .encrypted.ipv4.throughput.throughputBitsPerSecond > 0 and
    .encrypted.ipv6.throughput.throughputBitsPerSecond > 0 and
    .encrypted.capture.ciphertextPackets > 0 and
    .encrypted.capture.plaintextInnerPackets == 0 and
    (.peerScale | length) == 4 and .peerScale[-1].peers == 128 and
    .native.ipv4.mtu.accepted and .native.ipv4.mtu.rejected and
    .native.ipv6.mtu.accepted and .native.ipv6.mtu.rejected and
    .encrypted.ipv4.mtu.accepted and .encrypted.ipv4.mtu.rejected and
    .encrypted.ipv6.mtu.accepted and .encrypted.ipv6.mtu.rejected
' "${output}" >/dev/null
echo "Phase 9 encryption performance fixture written to ${output}"
