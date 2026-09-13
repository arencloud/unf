#!/usr/bin/env bash
# Disposable packet-time readback investigation. Program drops every packet.
set -Eeuo pipefail
umask 077
[[ ${UNF_DEVICE_OBSERVATION_ISOLATED_CONTAINER:-} == yes && $EUID == 0 && $(uname -m) == x86_64 ]]
for command in ip tc bpftool jq socat mount umount od kernel-netns-cookie device-observation-loader; do command -v "$command" >/dev/null; done
directory=$(mktemp -d /tmp/unf-device-observation.XXXXXX)
suffix=${directory##*.}
fabric=unf-do-f-$suffix
peer=unf-do-p-$suffix
foreign=unf-do-x-$suffix
namespaces=()
mounted=false
stage=setup
host=host0
count=0
cleanup() {
    local result=$?
    trap - EXIT
    for namespace in "${namespaces[@]}"; do
        ip -n "$namespace" -j -details link show > "$directory/final-$namespace-links.json" || result=1
    done
    if [[ $mounted == true ]]; then
        bpftool -j map dump pinned "$directory/bpffs/maps/P9DEVOBS" > "$directory/final-map.json" 2> "$directory/final-map.err" || result=1
    fi
    for namespace in "${namespaces[@]}"; do ip netns del "$namespace" || result=1; done
    if [[ $mounted == true ]]; then umount "$directory/bpffs" || result=1; fi
    printf 'Device observation qualification exit=%s stage=%s evidence=%s\n' "$result" "$stage" "$directory"
    exit "$result"
}
trap cleanup EXIT
for namespace in "$fabric" "$peer" "$foreign"; do
    ip netns add "$namespace"
    namespaces+=("$namespace")
    ip -n "$namespace" link set lo up
    ip netns exec "$namespace" kernel-netns-cookie > "$directory/$namespace-cookie.txt"
    [[ $(< "$directory/$namespace-cookie.txt") =~ ^[0-9a-f]{16}$ ]]
done
fabric_cookie=$(< "$directory/$fabric-cookie.txt")
peer_cookie=$(< "$directory/$peer-cookie.txt")
foreign_cookie=$(< "$directory/$foreign-cookie.txt")
[[ $fabric_cookie != "$peer_cookie" && $peer_cookie != "$foreign_cookie" && $fabric_cookie != "$foreign_cookie" ]]
ip -n "$fabric" link add "$host" type veth peer name eth0 netns "$peer"
ip -n "$fabric" link set "$host" up
ip -n "$fabric" addr add 10.244.44.1/32 dev "$host"
ip -n "$fabric" addr add fd44::1/128 dev "$host" nodad
ip -n "$fabric" -j link show "$host" > "$directory/host.json"
host_index=$(jq -er '.[0].ifindex' "$directory/host.json")
host_mac=$(jq -er '.[0].address' "$directory/host.json")
configure_peer() {
    local namespace=$1
    ip -n "$namespace" link set eth0 up
    ip -n "$namespace" addr replace 10.244.44.2/32 dev eth0
    ip -n "$namespace" addr replace fd44::2/128 dev eth0 nodad
    ip -n "$namespace" route replace 10.244.44.1/32 dev eth0
    ip -n "$namespace" -6 route replace fd44::1/128 dev eth0
    ip -n "$namespace" neigh replace 10.244.44.1 lladdr "$host_mac" nud permanent dev eth0
    ip -n "$namespace" neigh replace fd44::1 lladdr "$host_mac" nud permanent dev eth0
}
configure_peer "$peer"
stage=kernel-layout
[[ $(od -An -tx1 -N2 /sys/kernel/btf/vmlinux | tr -d ' \n') == 9feb ]]
[[ $(stat -c %s /sys/kernel/btf/vmlinux) -le 33554432 ]]
bpftool -j btf dump file /sys/kernel/btf/vmlinux format raw > "$directory/vmlinux.json"
if [[ -e /sys/kernel/btf/veth ]]; then
    [[ $(stat -c %s /sys/kernel/btf/veth) -le 4194304 ]]
    bpftool -j -B /sys/kernel/btf/vmlinux btf dump file /sys/kernel/btf/veth format raw > "$directory/veth.json"
else
    jq -n '{types:[]}' > "$directory/veth.json"
fi
jq -n -L /usr/local/share/unf-qualification --slurpfile vm "$directory/vmlinux.json" --slurpfile veth_types "$directory/veth.json" \
    'include "device-observation-layout"; [$vm[0],$veth_types[0]]|device_observation_layout' > "$directory/layout.json"
stage=verifier-load
install -d -m 0700 "$directory/bpffs"
mount -t bpf bpf "$directory/bpffs"
mounted=true
install -d -m 0700 "$directory/bpffs/maps"
device-observation-loader /usr/local/lib/unf/device-observation "$directory/bpffs" > "$directory/verifier.log" 2>&1
bpftool -j prog show pinned "$directory/bpffs/program" > "$directory/program.json"
encode32() {
    local value=$1
    printf '%02x %02x %02x %02x ' "$((value & 255))" "$(((value >> 8) & 255))" "$(((value >> 16) & 255))" "$(((value >> 24) & 255))"
}
encode64() { encode32 "$1" | tr -d ' '; printf '00000000'; }
config() {
    local schema=$1 value
    jq -r --argjson schema "$schema" --argjson index "$host_index" \
      '[$schema,.skbDevice,.deviceIndex,.deviceNet,.netCookie,.devicePeer,$index,0][]' "$directory/layout.json" > "$directory/config-values.txt"
    : > "$directory/config-bytes.txt"
    while read -r value; do encode32 "$value" >> "$directory/config-bytes.txt"; done < "$directory/config-values.txt"
    local bytes
    read -r -a bytes < "$directory/config-bytes.txt" || [[ ${#bytes[@]} == 32 ]]
    [[ ${#bytes[@]} == 32 ]]
    bpftool map update pinned "$directory/bpffs/maps/P9DEVCFG" key hex 00 00 00 00 value hex "${bytes[@]}"
}
config 1
ip netns exec "$fabric" tc qdisc add dev "$host" clsact
ip netns exec "$fabric" tc filter add dev "$host" ingress pref 1 handle 1 bpf da pinned "$directory/bpffs/program"
probe() {
    local name=$1 namespace=$2 family=$3 expected_cookie=$4 expected_error=$5 target protocol peer_index observed=false
    count=$((count+1))
    peer_index=$(ip -n "$namespace" -j link show eth0 | jq -er '.[0].ifindex')
    if [[ $family == 4 ]]; then target=UDP4-SENDTO:10.244.44.1:17778; protocol=2048; else target='UDP6-SENDTO:[fd44::1]:17778'; protocol=34525; fi
    printf 'unf-device-observation-%s\n' "$name" | ip netns exec "$namespace" socat -u - "$target"
    for _ in $(seq 1 30); do
        bpftool -j map lookup pinned "$directory/bpffs/maps/P9DEVOBS" key hex 00 00 00 00 > "$directory/$name-map.json"
        jq -e '.value|length==64 and all(.[];type=="string" and test("^0x[0-9a-fA-F]{2}$"))' "$directory/$name-map.json" >/dev/null
        jq '[.value|map(ltrimstr("0x")|ascii_downcase)|range(0;64;8) as $offset|.[$offset:$offset+8]|join("")]' "$directory/$name-map.json" > "$directory/$name-words.json"
        if [[ $(jq -r '.[0]' "$directory/$name-words.json") == "$(encode64 "$count")" ]]; then observed=true; break; fi
        sleep 0.1
    done
    [[ $observed == true ]]
    if [[ $expected_error == 0 ]]; then
        jq -e --arg count "$(encode64 "$count")" --arg host "$(encode64 "$host_index")" --arg fabric "$fabric_cookie" --arg peer "$(encode64 "$peer_index")" --arg cookie "$expected_cookie" --arg protocol "$(encode64 "$protocol")" \
          '.==[$count,$host,$host,$fabric,$peer,$cookie,"0000000000000000",$protocol]' "$directory/$name-words.json" >/dev/null
    else
        jq -e --arg count "$(encode64 "$count")" --arg host "$(encode64 "$host_index")" --arg protocol "$(encode64 "$protocol")" \
          '.==[$count,$host,"0000000000000000","0000000000000000","0000000000000000","0000000000000000","0100000000000000",$protocol]' "$directory/$name-words.json" >/dev/null
    fi
}
stage=baseline
probe baseline4 "$peer" 4 "$peer_cookie" 0
probe baseline6 "$peer" 6 "$peer_cookie" 0
stage=peer-move
ip -n "$peer" link set eth0 netns "$foreign"
configure_peer "$foreign"
probe moved4 "$foreign" 4 "$foreign_cookie" 0
probe moved6 "$foreign" 6 "$foreign_cookie" 0
stage=peer-return
ip -n "$foreign" link set eth0 netns "$peer"
configure_peer "$peer"
probe restored4 "$peer" 4 "$peer_cookie" 0
probe restored6 "$peer" 6 "$peer_cookie" 0
stage=host-rename
ip -n "$fabric" link set "$host" name renamed0
host=renamed0
probe renamed4 "$peer" 4 "$peer_cookie" 0
probe renamed6 "$peer" 6 "$peer_cookie" 0
stage=invalid-config
config 2
probe invalid-config "$peer" 4 "$peer_cookie" 1
config 1
probe recovered-config "$peer" 4 "$peer_cookie" 0
ip netns exec "$fabric" tc -j -s filter show dev "$host" ingress > "$directory/final-filter.json"
[[ $count == 10 ]]
stage=verified
jq -n '{schemaVersion:1,result:"passed",scope:"isolated-packet-device-namespace-readback",positiveReadbacks:9,invalidConfigRejections:1,kernelAdmitted:false,observedDelivery:false,allPacketsDropped:true}'
