#!/usr/bin/env bash
# Disposable two-ended lease experiment. No live UNF state or policy authority.
set -Eeuo pipefail
umask 077
[[ ${UNF_DEVICE_OBSERVATION_ISOLATED_CONTAINER:-} == yes && $EUID == 0 && $(uname -m) == x86_64 ]]
for command in ip tc bpftool jq socat ss timeout mount umount od grep kernel-netns-cookie device-observation-loader; do command -v "$command" >/dev/null; done
directory=$(mktemp -d /tmp/unf-device-observation.XXXXXX)
suffix=${directory##*.}
fabric=unf-dl-f-$suffix
source_ns=unf-dl-s-$suffix
target_ns=unf-dl-t-$suffix
foreign=unf-dl-x-$suffix
namespaces=()
mounted=false
receiver_pid=
stage=setup
host=target0
seen=0
redirects=0
rejected=0
delivered=0
denied=0
cleanup() {
    local result=$?
    trap - EXIT
    if [[ -n $receiver_pid ]]; then kill "$receiver_pid" 2>/dev/null || true; wait "$receiver_pid" 2>/dev/null || true; fi
    for namespace in "${namespaces[@]}"; do
        ip -n "$namespace" -j -details link show > "$directory/final-$namespace-links.json" || result=1
        ip -n "$namespace" -j addr show > "$directory/final-$namespace-addresses.json" || result=1
        ip -n "$namespace" -j route show > "$directory/final-$namespace-routes4.json" || result=1
        ip -n "$namespace" -j -6 route show > "$directory/final-$namespace-routes6.json" || result=1
    done
    if [[ $mounted == true ]]; then
        # Deliberately never dump P9LEASEPTR: it contains a private kernel address.
        bpftool -j map dump pinned "$directory/bpffs/maps/P9LEASERES" > "$directory/final-map.json" 2> "$directory/final-map.err" || result=1
    fi
    for namespace in "${namespaces[@]}"; do ip netns del "$namespace" || result=1; done
    if [[ $mounted == true ]]; then umount "$directory/bpffs" || result=1; fi
    printf 'Device lease qualification exit=%s stage=%s evidence=%s\n' "$result" "$stage" "$directory"
    exit "$result"
}
trap cleanup EXIT
for namespace in "$fabric" "$source_ns" "$target_ns" "$foreign"; do
    ip netns add "$namespace"
    namespaces+=("$namespace")
    ip -n "$namespace" link set lo up
    ip netns exec "$namespace" kernel-netns-cookie > "$directory/$namespace-cookie.txt"
    [[ $(< "$directory/$namespace-cookie.txt") =~ ^[0-9a-f]{16}$ ]]
done
[[ $(sort -u "$directory"/*-cookie.txt | wc -l) == 4 ]]
ip -n "$fabric" link add source0 index 201 address 02:44:45:00:01:01 type veth peer name eth0 index 202 netns "$source_ns" address 02:44:45:00:01:02
create_target() {
    ip -n "$fabric" link add "$host" index 301 address 02:44:46:00:01:01 type veth peer name eth0 index 302 netns "$target_ns" address 02:44:46:00:01:02
    ip -n "$fabric" link set "$host" up
    ip -n "$fabric" addr add 10.244.46.1/32 dev "$host"
    ip -n "$fabric" addr add fd46::1/128 dev "$host" nodad
    ip -n "$fabric" route replace 10.244.46.2/32 dev "$host"
    ip -n "$fabric" neigh replace 10.244.46.2 lladdr 02:44:46:00:01:02 nud permanent dev "$host"
}
create_target
ip -n "$fabric" link set source0 up
configure_source() {
    local namespace=$1
    ip -n "$namespace" link set eth0 up
    ip -n "$namespace" addr replace 10.244.45.2/32 dev eth0
    ip -n "$namespace" addr replace fd45::2/128 dev eth0 nodad
    ip -n "$namespace" route replace 10.244.46.2/32 dev eth0
    ip -n "$namespace" -6 route replace fd46::2/128 dev eth0
    ip -n "$namespace" neigh replace 10.244.46.2 lladdr 02:44:45:00:01:01 nud permanent dev eth0
    ip -n "$namespace" neigh replace fd46::2 lladdr 02:44:45:00:01:01 nud permanent dev eth0
}
configure_target() {
    local namespace=$1
    ip -n "$namespace" link set eth0 up
    ip -n "$namespace" addr replace 10.244.46.2/32 dev eth0
    ip -n "$namespace" addr replace fd46::2/128 dev eth0 nodad
    # Keep normal strict RPF defaults; declare the legitimate reverse path.
    ip -n "$namespace" route replace 10.244.45.2/32 dev eth0
    ip -n "$namespace" -6 route replace fd45::2/128 dev eth0
}
configure_source "$source_ns"
configure_target "$target_ns"
ip netns exec "$target_ns" cat /proc/sys/net/ipv4/conf/all/rp_filter /proc/sys/net/ipv4/conf/eth0/rp_filter > "$directory/receiver-rpf.txt"
stage=kernel-layout
[[ $(od -An -tx1 -N2 /sys/kernel/btf/vmlinux | tr -d ' \n') == 9feb ]]
[[ $(stat -c %s /sys/kernel/btf/vmlinux) -le 33554432 ]]
bpftool -j btf dump file /sys/kernel/btf/vmlinux format raw > "$directory/vmlinux.json"
if [[ -e /sys/kernel/btf/veth ]]; then
    [[ $(stat -c %s /sys/kernel/btf/veth) -le 4194304 ]]
    bpftool -j -B /sys/kernel/btf/vmlinux btf dump file /sys/kernel/btf/veth format raw > "$directory/veth.json"
else jq -n '{types:[]}' > "$directory/veth.json"; fi
jq -n -L /usr/local/share/unf-qualification --slurpfile vm "$directory/vmlinux.json" --slurpfile veth_types "$directory/veth.json" \
    'include "device-observation-layout"; [$vm[0],$veth_types[0]]|device_observation_layout' > "$directory/layout.json"
stage=verifier-load
install -d -m 0700 "$directory/bpffs"
mount -t bpf bpf "$directory/bpffs"
mounted=true
install -d -m 0700 "$directory/bpffs/maps"
device-observation-loader /usr/local/lib/unf/device-lease "$directory/bpffs" lease > "$directory/verifier.log" 2>&1
bpftool -j prog show pinned "$directory/bpffs/program" > "$directory/program.json"
bpftool -j prog show pinned "$directory/bpffs/seed" > "$directory/seed-program.json"
encode64() {
    local value=$1
    printf '%02x%02x%02x%02x00000000' "$((value & 255))" "$(((value >> 8) & 255))" "$(((value >> 16) & 255))" "$(((value >> 24) & 255))"
}
set_config() {
    local schema=$1 value words bytes
    jq -r --argjson schema "$schema" '[$schema,(.skbDevice/8),.deviceIndex,.deviceNet,.netCookie,.devicePeer,201,301,202,302][]' "$directory/layout.json" > "$directory/config-values.txt"
    words=
    while read -r value; do words+=$(encode64 "$value"); done < "$directory/config-values.txt"
    for namespace in "$fabric" "$source_ns" "$target_ns"; do words+=$(< "$directory/$namespace-cookie.txt"); done
    words+=000000000000000002444600010200000244460001010000
    [[ ${#words} == 256 ]]
    read -r -a bytes <<< "$(sed 's/../& /g' <<< "$words")"
    [[ ${#bytes[@]} == 128 ]]
    bpftool map update pinned "$directory/bpffs/maps/P9LEASECFG" key hex 00 00 00 00 value hex "${bytes[@]}"
}
set_config 1
ip netns exec "$fabric" bpftool map update pinned "$directory/bpffs/maps/P9LEASEDEV" key hex 00 00 00 00 value hex c9 00 00 00 00 00 00 00
read_result() {
    local name=$1
    bpftool -j map lookup pinned "$directory/bpffs/maps/P9LEASERES" key hex 00 00 00 00 > "$directory/$name-map.json"
    jq -e '.value|length==32 and all(.[];type=="string" and test("^0x[0-9a-fA-F]{2}$"))' "$directory/$name-map.json" >/dev/null
    jq '[.value|map(ltrimstr("0x")|ascii_downcase)|range(0;32;8) as $offset|.[$offset:$offset+8]|join("")]' "$directory/$name-map.json" > "$directory/$name-words.json"
}
bind_target() {
    local name=$1
    # The isolated sender is idle during explicit rebind. Production must use
    # distinct immutable incarnation entries/banks, not this serial test reset.
    bpftool map update pinned "$directory/bpffs/maps/P9LEASEPTR" key hex 00 00 00 00 value hex 00 00 00 00 00 00 00 00
    ip netns exec "$fabric" bpftool map update pinned "$directory/bpffs/maps/P9LEASEDEV" key hex 01 00 00 00 value hex 2d 01 00 00 00 00 00 00
    ip netns exec "$fabric" tc qdisc replace dev "$host" clsact
    ip netns exec "$fabric" tc filter replace dev "$host" egress pref 1 handle 1 bpf da pinned "$directory/bpffs/seed"
    printf 'seed\n' | ip netns exec "$fabric" socat -u - UDP4-SENDTO:10.244.46.2:17779
    read_result "$name-seed"
    jq -e '.[3]=="6400000000000000"' "$directory/$name-seed-words.json" >/dev/null
}
stage=initial-seed
bind_target initial
ip netns exec "$fabric" tc qdisc add dev source0 clsact
ip netns exec "$fabric" tc filter add dev source0 ingress pref 1 handle 1 bpf da pinned "$directory/bpffs/program"
probe() {
    local name=$1 family=$2 sender=$3 receiver=$4 allow=$5 requested=$6 failure=$7 target listen marker status=0 ready=false
    marker=unf-device-lease-$suffix-$name
    # A downed interface can lose its IPv6 address. Bind within the exact owned
    # receiver namespace without depending on that address surviving the fault.
    # The sender still targets the exact workload address and unique payload.
    if [[ $family == 4 ]]; then target=UDP4-SENDTO:10.244.46.2:17778; listen=UDP4-RECVFROM:17778,bind=0.0.0.0,reuseaddr
    else target='UDP6-SENDTO:[fd46::2]:17778'; listen='UDP6-RECVFROM:17778,bind=[::],ipv6only=1,reuseaddr'; fi
    timeout 3 ip netns exec "$receiver" socat -u "$listen" - > "$directory/$name-received.txt" 2> "$directory/$name-receiver.err" &
    receiver_pid=$!
    for _ in $(seq 1 30); do
        if ip netns exec "$receiver" ss -H -lun "sport = :17778" | grep -q .; then ready=true; break; fi
        sleep 0.05
    done
    [[ $ready == true ]]
    printf '%s\n' "$marker" | ip netns exec "$sender" socat -u - "$target"
    wait "$receiver_pid" || status=$?
    receiver_pid=
    printf '%s\n' "$status" > "$directory/$name-receiver-exit.txt"
    if [[ $allow == yes ]]; then
        [[ $status == 0 && $(< "$directory/$name-received.txt") == "$marker" ]]
        delivered=$((delivered+1))
    else
        [[ $status == 124 && ! -s $directory/$name-received.txt ]]
        denied=$((denied+1))
    fi
    seen=$((seen+1)); redirects=$((redirects+requested)); rejected=$((rejected+1-requested))
    read_result "$name"
    jq -e --arg seen "$(encode64 "$seen")" --arg redirects "$(encode64 "$redirects")" --arg rejected "$(encode64 "$rejected")" --arg failure "$(encode64 "$failure")" \
        '.==[$seen,$redirects,$rejected,$failure]' "$directory/$name-words.json" >/dev/null
}
pair() { local name=$1 sender=$2 receiver=$3 allow=$4 requested=$5 failure=$6; for family in 4 6; do probe "$name$family" "$family" "$sender" "$receiver" "$allow" "$requested" "$failure"; done; }
stage=baseline
pair baseline "$source_ns" "$target_ns" yes 1 0
stage=rename
ip -n "$fabric" link set "$host" name renamed0
host=renamed0
pair renamed "$source_ns" "$target_ns" yes 1 0
stage=target-peer-move
ip -n "$target_ns" link set eth0 netns "$foreign"
configure_target "$foreign"
pair target-moved "$source_ns" "$foreign" no 0 6
ip -n "$foreign" link set eth0 netns "$target_ns"
configure_target "$target_ns"
pair target-returned "$source_ns" "$target_ns" yes 1 0
stage=source-peer-move
ip -n "$source_ns" link set eth0 netns "$foreign"
configure_source "$foreign"
pair source-moved "$foreign" "$target_ns" no 0 4
ip -n "$foreign" link set eth0 netns "$source_ns"
configure_source "$source_ns"
pair source-returned "$source_ns" "$target_ns" yes 1 0
stage=peer-down
ip -n "$target_ns" -j addr show eth0 > "$directory/peer-before-down-addresses.json"
ip -n "$target_ns" link set eth0 down
ip -n "$target_ns" -j addr show eth0 > "$directory/peer-after-down-addresses.json"
pair peer-down "$source_ns" "$target_ns" no 1 0
configure_target "$target_ns"
pair peer-up "$source_ns" "$target_ns" yes 1 0
stage=host-move
ip -n "$fabric" link set "$host" netns "$foreign"
pair host-moved "$source_ns" "$target_ns" no 0 2
ip -n "$foreign" link set "$host" netns "$fabric"
ip -n "$fabric" link set "$host" up
pair host-returned-unbound "$source_ns" "$target_ns" no 0 2
ip -n "$fabric" addr replace 10.244.46.1/32 dev "$host"
ip -n "$fabric" route replace 10.244.46.2/32 dev "$host"
ip -n "$fabric" neigh replace 10.244.46.2 lladdr 02:44:46:00:01:02 nud permanent dev "$host"
bind_target returned
pair host-rebound "$source_ns" "$target_ns" yes 1 0
stage=delete-reuse
ip -n "$fabric" link del "$host"
create_target
configure_target "$target_ns"
pair replacement-unbound "$source_ns" "$target_ns" no 0 2
bind_target replacement
pair replacement-rebound "$source_ns" "$target_ns" yes 1 0
stage=invalid-config
set_config 2
pair invalid-config "$source_ns" "$target_ns" no 0 1
set_config 1
pair restored-config "$source_ns" "$target_ns" yes 1 0
[[ $seen == 30 && $redirects == 18 && $rejected == 12 && $delivered == 16 && $denied == 14 ]]
stage=verified
jq -n '{schemaVersion:1,result:"passed",scope:"isolated-two-ended-device-lease",positiveDeliveries:16,deniedDeliveries:14,requestedRedirects:18,guardRejections:12,kernelAdmitted:false,observedDelivery:false,productionAuthority:false,concurrentLifetimeVerified:false}'
