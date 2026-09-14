#!/usr/bin/env bash
# Disposable two-ended lease experiment. No live UNF state or policy authority.
set -Eeuo pipefail
umask 077
[[ ${UNF_DEVICE_OBSERVATION_ISOLATED_CONTAINER:-} == yes && $EUID == 0 && $(uname -m) == x86_64 ]]
for command in ip tc bpftool jq socat ss timeout mount umount od grep kernel-netns-cookie device-observation-loader device-owner-aliases device-context-seed device-lease-traffic; do command -v "$command" >/dev/null; done
directory=$(mktemp -d /tmp/unf-device-observation.XXXXXX)
suffix=${directory##*.}
fabric=unf-dl-f-$suffix
source_ns=unf-dl-s-$suffix
target_ns=unf-dl-t-$suffix
foreign=unf-dl-x-$suffix
namespaces=()
mounted=false
mounted_bank_b=false
receiver_pid=
traffic_pids=()
stage=setup
source_host=unf012345678901
host=unf012345678902
seen=0
redirects=0
rejected=0
delivered=0
denied=0
cleanup() {
    local result=$?
    trap - EXIT
    if [[ -n $receiver_pid ]]; then kill "$receiver_pid" 2>/dev/null || true; wait "$receiver_pid" 2>/dev/null || true; fi
    for pid in "${traffic_pids[@]}"; do kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; done
    for namespace in "${namespaces[@]}"; do
        ip -n "$namespace" -j -details link show > "$directory/final-$namespace-links.json" || result=1
        ip -n "$namespace" -j addr show > "$directory/final-$namespace-addresses.json" || result=1
        ip -n "$namespace" -j route show > "$directory/final-$namespace-routes4.json" || result=1
        ip -n "$namespace" -j -6 route show > "$directory/final-$namespace-routes6.json" || result=1
    done
    if [[ $mounted == true ]]; then
        # Deliberately never dump P9LEASEPTR: it contains a private kernel address.
        bpftool -j map dump pinned "$directory/bpffs/maps/P9LEASERES" > "$directory/final-map.json" 2> "$directory/final-map.err" || result=1
        if [[ -e $directory/bpffs/maps/P9LEASECON ]]; then
            bpftool -j map dump pinned "$directory/bpffs/maps/P9LEASECON" > "$directory/final-concurrent-map.json" 2> "$directory/final-concurrent-map.err" || result=1
        fi
    fi
    for namespace in "${namespaces[@]}"; do ip netns del "$namespace" || result=1; done
    if [[ $mounted_bank_b == true ]]; then umount "$directory/unf-device-observation.bank-b/bpffs" || result=1; fi
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
for side in source target; do
    if [[ $side == source ]]; then owner_host=$source_host; owner_namespace=$source_ns; octet=45
    else owner_host=$host; owner_namespace=$target_ns; octet=46; fi
    od -An -v -tu1 -N32 /dev/urandom | jq -sR 'split("\n")|join(" ")|split(" ")|map(select(length>0)|tonumber)' > "$directory/$side-nonce.json"
    jq -e 'length==32 and any(.[];.!=0)' "$directory/$side-nonce.json" >/dev/null
    jq -n --arg host "$owner_host" --arg namespace "$owner_namespace" --arg octet "$octet" --slurpfile nonce "$directory/$side-nonce.json" \
      '{spec:{key:{network:"isolated-device-lease",containerId:$namespace,ifname:"eth0"},netns:("/run/netns/"+$namespace),mtu:1500,workloadUid:("fixture-"+$namespace)},
        hostInterface:$host,phase:"ready",creationToken:$nonce[0],lease:{ipv4:{address:("10.244."+$octet+".2"),gateway:("10.244."+$octet+".1"),prefixLen:32},
          ipv6:{address:("fd"+$octet+"::2"),gateway:("fd"+$octet+"::1"),prefixLen:128}}}' > "$directory/$side-attachment.json"
    device-owner-aliases < "$directory/$side-attachment.json" > "$directory/$side-aliases.json"
    jq -e 'length==2 and all(.[];length==96 and startswith("unf:cni:v3:")) and .[0]!=.[1]' "$directory/$side-aliases.json" >/dev/null
done
aliases=("$(jq -er '.[0]' "$directory/source-aliases.json")" "$(jq -er '.[1]' "$directory/source-aliases.json")"
    "$(jq -er '.[0]' "$directory/target-aliases.json")" "$(jq -er '.[1]' "$directory/target-aliases.json")")
ip -n "$fabric" link add "$source_host" index 201 address 02:44:45:00:01:01 type veth peer name eth0 index 202 netns "$source_ns" address 02:44:45:00:01:02
ip -n "$fabric" link set "$source_host" alias "${aliases[0]}"
ip -n "$source_ns" link set eth0 alias "${aliases[1]}"
create_target() {
    ip -n "$fabric" link add "$host" index 301 address 02:44:46:00:01:01 type veth peer name eth0 index 302 netns "$target_ns" address 02:44:46:00:01:02
    ip -n "$fabric" link set "$host" alias "${aliases[2]}"
    ip -n "$target_ns" link set eth0 alias "${aliases[3]}"
    ip -n "$fabric" link set "$host" up
    ip -n "$fabric" addr add 10.244.46.1/32 dev "$host"
    ip -n "$fabric" addr add fd46::1/128 dev "$host" nodad
    ip -n "$fabric" route replace 10.244.46.2/32 dev "$host"
    ip -n "$fabric" neigh replace 10.244.46.2 lladdr 02:44:46:00:01:02 nud permanent dev "$host"
}
create_target
ip -n "$fabric" link set "$source_host" up
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
    'include "device-observation-layout"; [$vm[0],$veth_types[0]]|device_lease_layout' > "$directory/layout.json"
stage=verifier-load
install -d -m 0700 "$directory/bpffs"
mount -t bpf bpf "$directory/bpffs"
mounted=true
install -d -m 0700 "$directory/bpffs/maps"
device-observation-loader /usr/local/lib/unf/device-lease "$directory/bpffs" lease > "$directory/verifier.log" 2>&1
bpftool -j prog show pinned "$directory/bpffs/program" > "$directory/program.json"
bpftool -j prog show pinned "$directory/bpffs/seed" > "$directory/seed-program.json"
bpftool -j prog show pinned "$directory/bpffs/concurrent" > "$directory/concurrent-program.json"
encode64() {
    local value=$1
    printf '%02x%02x%02x%02x00000000' "$((value & 255))" "$(((value >> 8) & 255))" "$(((value >> 16) & 255))" "$(((value >> 24) & 255))"
}
set_config() {
    local schema=$1 target_cookie_namespace=${2:-$target_ns} value words bytes
    jq -r --argjson schema "$schema" '[$schema,(.skbDevice/8),.deviceIndex,.deviceNet,.netCookie,.devicePeer,201,301,202,302][]' "$directory/layout.json" > "$directory/config-values.txt"
    words=
    while read -r value; do words+=$(encode64 "$value"); done < "$directory/config-values.txt"
    for namespace in "$fabric" "$source_ns" "$target_cookie_namespace"; do words+=$(< "$directory/$namespace-cookie.txt"); done
    words+=000000000000000002444600010200000244460001010000
    jq -r '[.deviceFlags,.deviceAlias,.aliasData,0][]' "$directory/layout.json" > "$directory/config-owner-values.txt"
    while read -r value; do words+=$(encode64 "$value"); done < "$directory/config-owner-values.txt"
    [[ ${#words} == 320 ]]
    read -r -a bytes <<< "$(sed 's/../& /g' <<< "$words")"
    [[ ${#bytes[@]} == 160 ]]
    bpftool map update pinned "$directory/bpffs/maps/P9LEASECFG" key hex 00 00 00 00 value hex "${bytes[@]}"
}
set_config 3
for owner in 0 1 2 3; do
    hex=$(printf '%s' "${aliases[$owner]}" | od -An -v -tx1 | tr '\n' ' ')
    read -r -a bytes <<< "$hex"
    [[ ${#bytes[@]} == 96 ]]
    bytes+=(00 00 00 00 00 00 00 00)
    printf -v key '%02x' "$owner"
    bpftool map update pinned "$directory/bpffs/maps/P9LEASEOWN" key hex "$key" 00 00 00 value hex "${bytes[@]}"
done
ip netns exec "$fabric" bpftool map update pinned "$directory/bpffs/maps/P9LEASEDEV" key hex 00 00 00 00 value hex c9 00 00 00 00 00 00 00
ip netns exec "$source_ns" bpftool map update pinned "$directory/bpffs/maps/P9LEASEDEV" key hex 02 00 00 00 value hex ca 00 00 00 00 00 00 00
require_bindings() {
    local name=$1 expected=$2
    device-context-seed "$directory/bpffs" bindings > "$directory/$name-bindings.json"
    jq -e --argjson expected "$expected" '.==$expected' "$directory/$name-bindings.json" >/dev/null
}
read_result() {
    local name=$1
    bpftool -j map lookup pinned "$directory/bpffs/maps/P9LEASERES" key hex 00 00 00 00 > "$directory/$name-map.json"
    jq -e '.value|length==32 and all(.[];type=="string" and test("^0x[0-9a-fA-F]{2}$"))' "$directory/$name-map.json" >/dev/null
    jq '[.value|map(ltrimstr("0x")|ascii_downcase)|range(0;32;8) as $offset|.[$offset:$offset+8]|join("")]' "$directory/$name-map.json" > "$directory/$name-words.json"
}
seed_target() {
    local name=$1
    ip netns exec "$fabric" tc -j qdisc show dev "$host" > "$directory/$name-qdiscs-before.json"
    jq -e 'all(.[];.kind!="clsact" and .kind!="ingress")' "$directory/$name-qdiscs-before.json" >/dev/null
    ip netns exec "$fabric" device-context-seed "$directory/bpffs" 301 > "$directory/$name-context-seed.json"
    jq -e '.=={schemaVersion:1,seedMethod:"kernelTestContext",contextIfindex:301,programReturn:2,packetTransmitted:false,productionAuthority:false}' "$directory/$name-context-seed.json" >/dev/null
    ip netns exec "$fabric" tc -j qdisc show dev "$host" > "$directory/$name-qdiscs-after.json"
    jq -e 'all(.[];.kind!="clsact" and .kind!="ingress")' "$directory/$name-qdiscs-after.json" >/dev/null
    read_result "$name-seed"
    jq -e '.[3]=="6400000000000000"' "$directory/$name-seed-words.json" >/dev/null
}
bind_target() {
    local name=$1 peer_namespace=${2:-$target_ns}
    # The isolated sender is idle during explicit rebind. Production must use
    # distinct immutable incarnation entries/banks, not this serial test reset.
    bpftool map update pinned "$directory/bpffs/maps/P9LEASEPTR" key hex 00 00 00 00 value hex 00 00 00 00 00 00 00 00
    ip netns exec "$fabric" bpftool map update pinned "$directory/bpffs/maps/P9LEASEDEV" key hex 01 00 00 00 value hex 2d 01 00 00 00 00 00 00
    ip netns exec "$peer_namespace" bpftool map update pinned "$directory/bpffs/maps/P9LEASEDEV" key hex 03 00 00 00 value hex 2e 01 00 00 00 00 00 00
    seed_target "$name"
    require_bindings "$name" '[201,301,202,302]'
}
stage=initial-seed
bind_target initial
stage=seed-context-rejections
if ip netns exec "$fabric" device-context-seed "$directory/bpffs" 201 > "$directory/wrong-device-seed.out" 2> "$directory/wrong-device-seed.err"; then exit 1; fi
grep -Fq 'device context did not pass ownership checks' "$directory/wrong-device-seed.err"
read_result wrong-device-seed
jq -e '.==["0000000000000000","0000000000000000","0000000000000000","0000000000000000"]' "$directory/wrong-device-seed-words.json" >/dev/null
if ip netns exec "$foreign" device-context-seed "$directory/bpffs" 301 > "$directory/wrong-namespace-seed.out" 2> "$directory/wrong-namespace-seed.err"; then exit 1; fi
grep -Fq 'kernel device-context invocation' "$directory/wrong-namespace-seed.err"
grep -Fq 'No such device (os error 19)' "$directory/wrong-namespace-seed.err"
read_result wrong-namespace-seed
jq -e '.==["0000000000000000","0000000000000000","0000000000000000","0000000000000000"]' "$directory/wrong-namespace-seed-words.json" >/dev/null
seed_target context-recovered
ip netns exec "$fabric" tc qdisc add dev "$source_host" clsact
ip netns exec "$fabric" tc filter add dev "$source_host" ingress pref 1 handle 1 bpf da pinned "$directory/bpffs/program"
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
stage=ownership
for owner in 0 1 2 3; do
    case $owner in
        0) owner_namespace=$fabric; owner_device=$source_host; failure=4; offset=27;;
        1) owner_namespace=$source_ns; owner_device=eth0; failure=4; offset=59;;
        2) owner_namespace=$fabric; owner_device=$host; failure=6; offset=90;;
        3) owner_namespace=$target_ns; owner_device=eth0; failure=6; offset=92;;
    esac
    ip -n "$owner_namespace" link set "$owner_device" alias ''
    pair "owner-$owner-missing" "$source_ns" "$target_ns" no 0 "$failure"
    original=${aliases[$owner]}
    if [[ ${original:offset:1} == 0 ]]; then replacement=1; else replacement=0; fi
    changed=${original:0:offset}$replacement${original:offset+1}
    ip -n "$owner_namespace" link set "$owner_device" alias "$changed"
    pair "owner-$owner-mutated" "$source_ns" "$target_ns" no 0 "$failure"
    ip -n "$owner_namespace" link set "$owner_device" alias "$original"
    pair "owner-$owner-restored" "$source_ns" "$target_ns" yes 1 0
done
ip -n "$fabric" link set "$source_host" alias "${aliases[0]}x"
pair owner-truncated "$source_ns" "$target_ns" no 0 4
ip -n "$fabric" link set "$source_host" alias "${aliases[0]}"
pair owner-untruncated "$source_ns" "$target_ns" yes 1 0
stage=rename
ip -n "$fabric" link set "$host" name renamed0
host=renamed0
pair renamed "$source_ns" "$target_ns" yes 1 0
stage=target-peer-move
ip -n "$target_ns" link set eth0 netns "$foreign"
configure_target "$foreign"
require_bindings target-moved '[201,301,202,null]'
pair target-moved "$source_ns" "$foreign" no 0 2
ip -n "$foreign" link set eth0 netns "$target_ns"
configure_target "$target_ns"
require_bindings target-returned '[201,301,202,null]'
pair target-returned "$source_ns" "$target_ns" no 0 2
bind_target target-peer-rebound
pair target-peer-rebound "$source_ns" "$target_ns" yes 1 0
stage=source-peer-move
ip -n "$source_ns" link set eth0 netns "$foreign"
configure_source "$foreign"
require_bindings source-moved '[201,301,null,302]'
pair source-moved "$foreign" "$target_ns" no 0 2
ip -n "$foreign" link set eth0 netns "$source_ns"
configure_source "$source_ns"
require_bindings source-returned '[201,301,null,302]'
pair source-returned "$source_ns" "$target_ns" no 0 2
ip netns exec "$source_ns" bpftool map update pinned "$directory/bpffs/maps/P9LEASEDEV" key hex 02 00 00 00 value hex ca 00 00 00 00 00 00 00
require_bindings source-peer-rebound '[201,301,202,302]'
pair source-peer-rebound "$source_ns" "$target_ns" yes 1 0
stage=peer-down
ip -n "$target_ns" -j addr show eth0 > "$directory/peer-before-down-addresses.json"
ip -n "$target_ns" link set eth0 down
ip -n "$target_ns" -j addr show eth0 > "$directory/peer-after-down-addresses.json"
pair peer-down "$source_ns" "$target_ns" no 0 6
configure_target "$target_ns"
pair peer-up "$source_ns" "$target_ns" yes 1 0
stage=host-down
ip -n "$fabric" link set "$host" down
pair host-down "$source_ns" "$target_ns" no 0 6
ip -n "$fabric" link set "$host" up
pair host-up "$source_ns" "$target_ns" yes 1 0
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
set_config 3
pair restored-config "$source_ns" "$target_ns" yes 1 0
[[ $seen == 66 && $redirects == 28 && $rejected == 38 && $delivered == 28 && $denied == 38 ]]
stage=concurrent-target-movement
ip netns exec "$fabric" tc filter replace dev "$source_host" ingress pref 1 handle 1 bpf da pinned "$directory/bpffs/concurrent"
read_concurrent() {
    local name=$1
    bpftool -j map lookup pinned "$directory/bpffs/maps/P9LEASECON" key hex 00 00 00 00 > "$directory/$name-per-cpu.json"
    jq -L /usr/local/share/unf-qualification 'include "device-lease-concurrency-gate"; device_lease_counters' "$directory/$name-per-cpu.json" > "$directory/$name-counters.json"
}
start_receivers() {
    local name=$1 count=$2 seconds=$3 location namespace family pid ready
    run_token=$(od -An -v -tx1 -N16 /dev/urandom | tr -d ' \n')
    [[ $run_token =~ ^[0-9a-f]{32}$ && $run_token != 00000000000000000000000000000000 ]]
    printf '%s\n' "$run_token" > "$directory/$name-token.txt"
    for location in original foreign; do
        if [[ $location == original ]]; then namespace=$target_ns; else namespace=$foreign; fi
        for family in 4 6; do
            timeout 40 ip netns exec "$namespace" device-lease-traffic receive "$run_token" "$family" "$count" "$seconds" > "$directory/$name-$location$family.json" 2> "$directory/$name-$location$family.err" &
            pid=$!; traffic_pids+=("$pid"); ready=false
            for _ in $(seq 1 40); do
                if grep -Fxq "receiver-ready family=$family" "$directory/$name-$location$family.err"; then ready=true; break; fi
                kill -0 "$pid"
                sleep 0.05
            done
            [[ $ready == true ]]
        done
    done
}
start_senders() {
    local name=$1 count=$2 interval=$3 family
    for family in 4 6; do
        timeout 35 ip netns exec "$source_ns" device-lease-traffic send "$run_token" "$family" "$count" "$interval" > "$directory/$name-sent$family.json" 2> "$directory/$name-sent$family.err" &
        traffic_pids+=("$!")
    done
}
finish_traffic() {
    local name=$1 pid
    for pid in "${traffic_pids[@]}"; do wait "$pid"; done
    traffic_pids=()
    read_concurrent "$name"
    jq -n --slurpfile sent4 "$directory/$name-sent4.json" --slurpfile sent6 "$directory/$name-sent6.json" \
      --slurpfile original4 "$directory/$name-original4.json" --slurpfile original6 "$directory/$name-original6.json" \
      --slurpfile foreign4 "$directory/$name-foreign4.json" --slurpfile foreign6 "$directory/$name-foreign6.json" \
      --slurpfile counters "$directory/$name-counters.json" \
      '{sent4:$sent4[0],sent6:$sent6[0],original4:$original4[0],original6:$original6[0],foreign4:$foreign4[0],foreign6:$foreign6[0],counters:$counters[0]}' > "$directory/$name-traffic.json"
}
# Prove the foreign receiver/path works before testing its rejection. Only
# this private diagnostic configuration temporarily names the foreign cookie.
ip -n "$target_ns" link set eth0 netns "$foreign"
configure_target "$foreign"
set_config 3 "$foreign"
bind_target foreign-control "$foreign"
start_receivers control 20 3
start_senders control 20 5000
finish_traffic control
ip -n "$foreign" link set eth0 netns "$target_ns"
configure_target "$target_ns"
set_config 3
bind_target concurrent-recovered
start_receivers stress 20000 30
start_senders stress 20000 1000
sleep 1
for round in $(seq 1 10); do
    ip -n "$target_ns" link set eth0 netns "$foreign"
    configure_target "$foreign"
    ip -n "$foreign" -j -details link show eth0 > "$directory/concurrent-$round-foreign-links.json"
    require_bindings "concurrent-$round-foreign" '[201,301,202,null]'
    sleep 0.2
    ip -n "$foreign" link set eth0 netns "$target_ns"
    configure_target "$target_ns"
    ip -n "$target_ns" -j -details link show eth0 > "$directory/concurrent-$round-original-links.json"
    require_bindings "concurrent-$round-original" '[201,301,202,null]'
    sleep 0.2
done
finish_traffic stress
ip netns exec "$fabric" tc -j -s filter show dev "$source_host" ingress > "$directory/concurrent-final-tc.json"
jq -n -L /usr/local/share/unf-qualification --slurpfile control "$directory/control-traffic.json" --slurpfile stress "$directory/stress-traffic.json" \
  'include "device-lease-concurrency-gate"; {control:$control[0],stress:$stress[0]}|device_lease_concurrency_gate' > "$directory/concurrency-result.json"
jq -e -s --arg alias "${aliases[3]}" 'length==20 and all(.[];length==1 and .[0].ifindex==302 and .[0].ifalias==$alias and (.[0].flags|index("UP"))!=null)' "$directory"/concurrent-*-links.json >/dev/null
stage=post-movement-explicit-recovery
ip netns exec "$fabric" tc filter replace dev "$source_host" ingress pref 1 handle 1 bpf da pinned "$directory/bpffs/program"
pair concurrent-returned-unbound "$source_ns" "$target_ns" no 0 2
bind_target post-movement-rebound
pair concurrent-rebound "$source_ns" "$target_ns" yes 1 0
[[ $seen == 70 && $redirects == 30 && $rejected == 40 && $delivered == 30 && $denied == 40 ]]
UNF_DEVICE_LEASE_PARENT_FIXTURE=yes
source /usr/local/share/unf-qualification/verify-device-lease-publication.sh
stage=verified
jq -n --slurpfile concurrency "$directory/concurrency-result.json" --slurpfile publication "$directory/publication-result.json" '{schemaVersion:6,result:"passed",scope:"isolated-four-endpoint-device-lease",positiveDeliveries:30,deniedDeliveries:40,requestedRedirects:30,guardRejections:40,fullOwnershipAliasComparison:true,nonTransmittingContextSeeds:9,rejectedContexts:2,stickyPeerInvalidation:true,concurrency:$concurrency[0],publication:$publication[0],kernelAdmitted:false,observedDelivery:false,productionAuthority:false,concurrentLifetimeVerified:false}'
