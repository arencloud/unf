#!/usr/bin/env bash
# Isolated kernel primitive qualification; not a UNF policy/locality gate.
set -Eeuo pipefail
umask 077
[[ ${UNF_LOCAL_DELIVERY_ISOLATED_CONTAINER:-} == yes && $EUID == 0 ]]
for command in ip tc jq socat ss mktemp grep tee; do command -v "$command" >/dev/null; done
directory=$(mktemp -d /tmp/unf-local-delivery.XXXXXX)
suffix=${directory##*.}
fabric=unf-ld-f-$suffix
source_namespace=unf-ld-s-$suffix
destination=unf-ld-d-$suffix
replacement=unf-ld-r-$suffix
namespaces=()
servers=()
stage=setup
cleanup() {
    local result=$?
    trap - EXIT
    for pid in "${servers[@]}"; do
        kill "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
    done
    for namespace in "${namespaces[@]}"; do ip netns del "$namespace" || result=1; done
    printf 'Local delivery device qualification exit=%s stage=%s evidence=%s\n' "$result" "$stage" "$directory"
    exit "$result"
}
trap cleanup EXIT
trap 'printf "Local delivery failure: stage=%s line=%s\n" "$stage" "$LINENO" >&2' ERR
for namespace in "$fabric" "$source_namespace" "$destination" "$replacement"; do
    ip netns add "$namespace"
    namespaces+=("$namespace")
    ip -n "$namespace" link set lo up
done
fabric_tc() { ip netns exec "$fabric" tc "$@"; }
ip -n "$fabric" link add name source index 201 type veth peer name eth0 netns "$source_namespace"
ip -n "$fabric" link set source up
ip -n "$source_namespace" link set eth0 up
ip -n "$source_namespace" addr add 10.244.45.2/32 dev eth0
ip -n "$source_namespace" addr add fd45::2/128 dev eth0 nodad
ip -n "$source_namespace" route add 10.244.46.2/32 dev eth0
ip -n "$source_namespace" -6 route add fd46::2/128 dev eth0
ip -n "$source_namespace" neigh add 10.244.46.2 lladdr 02:46:00:00:00:02 nud permanent dev eth0
ip -n "$source_namespace" neigh add fd46::2 lladdr 02:46:00:00:00:02 nud permanent dev eth0

create_target() {
    local namespace=$1
    ip -n "$fabric" link add name target index 301 address 02:46:00:00:00:01 \
        type veth peer name eth0 index 302 netns "$namespace" address 02:46:00:00:00:02
    ip -n "$fabric" link set target up
    ip -n "$namespace" link set eth0 up
    ip -n "$namespace" addr add 10.244.46.2/32 dev eth0
    ip -n "$namespace" addr add fd46::2/128 dev eth0 nodad
    ip -n "$fabric" -j -details link show target > "$directory/target-$namespace.json"
    jq -e '.[0].ifindex==301 and .[0].address=="02:46:00:00:00:01"' "$directory/target-$namespace.json" >/dev/null
}
start_receivers() {
    local namespace=$1 role=$2
    ip netns exec "$namespace" socat -u UDP4-RECV:17777,reuseaddr \
        "OPEN:$directory/$role-v4.payload,creat,append" > "$directory/$role-v4.stdout" 2> "$directory/$role-v4.stderr" &
    servers+=("$!")
    ip netns exec "$namespace" socat -u UDP6-RECV:17778,reuseaddr,ipv6-v6only=1 \
        "OPEN:$directory/$role-v6.payload,creat,append" > "$directory/$role-v6.stdout" 2> "$directory/$role-v6.stderr" &
    servers+=("$!")
    for _ in $(seq 1 20); do
        for pid in "${servers[@]}"; do kill -0 "$pid"; done
        sockets=$(ip netns exec "$namespace" ss -H -lun)
        if [[ $sockets == *:17777* && $sockets == *:17778* ]]; then return; fi
        sleep 0.1
    done
    return 1
}
send_pair() {
    local token=$1
    for pid in "${servers[@]}"; do kill -0 "$pid"; done
    printf '%s-v4\n' "$token" | ip netns exec "$source_namespace" timeout 3 socat -u - UDP4-DATAGRAM:10.244.46.2:17777
    printf '%s-v6\n' "$token" | ip netns exec "$source_namespace" timeout 3 socat -u - 'UDP6-DATAGRAM:[fd46::2]:17778'
}
received() {
    local role=$1 token=$2
    for _ in $(seq 1 30); do
        for pid in "${servers[@]}"; do kill -0 "$pid"; done
        if [[ -f $directory/$role-v4.payload && -f $directory/$role-v6.payload ]] \
            && grep -Fxq "$token-v4" "$directory/$role-v4.payload" \
            && grep -Fxq "$token-v6" "$directory/$role-v6.payload"; then return; fi
        sleep 0.1
    done
    return 1
}
read_action() { fabric_tc -j -s actions get action mirred index "$1" > "$directory/$2.json"; }
create_target "$destination"
start_receivers "$destination" genuine
start_receivers "$replacement" replacement
fabric_tc qdisc add dev source clsact
fabric_tc actions add action mirred egress redirect dev target index 101
for family in ip ipv6; do
    priority=10; [[ $family != ipv6 ]] || priority=11
    fabric_tc filter add dev source ingress protocol "$family" pref "$priority" matchall \
        action mirred index 101
done
stage=positive-delivery
send_pair baseline
received genuine baseline
read_action 101 baseline-action

stage=rename-preserves-device
ip -n "$fabric" link set target name renamed
send_pair renamed
received genuine renamed
read_action 101 renamed-action

stage=down-fences-delivery
ip -n "$fabric" link set renamed down
send_pair down
sleep 0.2
read_action 101 down-action
! grep -Fq down- "$directory/genuine-v4.payload"
! grep -Fq down- "$directory/genuine-v6.payload"
ip -n "$fabric" link set renamed up
send_pair recovered
received genuine recovered

stage=delete-and-reuse-index
ip -n "$fabric" link del renamed
read_action 101 deleted-action
create_target "$replacement"
# An ordinary forwarding route intentionally points at the new foreign device.
# A missing redirect must drop, not fall back to this route.
# Configure only this private network namespace's kernel forwarding switches.
printf '1\n' | ip netns exec "$fabric" tee /proc/sys/net/ipv4/ip_forward /proc/sys/net/ipv6/conf/all/forwarding >/dev/null
ip -n "$fabric" route add 10.244.46.2/32 dev target
ip -n "$fabric" -6 route add fd46::2/128 dev target
ip -n "$fabric" neigh add 10.244.46.2 lladdr 02:46:00:00:00:02 nud permanent dev target
ip -n "$fabric" neigh add fd46::2 lladdr 02:46:00:00:00:02 nud permanent dev target
send_pair reused
sleep 0.2
read_action 101 reused-action
[[ ! -s $directory/replacement-v4.payload && ! -s $directory/replacement-v6.payload ]]

stage=explicit-fresh-device-binding
fabric_tc actions add action mirred egress redirect dev target index 102
for family in ip ipv6; do
    priority=10; [[ $family != ipv6 ]] || priority=11
    fabric_tc filter replace dev source ingress protocol "$family" pref "$priority" matchall \
        action mirred index 102
done
send_pair new-binding
received replacement new-binding
read_action 102 new-action
read_action 101 retired-action
! grep -Fq reused- "$directory/replacement-v4.payload"
! grep -Fq reused- "$directory/replacement-v6.payload"

stage=statistics-review
# Raw action and packet evidence is retained for independent strict review.
# No success is emitted until the caller's JSON gate validates target lifetime
# and positive attempt/drop counters; mere absence of payload is insufficient.
echo 'Device lifecycle traffic complete; strict action evidence review required'
