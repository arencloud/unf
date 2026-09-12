#!/bin/sh
# Runs inside the target Node; JSON is data, never evaluated as shell source.
set -eu
target=$1
mode=$2
case "$mode" in down|up) ;; *) exit 1 ;; esac
interface=$(printf '%s' "$target" | jq -er '.interfaceName | select(test("^unfwg[0-9a-z]{10}$"))')
if ! current=$(ip -j -details link show dev "$interface" 2>/dev/null); then
    # A retired fault target needs no restoration. Require a successful full
    # listing to distinguish absence from a failed netlink query.
    [ "$mode" = up ]
    ip -j link show | jq -e --arg name "$interface" 'all(.[]; .ifname != $name)' >/dev/null
    exit 0
fi
if [ "$mode" = up ] && printf '%s' "$current" | jq -e --argjson target "$target" \
    'length == 1 and .[0].ifindex != $target.interfaceIndex' >/dev/null; then
    # Never raise a replacement device just because its name was reused.
    exit 0
fi
printf '%s' "$current" | jq -e --argjson target "$target" '
    length == 1 and .[0].ifname == $target.interfaceName
    and .[0].ifindex == $target.interfaceIndex and .[0].ifalias == $target.ownerAlias
    and .[0].linkinfo.info_kind == "wireguard"' >/dev/null
ip link set dev "$interface" "$mode"
