#!/bin/sh
# Read-only host compatibility check, before any qualification fault.
set -eu
selector=$1
fixture='{"journal":{"nodeName":"worker","nodeUid":"uid","clusterId":"cluster","activeEpoch":412,"plans":[{"epoch":412,"interfaceName":"unfwg00000000bg","ownerAlias":"unf:encryption:v2:cluster:uid:412","clusterId":"cluster","localNodeUid":"uid"}],"transports":[{"keyEpoch":412,"state":"active","interfaceName":"unfwg00000000bg","interfaceIndex":7}]},"links":[{"ifname":"unfwg00000000bg","ifindex":7,"ifalias":"unf:encryption:v2:cluster:uid:412","linkinfo":{"info_kind":"wireguard"}}]}'
result=$(jq -cen --arg node worker --argjson fixture "$fixture" "\$fixture | $selector")
jq -en --argjson result "$result" '$result | length == 1 and .[0].epoch == 412 and .[0].interfaceIndex == 7' >/dev/null
if jq -cen --arg node foreign --argjson fixture "$fixture" "\$fixture | $selector" >/dev/null 2>&1; then
    echo 'host selector accepted a foreign Node' >&2
    exit 1
fi
jq --version
