#!/bin/sh
# Positive, read-only absence evidence. Every netlink dump must succeed;
# shell/API failures and malformed/empty documents never mean clean state.
set -eu
node=$1
links=$(ip -j -details link show)
rules4=$(ip -j -4 rule show)
rules6=$(ip -j -6 rule show)
routes4=$(ip -j -4 route show table all)
routes6=$(ip -j -6 route show table all)
jq -cen --arg node "$node" --argjson links "$links" \
    --argjson rules4 "$rules4" --argjson rules6 "$rules6" \
    --argjson routes4 "$routes4" --argjson routes6 "$routes6" '
    if ([$links,$rules4,$rules6,$routes4,$routes6] | all(.[]; type == "array"))
       and ($links | length) > 0 and all($links[]; (.ifname | type) == "string")
    then . else error("invalid netlink dump") end |
    # Runtime tables rotate through 20000..29999; protocol 0x55 also
    # identifies table-less unreachable fences and misplaced owned routes.
    def reserved: (.protocol | tostring) == "85" or
      ((.table | tonumber? // -1) as $table | $table >= 20000 and $table < 30000);
    {schemaVersion:1,node:$node,
     links:([$links[] | select((.ifname | startswith("unfwg"))
       or ((.ifalias // "") | startswith("unf:encryption:")))] | length),
     rules4:([$rules4[] | select(reserved)] | length),
     rules6:([$rules6[] | select(reserved)] | length),
     routes4:([$routes4[] | select(reserved)] | length),
     routes6:([$routes6[] | select(reserved)] | length)} |
    . + {absent:([.links,.rules4,.rules6,.routes4,.routes6] | all(.[]; . == 0))}'
