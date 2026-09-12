# Input is an explicit public journal projection plus current netlink objects.
# Plans are epoch-sorted: plans[0] is NOT necessarily the active transport.
.journal as $journal |
if $journal.nodeName != $node or ($journal.activeEpoch | type) != "number"
   or $journal.activeEpoch <= 0 or ($journal.clusterId | type) != "string"
   or ($journal.clusterId | length) == 0 or ($journal.nodeUid | type) != "string"
   or ($journal.nodeUid | length) == 0 then error("no exact active Node transport") else . end |
("unf:encryption:v2:" + $journal.clusterId + ":" + $journal.nodeUid + ":") as $owner |
[.links[] | select((.ifalias // "") | startswith($owner)) | . as $link |
  [$journal.plans[] | select(.interfaceName == $link.ifname
    and .ownerAlias == $link.ifalias and .clusterId == $journal.clusterId
    and .localNodeUid == $journal.nodeUid
    and .ownerAlias == ($owner + (.epoch | tostring)))] | unique as $plans |
  if ($plans | length) != 1 then error("live link lacks exact retained plan") else $plans[0] end as $plan |
  if ($link.ifname | test("^unfwg[0-9a-z]{10}$") | not)
     or $link.linkinfo.info_kind != "wireguard"
     or ($link.ifindex | type) != "number" or $link.ifindex <= 0
     or (any($journal.transports[]; .interfaceName == $link.ifname
       and .interfaceIndex == $link.ifindex and .keyEpoch == $plan.epoch
       and (.state == "active" or .state == "draining")) | not)
  then error("live link differs from admitted transport identity")
  else {interfaceName:$link.ifname,interfaceIndex:$link.ifindex,
        ownerAlias:$link.ifalias,epoch:$plan.epoch} end] | unique as $targets |
if ($targets | length) < 1 or ($targets | length) > 2
   or (any($targets[]; .epoch == $journal.activeEpoch) | not)
then error("expected one or two owned links including the active epoch")
else $targets end
