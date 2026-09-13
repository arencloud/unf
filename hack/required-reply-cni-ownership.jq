# Current API Pod placement plus a separately read Node-local public CNI journal.
# This checks incarnation metadata, not packet-time locality admission.
def required_reply_cni_owner_valid($pod; $node):
  . as $journal |
  ($pod.metadata.uid // "") as $uid |
  ($pod.status.podIPs // [] | map(.ip) | sort) as $ips |
  [(.attachments // [])[] | select(.spec.workloadUid == $uid)] as $records |
  ($records[0] // {}) as $record |
  $journal.schemaVersion == 4 and
  ($journal.attachments | type == "array") and
  ($uid | test("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")) and
  $pod.metadata.deletionTimestamp == null and $pod.spec.nodeName == $node and
  $pod.spec.hostNetwork != true and
  any($pod.status.conditions[]?; .type == "Ready" and .status == "True") and
  ($ips | length == 2 and (unique | length) == 2) and
  ($records | length == 1) and $record.phase == "ready" and
  $record.spec.key.network == "unf-primary" and $record.spec.key.ifname == "eth0" and
  ($record.hostInterface // "" | test("^unf[0-9a-f]{11}$")) and
  ($record.creationToken | type == "array" and length == 32 and
    all(.[]; type == "number" and . == floor and . >= 0 and . <= 255) and any(.[]; . != 0)) and
  ([$record.lease.ipv4.address,$record.lease.ipv6.address] | sort) == $ips and
  ($record.lease.ipv4.address | test("^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$")) and
  ($record.lease.ipv6.address | contains(":")) and
  ([$journal.attachments[] | select(.lease.ipv4.address == $record.lease.ipv4.address or
    .lease.ipv6.address == $record.lease.ipv6.address)] | length == 1) and
  ([$journal.attachments[] | select(.creationToken == $record.creationToken)] | length == 1);
