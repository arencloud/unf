#!/usr/bin/env bash
set -Eeuo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
bash -n "$root/hack/required-reply-cni-ownership.sh" "$root/hack/verify-required-reply-transport.sh"
fixture=$(jq -n '{pod:{metadata:{uid:"11111111-1111-1111-1111-111111111111"},spec:{nodeName:"node-a"},
 status:{conditions:[{type:"Ready",status:"True"}],podIPs:[{ip:"10.1.0.2"},{ip:"fd01::2"}]}},
 journal:{schemaVersion:4,attachments:[{phase:"ready",hostInterface:"unf123456789ab",creationToken:([range(0;32)]),
 spec:{key:{network:"unf-primary",ifname:"eth0"},workloadUid:"11111111-1111-1111-1111-111111111111"},
 lease:{ipv4:{address:"10.1.0.2"},ipv6:{address:"fd01::2"}}}]}}')
valid() { jq -L "$root/hack" -e 'include "required-reply-cni-ownership"; .pod as $pod | .journal | required_reply_cni_owner_valid($pod;"node-a")' >/dev/null; }
valid <<< "$fixture"
for mutation in \
 '.journal.schemaVersion=3' '.journal.attachments=[]' \
 '.pod.spec.nodeName="node-b"' '.pod.spec.hostNetwork=true' \
 '.pod.metadata.deletionTimestamp="now"' '.pod.status.conditions=[]' \
 '.pod.metadata.uid="22222222-2222-2222-2222-222222222222"' \
 '.pod.status.podIPs[1].ip="fd01::3"' '.pod.status.podIPs|=.[0:1]' \
 '.journal.attachments[0].phase="preparing"' '.journal.attachments[0].spec.key.network="foreign"' \
 '.journal.attachments[0].hostInterface="eth0"' '.journal.attachments[0].creationToken=null' \
 '.journal.attachments[0].creationToken=[range(0;32)|0]' \
 '.journal.attachments[0].creationToken[0]=256' '.journal.attachments[0].creationToken[0]=0.5' \
 '.journal.attachments += .journal.attachments' \
 '.journal.attachments += [(.journal.attachments[0]|.spec.workloadUid="foreign"|.creationToken[0]=33)]' \
 '.journal.attachments += [(.journal.attachments[0]|.spec.workloadUid="foreign"|.lease.ipv4.address="10.1.0.3"|.lease.ipv6.address="fd01::3")]'; do
    if jq "$mutation" <<< "$fixture" | valid; then
        echo "CNI ownership validator accepted mutation: $mutation" >&2; exit 1
    fi
done
echo 'Runtime CNI ownership validator: valid incarnation and 19 negative mutations verified'
