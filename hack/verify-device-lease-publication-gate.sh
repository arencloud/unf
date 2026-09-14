#!/usr/bin/env bash
set -Eeuo pipefail
directory=$(mktemp -d /tmp/unf-device-publication-gate.XXXXXX)
jq -n '
def sender($f): {schemaVersion:1,role:"sender",family:$f,runToken:[range(0;16)],sent:20000,elapsedNanos:20000000000,productionAuthority:false};
def receiver($f;$n): {schemaVersion:1,role:"receiver",family:$f,runToken:[range(0;16)],received:$n,sequences:[range(0;$n)],socketDrops:0,queuedBytes:0,productionAuthority:false};
{traffic:{sent4:sender(4),sent6:sender(6),original4:receiver(4;10000),original6:receiver(6;10000),foreign4:receiver(4;0),foreign6:receiver(6;0),counters:[60040,22042,37998]},
 before:[40040,2042,37998],afterB:[20000,0,20000],dispatch:[40040,0,40],
 ledgerA:{schemaVersion:1,capacity:65536,productionAuthority:false,entries:[range(0;20000)|[.,1,1]]},
 ledgerB:{schemaVersion:1,capacity:65536,productionAuthority:false,entries:[range(20000;40000)|[.,2,2]]}}' > "$directory/valid.json"
jq -e -L hack 'include "device-lease-publication-gate"; device_lease_publication_gate|.allowGenerationDeliveries==20000 and .denyGenerationRejections==20000 and .unobservedRedirects==0' "$directory/valid.json" >/dev/null
negative=0
reject() {
    jq "$1" "$directory/valid.json" > "$directory/invalid.json"
    if jq -e -L hack 'include "device-lease-publication-gate"; device_lease_publication_gate' "$directory/invalid.json" > "$directory/rejected.out" 2> "$directory/rejected.err"; then
        printf 'Accepted invalid publication: %s\n' "$1" >&2; exit 1
    fi
    negative=$((negative+1))
}
for ledger in ledgerA ledgerB; do
    for mutation in '.schemaVersion=0' '.capacity=1' '.productionAuthority=true' '.entries=[]' '.entries[0][0]=-1' '.entries[0][0]=40000' '.entries[0][1]=0' '.entries[0][2]=0' '.entries[1]=.entries[0]' '.entries|=reverse' '.entries[0]+=[0]'; do
        reject ".$ledger |= ($mutation)"
    done
done
for mutation in '.traffic.sent4.sent-=1' '.traffic.sent6.runToken[0]=99' '.traffic.original4.socketDrops=1' '.traffic.original6.queuedBytes=1' '.traffic.original4.received-=1' '.traffic.original6.sequences[0]=20000' '.traffic.foreign4.received=1 | .traffic.foreign4.sequences=[0]' '.traffic.foreign6.received=1 | .traffic.foreign6.sequences=[0]' '.before[0]-=1' '.before[1]+=1' '.afterB[0]+=1' '.afterB[1]=1 | .afterB[2]-=1' '.traffic.counters[1]-=1 | .traffic.counters[2]+=1' '.dispatch[0]-=1' '.dispatch[1]=1' '.dispatch[2]+=1' '.ledgerB.entries[0][0]=0' '.ledgerA.entries[0][0]=39999' '.traffic.original4.sequences[0]=15000 | .traffic.original4.sequences|=sort' '.ledgerA.entries[0][2]=2' '.ledgerB.entries[0][2]=1'; do reject "$mutation"; done
printf 'Device publication gate passed: 1 positive, %s negative; evidence=%s\n' "$negative" "$directory"
