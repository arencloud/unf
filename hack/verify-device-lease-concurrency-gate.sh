#!/usr/bin/env bash
set -Eeuo pipefail
directory=$(mktemp -d /tmp/unf-device-concurrency-gate.XXXXXX)
jq -n '
def sender($f;$n): {schemaVersion:1,role:"sender",family:$f,sent:$n,elapsedNanos:1000000000,productionAuthority:false};
def receiver($f;$n): {schemaVersion:1,role:"receiver",family:$f,received:$n,sequences:[range(0;$n)],socketDrops:0,queuedBytes:0,productionAuthority:false};
{control:{sent4:sender(4;20),sent6:sender(6;20),original4:receiver(4;0),original6:receiver(6;0),foreign4:receiver(4;20),foreign6:receiver(6;20),counters:[40,40,0]},
 stress:{sent4:sender(4;20000),sent6:sender(6;20000),original4:receiver(4;15000),original6:receiver(6;15000),foreign4:receiver(4;0),foreign6:receiver(6;0),counters:[40040,30040,10000]}}
 | .control |= with_entries(if .key=="counters" then . else .value.runToken=[range(0;16)] end)
 | .stress |= with_entries(if .key=="counters" then . else .value.runToken=[range(1;17)] end)' > "$directory/valid.json"
jq -e -L hack 'include "device-lease-concurrency-gate"; device_lease_concurrency_gate | .originalDeliveries==30000 and .unobservedRedirects==0' "$directory/valid.json" >/dev/null
jq '.stress.counters=[40040,31040,9000]' "$directory/valid.json" | jq -e -L hack 'include "device-lease-concurrency-gate"; device_lease_concurrency_gate | .unobservedRedirects==1000 and .losslessHandoffVerified==false' >/dev/null
negative=0
reject() {
    jq "$1" "$directory/valid.json" > "$directory/invalid.json"
    if jq -e -L hack 'include "device-lease-concurrency-gate"; device_lease_concurrency_gate' "$directory/invalid.json" > "$directory/rejected.out" 2> "$directory/rejected.err"; then
        printf 'Accepted invalid fixture: %s\n' "$1" >&2; exit 1
    fi
    negative=$((negative+1))
}
for phase in control stress; do
    for location in original foreign; do
        for family in 4 6; do
            field=.$phase.$location$family
            for mutation in 'del(.schemaVersion)' '.role="sender"' '.family=7' '.runToken[0]=99' '.productionAuthority=true' '.socketDrops=1' '.queuedBytes=1' '.received+=1' '.sequences=[999999]' '.sequences=[1,1]' '.sequences=[-1]' '.sequences=""'; do
                reject "$field |= ($mutation)"
            done
        done
    done
    for family in 4 6; do
        for mutation in 'del(.schemaVersion)' '.role="receiver"' '.family=7' '.sent-=1' '.elapsedNanos=0' '.elapsedNanos=25000000001' '.productionAuthority=true'; do
            reject ".$phase.sent$family |= ($mutation)"
        done
    done
done
for mutation in '.control.counters=[40,39,1]' '.stress.counters=[40039,30040,9999]' '.stress.counters=[40040,30041,10000]' '.stress.counters=[40040,29999,10041]' '.stress.counters=[40040,40040,0]' '.stress.counters=[40040,40,40000]' '.stress.foreign4.received=1 | .stress.foreign4.sequences=[0]' '.stress.foreign6.received=1 | .stress.foreign6.sequences=[0]' '.control.foreign4.received=0 | .control.foreign4.sequences=[]' '.control.original6.received=1 | .control.original6.sequences=[0]'; do reject "$mutation"; done
jq -n '{values:[{cpu:0,value:(["0x01"]+([range(0;23)]|map("0x00")))}]}' > "$directory/counters.json"
jq -e -L hack 'include "device-lease-concurrency-gate"; device_lease_counters==[1,0,0]' "$directory/counters.json" >/dev/null
for mutation in '.values=[]' '.values+=.values' '.values[0].cpu=-1' '.values[0].value[4]="0x01"' '.values[0].value[0]="0xGG"' '.values[0].value=[]' '.values[0].value[3]="0xff"'; do
    jq "$mutation" "$directory/counters.json" > "$directory/invalid-counters.json"
    if jq -e -L hack 'include "device-lease-concurrency-gate"; device_lease_counters' "$directory/invalid-counters.json" > "$directory/rejected.out" 2> "$directory/rejected.err"; then exit 1; fi
    negative=$((negative+1))
done
printf 'Device concurrency gate passed: 3 positive, %s negative; evidence=%s\n' "$negative" "$directory"
