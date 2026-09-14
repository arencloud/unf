#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
directory=$(mktemp -d /tmp/unf-device-layout.XXXXXX)
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
jq -n '[{types:[
 {id:1,kind:"INT",name:"int",size:4,nr_bits:32},
 {id:2,kind:"INT",name:"unsigned long",size:8,nr_bits:64},
 {id:3,kind:"PTR",name:"(anon)",type_id:7},
 {id:4,kind:"PTR",name:"(anon)",type_id:10},
 {id:5,kind:"STRUCT",name:"sk_buff",size:128,members:[{name:"(anon)",type_id:6,bits_offset:0}]},
 {id:6,kind:"UNION",name:"(anon)",size:24,members:[{name:"(anon)",type_id:8,bits_offset:0}]},
 {id:7,kind:"STRUCT",name:"net_device",size:128,members:[{name:"ifindex",type_id:1,bits_offset:64},{name:"nd_net",type_id:9,bits_offset:128}]},
 {id:8,kind:"STRUCT",name:"(anon)",size:24,members:[{name:"dev",type_id:3,bits_offset:128}]},
 {id:9,kind:"TYPEDEF",name:"possible_net_t",type_id:11},
 {id:10,kind:"STRUCT",name:"net",size:64,members:[{name:"net_cookie",type_id:2,bits_offset:256}]},
 {id:11,kind:"STRUCT",name:"(anon)",size:8,members:[{name:"net",type_id:4,bits_offset:0}]}]},
 {types:[{id:12,kind:"STRUCT",name:"veth_priv",size:16,members:[{name:"peer",type_id:3,bits_offset:0}]}]}]' > "$directory/valid.json"
jq -L "$root/hack" -e 'include "device-observation-layout"; device_observation_layout ==
 {schemaVersion:1,scope:"isolated-device-readback-layout",wordBytes:8,skbDevice:16,deviceIndex:8,deviceNet:16,netCookie:32,devicePeer:128,kernelAdmitted:false}' "$directory/valid.json" >/dev/null
cases=(
  '.[0].types += [.[0].types[0]]'
  '.[0].types += [(.[0].types[4]|.id=99)]'
  '.[0].types |= map(select(.id!=3))'
  '.[0].types |= map(if .id==3 then .type_id=10 else . end)'
  '.[0].types |= map(if .id==5 then .size=32 else . end)'
  '.[0].types |= map(if .id==7 then .size=9000 else . end)'
  '.[0].types |= map(if .id==8 then .members[0].bits_offset=512 else . end)'
  '.[0].types |= map(if .id==8 then .members[0].bits_offset=129 else . end)'
  '.[0].types |= map(if .id==8 then .members[0].bitfield_size=1 else . end)'
  '.[0].types |= map(if .id==8 then .members=[] else . end)'
  '.[0].types |= map(if .id==9 then .type_id=9 else . end)'
  '.[0].types |= map(if .id==2 then .size=4 else . end)'
  '.[0].types |= map(if .id==10 then .members[0].bits_offset=512 else . end)'
  '.[1].types[0].size=4'
  '.[1].types[0].members[0].bits_offset=1'
  '.[1].types[0].members[0].type_id=4'
  '.[0].types[0].id=1.5'
  '.[0].types[0].id=0'
  '.[1].types=null'
  '.=[]'
  '.[0].types |= map(if .id==6 then .members[0].type_id=6 else . end)'
  '.[0].types |= map(if .id==6 then .members=[range(0;65)|{name:"(anon)",type_id:8,bits_offset:0}] else . end)'
)
index=0
for mutation in "${cases[@]}"; do
    index=$((index+1))
    jq "$mutation" "$directory/valid.json" > "$directory/negative-$index.json"
    if jq -L "$root/hack" -e 'include "device-observation-layout"; device_observation_layout' "$directory/negative-$index.json" > "$directory/negative-$index.out" 2> "$directory/negative-$index.err"; then
        printf 'Incorrectly accepted layout mutation %s\n' "$index" >&2; exit 1
    fi
done
# Newer split module BTF retains equivalent structures under different type IDs.
# Exercise references into those copies, not just unused same-name records.
jq '.[0].types as $base | .[1].types += ($base|map(.id+=100
    | if has("type_id") then .type_id+=100 else . end
    | if has("members") then .members|=map(.type_id+=100) else . end))
    | .[1].types[0].members[0].type_id=103' "$directory/valid.json" > "$directory/split.json"
jq -L "$root/hack" -e 'include "device-observation-layout"; device_observation_layout ==
 {schemaVersion:1,scope:"isolated-device-readback-layout",wordBytes:8,skbDevice:16,deviceIndex:8,deviceNet:16,netCookie:32,devicePeer:128,kernelAdmitted:false}' "$directory/split.json" >/dev/null
split_cases=(
  '.[1].types += [(.[1].types[]|select(.id==105)|.id=205)]'
  '.[1].types |= map(if .id==107 then .members[0].bits_offset=96 else . end)'
  '.[1].types |= map(if .id==107 then .members[1].bits_offset=192 else . end)'
  '.[1].types |= map(if .id==110 then .members[0].bits_offset=320 else . end)'
  '.[1].types |= map(if .id==108 then .members[0].bits_offset=192 else . end)'
  '.[1].types |= map(if .id==107 then .size=160 else . end)'
  '.[1].types |= map(if .id==110 then .size=80 else . end)'
  '.[1].types |= map(if .id==105 then .size=160 else . end)'
  '.[1].types |= map(if .id==103 then .type_id=110 else . end)'
  '.[1].types |= map(if .id==110 then .members=[] else . end)'
)
for mutation in "${split_cases[@]}"; do
    index=$((index+1))
    jq "$mutation" "$directory/split.json" > "$directory/negative-$index.json"
    if jq -L "$root/hack" -e 'include "device-observation-layout"; device_observation_layout' "$directory/negative-$index.json" > "$directory/negative-$index.out" 2> "$directory/negative-$index.err"; then
        printf 'Incorrectly accepted split layout mutation %s\n' "$index" >&2; exit 1
    fi
done
printf 'Device layout 2-positive/%s-negative checks passed; evidence=%s\n' "$index" "$directory"
