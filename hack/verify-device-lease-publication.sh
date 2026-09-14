#!/usr/bin/env bash
# Sourced only after the complete owned four-endpoint fixture has passed.
[[ ${UNF_DEVICE_LEASE_PARENT_FIXTURE:-} == yes && $directory =~ ^/tmp/unf-device-observation\.[a-zA-Z0-9]{6}$ && $seen == 70 ]]
stage=generation-publication
bank_a=$directory/bpffs
bank_b=$directory/unf-device-observation.bank-b/bpffs
# bpffs reserves dotted entry names. Keep the guarded diagnostic parent on
# tmpfs and mount a second owned bpffs, never a dotted directory inside A.
install -d -m 0700 "$bank_b"
mount -t bpf bpf "$bank_b"
mounted_bank_b=true
install -d -m 0700 "$bank_b/maps"
device-observation-loader /usr/local/lib/unf/device-lease "$bank_b" lease > "$directory/bank-b-verifier.log" 2>&1
copy_public_row() {
    local map=$1 key=$2 width=$3 bytes
    case $map in P9LEASECFG|P9LEASEOWN) ;; *) return 1;; esac
    bpftool -j map lookup pinned "$bank_a/maps/$map" key hex "$key" 00 00 00 > "$directory/bank-copy-$map-$key.json"
    jq -e --argjson width "$width" '(.value|type)=="array" and (.value|length)==$width and all(.value[];test("^0x[0-9a-fA-F]{2}$"))' "$directory/bank-copy-$map-$key.json" >/dev/null
    read -r -a bytes <<< "$(jq -r '.value|map(ltrimstr("0x"))|join(" ")' "$directory/bank-copy-$map-$key.json")"
    bpftool map update pinned "$bank_b/maps/$map" key hex "$key" 00 00 00 value hex "${bytes[@]}"
}
copy_public_row P9LEASECFG 00 160
for key in 00 01 02 03; do copy_public_row P9LEASEOWN "$key" 104; done
ip netns exec "$fabric" bpftool map update pinned "$bank_b/maps/P9LEASEDEV" key hex 00 00 00 00 value hex c9 00 00 00 00 00 00 00
ip netns exec "$fabric" bpftool map update pinned "$bank_b/maps/P9LEASEDEV" key hex 01 00 00 00 value hex 2d 01 00 00 00 00 00 00
ip netns exec "$source_ns" bpftool map update pinned "$bank_b/maps/P9LEASEDEV" key hex 02 00 00 00 value hex ca 00 00 00 00 00 00 00
ip netns exec "$target_ns" bpftool map update pinned "$bank_b/maps/P9LEASEDEV" key hex 03 00 00 00 value hex 2e 01 00 00 00 00 00 00
ip netns exec "$fabric" device-context-seed "$bank_b" 301 > "$directory/bank-b-context-seed.json"
jq -e '.=={schemaVersion:1,seedMethod:"kernelTestContext",contextIfindex:301,programReturn:2,packetTransmitted:false,productionAuthority:false}' "$directory/bank-b-context-seed.json" >/dev/null
device-context-seed "$bank_b" bindings > "$directory/bank-b-initial-bindings.json"
jq -e '.==[201,301,202,302]' "$directory/bank-b-initial-bindings.json" >/dev/null
# B is an intentionally denied ownership generation, not a production policy.
# Seed with valid target ownership, then make only its expected source owner
# differ. A's ownership table must remain unchanged throughout publication.
read -r -a bytes <<< "$(jq -r '.value|map(ltrimstr("0x"))|join(" ")' "$directory/bank-copy-P9LEASEOWN-00.json")"
[[ ${bytes[0]} == 75 ]]
bytes[0]=74
bpftool map update pinned "$bank_b/maps/P9LEASEOWN" key hex 00 00 00 00 value hex "${bytes[@]}"
bpftool map update pinned "$bank_a/maps/P9LEASETAG" key hex 00 00 00 00 value hex 01 00 00 00
bpftool map update pinned "$bank_b/maps/P9LEASETAG" key hex 00 00 00 00 value hex 02 00 00 00
if device-context-seed "$bank_a" publish "$bank_b" > "$directory/unsealed-publish.out" 2> "$directory/unsealed-publish.err"; then exit 1; fi
grep -Fq 'bank is not sealed' "$directory/unsealed-publish.err"
for bank in "$bank_a" "$bank_b"; do
    for map in P9LEASECFG P9LEASEPTR P9LEASEDEV P9LEASEOWN P9LEASETAG; do
        bpftool map freeze pinned "$bank/maps/$map"
    done
    # Drop the only diagnostic program that can seed a cached pointer.
    # The exact pin was created by this fixture's loader; no live pins touched.
    [[ -e $bank/seed ]]
    unlink "$bank/seed"
done
for label in a b; do
    if [[ $label == a ]]; then bank=$bank_a; else bank=$bank_b; fi
    if ip netns exec "$fabric" bpftool map update pinned "$bank/maps/P9LEASEDEV" key hex 01 00 00 00 value hex 2d 01 00 00 00 00 00 00 > "$directory/bank-$label-frozen-update.out" 2> "$directory/bank-$label-frozen-update.err"; then exit 1; fi
    grep -Fq 'Operation not permitted' "$directory/bank-$label-frozen-update.err"
done
read_concurrent bank-a-before
bpftool -j prog show pinned "$bank_a/dispatch" > "$directory/bank-dispatch-program.json"
bpftool -j map show pinned "$bank_a/maps/P9LEASENEXT" > "$directory/bank-dispatch-next-map.json"
bpftool -j map show pinned "$bank_a/maps/P9LEASEDIS" > "$directory/bank-dispatch-counter-map.json"
jq -e --slurpfile next "$directory/bank-dispatch-next-map.json" --slurpfile counter "$directory/bank-dispatch-counter-map.json" \
  '(.map_ids|sort)==([$next[0].id,$counter[0].id]|sort)' "$directory/bank-dispatch-program.json" >/dev/null
ip netns exec "$fabric" tc filter replace dev "$source_host" ingress pref 1 handle 1 bpf da pinned "$bank_a/dispatch"
start_receivers dispatch-empty 20 3
start_senders dispatch-empty 20 5000
finish_traffic dispatch-empty
bpftool -j map lookup pinned "$bank_a/maps/P9LEASEDIS" key hex 00 00 00 00 > "$directory/dispatch-empty-per-cpu.json"
jq -e -L /usr/local/share/unf-qualification 'include "device-lease-concurrency-gate"; device_lease_counters==[40,0,40]' "$directory/dispatch-empty-per-cpu.json" >/dev/null
jq -e -L /usr/local/share/unf-qualification 'include "device-lease-concurrency-gate"; traffic(20) and .original4.received==0 and .original6.received==0 and .foreign4.received==0 and .foreign6.received==0' "$directory/dispatch-empty-traffic.json" >/dev/null
publish_bank() {
    local name=$1 bank=$2
    bpftool -j prog show pinned "$bank/concurrent" > "$directory/$name-program.json"
    device-context-seed "$bank_a" publish "$bank" > "$directory/$name-published.json"
    jq -e --slurpfile program "$directory/$name-program.json" '.schemaVersion==1 and .scope=="isolated-device-generation" and .productionAuthority==false and .publishedProgramId==$program[0].id' "$directory/$name-published.json" >/dev/null
    bpftool -j map lookup pinned "$bank_a/maps/P9LEASENEXT" key hex 00 00 00 00 > "$directory/$name-dispatch.json"
    encoded=$(encode64 "$(jq -er '.id' "$directory/$name-program.json")")
    jq -e --arg id "${encoded:0:8}" '.value|map(ltrimstr("0x")|ascii_downcase)|join("")==$id' "$directory/$name-dispatch.json" >/dev/null
}
publish_bank bank-initial-a "$bank_a"
start_receivers publication 20000 30
start_senders publication 20000 1000
sleep 1
for round in $(seq 1 10); do
    publish_bank "bank-$round-b" "$bank_b"
    sleep 0.1
    publish_bank "bank-$round-a" "$bank_a"
    sleep 0.1
done
# Remove A's pins while A is still selected and senders continue. The dispatch
# slot then holds its last program reference. The final B swap is the actual
# retirement operation, exercising deferred release at publication itself.
# Keep only public sequence/counter maps for the audit and the dispatcher.
[[ ! -s $directory/publication-sent4.json && ! -s $directory/publication-sent6.json ]]
kill -0 "${traffic_pids[4]}" "${traffic_pids[5]}"
for map in P9LEASECFG P9LEASEPTR P9LEASEDEV P9LEASEOWN P9LEASETAG; do
    bpftool -j map show pinned "$bank_a/maps/$map" > "$directory/retired-$map-info.json"
done
for program in program concurrent; do [[ -e $bank_a/$program ]]; unlink "$bank_a/$program"; done
for map in P9LEASECFG P9LEASEPTR P9LEASEDEV P9LEASEOWN P9LEASETAG; do unlink "$bank_a/maps/$map"; done
publish_bank bank-final-b "$bank_b"
jq -e -s 'length==22 and all(.[];.schemaVersion==1 and .scope=="isolated-device-generation" and .productionAuthority==false)' "$directory"/bank-*-published.json >/dev/null
for map in P9LEASECFG P9LEASEPTR P9LEASEDEV P9LEASEOWN P9LEASETAG; do
    id=$(jq -er '.id' "$directory/retired-$map-info.json")
    gone=false
    for _ in $(seq 1 50); do
        if bpftool -j map show id "$id" > "$directory/retired-$map-lookup.json" 2> "$directory/retired-$map-lookup.err"; then
            sleep 0.05
        else
            [[ ! -s $directory/retired-$map-lookup.err ]]
            jq -e -L /usr/local/share/unf-qualification --argjson id "$id" \
                'include "device-lease-publication-gate"; device_lease_retired_map($id)' \
                "$directory/retired-$map-lookup.json" >/dev/null
            gone=true; break
        fi
    done
    [[ $gone == true ]]
done
[[ ! -s $directory/publication-sent4.json && ! -s $directory/publication-sent6.json ]]
kill -0 "${traffic_pids[4]}" "${traffic_pids[5]}"
finish_traffic publication
bpftool -j map lookup pinned "$bank_b/maps/P9LEASECON" key hex 00 00 00 00 > "$directory/bank-b-after-per-cpu.json"
jq -L /usr/local/share/unf-qualification 'include "device-lease-concurrency-gate"; device_lease_counters' "$directory/bank-b-after-per-cpu.json" > "$directory/bank-b-after-counters.json"
bpftool -j map lookup pinned "$bank_a/maps/P9LEASEDIS" key hex 00 00 00 00 > "$directory/dispatch-final-per-cpu.json"
jq -L /usr/local/share/unf-qualification 'include "device-lease-concurrency-gate"; device_lease_counters' "$directory/dispatch-final-per-cpu.json" > "$directory/dispatch-final-counters.json"
device-context-seed "$bank_a" ledger > "$directory/bank-a-ledger.json"
device-context-seed "$bank_b" ledger > "$directory/bank-b-ledger.json"
jq -n -L /usr/local/share/unf-qualification --slurpfile traffic "$directory/publication-traffic.json" \
  --slurpfile before "$directory/bank-a-before-counters.json" --slurpfile after_b "$directory/bank-b-after-counters.json" \
  --slurpfile dispatch "$directory/dispatch-final-counters.json" --slurpfile ledger_a "$directory/bank-a-ledger.json" --slurpfile ledger_b "$directory/bank-b-ledger.json" \
  'include "device-lease-publication-gate"; {traffic:$traffic[0],before:$before[0],afterB:$after_b[0],dispatch:$dispatch[0],ledgerA:$ledger_a[0],ledgerB:$ledger_b[0]}|device_lease_publication_gate' > "$directory/publication-result.json"
# User freeze must not suppress kernel-owned revocation of the remaining bank.
ip -n "$target_ns" link set eth0 netns "$foreign"
configure_target "$foreign"
device-context-seed "$bank_b" bindings > "$directory/frozen-peer-moved-bindings.json"
jq -e '.==[201,301,202,null]' "$directory/frozen-peer-moved-bindings.json" >/dev/null
