#!/usr/bin/env bash
set -Eeuo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
bash -n "$root/hack/verify-required-reply-transport.sh" "$root/hack/required-reply-adoption.sh" "$root/hack/required-reply-capture.sh" "$root/hack/required-reply-diagnostics.sh"
jq -L "$root/hack" -ne '
  include "required-reply-adoption";
  def good: [{node:"a",pending:false,generation:5,policyRevision:3,serviceRevision:4,egressRevision:2,epochs:[7]},
             {node:"b",pending:false,generation:5,policyRevision:3,serviceRevision:4,egressRevision:2,epochs:[7]},
             {node:"c",pending:false,generation:5,policyRevision:3,serviceRevision:4,egressRevision:2,epochs:[]}];
  def valid: reply_generation_cut_valid("required";"a";"b";3;3;4;2);
  (good|valid) and ([(good|.[0].pending=true), (good|.[0].generation=4),
    (good|.[0].epochs=[]), (good|.[2].epochs=[7]), (good|.[0].policyRevision=2),
    (good|.[0].serviceRevision=1), (good|.[0].egressRevision=1),
    (good|.[1].node="a"), (good|.[0].node="foreign"), (good|.[0].epochs=[0]),
    (good|.[0:2]), []] | length==12 and all(.[];valid|not))
  and (good|map(.epochs=[])|reply_generation_cut_valid("native";"a";"b";3;3;4;2))
  and (good|reply_generation_cut_valid("native";"a";"b";3;3;4;2)|not)
' >/dev/null
jq -L "$root/hack" -ne '
  include "required-reply-adoption";
  def good: {snapshot:{policyRevision:3,generation:5,recipient:{nodeName:"b"},epochs:[{contract:{schemaVersion:2,plans:[{
    source:{identity:22,node:{name:"b"}},destination:{identity:11,node:{name:"a"}},disposition:"required",
    policy:{replyTo:{source:11,destination:22},revision:3}}]}}]}};
  def valid: reply_provenance_valid(11;22;"a";"b";3;5);
  (good|valid) and ([(good|.snapshot.generation=4), (good|.snapshot.policyRevision=2),
    (good|.snapshot.recipient.nodeName="foreign"),(good|.snapshot.epochs[0].contract.schemaVersion=1),
    (good|.snapshot.epochs[0].contract.plans[0].policy.replyTo=null),
    (good|.snapshot.epochs[0].contract.plans[0].policy.replyTo.source=99),
    (good|.snapshot.epochs[0].contract.plans[0].source.node.name="foreign"),
    (good|.snapshot.epochs[0].contract.plans[0].disposition="native")]|length==8 and all(.[];valid|not))
' >/dev/null
bash "$root/hack/verify-phase9-capture.sh"
rg -Fq 'del(.explicitStopAfterFault) + {explicitStopAfterTraffic:true}' "$root/hack/required-reply-capture.sh"
rg -Fq 'required_reply_preserve_failure_capture >' "$root/hack/verify-required-reply-transport.sh"
rg -Fq '"$directory/probes.jsonl"' "$root/hack/verify-required-reply-transport.sh"
# Capture object creation must precede the final adoption barrier. Starting
# capture afterward may only signal the already-created, bounded process.
awk '
  /^required_reply_capture_prepare$/ {prepare=NR}
  /^required_reply_wait_policy$/ {policy=NR}
  /^required_reply_wait_generation required$/ {generation=NR}
  /^required_reply_capture_start$/ {start=NR}
  END {exit !(prepare>0 && prepare<policy && policy<generation && generation<start)}
' "$root/hack/verify-required-reply-transport.sh"
rg -Fq 'exec /usr/bin/timeout --signal=INT 300 /usr/bin/tcpdump' "$root/hack/required-reply-capture.sh"
rg -Fq '/usr/bin/timeout 600 /bin/sh' "$root/hack/required-reply-capture.sh"
source "$root/hack/required-reply-capture.sh"
directory=$(mktemp -d)
trap 'rm -r -- "$directory"' EXIT
phase9_capture_finish() {
    mkdir -p "$1"
    printf 'retained-failed-run-pcap\n' > "$1/received.pcap"
    jq -n '{explicitStopAfterFault:true,exitCode:0,packetsDroppedByKernel:0}'
}
required_reply_preserve_failure_capture | jq -e '.explicitStopAfterTraffic and (has("explicitStopAfterFault")|not)' >/dev/null
[[ -s $directory/failed-capture/received.pcap ]]
phase9_capture_finish() { return 1; }
if required_reply_preserve_failure_capture >/dev/null 2>&1; then
    echo 'Failed capture observation must not be accepted' >&2; exit 1
fi
source "$root/hack/required-reply-diagnostics.sh"
controller_raw() {
    case $1 in
        /v1/flows) printf '{"entries":[]}\n';;
        /v1/state/agents) echo 'mock observer failure' >&2; return 22;;
        /v1/encryption/status) printf '{"generation":7}\n';;
        *) return 99;;
    esac
}
required_reply_preserve_failure_status
[[ $(< "$directory/failed-flows.exit") == 0 ]]
[[ $(< "$directory/failed-state-agents.exit") == 22 ]]
[[ $(< "$directory/failed-encryption-status.exit") == 0 ]]
jq -e '.entries==[]' "$directory/failed-flows.json" >/dev/null
jq -e '.generation==7' "$directory/failed-encryption-status.json" >/dev/null
rg -Fq 'mock observer failure' "$directory/failed-state-agents.observer.log"
echo 'Required reply gate rejects incomplete/stale/foreign cuts and unbound reply provenance'
