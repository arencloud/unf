#!/usr/bin/env bash
set -Eeuo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
bash -n "$root/hack/verify-required-reply-transport.sh" "$root/hack/required-reply-adoption.sh" "$root/hack/required-reply-capture.sh"
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
echo 'Required reply gate rejects incomplete/stale/foreign cuts and unbound reply provenance'
