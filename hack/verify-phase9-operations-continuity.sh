#!/usr/bin/env bash
set -Eeuo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
bash -n "${root}/hack/phase9-operations.sh"
# Synthetic summaries exercise ONLY the cross-checkpoint comparison. Full
# schema/hash-chain tamper refusal is independently tested by unfctl.
jq -L "${root}/hack" -n -e '
  include "phase9-qualification";
  def checkpoint($revision; $evicted):
    {schemaVersion:1,revision:$revision,generation:10,
     evictedRecords:$evicted,evictedObservations:$evicted,reportedLostObservations:0,
     anchorDigest:$evicted,
     counters:{cells: [range(0;6) | . as $row |
       [range(0;9) | if $row == 0 and . == 0 then $revision else 0 end]]},
     records:[range($evicted+1; $revision+1) | {sequence:.,recordDigest:.}]};
  checkpoint(512;0) as $initial |
  checkpoint(514;2) as $retained |
  checkpoint(1026;514) as $next |
  {before:$initial,after:$retained} as $pair |
  [($pair | phase9_operations_continuity_valid),
   ({before:$retained,after:$retained} | phase9_operations_continuity_valid),
   ({before:$retained,after:$next} | phase9_operations_continuity_valid),
   ($pair | .after.reportedLostObservations=1 | phase9_operations_continuity_valid | not),
   ($pair | .before.reportedLostObservations=1 | phase9_operations_continuity_valid | not),
   ($pair | .after.generation=1 | phase9_operations_continuity_valid | not),
   ($pair | .after.revision=1 | phase9_operations_continuity_valid | not),
   ($pair | .after.counters.cells[0][0]=0 | phase9_operations_continuity_valid | not),
   ($pair | .after.records[0].recordDigest=9999 | phase9_operations_continuity_valid | not),
   ($pair | .after.records=[] | phase9_operations_continuity_valid | not),
   ({before:$retained,after:$next} | .after.anchorDigest=0 | phase9_operations_continuity_valid | not),
   ({before:$retained,after:$retained} | .after.evictedObservations=1 | phase9_operations_continuity_valid | not),
   ({before:$retained,after:$retained} | .after.evictedRecords=1 | phase9_operations_continuity_valid | not)]
  | all
' >/dev/null
echo "Phase 9 bounded operations comparison rejects loss, regression, reset and conflicting overlap"

# Exercise capture orchestration only. The real unfctl schema/hash-chain tests
# remain the authority for content validation; this mock checks invocation and
# ensures invalid successful reads cannot be hidden by fetching another cut.
project_root=${root}
source "${root}/hack/phase9-operations.sh"
scratch=$(mktemp -d)
trap 'rm -r -- "${scratch}"' EXIT
reads=0 verifications=0 fail_reads=0 verifier_status=0
controller_raw() {
    [[ $1 == /v1/encryption/history ]] || return 99
    reads=$((reads + 1))
    if (( reads <= fail_reads )); then
        printf '{"partial":'
        return 124
    fi
    printf '{"revision":7,"evictedObservations":0,"reportedLostObservations":0}'
}
cargo() {
    verifications=$((verifications + 1))
    [[ $* == *'encryption-history --file '* ]] || return 99
    (( verifier_status == 0 )) || return "${verifier_status}"
    command cat "${!#}"
}
sleep() { [[ $1 == 1 ]]; }

phase9_operations_capture first "${scratch}" >"${scratch}/first-path"
[[ ${reads} == 1 && ${verifications} == 1 ]]
jq -e '.attempts == [{attempt:1,transferExitCode:0,receivedBytes:67}] and .verificationExitCode == 0' \
    "${scratch}/first-read.json" >/dev/null
reads=0 verifications=0 fail_reads=2
phase9_operations_capture retried "${scratch}" >"${scratch}/retried-path"
[[ ${reads} == 3 && ${verifications} == 1 ]]
jq -e '[.attempts[].transferExitCode] == [124,124,0] and .verificationExitCode == 0' \
    "${scratch}/retried-read.json" >/dev/null
[[ $(wc -c <"${scratch}/retried-attempt-1-received.json") == 11 ]]
cmp "${scratch}/retried-attempt-3-received.json" "${scratch}/retried-received.json"
phase9_operations_evidence "${scratch}/first-verified.json" "${scratch}/retried-verified.json" |
    jq -e '(.reads.before.attempts | length) == 1 and (.reads.after.attempts | length) == 3' >/dev/null

reads=0 verifications=0 fail_reads=3
status=0
phase9_operations_capture unavailable "${scratch}" >"${scratch}/unavailable-path" || status=$?
[[ ${status} == 124 && ${reads} == 3 && ${verifications} == 0 ]]
[[ ! -e ${scratch}/unavailable-received.json && ! -e ${scratch}/unavailable-verified.json ]]
jq -e '.verificationExitCode == null and [.attempts[].transferExitCode] == [124,124,124]' \
    "${scratch}/unavailable-read.json" >/dev/null

reads=0 verifications=0 fail_reads=0 verifier_status=42
status=0
phase9_operations_capture invalid "${scratch}" >"${scratch}/invalid-path" || status=$?
[[ ${status} == 42 && ${reads} == 1 && ${verifications} == 1 ]]
jq -e '.verificationExitCode == 42 and (.attempts | length) == 1' \
    "${scratch}/invalid-read.json" >/dev/null
echo "Phase 9 history capture bounds transport retries and never retries verification failure"
