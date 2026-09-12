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
