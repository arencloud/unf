#!/usr/bin/env bash
set -Eeuo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
jq -ne -L "${root}/hack" '
  include "phase9-qualification";
  {sourceRevision:("a"*40),qualificationOrder:"openshift-first",
   kindQualification:{schemaVersion:1,milestone:"9.8",runtimeRevision:("a"*40),result:"pending"}} as $pending |
  ($pending | .kindQualification += {result:"passed",qualificationRevision:("b"*40),
    evidenceSha256:("c"*64),captureSha256:("d"*64),kubeProxyPresent:false}) as $passed |
  [($pending | phase9_kind_qualification_valid),
   ($passed | phase9_kind_qualification_valid),
   ($passed | del(.qualificationOrder) | phase9_kind_qualification_valid),
   ($pending | del(.qualificationOrder) | phase9_kind_qualification_valid | not),
   ($pending | .kindQualification.runtimeRevision=("b"*40) | phase9_kind_qualification_valid | not),
   ($pending | .kindQualification.evidenceSha256=("b"*64) | phase9_kind_qualification_valid | not),
   ($pending | .kindQualification.kubeProxyPresent=false | phase9_kind_qualification_valid | not),
   ($pending | .kindQualification.result="passed" | phase9_kind_qualification_valid | not),
   ($passed | .kindQualification.captureSha256=null | phase9_kind_qualification_valid | not)] | all
' >/dev/null
echo 'Phase 9 qualification order and pending-evidence rejection verified'
