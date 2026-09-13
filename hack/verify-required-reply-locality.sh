#!/usr/bin/env bash
set -Eeuo pipefail
project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
jq -n -L "$project_root/hack" '
  include "required-reply-locality";
  ([range(0;32)|7]) as $digest
  | {ready:true,bpf_loaded:true,applied_identity_epoch:7,desired_identity_epoch:7,
      applied_identity_revision:9,desired_identity_revision:9,
      applied_remote_route_epoch:7,desired_remote_route_epoch:7,
      applied_remote_route_revision:11,desired_remote_route_revision:11} as $report
  | {controllerEpoch:7,admittedDigest:$digest,snapshot:{recipient:{nodeName:"worker-a",nodeUid:"uid-a"},membershipRevision:3}} as $plan
  | {schemaVersion:1,scope:"localityPlacementCandidate",dataplaneReady:true,
      matchesReportedIdentityAndRouting:true,kernelAdmitted:false,observedDelivery:false,
      observation:{phase:"replayed",observedAtUnixMs:123,planDigest:$digest,localAddresses:4,
        context:{clusterId:"cluster-a",recipient:{nodeName:"worker-a",nodeUid:"uid-a"},
          membershipRevision:3,identityEpoch:7,identityRevision:9,routingRevision:11}}} as $valid
  | {schemaVersion:1,scope:"localityPlacementCandidate",dataplaneReady:true,
      matchesReportedIdentityAndRouting:false,kernelAdmitted:false,observedDelivery:false,
      observation:{phase:"absent",observedAtUnixMs:124,context:null,planDigest:null,localAddresses:0}} as $absent
  | def check($report; $plan): locality_candidate_valid("worker-a";"uid-a";"cluster-a";$report;$plan;4);
  ($valid | check($report;$plan)) as $positive
  | ($absent | locality_absent_valid) as $empty_positive
  | [($valid | paths(scalars))] as $paths
  | [ $paths[] as $path
      | ($valid | setpath($path;null) | check($report;$plan)) ] as $missing
  | [ ($report|keys[]) as $key
      | ($report|.[$key]=null) as $changed
      | ($valid|check($changed;$plan)) ] as $reports
  | [($plan|paths(scalars))] as $plan_paths
  | [ $plan_paths[] as $path
      | ($plan|setpath($path;null)) as $changed
      | ($valid|check($report;$changed)) ] as $plans
  | [ $valid | .observation.phase="fetching", (.kernelAdmitted=true), (.observedDelivery=true),
      (.observation.localAddresses=3), (.observation.context.routingRevision=12),
      (.observation.context.recipient.nodeUid="replacement"), (.observation.planDigest=[7])
      | check($report;$plan) ] as $mutations
  | [ $absent | .observation.phase="failed", (.kernelAdmitted=true), (.observedDelivery=true),
      (.observation.localAddresses=1), (.observation.context={}), (.dataplaneReady=false)
      | locality_absent_valid ] as $retirements
  | ($missing+$reports+$plans+$mutations+$retirements) as $negative
  | if $positive and $empty_positive and all($negative[]; .==false)
    then {result:"passed",positiveCases:2,negativeCases:($negative|length)}
    else error("locality observer accepted an invalid cut") end
'
