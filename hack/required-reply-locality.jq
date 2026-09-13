def locality_candidate_valid($node; $uid; $cluster; $report; $plan; $minimum_addresses):
  .schemaVersion == 1 and .scope == "localityPlacementCandidate"
  and .observation.phase == "replayed"
  and (.observation.observedAtUnixMs | type == "number" and . > 0 and . == floor)
  and .dataplaneReady == true and .matchesReportedIdentityAndRouting == true
  and .kernelAdmitted == false and .observedDelivery == false
  and .observation.context.clusterId == $cluster
  and .observation.context.recipient == {nodeName:$node,nodeUid:$uid}
  and .observation.context.recipient == $plan.snapshot.recipient
  and ([$node,$uid,$cluster] | all(.[]; type == "string" and length > 0))
  and ([.observation.context.membershipRevision,.observation.context.identityEpoch,
        .observation.context.identityRevision,.observation.context.routingRevision]
       | all(.[]; type == "number" and . > 0 and . == floor))
  and .observation.context.membershipRevision == $plan.snapshot.membershipRevision
  and .observation.context.identityEpoch == $plan.controllerEpoch
  and .observation.context.identityEpoch == $report.applied_identity_epoch
  and .observation.context.identityEpoch == $report.desired_identity_epoch
  and .observation.context.identityEpoch == $report.applied_remote_route_epoch
  and .observation.context.identityEpoch == $report.desired_remote_route_epoch
  and .observation.context.identityRevision == $report.applied_identity_revision
  and .observation.context.identityRevision == $report.desired_identity_revision
  and .observation.context.routingRevision == $report.applied_remote_route_revision
  and .observation.context.routingRevision == $report.desired_remote_route_revision
  and .observation.planDigest == $plan.admittedDigest
  and (.observation.planDigest | type == "array" and length == 32 and all(.[]; type == "number" and . >= 0 and . <= 255 and . == floor))
  and (.observation.localAddresses | type == "number" and . >= $minimum_addresses and . <= 65536 and . == floor)
  and $report.ready == true and $report.bpf_loaded == true;

def locality_absent_valid:
  .schemaVersion == 1 and .scope == "localityPlacementCandidate"
  and .observation.phase == "absent"
  and (.observation.observedAtUnixMs | type == "number" and . > 0 and . == floor)
  and .observation.context == null and .observation.planDigest == null
  and .observation.localAddresses == 0
  and .matchesReportedIdentityAndRouting == false
  and .kernelAdmitted == false and .observedDelivery == false
  and .dataplaneReady == true;
