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

# Candidate counters only: never substitute these for per-attachment kernel
# proof or for the separate API UID/nonce ownership gate.
def locality_inventory_valid($minimum_addresses):
  try (
    .observation as $o
    | ([$o.journalSelectedAttachments, $o.journalSelectedAddresses,
        $o.journalSelectedPayloadBytes]
       | all(.[]; type == "number" and . > 0 and . == floor))
    and $o.journalSelectedAddresses >= $minimum_addresses
    and $o.journalSelectedAddresses <= $o.localAddresses
    and $o.journalSelectedAttachments <= $o.journalSelectedAddresses
    and $o.journalSelectedAddresses <= (2 * $o.journalSelectedAttachments)
    and $o.journalSelectedPayloadBytes <= 16777216
  ) catch false;

def locality_inventory_absent_valid:
  .observation.journalSelectedAttachments == 0
  and .observation.journalSelectedAddresses == 0
  and .observation.journalSelectedPayloadBytes == 0;
