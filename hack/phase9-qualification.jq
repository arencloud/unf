# Independent platform results may arrive in either order. Pending evidence
# carries no invented revision, capture, hash, or kube-proxy observation.
def phase9_kind_qualification_valid:
  .kindQualification as $kind |
  ($kind.schemaVersion == 1 and $kind.milestone == "9.8"
   and $kind.runtimeRevision == .sourceRevision
   and (($kind.result == "passed"
         and ($kind.qualificationRevision | type == "string" and test("^[0-9a-f]{40}$"))
         and ($kind.evidenceSha256 | type == "string" and test("^[0-9a-f]{64}$"))
         and ($kind.captureSha256 | type == "string" and test("^[0-9a-f]{64}$"))
         and $kind.kubeProxyPresent == false)
     or (.qualificationOrder == "openshift-first"
         and $kind.result == "pending"
         and $kind.qualificationRevision == null
         and $kind.evidenceSha256 == null
         and $kind.captureSha256 == null
         and $kind.kubeProxyPresent == null)));

# Every planned controller replacement must first preserve its write/error
# counters. Successful traffic cannot mask a transient checkpoint failure.
def phase9_checkpoint_persistence_valid:
  (.stage | type == "string" and length > 0)
  and (.controllerPod | type == "string" and length > 0)
  and (.writes | type == "number" and . > 0 and floor == .)
  and .errors == 0
  and .controllerRestarts == 0
  and .controllerMemoryLimit == "2Gi"
  and ((.descriptor.schemaVersion == 1 and .descriptor.codec == "gzip")
    or (.descriptor.schemaVersion == 2 and .descriptor.codec == "zstd"))
  and (.descriptor.compressedBytes | type == "number" and . > 0 and floor == .)
  and (.descriptor.uncompressedBytes | type == "number" and . > 0 and . <= 64000000 and floor == .)
  and (.storedBytes | type == "number" and . > 0 and . <= 900000 and floor == .)
  and .storedBytes > .descriptor.compressedBytes;

# Both inputs MUST first pass the independent typed/hash-chain CLI verifier.
# This comparison adds restart continuity, not full-history completeness.
# Intentional bounded retention remains explicit; upstream loss is not waived.
def phase9_operations_continuity_valid:
  .before as $before | .after as $after |
  ($before.counters.cells | flatten) as $oldCounters |
  ($after.counters.cells | flatten) as $newCounters |
  INDEX($after.records[]; .sequence | tostring) as $retained |
  $before.schemaVersion == 1 and $after.schemaVersion == 1
  and ($before.records | length > 0 and length <= 512)
  and ($after.records | length > 0 and length <= 512)
  and $before.reportedLostObservations == 0 and $after.reportedLostObservations == 0
  and $after.revision >= $before.revision
  and $after.generation >= $before.generation
  and $after.evictedRecords >= $before.evictedRecords
  and $after.evictedObservations >= $before.evictedObservations
  and ($oldCounters | length) == 54 and ($newCounters | length) == 54
  and all(range(0; $oldCounters | length); . as $index | $newCounters[$index] >= $oldCounters[$index])
  and (if $before.revision == $after.revision then $before == $after else true end)
  and all($before.records[]; . as $record |
    $retained[.sequence | tostring] as $overlap | $overlap == null or $overlap == $record)
  and (if $after.records[0].sequence == ($before.records[-1].sequence + 1)
    then $after.anchorDigest == $before.records[-1].recordDigest else true end);
