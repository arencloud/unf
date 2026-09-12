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
