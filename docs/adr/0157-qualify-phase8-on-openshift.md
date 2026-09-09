# ADR 0157: Qualify Phase 8 on OpenShift

**Status:** Accepted and implemented for Phase 8 milestone 8.11

## Context

Milestone 8.10 proved that the complete egress runtime composes on a dedicated
three-Node dual-stack Kind cluster. That result cannot establish RHCOS, SELinux,
CRI-O, five-Node cross-worker, or OpenShift lifecycle behavior. Phase 8 therefore
requires an independent, digest-pinned OpenShift gate against the exact runtime
that passed Kind, with explicit destructive-cluster and address-range
acknowledgements and a health baseline captured before fixture creation.

## Decision

`hack/verify-openshift-egress-phase8.sh` is the milestone 8.11 gate. It admits
only the release record's exact source revision and images, requires kube-proxy
to remain absent, and verifies on cl02:

1. policy-first cross-worker IPv4 and IPv6 source steering and gateway NAT,
   including external observation of managed egress addresses and native source
   preservation for an unmanaged workload;
2. four exclusive dual-stack addresses distributed over three CCR gateways;
3. graceful gateway drain, bounded traffic observation, deterministic shard
   reassignment, and restoration of full warm-standby capacity without changing
   active ownership;
4. durable controller checkpoint replay and replacement of one gateway agent;
5. evidence-complete explanation and non-authoritative simulation;
6. exact policy, pool, address, label, and Namespace release; and
7. final five-agent convergence, all Nodes Ready, and no additional unhealthy
   ClusterOperator relative to the captured baseline.

The evidence collector records Pod phase and treats absent terminal
`containerStatuses` as an empty list. A historical failed Pod therefore remains
visible without preventing exact runtime-image evidence from every live agent
and controller.

## Evidence

Runtime `2f404edcff94becd6d023bd8885c3c71ce4993b4` and qualification harness
`baf2bb031a39894f3d5377b6fc1af5b5622f670b` passed the uninterrupted 411-second
gate on five-Node dual-stack cl02, OpenShift 4.22.10/Kubernetes 1.35.6. The
controller and agent ran from immutable public digests:

- controller: `sha256:a7945ae471ca366fdc7fa0f9b7f8df971796612ee12021120764068eb7fc10ba`;
- agent: `sha256:75dc091af8d886b414ba136bfc3cae95012e477505f7c066a03a3fb05bf37814`;
- test tools: `sha256:735a7a70065e3f61209d90633c58c367da44264458e64a289fb30c0ffad229a6`.

The schema-v1 artifact is
`.artifacts/phase8-egress-complete-openshift.json`, SHA-256
`a2f8cb2279a3e1417ad1533575b644487e64cbfd1d8afafe351e99fad7e126d3`.
It records zero kube-proxy presence, all five runtime agents converged, observed
managed IPv4/IPv6 sources before and after drain/recovery, exact release, and
the unchanged `network` unhealthy-operator baseline. The guarded deployment
evidence SHA-256 is
`91573f6fd601f850a2acebffa6654e0820c574bf2d1f1aa140815060c733d27a`.

## Consequences

- Milestone 8.11 and Phase 8 are Verified. The independent Kind and OpenShift
  artifacts are complementary and remain non-transitive.
- Warm standby restores eligible HA capacity after graceful membership rejoin
  without moving active shards; failure contingencies still promote the standby
  only through the existing fenced transaction.
- The passing lab baseline contained the `network` ClusterOperator as unhealthy.
  The gate proves no regression relative to that baseline, not universal
  ClusterOperator health.
- Production availability and scale, abrupt physical Node loss,
  production-scale BGP/ECMP/BFD, BFD authentication, TCP-AO/MD5 secret delivery,
  EVPN, cross-cluster egress, and encryption remain explicitly unqualified.
