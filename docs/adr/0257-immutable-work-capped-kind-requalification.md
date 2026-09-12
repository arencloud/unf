# ADR 0257: Immutable Work-Capped Kind Requalification

## Status

Accepted and verified for Phase 9.9 release admission

## Context

ADR 0255 changes the controller's exact encryption-policy planning path and
ADR 0256 closes the final rollback over a validated producer-owned pending
checkpoint. The previously admitted ADR 0253 tuple cannot qualify either
change. Phase 9.9 requires one clean committed revision to pass the complete
fresh Kind lifecycle before it can be deployed to cl02.

## Decision

Revision `a7280171687a9f81ffd51a3c230942475c1500ef` is the sole admitted Phase
9.9 runtime. Its anonymously resolvable public Linux/amd64 images are:

- controller: `quay.io/arencloud/unf-controller-dev@sha256:ba7a153a04720a0f34aa6659d85605cbf04e62160a73cc1ac160780ffc78c1f9`;
- agent: `quay.io/arencloud/unf-agent-dev@sha256:1d36b8c273fa225e0cf036995382928763a39abd461abfe8efb7f355560d9fd1`;
- test tools: `quay.io/arencloud/unf-test-tools-dev@sha256:e9cce439d92d0f7d3d6751f234e397a7efc29f9983bc0ae8fc318432c4ff2352`.

All were also published under the diagnostic tag `phase9-kind-a728017`.
Runtime and qualifier revision `a7280171687a9f81ffd51a3c230942475c1500ef`
passed `make encryption-phase9-kind-test` on a newly created three-Node,
dual-stack Kubernetes v1.35.0 cluster with kube-proxy absent. The gate proved:

- default-Required and explicit-selective IPv4/IPv6 PodIP and ClusterIP paths;
- 399 WireGuard underlay frames, zero Required plaintext frames, and 311
  explicit-Native plaintext frames;
- eight of eight Required fault probes blocked while eight of eight Native
  probes succeeded;
- natural two-epoch rotation, controlled agent and controller replacement, and
  298 loss-free causal operation records;
- Phase 8 egress coexistence and exact encryption/fixture cleanup; and
- complete primary-CNI rollback, including the validated LoadBalancer pending
  checkpoint boundary, to the saved no-CNI baseline.

The evidence JSON SHA-256 is
`7015cf0026fdc883d44eda94a2fc9a544ff3e8fdb021f8e969915b259802b4c5`.
The packet capture SHA-256 is
`4dd62631f64d3c88421fdfbb63ba59a56255659732f62c57e2ce8bb4d386415d`.

## Consequences

- ADR 0253 remains historical qualification evidence but is no longer
  deployable as the Phase 9.9 release candidate.
- The release record and OpenShift overlay pin only the three digests above.
- cl02 must accept this exact tuple, preserve its Node-local recovery state,
  keep controller memory within the declared cgroup, and pass the complete
  OpenShift gate before Phase 9 can close.
