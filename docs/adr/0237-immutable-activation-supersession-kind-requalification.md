# ADR 0237: Immutable Activation-Supersession Kind Requalification

## Status

Accepted

## Context

ADR 0236 changes the controller/agent activation-report protocol and therefore
invalidates the previous runtime tuple even though its packet ABI is unchanged.
A new cl02 rollout is admissible only after the exact revised binaries pass the
complete Phase 9 lifecycle on a fresh kube-proxy-free dual-stack Kind cluster.

## Decision

Revision `e1dbb946239dcf2b94da5ceb8083fda85dbc2da4` is the sole admitted
Phase 9.9 runtime. Its public Linux/amd64 images are:

- controller: `quay.io/arencloud/unf-controller-dev@sha256:e12ca6efb07f0ae85f98fa6069618dcf28823199e5439ac4d0ebe4d050da71ed`;
- agent: `quay.io/arencloud/unf-agent-dev@sha256:f9e3d4d9f955ed9e548095f5603da1dc757a0f79e85d9c0b541c4676e44b83c9`;
- test tools: `quay.io/arencloud/unf-test-tools-dev@sha256:e9cce439d92d0f7d3d6751f234e397a7efc29f9983bc0ae8fc318432c4ff2352`.

Runtime and qualifier revision `e1dbb946239dcf2b94da5ceb8083fda85dbc2da4`
passed `make encryption-phase9-kind-test` on a newly created three-Node,
dual-stack Kubernetes v1.35.0 cluster with kube-proxy absent. The gate proved:

- default-Required and explicit-selective IPv4/IPv6 PodIP and ClusterIP paths;
- 340 WireGuard underlay frames, zero Required plaintext frames, and 312
  explicit-Native plaintext frames;
- eight of eight Required fault probes blocked while eight of eight Native
  probes succeeded;
- natural two-epoch rotation, controlled agent replacement, controller
  replacement, and 295 loss-free causal operation records;
- Phase 8 egress coexistence, exact cleanup, and complete no-CNI rollback.

The evidence JSON SHA-256 is
`870e92095c240b609d58d138749da2d065a941e2dc88b5d7ed87b912f6a505f5`.
The packet capture SHA-256 is
`c02654ee67f3d252612892bbcc64c77b3c5ae268e343f05bd5205f4f4707dc94`.
Both images were independently resolved without credentials after publication.

## Consequences

- The prior ADR 0233 tuple remains historical evidence but is no longer
  eligible for Phase 9.9 deployment.
- The release record and OpenShift overlay fail closed on these exact digests.
- cl02 must still prove the simultaneous-reboot recovery and complete Phase
  9.9 platform gate before the phase can close.
