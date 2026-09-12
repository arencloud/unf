# ADR 0249: Immutable Continuous-Bridge Kind Requalification

## Status

Accepted

## Context

ADR 0248 makes the tombstoned-predecessor bridge reachable during continuous
plan reconciliation as well as startup. That runtime change invalidates the ADR
0247 tuple. It is eligible for cl02 only after its exact committed source passes
the complete fresh Phase 9 Kind lifecycle and its public images are pinned by
digest.

## Decision

Revision `f89ae63c36f3fa17cb5ad0311ee8028d544b5226` is the sole admitted Phase
9.9 runtime. Its public Linux/amd64 images are:

- controller: `quay.io/arencloud/unf-controller-dev@sha256:4588f01c15fbc925f38557fab9fcdbdd9a76b13c59e52b52ce2e9182840b2b72`;
- agent: `quay.io/arencloud/unf-agent-dev@sha256:0d4f267e30bd4d864d61db309700723db356c6fca35933cc16385a949bd0480c`;
- test tools: `quay.io/arencloud/unf-test-tools-dev@sha256:e9cce439d92d0f7d3d6751f234e397a7efc29f9983bc0ae8fc318432c4ff2352`.

Runtime and qualifier revision `f89ae63c36f3fa17cb5ad0311ee8028d544b5226`
passed `make encryption-phase9-kind-test` on a newly created three-Node,
dual-stack Kubernetes v1.35.0 cluster with kube-proxy absent. The gate proved:

- default-Required and explicit-selective IPv4/IPv6 PodIP and ClusterIP paths;
- 336 WireGuard underlay frames, zero Required plaintext frames, and 310
  explicit-Native plaintext frames;
- eight of eight Required fault probes blocked while eight of eight Native
  probes succeeded;
- natural two-epoch rotation, controlled agent and controller replacement, and
  308 loss-free causal operation records; and
- Phase 8 egress coexistence, exact cleanup, and complete no-CNI rollback.

The evidence JSON SHA-256 is
`f933114524ade5a49154e8cb20aa011f36de0e73a52e266f10002dfc46b3a25a`.
The packet capture SHA-256 is
`b3d23e938a41fb5482579288b3d9e2714d00574b0725e31189af313ef8dc07e8`.
All three images were independently resolved without credentials after
publication.

## Consequences

- The ADR 0247 tuple remains historical evidence but is no longer eligible for
  deployment.
- The release record and OpenShift overlay fail closed on these exact digests.
- cl02 must now cross its live tombstoned epoch-42 admission through continuous
  reconciliation and pass the complete Phase 9.9 platform gate before the phase
  can close.
