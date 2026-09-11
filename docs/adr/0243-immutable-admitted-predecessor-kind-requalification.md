# ADR 0243: Immutable Admitted-Predecessor Kind Requalification

## Status

Accepted

## Context

ADR 0242 changes startup generation ordering and invalidates the ADR 0241
runtime tuple. The revised binary is eligible for cl02 only after the exact
source passes the complete fresh Phase 9 Kind lifecycle and its public image
manifests are pinned by digest.

## Decision

Revision `180ae2f15bb3c794cc6143511eab148d87005c8c` is the sole admitted Phase
9.9 runtime. Its public Linux/amd64 images are:

- controller: `quay.io/arencloud/unf-controller-dev@sha256:2105f2090224ac894671ab7b691381dbdad02c684dcc3312631a8a89e14431b1`;
- agent: `quay.io/arencloud/unf-agent-dev@sha256:107a119b3d7567f262e4b3520e0451259073fa0e66b349655192bbca1bd3b412`;
- test tools: `quay.io/arencloud/unf-test-tools-dev@sha256:e9cce439d92d0f7d3d6751f234e397a7efc29f9983bc0ae8fc318432c4ff2352`.

Runtime and qualifier revision `180ae2f15bb3c794cc6143511eab148d87005c8c`
passed `make encryption-phase9-kind-test` on a newly created three-Node,
dual-stack Kubernetes v1.35.0 cluster with kube-proxy absent. The gate proved:

- default-Required and explicit-selective IPv4/IPv6 PodIP and ClusterIP paths;
- 284 WireGuard underlay frames, zero Required plaintext frames, and 309
  explicit-Native plaintext frames;
- eight of eight Required fault probes blocked while eight of eight Native
  probes succeeded;
- natural two-epoch rotation, controlled agent and controller replacement, and
  308 loss-free causal operation records; and
- Phase 8 egress coexistence, exact cleanup, and complete no-CNI rollback.

The evidence JSON SHA-256 is
`9c947374d70de860357eee1929cd7dea09c90cf6b747b195c9b5ae32f3fde071`.
The packet capture SHA-256 is
`b39d6d3b37634ea6cb3241c9674ab8a30238322c791a7de54b56fc65e5390d41`.
All three images were independently resolved without credentials after
publication.

## Consequences

- The ADR 0241 tuple remains historical evidence but is not eligible for the
  resumed deployment.
- The release record and OpenShift overlay fail closed on these exact digests.
- cl02 must now prove the five-Node admitted-predecessor recovery and complete
  Phase 9.9 platform gate before the phase can close.
