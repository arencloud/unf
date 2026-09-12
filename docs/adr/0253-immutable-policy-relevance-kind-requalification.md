# ADR 0253: Immutable Policy-Relevance Kind Requalification

## Status

Accepted

## Context

ADR 0252 replaces the cluster-wide Cartesian policy scan exposed by cl02 with
the Policy-Relevance Quotient. Because that changes encryption-plan production,
the ADR 0251 image tuple cannot qualify the correction. The exact corrected
source must pass the complete fresh Phase 9 Kind lifecycle before cl02 receives
it.

## Decision

Revision `046b1b24a875e36f338f0ec0d30f13c1e3551429` is the sole admitted Phase
9.9 runtime. Its anonymously resolvable public Linux/amd64 images are:

- controller: `quay.io/arencloud/unf-controller-dev@sha256:6cabe78993e42e91ce129f220e89d27ba2416490e7ba84d8de2e5cf28bb15413`;
- agent: `quay.io/arencloud/unf-agent-dev@sha256:8576eb514213fa686060392fa5a44daa910d7b3d0a59c690a907cbce75cfe7c2`;
- test tools: `quay.io/arencloud/unf-test-tools-dev@sha256:e9cce439d92d0f7d3d6751f234e397a7efc29f9983bc0ae8fc318432c4ff2352`.

Runtime and qualifier revision `046b1b24a875e36f338f0ec0d30f13c1e3551429`
passed `make encryption-phase9-kind-test` on a newly created three-Node,
dual-stack Kubernetes v1.35.0 cluster with kube-proxy absent. The gate proved:

- default-Required and explicit-selective IPv4/IPv6 PodIP and ClusterIP paths;
- 335 WireGuard underlay frames, zero Required plaintext frames, and 311
  explicit-Native plaintext frames;
- eight of eight Required fault probes blocked while eight of eight Native
  probes succeeded;
- natural two-epoch rotation, controlled agent and controller replacement, and
  298 loss-free causal operation records; and
- Phase 8 egress coexistence, exact cleanup, and complete no-CNI rollback.

The evidence JSON SHA-256 is
`3c7255fc0a79cce5728e78357cdfc1427d5d1b1daee73429cea545f19a2270b4`.
The packet capture SHA-256 is
`c4c4e5b04ef391bd8fb26383c54272695a29f5dc7d04bd8c22047d9ec3dfc1f2`.

## Consequences

- ADR 0251 remains historical recovery evidence but is no longer deployable.
- The Phase 9.9 release record and OpenShift overlay pin this exact tuple.
- Preserved-state cl02 recovery must demonstrate that policy relevance remains
  exact at platform scale and that controller memory stays bounded before the
  complete OpenShift gate can close Phase 9.
