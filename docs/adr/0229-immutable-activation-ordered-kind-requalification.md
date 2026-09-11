# ADR 0229: Immutable Activation-Ordered Kind Requalification

- Status: Accepted and verified for Phase 9.9 release admission
- Date: 2026-09-11

## Context

ADRs 0227 and 0228 changed zero-transport activation and replacement-controller
recovery ordering after the previously admitted Phase 9.8 tuple. Focused tests
cannot authorize an OpenShift rollout. The exact combined runtime must repeat
the complete fresh-cluster transaction and become anonymously retrievable by
registry manifest digest.

## Decision

Revision `32b5501e88fe17de7159e97e4665b1fb47dcd3af` is the only admitted
Phase 9.9 development tuple for the next cl02 attempt. That exact revision
built and qualified both controller and agent. Anonymous registry inspection
proved the referenced images are public Linux/amd64 manifests:

- controller: `quay.io/arencloud/unf-controller-dev@sha256:7f58c86fc6491807f49878158e8c0a1f64f7f9d81f5284eb7817ff5352db29f6`;
- agent: `quay.io/arencloud/unf-agent-dev@sha256:497446e841fdd4fd53c912d55a1f6a3447a52c62aa2f38b4ab3790c0a0670cea`;
- test tools: `quay.io/arencloud/unf-test-tools-dev@sha256:e9cce439d92d0f7d3d6751f234e397a7efc29f9983bc0ae8fc318432c4ff2352`.

The OpenShift overlay and schema-v1 release record grant deployment authority
only to these digests. Tags remain discovery metadata.

## Evidence

`make encryption-phase9-kind-test` passed on a newly created three-Node
dual-stack Kubernetes v1.35.0 cluster. It verified exact component build
revisions and image IDs, default-Required and explicit-Native IPv4/IPv6 PodIP
and ClusterIP traffic, eight-of-eight Required denials during peer loss beside
eight-of-eight Native successes, natural rotation, agent replacement,
activation-ordered controller replacement, loss-free operations, Phase 8
egress coexistence, performance bounds, exact cleanup, and no-CNI rollback.

The schema-v1 evidence SHA-256 is
`9a99fb97f5d3d1ac5a490784ee09554b7835e713671e62c635c29a814a6eeb31`.
The independent packet capture SHA-256 is
`74b22d10244b9b9bf4cb4176bafe01128399c054e75ca38fce2501dc5f7beb0b`;
it contains 297 WireGuard frames, zero Required plaintext frames, and 311
Native plaintext frames. Operations retained all 340 records with no reported
loss.

## Consequences

- Zero-transport and restored-cut ordering fixes are proven in the complete
  runtime lifecycle, not only by unit tests.
- Earlier development digests remain historical evidence but are no longer
  eligible for the Phase 9.9 cl02 rollout.
- This result admits the exact tuple to OpenShift qualification; it does not by
  itself qualify RHCOS, SELinux, CRI-O, or five-Node behavior.
