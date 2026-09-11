# ADR 0233: Immutable Expiry-Recovery Kind Requalification

- Status: Accepted and verified for Phase 9.9 release admission
- Date: 2026-09-11

## Context

Expired Authority Recovery and Crash-Residue Cleanup Closure changed the
runtime recovery and qualification transaction after the previously admitted
Phase 9.9 tuple. Focused tests and a resumed cleanup cannot authorize an
OpenShift rollout. One exact combined source revision must repeat the complete
fresh-cluster transaction and become anonymously retrievable by immutable
registry digest.

## Decision

Revision `7296f061090656d17ff9c13440ebb1a1e5167c75` is the admitted Phase
9.9 recovery tuple. That exact revision built and qualified controller and
agent. Anonymous registry inspection proved all referenced artifacts are
public Linux/amd64 images:

- controller: `quay.io/arencloud/unf-controller-dev@sha256:ce7960c69ebce84ee214cb7984a0b18981deda348f8b365f74a4985010f05333`;
- agent: `quay.io/arencloud/unf-agent-dev@sha256:39ec92505df84b021c8822d0d002aeb984a658a5ba266915ec4e550de32d6648`;
- test tools: `quay.io/arencloud/unf-test-tools-dev@sha256:e9cce439d92d0f7d3d6751f234e397a7efc29f9983bc0ae8fc318432c4ff2352`.

The OpenShift overlay and schema-v1 release record grant deployment authority
only to these digests. Tags remain non-authoritative discovery metadata.

## Evidence

`make encryption-phase9-kind-test` passed on a newly created three-Node,
kube-proxy-free, dual-stack Kubernetes v1.35.0 cluster. It verified exact build
revisions and image IDs, default-Required and explicit-Native IPv4/IPv6 PodIP
and ClusterIP traffic, eight-of-eight Required denials beside eight-of-eight
Native successes during peer loss, natural rotation, agent and controller
replacement, loss-free operations, Phase 8 egress coexistence, performance,
exact cleanup, crash-residue closure, and no-CNI rollback.

The schema-v1 evidence SHA-256 is
`e65bb611a65a2878446341d0c0571f79f103d674c0dea6914dd5f4d81e1d9fd9`.
The independent packet capture SHA-256 is
`2667fc48a24b15878e5cbd0c8180f2a8c57a500708c1183149667314ab2e0fa9`;
it contains 366 WireGuard frames, zero Required plaintext frames, and 310
Native plaintext frames. Operations retained all 272 records without reported
loss.

## Consequences

- The simultaneous-reboot recovery implementation is admitted only through a
  complete fresh lifecycle, not through focused tests alone.
- Final rollback is proven across the exact atomic-write interruption class
  discovered by the preceding run.
- Earlier development digests remain historical evidence but are not eligible
  for the next cl02 rollout.
- This result authorizes cl02 qualification; it does not itself prove RHCOS,
  SELinux, CRI-O, or five-Node behavior.
