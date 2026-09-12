# ADR 0251: Immutable Compact-Chain Kind Requalification

## Status

Accepted

## Context

ADR 0250 extends recovery from one tombstoned admitted predecessor to a
verified compact chain of consecutive tombstoned admissions. That runtime
change invalidates the ADR 0249 tuple. It is eligible for cl02 only after its
exact committed source passes the complete fresh Phase 9 Kind lifecycle and
its public images are pinned by digest.

## Decision

Revision `0590d9bac3b91761e87b54dda365afd43b6173c9` is the sole admitted Phase
9.9 runtime. Its public Linux/amd64 images are:

- controller: `quay.io/arencloud/unf-controller-dev@sha256:d0fd2b3dbf30f64efdbc711cd3e0b1908e18ff92fe79083fb997560e30212f5f`;
- agent: `quay.io/arencloud/unf-agent-dev@sha256:629fbbf087e46958d5f4ae5c8b53af50c2e23cd40bccf4f61a6ab22a502b8e73`;
- test tools: `quay.io/arencloud/unf-test-tools-dev@sha256:e9cce439d92d0f7d3d6751f234e397a7efc29f9983bc0ae8fc318432c4ff2352`.

Runtime and qualifier revision `0590d9bac3b91761e87b54dda365afd43b6173c9`
passed `make encryption-phase9-kind-test` on a newly created three-Node,
dual-stack Kubernetes v1.35.0 cluster with kube-proxy absent. The gate proved:

- default-Required and explicit-selective IPv4/IPv6 PodIP and ClusterIP paths;
- 401 WireGuard underlay frames, zero Required plaintext frames, and 310
  explicit-Native plaintext frames;
- eight of eight Required fault probes blocked while eight of eight Native
  probes succeeded;
- natural two-epoch rotation, controlled agent and controller replacement, and
  354 loss-free causal operation records; and
- Phase 8 egress coexistence, exact cleanup, and complete no-CNI rollback.

The evidence JSON SHA-256 is
`0023b630e92551508dc25d07d2576d9f2d6e75f611b49aa63cfbabfba712b5b5`.
The packet capture SHA-256 is
`fcbaf3c8de08f312565947eee0b27daaf469e1d32414570108a4fb3608957caa`.
All three images were independently resolved without credentials after
publication.

## Consequences

- The ADR 0249 tuple remains historical evidence but is no longer eligible for
  deployment.
- The release record and OpenShift overlay fail closed on these exact digests.
- cl02 must preserve its live two-hop tombstone residue, recover it with this
  tuple, and pass the complete Phase 9.9 platform gate before the phase can
  close.
