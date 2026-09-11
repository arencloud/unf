# ADR 0247: Immutable Tombstoned-Predecessor-Bridge Kind Requalification

## Status

Accepted

## Context

ADR 0246 changes restart recovery across a controller-admitted predecessor
whose only key epoch is durably tombstoned. That change invalidates the ADR
0245 runtime tuple. The bridge is eligible for cl02 only after its exact source
passes the complete fresh Phase 9 Kind lifecycle and its public images are
pinned by digest.

## Decision

Revision `b64282a0cf328857f121e952fe422dc6ce0b67ec` is the sole admitted Phase
9.9 runtime. Its public Linux/amd64 images are:

- controller: `quay.io/arencloud/unf-controller-dev@sha256:aed43801ccd9a5b899045ed97ee9a77ce01be6fffea17991a0e2ddb5b136b982`;
- agent: `quay.io/arencloud/unf-agent-dev@sha256:cf611188c2a66b7e5cb8f193605f7c0d48c0fe640014483bd25520a711ba496f`;
- test tools: `quay.io/arencloud/unf-test-tools-dev@sha256:e9cce439d92d0f7d3d6751f234e397a7efc29f9983bc0ae8fc318432c4ff2352`.

Runtime and qualifier revision `b64282a0cf328857f121e952fe422dc6ce0b67ec`
passed `make encryption-phase9-kind-test` on a newly created three-Node,
dual-stack Kubernetes v1.35.0 cluster with kube-proxy absent. The gate proved:

- default-Required and explicit-selective IPv4/IPv6 PodIP and ClusterIP paths;
- 400 WireGuard underlay frames, zero Required plaintext frames, and 312
  explicit-Native plaintext frames;
- eight of eight Required fault probes blocked while eight of eight Native
  probes succeeded;
- natural two-epoch rotation, controlled agent and controller replacement, and
  312 loss-free causal operation records; and
- Phase 8 egress coexistence, exact cleanup, and complete no-CNI rollback.

The evidence JSON SHA-256 is
`714c58c825988f331ceadfc556045c793169d8ec343dfa1163addfcff4279b89`.
The packet capture SHA-256 is
`233160967e2d9492ab2df44c38c4d3edcbf2c719f00f070065c1389116f2a5da`.
All three images were independently resolved without credentials after
publication.

## Consequences

- The ADR 0245 tuple remains historical evidence but is no longer eligible for
  deployment.
- The release record and OpenShift overlay fail closed on these exact digests.
- cl02 must now prove the tombstoned-predecessor bridge against its five-Node
  reboot residue and pass the complete Phase 9.9 platform gate before the phase
  can close.
