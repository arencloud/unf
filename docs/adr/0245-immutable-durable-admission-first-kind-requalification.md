# ADR 0245: Immutable Durable-Admission-First Kind Requalification

## Status

Accepted

## Context

ADR 0244 changes restart-time admission reconstruction and invalidates the ADR
0243 runtime tuple. The corrected binary is eligible for cl02 only after its
exact source passes the complete fresh Phase 9 Kind lifecycle and the resulting
public image manifests are pinned by digest.

## Decision

Revision `b3aee0ad8a5f8d46bbac27f453dfa4f737609f6d` is the sole admitted Phase
9.9 runtime. Its public Linux/amd64 images are:

- controller: `quay.io/arencloud/unf-controller-dev@sha256:acab9a2185b1457307e48b113ec41f40cb95b9d61729befe0a7ad58f1c0cc59c`;
- agent: `quay.io/arencloud/unf-agent-dev@sha256:0b34041ea3e151605f23579d8d8904cd607436ec8057ffe03a3dc8bea7753987`;
- test tools: `quay.io/arencloud/unf-test-tools-dev@sha256:e9cce439d92d0f7d3d6751f234e397a7efc29f9983bc0ae8fc318432c4ff2352`.

Runtime and qualifier revision `b3aee0ad8a5f8d46bbac27f453dfa4f737609f6d`
passed `make encryption-phase9-kind-test` on a newly created three-Node,
dual-stack Kubernetes v1.35.0 cluster with kube-proxy absent. The gate proved:

- default-Required and explicit-selective IPv4/IPv6 PodIP and ClusterIP paths;
- 729 WireGuard underlay frames, zero Required plaintext frames, and 272
  explicit-Native plaintext frames;
- eight of eight Required fault probes blocked while eight of eight Native
  probes succeeded;
- natural two-epoch rotation, controlled agent and controller replacement, and
  321 loss-free causal operation records; and
- Phase 8 egress coexistence, exact cleanup, and complete no-CNI rollback.

The evidence JSON SHA-256 is
`e721ff35a95421bebdb7057b153683589513f95a8a883ce9d73baf96079d49eb`.
The packet capture SHA-256 is
`e51241c49181816fb7d5edb8cb9798c128ed3e33316e8d39611b6b88d4c8c47c`.
All three images were independently resolved without credentials after
publication.

## Consequences

- The ADR 0243 tuple remains historical evidence but is no longer eligible for
  deployment.
- The release record and OpenShift overlay fail closed on these exact digests.
- cl02 must now prove durable-first predecessor recovery on the five-Node
  reboot residue and pass the complete Phase 9.9 platform gate before the phase
  can close.
