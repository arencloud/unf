# ADR 0241: Immutable Tombstone-Handoff Kind Requalification

## Status

Accepted

## Context

ADR 0240 changes startup recovery authority and therefore supersedes the ADR
0237 runtime tuple even though the packet and persistent-map ABIs are
unchanged. The exact revised binary had to pass the complete fresh Phase 9 Kind
lifecycle before it could be deployed to cl02.

## Decision

Revision `1fd2d7767b66d7147ac6be2ccbcb9e016446651f` is the sole admitted Phase
9.9 runtime. Its public Linux/amd64 images are:

- controller: `quay.io/arencloud/unf-controller-dev@sha256:335748d2475615292b99bb80c129cf83b23b95c43b1ec06e4527a3096a319fb6`;
- agent: `quay.io/arencloud/unf-agent-dev@sha256:17d32bd08cf599b7d9c1ebde21e0b32227e0b43432dbb6667d232349f7e8de1d`;
- test tools: `quay.io/arencloud/unf-test-tools-dev@sha256:e9cce439d92d0f7d3d6751f234e397a7efc29f9983bc0ae8fc318432c4ff2352`.

Runtime and qualifier revision `1fd2d7767b66d7147ac6be2ccbcb9e016446651f`
passed `make encryption-phase9-kind-test` on a newly created three-Node,
dual-stack Kubernetes v1.35.0 cluster with kube-proxy absent. The gate proved:

- default-Required and explicit-selective IPv4/IPv6 PodIP and ClusterIP paths;
- 352 WireGuard underlay frames, zero Required plaintext frames, and 309
  explicit-Native plaintext frames;
- eight of eight Required fault probes blocked while eight of eight Native
  probes succeeded;
- natural two-epoch rotation, controlled agent and controller replacement, and
  341 loss-free causal operation records; and
- Phase 8 egress coexistence, exact cleanup, and complete no-CNI rollback.

The evidence JSON SHA-256 is
`18e8d9e9d316e372703ec87330aa8db410c71a573d971372e4864952f0d666a9`.
The packet capture SHA-256 is
`875978e12ac35e32f7ac820f392b15bdbb2a11f13e8d1891f52c56c00d31602b`.
All three images were independently resolved without credentials after
publication.

## Consequences

- The ADR 0237 tuple remains historical evidence but is no longer eligible for
  Phase 9.9 deployment.
- The release record and OpenShift overlay fail closed on these exact digests.
- cl02 must still prove tombstone-aware reboot recovery and the complete Phase
  9.9 platform gate before the phase can close.
