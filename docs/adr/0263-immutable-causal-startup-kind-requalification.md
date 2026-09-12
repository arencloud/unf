# ADR 0263: Immutable Causal-Startup Kind Requalification

## Status

Accepted as the Phase 9.9 OpenShift candidate

## Context

ADR 0262 extends intentional controller backpressure across both pre-BPF
startup authority reads. This changes the agent runtime and invalidates the ADR
0261 tuple even though its controller-side bound was proven on cl02. A new
fresh-cluster qualification is required before the corrected agent can resume
the preserved-state platform gate.

## Decision

Revision `2b1184f95802bbd0bf5fa1f01a0dce99d5ac0528` is the sole admitted Phase
9.9 candidate. Its anonymously resolvable public Linux/amd64 images are:

- controller: `quay.io/arencloud/unf-controller-dev@sha256:05aab93bff2f774334dcdb6de7e92d0d12d0dc81013caf819d502de8284458f9`;
- agent: `quay.io/arencloud/unf-agent-dev@sha256:3d16ba733c4cecdbdd9f6bbbc009d860842fbaaa2df4b535a8ff3a2e16c0427c`;
- test tools: `quay.io/arencloud/unf-test-tools-dev@sha256:e9cce439d92d0f7d3d6751f234e397a7efc29f9983bc0ae8fc318432c4ff2352`.

They are also published under diagnostic tag `phase9-kind-2b1184f`. Runtime and
qualifier revision `2b1184f95802bbd0bf5fa1f01a0dce99d5ac0528` passed
`make encryption-phase9-kind-test` on a newly created three-Node, dual-stack
Kubernetes v1.35.0 cluster with kube-proxy absent. The uninterrupted gate
proved:

- default-Required and explicit-selective IPv4/IPv6 PodIP and ClusterIP paths;
- 269 WireGuard underlay frames, zero Required plaintext frames, and 312
  explicit-Native plaintext frames;
- eight of eight Required fault probes blocked while eight of eight Native
  probes succeeded;
- natural two-epoch rotation, controlled agent and controller replacement, and
  308 loss-free causal operation records;
- Phase 8 egress coexistence and exact encryption/fixture cleanup; and
- complete primary-CNI rollback to the saved no-CNI baseline.

The evidence JSON SHA-256 is
`63978ec431125539f6bc08b1b1c3922037c2358685c49a53cf9ff94d27e24dbf`.
The packet capture SHA-256 is
`047780be95257004eabcdc2cbdf0db596d02b523dce97fb75d825039a598874c`.

## Consequences

- ADR 0261 remains the historical proof of the controller memory bound and the
  agent-side serial-replacement defect; its tuple is no longer deployable.
- The release record and OpenShift overlay pin only this successor.
- cl02 must accept exact preserved-state serial replacement and then pass the
  complete Phase 9.9 gate before Phase 9 can be marked Verified.
