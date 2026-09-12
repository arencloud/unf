# ADR 0259: Immutable Informer-Cut Kind Requalification

## Status

Historical Kind qualification; rejected by the cl02 platform gate

## Context

ADR 0258 closes the cold-start race exposed by cl02. Agent delivery must not
observe a changing partial controller cut while the initial authoritative
informers are relisting. Because this changes controller runtime behavior, the
previously admitted `a728017` tuple cannot qualify the fix.

## Decision

Revision `fbd62447234684156bd04088c1fec40707c1363e` is the sole admitted Phase
9.9 successor runtime. Its anonymously resolvable public Linux/amd64 images
are:

- controller: `quay.io/arencloud/unf-controller-dev@sha256:2c4cf844a2546e12e5aa605a5901191e1674f283b6daa9eb49b9131f590f6846`;
- agent: `quay.io/arencloud/unf-agent-dev@sha256:1cff5f5e8f007fbead35875d43647126c11e4aea7f9d2af2d6986f6aeeb5848b`;
- test tools: `quay.io/arencloud/unf-test-tools-dev@sha256:e9cce439d92d0f7d3d6751f234e397a7efc29f9983bc0ae8fc318432c4ff2352`.

All are published under the diagnostic tag `phase9-kind-fbd6244`. Runtime and
qualifier revision `fbd62447234684156bd04088c1fec40707c1363e` passed
`make encryption-phase9-kind-test` on a newly created three-Node, dual-stack
Kubernetes v1.35.0 cluster with kube-proxy absent. The gate proved:

- default-Required and explicit-selective IPv4/IPv6 PodIP and ClusterIP paths;
- 258 WireGuard underlay frames, zero Required plaintext frames, and 312
  explicit-Native plaintext frames;
- eight of eight Required fault probes blocked while eight of eight Native
  probes succeeded;
- natural two-epoch rotation, controlled agent and controller replacement, and
  358 loss-free causal operation records;
- Phase 8 egress coexistence and exact encryption/fixture cleanup; and
- complete primary-CNI rollback to the saved no-CNI baseline.

The evidence JSON SHA-256 is
`9c4efb777ca3b492c17324345237f5cc63d4da0eb1a62eb0850f11ab4268d6fb`.
The packet capture SHA-256 is
`711fd4d384bb292561d83ac377fe358dd04da8d013f18cd8bbd16d5164201d34`.

## Consequences

- ADR 0257 remains historical evidence but its tuple is no longer deployable
  as the Phase 9.9 candidate.
- The OpenShift release record and rendered overlay pin only this successor.
- cl02 must accept this exact tuple, preserve Node-local recovery state, prove
  cold controller replacement remains inside the 2-GiB cgroup, and pass the
  complete platform gate before Phase 9 closes.

## Platform result

cl02 rejected this tuple. OpenShift primary-CNI agents resolve
`unf-primary-controller.internal` through a Pod `hostAliases` entry pointing
directly at the host-network controller Node. They therefore bypass the
readiness-aware Service and reached port 9964 while the controller was
unready. One released agent was sufficient to trigger overlapping authority
materializations and an OOM kill. ADR 0260 replaces Service-only admission
with readiness-, concurrency-, and cut-revision enforcement on the internal
API itself.
