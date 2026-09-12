# ADR 0267: Immutable Delivery-Leased Kind Requalification

## Status

Rejected by Phase 9.9 OpenShift qualification; immutable Kind evidence retained

## Context

ADR 0266 extends the bounded-fair authority admission permits through response
body completion or disconnect. That lifetime correction changes the controller
runtime image and must pass an independent fresh-cluster qualification before
the preserved-state OpenShift cluster can consume it.

## Decision

Revision `30266627f42321cd90613c00cb5ba71ac648e02f` is the sole admitted Phase
9.9 candidate. Its anonymously resolvable public Linux/amd64 images are:

- controller: `quay.io/arencloud/unf-controller-dev@sha256:936f6ef5da7f08234f2e3d34f10484f100837044d6071ba1c911262bdcd6352a`;
- agent: `quay.io/arencloud/unf-agent-dev@sha256:ed7eca8069dcf3c8b483d04cafc423cf254ba375ecd3ab82666beaf37c3fffa4`;
- test tools: `quay.io/arencloud/unf-test-tools-dev@sha256:e9cce439d92d0f7d3d6751f234e397a7efc29f9983bc0ae8fc318432c4ff2352`.

They are also published under diagnostic tag `phase9-kind-3026662`. Runtime and
qualifier revision `30266627f42321cd90613c00cb5ba71ac648e02f` passed
`make encryption-phase9-kind-test` on a newly created three-Node, dual-stack
Kubernetes v1.35.0 cluster with kube-proxy absent. The uninterrupted gate
proved:

- default-Required and explicit-selective IPv4/IPv6 PodIP and ClusterIP paths;
- 404 WireGuard underlay frames, zero Required plaintext frames, and 311
  explicit-Native plaintext frames;
- eight of eight Required fault probes blocked while eight of eight Native
  probes succeeded;
- natural two-epoch rotation, controlled agent and controller replacement, and
  295 loss-free causal operation records;
- 32 bounded performance requests against the committed regression ledger;
- Phase 8 egress coexistence and exact encryption/fixture cleanup; and
- complete primary-CNI rollback to the saved no-CNI baseline.

The evidence JSON SHA-256 is
`7801aa7d09e5a8caea3e1168b4f45afdc15f330ce6d80c1192eaecade9ea0775`.
The packet capture SHA-256 is
`aff51bb96ba6ca85b59d76ea7400749613ad021a9da4bb0d5ce5ffb46d1ecf03`.

## Consequences

- ADR 0265 remains the historical proof of bounded-fair admission and the
  response-lifetime failure found on cl02; its tuple is no longer deployable.
- The preserved-state cl02 deployment accepted this exact tuple on five Nodes,
  but the Required migration exposed per-plan full-contract duplication and
  repeatedly exceeded the controller memory limit before generation advance.
- This tuple must not be redeployed as the Phase 9.9 candidate. ADR 0268 defines
  the contract-deduplicated successor boundary; this ADR's Kind evidence remains
  historical and immutable.
