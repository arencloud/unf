# ADR 0226: Immutable Retirement-Ordered Kind Requalification

- Status: Accepted and verified for Phase 9.9 release admission
- Date: 2026-09-11

## Context

ADRs 0223–0225 changed controller persistence/recovery and replacement-agent
key/startup ordering after the prior Phase 9.8 qualification. Phase 9.9 cannot
deploy a source-only fix or infer safety from focused tests. The exact combined
runtime must repeat the complete fresh-cluster gate and be published by registry
manifest digest before OpenShift migration.

## Decision

Revision `ec76916aae136b3aba7f42ea00d058b3cf63f795` is the only admitted
Phase 9.9 development tuple for the next cl02 attempt. The same revision built
the controller and agent and qualified the gate; the unchanged test-tool image
was republished under the same qualification tag. Anonymous registry inspection
proved all three referenced manifests are Linux/amd64 images:

- controller: `quay.io/arencloud/unf-controller-dev@sha256:3c52ed0f354dfe8af3c73ddb5a977e1693bf43f62463c413605d4ff321131939`;
- agent: `quay.io/arencloud/unf-agent-dev@sha256:6275ffefeb19efec0d44cc85921b9726278907e3cdcb63dd606ef13017e8e800`;
- test tools: `quay.io/arencloud/unf-test-tools-dev@sha256:e9cce439d92d0f7d3d6751f234e397a7efc29f9983bc0ae8fc318432c4ff2352`.

The OpenShift overlay and schema-v1 release record use only those digests. A tag
is discovery metadata and grants no deployment authority.

## Evidence

`make encryption-phase9-kind-test` passed on a newly created three-Node
dual-stack Kubernetes v1.35.0 cluster. The test required exact component build
revisions and image IDs, default-Required plus explicit-Native IPv4/IPv6 PodIP
and ClusterIP traffic, eight-of-eight Required denials during peer loss beside
eight-of-eight Native successes, natural epoch rotation, controlled agent and
controller replacement, loss-free operations history, Phase 8 egress
coexistence, performance bounds, exact cleanup, and no-CNI rollback.

The schema-v1 evidence SHA-256 is
`a975dcccd2c0b70aa534eff389686404bd40177e3655120d6ab262e147d8bcd3`.
The independently captured packet evidence SHA-256 is
`4b15c00a3f8693893cd4ee5bbd24c5b56eb87f2ba49962c34d43cd48aefc2ce4`;
it records 381 WireGuard frames, zero Required plaintext frames, and 312 Native
plaintext frames.

## Consequences

- The replacement-agent regression is proven in its real rotation lifecycle,
  not only by a unit test.
- Earlier development image digests remain historical evidence but are no
  longer eligible for the Phase 9.9 cl02 rollout.
- This result admits the exact tuple to OpenShift qualification; it does not by
  itself qualify RHCOS, SELinux, CRI-O, or five-Node behavior.
