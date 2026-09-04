# ADR 0147: Authenticate and durably order Internet classifier publications

**Status:** Accepted and implemented for Phase 8 milestone 8.7f

## Context

Authority-Carved Internet defines how a complete classifier snapshot becomes a
bounded dual-stack packet decision, but a safe algorithm also needs an explicit
publisher boundary and durable lifecycle. Watching an unauthenticated feed,
forgetting the last revision when an object disappears, or distributing a new
classification before it is recoverable would permit replay, split authority,
or restart-dependent policy.

The lifecycle must preserve classifier independence. Agents consume sealed
classification results; they do not receive permission to publish those
results, and neither Kubernetes object presence nor controller availability may
extend an expired packet deadline.

## Decision

1. `EgressInternetClassification` is a cluster-scoped Kubernetes API for one
   complete classifier publication. The API carries classifier name/instance,
   source epoch, revision, observation and validity times, and canonical
   IPv4/IPv6 `Internet` or `NonInternet` prefix rules with provenance.
2. Publishing is opt-in. The unbound
   `unf-internet-classifier-publisher` ClusterRole grants only classifier-object
   operations. The controller may read the objects; the agent ServiceAccount
   cannot create them. A deployment binds the publisher role only to its chosen
   classifier identity.
3. A bounded classifier store independently verifies every publication and
   permits one current Kubernetes source per classifier identity. Ordering is
   monotonic by `(sourceEpoch, revision)`. Deletion removes current authority
   but retains the latest position, so relist, restart, and object recreation
   cannot erase replay or same-position-mutation protection.
4. Current publications, retained positions, and exact per-intent materialized
   snapshots share one canonical domain-separated SHA-256 checkpoint in the
   controller's durable desired-state ConfigMap. The controller persists a
   changed classification and its materialization before issuing replacement
   source or gateway distributions.
5. Publication loss may enter explicit `LastKnownGood` immediately, including
   before the signed classification's validity deadline. Its absolute authority
   remains capped at `classification.validUntil + maxStaleness`; loss never
   restarts that clock. Controller and agents independently verify the exact
   preceding digest and the same deadline. At expiry, packet-path monotonic
   deadlines deny new traffic without a controller event.
6. Watch initialization is transactional: a complete relist replaces the
   current object set only after every object verifies. Invalid, duplicate,
   regressed, mutated, oversized, future, or noncanonical input retains the
   previous durable and distributed authority.

## Consequences

- Operators can run route, RPKI, cloud, enterprise, or composed classifier
  publishers without embedding them in UNF's controller or granting them agent
  authority.
- A deleted publication has deterministic behavior across controller restart:
  bounded LKG if policy explicitly requested it, otherwise deny-closed.
- Source and gateway agents reject semantic skew independently. A rolling change
  to classification invariants therefore requires compatible controller/agent
  rollout handling, just like other behavior-contract changes.
- This milestone does not provide a production classifier implementation,
  DNSSEC, passive DNS capture, BGP/BFD reachability, scale qualification, or
  OpenShift qualification. Those remain separate provider and platform gates.

## Verification

`make egress-internet-lifecycle-test` inherits the Authority-Carved Internet and
three-node service-fabric gates. Focused tests cover API/CRD equality,
translation, canonical checkpoint recovery, publication loss before and after
validity expiry, relist, replay, mutation, duplicate ownership, and strict
linting. The dedicated kube-proxy-free dual-stack Kind lifecycle proves
publisher RBAC, agent denial, durable-before-distribution ordering, current
Internet traffic, absolute exceptions, provider-negative and unknown denial,
digest-linked LKG across controller restart, autonomous deny-closed expiry,
higher-revision recovery, and exact cleanup. It writes schema-v1 evidence to
`.artifacts/phase8-egress-internet-kind.json`.
