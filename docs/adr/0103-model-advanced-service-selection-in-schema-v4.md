# ADR 0103: Model advanced Service selection in schema v4

**Status:** Accepted and implemented for the Phase 7.2 domain/compiler boundary

## Context

Service schema v3 owns ClusterIP, NodePort, and explicit-class LoadBalancer
intent, but it cannot distinguish internal locality, session affinity, topology
preference, algorithm choice, or forwarding mode. Encoding those semantics in
map flags first would couple Kubernetes strings to persistent state and make an
old agent appear converged while ignoring behavior that changes backend choice.

## Decision

Schema v4 adds Kubernetes-independent, typed fields to each Service:

- internal traffic policy: `Cluster` or `Local`, default `Cluster`;
- session affinity: `None` or `ClientIp { timeout_seconds }`, with the
  Kubernetes 10,800-second default and exact 1–86,400 second bound;
- traffic distribution: `Any`, `PreferSameZone`, or `PreferSameNode`, with
  Kubernetes `PreferClose` canonicalized to `PreferSameZone`;
- selection algorithm: `StableHash` or `Maglev`, default `StableHash`; and
- forwarding mode: `Nat` or `Dsr`, default `Nat`.

The Kubernetes adapter validates and defaults the standard Service fields.
Algorithm and forwarding intent currently retain safe defaults; their native
API admission is a later gate. Unsupported values and contradictory affinity
configuration reject the candidate so controller last-valid state is retained.

Default-valued fields are omitted on the wire. Schemas v1, v2, and v3 therefore
migrate exactly to v4 default behavior, and a current controller can project a
safe old view only when advanced intent is absent. Advanced intent makes legacy
projection fail closed. New agents accept schema v3 during controller-first
rollout. Existing ClusterIP, NodePort, and LoadBalancer lowerers accept default
v4 state but explicitly reject advanced intent until transactional Phase 7
selection state exists.

## Consequences

- Milestone 7.2 is a domain/compiler claim, not dataplane support.
- Four-version negotiation is explicit; schema capability cannot falsely
  acknowledge advanced intent.
- `ClientIP` is a selection key only and does not become identity authority.
- Endpoint/Node tier compilation, affinity maps, Maglev tables, DSR host state,
  operations, and platform qualification remain later milestones.
