# ADR 0172: Complete-Cut Fact Reconciler

- Status: Accepted and implemented for Phase 9.5k
- Date: 2026-09-09

## Context

The Causal Generation Frontier and Proof-Carrying Frontier Recovery make a
complete fleet cut durable, but the controller previously had no live input
path that could create that cut. Letting the controller invent Node-local
WireGuard or kernel-readback facts would violate the Phase 9 authority split.
Publishing independently as Nodes arrive would instead permit mixed topology,
policy, Service, egress, or key truth.

Common quorum algorithms are also the wrong safety primitive here. A majority
can establish agreement between replicas, but it cannot make a missing Node's
required encryption path safe. Every Node participating in the authoritative
Kubernetes membership is part of the dataplane cut.

## Decision

Phase 9.5k introduces the **Complete-Cut Fact Reconciler**.

Each agent can submit a strict, secret-free `EncryptionGenerationFact` over the
existing Pod-bound TokenReview and TLS boundary. The fact binds:

- one authoritative Node name and UID;
- one exact Kubernetes topology/membership revision;
- the Node's independently prepared proof-carrying Aya checkpoint; and
- a domain-separated digest over the complete nested value.

The controller validates the authenticated Pod placement and current Node UID,
replays the nested checkpoint, and admits the fact into an exact-membership
anti-entropy accumulator. Any membership revision or name/UID change atomically
invalidates all staged facts. A same-generation mutation is equivocation, an
older generation is regression, and a foreign membership revision is stale.
No case replaces last-known-good publication authority.

Publication occurs only when every selected Kubernetes Node has reported the
same generation and the existing Causal Generation Frontier independently
accepts the complete cut. The existing slowest-member acknowledgement barrier
still gates its successor. The final acknowledgement rechecks any already
staged successor, so progress does not depend on another report arriving.

This is deliberately quorumless all-or-nothing admission. It sacrifices
availability when a required member is missing because majority publication
would create an unsafe mixed-truth encryption fabric. Fixed-cardinality
counters report accepted facts and published frontiers without Node labels.

## Consequences

- Controller generation input is now live and authenticated without moving
  private keys or non-serializable kernel authority off the Node.
- Missing, stale, replaced, mixed-revision, regressing, and equivocating Nodes
  cannot produce a partial frontier.
- Topology churn clears staged reports and requires fresh reports for the new
  cut; this is intentional anti-entropy, not data loss.
- The controller still cannot claim WireGuard readiness, route readiness, TC
  attachment, or encrypted workload traffic from these facts alone.
- Agent-side production of these facts and the local WireGuard/route/Aya
  orchestrator are the next Phase 9.5 boundary. Membership removal also remains
  fail closed until an explicit retirement/fence protocol is implemented; it
  is not silently treated as an acknowledgement.

## Verification

`make encryption-generation-reconciler-test` inherits every earlier Phase 9.5
gate and additionally verifies canonical fact replay, exact membership
invalidation, idempotence, stale-cut rejection, unknown-field and digest
mutation refusal, the authenticated controller endpoint, publication retry on
the final predecessor receipt, strict Clippy, and all supported deployment
renders.
