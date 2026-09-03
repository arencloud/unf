# ADR 0131: Publish Node-bound source-retirement evidence

**Status:** Accepted and implemented for the Phase 8.5 source-retirement slice

## Context

ADR 0130 defines the exact Proof of Safe Forgetting required before an egress
address can be reused. Its source component must be produced by the Node that
actually owns the source maps. A controller cannot safely infer fencing from a
deleted desired object, a disconnected agent, an empty distribution cache, or
the passage of time.

The controller previously invalidated admitted source state before deriving the
withdrawal. That ordering discarded the only authoritative source set from
which a complete retirement manifest could be frozen.

## Decision

The live controller snapshots the admitted source projections before desired
state invalidation. It reconciles allocation/gateway withdrawal and registers
every new retirement manifest on a cloned control-plane transaction; only the
complete result is committed. Failure invalidates active distribution but does
not partially mutate the release transaction.

Two internal TLS endpoints reuse the existing TokenReview-authenticated
ServiceAccount/Pod/Node trust path:

- `GET /v1/state/egress-source-retirements` returns a strict bounded challenge
  carrying the current controller epoch and only manifests containing the
  caller's authoritative Node name and UID;
- `POST /v1/state/egress-source-fence` accepts the exact source union only from
  that same current Pod/Node identity and epoch.

On a `204` source withdrawal, the agent first atomically converts active state
to destination-preserving `Fenced`, removes address/path/selection authority,
and clears source connection state. It then validates the sealed challenges and
publishes evidence from its retained admitted projection and active bank.
Evidence is replayable and may be republished after controller runtime-state
loss. Controller restart changes the challenge epoch, preventing old bearer
evidence from being adopted into the new authority.

## Consequences

Deletion no longer destroys the source-membership information needed to prove
safe retirement. A replacement Pod, stale controller epoch, foreign Node UID,
partial source set, or unregistered manifest cannot contribute release
evidence. Missing evidence preserves quarantine.

This slice stores accepted source evidence but does not yet assemble or consume
the final authority. Gateway empty-projection/NAT-drain evidence and independent
reachability withdrawal are still required. Agent restart without a retained
projection may delay evidence and therefore release; it cannot cause unsafe
reuse. Durable readback-only source reconstruction remains an operations gate.

`make egress-source-retirement-test` inherits the complete Phase 8.5 gate and
adds exact manifest-capture, Node scoping, Pod replacement, controller epoch,
strict challenge, agent publication-order, and Clippy checks.
