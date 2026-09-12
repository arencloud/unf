# ADR 0264: Bounded Fair Authority Admission

## Status

Accepted for Phase 9.9 implementation and requalification

## Context

ADR 0260's zero-waiter admission prevented controller OOM, but the ADR 0263
cl02 gate demonstrated starvation at realistic preserved cluster cardinality.
Every agent continuously reconciles identity, policy, Service, LoadBalancer,
egress, encryption, and status authority. Rejecting every collision made those
independent loops race again immediately. After five minutes all agents were
Ready and on current state, yet transient errors could not clear, two reports
were stale, and controller convergence remained zero of five.

The controller itself stayed within 104–189 MiB RSS with zero restarts. The
correct requirement is therefore one expensive materialization, bounded memory,
and guaranteed progress for requests that have already been admitted.

## Decision

The internal API uses **Bounded Fair Authority Admission**:

1. Exactly one authority materialization runs at a time, preserving ADR 0260's
   peak-memory invariant.
2. At most 16 materialization requests exist inside the admission domain,
   including the active request. Tokio's fair semaphore orders the admitted
   waiters FIFO. A seventeenth request receives immediate `503`, retaining a
   hard constant-space bound.
3. `/v1/version` and authenticated agent-status ingestion form a constant-work
   control lane. They still require controller readiness and remain fenced by
   the informer-cut revision, but cannot be starved behind large snapshots.
4. Agent compatibility preflight applies the same bounded `403`/`503` startup
   retry as the other pre-BPF reads. Invalid compatibility, authentication, or
   exhausted retry budgets remain fatal.
5. A request captures the informer revision only after it reaches the single
   materializer. A relist before or during execution still discards the
   response, so queueing cannot bridge authority cuts.

The queue retains only request state; response and snapshot construction starts
after the single permit is acquired. The bound is independent of Node, Pod,
policy, Service, and endpoint cardinality.

## Consequences

- Admitted materializations make FIFO progress instead of joining a retry
  storm, while overload remains explicit and constant-space.
- Compatibility and freshness reporting remain available during heavy
  reconciliation without bypassing readiness or cut fencing.
- The agent never opens persistent BPF state while compatibility admission is
  transiently unavailable.
- Focused tests, full workspace validation, a new fresh Kind lifecycle, new
  immutable images, and the complete cl02 gate are mandatory.
