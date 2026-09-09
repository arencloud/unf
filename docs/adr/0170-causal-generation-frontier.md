# ADR 0170: Causal Generation Frontier

**Status:** Accepted and implemented for Phase 9.5i

## Context

Node-Sealed Generation Capsules make one delivery an exact successor, but a
controller-side map of independent Node checkpoints can still advance Nodes at
different rates. If the producer replaces generation N with N+1 before a slow
Node has durably admitted N, that Node cannot accept N+1 without violating the
predecessor chain. Publishing only part of a cluster cut can also expose policy,
Service, or egress revision skew across encrypted paths.

Keeping an unbounded generation history would hide the ordering error while
adding memory, recovery, and replay complexity. Treating Node name as ownership
would also let a recreated Node inherit the old member's desired authority.

## Decision

UNF introduces the **Causal Generation Frontier**: one canonical, digest-bound,
cluster-complete cut of prepared per-Node checkpoints. Issuance requires:

1. an exact authoritative member set with no missing, extra, or duplicate Node;
2. one prepared checkpoint per exact Node name and UID;
3. a common generation, transaction, policy, Service, and egress revision;
4. one common trust domain and transport authority whose local Node UID equals
   its recipient; and
5. independently replayable checkpoint and frontier digests.

The controller holds the frontier behind a single publication authority. An
authenticated agent's exact durable cursor becomes a receipt for its current
member cut, but remains explicitly distinct from kernel or packet proof. The
producer cannot publish the next frontier until every member has acknowledged
the current one. The successor must keep the exact membership and UID set and
each new checkpoint must name that member's exact published predecessor.
Identical frontier replay is idempotent.

This is **slowest-member causal backpressure**: bounded memory remains O(Nodes),
there is no partial successor and no skipped predecessor to repair. Membership
change and Node replacement intentionally require a later explicit retirement
protocol rather than silently weakening the active cut.

The authenticated generation endpoint now reads through this producer and
records an acknowledgement only when its Node-scoped cursor exactly equals the
current desired checkpoint. The frontier starts empty, so existing deployments
remain inert until the live authority reconciler supplies a complete cut.

## Consequences

Controller reconciliation can no longer manufacture a mixed-revision fleet or
trade consistency for availability during a partition. The last complete cut
is retained, a lagging Node has exactly one successor to fetch, and a Node-name
reuse cannot acknowledge or receive another UID's checkpoint. This is safer
and more memory-bounded than maintaining an opportunistic per-Node queue.

The deliberate cost is that one unavailable member blocks the next cluster
frontier. Future topology retirement must prove that the removed Node's map and
route authority is fenced before membership changes. This slice provides the
validated publication source and delivery backpressure; it does not yet derive
frontiers from live Kubernetes/key/path facts, persist producer state, invoke
the Node-local WireGuard/route orchestrator, or claim encrypted packets.

## Verification

`make encryption-generation-frontier-test` inherits every Phase 9.5h gate and
proves canonical issuance, complete membership, exact Node-UID/trust-domain
binding, common revisions, digest replay, idempotence, acknowledgement
backpressure, stale acknowledgement rejection, and exact per-Node predecessor
advancement. Controller integration and strict Clippy are included.
