# ADR 0137: Proof-carrying split-brain-safe HA promotion

**Status:** Accepted and implemented for Phase 8 milestone 8.6b

## Context

The Phase 8.6a CCR planner precomputes where every address shard should move
after a gateway failure. A placement decision is not permission to move
ownership. If a controller promotes from Kubernetes `Ready=False`, an isolated
gateway may still own the address and forward traffic. Letting the replacement
claim the same `/32` or `/128` would create split brain, duplicate neighbor
ownership, and nondeterministic reverse NAT.

The safe order also starts at sources. Existing source Nodes must stop steering
new flows toward affected shards before old ownership changes. After isolation,
replacement ownership and the independent reachability provider must both be
read back before a source may install the contingency.

## Decision

UNF uses a schema-v1 proof-carrying promotion protocol. An immutable manifest
binds controller and promotion epochs, authority revision, intent/allocation/
lease identity, active CCR plan, exact contingency, failed Node UID, affected
dual-stack shard handoffs, and every exact source Node UID.

Promotion is monotonic:

1. Every named source installs an inactive/fenced shard set and returns exact
   plan-, epoch-, bank-, and manifest-bound readback.
2. The old gateway proves the affected addresses absent, or an independent
   infrastructure isolation plane supplies a positive versioned fence token.
3. Each replacement gateway proves the exact addresses for its assigned
   shards present in kernel state.
4. The reachability provider compare-and-swaps from the active plan digest to
   the certified contingency digest and returns the exact handoff set.
5. Only the complete canonical evidence union creates an activation authority.

Kubernetes Node readiness and Node Lease observations can trigger orchestration
but are explicitly rejected as fence providers. Timeouts and controller
leadership also grant no authority. Graceful removal and abrupt infrastructure
fencing are separate evidence variants, while all downstream stages share the
same checks.

The final authority embeds all source, isolation, acquisition, and
reachability witnesses. A consumer validates exact contents before checking the
outer domain-separated digest, so recomputing the digest cannot hide a mutated
address set. Duplicate, partial, stale, foreign, concurrent, or reordered
evidence fails closed.

## Consequences

`make egress-ha-promotion-test` exercises graceful and abrupt paths, source-first
ordering, rejection of Kubernetes health as fencing, exact replacement
readback, stale promotion epochs, and inner-evidence mutation with a recomputed
outer digest.

This is the safety authority for promotion, not yet a live availability claim.
Milestone 8.6c must define established-flow continuity and atomic complete-table
activation. Later 8.6 slices must integrate the protocol with watched
controller/agent state and measure failure, drain, recovery, and split-brain
behavior on the dual-stack Kind fixture.
