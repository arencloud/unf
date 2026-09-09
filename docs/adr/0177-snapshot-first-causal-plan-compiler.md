# ADR 0177: Snapshot-First Causal Plan Compiler

- Status: Accepted and implemented for Phase 9.5p
- Date: 2026-09-10

## Context

Phase 9.5o can safely consume and rehydrate a Node-local generation, but the
inputs had previously been assembled only by fixtures. Naively compiling the
map image first is circular: its transport authority commits to exact kernel
interface indexes and configuration digests that exist only after WireGuard
staging. Creating one tunnel per identity or policy would avoid none of that
cycle and would scale with the wrong cardinality.

## Decision

Phase 9.5p introduces the **Snapshot-First Causal Plan Compiler**.

For each active or draining epoch it independently verifies the attested
contract, folds the identity-pair Cartesian product into one canonical peer per
destination Node, derives one safe MTU envelope and one inactive WireGuard
interface plan, and rejects conflicting peer, route, mark, key, or Node
authority. All Node-local keys are preflighted before the first mutation.

The Linux path then stages each bounded epoch through the existing transactional
kernel provider and obtains fresh exact readback. Only those observed interface
indexes and configuration digests can create committed kernel transactions,
the coalesced fast-path generation, and its prepared map checkpoint. That
checkpoint finally enters the existing capability-typed exchange and activation
pipeline.

This ordering is intentionally asymmetric:

1. identity and policy authority determines required paths;
2. contracts determine a bounded Node/epoch plan;
3. real kernel readback determines transport facts; and
4. those facts determine map authority.

No later stage can manufacture evidence for an earlier one. Private-key
authority is borrowed only by the local provider and is never persisted or
serialized by the compiler.

## Consequences

- Tunnel count is `O(Node peers × at most two epochs)`, independent of policy
  and workload count, while every identity decision remains exact in eBPF.
- A compiler failure after staging leaves only isolated, unselected interfaces;
  it cannot publish policy routes or a map generation.
- Input order cannot change the canonical peer set, transaction, checkpoint,
  or recovery plan.
- Partial readback, a replacement Node UID, mixed epoch transport facts,
  conflicting destinations, or revision skew fails closed.
- The running agent still needs an authenticated, durable source for contracts,
  readiness, decisions, and its Node key authority. That is the next slice.

## Verification

`make encryption-local-plan-compiler-test` inherits every Phase 9.5o gate,
checks the key/readback/map ordering structurally, proves multiple identity
pairs coalesce to one Node peer and transport without losing decisions, rejects
partial and foreign authority, and applies strict Clippy.
