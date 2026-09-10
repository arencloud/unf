# ADR 0190: Authority-Free Quiescent Generation

- Status: Accepted and implemented for Phase 9.5ac
- Date: 2026-09-10

## Context

Demand-sparse fleet planning deliberately gives a Node with no cross-Node
authorized workload path a `Dormant` plan. The local proof pipeline previously
required one active WireGuard epoch, one transport, and one kernel commitment.
Such a Node could persist its plan but could never contribute to the exact
all-member generation frontier, deadlocking active peers or tempting the
controller to omit idle members.

## Decision

UNF introduces an **Authority-Free Quiescent Generation**:

- an authenticated dormant plan compiles to a generation with zero epochs,
  decisions, address paths, transports, WireGuard plans, route rules, and
  kernel commitments;
- the zero shape is accepted only when every authority collection and lowered
  count is also zero. Adding any decision, transport, epoch, path, route, or
  trust domain makes the state invalid;
- the empty state still binds membership, recipient Node UID, generation, and
  policy/Service/egress revisions through the normal map checkpoint, causal
  vector, generation fact, recovery digest, and controller complete frontier;
- the agent compiles a newly durable plan only after Node-local key bootstrap.
  Active plans consume the exact private-key authority and real Linux
  WireGuard readback; dormant plans perform no kernel network mutation;
- one in-flight generation backpressures newer plans. Exact retry is
  idempotent, while plan regression or same-generation revision mutation fails
  closed.

The quiescent state is proof of absence, not a plaintext permission. The packet
path cannot select encryption transport from a zero-epoch bank.

## Consequences

Fleet synchronization no longer pays for tunnels on idle Nodes and never needs
fake peers to satisfy an all-member barrier. Nodes can move between quiescent
and active generations with the same transaction protocol, preserving sparse
resource use at cluster scale.

## Verification

`make encryption-agent-plan-compile-test` inherits Phase 9.5ab and proves exact
empty compilation/replay/recovery, fabricated authority rejection, one-time
agent preparation, in-flight coalescing, active snapshot-first compilation,
and strict Clippy. TC consumption and live packet verification remain later
milestones.
