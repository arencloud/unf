# ADR 0136: Continuity-Certified Rendezvous HA planning

**Status:** Accepted and implemented for Phase 8 milestone 8.6a

## Context

Milestone 8.5 proves one live dual-stack egress gateway. Simply giving every
eligible gateway the same address would create duplicate L2 ownership and
ambiguous reverse traffic. Plain rendezvous hashing minimizes disruption when a
member disappears, but it does not enforce an exact capacity bound, preserve
failure-domain diversity, or state the disruption before activation. A
health-sensitive algorithm in eBPF would also make Nodes disagree and add work
to every packet.

Multiple egress addresses provide a safer unit of ownership. Same-ordinal IPv4
and IPv6 addresses represent one dual-stack continuity shard. A shard can have
one active gateway while an independently fenced promotion protocol later moves
both families together. The planner must remain provider neutral because L2,
BGP, cloud, and future reachability providers have different activation
mechanisms but need the same deterministic ownership decision.

## Decision

UNF uses Continuity-Certified Rendezvous (CCR) algorithm v1. CCR accepts one
exact allocation lease and two to sixteen canonical gateway candidates. Each
candidate has bounded integer capacity units and up to eight explicit failure
domains. Candidate ordering is normalized before any digest or decision.

CCR groups the first IPv4 and first IPv6 address into shard zero, the second
pair into shard one, and so on. A single-family remainder is still a valid
shard. Largest-remainder integer apportionment derives an exact number of
active shards per gateway without floating point. Domain-separated SHA-256
scores resolve every tie deterministically.

On a membership or capacity change, CCR retains exactly the best
`min(previous ownership, new target)` shards for each surviving gateway. Only
unretained shards enter deterministic placement. The sum of ownership above
new targets—including removed gateways—is an independent lower bound on the
number of necessary moves. Compilation fails unless the achieved move count
equals that bound and every capacity target is exact.

For each candidate, CCR also compiles the entire placement with that gateway
absent. Shards that must leave the failed gateway prefer candidates sharing the
fewest explicit failure-domain values before applying their rendezvous score,
subject to exact survivor capacity. Each contingency binds the failed Node UID,
all assignments, targets, diversity count, and disruption certificate into a
digest. The complete plan separately binds membership and all contingencies.
Consumers recompile from authoritative lease and candidate input; serialized
digests or certificates are never trusted by themselves.

The compiler is bounded by sixteen addresses and sixteen gateways. All scoring,
capacity, and topology work happens outside eBPF. A future source dataplane will
consume one fixed active assignment table and atomically replace it with an
already certified contingency.

## Why this is different

CCR deliberately combines properties that are commonly treated separately:

- exclusive dual-stack address ownership rather than duplicate active L2
  addresses;
- exact heterogeneous capacity rather than best-effort statistical balance;
- mathematically minimum reshuffling rather than an undocumented churn claim;
- topology-aware single-failure contingencies rather than a single flat backup;
- precomputed, replay-verifiable blast radius rather than packet-path health
  heuristics; and
- constant packet-path lookup cost regardless of planner sophistication.

The name is an UNF algorithm designation, not a claim that its component ideas
replace the published work on rendezvous hashing, consistent hashing with
bounded loads, or Maglev. The new contribution here is their bounded,
provider-neutral composition around lease-fenced egress-address shards and
proof-carrying failover plans.

Related foundations include Google's published
[Maglev](https://research.google/pubs/maglev-a-fast-and-reliable-software-network-load-balancer/)
design and
[Consistent Hashing with Bounded Loads](https://research.google/pubs/consistent-hashing-with-bounded-loads/).

## Consequences

`make egress-ha-planner-test` verifies dual-stack shard formation, weighted
capacity, byte determinism, exact replay, minimum movement under capacity
change, every single-gateway contingency, failure-domain preference, and
fail-closed malformed/mutated state.

This slice makes no availability claim. Milestone 8.6b must define a
monotonic promotion authority and prove that old address ownership is revoked
or independently fenced before a contingency activates. Later 8.6 work must
define established TCP/UDP behavior, transfer or reconstruct only valid NAT
state, exercise abrupt failure and graceful Node drain, and measure disruption
on the live dual-stack fixture. Until those gates pass, CCR output is planning
evidence only.
