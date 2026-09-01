# ADR 0110: Preserve and explain advanced Service-selection outcomes

**Status:** Accepted and implemented for Phase 7.8

## Context

Milestones 7.4–7.7 put the selected locality tier, actual selection algorithm,
affinity result, and NAT/DSR mode into the fixed 96-byte service event. The
agent validated those fields, but the operations path retained only the
frontend, backend, revision, action, and reason. That made packet tests exact
without giving operators the same evidence through metrics, status, durable
history, explanation, or simulation.

Treating missing legacy fields as Cluster, StableHash, no affinity, or NAT would
fabricate evidence during a rolling upgrade. Simulation also cannot truthfully
predict an already-established connection or inspect an agent's private LRU
affinity map from the controller.

## Decision

Flow-export schema v6 and history snapshot/checkpoint schemas v7/v6 preserve
four typed, bounded outcome dimensions: selection tier, affinity outcome,
actual algorithm, and forwarding mode. They are part of the aggregation key so
different outcomes cannot collapse into one history entry. Schema-v5 exports
and older checkpoints remain readable, but omitted dimensions deserialize as
explicit `unknown` values. Current-schema exports containing `unknown` fail
validation.

Agent-status schema v8 exposes fixed-name counters for SameNode, SameZone,
Cluster, StableHash, Maglev, affinity reuse/create/reselection, NAT, and DSR,
plus the last complete typed decision witness. The controller requires the
tier, algorithm, and forwarding totals to equal translation totals, bounds
affinity totals by translations, and rejects partial last witnesses. Schema-v6
and schema-v7 reports remain accepted only without advanced fields. Metrics use
the same fixed names and introduce no Service, backend, Node, revision, or
address labels.

Service explanation retains the complete durable outcomes and adds an
observation-weighted fixed-cardinality summary across exact Service revisions.
Current intent reports internal policy, topology distribution, affinity,
algorithm, forwarding mode, ready new-flow backends, and terminating-serving
backends so graceful drain state is distinct from per-flow affinity and
connection persistence.

ClusterIP, NodePort, and LoadBalancer simulations resolve the exact first
non-empty tier from a freshly compiled, digest-bound per-Node Network Behavior
Contract. They return the contract revision and digest, tier, ordered eligible
backends, algorithm, affinity intent, forwarding mode, and allow/drop decision.
LoadBalancer simulation additionally remains allocation-, reachability-, and
source-range-exact. Simulation is read-only and does not claim which backend an
existing connection or private affinity entry will reuse.

Persistent eBPF ownership stays at ABI v11: the event already carried all four
fields and no map layout or recovery ownership changed. Controller flow-history
checkpoint recovery and the inherited ABI-v11 agent reconstruction gate cover
the two durable owners independently.

## Compatibility and recovery

- Upgrade order is controller before agent. The v8/v6 controller accepts the
  adjacent v7 status and v5 flow export without inventing advanced evidence.
- A new agent accepts controller compatibility tuples advertising either the
  adjacent or current status/export generation. Once it emits v8/v6 evidence,
  an older controller is intentionally incompatible rather than silently
  dropping fields.
- Durable history checkpoint v6 reads all earlier supported checkpoints and
  writes only the current schema. Unknown future schemas remain rejected.
- Durable agent acknowledgements continue to discard older status generations
  on controller restart; live agents republish current validated status.
- No eBPF map cleanup, pin path, or cold-reconstruction rule changes in this
  milestone.

## Evidence

`make service-selection-operations-test` inherits the complete DSR/NAT,
Maglev, affinity/draining, locality/topology, verifier, recovery, and cleanup
gates. It then verifies event-to-metric/status/export preservation,
fixed-cardinality status validation, v5/v6 and v7/v8 adjacent transitions,
durable checkpoint migration, observation-weighted explanation, digest-bound
read-only simulation for all three frontend origins, exact CLI queries, and
strict Clippy.

Kind and OpenShift remain independent Phase 7.9 and 7.10 runtime gates. This
milestone does not turn workstation evidence into a platform claim.

## Consequences

- Operators can correlate desired intent, exact per-Node contract, observed
  backend, locality, algorithm, affinity behavior, forwarding mode, and
  revision without high-cardinality metric labels.
- Legacy observations remain useful but visibly incomplete.
- Read-only simulation is exact for current authoritative eligibility and
  control-plane decisions; private connection and affinity state remains agent
  runtime evidence and is never guessed.
- The next milestone can qualify operations and recovery on kube-proxy-free
  dual-stack Kind without another operations schema change.
