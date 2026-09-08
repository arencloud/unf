# ADR 0153: Preserve a loss-explicit Causal Egress Chronicle

**Status:** Accepted and implemented for Phase 8 milestone 8.9a

## Context

Phase 8.5 emits sparse, proof-bound NAT lifecycle events, but the agent only
logged them. That made a live log useful while leaving no bounded API history
after rotation or controller restart. Worse, an operations tool could present
the absence of retained events as evidence that no translation occurred even
when the kernel ring or userspace exporter had dropped observations.

Reading the private gateway NAT map from the controller would appear to fill
that gap, but it would couple operations to Node-local mutable state, expose
sensitive tuples, and still provide no truthful answer after expiry, restart,
or loss. UNF needs useful historical evidence with an explicit statement of
what it does not know.

## Decision

1. Flow-export schema v7 adds a Causal Egress Chronicle record. Its aggregation
   key includes the original dual-stack tuple and source identity plus contract
   revision, lease epoch, translated address/port, address and gateway indexes,
   primary/standby gateway digests, proof witness, flags, and the closed
   action/reason pair. Evidence from different authorities can never collapse
   into one apparent outcome.
2. The agent converts only already validated 152-byte egress ABI records. Export
   remains non-blocking and shares the bounded authenticated telemetry channel.
   Aggregation preserves the minimum and maximum kernel monotonic timestamps.
3. The agent reports the cumulative per-CPU kernel-ring drop total even when no
   lifecycle record survived the ring. A loss-only update therefore reaches the
   controller. Userspace queue loss remains independently cumulative.
4. The controller binds the batch to the authenticated authoritative Node,
   independently checks address family, source identity, action/verdict,
   contract/lease, gateway and proof witnesses, timestamps, and schema, then
   rejects partial or mislabeled provenance.
5. The existing bounded history and ConfigMap checkpoint advance to schema v7.
   Per-Node loss baselines are durable, so a controller restart neither recounts
   old loss nor erases it. Schema-v5 policy/service and schema-v6 advanced
   service exports remain explicitly compatible; egress evidence is accepted
   only in v7.
6. `GET /v1/egress/history` returns only observed egress lifecycle outcomes and
   an evidence summary. Completeness is one of `complete`, `loss_observed`,
   `history_evicted`, or `durable_history_omitted`. More conservative states win.
   The response always reports `private_nat_state_inferred: false`; `unfctl`
   renders the completeness barrier and causal NAT tuple directly.
7. Chronicle data is observational. Its types contain no lease acquisition,
   address ownership, reachability, source activation, NAT insertion, or HA
   promotion capability. It cannot become dataplane or failover authority.

## Consequences

Operators can correlate an observed translation with the exact immutable
authority that produced it across controller restart. They can also distinguish
“no retained event” from “complete evidence says none”: any known loss,
eviction, or persistence omission remains visible. The design intentionally
refuses to reconstruct unknown private NAT mappings. This sacrifices a
comforting guess in favor of an actionable and machine-readable uncertainty
boundary.

The shared flow-history capacity is conservative: eviction or durable omission
of any flow marks egress evidence incomplete even when the omitted flow might
not have been egress. A future independently capacity-budgeted chronicle may
narrow that uncertainty, but must never weaken it.

## Verification

`make egress-operations-history-test` verifies ABI-to-export conversion,
contract/lease/gateway/proof preservation, timestamp aggregation, cumulative
kernel-loss accounting, checkpoint/restart baselines, schema-v5/v6
compatibility, authenticated controller validation, egress-only API filtering,
zero-proof rejection, CLI rendering compatibility, and strict Clippy across
state, agent, controller, and CLI.
