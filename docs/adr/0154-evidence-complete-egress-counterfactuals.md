# ADR 0154: Make egress counterfactuals evidence-complete and non-authoritative

**Status:** Accepted and implemented for Phase 8 milestone 8.9b

## Context

An operator asking why an egress flow failed needs one answer spanning policy,
intent, allocation, gateway ownership, contract distribution, external
reachability, source activation, NAT observations, and failover. Reporting only
the current desired state hides expired or missing evidence. Predicting a
private NAT mapping from desired state is worse: it presents a tuple that the
gateway may never have created.

Completed HA transactions were also removed after finalization. The active
coordinator remained safely bounded, but post-incident analysis lost the
terminal transition that joined the old and replacement ownership plans.

## Decision

1. `POST /v1/egress/explain` and `POST /v1/egress/simulate` accept one concrete
   source Pod, destination address, protocol, and port. They evaluate the
   egress NetworkPolicy decision and the normalized priority-ordered egress
   intent over one immutable controller snapshot.
2. The response joins policy, intent, allocation, gateway acknowledgement,
   source contract, DQR assessment, source activation, Causal Egress Chronicle,
   transport support, and HA evidence. Every layer is classified as
   `authoritative`, `observed`, `derived`, `expired`, `unavailable`, or
   `loss_affected`; absence is never silently promoted to a negative fact.
3. The counterfactual result is one of `policy_denied`, `native_routing`,
   `fenced`, or `eligible`. `eligible` is a derived prediction, not activation
   authority. The response is structurally incapable of carrying grants or
   writable capabilities and always states `private_nat_state_inferred: false`.
4. Terminal HA promotion state is compacted into a 256-record SHA-256 chain.
   Each record binds the owner, epochs, revisions, lease, failed gateway,
   manifest, previous/replacement plan, activation authority, fence kind,
   source completion, moved shards, and acknowledged Flow Twins. Eviction
   retains the last removed digest as a verifiable chain anchor and an explicit
   count. Control-plane checkpoint schema v6 persists and validates this ledger;
   schemas v2–v5 remain readable only with empty history.
5. `GET /v1/egress/failovers` and `unfctl egress-failovers` expose the bounded
   terminal ledger. `unfctl egress-explain`, `egress-simulate`, and
   `egress-history` expose the other operations surfaces.
6. Controller status adds only fixed-cardinality scalar totals for intent,
   allocation, gateway, reachability, HA, Chronicle, and history-loss state. No
   owner, Pod, address, or tuple becomes a metric/status label.

## Consequences

One answer can distinguish an explicit policy denial, native routing, a
fail-closed missing dependency, and a currently eligible managed path. Temporal
destination and reachability evidence can be shown as expired, while telemetry
loss and history eviction remain visible barriers to certainty.

The API does not promise that an eligible packet was sent, that a NAT mapping
exists, or which translated source port would be selected. Historical records
are tamper-evident within the persisted chain but are not an external
transparency log. Cross-controller replication and external anchoring remain
future work.

## Verification

`make egress-operations-causal-test` verifies terminal HA compaction, mutation
rejection, bounded eviction and anchor replay, read-only explicit/native
counterfactuals, missing-authority classification, CLI parsing/query surfaces,
and strict Clippy for the egress, controller, and CLI crates.
