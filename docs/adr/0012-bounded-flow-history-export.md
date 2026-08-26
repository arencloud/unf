# ADR 0012: Bounded flow-history export

## Status

Accepted and implemented for flow export schema v2. Extended by
[ADR 0030](0030-durable-flow-history-checkpoint-and-time-windows.md).

## Context

The TC program already emitted compact revisioned flow events, but agents only
wrote them to structured logs. Policy simulation therefore had no historical
input, and introducing an unbounded queue or mandatory database would violate the
overlay's networking-first failure model and the Phase 3 scope.

## Decision

Flow export schema v2 defines a backend-neutral Rust/JSON contract in `unf-state`.
Each record identifies a logical source/destination identity and exactly one
complete IPv4 or IPv6 address pair,
protocol, destination port, last observed actual/shadow provenance, policy
revision, and aggregated observation count.

Agents export only events with a resolved destination identity. The ring-buffer
consumer uses non-blocking `try_send` into a 4,096-record channel. A separate task
aggregates at most 2,048 logical keys and sends batches of at most 512 records to
`POST /v1/telemetry/flows`. Full channels/aggregators drop telemetry immediately,
increment a cumulative metric/status counter, and never block or alter forwarding.
Failed HTTP exports retain the bounded pending set and increment an error metric.

The controller rejects incomplete or mixed-family address pairs and retains at
most 4,096 logical keys in
memory. Oldest-received keys are evicted deterministically. Schema v1 snapshots
from `GET /v1/flows` report revision, capacity, retained observations, evictions,
cumulative agent drops, reporting Nodes, last provenance, and workload references
that still resolve in current topology. `unfctl flows` renders the snapshot in
table, JSON, or YAML form.

Policy simulation schema v2 fences the flow-history revision and reports
historical results separately from representative topology probes. It evaluates
unique retained keys through the same current/proposed policy evaluator, weights
impact by observation count, reports affected Services, and explicitly counts
flows skipped because their identities no longer resolve.

## Consequences

Networking correctness does not depend on telemetry delivery, and open-source UNF
requires no external database. The HTTP schema is the clean exporter boundary;
generic plugins are deferred until multiple real transports exist.

History remains bounded advisory telemetry and can contain duplicate
interface-level observations. ADR 0024 subsequently moved ingestion behind the
CA-pinned, Pod-bound authenticated internal transport. ADR 0030 adds a bounded
ConfigMap checkpoint plus inclusive last-received-time windows while retaining
the failure-priority contract. External durable backends, event-time buckets,
deduplication, and sampling remain future work; history must not become
authoritative enforcement input.

Schema v1 was the IPv4-only predecessor. The queueing, aggregation, retention,
and failure-priority contracts are unchanged in schema v2.
