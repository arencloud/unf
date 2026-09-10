# ADR 0201: Poll-Stable Evidence Export

- Status: Accepted and implemented for Phase 9.7b
- Date: 2026-09-10

## Context

The Phase 9.7a evidence contract was intentionally independent of runtime
transport. Exporting it naively from pull handlers would count every agent poll
as progress and make retry rate indistinguishable from lifecycle state. Creating
metric labels for each contract or peer would also turn diagnosis into a memory
and disclosure risk.

## Decision

Phase 9.7b adds **Poll-Stable Evidence Export**:

- the controller owns one operations ledger and publishes its current watermark
  at `/v1/encryption/status` and its bounded chain at
  `/v1/encryption/history`;
- the Prometheus family is materialized at startup as exactly all 54 closed
  stage/outcome combinations. Zero values remain visible and fleet state can
  never create another series;
- a new or renewed complete challenge cut records requirement and assignment
  transitions only when the coordinator reports that the cut changed;
- an independently accepted endpoint proof records local exchange exactly once;
  an idempotent proof retry records nothing; and
- only the second matching endpoint proof records remote quorum. Receipt polling
  records nothing because delivery is not evidence of agent-side activation.

The exporter intentionally stops at proven remote quorum. Reporting actual map
activation requires an authenticated agent acknowledgement and durable retry,
which is the next slice; it is not inferred from a controller response.

## Consequences

Metrics represent causal transitions instead of API traffic. Their memory and
Prometheus cardinality costs are constant, while bounded history retains safe
contract/epoch correlation. The controller does not overstate activation.

## Verification

`make encryption-operations-runtime-test` inherits the complete 9.7a/live path
gate, verifies API and exporter wiring, proves exactly 54 emitted series and no
contract/Node/peer/epoch labels, checks watermark/history responses, exercises
the current plan-cut path, and applies strict controller Clippy.
