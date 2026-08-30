# ADR 0088: NodePort operations and simulation

**Status:** Accepted and implemented (2026-08-30)

## Context

The Phase 5.4 and 5.5 dataplanes could forward both NodePort traffic policies,
but their events were indistinguishable from ClusterIP outcomes after leaving
the kernel. Inferring the frontend kind from the latest Service snapshot is not
restart safe: an established connection can outlive the revision that created
it. Per-Service metric labels would also create an unbounded cardinality
surface.

Phase 5.6 needs explicit Cluster/Local evidence, read-only prediction, durable
history compatibility, and actionable failure status without adding Kubernetes
strings or a larger event to the eBPF ABI.

## Decision

Service-event ABI v2 keeps the fixed 96-byte layout and assigns the first
previously reserved byte a bounded frontend kind:

- `1`: ClusterIP;
- `2`: NodePort with `externalTrafficPolicy: Cluster`;
- `3`: NodePort with `externalTrafficPolicy: Local`.

The remaining nine reserved bytes must be zero. Connection events derive the
kind from the persisted connection flags, while lookup failures receive it from
the validated frontend. This makes classification independent of current
userspace intent and stable across agent restart and Service churn.

Agent-status schema v5 adds desired/applied NodePort frontend counts, applied
Cluster/Local counts, Cluster/Local translation totals, and NodePort no-backend
drops. Prometheus exposes the applicable dimensions through six fixed-name,
label-free metrics. The existing failed epoch/revision, reconcile-error total,
and UTF-8-safe 1,024-byte last-error field remain the actionable failure
channel.

Flow-export schema v5 and flow-history snapshot/checkpoint schemas v6/v5 carry
the frontend kind in both the aggregation key and service outcome. Older
checkpoint records default to ClusterIP, which is exact because NodePort event
classification did not exist in those schemas. The bounded 4,096-key runtime
store and 1,024-entry/900,000-byte durable checkpoint limits do not change.

`GET /v1/services/explain` accepts an optional frontend-kind filter and returns
classified retained outcomes. `GET /v1/services/nodeport/simulate` validates an
exact admitted Node name/address/port/protocol against the current Service and
Node snapshots, applies the same readiness, termination, placement, and traffic
policy eligibility rules as lowering, and predicts either `translate` or
`drop_no_backend`. It does not mutate revisions, maps, connections, or history.
`unfctl service-explain --frontend-kind ...` and `unfctl service-simulate`
provide JSON, YAML, and table access.

No persistent BPF map is added. ABI v5 therefore remains the exact 21-map
ownership boundary, and its existing dry-run-first cleanup path remains
authoritative.

## Consequences

- ClusterIP, NodePort/Cluster, and NodePort/Local evidence cannot aggregate into
  one logical history key accidentally.
- Metrics remain bounded regardless of the number of Services.
- Restarted agents classify surviving connections from their persisted flags,
  not from a potentially newer snapshot.
- Simulation predicts eligibility from current intent; it deliberately does not
  claim the backend retained by an existing connection.
- The schema changes require a coordinated controller/agent rollout and are not
  covered by an older compatibility tuple.
- LoadBalancer health checks, session affinity, topology hints, Maglev, and DSR
  remain outside this decision.

## Verification

`make nodeport-operations-test` includes the complete Phase 5.1–5.5 prerequisite
chain, the real-kernel dual-stack Cluster/Local event assertions, status and
metric accounting, strict flow provenance, schema-v4 checkpoint migration,
restart-restored NodePort counts, explanation/CLI query construction, read-only
Local eligibility/no-backend simulation, rendering, and strict Clippy.
