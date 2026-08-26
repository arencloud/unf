# ADR 0030: Durable flow-history checkpoint and time-window queries

## Status

Accepted, implemented, and live verified on the two-node kind fixture.

## Context

ADR 0012 intentionally made flow telemetry bounded and advisory, but its
controller history disappeared on every restart and operators could only retrieve
the complete retained set. Phase 3 needs useful recent-flow queries and restart
continuity without introducing a required database or allowing telemetry work to
affect packet forwarding.

## Decision

The in-memory store remains the primary 4,096-logical-key analysis window. The
controller coalesces changed history at most once every two seconds into the
pre-created `unf-flow-history` ConfigMap, using only exact-name `get` and `patch`
RBAC. Checkpoint schema v1 preserves the newest 1,024 logical keys, revision,
timestamps, actual and shadow decisions, observation counts, reporting Nodes,
controller eviction counts, cumulative agent drops, and the per-Node cumulative
drop baselines required to avoid double counting after restore.

The serialized checkpoint is limited to 900,000 bytes. If the newest 1,024 keys
do not fit, the controller repeatedly halves the retained subset. The checkpoint
records cumulative omitted-flow and omitted-observation counts so this loss is
visible. Startup strictly validates the schema, keys, addresses, timestamps, and
reasonable clock bounds before restoring any state; malformed state fails
controller startup instead of being silently accepted. Restore finishes before
readiness and Kubernetes watchers begin.

`GET /v1/flows` now returns flow-history snapshot schema v3 and accepts inclusive
`since_unix_ms`, `until_unix_ms`, and `limit` query parameters. `limit` must be
between 1 and 4,096, and the lower bound cannot exceed the upper bound. Selection
uses each aggregate logical entry's exact `last_received_unix_ms`; results are
newest first with a deterministic key tie-break. The response reports its applied
bounds, matched flows and observations, returned flows, and truncation state,
along with checkpointed, restored, and omitted counts.

`unfctl flows` exposes the absolute bounds plus `--last <duration>` for positive
integer `ms`, `s`, `m`, `h`, or `d` durations. A relative window ends at
`--until-unix-ms` when supplied, otherwise at the local current time.

## Verification

State and controller unit tests cover exact inclusive windows, newest-first
limits, checkpoint truncation and restoration, drop baselines, invalid query
bounds, and future checkpoint rejection. `make kind-flow-history-retention-test`
proves exact ConfigMap RBAC, checkpoint creation, absolute and relative queries,
limit and empty-future behavior, controller restart restoration with the original
first-received time, positive restore metrics, zero persistence errors, and no
agent replacement. The focused gate is included in `make kind-test`.

## Consequences

Short controller restarts no longer erase the newest retained evidence, and
operators can bound transfers and ask for recent aggregate entries without a
database. Telemetry remains advisory and cannot block forwarding.

These queries are not event-time buckets: all observations attached to a matching
logical entry are returned even if some occurred before the requested window.
The ConfigMap is a bounded single-controller checkpoint, not a high-availability
database. Interface-level deduplication, sampling, simulation-window input,
topology history, pagination, and external flow backends remain future work.
