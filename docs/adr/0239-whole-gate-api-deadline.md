# ADR 0239: Whole-Gate API Deadline

## Status

Accepted

## Context

ADR 0238 bounded Kubernetes streaming operations, but the next cl02 run showed
that an ordinary `get infrastructure` request could also stall before runtime
qualification began. The read retry count did not create a wall-clock bound
when any individual non-streaming request could wait indefinitely.

## Decision

Apply a 20-second Kubernetes client request timeout to the shared `oc` command
used by the complete Phase 9 OpenShift gate. The duration is explicitly
configurable for slower environments through
`UNF_OPENSHIFT_ENCRYPTION_REQUEST_TIMEOUT`, while process-level timeouts remain
around streaming and diagnostic operations.

Every failed or timed-out read is unavailable evidence. The existing retry
logic may obtain a fresh sample, but no previous response is cached or treated
as current. Mutating calls also inherit the deadline; an uncertain result is
handled by the existing idempotent cleanup latch and exact precondition checks.

## Consequences

- Every API operation now contributes a finite duration to the gate's outer
  bounds.
- API transport degradation produces a diagnosable rejection instead of an
  indefinitely blocked qualification process.
- The setting changes qualification behavior only; runtime revision
  `e1dbb94` and the ADR 0237 image tuple remain unchanged.
