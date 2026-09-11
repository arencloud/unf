# ADR 0236: Conflict-Acknowledged Activation Supersession

## Status

Accepted

## Context

A simultaneous cl02 reboot followed by the exact expiry-recovery rollout
exposed a liveness boundary after key recovery. Each agent reconstructed its
durable active generation and locally produced retry-stable activation
testimony for that predecessor. While the report was awaiting a controller
reply, all agents admitted a newer fleet generation. The controller correctly
rejected the predecessor report because it no longer matched the current
prepared generation, but represented that supersession as generic HTTP 400.
The agent therefore retained the immutable old report forever, and the outbox
fence prevented activation of the already-prepared successor.

The dataplane remained fail closed and never fell back to plaintext, but the
fleet could not regain availability without intervention.

## Decision

The controller returns HTTP 409 Conflict when a structurally valid activation
report is superseded by either the current prepared fast-path generation or the
current fleet-plan generation. Exact durable replays remain accepted before
this comparison.

The agent gives 409 one narrow meaning: the controller has authoritatively
confirmed that this exact queued report can no longer become current. It
removes only that volatile outbox entry and proceeds to prove the newer locally
prepared generation. HTTP 202 also closes the outbox. HTTP 400, authentication
failures, transport errors, and 5xx responses retain the report and remain
fail closed.

Clearing a superseded report does not authorize packets, mutate keys, alter
WireGuard state, replace the durable generation journal, or weaken Required
encryption. A successor must still independently complete plan admission,
kernel readback, live path proof, controller admission, and map activation.

## Consequences

- Controller replacement and input churn can converge beyond an unacknowledged
  predecessor activation without manual host cleanup.
- Invalid and equivocal reports remain distinguishable from safe
  supersession and cannot gain a liveness exception.
- The protocol is compatible with controller-first rollout: an older agent
  treats 409 as a retryable error until its serial replacement installs the
  new semantics.
- Full Kind lifecycle requalification and the cl02 reboot gate remain required
  before this runtime is admitted as the Phase 9 release tuple.
