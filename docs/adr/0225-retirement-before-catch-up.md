# ADR 0225: Retirement-Before-Catch-Up

- Status: Accepted and implemented for Phase 9.9 remediation
- Date: 2026-09-11

## Context

The fresh qualification after Complete Fleet Cursor Recovery reached controlled
agent replacement after a natural rotation. The replacement restored two valid
Node-local epochs: the predecessor was `Draining` and the successor was
`Active`. Meanwhile the recovered controller fleet floor had advanced to the
next epoch. Startup tried to prepare that epoch before opening persistent BPF
state, but the deliberately bounded two-epoch authority had no free slot. The
agent failed closed with its exact active authority intact.

The same replacement initially received `403` while the controller's Pod watch
had not yet observed its new UID. Immediate process exit turned this safe,
temporary observation gap into orchestrator backoff and delayed convergence.

## Decision

Phase 9 adopts **Retirement-Before-Catch-Up**. When exact Node-local authority
contains one `Draining` and one `Active` epoch, and the active epoch is exactly
one step behind the authenticated fleet floor, bootstrap retains both epochs
and defers preparation. The agent may revalidate and attach only its existing
active generation. Its normal zero-flow/zero-route proof then retires the
draining predecessor, and the next authenticated key synchronization prepares
the fleet-aligned successor in the newly free slot.

Controller-distributed CNI bootstrap also retries `403` and `503` for at most
120 one-second attempts while remaining fenced. It never treats those responses
as last-known-good authority. `401`, other status codes, and exhaustion still
fail closed; only connection/timeout outage may use the separately validated
durable snapshot under the existing offline-start rule.

## Consequences

- Catch-up cannot exceed the two-epoch secret-capacity invariant.
- No active or draining private key is copied, revoked, or discarded merely to
  follow controller state.
- Existing flows retain their bounded draining lease; new flows use only the
  exact active epoch.
- Replacement-Pod watch latency no longer creates avoidable CrashLoop backoff,
  and retry does not weaken Pod UID authentication.
- A permanently unauthorized replacement remains visibly unready and fails
  after a bounded interval.

## Verification

The regression activates epoch 1, rotates to epoch 2 with epoch 1 draining,
raises the fleet floor to 3, and proves that catch-up performs no mutation until
a positive drain proof retires epoch 1. It then requires epoch 2 to remain
active while epoch 3 is prepared. A separate boundary test proves the exact
retryable statuses and final-attempt/unauthorized refusal. Focused agent tests
and strict Clippy pass. Complete fresh Kind and independent cl02 qualification
remain mandatory before Phase 9 closes.
