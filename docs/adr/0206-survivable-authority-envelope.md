# ADR 0206: Survivable Authority Envelope

- Status: Accepted and implemented for Phase 9.7g
- Date: 2026-09-10

## Context

Availability and ownership can disagree during controller outage, process
replacement, or Node recreation. Dropping already proven encrypted state merely
because the controller is temporarily unreachable creates avoidable outages.
Blindly trusting disk and pinned maps when current Kubernetes authority is
reachable, however, can revive a predecessor Node UID. Teardown has the inverse
risk: broad recursive deletion can remove operator or adjacent-version state.

## Decision

Phase 9.7g introduces the **Survivable Authority Envelope**:

- controller outage retains the last durable, locally re-read, cryptographically
  proven generation. It cannot create a successor, refresh expired proof, or
  downgrade a Required flow to plaintext;
- when the controller is reachable, the agent obtains its Pod-authenticated,
  Node-UID-bound encryption bootstrap before opening persistent BPF state. The
  durable plan, generation, recovery journal, and private-key authority must all
  name that exact recipient or startup fails closed;
- controller replacement restores the hash-chained operations watermark and
  activation cursors before readiness; agent replacement rehydrates fresh Linux,
  route, map, and duplex authority instead of deserializing a capability;
- current-ABI cleanup independently preflights both the shared map directory and
  `/encryption/v2` before deleting either. Encryption map authority is removed
  first, followed by shared state; and
- only six exact regular encryption pins and now-empty owned directories may be
  removed. Foreign entries, symlinks, and partial ownership ambiguity refuse the
  complete plan; adjacent ABI directories and unrelated siblings survive.

## Consequences

Temporary control-plane loss does not become an availability-driven plaintext
escape, while a detectable Node replacement cannot inherit the previous UID's
keys or packet authority. Cleanup is deterministic, dry-run visible, retryable,
and version scoped instead of depending on a recursive filesystem operation.

## Verification

`make encryption-recovery-cleanup-test` inherits the real WireGuard, route, BPF,
operations-restart, and compatibility gates; verifies outage retention and
activation outbox retry, exact controller restore, pre-BPF plan/generation/key
UID fencing, agent rehydration, foreign-safe encryption-island cleanup, positive
absence, adjacent-state preservation, and strict Clippy.
