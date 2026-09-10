# ADR 0202: Restart-Continuous Evidence Chain

- Status: Accepted and implemented for Phase 9.7c
- Date: 2026-09-10

## Context

An in-memory operations watermark becomes misleading after controller
replacement: history disappears while Prometheus counters restart at zero.
Persisting unchecked JSON would be worse because a damaged checkpoint could
manufacture lifecycle evidence. Operations state is not activation authority,
but operators still need to know whether the evidence window is continuous.

## Decision

Phase 9.7c adds the **Restart-Continuous Evidence Chain**:

- the controller owns one exact-name `unf-encryption-operations` ConfigMap and
  exact-name RBAC; every base, Kind primary-CNI, and OpenShift primary-CNI render
  includes it through the shared deployment base;
- every accepted transition marks the ledger dirty. A two-second coalescing
  writer snapshots the complete bounded checkpoint, retries failed writes, and
  performs a final shutdown flush;
- startup refuses unsupported schema, malformed counters, generation drift,
  broken sequence/anchor linkage, record mutation, or oversized state before
  publishing restored evidence;
- all 54 Prometheus counters resume from the durable counter matrix, so the API
  watermark and metrics do not disagree after controller replacement; and
- restored record count plus persistence success/failure use fixed-name
  counters, never topology labels.

The checkpoint remains diagnostic only. Restoring it cannot configure a key,
peer, route, map, or activation latch.

## Consequences

Controller replacement preserves a verifiable bounded evidence window and its
loss accounting. A malformed checkpoint fails visibly rather than resetting to
apparently healthy zero state. ConfigMap writes are bounded and coalesced away
from the packet path.

## Verification

`make encryption-operations-recovery-test` inherits the live 9.7b chain, tests
round-trip and mutated checkpoint refusal, checks dirty/persistence wiring and
metric resumption, renders the base, Kind primary-CNI, and OpenShift primary-CNI
manifests, and applies strict controller Clippy.
