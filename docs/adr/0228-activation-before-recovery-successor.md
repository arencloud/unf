# ADR 0228: Activation-Before-Recovery-Successor

- Status: Accepted and implemented for Phase 9.9 remediation
- Date: 2026-09-11

## Context

The first fresh Kind qualification of ADR 0227 reached controller replacement
after rotation. The replacement restored an exact durable fleet-plan cut, and
all authenticated agent plan cursors were at that cut. One Node had durably
admitted the generation but had not yet consumed its duplex path-proof permit.
The complete fleet-cursor recovery join nevertheless minted a successor. The
controller then served only successor path challenges, so that Node correctly
refused the generation-mismatched assignments and retained its active
predecessor. Fleet convergence could no longer close.

## Decision

Phase 9 adds **Activation-Before-Recovery-Successor**. When a complete recovery
cursor join proves every agent is at or behind the exact restored catalog, the
controller keeps that catalog published until its durable fleet activation
cursor cut is complete. This lets already-admitted Nodes finish fresh,
nonce-bound path proof against reconstructible controller authority.

The hold is not a timeout, a plaintext fallback, or an acceptance of stale
evidence. The restored cut must still be current, every endpoint must produce
the normal proof and activation report, and Required traffic remains fail
closed. Once activation closes, normal reconciliation sees the deliberately
unreconstructed source coordinate and publishes one fresh successor from
current inputs. An authenticated cursor strictly ahead of the durable catalog
continues to use the fleet high-watermark recovery path from ADR 0224.

## Consequences

- Replacement-controller recovery cannot orphan an admitted, reconstructible
  path-proof generation merely because agent plan polls complete quickly.
- Recovery ordering is derived from durable fleet activation evidence rather
  than timing between independent poll loops.
- Controller restart adds no steady-state work and creates no extra packet
  authority.
- Ahead-of-catalog recovery remains explicit and fail closed; this decision
  does not fabricate a lost plan cut.

## Verification

The controller regression reconstructs an unactivated durable catalog, joins
its exact authenticated agent cursor, and requires the plan endpoint to retain
that generation. The existing continuation then proves that closing activation
allows a newer causal-source cut. All 107 controller tests, strict Clippy, and
the Kind/OpenShift static gate contracts pass. Fresh full Kind requalification
and the resumed five-Node cl02 gate remain mandatory.
