# ADR 0179: Nonce-Bound Plan Relay

- Status: Accepted and implemented for Phase 9.5r
- Date: 2026-09-10

## Context

The Causally Sealed Input Manifold prevents internal plan tearing, but transport
and caching can still replay a valid old manifold, redirect it to a recreated
Node, or answer a different pull. Durable agent state also needs to distinguish
desired input from proof that local encryption is active.

## Decision

Phase 9.5r introduces the **Nonce-Bound Plan Relay**. An agent request contains
a fresh OS-CSPRNG nonce and its exact durable cursor. A controller capsule binds
that request to its incarnation, the authoritative Node name/UID, and one whole
verified `NodeLocalPlanSnapshot`. Admission requires exact request and cursor
equality plus monotonic controller epoch, membership revision, and generation.

The admitted checkpoint is digest-sealed and strict, but remains desired input.
It contains no private key, kernel readback, policy-route permit, map
transaction capability, or activation latch. Local compilation and every
proof-consuming boundary remain mandatory.

## Consequences

- Retry uses a fresh challenge without allowing a delayed response to win.
- Node name reuse cannot transfer a plan across Node UIDs.
- Restart can recover the exact predecessor and refuse corrupt state.
- A valid current cursor permits an efficient controller `204` response.
- The controller endpoint and atomic agent checkpoint loop are the next slice;
  this milestone establishes the independently testable protocol contract.

## Verification

`make encryption-plan-distribution-test` inherits the complete Phase 9.5q gate,
tests first admission and successor delivery, then rejects nonce replay,
generation regression, Node replacement, and unknown serialized authority under
strict Clippy.
