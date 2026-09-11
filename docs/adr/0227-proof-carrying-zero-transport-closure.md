# ADR 0227: Proof-Carrying Zero-Transport Closure

- Status: Accepted and implemented for Phase 9.9 remediation
- Date: 2026-09-11

## Context

After deploying the ADR 0226 controller and replacing all five agents, cl02
correctly retained the Phase 9 pre-attachment fence. The staged migration
baseline was entirely `Native`: each durable generation contained explicit
Native decision authority but zero epochs, transports, paths, and kernel plans.
Agent activation nevertheless requested encrypted path-proof assignments. The
controller correctly returned `503` because no encrypted path round can exist
for a zero-transport generation, leaving Service forwarding unavailable.

## Decision

Phase 9 adds **Proof-Carrying Zero-Transport Closure**. Before contacting the
path-proof service, the agent verifies the complete fast-path state. If it has
no `Required` decision, it additionally requires an empty kernel-plan set,
clears any cached path proof, and supplies the existing consuming generation
permit with an empty receipt cut. The permit independently re-verifies state
integrity and already defines empty receipts as complete only when no Required
decision exists.

Any Required decision continues through the full controller-coordinated duplex
WireGuard proof path. A Native generation with an unexpected kernel plan fails
closed instead of silently discarding it.

## Consequences

- A fresh or reboot-recovered staged migration can restore explicit Native
  packet authority without inventing an encrypted path.
- Absence of a path round is no longer confused with failure of a Required
  path round.
- The optimization performs zero network requests and zero kernel work, while
  preserving the same single-use generation/route/map activation chain.
- Missing decision authority still drops; this is not a plaintext fallback.

## Verification

The agent regression compiles a non-empty Native decision generation with zero
epochs/transports/paths, gives the synchronizer no controller URL, obtains an
empty receipt cut, and requires the existing generation permit to verify it.
Focused tests and strict Clippy pass. Fresh full Kind requalification and the
resumed five-Node cl02 migration remain mandatory before Phase 9 closes.
