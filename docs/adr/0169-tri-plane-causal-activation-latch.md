# ADR 0169: Tri-Plane Causal Activation Latch

**Status:** Accepted and implemented for Phase 9.5h

## Context

Phase 9.5g safely delivers a prepared encryption generation, and Phase 9.5f
allows only exact local route/rule readback to mint a map-publication permit.
Checking those inputs in separate calls still leaves a dangerous seam: the
active Aya predecessor can move between checks, a permit can be presented for
another image, or a serialized pending checkpoint can resume after restart
when the non-serializable route permit no longer exists.

That restart case is subtle. Persist-before-mutate is necessary for crash
recovery, but persistent intent is not fresh evidence that the WireGuard link,
routes, and rules still exist. Automatically completing a pending pointer flip
would turn a checkpoint into local kernel authority.

## Decision

UNF introduces the **Tri-Plane Causal Activation Latch**. It is a
non-serializable, non-cloneable, single-use Rust capability that joins:

1. the Node-Sealed Generation Capsule already durably admitted from the
   authenticated controller;
2. the non-serializable Route-Before-Authority permit freshly minted from exact
   Node-local WireGuard route and rule readback; and
3. the Aya adapter's exact currently applied predecessor and, after a crash,
   the exact quarantined transaction.

Issuance independently replays the admitted record and checkpoint, binds the
authoritative Node name/UID, requires the distributed `prior` to equal the
adapter's applied generation, reconstructs the complete fast-path image, and
verifies the local permit against that generation and digest. A
domain-separated activation witness binds the admitted-generation digest,
controller incarnation, recipient, published generation, and route-authority
digest for future secret-free provenance; the witness is evidence, not a
reusable capability.

Opening consumes the latch and repeats every check at the map boundary. The Aya
adapter persists and recovers the exact checkpoint supplied by the capsule—it
does not create a similar transaction locally. If a prepared or staged
checkpoint survives a crash, startup validates but quarantines it. Resumption
requires a newly issued latch for an identical transaction; phase-only progress
from prepared to staged may be retained, while any desired vector, revision,
predecessor, decision, or transport drift is refused.

Any committed or pending encryption generation recovered from disk marks the
adapter as requiring local revalidation. Until live orchestration supplies a
fresh latch, the agent refuses TC attachment. A quiescent encryption island
continues normally. This is intentionally fail closed: serialized state cannot
silently reacquire the authority that was lost with the process.

## Consequences

No individual plane can make Required traffic authoritative. Controller
compromise cannot invent local route proof; stale routes cannot select a new
controller generation; a correct map image cannot bypass either; and crash
recovery cannot convert bytes on disk into a route permit. The single-use type
also makes accidental reuse visible at compile time, while exact predecessor
revalidation rejects reconstructed replay.

The price is deliberate startup unavailability whenever non-quiescent
encryption state exists but the future live local orchestrator cannot recreate
proof. That is safer than plaintext downgrade or unproved attachment and has no
effect on current deployments because production generation remains empty.
This slice does not yet configure WireGuard from live controller state, invoke
TC encryption lookup, or claim encrypted packets.

## Verification

`make encryption-activation-latch-test` inherits all Phase 9.5g gates and proves
the exact three-plane join, stable nonzero witness, cross-Node rejection,
wrong-predecessor rejection, wrong-image permit rejection, exact staged-crash
resumption, mismatched pending-state refusal, non-serializable latch boundary,
adapter consumption, startup quarantine before TC attachment, and strict
Clippy. The complete workspace suite remains the regression gate.
