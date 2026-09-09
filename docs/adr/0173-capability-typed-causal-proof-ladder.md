# ADR 0173: Capability-Typed Causal Proof Ladder

- Status: Accepted and implemented for Phase 9.5l
- Date: 2026-09-09

## Context

Phase 9.5k accepts authenticated Node-local prepared facts and produces a
complete controller frontier. The remaining Node path must join that returned
intent with local kernel and route evidence. A conventional persisted enum or
set of booleans would make illegal stage combinations representable and could
accidentally treat recovered bytes as renewed kernel authority.

The controller must also be unable to substitute a different prepared image
after accepting a Node's fact. TLS and TokenReview authenticate the peer, but
they do not by themselves prove that the returned generation is byte-for-byte
the one independently prepared by that Node.

## Decision

Phase 9.5l introduces the **Capability-Typed Causal Proof Ladder**.

The ladder is encoded as consuming Rust types:

1. `NodeLocalGenerationProposal` owns the strict digest-bound fact and supports
   retrying its public submission, but cannot mutate Aya maps.
2. `bind_controller_admission(self, admitted)` independently replays both
   values and consumes the proposal only when the Node recipient and complete
   nested checkpoint are exact. Any controller substitution fails closed.
3. The resulting `ControllerAdmittedLocalGeneration` is neither cloneable nor
   serializable. `authorize_map_activation(self, applied, route_permit)` consumes
   it together with the fresh non-serializable Route-Before-Authority permit.
4. Only that transition can produce the existing single-use Tri-Plane Causal
   Activation Latch accepted by the Aya transaction adapter.

This is a proof ladder rather than a durable readiness state. After restart,
the retryable public proposal may be reconstructed from independently verified
checkpoint inputs, but controller admission and route authority must be
recreated. Serialized state cannot skip a rung.

## Consequences

- Proof ordering is enforced by the type system, reducing the runtime state
  combinations that operators and recovery logic must reason about.
- A compromised or faulty controller cannot replace the Node-proposed map image
  without explicit rejection at the local boundary.
- Route permits and controller-bound activation capabilities are consuming and
  cannot be replayed across generations.
- The contract introduces no Linux interface, policy rule, map mutation, TC
  attachment, or encrypted-packet claim by itself.
- The next slice must wire the agent's real key authority, WireGuard provider,
  exact route readback, controller fact POST, and Aya adapter through this
  ladder before removing the current restart quarantine.

## Verification

`make encryption-local-proof-ladder-test` inherits all earlier Phase 9.5 gates,
then proves exact fact replay, controller-substitution refusal, the consuming
route-permit transition, successful latch opening, non-serializable capability
types, and strict Clippy.
