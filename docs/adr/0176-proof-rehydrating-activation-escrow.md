# ADR 0176: Proof-Rehydrating Activation Escrow

- Status: Accepted and implemented for Phase 9.5o
- Date: 2026-09-10

## Context

Phase 9.5n retains one locally proven capability across controller retries and
persists only an exact returned admission. The capability is intentionally
non-serializable, so a process restart cannot reuse it. Previously, any
recovered current or pending encryption map generation therefore remained
quarantined before TC attachment even when the real WireGuard state was still
complete and exact.

Persisting a route permit or activation latch would weaken the proof model.
Discarding exact kernel state on every restart would instead create avoidable
traffic disruption and operational cleanup.

## Decision

Phase 9.5o introduces **Proof-Rehydrating Activation Escrow**.

A strict `NodeLocalRecoveryPlan` durably records only the secret-free generation
fact and canonical public WireGuard plans. A bounded journal retains separate
active and pending plans so rotation cannot destroy current restart authority.
A domain-separated digest binds each complete nested checkpoint and plan set.
The journal contains no private key, route permit, activation latch, or Aya
authority, and unknown fields fail closed.

Before TC attachment, the agent:

1. loads the owner-only recovery plan adjacent to its admitted-generation
   checkpoint;
2. independently replays every nested digest and transport commitment;
3. rereads every real Linux WireGuard link, peer, key identity, route, mark,
   table, MTU, and ownership alias;
4. reconstructs a fresh non-serializable convergence capability only from the
   complete exact readback cut;
5. requires the durable controller admission to byte-exactly match that local
   fact;
6. installs and rereads policy-route authority; and
7. consumes the resulting tri-plane latch through deterministic Aya
   current/pending transaction recovery.

Only after this sequence may restart quarantine clear and TC programs attach.
For a newly admitted generation the same consuming boundary runs immediately.
An activation failure stops the dataplane task; its supervisor restarts into
the durable rehydration sequence rather than continuing with ambiguous state.

## Consequences

- Exact kernel state survives routine agent restart without serializing live
  authority or destructively rebuilding WireGuard devices.
- Partial, foreign, stale, reordered, or tampered state cannot clear quarantine.
- Crash boundaries during map staging converge through the existing total Aya
  recovery state machine with newly proven route authority.
- A pre-admission crash first revalidates the active slot and then resumes the
  pending fact; a post-admission crash directly completes the pending slot.
- The recovery plan is useful operational provenance and contains no private
  key material.
- Automatic production of the first local plan/capability and TC packet-path
  consumption remain subsequent Phase 9.5 work.

## Verification

`make encryption-activation-rehydration-test` inherits every Phase 9.5n gate,
checks persistence/readback/attachment ordering, exercises exact rehydration,
mutation, partial evidence and strict-wire refusal, verifies owner-only agent
recovery handling, and applies strict Clippy.
