# ADR 0205: Bidirectional Compatibility Sextant

- Status: Accepted and implemented for Phase 9.7f
- Date: 2026-09-10
- Adjacent baseline: `372cdec7be4318659502fd0c2fd28d8cab58e283`

## Context

An encryption upgrade crosses several independently versioned boundaries:
intent, Node-local plan, duplex proof, operations evidence, and persistent BPF
maps. One aggregate “compatible” boolean can hide a partial rollout, and a
controller-first or agent-first transition must not turn missing features into
plaintext permission. Adding fields should not force an otherwise safe
flag-day rollout.

## Decision

Phase 9.7f adds the **Bidirectional Compatibility Sextant**:

- the existing compatibility document gains additive encryption model, local
  plan, path-proof, operations, and map-ABI coordinates without changing its
  outer schema;
- an older reader ignores those additive coordinates. A new reader maps their
  complete absence to one all-zero adjacent tuple. That tuple is not authority:
  every plan, proof, operation, and map payload still validates its exact schema
  before it can affect state;
- any partially advertised tuple is transition tearing and fails before the
  agent opens persistent BPF state. A complete tuple must match exactly;
- incompatible model/proof/operations or map state never falls back to native
  traffic for a Required flow; and
- the controller continues to migrate the adjacent bare operations history
  into its activation-cursor wrapper. Rollback that cannot read a newer durable
  schema remains blocked instead of discarding evidence.

This gives both rollout directions a deterministic coordinate: N controller
with N+1 agent is authority-fenced by strict endpoint payloads, while N+1 controller
with N agent remains wire-compatible because all coordinates are additive.

## Consequences

Mixed-version fleets do not need a global stop, but they also cannot assemble a
fictional partial capability. The mechanism is O(1), checked before map access,
and diagnoses the exact mismatched plane. It preserves availability only where
last-known-good authority is independently recoverable; encryption Required
semantics still fail closed.

## Verification

`make encryption-adjacent-compatibility-test` pins the exact N revision, proves
the old wire shape lacks the new coordinates, exercises old-reader/new-writer
and new-reader/old-writer serde behavior, accepts only the all-zero or exact
complete tuple, rejects partial and foreign versions before BPF access, replays
the adjacent operations checkpoint migration, and runs strict Clippy.
