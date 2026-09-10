# ADR 0210: Convergent Attested Rotation Wave

Status: Accepted

Date: 2026-09-10

## Context

The Node key authority already modeled two-epoch rotation, but the live agent
created only its initial epoch. The reciprocal-attestation ledger also treated
stable membership as a single lifetime round. A long-running cluster therefore
could not rotate without artificial Node/topology churn. Separately, a settled
agent stopped polling the generation frontier, so a fully activated cut never
accumulated the durable adoption receipts needed to publish its successor.

Rotation must not depend on a synchronized wall-clock instant, a controller
holding private keys, or a broad restart. It must also remain testable without
weakening the production default.

## Decision

UNF uses a **Convergent Attested Rotation Wave**:

- every settled agent continuously anti-entropies its exact durable generation
  cursor, even when it has no new fact to publish;
- agents prepare a successor before expiry using a bounded, deterministic
  Node-UID-derived jitter, avoiding a fleet-wide key-generation spike;
- production timing defaults to a seven-day lifetime, one-day preparation
  horizon, one-hour staggering window, and five-minute drain window, while the
  same bounded values are configurable for qualification;
- the controller opens a new reciprocal witness round only when every member
  exposes a strictly newer prepared epoch over the unchanged exact membership;
- partial waves retain the frozen current round and cannot activate; and
- receipt completion promotes the local epoch durably to `Active`, placing an
  existing active predecessor into bounded `Draining` state.

An exact current cursor is an acknowledgement, not a request to manufacture a
new plan. A successor response without a locally prepared capability is refused.
Private keys remain Node-local throughout the wave.

## Consequences

Rotation converges without topology mutation or a single fleet timer, while
deterministic staggering reduces burst load and the complete matrix preserves
all-member readiness. Node replacement, proposal regression, partial proposal
cuts, and remote successor injection remain fail closed. Phase 9.8 must still
prove the live two-epoch transition, traffic continuity, and cleanup on the
exact committed runtime.

