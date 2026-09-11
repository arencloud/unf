# ADR 0215: Monotonic Fleet Key Epoch Floor

- Status: Accepted and implemented for Phase 9.9
- Date: 2026-09-11

## Context

The safety-fixed cl02 rollout proved that the Causal Pre-Attachment Fleet
Barrier preserved every host and API path, but it also exposed a durable key
recovery edge. The worker interrupted during the earlier attempt retained
epoch 1 in `Prepared` state after its validity window expired. The other four
Nodes later prepared fresh epoch-1 keys. The controller correctly refused to
open a reciprocal attestation round over an expired, non-overlapping cut, while
all agents correctly remained live, unattached, and unready.

Waiting for every independently staggered key lifetime to expire would
eventually align the Nodes at a successor epoch, but that is neither bounded by
fleet convergence intent nor suitable for long production key lifetimes.
Replacing a public key under the same epoch would be faster but would violate
the existing replay and mutation fence.

## Decision

The authenticated key bootstrap is schema v2 and carries a digest-bound
`epochFloor`. The controller derives this monotonic public-only frontier from
the greatest issued, retired, or revoked epoch already admitted for the exact
membership cut. It contains no private material and grants no packet authority.

An agent with no Active or Draining authority may durably revoke an expired
Prepared/MutuallyAttested epoch as `ExpiredBeforeActivation`. The resulting
monotonic publication raises the fleet floor. Other agents whose never-active
transition is below that floor durably tombstone it as
`FleetEpochSuperseded` and prepare the same successor immediately. A new Node
may catch up through at most 4,096 persisted steps; exceeding that bound fails
closed. An Active Node may prepare only its exact next floor and may never leap
over live or draining packet authority.

This creates a self-healing convergence wave without coordinating private
keys, reusing epoch identifiers, relaxing attestation, attaching an empty TC
graph, or interpreting missing authority as Native.

## Consequences

- Interrupted first-generation rollout converges after the first recovered
  member publishes its successor instead of waiting for every local lifetime.
- Epoch and public-key history remains monotonic; abandoned secrets are
  zeroized through the existing durable revocation transaction.
- Controller restart begins conservatively at floor one and relearns a higher
  frontier from authenticated Node publications.
- Membership, Node UID, topology revision, bootstrap digest, reciprocal
  attestation, plan, path proof, and activation barriers remain mandatory.

## Verification

Focused agent tests reproduce expired epoch recovery and signed-floor
supersession through epochs 1, 2, and 3. The complete `unf-encryption` suite,
controller key tests, and strict Clippy pass. The full key runtime/attestation
chain, fresh three-Node Kind qualification, and five-Node cl02 gate must pass
before Phase 9.9 can be marked Verified.
