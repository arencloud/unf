# ADR 0108: Adopt bounded measured Maglev selection

- Status: Accepted
- Date: 2026-09-01

## Context

Schema v4 and the Network Behavior Contract already distinguish StableHash
from Maglev, but milestones 7.2–7.5 intentionally rejected Maglev at lowering.
ADR 0102 requires evidence for balance, disruption, memory, compile/update
latency, map writes, and packet cost before adoption. A label without a table,
an unbounded table per frontend, or an extra packet-time loop would violate that
boundary.

## Decision

Userspace builds the standard deterministic Maglev permutation from stable
ServiceId, frontend index, and canonical BackendIds. It stores the resulting
backend sequence in the existing `SERVICE_BACKEND_SLOTS` map. The eBPF program
therefore keeps the verified hash/modulo/one-slot-lookup path; only the slot
sequence and bounded divisor differ.

The operating range is 2–4,096 eligible backends. Fixed prime table sizes from
251 through 65,537 maintain at least sixteen slots per backend. All table slots
count against the existing 524,288-entry per-bank admission limit. If a table
does not fit, lowering uses the exact eligible StableHash list and clears the
Maglev flag. Empty and singleton sets also use StableHash. ClusterIP, NodePort,
and LoadBalancer values carry the actual result, not merely requested intent.

ClientIP affinity stores the selected table slot with the same immutable
bank-plus-revision eligibility proof. Established connections still win before
affinity and table selection, so table updates and size-boundary changes do not
move live flows. Service events carry actual StableHash/Maglev provenance.

The Kubernetes opt-in is the strict annotation
`network.unf.io/service-selection-algorithm: maglev`. StableHash remains the
absence default because silently changing every Service would make legacy
schema projections impossible during a rolling controller-first upgrade.
Current agents request both capabilities; an old agent cannot acknowledge a
Maglev contract and retains last-known-good state.

The fixed-layout map/event schemas advance and persistent ownership moves to
ABI v10 without adding a map. Historical ABI v9 remains separately recognized
for scoped cleanup and is never treated as partial v10 state.

## Evidence

The committed release fixture covers 2, 8, 32, 128, 512, 1,024, 2,048, and
4,096 backends over 200,000 deterministic dual-stack TCP/UDP flows. Within a
fixed table, backend-add disruption is materially lower than StableHash.
Intrinsic table balance error is no more than 6.25%. Maximum table compilation
was about 1.9 ms in the recorded run. Both algorithms use one packet map lookup;
the timed two-million-lookup observations were within ordinary benchmark noise.
The full record and boundary caveat are in
`docs/benchmarks/phase7-maglev-measurement.md`.

`make service-maglev-dataplane-test` regenerates and validates the measurement,
tests deterministic balance/disruption/fallback, verifies all three frontend
origins and provenance, inherits affinity and real-kernel verifier gates, and
runs strict Clippy.

## Consequences

- Maglev is implemented and available, with bounded fallback instead of an
  unqualified performance claim.
- The table consumes more logical map entries and update writes than
  StableHash; admission and actual-algorithm provenance make that cost visible.
- Crossing a table-size boundary may remap most new-flow keys. It is an explicit
  bank/revision upgrade, not a minimal-disruption claim.
- Default behavior remains rollout-compatible. A future independently gated
  cluster default may choose Maglev only with compatibility-aware orchestration.
- DSR remains gated by milestone 7.7.
