# ADR 0427: Agent applied-writer locality fencing

Date: 2026-09-21

Status: implemented and locally verified; production composition pending

The real identity and remote-route writers now use the singleton locality
admission coordinator. A guard withdraws locality before mutation, remains held
across readback, persistence and rollback, and cannot independently arm a bank.
Cancellation, error or panic drops the guard into Failed. Both actual inputs
must be settled before a subsequent independently validated bank publication.

Covered production paths:

- Remote-route startup restoration, desired replacement, checkpoint persistence
  failure/rollback and last-known-good repair.
- Actual identity-map startup recovery and new bank application, including
  staging rollback and readback of the activated configuration.
- Recovery of a failed/unknown identity observation on an unchanged snapshot,
  using exact active kernel maps/configuration rather than atomics alone.

An unchanged route poll requires both the exact durable snapshot and identical
lowered plan, then real kernel readback. When the coordinator is already Current,
it avoids route replacement, checkpoint fsync and locality withdrawal. Failed or
unknown observations are guarded and revalidated before completion. The ordinary
unchanged identity path uses an O(1) coordinator observation; full bank readback
is needed after failed/unknown admission, not every normal poll. Regression tests
distinguish unchanged snapshots from changed revisions, uplinks and onlink modes,
and verify that repeated coordinator observations perform no fence writes.

A one-second, non-bursting health supervisor treats an uncertain/poisoned kernel
fence as fatal to the agent. It clears readiness and enters normal supervised
shutdown. Pending/failed writers with a successfully withdrawn fence are not
fatal. No failed guard acquisition permits its caller to mutate inputs.

These are structural work reductions, not measured CPU/RSS or throughput claims.
The full local workspace and strict Clippy are required before commit. Existing
paired coordinator gates remain library-level evidence; they do not qualify
these actual writer paths as part of production packet composition.

The `4a027ea` startup diagnostic is built from its already-copied fixed source
while this next implementation is developed. Its forthcoming cl02/Kind evidence
will qualify that startup correction only, not this newer writer code. Both live
fleets remain `45d85d5`. Actual bank production, policy-first packet/reply wiring,
restart continuity and L3/L4/L5/Q remain open.
