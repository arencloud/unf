# ADR 0182: Node-Local Public-Key Transparency Cut

- Status: Accepted and implemented for Phase 9.5u
- Date: 2026-09-10

## Context

Fleet plan production requires current public keys and readiness facts for every
Node. Central key generation would create a high-value secret store and violate
Node-local ownership. Incremental public-key observation would still allow a
plan to combine facts from different topology cuts.

## Decision

Phase 9.5u introduces the **Node-Local Public-Key Transparency Cut**. A ledger
admits an update only under its authenticated cluster, Node name, and Node UID,
using the existing monotonic publication validator. Every public epoch must
bind the current topology/membership revision.

Membership replacement clears all observations atomically. The ledger exposes
a canonical digest-sealed cut only after every exact member has contributed one
valid publication. The cut contains public keys, phases, lifetimes, barriers,
readiness digests, and monotonic retirement/revocation counters—but no private
key or reusable local authority.

## Consequences

- Private keys remain generated, persisted, and consumed only on their Node.
- Missing members and Node replacement are explicit lack of plan input.
- Topology change cannot reuse a key-readiness observation from the old cut.
- Exact retries are idempotent; revision mutation or regression fails closed.
- The next runtime slice must initialize local key authority and publish this
  public-only record through the Pod-bound controller API.

## Verification

`make encryption-key-transparency-test` inherits the fleet-plan catalog gate,
proves two-Node all-member joining and secret-free serialization, then verifies
idempotency, topology-change clearing, replacement refusal, membership rollback
denial, strict schema, and strict Clippy.
