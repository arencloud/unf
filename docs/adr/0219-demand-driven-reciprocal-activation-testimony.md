# ADR 0219: Demand-Driven Reciprocal Activation Testimony

- Status: Accepted and implemented for Phase 9.9
- Date: 2026-09-11

## Context

A full Kind recovery run proved kernel self-healing, agent replacement, natural
key rotation, and forward recovery from an agent cursor ahead of a replacement
controller. The replacement restored the correct active fleet-plan cut, but its
separately coalesced operations checkpoint predated that cut's activation
cursors. Agents had already committed the generation and cleared their
activation outboxes, so no member could reconstruct the missing controller
history. The controller consequently held the old cut while Service revision
advanced. This was safe—the encryption fast path rejected the revision
mismatch—but it permanently denied ClusterIP traffic.

Blind periodic activation reports would create avoidable API and checkpoint
work. Replaying old receipts would violate nonce freshness. Treating active
state as proof of controller history would collapse local packet authority and
replaceable control-plane evidence into one trust domain.

## Decision

The controller exposes an authenticated, read-only activation-testimony
request. HTTP `204` means the exact fleet cursor cut is complete. Otherwise the
strict response binds the authenticated recipient, generation, and prepared
state digest, and separately says whether that Node's report is missing.

While any member is missing, every exactly revalidated active endpoint remains
available for the fresh reciprocal path rounds defined by ADR 0216. Only a
member whose own cursor is missing may report. It first repairs and independently
reads back its exact durable kernel plan, completes current nonce-bound duplex
receipts, and runs a non-authoritative coverage validator. It then emits the
normal secret-free activation report. This path never creates or consumes a map
activation permit and never changes local maps, routes, keys, recovery journals,
or attachment authority.

The controller accepts testimony through the existing full validation path:
current Pod identity, complete generation frontier, exact plan cut, exact state
digest, and exact path set remain mandatory. A retry that finds the same
generation/state cursor already present receives `202` without replacing its
report digest, recording duplicate operations, or dirtying the checkpoint.
Same-generation state divergence remains equivocation and fails closed.

## Consequences

- A plan checkpoint and a slightly older operations checkpoint converge without
  generation churn or plaintext fallback.
- Active peers do proof work only while the fleet has a missing exact cursor;
  steady state costs one bounded status request per synchronization interval.
- A cursor-complete peer still participates so a missing peer can obtain
  two-ended evidence, but it does not publish a redundant report.
- Dormant members can reconstruct an empty-path cursor, while Required members
  must present the full current receipt set.
- Controller testimony remains replaceable history and cannot manufacture
  Node-local packet authority.

## Verification

The shared wire type is strict and contains no key, receipt, witness, or permit.
Encryption-library, controller, and agent suites plus strict Clippy validate the
new boundary. The activation-rehydration structural gate requires demand
signaling, exact local matching, non-authoritative receipt validation, report
publication, and ADR tracking. The full fresh Kind transaction—including link
fault, agent replacement, rotation, controller replacement, post-recovery
ClusterIP traffic, operations, performance, cleanup, and rollback—remains the
promotion gate before immutable images or cl02 qualification.
