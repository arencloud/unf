# ADR 0216: Reciprocal Active-Generation Proof Service

- Status: Accepted and implemented for Phase 9.9
- Date: 2026-09-11

## Context

The first full Kind run of the epoch-floor runtime reached controller recovery
with two Nodes already committed to one generation and the third still holding
its activation escrow. The replacement controller correctly restored the
durable fleet plan and generation frontier, then replaced its volatile path
coordinator with fresh nonce-bound rounds. The pending Node could not complete
those rounds because already-active peers no longer requested assignments and
their responder leases belonged to the pre-restart nonces.

Persisting or replaying an old round would weaken freshness. Treating one-ended
reachability as sufficient would weaken the duplex quorum. Forcing a new
generation merely to recover a proof coordinator would couple data authority to
controller process lifetime and still leave a scheduling race.

## Decision

An agent with an exactly revalidated active generation remains a reciprocal
participant in the controller's current path-proof rounds. It reconstructs the
secret-free desired state and WireGuard plans only when its durable active
recovery plan byte-matches its durable controller admission. It fetches fresh
authenticated assignments, performs the same marked dual-stack encrypted
challenge, independently reads kernel counters, and publishes endpoint proof.

This service grants no new packet authority. An active participant never opens
an activation latch. It normally discards receipts; ADR 0219 permits their
non-authoritative validation only when a replacement controller explicitly
requests reconstruction of a missing activation cursor. A Node with pending
work uses the existing activation path instead. Proofs are cached only in memory for their
exact round digest and lifetime; a changed or expired round evicts the cache and
requires a new exchange. The existing bounded responder lease stays alive until
that round expires, allowing scheduler-skewed peers to finish without making a
reusable responder.

## Consequences

- Controller replacement cannot strand the last pending member of an otherwise
  active generation.
- Freshness, two-ended Node identity, exact generation/contract/epoch binding,
  kernel readback, policy-route marking, and ciphertext traversal remain
  mandatory.
- Active Nodes prove availability only while controller-authenticated current
  work exists; they cannot mutate maps, routes, keys, recovery journals, or
  local activation authority through this path. ADR 0219 separately governs
  demand-driven reconstruction of controller activation history.
- Duplicate publication is idempotent and provides retry safety after an
  ambiguous HTTP acknowledgement.

## Verification

The structural activation-rehydration gate requires the active participation
path, exact durable admission/recovery match, current-round cache eviction, and
non-consuming receipt handling. Runtime `6d29ac3` passed the full fresh
three-Node Kind gate, reproducing agent recovery, natural key rotation,
controller replacement, a strictly newer fleet generation, traffic continuity,
and exact cleanup. The independent five-Node OpenShift gate remains.
