# ADR 0274: Replica-aware exact receipt coverage

Date: 2026-09-12

Status: Implemented; full cl02 qualification pending

## Context

cl02 advanced from rendezvous failures to completed remote quorums, but rejected
activation. The address-bound compiler intentionally merges several replica
plans into one identity-pair decision, hashing their sorted individual witnesses
into an aggregate and leaving the direct transport ID absent. The original
receipt join assumed one receipt and one direct transport per decision. That
assumption cannot validate replicated identities.

## Decision

Use the already-admitted assignment batch to bind every returned receipt to its
exact generation, nonce-bound round, contract and selected plan. Derive compact
private source/destination identity pairs from those verified plans, then release
the full batch before map publication. No wire, checkpoint or BPF schema changes.

Group receipts by those identities. Direct decisions require exactly one matching
witness and their exact transport. Address-bound decisions require the complete
sorted witness set to reproduce the compiler's aggregate, and every receipt must
match an admitted destination Node, key epoch, contract revision and source kernel
configuration. Unknown groups, duplicate witnesses/receipts, missing evidence,
foreign recipients, expiry and substituted rounds fail closed. Receipt and
transport indexes replace repeated full-list searches.

The consuming permit retains only compact private bindings, revalidates them
immediately before publication and keeps its existing generation/receipt witness.
Active-controller recovery uses the same assignment-bound validation without
creating a map capability. The legacy direct-only constructor remains strict;
callers without admitted replica assignments do not gain replica authority.

## Verification

The regression proves two replica receipts cover one address-bound decision,
replays the consuming permit through expiry, accepts permutation, rejects
missing/duplicate/extra/unbound/wrong-kernel/foreign-generation evidence, and
preserves the direct constructor's exact witness. Native-only activation still
requires neither assignments nor controller traffic. Workspace tests and strict
lint must pass before publication; cl02 runs before fresh Kind. The checkpoint
size gap remains a separate follow-up, and Phase 9 is not yet Verified.
