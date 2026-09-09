# ADR 0171: Proof-Carrying Frontier Recovery

**Status:** Accepted and implemented for Phase 9.5j

## Context

Phase 9.5i prevents the controller from advancing beyond the slowest member,
but its frontier and receipt set were process-local. A controller restart could
forget the active cut, offer no successor to an agent that had not yet pulled
it, or forget enough receipts to make rollout progress ambiguous. Persisting
only Node names would be unsafe because it would not prove which Node UID,
frontier, or per-Node generation was acknowledged.

This state is control-plane anti-entropy authority. It is not evidence that a
Node configured WireGuard, installed routes, activated Aya maps, or delivered
an encrypted packet.

## Decision

UNF adds a **Proof-Carrying Frontier Recovery** checkpoint containing the exact
active Causal Generation Frontier and a canonical list of receipts. Every
receipt repeats:

- the authoritative Node name and UID;
- that Node's complete published-generation vector; and
- the digest of the fleet frontier being acknowledged.

Restore independently replays the frontier, every nested map checkpoint, the
canonical receipt order, exact membership, per-Node published generation,
frontier digest, schema, and a domain-separated checkpoint digest. A receipt
for a stale generation, another frontier, an unknown Node, or a replacement UID
invalidates the entire recovery image. An empty producer has exactly one valid
shape: no active frontier and no receipts.

The controller stores the secret-free checkpoint in its dedicated
`unf-encryption-generation-frontier` ConfigMap. It restores and validates this
state before becoming ready or serving generation pulls. Newly accepted exact
cursor receipts mark the producer dirty. A bounded periodic worker writes a
fresh complete checkpoint, retries after failures, and performs a final flush
on shutdown. A concurrent receipt arriving during an older write leaves the
dirty bit set for a later complete write.

The deployment creates the empty store and grants the controller `get` and
`patch` only through the existing resource-name-constrained ConfigMap rule.
Three fixed-cardinality metrics expose successful writes, failed operations,
and restored receipt count.

## Consequences

Controller restarts preserve one exact successor for lagging agents and retain
the slowest-member barrier without an unbounded log. If the newest receipt is
lost before persistence, the agent repeats its authenticated durable cursor;
UNF may delay the next cut but cannot skip one. Corrupt or cross-frontier state
stops controller startup instead of reconstructing optimistic progress.

The current Kubernetes persistence adapter deliberately caps encoded state at
900,000 bytes to stay below ConfigMap limits. Exceeding the cap retains dirty
state and reports failure; it does not truncate authority. Content-addressed
multi-object storage is a future scale gate if measured production frontiers
need it. Live fact reconciliation, Node-local activation orchestration, TC
consumption, and encrypted packet proof remain unimplemented.

## Verification

`make encryption-generation-recovery-test` inherits every Phase 9.5i gate and
adds checkpoint round-trip, strict unknown-field rejection, checkpoint and
cross-frontier receipt corruption, empty-state recovery, controller decode,
startup restore, retry/shutdown persistence wiring, fixed-cardinality metrics,
dedicated manifest/RBAC checks, deployment renders, and strict Clippy.
