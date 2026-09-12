# ADR 0250: Compact Causal Tombstone Chain

## Status

Accepted

## Context

After cl02's control-plane node rebooted, its agent recovered a previously
persisted fail-closed bridge from physical generation `1789174522791` to
tombstoned logical generation `1789174577391`. The same outage had also left a
newer controller-admitted generation `1789175304635`; its epoch 56 was durably
revoked through epoch 117. That second admission correctly extended the first
logical predecessor, but the original bridge accepted only a generation that
immediately extended the last physical map. The agent therefore remained
fenced with zero map authority instead of fabricating ancestry or reusing an
expired key.

Keeping a complete decision, transport, path, and Linux recovery image for
every skipped generation would make outage recovery grow with the size of the
dataplane. Discarding intermediate ancestry would make a later restart unable
to prove that the newest logical predecessor still descends from the last
physical map.

## Decision

Represent consecutive tombstoned admissions as a Compact Causal Tombstone
Chain. The durable map bridge retains:

- the newest full, independently verified admitted checkpoint;
- only the digest-bearing `FastPathMapTransaction` for each compacted
  intermediate generation; and
- an implicit root at the separately persisted last physical map checkpoint.

Recovery verifies every transaction digest, exact predecessor edge, monotonic
published generation, and the final admitted checkpoint before accepting the
logical cursor. Advancing the chain is persist-before-abandon: the new bridge
is durably written before the pending Linux stage is removed. The shared map
config stays zero and established-flow leases stay absent until a fresh-key
successor joins the chain and commits through normal route, kernel, and map
readback.

The Linux recovery journal carries the same compact transaction ancestry and
verifies it against its physical active plan. A successful successor commit
atomically clears both the tombstoned plan and its compact ancestry. Existing
single-generation bridge and recovery files remain readable as a zero-length
ancestry migration.

## Consequences

- A node can recover across multiple consecutive admission/expiry races
  without plaintext fallback, key reuse, state deletion, or full-image growth
  per skipped generation.
- Corrupt, disconnected, foreign, or nonmonotonic ancestry remains fail
  closed; no chain element grants packet authority.
- The ADR 0249 runtime remains historical Kind evidence but is not eligible
  for final cl02 qualification. This runtime change requires a fresh complete
  Kind lifecycle, immutable publication, preserved-state cl02 deployment, and
  the full OpenShift gate.
