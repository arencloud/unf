# ADR 0423: Owned locality runtime startup

Date: 2026-09-21

Status: implemented; paired kernel qualification and agent integration pending

The locality runtime now has explicit create and reopen operations for its four
shared maps. A retained exclusive root-owned regular-file lock prevents two
participating startup owners. Fresh creation validates an exact private map set
and atomically publishes the directory without replacing an existing path.
Reopen rejects partial, foreign, aliased or incompatible inventories. Neither
operation restores a bank, attachment lease or applied coordinates. Successful
startup withdraws the applied fence, selected bank and all four continuations.

Missing pins do not prove that old programs have disappeared. Reopen therefore
never creates missing maps. Fresh creation requires a caller-established first
deployment or independently verified kernel-boot transition. The actual agent
must persist and validate that decision before enabling the journal reader floor
or serving CNI. This API alone does not implement that production decision.

The production loader can be bound to the held pins and must then prove exact
kernel map IDs, not just compatible shapes. The owner lock is retained through
the same shared runtime object held by preparations and banks. Pin permissions,
map names, widths, capacities, flags, private parent ownership and non-symlink
paths are checked; no unknown inventory is repaired or removed.

The new `kernel-runtime-owner` diagnostic includes all existing native, bank,
coordinator, socket and reader-floor checks. In an isolated disposable bpffs it
tests atomic creation, competing-owner rejection, armed reopen withdrawal,
substituted-map rejection, refusal to recreate missing pins, preservation of
foreign entries and exact-ID cleanup. No production pin, journal, attachment or
program is modified. cl02 must pass before identical-image Kind.

Local workspace tests and strict Clippy are required before committing this
slice. Actual early agent startup ordering, applied writer hooks, bank production
and policy-first packet continuations remain next. L3/L4/L5/Q and Phase 9 remain
open; this is not a runtime rollout or a performance claim.
