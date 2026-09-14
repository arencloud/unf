# ADR 0383: Stale-Safe Journal Cuts and Bounded Read Copies

Date: 2026-09-14

Status: locally verified; consuming integration and runtime qualification pending

The joint kernel observation must be tied to actual CNI journal state, without
holding the transaction lock during asynchronous namespace inspection. Add an
opaque `AttachmentJournalCut` and borrowed record iterator. A caller can capture
a cut and clone only selected records under its journal lock, perform work, then
validate the same cut under that lock before consumption. Validation and the
publication it authorizes must share the caller's synchronization.

A cut retains an allocation-identity token and monotonic process-local revision.
Every successful changing transaction advances the revision. Read-only requests
and idempotent replays do not. Change-and-restore invalidates the old cut even
when the inventory becomes byte-equivalent. Another journal instance, including
a reopen of the same path, has a distinct retained identity and rejects old cuts.
Checked revision exhaustion restores memory before any persistence attempt.
No token is deserializable or accepted from the transaction protocol.

Any persistence failure revokes the instance's cuts and makes `cut()` return
`None`. A write may fail after rename; the existing rollback behavior therefore
cannot establish unambiguous durability for locality. Reads and no-op replays do
not restore trust. A later successful durable mutation creates a new instance
identity; a freshly validated reopen is also a new identity. This conservatively
fences the new consumer, not a repair of every existing post-rename durability
failure. Writes bypassing the journal's exclusive owner are outside this token's
protection. It is not a file lock, kernel lease or placement permission.

Remove full-inventory rollback cloning and equality comparison from Status,
List, Inspect and CHECK. Those operations cannot mutate the inventory. List uses
an ordered tree range starting at the network/cursor lower bound, stops at the
network boundary and copies only the bounded page. It preserves legacy cursor
semantics even for a cursor in another network. Write rollback behavior and all
wire/journal schema versions remain unchanged; write-side whole-inventory copies
remain a separate optimization target.

Local verification: 813 workspace tests pass, 26 ignored; strict workspace and
all-target Clippy and formatting pass. Four new tests cover durable mutation,
read/no-op stability, change-and-restore, foreign/reopened instances, persistence
failure revocation and successful recovery, revision exhaustion, and borrowed
iteration. Pagination is compared against the original filtering semantics for
36 records, 39 cursor choices, five network queries and three page limits (585
comparisons), including absent and cross-network cursors. The injected I/O failure
occurs before writing; late-rename fault injection remains separate work.

These are code-path cost reductions, not measured CPU/memory savings or a load
envelope. Actual agent inventory/placement joining, locked consumption, kernel
qualification and current-runtime cl02-before-Kind validation remain next. Live
fleets stay `f984db9`; full Phase 9 and stabilization S1–S5 remain open.
