# ADR 0402: CNI Incarnation Retirement Before Durable Teardown

Date: 2026-09-21

Status: locally verified journal boundary; kernel bank integration pending

## Decision

Locality publication must share the real CNI journal's transaction lock and
install one process-local `AttachmentRetirement` hook before admitting packets.
For a changed Ready, nonce-bound record, `AttachmentJournal::apply` invokes
that hook with the full 32-byte creation nonce before persistence and before a
successful transaction reply. The intended kernel implementation revokes this
incarnation in every published bank, without revoking unrelated attachments.
Installation invalidates all earlier process-local journal cuts. Replacement
and removal of an installed hook are prohibited for that open journal.

The callback is synchronous and idempotent; an already absent nonce is success.
On callback failure, the transaction restores its prior record, writes no
journal, returns a retryable CNI `PersistenceFailure` with an explicit retirement
error, and invalidates publication cuts. On subsequent persistence failure,
the record rolls back but revocation does not. Reads and no-op replays cannot
restore a trustworthy cut. A new successful durable mutation can establish a
new cut; it does not itself rearm any kernel permission. Reopening restores no
hook or packet authority. Startup fencing of previously published banks remains
mandatory work for the actual publisher.

Invalid requests, incompatible schemas, read operations, idempotent replay,
non-Ready and legacy unbound records do not trigger retirement. Revision
exhaustion is rejected before the hook. The CNI's existing DEL ordering waits
for successful BeginDelete before calling kernel cleanup.

Transactions now retain a rollback copy of the one affected record instead
of cloning/comparing the entire attachment inventory. The durable document is
still serialized in full, and allocation still scans existing leases. This is
a structural reduction in rollback copying, not a measured latency, CPU or
RSS improvement and not a claim of constant-time total CNI transactions.

## Verification and limits

Six new journal regressions cover exact incarnation and unrelated-record
preservation, callback-before-disk ordering, replacement/no-op/schema/phase
negatives, partial retirement failure, write failure/retry, revision exhaustion,
reopen, and rollback for all mutation kinds. A real agent request-handler test
verifies retryable failure without a successful teardown reply or nonce leak.
All 843 workspace tests pass, with 26 privileged tests ignored; formatting and
strict all-target Clippy pass. Evidence is retained in
`.artifacts/p9-cni-retirement-{tests,workspace-2,clippy-3}.log`.

A read-only cl02 preflight reviews all current UNF regular/init logs. It records
428 warnings (418 bounded flow-history retention, eight proof-assistance, one
key-publication and one topology-history retention) and no ERROR. This log read
does not qualify the new code. No cluster runtime, CNI record, BPF ABI, release
pin or credential is changed by this milestone.

The production bank has not yet installed a kernel-backed hook. Consequently
this API does not claim packet-time revocation, bank publication or locality
delivery. Next: integrate the kernel gate and authenticated immutable consumer,
including restart fencing, then qualify on cl02 before matching Kind. L3,
L4/L5/Q, full Phase 9 and stabilization remain open.
