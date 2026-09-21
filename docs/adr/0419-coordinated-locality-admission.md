# ADR 0419: Coordinated locality admission across applied writers

Date: 2026-09-21

Status: implemented; immutable cl02-first qualification pending

Add one exclusive owner of the actual locality runtime maps and its publication
lock. Identity and routing are independent applied components. Each starts
unknown, including on restart. Before a writer can mutate either input, it must
obtain a non-cloneable update guard: this synchronously withdraws both fence and
dispatch. Distinct components may then work concurrently outside the lock;
overlapping writers for the same component reject.

Completion records only nonzero actual applied/durable coordinates. It never
arms or publishes. Cancellation, panic or early return drops the guard into a
failed state. Thus successful identity completion cannot mask an outstanding
or failed route update, and vice versa. Rollback alone does not rearm locality;
the affected component needs explicit successful revalidation. Serial overflow,
mutex poison and uncertain withdrawal fail closed without silent reset.

Publication first withdraws, checks both settled components against fresh
context, validates the bank's exact runtime/original journal cut, publishes the
consumer and arms the fence under one lock. The caller also holds its real CNI
transaction lock. Publication/write failure retires both applied observations;
withdrawal failure poisons this runtime. No lock is held across an await or
namespace/seeding work. Preparation uses the existing bounded worker. This
adds O(1) coordination, not per-endpoint or per-packet locks.

Ten local regressions cover both completion orders, cancellation, same-writer
overlap, zero/stale coordinates, startup, serial exhaustion, mutex poison and
publication/fence failures. The complete kernel fixture adds eight explicit
decisions around pending/cancelled writers, real private route deletion and
rollback, fresh readback/revalidation, and both recovery families. Its restored
TCP/UDP application exchanges now run after coordinated publication; nonce
retirement still denies. The `kernel-admission` gate additionally requires the
eight coordinator records and completion marker. All original 28 native checks,
nineteen kernel decisions and 24 socket cases remain required.

All 891 workspace tests pass (26 privileged tests intentionally ignored), as
does strict workspace all-target Clippy. Formatting and shell syntax checks
pass. Evidence: `.artifacts/p9-admission-workspace-{test,clippy}.log`.

The production agent has not yet adopted this coordinator, new maps or packet
continuations. Actual identity/route writer hooks, CNI startup fencing, pure-local
demand, policy/Service/source-egress/reverse-path composition and authenticated
restart continuity remain open. Qualify the complete immutable fixture on cl02
first, then identical-image Kind; this API alone does not close L3/L4/L5/Q.
