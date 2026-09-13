# ADR 0298: Exact Predecessor Receipt Recovery

Date: 2026-09-13

Status: implemented; cl02-first live qualification pending

## Decision

Repair ADR 0297's mixed-cursor deadlock using an authenticated durable Node
admission to recover only that Node's receipt for the controller's existing
frontier. Accept either the exact current publication or an exact predecessor
publication embedded in the admitted successor. Compare the entire fixed-width
publication, including digest, bank and policy/Service/egress revisions, not
only its generation number.

Current agent Pod UID, authoritative Node UID and membership, checkpoint
integrity, and ledger acceptance all precede receipt recovery. Prepared facts,
regressions and equivocation cannot create receipts. A receipt restores
controller backpressure, not kernel authority or packet proof. Complete-cut
admission recovery and exact-successor publication/delivery remain unchanged;
lagging Nodes are not marked as having admitted a successor. A later prepared
cut still cannot make acknowledgement of a durable admitted cut fail.

Only the recipient and two fixed-width publication records survive moving the
fact into its ledger; the new path does not clone a large checkpoint. The
existing checkpoint mechanism persists changed receipts, and repeated replay
does not dirty an already recovered frontier. No schema, ABI, key lifetime,
map/journal reset or policy/Required fallback changes are involved.

## Local verification

The new three-Node regression fails before the fix at the missing predecessor
receipt assertion. After the fix it restores a two-receipt checkpoint, observes
mixed predecessor/successor admissions, completes only the old frontier, and
then delivers the exact successor to the lagging Node. It independently checks
that the newer cut is not fully acknowledged until that Node admits it, and
that repeated replay does not trigger another persistence write.

A second regression covers prepared-only facts, wrong membership, replaced
Pod/Node UIDs, corrupt checkpoints, unrelated or skipped predecessors,
equivocation, regression, and receipt-only recovery from a current admission.
It compares complete producer checkpoints and dirty flags, including a durable
receipt round trip. Local verification passes: 739 workspace tests, with 25
explicit environment-dependent tests ignored; formatting; strict workspace
Clippy over all targets/features; and the Native coverage gate's observation
safety checks. Red/green and full-suite logs remain under ignored
`.artifacts/s1-mixed-cursor-*`. These are local checks, not platform passes.

## Remaining gates

Commit and push the candidate, publish immutable development image digests,
then deploy and verify Native traffic on cl02 before updating retained Kind
`unf-s1-571379d`. Recover its existing durable state without clearing anything,
check actual generation progression and packets, then qualify fresh Kind and
the complete lifecycle. Required locality/replica/reply coverage, Native traffic
continuity under benign metadata churn, and stabilization S1–S5 remain open.
This repair alone does not close Phase 9 or establish a heavy-load envelope.
