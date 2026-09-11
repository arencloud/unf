# ADR 0224: Complete Fleet Cursor Recovery Barrier

- Status: Accepted and implemented for Phase 9.9 remediation
- Date: 2026-09-11

## Context

The first fresh Kind qualification of the compact-frontier runtime passed live
ciphertext, selective fail-closed behavior, agent replacement, and natural key
rotation. During controller replacement, however, agents presented their
durable plan cursors sequentially. The restored controller could publish a
successor above the first cursor before learning that another Node had already
admitted a higher cut. Publishing a second successor then left different Nodes
holding different controller-admitted pending generations. The existing
single-pending-capability rule correctly refused to overwrite either one, so
the fleet stayed safe and unattached but could not converge.

## Decision

After restoring a durable fleet plan, the controller opens a **Complete Fleet
Cursor Recovery Barrier**. It records at most one current-plan generation for
each exact authenticated Node UID in the current membership. Cursors from a
different membership are treated as having no usable recovery coordinate.

The controller returns no successor until every member has contributed. It
then computes one monotonic floor above both the restored catalog and the
maximum accepted fleet cursor, closes the one-shot barrier, and produces one
atomic all-member plan cut. Normal non-recovery polling retains the existing
coalescing behavior and does not gain a new source of plan churn.

## Consequences

- Poll order, retry rate, and temporary per-Node cursor skew cannot create
  multiple restart-recovery successors.
- An absent member delays recovery rather than permitting a partial fleet cut
  or plaintext fallback.
- The barrier is volatile and restart-only. Its inputs remain authenticated
  durable agent cursors; it grants no key, route, map, proof, or packet
  authority.
- The generation remains explicitly bounded by the existing fleet membership
  and monotonic revision types.

## Verification

A three-member unit regression presents cursors out of order, proves that the
first two observations cannot publish, and requires the only completed floor
to be exactly one above the maximum. Existing authenticated delivery and
single-member predecessor-recovery tests remain green under strict Clippy. The
complete fresh dual-stack Kind transaction and independent cl02 qualification
remain mandatory before Phase 9 closes.
