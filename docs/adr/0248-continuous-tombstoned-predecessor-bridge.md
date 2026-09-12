# ADR 0248: Continuous Tombstoned Predecessor Bridge

## Status

Accepted

## Context

The ADR 0247 tuple crossed the original cl02 reboot residue and made all five
agents ready without resetting state. The complete Phase 9.9 gate then changed
the encryption baseline. A successor using epoch 42 became controller-admitted
but did not activate before authority expiry durably revoked through epoch 42
and advanced to fresh epochs. All agents correctly retained their active
predecessor and refused the unknown key, but ADR 0246 exposed its bridge only
during startup. Periodic plan reconciliation therefore could not consume the
newer authenticated plan.

## Decision

Use one shared tombstoned-admission transition from both startup recovery and
the continuous plan loop. On every periodic plan reconciliation, before an
admitted predecessor is selected for ordinary settlement, the agent checks the
same strict conditions as ADR 0246: a newer authenticated desired generation,
an exact durable admission and recovery-plan match, and a complete local plan
whose key references are all durably tombstoned.

When those conditions hold, the shared transition preserves the original
ordering:

1. persist the exact map predecessor bridge;
2. zero encryption configuration and remove connection leases;
3. verify the dataplane is fail closed;
4. remove only the tombstoned pending Linux stage; and
5. retain the admitted logical cursor for an exact fresh-key successor.

Any classification, persistence, map, readback, Linux cleanup, or ancestry
failure leaves the predecessor fenced and retries through normal periodic
reconciliation. Mixed, available, unknown, empty, non-adjacent, or conflicting
authority is never treated as a bridge candidate.

## Consequences

- Authority expiry between admission and activation no longer requires an
  agent restart to reach the existing safe recovery transition.
- Restart and steady-state recovery use identical ordering and invariants.
- The ADR 0247 tuple remains valid historical Kind evidence but is not eligible
  to complete cl02. The revised runtime requires fresh Kind qualification,
  immutable publication, and a complete cl02 rerun.
