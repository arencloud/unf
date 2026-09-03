# ADR 0140: Durable HA promotion transaction

**Status:** Accepted and implemented for Phase 8 milestone 8.6e

## Context

The individual CCR, promotion, and flow-twin protocols were independently
replayable, but a controller restart between their transitions could lose
which evidence had been accepted. A safe live transport requires one durable
transaction whose partial states cannot be mistaken for activation authority.

## Decision

Control-plane checkpoint schema v4 stores an ordered promotion transaction per
intent. It embeds the exact previous CCR plan, immutable manifest, admitted
source fences, old-owner revocation or independent infrastructure fence,
replacement acquisitions, reachability CAS, flow-twin streams and standby
acknowledgements, and source-specific continuity cutovers.

Schema v3 has no promotion field and is migrated only as the unambiguous empty
transaction set; v4 data never downgrades. All earlier schemas remain rejected.

Restore independently verifies the previous plan, rebuilds the coordinator by
re-admitting every witness in protocol order, validates every stream and
acknowledgement, and reissues each cutover. Unknown, duplicate, reordered,
foreign, or partially forged state rejects the complete checkpoint.

Ownership cannot be restaged before all sources and the old owner are fenced.
After that barrier, the gateway registry removes the failed Node and CCR
compiles the survivor plan using the previous assignment, retaining the
mathematical maximum ownership. Sources remain fenced. Replacement address
readback and reachability CAS then complete the promotion authority. Each
source gets its own cutover bound to the inactive bank it actually reported;
only an exact set of acknowledged flow-twin streams can seal that cutover.

Kubernetes readiness and Lease are deliberately absent from every evidence
admission API. They may trigger investigation in the live adapter but cannot
advance the transaction.

## Consequences

`make egress-ha-transaction-test` inherits 8.6a–8.6d and proves an entire
three-gateway, multiple-address transaction across checkpoint restoration,
including rejection of a Kubernetes health fence and premature ownership.

The next slice transports these exact challenges and witnesses between watched
controller state and authenticated agents, imports flow twins into gateway
state, and measures drain/failure/recovery disruption on dual-stack Kind.
