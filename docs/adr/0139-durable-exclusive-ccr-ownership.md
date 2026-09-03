# ADR 0139: Durable exclusive CCR ownership

**Status:** Accepted and implemented for Phase 8 milestone 8.6d

## Context

The Phase 8.6a planner produced exclusive assignments, but the Phase 8.5 live
transport still sent the complete lease to every candidate gateway. Recomputing
placement from current Node readiness also allowed a health observation to
change authority without the promotion proof from ADR 0137. Source proof and
gateway dataplane selection could consequently disagree with address ownership.

## Decision

Control-plane checkpoint schema v3 stores the exact canonical CCR plan beside
allocation and gateway desired state. Restart restores it only after replaying
plan structure and cross-checking owner, allocation revision, lease epoch,
gateway revision, candidate identities, and complete address set. Once any
gateway record exists, ordinary watched reconciliation freezes that membership;
Node `Ready`, Lease, or label loss cannot silently rewrite ownership.

Source and gateway projections carry the same plan. Selection algorithm v3
first chooses an address shard, then uses the CCR active assignment and its
precomputed contingency for primary and standby. Flow proofs bind the HA plan
digest, and gateway verification repeats the same selection. Each gateway
address projection contains only the shards assigned to its authenticated Node.

Address transitions include the exact last controller-acknowledged Node set.
The agent independently reads that set back before a monotonic subset removal
or superset acquisition; mixed add/remove transactions fail closed. A former
owner can therefore receive and acknowledge an exact empty desired set instead
of interpreting HTTP 204 as cleanup. Kernel rollback retains the prior set on a
partial removal.

A selected standby is only a replication target. New packet state starts with
no `STANDBY_CERTIFIED` bit; that bit may be set only after Acknowledged Flow Twin
readback. This prevents an optimization hint from becoming a false continuity
claim.

## Consequences

`make egress-ha-live-ownership-test` inherits the planner, promotion,
continuity, and live Phase 8.5 gates, then runs the complete egress/controller/
agent suites and strict Clippy. The resulting live baseline has exactly one
address owner and one proof/dataplane choice per shard across restart.

This slice deliberately does not infer failover from Kubernetes health. The
next transaction must transport source fences, old-owner or infrastructure
fencing, replacement acquisition, reachability CAS, flow-twin import, and the
final activation authority before measured failure availability can be claimed.
