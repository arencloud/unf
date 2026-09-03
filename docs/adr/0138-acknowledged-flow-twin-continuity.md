# ADR 0138: Acknowledged Flow Twin continuity

**Status:** Accepted and implemented for Phase 8 milestone 8.6c

## Context

Moving an egress address and source selection preserves new-flow availability,
but an established TCP or UDP flow also depends on its exact NAT mapping. A
replacement gateway that chooses a different translated port breaks reverse
traffic. Blindly copying a raw conntrack map is unsafe: it can copy half a
forward/reverse pair, foreign leases, expired records, torn updates, or state
that the standby never actually installed.

An asynchronous system also cannot truthfully guarantee that the newest flow
was replicated immediately before an abrupt power loss. UNF therefore needs a
clear boundary between acknowledged continuity and the visible, measurable
replication tail.

## Decision

UNF uses schema-v1 Acknowledged Flow Twins (AFT). A flow twin is one semantic
forward/reverse NAT pair, never two independently transferable map entries. It
binds the original tuple, identity, protocol, egress address and translated
port, contract revision/digest, proof witness, lease epoch, CCR shard, and last
seen time. Its immutable flow ID excludes only the mutable liveness timestamp.

For every old-to-new gateway pair in a certified contingency, a bounded stream
names the exact shard set. Each upsert or remove has a strictly increasing
sequence, previous chain digest, and domain-separated operation digest. Primary
and standby apply the same validator and canonical state transition. Missing,
reordered, replayed, malformed, foreign-shard, regressing, or over-capacity
deltas fail closed.

The standby acknowledges the complete canonical snapshot, record count, chain
watermark, stream/controller epoch, exact Node UIDs, active plan digest, and a
local replica revision. Promotion accepts one exact stream and acknowledgement
per distinct shard handoff pair.

Cutover is bound to the complete proof-carrying promotion authority. It imports
only acknowledged records whose lease, address, and shard match that handoff
and whose protocol timeout has not elapsed at the monotonic cutoff. Duplicate
flow identity across streams is rejected. The output binds the replacement
records and target source bank into one digest, allowing the gateway import to
complete before a single atomic source-bank switch.

The guarantee is intentionally precise: flows at or below the acknowledged
watermark can continue; an unacknowledged asynchronous tail may reconnect and
is reported as a continuity gap. A provider may later choose synchronous
replication for stricter durability without changing the proof format.

## Why this is useful

AFT combines pair integrity, ordered replication, exact standby readback,
lease/shard provenance, expiration safety, and atomic cutover under one replay
boundary. It avoids a dependency on a particular kernel conntrack engine,
gateway count, reachability provider, or consensus database. The packet path
continues to perform fixed map lookups; stream validation stays in userspace.

## Consequences

`make egress-ha-continuity-test` verifies primary/standby convergence, exact
watermark acknowledgement, replay/loss/reorder rejection, shard fencing,
live-only import, and mutation resistance.

This slice defines and proves the state protocol. Milestone 8.6d must connect it
to live controller/agent transport, exact exclusive gateway projections, map
pair import, and atomic source activation. The final 8.6 gate must measure the
acknowledged and unacknowledged disruption windows on dual-stack Kind.
