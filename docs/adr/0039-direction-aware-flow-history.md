# ADR 0039: Direction-aware flow export and history

Status: Accepted and live verified on dual-stack kind

## Context

Flow events already carry the decisive policy direction, but agent export
dropped it. The controller therefore aggregated identical ingress and egress
tuples into one logical history key, and historical simulation always evaluated
them as ingress. That made egress history and impact analysis untrustworthy.

The previous controller also required a resolved destination identity for every
export. That is correct for destination-selected ingress but rejects valid
source-selected egress to an external address.

## Decision

Flow export schema v3 adds policy direction to `FlowHistoryKey`. History snapshot
schema v4 uses direction as part of the aggregation key, so ingress and egress
observations of the same L3/L4 tuple remain separate. The agent validates the
event direction and exports when the direction-selected identity is resolved:
destination identity for ingress, source identity for egress.

Controller validation applies the same selected-identity rule. Historical
evaluation dispatches through the shared direction-aware evaluator and supplies
the retained concrete destination address, preserving egress `ipBlock` behavior.
Historical change records expose their direction explicitly.

Checkpoint schema v2 persists the expanded key. The reader accepts schema v1 and
uses the field's serde default to migrate its records to ingress, the only policy
direction supported when that schema was written. New checkpoints are always
schema v2; unknown schemas remain rejected.

## Verification

State tests prove the same tuple in ingress and egress remains two logical keys,
observations stay bounded, and a serialized schema-v1 checkpoint without the
field restores as ingress. Agent tests prove event conversion, selected-source
external egress eligibility, and invalid direction rejection. Controller tests
prove direction-specific selected-identity validation and direction-aware
historical evaluation inputs.

The focused dual-stack egress matrix requires schema-v4 history containing
IPv4/IPv6 egress allows and a retained egress default deny at the exact active
policy revision. The complete Kind retention gate verifies schema-v2 persistence
and restore, controller restart continuity, and no agent replacement; schema-v1
migration is covered deterministically by the state-store unit test.

## Consequences

`unfctl flows` can distinguish the policy direction responsible for each
retained decision, and simulation cannot silently reinterpret an egress record
as ingress. External egress can enter bounded history without inventing a
destination workload identity.

This does not by itself add a NetworkPolicy what-if input. The existing native
SecurityPolicy simulation remains ingress-scoped; a separate API slice is needed
to simulate add/replace of multi-direction NetworkPolicy objects.
