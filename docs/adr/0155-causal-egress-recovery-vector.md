# ADR 0155: Fence restart and rollback with a Causal Egress Recovery Vector

**Status:** Accepted and implemented for Phase 8 milestone 8.9c

## Context

Phase 8 persists desired intent, allocation/gateway/HA control state, DNS and
internet evidence, DQR evidence, agent host state, BGP state, and observed flow
history in deliberately separate ownership domains. A restart must not convert
their independent durability into accidental authority. In particular, equal
revision numbers with different desired models are not a valid last-known-good
state, and derived control state may never lead its durable desired source.

The component compatibility endpoint previously exposed the general persistent
BPF ABI and policy/service schemas but omitted the egress distribution,
host-state, promotion, map, and event contracts. Their payloads still validated
themselves, but an operator could not audit the complete egress upgrade vector
before rollout.

## Decision

UNF treats the ordered compatibility fields and recovery comparisons as a
**Causal Egress Recovery Vector (CRV)**:

1. Controller and agent compatibility responses add egress distribution,
   host-state, HA-promotion, map, and event schema versions. This is an additive
   compatibility-schema-v2 extension, so adjacent readers ignore unknown
   fields. A missing field decodes as zero and is accepted only as a legacy
   preflight; every subsequent egress payload still requires its exact schema,
   recipient, capabilities, revisions, and digest. Any advertised nonzero
   mismatch is rejected before persistent BPF state access.
2. Controller restart compares the restored control-plane checkpoint with the
   separately durable desired store. Derived state ahead of desired state is
   rejected. Equal revisions require byte-semantic model equality. Desired
   state one or more revisions ahead is the only recoverable skew and is marked
   `ReconcileForward`, preserving the existing desired-before-derived write
   order without manufacturing an intermediate grant.
3. Control-plane checkpoint v5 migrates to v6 with empty failover history.
   Future schemas fail closed. A v6 checkpoint containing terminal history
   cannot be relabeled as v5 to make a rollback silently discard evidence.
4. Current persistent ABI cleanup remains opt-in and exact. Planning rejects
   the whole operation if any foreign pin exists. Execution removes only the 40
   recognized Phase 8 maps, exact TCX links, and exact tail programs in the
   named version directory; adjacent ABI directories and sibling operator data
   remain untouched.
5. The milestone gate composes existing controller, DQR/provider, agent
   persistent-state, BGP, Chronicle, and operations recovery tests with the new
   CRV, migration, rollback-refusal, and cleanup tests. Passing unit tests does
   not claim a live platform upgrade; that remains part of 8.10 and 8.11.

## Consequences

An upgrade has a machine-readable egress contract before any persistent map is
opened. Restart skew has exactly one safe forward direction, while equal-index
mutation and derived-ahead state stop startup. An older adjacent component can
still participate when the shared persistent ABI is unchanged, but it gains no
permission to bypass exact egress payload admission.

Rollback after terminal failover history appears may require exporting or
retaining the v6 checkpoint rather than running an older controller. This is
intentional: evidence is not discarded merely to make a downgrade convenient.

## Verification

`make egress-upgrade-recovery-test` verifies the complete CRV, current and
legacy additive wire shape, nonzero mismatch rejection, v5-to-v6 migration,
future-version and evidence-losing rollback refusal, cross-checkpoint restart
ordering, DQR/provider replay, agent last-known-good rejection paths, BGP
durability, exact current-ABI cleanup, inherited causal operations, and strict
Clippy.
