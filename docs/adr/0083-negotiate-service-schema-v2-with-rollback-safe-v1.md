# ADR 0083: Negotiate service schema v2 with rollback-safe v1 state

Status: Accepted and implemented for Phase 5.2

## Context

Phase 5.1 made service schema v2 an intentional compatibility change. A direct
controller-first rollout would make an old agent reject the new controller's
compatibility tuple before persistent BPF access. An agent-first rollout would
have the inverse problem against an old controller. Sending schema-v2 NodePort
fields to a schema-v1 binary is unsafe, but requiring a simultaneous restart
would weaken the verified Phase 4 last-known-good and serial rollout contract.

The service-map ABI remains v1 under persistent BPF ABI v4 and can continue to
represent ClusterIP state. The additive schema change therefore needs a narrow
wire negotiation boundary rather than a dataplane rebuild.

## Decision

New agents explicitly request service schema v2 on both `/v1/version` and
`/v1/state/services`. An old controller ignores the unknown query parameter and
returns schema v1. The new agent accepts only that one legacy service schema,
adds an empty NodePort collection, normalizes it as v2 in memory, and continues
to require exact matches for every other compatibility field.

A new controller defaults requests without an explicit schema to v1. Its
compatibility response advertises v1 and its service response clones validated
current state, removes every NodePort record, sets schema v1, and omits the
additive field from JSON. An explicit v2 request receives the complete current
snapshot. Unknown requested versions and schema-v1 payloads containing
NodePort state fail closed.

This produces four deterministic combinations:

| Agent | Controller | Compatibility and state |
|---|---|---|
| old v1 | old v1 | Existing exact v1 behavior |
| new v2 | old v1 | Query is ignored; v1 is normalized in memory |
| old v1 | new v2 | Default compatibility and exact projection stay v1 |
| new v2 | new v2 | Explicit negotiation returns complete v2 intent |

While a snapshot has only ClusterIP intent, new agents persist its exact v1
projection. Read-time normalization does not rewrite that checkpoint, so a
serial rollback to an old binary can still consume the durable state and the
unchanged service-map ABI. A snapshot containing NodePort intent cannot be
projected for current lowering or persisted by the current agent because the
ClusterIP dataplane compiler rejects it before staging.

Agent status adds a defaulted service-schema capability field without changing
the agent-status schema. Old reports decode as capability zero and old
controllers ignore the additive field. A new controller may consider a legacy
report converged for ClusterIP-only state, but requires schema-v2 capability
when its authoritative snapshot contains any NodePort intent. New agents that
receive such intent publish the desired tuple and report the explicit lowering
failure while retaining last-known-good applied state.

## Verification

`make service-distribution-test` requires:

- v1 deserialization, in-memory normalization, and deterministic v1 projection;
- omission of `nodePorts` from the legacy JSON wire shape;
- rejection of disguised schema-v1 NodePort intent and unsupported versions;
- current and legacy compatibility negotiation;
- durable v1 read normalization without an on-disk schema rewrite;
- agent reporting of its current service-schema capability;
- legacy-agent convergence rejection when authoritative NodePort intent exists;
- strict service/controller/agent/state Clippy; and
- rendering of every supported deployment overlay.

The workspace-wide test gate remains required before commit.

## Consequences

Controller-first and agent-first serial transitions can preserve qualified
ClusterIP traffic and rollback state without weakening unrelated compatibility
checks. NodePort intent is visible only to a consumer that asked for schema v2,
and its failure remains explicit until Phase 5.3 adds host-facing transactional
state. Schema v1 is a bounded transition format, not a permanent extension
mechanism; later incompatible changes require their own negotiation decision.
