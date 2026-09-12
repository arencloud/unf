# ADR 0256: LoadBalancer Pending-Checkpoint Cleanup Closure

## Status

Accepted and implemented for Phase 9.9 requalification

## Context

The first complete Kind run of ADR 0255 passed encryption traffic, ciphertext,
fault denial/recovery, rotation, component replacement, and Phase 8 egress
coexistence. Its final no-CNI rollback then stopped on one exact file:
`load-balancer-reachability.json.pending` on the replaced worker agent.

This is not an atomic-write temporary covered by ADR 0232. It is the agent's
ordinary persist-before-host-adoption checkpoint. SIGTERM after persistence and
before the pending state is committed or superseded may legitimately retain
it. The rollback already validates and removes the committed LoadBalancer
checkpoint, but did not close over this producer-owned pending name.

## Decision

The isolated Kind rollback adds **LoadBalancer Pending-Checkpoint Cleanup
Closure**. After every agent has stopped and fixture workloads are drained, it:

- names only the exact committed and `.pending` LoadBalancer checkpoint paths;
- applies the existing strict schema, owner-only mode, Node name/UID, provider,
  revision, allocation, and target validation independently to either file;
- removes a validated pending checkpoint in both the ordinary and idempotent
  resumed-rollback branches; and
- leaves unknown names, symlinks, modes, Nodes, providers, or payloads as hard
  failures that keep the state directory nonempty.

No glob, recursive deletion, runtime behavior, BPF state, or image content is
changed.

## Consequences

- A normal termination between LoadBalancer checkpoint preparation and commit
  no longer strands an otherwise exact no-CNI rollback.
- A pending file gains no authority from its name; it must independently prove
  the same bounded Node-owned payload as the committed checkpoint.
- The interrupted rollback must first resume successfully, then a completely
  fresh Phase 9 Kind lifecycle must pass at one clean committed revision before
  any image is published or cl02 is mutated.
