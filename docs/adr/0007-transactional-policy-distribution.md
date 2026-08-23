# ADR 0007: Dual-bank transactional policy distribution

Status: Accepted for the Phase 2 policy-distribution slice

## Context

Policy state affects forwarding and cannot be updated entry by entry in the
active lookup set. A failed or interrupted update must leave the previously
acknowledged policy revision usable. The BPF representation must also remain
independent of Kubernetes selectors and controller watch order.

## Decision

The controller resolves the normalized policy IR against admitted endpoint
identities. It emits sorted entries for exact identity/protocol/port decisions
and a protocol/port-zero fallback for wildcard rules and policy defaults. Each
decision retains actual and shadow verdict, policy ID, rule ID, and a stable
machine-readable reason.

Agents poll an epoch/revision policy snapshot and manage two logical banks in
`POLICY_RULES`. The bank number is part of the fixed-size key. For revision
`N+1`, an agent:

1. validates the complete snapshot and encodes the inactive bank;
2. populates that bank without modifying the active bank;
3. reads every staged entry back for validation;
4. atomically writes `POLICY_CONFIG[0]` with the epoch, revision, count, and new
   active bank;
5. acknowledges the revision and garbage-collects the old bank.

Any failure before the configuration write leaves the active bank selected and
attempts to restore the inactive bank's cached contents. Failure to collect an
old bank after activation is reported but cannot invalidate the newly active
revision. Map and snapshot schemas are independently versioned.

## Alternatives

A single hash map would expose partially written revisions. A map-in-map design
offers stronger kernel-level isolation but increases kernel compatibility and
loader complexity before measurements justify it. Sending Kubernetes objects to
the agent would duplicate selector and priority semantics outside the policy
compiler. gRPC remains deferred until HTTP snapshot polling is demonstrably
insufficient.

## Consequences

Policy distribution now has a single atomic activation point and observable
desired/applied revisions. The initial compiler expands known source and
destination identity pairs, so its cost and map cardinality are quadratic in the
number of distinct identities; scale tests and a more compact representation are
required before production. Maps are still unpinned, transport is unauthenticated
inside the prototype cluster, and the TC program does not consume the active
policy bank yet. Therefore this decision does not claim enforcement.

## Open questions

- measured entry count, update latency, and memory limits at production scale;
- map-in-map compatibility and migration from the bank-in-key representation;
- map pinning, agent restart recovery, and last-known-good persistence;
- authenticated node-specific state distribution and acknowledgement aggregation;
- compact CIDR, port-range, IPv6, and external-identity representations.
