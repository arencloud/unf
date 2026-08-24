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
plus two wildcard levels: `(protocol, port=0)` for protocol-only rules, followed
by `(protocol=0, port=0)` for all-protocol rules and policy defaults. Each decision
retains actual and shadow verdict, policy ID, rule ID, and a stable
machine-readable reason.

Agents poll an epoch/revision policy snapshot and manage two logical banks in
`POLICY_RULES`, `POLICY_IPV4`, and the later `POLICY_IPV6` LPM trie. The bank
number is part of each key. Snapshot schema v3 carries all three entry sets. For
revision `N+1`, an agent:

1. validates the complete snapshot and encodes all inactive banks;
2. populates those banks without modifying any active bank;
3. reads every staged entry in all maps back for validation;
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
desired/applied revisions. Agents periodically acknowledge their applied state;
the controller aggregates fresh reports against watched Nodes and current
identity/policy revisions for status and CLI inspection. The initial compiler
expands known source and destination identity pairs, so its cost and map
cardinality are quadratic in the number of distinct identities; scale tests and
a more compact representation are required before production. Maps are still
unpinned and transport is unauthenticated inside the prototype cluster. ADR 0008
connects TC enforcement to the active bank without changing this distribution
protocol.

## Open questions

- measured entry count, update latency, and memory limits at production scale;
- map-in-map compatibility and migration from the bank-in-key representation;
- map pinning, agent restart recovery, and last-known-good persistence;
- authenticated node-specific state distribution and durable acknowledgements;
- compact unbounded-CIDR, port-range, and external-identity representations.
