# ADR 0132: Publish lease-specific gateway-drain evidence

**Status:** Accepted and implemented for the Phase 8.5 gateway-retirement slice

## Context

ADR 0130 requires every selected gateway to prove that a retiring egress lease
has no persistent NAT state before its addresses can be reused. Controller
intent, a disconnected gateway, an empty cache, and elapsed wall-clock time are
not proof of kernel state. Requiring the entire gateway projection to become
empty would also couple unrelated tenants and prevent one lease from retiring
while a gateway continued serving another.

The persistent LRU contains separate forward and reverse records. Deleting one
expired record while its peer is still active can interrupt an established
flow, while counting all gateway records would make unrelated leases block one
another.

## Decision

The controller exposes two internal TLS endpoints on the existing
TokenReview-authenticated Pod/Node trust path:

- `GET /v1/state/egress-gateway-retirements` returns the current controller
  epoch and only sealed manifests naming the caller's authoritative Node UID;
- `POST /v1/state/egress-gateway-drain` accepts a schema-v2, digest-bound
  zero-flow witness only from that current Pod, Node, UID, and epoch. Version 2
  explicitly adds the epoch rather than silently changing the earlier
  schema-v1 evidence shape.

The agent attempts retirement only after its monotonic gateway ledger has
adopted and acknowledged a projection containing no plan for the exact retiring
owner and lease epoch. Other leases may remain active. It snapshots and
validates the complete persistent connection map, using the same Linux
`CLOCK_BOOTTIME` basis and protocol timeouts as eBPF. If any record for the
lease remains active, it removes nothing. Once all records for that lease have
naturally expired, it removes the whole lease set and rescans the map. Evidence
is emitted only if that second validated snapshot contains zero matching
records.

The controller independently verifies the retained manifest, current epoch,
current agent Pod, authoritative Node UID, exact current pending projection,
and its accepted application acknowledgement. The current projection must
exclude the retired owner/epoch; a claimed boolean is never sufficient.

## Consequences

Established flows retain their full protocol lifetime and forward/reverse
state is collected as one lease unit. Unrelated tenants neither block nor lose
traffic during retirement. Corrupt map entries, map iteration/removal errors,
active records, a projection that still names the lease, stale controller
epochs, replaced Pods, and missing application evidence all preserve address
quarantine.

Accepted drain evidence is runtime state and cannot release an allocation by
itself. Independent reachability withdrawal and final authority assembly remain
required. `make egress-gateway-retirement-test` inherits the complete Phase 8.5
gate and adds domain, agent, controller, static contract, and strict Clippy
coverage.
