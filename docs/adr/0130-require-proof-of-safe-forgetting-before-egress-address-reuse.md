# ADR 0130: Require Proof of Safe Forgetting before egress-address reuse

**Status:** Accepted and implemented for the Phase 8.5 release-authority slice

## Context

An egress address can remain dangerous after desired state has been removed.
An old source may still steer toward it, a gateway may retain a NAT tuple, or a
reachability provider may still advertise it. Releasing the allocator lease
after a timeout, controller-election change, or inferred absence can therefore
assign the same public identity to a new tenant while stale traffic still uses
the old authority.

The prior controller path waited for gateway and reachability provider
withdrawal acknowledgements, but it did not require an exact source-fence set or
a zero-connection gateway drain. That was insufficient for safe reuse.

## Decision

UNF introduces a schema-v1 **Proof of Safe Forgetting** protocol. When an
allocation enters withdrawal, the controller freezes a canonical retirement
manifest containing the exact owner, lease epoch, addresses, selected gateway
Nodes, and admitted source identities with their recipient, contract revision,
and digest. The manifest is stored in checkpoint schema v2. Exact replay is
idempotent; a later attempt to replace the set is rejected.

Release requires one domain-separated SHA-256-sealed authority joining:

- destination-preserving fence evidence covering the exact manifest source set;
- explicit withdrawal plus a zero-active-connection drain from every exact
  selected gateway;
- the exact retained reachability-provider `Withdrawn` acknowledgement; and
- the same retained manifest, owner, lease, allocation, address, revision, and
  controller epoch.

All collections are canonical, bounded, duplicate-free, and exact-set checked.
Empty source membership is valid only when explicitly captured in the durable
manifest. Foreign, missing, duplicated, stale, nonzero-flow, same-revision
mutated, or digest-mutated evidence fails closed. The controller consumes the
authority atomically: gateway ownership, allocation, and retirement state are
removed together or all remain quarantined.

Ordinary reconciliation no longer finalizes withdrawal. Provider
acknowledgements alone cannot release an address, and no timer, leader tenure,
or missing runtime record substitutes for positive evidence.

## Consequences

Address reuse becomes a positive distributed-safety decision rather than a
garbage-collection side effect. This is particularly useful after partitions,
controller replacement, slow route withdrawal, and asymmetric NAT recovery:
availability may pause, but stale authority cannot silently cross tenant or
workload boundaries.

This slice verifies the domain protocol, durable controller registration,
restart replay, atomic consumption, and adversarial rejection. Live agent
production and transport of source-fence/gateway-drain evidence, a concrete
reachability provider, NAT event export, and end-to-end platform packets remain
separate gates; no runtime release is claimed until those producers are wired.

`make egress-safe-forgetting-test` inherits all prior Phase 8.5 gates and adds
focused exact-set, digest mutation, nonzero-flow, unregistered-manifest,
provider-only, restart, release/reuse, and strict Clippy evidence.
