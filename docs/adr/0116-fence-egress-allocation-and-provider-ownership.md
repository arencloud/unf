# ADR 0116: Fence egress allocation and provider ownership

**Status:** Accepted and implemented for Phase 8.3

## Context

An egress address cannot become usable merely because intent requested it.
Allocation, gateway host readiness, and external reachability can succeed or
fail independently, and stale provider state can outlive controller or workload
restarts. Reusing an address before old gateway and reachability state is
withdrawn creates split ownership and potentially routes traffic through the
wrong security context.

Phase 8.3 needs durable, replayable ownership semantics before authenticated
distribution or packet processing exists. The checkpoint formats are durable
domain records; wiring them to controller storage belongs with the later runtime
watch/reconciliation integration.

## Decision

`EgressAllocator` owns canonical allocation checkpoints at schema v1. It:

- validates the complete non-overlapping pool set before use;
- allocates the lowest available usable address deterministically across
  canonical prefixes, with an explicit bounded scan;
- allocates the requested count independently for IPv4 and IPv6 and plans all
  addresses before mutating ownership;
- requires explicit provider provenance for non-pool address requests;
- prevents address collision across pool and explicit leases;
- treats address request and provider as immutable while allowing newer
  selector/destination intent to refresh the same lease;
- fences intent epoch/revision regression and allocation revision exhaustion;
- assigns a monotonically increasing lease epoch on new ownership, including
  reuse after release; and
- restores only sorted, collision-free, pool/provider/address/revision/epoch
  exact checkpoints.

`EgressGatewayRegistry` separately owns schema-v1 gateway desired state,
gateway-readiness acknowledgements, reachability acknowledgements, and its
checkpoint. Gateway and reachability providers implement separate interfaces.
Every desired operation binds owner, provider, allocation revision, lease epoch,
addresses, exact Nodes, and a monotonically increasing gateway revision.

An ensure operation is idempotent only for the identical active epoch. A
different epoch or address cannot replace a retained record. Addresses stay
fenced through withdrawal until both providers acknowledge the exact Withdraw
revision. Acknowledgement streams have independent nonzero monotonic revisions;
regression, same-revision mutation, provenance mismatch, partial success, and
unbounded rejection errors fail closed.

Publication is ready only for Ensure state with exact Ready acknowledgement from
both providers. Only that state can project gateway facts into an Egress
Behavior Contract. Allocation leases likewise project exact pool UID/address/
epoch facts directly, so adapters never reconstruct ownership heuristically.

## Consequences

- Allocation does not imply gateway readiness, reachability, dataplane state, or
  status publication.
- Gateway readiness does not imply reachability; both are separately revisioned
  and replayed.
- Safe withdrawal precedes address release/reuse at the orchestration boundary.
- Failure is atomic: exhaustion, collision, stale intent, malformed checkpoint,
  and stale provider acknowledgement retain last-known-good state.
- Canonical Node ordering is only a deterministic input order. Phase 8.3 makes
  no HA-placement quality or disruption claim; milestone 8.6 requires measured
  placement and failover.
- This milestone adds no Kubernetes watcher/CRD/RBAC, controller storage adapter,
  authenticated distribution, host mutation, BPF ABI, packet behavior, or
  platform qualification claim.
- `make egress-allocation-test` is the repeatable milestone gate.
