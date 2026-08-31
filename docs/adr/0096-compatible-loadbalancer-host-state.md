# ADR 0096: Distribute and activate LoadBalancer host state independently

**Status:** Accepted and implemented for Phase 6.4 (2026-08-31)

## Context

The Phase 6.3 allocator and reachability provider established ownership but did
not give an authenticated Node an exact desired VIP set or make that state
restart safe. Reusing the service or NodePort bank would couple independent
failure domains, and publishing Kubernetes status before packet translation
would expose a promise the dataplane cannot yet satisfy.

## Decision

- Compatibility responses add a LoadBalancer reachability schema. Old
  controllers decode as schema zero, so new agents omit this reconcile loop;
  controllers require the current capability before accepting convergence.
- The controller enables allocation only when an operator supplies at least one
  IPv4/IPv6 pool and a stable pool UID. It persists the exact allocator and
  reachability revision in `unf-load-balancer-control-plane` before exposing a
  changed desired snapshot. Allocation intent fences the complete controller
  epoch/revision tuple; allocation checkpoint v2 explicitly migrates v1 leases.
- Only Services with `network.unf.io/load-balancer` participate. The live loop
  adds or removes only `network.unf.io/load-balancer-protection`, preserves
  foreign finalizers, excludes deleting or orphaned owners from reachability,
  waits for exact fresh all-Node acknowledgements, releases their leases, then
  removes the finalizer. It does not publish LoadBalancer status in this
  milestone.
- The Pod-bound TokenReview channel projects a complete snapshot to the exact
  Node name and UID. The agent persists an owner-only checkpoint with mode
  `0600`, rejects regression or same-revision mutation, and reports desired and
  applied epoch, reachability revision, allocation revision, bank, count, and a
  bounded failure.
- Persistent BPF-state ABI v6 owns an exact 24-map set. Separate IPv4/IPv6
  LoadBalancer frontend maps and config use their own two banks while every
  value references the exact active service revision and bank. The agent stages
  the inactive bank, reads every entry back, prepares its checkpoint, switches
  one pointer, commits, and then retires the previous bank. Startup either
  completes or rolls back an interrupted transaction from exact map/checkpoint
  evidence.
- The new maps are deliberately not consumed by the TC packet path until
  milestone 6.5. ClusterIP and NodePort attachment and forwarding semantics are
  unchanged.

## Consequences

Controller, agent, and host replacement retain deterministic allocation and
last-known-good Node state without treating service state as advertisement or
dataplane readiness. Capacity failure, checkpoint failure, and restart cannot
partially activate a VIP bank. Kubernetes status remains empty until the
`externalTrafficPolicy: Cluster` packet gate proves translation and reverse
state.

The ConfigMap store is bounded to 900,000 encoded bytes. Larger production
allocation stores and production BGP/L2/cloud providers remain independent
future gates.

## Verification

`make loadbalancer-host-state-test` runs the prior Phase 6 gates, allocation
checkpoint migration and epoch fencing, authenticated Node projection,
capability/revision/error convergence tests, strict agent checkpoint and
transaction tests, exact v4/v5/v6 cleanup classification, every deployment
render, strict Clippy, an LLVM-compatible eBPF build, and privileged real-kernel
map tests. The LoadBalancer test injects partial inactive-bank capacity failure,
proves exact rollback, and reconstructs the committed bank after restart while
the existing ClusterIP and NodePort transaction tests remain green.
