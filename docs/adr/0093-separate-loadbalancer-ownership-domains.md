# ADR 0093: Separate LoadBalancer ownership domains

**Status:** Accepted and implemented for the Phase 6.1 architecture boundary
(2026-08-31)

## Context

Phase 5 verifies dual-stack ClusterIP and NodePort translation without
kube-proxy. A Kubernetes LoadBalancer adds at least three independently failing
domains: allocating a VIP and publishing API status, making that VIP reachable
from a network, and translating traffic to eligible backends. Treating those as
one boolean or representing a VIP as a synthetic ClusterIP/NodePort would hide
partial failure, couple UNF to one routing backend, and let status promise
reachability before packets can arrive.

LoadBalancer ownership can also conflict with cloud controllers, in-cluster
implementations, manually managed addresses, and routing systems. UNF needs an
explicit admission boundary before it watches or mutates such Services.

## Decision

UNF owns a Service only when `spec.loadBalancerClass` is exactly
`network.unf.io/load-balancer`. Classless ownership is disabled by default and
may be added only as explicit operator configuration with conflict detection.
UNF does not adopt another controller's status or infer ownership from an
address value.

The service domain will add a distinct, bounded LoadBalancer frontend record.
It carries address family, VIP, Service and backend linkage, protocol/ports,
external traffic policy, source ranges, and allocation/provider provenance. It
may share validated backends, slots, and connection machinery, but it remains
separate intent on the wire, in status, in events, and at the host dataplane.

The controller and agents model three independent transactions:

1. allocation owns a collision-free address lease and Kubernetes finalizer;
2. advertisement owns revisioned provider intent and acknowledgement; and
3. dataplane owns transactionally activated VIP translation and health state.

Kubernetes `status.loadBalancer.ingress` is published only after the allocation
is durable and the required advertisement and dataplane participants report the
same admitted revision ready. Withdrawal removes externally promised status
before releasing address ownership. Failure retains the last complete valid
state when safe and exposes the blocked desired revision explicitly.

Allocation and advertisement use provider interfaces. The first qualification
backend will be intentionally bounded and reproducible; BGP and cloud/fabric
adapters remain independent later implementations. Routing protocols do not run
inside eBPF, and policy/IPAM/CNI ownership does not depend on one provider.

`allocateLoadBalancerNodePorts: false` remains meaningful. Direct VIP delivery
cannot require a traffic NodePort. `healthCheckNodePort`, when Kubernetes
allocates it for `externalTrafficPolicy: Local`, is separate health behavior and
must report exact local eligibility rather than act as a traffic shortcut.

## Consequences

- Service snapshot schema v3 and explicit old/new negotiation are required.
- Allocation, advertisement, and translation can progress or fail
  independently without falsely declaring a Service ready.
- The controller needs narrowly scoped status/finalizer writes and durable
  allocation state; agents need authenticated provider/dataplane inputs.
- A route, address, neighbor, socket, or BPF entry without exact UNF ownership
  is foreign and must survive reconciliation and cleanup.
- The initial implementation is larger than translating a status IP, but it
  avoids baking cloud, L2, or BGP assumptions into the core service model.
- Session affinity, internal traffic policy, topology-aware selection, Maglev,
  DSR, SCTP, production BGP/ECMP/BFD, multi-cluster, Gateway API, and production
  scale remain outside Phase 6 unless a later ADR and repeatable gate admit
  them.

## Verification

Phase 6.1 is the architecture and acceptance milestone. It is verified when the
execution plan, roadmap, authoritative status tracker, README, and component
ownership descriptions agree on the three-domain transaction, explicit class,
ordered compatibility path, platform gates, and exclusions. Milestones 6.2–6.9
must add their listed automated and live evidence before Phase 6 can close.
`make loadbalancer-boundary-test` checks that this contract and milestone state
remain consistent across those documentation surfaces.
