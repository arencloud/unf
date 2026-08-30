# Phase 6 LoadBalancer execution plan

Last reviewed: **2026-08-31**

Phase 6 extends the verified ClusterIP and NodePort fabric with bounded,
provider-neutral LoadBalancer exposure. It separates Kubernetes ownership, VIP
allocation, network advertisement, and packet translation so a routing or cloud
backend can change without changing Service intent or the eBPF fast path. The
authoritative feature state remains in [project-status.md](../project-status.md).

The `6.x` identifiers below are product-phase identifiers. Historical Full-CNI
foundation deliverable numbers in the Phase 3 completion plan remain immutable
evidence and are not reinterpreted by this plan.

## Milestone summary

| ID | Milestone | State | Exit evidence |
|---|---|---|---|
| 6.1 | Architecture, ownership, and acceptance boundary | **Verified** | ADR 0093 fixes explicit class ownership, distinct VIP intent, independent allocation/advertisement/translation revisions, fail-closed status publication, the ordered compatibility path, platform gates, and bounded exclusions; `make loadbalancer-boundary-test` prevents drift across the plan, ADR, trackers, README, and component boundary |
| 6.2 | LoadBalancer domain and Kubernetes compiler | **In progress** | Service snapshot schema v3; typed dual-stack VIP/frontend records; exact Service-port/backend linkage; class, family, policy, source-range, and NodePort-allocation semantics; deterministic normalization, bounds, collision rejection, retained-last-valid controller status; `make loadbalancer-ir-test` |
| 6.3 | Address allocation and reachability-provider contract | **Planned** | Durable conflict-safe dual-stack allocation; explicit pool/provider ownership; finalizer and status transaction; revisioned advertisement intent/acknowledgement; first bounded qualification provider; withdrawal, replay, and foreign-state preservation tests |
| 6.4 | Compatible distribution and transactional host state | **Planned** | Old/new controller-agent negotiation; rollback-safe projection; capability-aware convergence; authenticated provider state; inactive-bank staging/readback; crash repair, restart recovery, and exact cleanup without disturbing verified ClusterIP/NodePort state |
| 6.5 | `externalTrafficPolicy: Cluster` LoadBalancer dataplane | **Planned** | Exact IPv4/IPv6 TCP/UDP VIP lookup; bounded Node SNAT where required; paired reverse restoration; connection persistence; lifecycle and policy ordering; verifier-loaded packet execution |
| 6.6 | `externalTrafficPolicy: Local`, source ranges, and health checks | **Planned** | Ready non-terminating local selection, client-source preservation, no-local-backend behavior, IPv4/IPv6 source-range enforcement, exact `healthCheckNodePort` semantics, placement/readiness recovery, and Cluster regression |
| 6.7 | Operations, simulation, upgrade, and recovery | **Planned** | Fixed-cardinality metrics and events; status, history, explanation, allocation/advertisement provenance, read-only simulation, controller outage, agent/provider replacement, adjacent rollback, and actionable failures |
| 6.8 | Kube-proxy-free Kind qualification | **Planned** | Disposable dual-stack external-client fixture; VIP reachability, host-origin and external TCP/UDP, Cluster/Local/source-range/health lifecycle, outage recovery, exact cleanup and rollback, immutable evidence |
| 6.9 | OpenShift qualification | **Planned** | Digest-pinned five-Node dual-stack cl02 gate for RHCOS/SELinux/CRI-O, cross-worker VIP traffic, provider recovery, health/status convergence, exact cleanup, and no new unhealthy ClusterOperator |

## Accepted Phase 6 gate

The bounded LoadBalancer gate closes only when one exact committed tuple passes
both Kind and OpenShift with kube-proxy absent and demonstrates:

- explicit ownership of `spec.loadBalancerClass: network.unf.io/load-balancer`;
- collision-safe dual-stack VIP allocation and exact release/reuse;
- separately revisioned allocation, advertisement, and dataplane convergence;
- status publication only for VIPs whose reachability and dataplane are ready;
- IPv4 and IPv6 TCP/UDP through externally routed VIPs;
- `Cluster` and `Local` source/reverse tuple behavior;
- `loadBalancerSourceRanges` and `healthCheckNodePort` semantics;
- readiness, termination, deletion, reassignment, withdrawal, and recovery;
- controller outage plus source/destination agent and provider recovery from
  validated last-known-good state;
- metrics, status, history, explanation, and read-only simulation with bounded
  allocation, provider, Service, backend, and revision provenance;
- exact map, route/address, socket, checkpoint, fixture, status/finalizer, and
  provider-state cleanup; and
- immutable source, image, platform, and qualification evidence.

## Ownership and compatibility rules

- UNF owns only the explicit class above. Managing classless LoadBalancer
  Services requires a separate opt-in configuration and independent conflict
  checks; it is disabled by default.
- VIP allocation never implies advertisement, and advertisement never implies
  dataplane readiness. Each domain has an independent desired/applied revision
  and bounded error state.
- A LoadBalancer VIP is distinct intent. It is never encoded as a synthetic
  ClusterIP or NodePort, even when the implementation reuses common backend
  slots and connection state.
- `allocateLoadBalancerNodePorts: false` is preserved. UNF must not require a
  traffic NodePort merely to implement direct VIP delivery.
- Foreign status, address ownership, advertisements, routes, sockets, and BPF
  state are rejected or preserved according to explicit ownership; they are
  never adopted by name or deleted broadly.
- Schema and persistent-state changes use controller-first negotiation,
  last-known-good persistence, inactive staging, readback, atomic activation,
  rollback, and exact versioned cleanup.

## Explicit exclusions

Phase 6 does not silently claim classless/cloud-provider takeover, production
BGP, EVPN, ECMP, BFD, session affinity, `internalTrafficPolicy`, topology hints,
Maglev, DSR, SCTP Service forwarding, fragments, generic NAT `RELATED`
tracking, multi-cluster VIPs, Gateway API, or production availability/scale.
Those capabilities require independent implementations and qualification gates.

## Immediate next slice

Milestone 6.2 introduces the Kubernetes-independent LoadBalancer record and
schema-v3 transition before any controller writes status, allocates an address,
advertises a route, mutates a host map, or claims packet support. The compiler
must preserve exact family/port/protocol/backend linkage and fail closed on
unknown class ownership, malformed source ranges, ambiguous VIP ownership, or
unsupported semantics.
