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
| 6.2 | LoadBalancer domain and Kubernetes compiler | **Verified** | Service snapshot schema v3 carries typed dual-stack family/frontends, requested VIPs, exact Service-port/backend linkage, class/policy/source-range/NodePort-allocation semantics, deterministic validation and collision rejection; the controller preserves foreign/classless ownership and last-valid state; exact v2/v1 projections and fail-closed lowerers prevent false convergence; `make loadbalancer-ir-test`; ADR 0094 |
| 6.3 | Address allocation and reachability-provider contract | **Verified** | `unf-loadbalancer` provides durable conflict-safe dual-stack leases, exact pool/provider/owner provenance, explicit-class Service translation, separately revisioned complete direct-Node reachability intent/acknowledgement, fail-closed finalizer/status ordering, exact withdrawal/replay/recovery, and foreign-state preservation; `make loadbalancer-control-plane-test`; ADR 0095 |
| 6.4 | Compatible distribution and transactional host state | **Verified** | Explicit schema negotiation; durable epoch-fenced allocation production; exact finalizer-safe withdrawal; Pod-bound per-Node projection; capability-aware convergence; private last-known-good checkpoints; persistent ABI v6's exact 24-map boundary; independent inactive-bank staging/readback/activation, rollback, crash repair, restart recovery, and v4/v5/v6 cleanup; `make loadbalancer-host-state-test`; ADR 0096 |
| 6.5 | `externalTrafficPolicy: Cluster` LoadBalancer dataplane | **Verified** | Exact coherent IPv4/IPv6 TCP/UDP VIP lookup; bounded collision-safe VIP source translation and paired reverse restoration; connection persistence through backend churn; backendless drop; policy and withdrawal ordering; bounded event provenance; verifier-loaded release execution plus ClusterIP/NodePort regression under `make loadbalancer-cluster-dataplane-test`; ADR 0097 |
| 6.6 | `externalTrafficPolicy: Local`, source ranges, and health checks | **Verified** | Receiving-Node-only ready/non-terminating selection, client-source preservation and reverse restoration, no-local-backend drop, transactional IPv4/IPv6 source-range LPM enforcement and restart reconstruction, exact dual-stack `healthCheckNodePort` 200/503 lifecycle, placement/readiness recovery, bounded provenance, and inherited Cluster/NodePort/ClusterIP regression under `make loadbalancer-local-dataplane-test`; ADR 0098 |
| 6.7 | Operations, simulation, upgrade, and recovery | **Verified** | Fixed-cardinality revision/frontend/source-range/health/outcome metrics; validated additive status; durable Cluster/Local history; allocation/provider/reachability explanation; source-aware read-only VIP simulation and CLI; exact durable controller/provider replay, foreign-provider refusal, agent runtime-state reconstruction, and same-tuple adjacent compatibility under `make loadbalancer-operations-test`; ADR 0099 |
| 6.8 | Kube-proxy-free Kind qualification | **Verified** | Runtime revision `dd11ae3` and qualifier `793273f` passed the 285-second three-Node Kubernetes v1.35.0 dual-stack gate with kube-proxy absent: external and host-origin IPv4/IPv6 TCP/UDP, Cluster/Local tuples, source ranges, health lifecycle, controller/provider/agent recovery, exact ABI-v7/CNI rollback, and schema-v1 evidence; `make loadbalancer-kind-test`; ADR 0100 |
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

Milestone 6.9 independently qualifies the bounded LoadBalancer contract on the
five-Node dual-stack OpenShift cl02 fixture. It must publish digest-pinned
controller, agent, and test-tool images, stage the compatible transition,
exercise cross-worker RHCOS/SELinux/CRI-O traffic and provider recovery, compare
ClusterOperator health, remove only owned fixture and host state, and retain an
immutable evidence record. The Kind result does not transitively qualify that
platform or production advertisement providers.
