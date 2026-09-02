# Phase 8 identity-aware egress-fabric execution plan

Last reviewed: **2026-09-02**

Phase 8 implements master-prompt §24 as a provider-neutral enterprise egress
fabric. It builds on the verified source-side NetworkPolicy egress engine and
primary CNI, but treats external address ownership, gateway placement, steering,
NAT, reachability, and failover as separately revisioned domains. The
authoritative state remains in [project-status.md](../project-status.md).

## Milestone summary

| ID | Milestone | State | Exit evidence |
|---|---|---|---|
| 8.1 | Architecture and acceptance boundary | **Verified** | ADR 0113 fixes explicit ownership, policy-before-steering precedence, an independently verified Egress Behavior Contract, lease-fenced gateway epochs, deterministic placement/failover, provider boundaries, compatibility, recovery, platform gates, and exclusions; `make egress-fabric-boundary-test` prevents drift |
| 8.2 | Egress intent, pool, and compatibility model | **Verified** | `unf-egress` provides bounded canonical Namespace/workload/ServiceAccount selectors, destinations, dual-stack non-overlapping pools, pool or explicit-address requests, deterministic complete-model validation, and strict ownership. The controller translates OpenShift `k8s.ovn.org/v1` EgressIP into the same intent, defaults/intersects selectors exactly, and preserves foreign status; `make egress-intent-test`; ADR 0114 |
| 8.2a | Egress Behavior Contract and reference validator | **Planned** | Canonical per-source/per-Node plans bind identity, destination, policy, pool, gateway candidates, capabilities, and revisions; independent replay produces compact decision witnesses and bounded failure envelopes |
| 8.3 | Durable allocation and gateway-provider contract | **Planned** | Conflict-safe dual-stack leases, multiple addresses, exact owner/pool/provider provenance, separately revisioned gateway readiness and reachability, safe withdrawal, checkpoint replay, and no status before complete acknowledgement |
| 8.4 | Transactional distribution and gateway host state | **Planned** | Authenticated exact-Node projection, capability negotiation, inactive staging/readback/activation, last-known-good checkpoints, epoch fencing, rollback/crash repair, and exact versioned cleanup |
| 8.5 | Source steering and gateway NAT dataplane | **Planned** | Policy-first IPv4/IPv6 TCP/UDP steering, original identity/source witness, collision-safe SNAT/reverse state, fragments and unsupported protocols fail closed, and bounded event provenance without Linux-conntrack duplication by assumption |
| 8.6 | Deterministic HA, failover, and multiple addresses | **Planned** | Lease-fenced gateway ownership, deterministic placement and failover, established-flow contract, bounded convergence, split-brain rejection, node drain/recovery, and measured disruption |
| 8.7 | FQDN and internet-access controls | **Planned** | DNS-derived destination sets with bounded TTL/staleness/provenance, explicit wildcard semantics, fail-closed capacity behavior, IP fallback visibility, and no use of DNS names as workload identity |
| 8.8 | Reachability and advertisement providers | **Planned** | Static/native development provider first; BGP advertisement remains a replaceable provider with independent route-policy, ECMP, graceful-restart, BFD, and production qualification gates |
| 8.9 | Operations, simulation, upgrade, and recovery | **Planned** | Fixed-cardinality metrics/status, NAT and failover history, allocation/gateway/policy explanation, read-only simulation, controller/provider/agent recovery, compatibility, and exact cleanup |
| 8.10 | Kube-proxy-free Kind qualification | **Planned** | Exact committed dual-stack multi-Node lifecycle covering policy, allocation, steering/NAT, HA, recovery, provenance, cleanup, and rollback with immutable evidence |
| 8.11 | OpenShift qualification | **Planned** | Independent digest-pinned cl02 RHCOS/SELinux/CRI-O gate covering cross-worker dual-stack egress, source addresses, failover, recovery, exact cleanup, convergence, and ClusterOperator comparison |

## Accepted Phase 8 gate

The phase closes only when one exact committed tuple passes independent Kind and
OpenShift gates and demonstrates:

- explicit ownership: ordinary Pod egress remains native unless admitted egress
  intent selects the source and an owned pool/provider;
- source-side security policy before egress steering, allocation, or NAT;
- identity-aware selection by Namespace, workload, and ServiceAccount without
  treating an IP address as trust identity;
- deterministic conflict-safe dual-stack allocation, multiple-address
  semantics, exact release/reuse, and foreign-state preservation;
- a canonical Egress Behavior Contract independently verified before activation;
- lease-fenced gateway ownership, deterministic HA/failover, split-brain
  rejection, and explicit established-flow behavior;
- IPv4/IPv6 TCP/UDP steering and NAT with exact original source, translated
  source, destination, gateway, policy, allocation, and revision provenance;
- separately revisioned allocation, gateway readiness, reachability, dataplane,
  and publication state with last-known-good recovery;
- FQDN controls with bounded DNS-derived state, TTL/staleness, wildcard,
  capacity, and explanation semantics;
- fixed-cardinality operations, durable history, explanation, and read-only
  simulation that never guesses private NAT state;
- exact route/address/neighbor/map/checkpoint/lease/fixture cleanup; and
- immutable source, image, platform, measurement, and qualification evidence.

## Semantic precedence

For a new egress flow the order is fixed:

1. resolve the source workload identity and direction;
2. enforce source-side security policy against the original destination;
3. match explicit egress intent and destination constraints;
4. select a current owned address and lease-fenced ready gateway from a verified
   contract;
5. create bounded flow/NAT state and steer to that gateway; and
6. publish the translated source only through an acknowledged reachability
   provider.

An existing validated flow follows its documented failover contract. A gateway
or address lease never grants policy permission. FQDN-derived IP membership is a
destination constraint with provenance and expiry, not a workload identity.

## Ownership and compatibility

- The controller adapter owns Kubernetes/OpenShift translation only; normalized
  egress intent contains no provider-specific API strings.
- The egress domain owns pools, leases, gateway candidates, provider intent, and
  canonical contracts. Allocation does not imply reachability or dataplane
  readiness.
- Agents independently verify exact-Node contracts, own host steering/NAT state,
  and activate only coherent revisions. eBPF consumes fixed-width bounded state.
- Gateway and advertisement implementations are provider interfaces. Static
  development reachability, OpenShift compatibility, and future BGP backends do
  not fork policy or NAT semantics.
- Every schema/ABI transition negotiates capabilities, retains last-known-good
  state, stages and reads back inactive state, activates atomically, and cleans
  only exact versioned ownership.

## Default behavior

Safe features are enabled by default only after their milestone is verified.
Unowned traffic remains on native routing; no egress address, gateway, FQDN
rule, BGP advertisement, or cross-cluster route is inferred. Explicit intent
that cannot satisfy its contract fails closed without silently reverting to a
different source address.

## Explicit exclusions

Phase 8 does not silently claim production BGP/EVPN/ECMP/BFD, cloud-provider
adapters, cross-cluster egress, overlapping-CIDR translation, WireGuard,
application identity from DNS, L7 proxying, Gateway API, SCTP egress NAT,
fragments, generic NAT `RELATED`, arbitrary ICMP error translation, production
HA, availability, or scale. Those require independent architecture and gates.

## Immediate next slice

Milestone 8.2a defines the canonical per-source/per-Node Egress Behavior
Contract and independent reference validator. Milestone 8.2 changed no BPF ABI,
host routing, address ownership, watcher/RBAC behavior, packet behavior, or
platform claim.
