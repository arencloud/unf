# Phase 4 service-fabric execution plan

Last reviewed: **2026-08-29**

Phase 4 begins the post-CNI Universal Network Fabric. It implements the smallest
coherent eBPF Service foundation before NodePort, LoadBalancer, BGP, enterprise
egress, encryption, or multi-cluster expansion. The authoritative feature state
remains in [project-status.md](../project-status.md).

A row is Verified only when its implementation and repeatable evidence are in
the repository. A userspace or unit-tested child row never implies dataplane or
cluster support.

## Milestone summary

| ID | Milestone | State | Exit evidence |
|---|---|---|---|
| 4.1 | Service domain contract | **Verified** | `make service-ir-test`; explicit per-frontend same-family backend references; ADR 0074 |
| 4.2 | Kubernetes service compiler | **Verified** | `make service-compiler-test`; deterministic exact dual-stack translation, stable collision rejection, lifecycle provenance, retained-last-valid status and topology non-regression; ADR 0075 |
| 4.3 | Revisioned agent distribution | **Planned** | Authenticated snapshot, compatibility tuple, desired/applied status, LKG persistence and outage recovery |
| 4.4 | Transactional eBPF service state | **Planned** | Accepted map/connection-state ADR, verifier build, staging/readback/atomic activation/rollback and capacity fault gate |
| 4.5 | Dual-stack ClusterIP dataplane | **Planned** | TCP/UDP translation, deterministic backend persistence, reverse path, endpoint churn, no-backend behavior and provenance |
| 4.6 | Service operations | **Planned** | Metrics, status, flow history, explanation, cleanup and actionable failure reasons |
| 4.7 | Kube-proxy-free Kind qualification | **Planned** | Dedicated primary-CNI dual-stack lifecycle/failure/recovery artifact |
| 4.8 | OpenShift qualification | **Planned** | Kind gate closed; deliberately configured disposable cluster; RHCOS/SELinux/CRI-O/operator evidence |

## Accepted Phase 4 gate

The foundation gate closes only when a dedicated dual-stack Kind cluster runs
UNF primary CNI with kube-proxy absent and demonstrates:

- direct Pod traffic and DNS continuity;
- TCP and UDP ClusterIP forwarding on IPv4 and IPv6;
- deterministic connection persistence across repeated packets;
- EndpointSlice add, readiness change, termination, deletion, and recovery;
- explicit no-backend behavior with machine-readable provenance;
- transactional service revision activation and rollback under capacity failure;
- controller outage and source/destination agent replacement from last-known-good
  state without corrupting active Service traffic;
- service/backend/revision/translation visibility in metrics, status, history,
  and explanation;
- exact service-map and fixture cleanup; and
- schema-versioned environment and Git evidence.

SCTP, NodePort, LoadBalancer, session affinity, traffic policies, Maglev, DSR,
generic NAT/RELATED tracking, and OpenShift are not silently inherited by this
first gate. They receive separate rows after the ClusterIP foundation closes.

## Immediate next slice

Define Phase 4.3's authenticated service distribution contract. Add the service
schema to component compatibility, expose an epoch/revision-fenced snapshot to
authenticated Node agents, persist a validated owner-only last-known-good copy,
report desired/applied/error revisions independently from policy and routing,
and prove controller outage, stale epoch/revision rejection, replacement, and
recovery without defining or mutating service BPF maps.
