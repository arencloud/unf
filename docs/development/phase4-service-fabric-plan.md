# Phase 4 service-fabric execution plan

Last reviewed: **2026-08-30**

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
| 4.3 | Revisioned agent distribution | **Verified** | `make service-distribution-test`; authenticated snapshot, compatibility fencing, desired/applied/failed status, durable mode-0600 LKG persistence and outage recovery; ADR 0076 |
| 4.4 | Transactional eBPF service state | **Verified** | `make service-dataplane-test`; fixed dual-stack ABI, v4/eighteen-pin clean boundary, real-map staging/readback/atomic activation/rollback/capacity fault; ADR 0077 |
| 4.5 | Dual-stack ClusterIP dataplane | **Verified** | `make service-dataplane-test`; verifier-loaded IPv4/IPv6 TCP/UDP DNAT and reverse SNAT, checksum proof, deterministic ready/non-terminating selection, paired connection provenance, churn persistence, expiry/reselection, and exact no-backend drop; ADR 0078 |
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

Implement Phase 4.6 without widening the forwarding claim: export bounded
service translation and failure records from the existing TC paths, aggregate
metrics/status/history in userspace, and add an `unfctl` explanation surface for
ServiceId, BackendId, selected tuple, service revision, no-backend, corrupt-state,
and pair-insertion outcomes. Phase 4.7 remains the first kube-proxy-free cluster
forwarding claim.
