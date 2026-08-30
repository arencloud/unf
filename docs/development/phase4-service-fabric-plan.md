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
| 4.6 | Service operations | **Verified** | `make service-operations-test`; fixed event ABI, bounded metrics/status/export/history, durable migration, service explanation, and actionable translation/drop/expiry reasons; ADR 0079 |
| 4.7 | Kube-proxy-free Kind qualification | **Verified** | `make service-kind-test`; dedicated Kubernetes 1.35 dual-stack primary-CNI fixture, lifecycle/failure/recovery artifact, and exact rollback; ADR 0080 |
| 4.8 | OpenShift qualification | **In progress** | The first Kind-qualified revision is published by three immutable public Quay digests. `make openshift-service-deploy` passed the guarded controller-first, `OnDelete`, five-Node ABI-v3→v4 handoff with 5/5 agents converged while kube-proxy remained available. The live kube-proxy-free gate reached controller-outage recovery and found a bounded wall-clock regression in its own durable flow checkpoint; schema-v4 prevention/migration is implemented and requires a fresh Kind-qualified image before the cl02 gate resumes |

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

## Reproducing the Kind gate

Create and qualify the isolated fixture from the repository root:

```console
make service-kind-up
make service-kind-deploy
make service-kind-test
```

The test deliberately rolls UNF back to the saved no-CNI bootstrap baseline
after writing `.artifacts/phase4-service-kind.json`. Run
`make service-kind-deploy` before repeating the gate; that target idempotently
restores the primary-CNI labels and CoreDNS bootstrap prerequisites. Run
`make service-kind-down` to remove the disposable cluster.

## Immediate next slice

Execute Phase 4.8 without widening unsupported Service types. The qualified
revision and immutable release record are now published, and the checked-in
workflow deliberately crosses persistent BPF ABI v3 to v4 controller-first and
one Node at a time while kube-proxy remains a safety net. The second gate may
remove kube-proxy only after all five agents converge; it then proves the same
dual-stack TCP/UDP ClusterIP lifecycle, failure/recovery, observability, RHCOS,
SELinux, CRI-O, and operator-health invariants and retires only the obsolete v3
map directory. Passing live cl02 evidence remains required; no behavior is
inherited from the Kind result.
