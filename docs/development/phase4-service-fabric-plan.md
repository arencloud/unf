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
| 4.8 | OpenShift qualification | **Verified** | `make openshift-service-deploy` and `make openshift-service-test`; exact digest-pinned revision `f721f9a`, guarded controller-first five-Node rollout, preserved schema-v3→v4 checkpoint recovery, kube-proxy-free IPv4/IPv6 TCP/UDP/DNS lifecycle, controller-offline source/destination agent replacement, bounded outcome/explanation evidence, exact cleanup, ABI-v3 retirement, and no new unhealthy operator; ADR 0081 |

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
and generic NAT/RELATED tracking are not silently inherited by this first gate.
OpenShift receives its independent bounded qualification in row 4.8; the other
modes require separate post-foundation rows.

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

## Closure and next scope

All eight Phase 4 milestones are Verified. The exact OpenShift tuple and
evidence are recorded by ADR 0081 and the support matrix; the result does not
broaden the unsupported Service modes listed above. The next phase must select
and independently gate advanced Service exposure and selection, routing,
encryption, gateway, or multi-cluster slices rather than silently extending the
bounded ClusterIP claim.
