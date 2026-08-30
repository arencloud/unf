# Phase 5 NodePort execution plan

Last reviewed: **2026-08-30**

Phase 5 extends the verified ClusterIP foundation with the smallest sound
host-facing Service exposure. It does not infer LoadBalancer, session affinity,
topology-aware routing, Maglev, DSR, or production-scale support. The
authoritative feature state remains in [project-status.md](../project-status.md).

## Milestone summary

| ID | Milestone | State | Exit evidence |
|---|---|---|---|
| 5.1 | NodePort domain and Kubernetes compiler | **Verified** | Service snapshot schema v2, typed family/policy/backend linkage, collision and malformed-input rejection, Kubernetes translation, explicit ClusterIP-lowerer rejection; `make service-ir-test`; ADR 0082 |
| 5.2 | Compatible distribution transition | **Verified** | Explicit schema negotiation supports every old/new controller-agent pairing, read-time v1 migration with rollback-safe persistence, NodePort-capability convergence fencing, desired/applied failure status, rendering, and `make service-distribution-test`; ADR 0083 |
| 5.3 | Transactional host-facing state | **Verified** | TokenReview-scoped Node intent; persistent ABI v5 with an exact 21-map boundary; composite checkpoint; inactive service/NodePort staging and readback; address-only switching; dual-pointer rollback/crash recovery; v4/v5 cleanup; `make nodeport-transaction-test`; ADRs 0084–0085 |
| 5.4 | `externalTrafficPolicy: Cluster` dataplane | **Verified** | Exact Node-address/port/protocol lookup, coherent service-bank validation, IPv4/IPv6 TCP/UDP DNAT with bounded collision-safe Node SNAT, paired reverse restoration, deterministic slots, connection persistence, backend policy ordering, checksum/provenance packet execution; `make nodeport-cluster-dataplane-test`; ADR 0086 |
| 5.5 | `externalTrafficPolicy: Local` | **Verified** | Deterministic per-Node slot namespace merged transactionally with the service bank; ready/non-terminating placement eligibility; source preservation; exact no-local-backend drop; placement/readiness loss, established-flow retention, recovery, reverse translation, and backend policy ordering; NodePort/LoadBalancer health-check boundary; `make nodeport-local-dataplane-test`; ADR 0087 |
| 5.6 | NodePort operations | **Verified** | Fixed-width event classification; label-free metrics; status v5; export/history/checkpoint v5/v6/v5; filtered explanation; read-only simulation; actionable bounded failures; restart migration; `make nodeport-operations-test`; ADR 0088 |
| 5.7 | Kube-proxy-free Kind qualification | **Verified** | Committed revision `892ef1a` passed `make nodeport-kind-test`: cross-node dual-stack Cluster/Local lifecycle, source and reverse tuple checks, retained UDP connections, classified operations, controller outage, both worker-agent replacements, empty-map cleanup, exact rollback, reversible IPv4 host prerequisites, dispersed bounded SNAT allocation across restart churn, and schema-v2 evidence; ADRs 0089–0091 |
| 5.8 | OpenShift qualification | **Planned** | Digest-pinned RHCOS/SELinux/CRI-O rollout and kube-proxy-free cross-worker NodePort lifecycle/recovery on the exact disposable tuple |

## Accepted Phase 5 gate

The bounded NodePort gate closes only when the exact Kind and OpenShift tuples
run with kube-proxy absent and demonstrate:

- IPv4 and IPv6 TCP/UDP through eligible Node addresses;
- explicit `Cluster` and `Local` traffic-policy behavior;
- source/reverse tuple correctness and connection persistence;
- readiness, termination, deletion, local-backend loss, and recovery;
- controller outage plus source/destination agent replacement from validated
  last-known-good state;
- NodePort-specific metrics, status, history, explanation, and simulation;
- exact host-map, attachment, fixture, and legacy-state cleanup; and
- exact backup, application, and restoration of the IPv4 NodePort host sysctl
  contract; and
- immutable schema-versioned source, image, and platform evidence.

SCTP forwarding, LoadBalancer, session affinity, topology hints, Maglev, DSR,
host-network clients, fragments, generic NAT/RELATED tracking, and production
availability/scale require independent later gates.

## Immediate next slice

Phase 5.8 must qualify the exact committed NodePort implementation on the
five-Node dual-stack OpenShift cl02 tuple with kube-proxy absent. Images must be
published and deployed by digest, the master and worker MachineConfigPools must
converge on the NodePort host contract, and the Kind NodePort matrix must be
repeated across RHCOS/SELinux/CRI-O workers. Evidence must include source and
image provenance, Cluster/Local dual-stack TCP/UDP, lifecycle and offline-agent
recovery, operations/simulation, host-map cleanup, and cluster health before
Phase 5 can close.
