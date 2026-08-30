# Phase 5 NodePort execution plan

Last reviewed: **2026-08-31**

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
| 5.7 | Kube-proxy-free Kind qualification | **Verified** | Runtime and qualification revision `bc03d5c` passed `make nodeport-kind-test` in 820 seconds: all-node host-origin ClusterIP, cross-node dual-stack Cluster/Local lifecycle, source and reverse tuple checks, retained UDP connections, classified operations, controller outage, both worker-agent replacements, empty-map cleanup, exact rollback, reversible IPv4 host prerequisites, and schema-v2 evidence; ADRs 0089–0091 |
| 5.8 | OpenShift qualification | **Verified** | Runtime revision `bc03d5c` and qualification revision `76828c3` passed the guarded digest-pinned deployment and 3,803-second `make nodeport-openshift-test` gate on five-Node dual-stack cl02: RHCOS/SELinux/CRI-O, kube-proxy absence, all-node host-origin ClusterIP, cross-worker Cluster/Local lifecycle and tuples, offline composite recovery, operations/simulation, exact cleanup, ABI-v4 rollback classification, five-agent convergence, and unchanged `insights`-only unhealthy baseline; ADR 0092 |

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
host-origin NodePort clients, fragments, generic NAT/RELATED tracking, and production
availability/scale require independent later gates.

## Closure evidence

Phase 5 closed after the exact runtime revision `bc03d5c` passed both platform
gates. The final OpenShift schema-v2 artifact binds qualification revision
`76828c3`, three immutable public image digests, OpenShift 4.22.10/Kubernetes
1.35.6, five converged ABI-v5 agents, kube-proxy absence, complete cleanup, and
identical baseline/final unhealthy-operator sets containing only disconnected
`insights`. The artifact records every bounded exclusion explicitly.
