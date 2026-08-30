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
| 5.2 | Compatible distribution transition | **In progress** | Define schema-v1→v2 controller-first behavior, durable snapshot migration/rebuild, mixed-version fencing, desired/applied status, and rendered compatibility evidence |
| 5.3 | Transactional host-facing state | **Planned** | Authenticated Node-address intent, fixed dual-stack NodePort maps, capacity preflight, inactive-bank validation, atomic activation, rollback, and recovery |
| 5.4 | `externalTrafficPolicy: Cluster` dataplane | **Planned** | IPv4/IPv6 TCP/UDP Node-address ingress, deterministic backend selection, reverse translation, connection persistence, checksum and provenance packet execution |
| 5.5 | `externalTrafficPolicy: Local` | **Planned** | Node-local eligibility, source preservation, no-local-backend behavior, endpoint churn, health-check boundary, and direction-correct policy composition |
| 5.6 | NodePort operations | **Planned** | Metrics, status, flow history, explanation, simulation, actionable failures, and bounded restart recovery |
| 5.7 | Kube-proxy-free Kind qualification | **Planned** | Cross-node dual-stack NodePort lifecycle, controller outage, source/destination agent replacement, cleanup, and exact rollback |
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
- immutable schema-versioned source, image, and platform evidence.

SCTP forwarding, LoadBalancer, session affinity, topology hints, Maglev, DSR,
host-network clients, fragments, generic NAT/RELATED tracking, and production
availability/scale require independent later gates.

## Immediate next slice

Phase 5.2 must make the schema transition deployable without weakening the
Phase 4 last-known-good contract. It must choose and verify either bounded
migration or explicit clean rebuild, keep mixed binaries fail closed, and avoid
publishing NodePort intent to a consumer that can only lower ClusterIP.
