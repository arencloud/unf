# Phase 7 advanced Service-selection execution plan

Last reviewed: **2026-09-02**

Phase 7 completes the remaining bounded Service behavior in master-prompt §§20,
21, and 30: internal locality, session affinity, topology preference, graceful
endpoint removal, measured scalable selection, and DSR where it is technically
safe. It builds on the qualified Phase 4–6 ClusterIP, NodePort, LoadBalancer,
and connection-state foundation. The authoritative feature state remains in
[project-status.md](../project-status.md).

## Milestone summary

| ID | Milestone | State | Exit evidence |
|---|---|---|---|
| 7.1 | Architecture and acceptance boundary | **Verified** | ADR 0102 fixes semantic precedence, ownership, compatibility, transactional state, measurement, operations, platform gates, cleanup, and exclusions; `make service-selection-boundary-test` prevents drift across the plan, tracker, roadmap, README, and component boundary |
| 7.2 | Service schema v4 and Kubernetes compiler | **Verified** | Schema v4 carries typed/defaulted `internalTrafficPolicy`, ClientIP timeout, canonical traffic distribution, algorithm, and forwarding intent. Exact timeout/enum validation, v1/v2/v3 migration and safe projection, legacy fencing, Kubernetes conversion, unchanged default lowering, and explicit pre-transaction rejection pass `make service-selection-ir-test`; ADR 0103 |
| 7.2a | Network Behavior Contract and reference validator | **Verified** | Schema-v1 canonical per-Node contracts independently bind source/topology/contract revisions, exact frontend intent, strict-policy-first tiers, eligible family/protocol/placement sets, and Node capabilities. Domain-separated SHA-256 plan/contract digests, compact decision witnesses, bounded explicit single-failure envelopes, golden encoding, mutation/property/replay tests, and strict Clippy pass `make service-selection-contract-test`; ADR 0104 |
| 7.3 | Compatible distribution and transactional selection state | **Verified** | Schema-v1 negotiation, authenticated exact-Node projection, capability fencing, independent agent replay, two-bank userspace staging/readback/activation, owner-only contract+Node checkpoints, rollback/crash repair/cold reconstruction, digest-exact convergence, and exact v1 state cleanup pass `make service-selection-state-test`; ADR 0105 |
| 7.4 | Internal locality and topology-aware dataplane | **Verified** | `make service-selection-dataplane-test` proves fixed-width ABI-v8 SameNode/SameZone/Cluster state, first-nonempty userspace resolution, dual-stack TCP/UDP strict Local and ordered fallback across ClusterIP/NodePort/LoadBalancer, external-policy precedence, lifecycle filtering, tier event provenance, topology-only activation, exact recovery, inherited state tests, and strict Clippy; ADR 0106 |
| 7.5 | ClientIP affinity and graceful draining | **Verified** | `make service-affinity-dataplane-test` proves exact original-client/frontend keys, 1–86,400 second timeout encoding, eligible bank+revision reuse, explicit create/reuse/reselection outcomes, connection-before-affinity precedence, ready/non-terminating new-flow slots, established-flow survival during termination, dual-stack ClusterIP packet behavior, bounded LRU recovery under persistent ABI v9, inherited 7.4 gates, real-kernel verifier acceptance, and strict Clippy; ADR 0107 |
| 7.6 | Measured Maglev selection | **Verified** | `make service-maglev-dataplane-test` regenerates the 2–4,096-backend fixture; proves deterministic prime tables with at least 16 slots/backend, at most 6.25% intrinsic table error, materially lower same-table add disruption, bounded memory/writes/compile time, the same hash/modulo/one-map packet path, capacity fallback with actual-algorithm flags, ClusterIP/NodePort/LoadBalancer lowering, annotation admission, ABI-v10 recovery/cleanup, inherited real-kernel gates, and strict Clippy; ADR 0108 |
| 7.7 | Opt-in DSR dataplane | **Verified** | `make service-dsr-dataplane-test` proves explicit acknowledged UNF LoadBalancer-only intent, equal Service/backend tuples, dual-stack capability fencing, unchanged policy/source-range/selection/lifecycle semantics, VIP-preserving direct or neighbor-routed output after route/neighbor/MTU FIB proof, runtime-bound transport topology retained in optimized bytecode, fail-closed verifier-isolated tail stages, forward-only connection state and direct return, bounded mode provenance, 25-map ABI-v11 recovery/cleanup, all 13 inherited privileged packet paths, and strict Clippy; ADR 0109 |
| 7.8 | Operations, simulation, upgrade, and recovery | **Verified** | `make service-selection-operations-test` preserves exact tier/algorithm/affinity/NAT-or-DSR witnesses through fixed-cardinality metrics and status-v8, export-v6, durable history-v7/checkpoint-v6, revision-aware explanation, and digest-bound ClusterIP/NodePort/LoadBalancer simulation; explicit unknown migration, adjacent v7/v8 and v5/v6 compatibility, inherited ABI-v11 recovery/cleanup, and strict Clippy; ADR 0110 |
| 7.9 | Kube-proxy-free Kind qualification | **Verified** | Runtime/qualifier `06fc937` passed the 463-second three-Node Kubernetes v1.35.0 dual-stack gate with kube-proxy absent: complete Phase 6 regression, strict SameNode/SameZone/Cluster fallback, ClientIP lifecycle, measured Maglev/StableHash provenance, acknowledged cross-worker IPv4/IPv6 DSR, operations, controller-offline agent replacement, ABI-v11/CNI cleanup, and exact no-CNI rollback; schema-v1 evidence is `.artifacts/phase7-service-selection-kind.json`; ADR 0111 |
| 7.10 | OpenShift qualification | **Verified** | Runtime `06fc937` and qualifier `018f14c` passed the 1,670-second digest-pinned five-Node OpenShift 4.22.10/Kubernetes 1.35.6 cl02 RHCOS/SELinux/CRI-O gate: complete Phase 6 regression, cross-worker/node/zone dual-stack behavior, acknowledged DSR source/return tuples and source ranges, operations, controller-offline agent recovery, exact cleanup, five-agent convergence, and unchanged `insights`/`network` unhealthy baseline; schema-v1 evidence is `.artifacts/phase7-service-selection-openshift.json`; ADR 0112 |

## Accepted Phase 7 gate

The phase closes only when one exact committed tuple passes both Kind and
OpenShift with kube-proxy absent and demonstrates:

- Kubernetes-compatible defaulting and validation for internal traffic policy,
  ClientIP affinity/timeout, and supported traffic-distribution values;
- strict internal/external `Local` eligibility before any soft topology tier;
- deterministic same-Node, same-zone, then cluster fallback from authoritative
  Node and EndpointSlice placement without silently dropping on a preference;
- affinity keyed by the original client and exact frontend, applied only to the
  current eligible set, with bounded timeout and explicit expiry/reselection;
- established-flow persistence, new-session affinity, and backend draining as
  distinct observable state machines;
- userspace compilation and transactional activation of all per-Node selection
  state only after Network Behavior Contract verification, with bounded
  verifier-friendly eBPF lookups and compact decision witnesses;
- measured algorithm evidence and no unsupported Maglev performance claim;
- opt-in DSR only after route, neighbor, MTU, backend VIP, policy, source-range,
  return-path telemetry, lifecycle, recovery, and cleanup proofs;
- metrics, status, history, explanation, and read-only simulation that expose
  exact tier, algorithm, affinity, forwarding mode, backend, and revisions;
- controller and agent outage/replacement recovery, schema/ABI compatibility,
  rollback, and last-known-good fencing;
- exact map, checkpoint, route/address, neighbor, fixture, and CNI cleanup; and
- immutable source, image, platform, benchmark, and qualification evidence.

## Semantic precedence

For a new flow the eligibility order is fixed:

1. classify the frontend and traffic origin;
2. apply the corresponding strict internal or external traffic policy;
3. derive the preferred topology tier, falling back only when the policy allows;
4. reuse ClientIP affinity only if its backend remains in that eligible tier;
5. select through the admitted algorithm and create per-flow connection state;
6. apply NAT or explicitly admitted DSR forwarding.

An existing validated connection uses its bounded connection-state contract.
Affinity never restores an unready, removed, wrong-Node, wrong-tier, or
otherwise ineligible backend. A preference is not a strict availability policy:
when its tier is empty, it falls back in the documented order.

## Ownership and compatibility

- `unf-service` owns Kubernetes-independent normalized intent and deterministic
  validation. Kubernetes strings and defaulting stop at the controller adapter.
- The controller owns authoritative Service, EndpointSlice, Node placement, and
  zone inputs. It does not choose a backend per packet.
- The agent compiles per-Node eligibility/selection state in userspace, stages
  and reads it back, and activates it only with a coherent service revision.
- eBPF consumes fixed-width state with bounded lookups. It never parses labels,
  topology strings, or variable-size backend lists.
- Schema and persistent ABI changes negotiate explicitly. Older consumers get
  a safe projection only when advanced intent is absent; otherwise convergence
  fails closed while last-known-good state remains active.
- DSR is never inferred from Service type or enabled cluster-wide by accident.
  Its intent and node capability must both be explicit and observable.

## Measurement rule

Maglev is evaluated against the current stable selector using committed,
reproducible fixtures. At minimum the record reports backend cardinalities,
table sizing, memory per frontend, distribution error, key remapping after
add/remove, userspace compile/update time, map write volume, and packet lookup
cost. A table size or benchmark target is not fixed before measurement. Failure
to beat the baseline for an admitted operating range results in a documented
fallback or rejection, not a misleading feature claim.

## Explicit exclusions

Phase 7 does not silently claim weighted traffic splitting, latency- or
load-feedback routing, application-cookie affinity, cross-cluster selection,
production BGP/EVPN/ECMP/BFD, cloud adapters, SCTP Service forwarding,
fragments, generic NAT `RELATED`, Gateway API, L7 proxying, production HA, or
production availability/scale. Those capabilities require independent gates.

## Phase closure

Milestones 7.1–7.10 are Verified. The exact runtime passed both non-transitive
kube-proxy-free Kind and OpenShift gates, including cross-worker dual-stack DSR
on cl02's stacked VLAN host network. No subsequent phase is implied by this
closure; the next architecture slice must be accepted and tracked separately.
