# Project status and requirements traceability

Last verified: **2026-08-24**

This document is the authoritative implementation tracker. The roadmap describes
direction; this file records phase gates, evidence, limitations, and the next
exit criteria. A feature is marked verified only when its implementation and a
repeatable test are both present in this repository.

## Status model

| Status | Meaning |
|---|---|
| **Verified** | Implemented and exercised by the listed automated evidence |
| **Implemented** | Code exists and unit/static checks pass; cluster proof is pending |
| **In progress** | A bounded implementation slice is underway |
| **Planned** | Accepted scope with no implementation claim |
| **Blocked** | Cannot proceed without an identified external dependency or decision |

## Phase gates

| Phase | State | Gate | Evidence |
|---|---|---|---|
| Phase 1 — observation foundation | **Verified** | Master prompt §101: controller, identity state, policy compiler, agent/Aya/TC flow events, and successful `unfctl status` | `make fmt-check lint test`, `make ebpf`, `make kind-test` |
| Phase 2 — identity and policy enforcement | **Verified** | §102: BPF policy maps, allowed flow passes, denied flow drops, denial event has identity/policy/rule/reason, and accurate `unfctl explain` | `make fmt-check lint test`, `make ebpf`, and `make kind-test` verify the complete gate |
| Phase 3 — compatibility and simulation | **In progress** | §103: NetworkPolicy adapter, simulation foundation, improved topology, and historical export | The supported ingress adapter, history-aware read-only policy simulation, EndpointSlice-aware topology schema v2, and bounded historical export are live verified; broader compatibility remains open |
| Full CNI and later fabric capabilities | **Planned** | §104 and later roadmap gates | Explicitly out of current scope |

Sections 98–99 describe the richer first enforcement and enriched-observability
scenario. Those scenarios span the Phase 2 gate because they require a real deny
and nonzero identity/policy provenance from the dataplane. They are not counted as
completed by Phase 1's observation-only shadow evaluation.

## Latest verification record

| Check | Result on 2026-08-24 |
|---|---|
| Stable userspace formatting, lint, and tests | Passed: `make fmt-check lint test` |
| eBPF target build and manifest rendering | Passed: `make ebpf` and `kubectl kustomize deploy` |
| Two-node cluster integration | Passed: `make kind-test` |
| Demo dataplane | Native policy: open port 8080 passed and 9090 dropped, passed in shadow, then dropped after restore. NetworkPolicy: named port 8081 and range endpoints 8082–8083 passed; a temporary TCP-only wildcard allowed independently open port 9091 while UDP remained default-denied, and removal restored the TCP drop; an exact IPv4 block allowed 8081 and its `except` denied it |
| Agent state | Two ready agents with BPF loaded; both applied identity revision 20 and policy revision 45 in controller epoch 7677537380751979833, with 7 identity-map and 55 combined active policy-map entries; they exported 852 and 4,286 observations with zero queued/dropped at capture |
| Controller state | Ready with 2 watched Nodes, 17 watched Pods, 5 watched Services, 5 watched EndpointSlices, 15 admitted identities, 7 indexed non-host-network Pod IPs, one native policy, one accepted NetworkPolicy, zero rejected NetworkPolicies, 55 resolved identity/IPv4 entries, and zero reported telemetry drops |
| Topology state | Schema v2 returned 2 ready Nodes, 17 placed workloads, 5 Services, and their EndpointSlice backends at topology revision 49/service revision 27; a selectorless `frontend/topology-probe` exposed a not-ready backend for `frontend/client`, changed it to ready, removed it on EndpointSlice deletion, then removed the Service, while policy revision remained unchanged |
| Flow history | Schema v1 retained 189 logical flows/1,283 observations at telemetry revision 152 in its 4,096-key bound; `frontend/client` → `backend/server` TCP/8080 was enriched and attributed to `unf-dev-worker`, while both agents reported zero export drops |
| Transactional policy update | The verifier switched enforce → shadow → enforce and exercised protocol-wildcard and IPv4-block mutations, requiring a higher revision and opposite bank on every agent; snapshot schema v2 stages both policy maps before one activation write |
| Interruption recovery | With the controller scaled to zero, the active bank continued allowing 8080 and denying 9090; both agents then accepted the restarted controller epoch and reconverged |
| Dataplane provenance | ABI v2 events matched the applied revision and carried nonzero identities plus actual/shadow policy and explicit-deny rule provenance |
| NetworkPolicy lifecycle | Named port `allowed` resolved to TCP/8081; the inclusive 8082–8083 range enforced both boundaries and excluded 8084; a protocol-only TCP entry allowed arbitrary TCP/9091 without allowing UDP/9091 and removal restored isolation; an exact IPv4 block allowed the client, a nested exception denied it, and exception removal recovered; Namespace relabel removed/restored the allow without identity churn; oversized range/block updates removed stale state and recovered; deletion allowed 9091 and recreation restored the drop |
| Policy explanation | Native 8080/9090, compatibility exact/range/protocol-only ports, and bounded IPv4 block/exception transitions reported the expected explicit/default provenance with dataplane enforcement truthfully enabled |
| Policy simulation | Schema v2 evaluated 68 topology-derived flows at identity revision 20/policy revision 45/topology revision 49 and 185 of 189 retained historical flows/647 observations at history revision 152; it predicted one representative and 26 observed TCP/8080 denials, reported `backend/server` affected, explicitly skipped four stale-identity flows, left live policy state unchanged, and TCP/8080 remained allowed |

The kind cluster is disposable and its object counts can change as system Pods
roll. The repeatable commands, rather than these snapshot counts, are the release
gate.

## Phase 1 acceptance matrix

| Requirement | State | Implementation | Verification |
|---|---|---|---|
| Rust workspace and pinned toolchains | **Verified** | Root workspace and isolated nightly BPF workspace | `make build`, `make ebpf` |
| Versioned userspace/BPF ABI | **Verified** | `unf-common`, `unf-ebpf-common` | ABI layout and typed-ID unit tests |
| SecurityPolicy API and generated CRD | **Verified** | `unf-api`, checked-in CRD | Schema drift and structural schema tests |
| Deterministic policy compiler/evaluator | **Verified** | `unf-policy` | Unit and property tests for rules, defaults, priorities, conflicts, and order independence |
| Kubernetes desired state | **Verified** | Node, Pod, Namespace, Service, EndpointSlice, SecurityPolicy, and supported NetworkPolicy watchers | Live controller reports watched/compiled objects, backend topology relationships, and explicit compatibility rejection counts |
| Identity state | **Verified** | Metadata-derived numeric identities; Phase 2 registry adds collision admission and Pod-IP indexes | Identity unit tests and live explain resolution |
| Agent and Aya loader | **Verified** | Privileged per-node DaemonSet and dynamic non-loopback TC attachment | Two ready agents report `bpf_loaded: true` |
| TC observation | **Verified** | Bounded Ethernet/IPv4/TCP/UDP parsing, counters, ring buffer, pass-only verdict | Cross-node port 8080 event asserted by `hack/verify-kind.sh` |
| Health, metrics, and structured events | **Verified** | Controller/agent HTTP endpoints and JSON tracing | kind verifier plus endpoint checks |
| CLI status and explanation | **Verified** | Live controller-backed `unfctl` status, topology, flows, explain, and simulation commands | Structured topology/history plus shadow explicit-allow and default-deny provenance asserted in kind |
| Reproducible local environment | **Verified** | Rootful Podman kind workflow, local kubeconfig, local images | `make kind-up kind-deploy kind-test` |
| Architecture and operational documentation | **Verified** | Architecture, ADRs, roadmap, development guide, and this tracker | Link/static review during phase gate |

## Phase 2 work breakdown

| Deliverable | State | Exit evidence |
|---|---|---|
| Collision-safe identity admission | **Verified** | Reject reserved/colliding IDs without state mutation |
| Pod-IP to identity desired-state index | **Verified** | Update, conflict, lookup, deletion, and GC unit tests |
| Controller integration and identity counts | **Verified** | `make kind-test` requires nonzero admitted identities and indexed Pod IPs |
| Versioned BPF identity map schema | **Verified** | ABI tests plus `make kind-test` require a populated live kernel map |
| Controller-to-agent revisioned distribution | **Verified** | Both node agents report desired/applied epoch and revision convergence; controller-restart recovery exercised live |
| Selector-to-identity policy lowering | **Verified** | Unit tests cover exact/default, shadow provenance, conflicts, and deterministic ordering; `make kind-test` requires nonzero resolved entries |
| Transactional policy map set | **Verified** | `make kind-test` stages a changed policy on the opposite bank, verifies a higher applied revision, restores it, and verifies reconvergence |
| TC identity lookup | **Verified** | Cross-node demo flow carries nonzero source and destination IDs |
| L3/L4 policy decision | **Verified** | Exact/fallback active-bank lookup plus ABI v2 revision, verdict, reason, policy, rule, and shadow provenance |
| Enforcement | **Verified** | `make kind-test` proves 8080 allow, open-port 9090 drop, shadow pass-through, and restored drop |
| Accurate live explanation | **Verified** | CLI actual decisions and IDs are checked while every traffic-path agent reports the active revision applied |
| Failure behavior | **In progress** | Last-known-good enforcement survived a controller interruption; pinned map recovery, agent restart fencing, and pressure/fault injection remain |

## Current limitations

- Enforcement currently covers resolved-identity IPv4 TCP/UDP exact and wildcard
  decisions; IPv6, fragments beyond the initial fragment, and other protocols
  fail open.
- Identity and compiled policy desired state remain in-memory and their BPF maps
  are unpinned. Agent restart therefore has a resynchronization window where the
  overlay intentionally fails open.
- Unknown destination identities, missing/incompatible map config, invalid
  values, and absent identity/IP decisions fail open with revision-zero
  observed/identity-unknown provenance. Unknown source identities can be enforced
  by a valid exact or external-fallback IPv4 policy entry.
- Applied policy status is node-local; the controller and CLI do not yet aggregate
  node acknowledgements.
- Policy simulation currently accepts one native `SecurityPolicy`, uses current
  Pods plus representative policy-derived TCP/UDP probes, and rejects matrices
  above 10,000 flows. It separately evaluates retained history and observation
  frequency, but has no time-window filtering, cannot evaluate external sources
  without a current identity, and accepts no user-supplied flow sets.
- Flow history is advisory, destination-resolved, current-process telemetry. Agent
  channels/pending state and controller retention are bounded with explicit drop
  and eviction counters, but history is not durable, authenticated, sampled, or
  deduplicated across interface-level observations.
- Topology schema v2 reports current in-memory Node, Pod workload, Service intent,
  and EndpointSlice runtime relationships. Conditions are Kubernetes-reported
  state rather than active traffic health; topology history, filtering,
  pagination, and routing/load-balancing behavior are not implemented.
- The NetworkPolicy adapter intentionally accepts only the documented ingress
  subset. Numeric ranges are limited to 1,024 inclusive ports, and complete
  identity-keyed snapshots to 131,072 entries per bank. IPv4 blocks support
  `except` but are limited to 1,024 addresses each and 131,072 IPv4 entries per
  bank; IPv6/unbounded blocks remain unsupported. Unsupported or oversized
  objects are counted as rejected but rejection details do not yet have a
  dedicated API endpoint.
- Interface index is currently zero in emitted events.
- Dynamic attachment can observe one packet on multiple interfaces; flow
  history aggregates identical logical keys but does not deduplicate one packet's
  interface-level observations.
- The development DaemonSet is privileged; narrow capabilities and OpenShift SCC/
  SELinux validation remain required.
- kind verification is Kubernetes evidence, not an OpenShift support claim.

## Phase 3 work breakdown

| Deliverable | State | Exit evidence |
|---|---|---|
| NetworkPolicy ingress translator foundation | **Verified** | Unit tests cover allow/default isolation, pod/Namespace expressions, named and protocol-only TCP/UDP ports, bounded numeric ranges, bounded IPv4 blocks/exceptions, wildcards, local/exact-namespace peers, and explicit unsupported-feature errors; `make kind-test` exercises each supported peer/port form |
| Additive compatibility semantics | **Verified** | Multiple selecting policies combine allows in the shared evaluator and lower through the shared dataplane compiler; the live adapter uses that same engine |
| NetworkPolicy controller watch and live enforcement | **Verified** | `make kind-test` covers reconciliation/status, explicit allow, isolation drop, revisioned provenance, rejection/removal/recovery, and deletion/recreation |
| Full ingress peer/port compatibility | **In progress** | Pod/Namespace expressions, named and protocol-only TCP/UDP ports, inclusive numeric ranges up to 1,024 ports, and IPv4 blocks up to 1,024 addresses with `except` are live verified; IPv6/unbounded blocks and broader conformance cases remain |
| IPv4 `ipBlock` dataplane | **Verified** | Snapshot schema v2 carries exact/fallback source-IP decisions; `POLICY_IPV4` and `POLICY_RULES` stage under one bank/revision; unit tests cover CIDR validation/lowering and `make kind-test` covers allow, exception deny, recovery, provenance, and oversized-block rejection |
| Dataplane policy capacity safety | **Verified** | Shared lowering and agent snapshot validation cap each identity and IPv4 transactional bank at 131,072 entries; staging deletes stale inactive keys before insertions, and unit tests exercise the exact boundary |
| Egress NetworkPolicy compatibility | **Planned** | Direction-aware IR and dataplane enforcement evidence |
| Policy simulation foundation | **Verified** | Versioned read-only add/replace API and `unfctl policy simulate` compare current/proposed provenance over a bounded topology-derived matrix and retained flow history; unit tests prove no state mutation and historical weighting, while `make kind-test` proves predicted deny, revision stability, and unchanged live forwarding |
| Better topology state | **Verified** | Topology schema v2 preserves selector intent and adds EndpointSlice-derived address/port, Pod target, Node/zone, and ready/serving/terminating backend state; unit tests prove normalization, idempotence, stale-state removal, and revision isolation, while `make kind-test` exercises not-ready → ready → deleted backend and Service deletion transitions without policy-revision mutation |
| Historical flow export | **Verified** | Schema v1, non-blocking 4,096-record agent channel, 2,048-key pending aggregation, 512-entry HTTP batches, 4,096-key revisioned controller retention, drop/eviction metrics, `unfctl flows`, and history-aware simulation; unit tests cover bounds/aggregation/eviction and `make kind-test` requires an enriched live cross-node flow |

## Updating this tracker

Every phase-affecting change must update the relevant table in the same change.
Moving a row to **Verified** requires a repeatable command or test. Known gaps stay
visible here and in user-facing status output; planned work is never described as
implemented.
