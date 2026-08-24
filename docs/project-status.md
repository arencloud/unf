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
| Phase 3 — compatibility and simulation | **In progress** | §103: NetworkPolicy adapter, simulation foundation, improved topology, and historical export | The supported ingress adapter is controller-integrated and live verified; broader compatibility, simulation, topology, and export remain open |
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
| Agent state | Two ready agents with BPF loaded; both applied identity revision 24 and policy revision 48 in controller epoch 7677506960295401386, with 7 identity-map and 55 combined active policy-map entries |
| Controller state | Ready with 17 watched Pods, 15 admitted identities, 7 indexed non-host-network Pod IPs, one native policy, one accepted NetworkPolicy, zero rejected NetworkPolicies, and 55 resolved identity/IPv4 entries |
| Transactional policy update | The verifier switched enforce → shadow → enforce and exercised protocol-wildcard and IPv4-block mutations, requiring a higher revision and opposite bank on every agent; snapshot schema v2 stages both policy maps before one activation write |
| Interruption recovery | With the controller scaled to zero, the active bank continued allowing 8080 and denying 9090; both agents then accepted the restarted controller epoch and reconverged |
| Dataplane provenance | ABI v2 events matched the applied revision and carried nonzero identities plus actual/shadow policy and explicit-deny rule provenance |
| NetworkPolicy lifecycle | Named port `allowed` resolved to TCP/8081; the inclusive 8082–8083 range enforced both boundaries and excluded 8084; a protocol-only TCP entry allowed arbitrary TCP/9091 without allowing UDP/9091 and removal restored isolation; an exact IPv4 block allowed the client, a nested exception denied it, and exception removal recovered; Namespace relabel removed/restored the allow without identity churn; oversized range/block updates removed stale state and recovered; deletion allowed 9091 and recreation restored the drop |
| Policy explanation | Native 8080/9090, compatibility exact/range/protocol-only ports, and bounded IPv4 block/exception transitions reported the expected explicit/default provenance with dataplane enforcement truthfully enabled |

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
| Kubernetes desired state | **Verified** | Pod, Namespace, SecurityPolicy, and supported NetworkPolicy watchers | Live controller reports watched/compiled objects and explicit compatibility rejection counts |
| Identity state | **Verified** | Metadata-derived numeric identities; Phase 2 registry adds collision admission and Pod-IP indexes | Identity unit tests and live explain resolution |
| Agent and Aya loader | **Verified** | Privileged per-node DaemonSet and dynamic non-loopback TC attachment | Two ready agents report `bpf_loaded: true` |
| TC observation | **Verified** | Bounded Ethernet/IPv4/TCP/UDP parsing, counters, ring buffer, pass-only verdict | Cross-node port 8080 event asserted by `hack/verify-kind.sh` |
| Health, metrics, and structured events | **Verified** | Controller/agent HTTP endpoints and JSON tracing | kind verifier plus endpoint checks |
| CLI status and explanation | **Verified** | Live controller-backed `unfctl` | Shadow explicit-allow and default-deny provenance asserted in kind |
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
- The NetworkPolicy adapter intentionally accepts only the documented ingress
  subset. Numeric ranges are limited to 1,024 inclusive ports, and complete
  identity-keyed snapshots to 131,072 entries per bank. IPv4 blocks support
  `except` but are limited to 1,024 addresses each and 131,072 IPv4 entries per
  bank; IPv6/unbounded blocks remain unsupported. Unsupported or oversized
  objects are counted as rejected but rejection details do not yet have a
  dedicated API endpoint.
- Interface index is currently zero in emitted events.
- Dynamic attachment can observe one packet on multiple interfaces; flow
  aggregation and deduplication are not implemented.
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
| Policy simulation foundation | **Planned** | Proposed-policy evaluation against a versioned topology/flow snapshot |
| Better topology state | **Planned** | Versioned node/workload/service relationships with query tests |
| Historical flow export | **Planned** | Stable exporter contract plus bounded-buffer/backpressure tests |

## Updating this tracker

Every phase-affecting change must update the relevant table in the same change.
Moving a row to **Verified** requires a repeatable command or test. Known gaps stay
visible here and in user-facing status output; planned work is never described as
implemented.
