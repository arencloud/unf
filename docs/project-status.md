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
| Phase 3 — compatibility and simulation | **Planned** | §103: NetworkPolicy adapter, simulation foundation, improved topology, and historical export | No implementation claim |
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
| Demo dataplane | Open port 8080 passed and open port 9090 was dropped in enforce mode; 9090 passed when the same policy switched to shadow and dropped again after restore |
| Agent state | Two ready agents; BPF loaded; after controller recovery both applied identity/policy revision 17 with six identity and 16 active policy entries |
| Controller state | Ready after restart; 16 watched Pods, 14 admitted identities, 6 indexed non-host-network Pod IPs, one compiled policy, 16 resolved policy entries |
| Transactional policy update | The verifier switched enforce → shadow → enforce, requiring a higher revision and opposite bank on every agent for both transitions |
| Interruption recovery | With the controller scaled to zero, the active bank continued allowing 8080 and denying 9090; both agents then accepted the restarted controller epoch and reconverged |
| Dataplane provenance | ABI v2 events matched the applied revision and carried nonzero identities plus actual/shadow policy and explicit-deny rule provenance |
| Policy explanation | Port 8080 reported explicit allow and port 9090 explicit deny with dataplane enforcement truthfully enabled |

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
| Kubernetes desired state | **Verified** | Pod, Namespace, and SecurityPolicy watchers | Live controller reports watched/compiled objects and zero reconcile errors |
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
- Unknown identities, missing/incompatible map config, invalid values, and absent
  decisions fail open with revision-zero observed/identity-unknown provenance.
- Applied policy status is node-local; the controller and CLI do not yet aggregate
  node acknowledgements.
- Interface index is currently zero in emitted events.
- Dynamic attachment can observe one packet on multiple interfaces; flow
  aggregation and deduplication are not implemented.
- The development DaemonSet is privileged; narrow capabilities and OpenShift SCC/
  SELinux validation remain required.
- kind verification is Kubernetes evidence, not an OpenShift support claim.

## Updating this tracker

Every phase-affecting change must update the relevant table in the same change.
Moving a row to **Verified** requires a repeatable command or test. Known gaps stay
visible here and in user-facing status output; planned work is never described as
implemented.
