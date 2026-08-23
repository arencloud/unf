# Project status and requirements traceability

Last verified: **2026-08-23**

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
| Phase 2 — identity and policy enforcement | **In progress** | §102: BPF policy maps, allowed flow passes, denied flow drops, denial event has identity/policy/rule/reason, and accurate `unfctl explain` | Identity admission/index slice implemented; enforcement gate remains open |
| Phase 3 — compatibility and simulation | **Planned** | §103: NetworkPolicy adapter, simulation foundation, improved topology, and historical export | No implementation claim |
| Full CNI and later fabric capabilities | **Planned** | §104 and later roadmap gates | Explicitly out of current scope |

Sections 98–99 describe the richer first enforcement and enriched-observability
scenario. Those scenarios span the Phase 2 gate because they require a real deny
and nonzero identity/policy provenance from the dataplane. They are not counted as
completed by Phase 1's observation-only shadow evaluation.

## Latest verification record

| Check | Result on 2026-08-23 |
|---|---|
| Stable userspace formatting, lint, and tests | Passed: `make fmt-check lint test` |
| eBPF target build and manifest rendering | Passed: `make ebpf` and `kubectl kustomize deploy` |
| Two-node cluster integration | Passed: `make kind-test` |
| Demo dataplane | `frontend/client` reached `backend/server:8080`; the worker agent emitted the flow with nonzero source and destination identities |
| Agent state | Two ready agents; BPF loaded; both applied the controller epoch/revision and populated six IPv4 entries |
| Controller state | Ready; 16 watched Pods, 14 admitted identities, 6 indexed non-host-network Pod IPs, one compiled policy |
| Restart recovery | Both running agents accepted a new controller epoch and converged from revision 33 to the restarted controller's revision 20 without restarting the dataplane |
| Policy explanation | Port 8080 matched the explicit shadow allow; port 9090 matched shadow default deny |

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
| Transactional policy map set | **Planned** | Failed update preserves last-known-good active revision |
| TC identity lookup | **Verified** | Cross-node demo flow carries nonzero source and destination IDs |
| L3/L4 policy decision | **Planned** | Deterministic policy/rule provenance and reason code in events |
| Enforcement | **Planned** | 8080 passes and 9090 is dropped in kind |
| Accurate live explanation | **Planned** | CLI decision and applied node revision match the dataplane |
| Failure behavior | **Planned** | Controller/API interruption and agent restart tests |

## Current limitations

- TC remains observation-only and always passes traffic.
- Identity desired state is distributed but remains in-memory and unpinned;
  compiled policy is not distributed to agent/BPF maps.
- Resolved IPv4 flows carry identity IDs. Policy, rule, and interface IDs remain
  zero until their Phase 2 lookup/provenance paths are connected.
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
