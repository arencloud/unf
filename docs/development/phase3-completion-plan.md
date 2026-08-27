# Phase 3 completion and full-CNI entry plan

Last reviewed: **2026-08-27**

This is the execution matrix for the remaining qualification work. The
authoritative feature status remains in [project-status.md](../project-status.md).
A row moves to **Verified** only when its implementation, repeatable command,
and recorded evidence are all present. Passing a narrower child row does not
complete its parent milestone.

## Milestone summary

| ID | Milestone | State | Dependency | Exit evidence |
|---|---|---|---|---|
| 1 | Broader failure and scale qualification | **Verified** | Existing two-node dual-stack Kind fixture | `make kind-scale-failure-test` plus a schema-versioned result record; ADR 0048 |
| 2 | Expanded version compatibility matrix | **In progress** | Milestone 1 budgets and the compatibility tuple from ADR 0047 | Skipped-version, incompatible-tuple, migration, downgrade, and rollback gates |
| 3 | OpenShift cl02 upgrade qualification | **Planned** | Milestone 2 Kind evidence and development images in Quay | Repeatable dual-stack RHCOS controller/agent rollout and rollback gate |
| 4 | Broader platform/version coverage | **Planned** | Available clusters for each claimed platform | Versioned support matrix with one evidence record per claimed combination |
| 5 | Phase 3 closure | **Planned** | Milestones 1–4 Verified | Complete release audit and Phase 3 marked **Verified** in `project-status.md` |
| 6 | Full-CNI foundation entry | **Gated** | Milestone 5 and explicit approval at the architecture gate | Accepted design plus bounded CNI/IPAM/veth/routing/MTU/node-networking slices |

## 1. Broader failure and scale qualification

| ID | Deliverable | State | Required evidence |
|---|---|---|---|
| 1.1 | Deterministic scale fixture | **Verified** | The bounded generator creates exact Namespace, workload, and paired ingress/egress policy counts deterministically; client dry-run validation and exact cleanup pass |
| 1.2 | Measured convergence budgets | **Verified** | Default-profile apply completed in 11s, churn in 39s, simultaneous-agent recovery in 32s, and controller reconvergence in 7s against 180s budgets |
| 1.3 | Sustained object churn | **Verified** | Three Namespace selector cycles, Pod selection removal/restoration, and paired ingress/egress policy mutation advanced revisions with 62 indexed IPs, no rejection, and converged agents |
| 1.4 | Combined controller and agent failure | **Verified** | Both agents recovered the exact nonzero applied revisions and 1,355 policy entries while desired revisions correctly remained zero with the controller offline, then reconverged to its new epoch |
| 1.5 | Enforcement and queue safety | **Verified** | Continuous dual-stack 8080 allow/9090 deny reported no breach; queues drained within budget, six expected outage sync errors stayed below ten, and flow/telemetry drop deltas were zero |
| 1.6 | Reproducible qualification record | **Verified** | Schema-v1 JSON captures Git/tree/component provenance, environment, profile, budgets, measurements, peak/recovered/cleanup state, with append-only JSONL attempt history |

The initial Kind gate is a bounded qualification profile, not an unlimited
production-scale claim. Larger profiles must state their own cardinalities and
budgets and retain a separate result record.

## 2. Expanded version compatibility matrix

| ID | Deliverable | State | Required evidence |
|---|---|---|---|
| 2.1 | Skipped revision | **In progress** | `make kind-skipped-upgrade-test` must prove a minimum two-commit N to N+2 controller-first and node-serial rollout under an exactly matching published compatibility tuple |
| 2.2 | Incompatible tuple rejection | **Planned** | Schema/ABI mismatch is observable, actionable, and cannot mutate active BPF state |
| 2.3 | Persistent-state migration contract | **Planned** | Versioned migration or deliberate clean-rebuild behavior with atomic failure recovery |
| 2.4 | Downgrade behavior | **Planned** | Supported downgrade succeeds; unsupported downgrade fails before dataplane mutation |
| 2.5 | Rollback reporting | **Planned** | Status, metrics, and logs distinguish compatible rollback, blocked rollback, and recovery |

## 3. OpenShift cl02 upgrade qualification

| ID | Deliverable | State | Required evidence |
|---|---|---|---|
| 3.1 | Immutable development images | **Planned** | N and N+1 controller, agent, and test-tool images published by digest to the development Quay repositories |
| 3.2 | Controller-first rollout | **Planned** | N+1 controller remains compatible with N agents and every authenticated agent stays observable |
| 3.3 | Worker-serial agent rollout | **Planned** | One RHCOS worker at a time transitions under dual-stack traffic with no simultaneous dataplane gap |
| 3.4 | OpenShift rollback | **Planned** | Agent and controller rollback/forward recovery retain policy revision, provenance, and telemetry |
| 3.5 | Platform invariants | **Planned** | Enforcing SELinux, constrained SCC, Service CA, TokenReview, OVN replies, legacy-netlink attachment, and cluster operators remain healthy |

cl02 is first required by milestone 3. Milestones 1 and 2 run against Kind.

## 4. Broader platform/version coverage

| ID | Deliverable | State | Required evidence |
|---|---|---|---|
| 4.1 | Support-matrix schema | **Planned** | Each row records Kubernetes/OpenShift, kernel, OS, CNI, address families, attachment mode, architecture, and evidence revision |
| 4.2 | Existing fixtures | **Planned** | cl01 remains the IPv4 OpenShift row; cl02 remains the dual-stack OpenShift row; Kind remains the dual-stack TCX row |
| 4.3 | Additional release | **Planned** | At least one additional Kubernetes or OpenShift release is qualified before claiming multi-version support |
| 4.4 | Additional kernel/attachment coverage | **Planned** | Every newly claimed kernel and TCX/legacy combination passes enforcement, recovery, and upgrade gates |
| 4.5 | Unsupported boundaries | **Planned** | Untested combinations remain explicitly unqualified rather than inferred from nearby rows |

## 5. Phase 3 closure

| ID | Deliverable | State | Required evidence |
|---|---|---|---|
| 5.1 | Complete regression suite | **Planned** | Formatting, lint, workspace tests, eBPF, render, Kind, scale/failure, upgrade, and OpenShift gates pass from committed revisions |
| 5.2 | Requirements audit | **Planned** | Master-prompt Phase 3 requirements and every tracker row map one-to-one to evidence or a documented exclusion |
| 5.3 | Limitation audit | **Planned** | User-facing status, roadmap, ADRs, and support matrix agree on remaining limits |
| 5.4 | Release-readiness record | **Planned** | Immutable revisions, image digests, cluster versions, commands, results, and retry history are recorded |
| 5.5 | Gate transition | **Planned** | Phase 3 changes from **In progress** to **Verified** only after 5.1–5.4 pass |

## 6. Full-CNI foundation entry

This milestone starts only after the Phase 3 gate and an explicit architecture
approval. It must not silently change the current overlay deployment into a CNI.

| ID | Deliverable | State | Required evidence |
|---|---|---|---|
| 6.1 | CNI architecture and ownership | **Gated** | Accepted API/state, host-ownership, coexistence, upgrade, rollback, and uninstall design |
| 6.2 | CNI executable/configuration | **Gated** | Versioned ADD/CHECK/DEL behavior with idempotence and actionable errors |
| 6.3 | IPAM | **Gated** | Dual-stack allocation, persistence, collision prevention, release, exhaustion, and recovery tests |
| 6.4 | Link lifecycle | **Gated** | veth/netkit creation, namespace movement, naming, cleanup, and crash recovery |
| 6.5 | Routing and MTU | **Gated** | Per-family routes, neighbor behavior, MTU derivation, fragmentation boundaries, and rollback |
| 6.6 | Node-to-node networking | **Gated** | Cross-node dual-stack lifecycle, failure recovery, observability, and coexistence qualification |

## Updating this plan

Every milestone change updates this file and `project-status.md` in the same
commit. Evidence records retries and partial failures; rerunning a failed check
does not erase its history. External dependencies, especially a new cluster
version, are marked explicitly and do not become implicit support claims.
