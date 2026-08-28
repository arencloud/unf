# Phase 3 completion and full-CNI entry plan

Last reviewed: **2026-08-28**

This is the execution matrix for Phase 3 closure and the separately tracked
full-CNI entry work. The
authoritative feature status remains in [project-status.md](../project-status.md).
A row moves to **Verified** only when its implementation, repeatable command,
and recorded evidence are all present. Passing a narrower child row does not
complete its parent milestone.

## Milestone summary

| ID | Milestone | State | Dependency | Exit evidence |
|---|---|---|---|---|
| 1 | Broader failure and scale qualification | **Verified** | Existing two-node dual-stack Kind fixture | `make kind-scale-failure-test` plus a schema-versioned result record; ADR 0048 |
| 2 | Expanded version compatibility matrix | **Verified** | Milestone 1 budgets and the compatibility tuple from ADR 0047 | Same-tuple skipped upgrade, incompatible-tuple rejection, persistent-state clean rebuild, supported/unsupported downgrade behavior, and transition reporting are Verified; ADRs 0049–0053 |
| 3 | OpenShift cl02 upgrade qualification | **Verified** | Milestone 2 Kind evidence and development images in Quay | `make openshift-upgrade-test OPENSHIFT_KUBECONFIG=.tools/cl02-audit.kubeconfig`; ADR 0054 |
| 4 | Broader platform/version coverage | **Verified** | Available clusters for each claimed platform | Four exact qualified tuples, including an isolated Kubernetes 1.34.8 endpoint/recovery/upgrade record; ADR 0055 |
| 5 | Phase 3 closure | **Verified** | Milestones 1–4 Verified | Complete release audit and Phase 3 marked **Verified** in `project-status.md`; ADR 0056 |
| 6 | Full-CNI foundation entry | **In progress** | Milestone 5 Verified; architecture entry explicitly approved | ADR 0057 plus bounded CNI/IPAM/veth/routing/MTU/node-networking slices |

## 1. Broader failure and scale qualification

| ID | Deliverable | State | Required evidence |
|---|---|---|---|
| 1.1 | Deterministic scale fixture | **Verified** | The bounded generator creates exact Namespace, workload, and paired ingress/egress policy counts deterministically; client dry-run validation and exact cleanup pass |
| 1.2 | Measured convergence budgets | **Verified** | The closure run completed default-profile apply in 11s, churn in 40s, simultaneous-agent recovery in 33s, and controller reconvergence in 7s against 180s budgets |
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
| 2.1 | Skipped revision | **Verified** | `make kind-skipped-upgrade-test` passed N=`e6e5ac6`, skipped=`9dc6023`, N+2=`a630ee1` at exact distance two, requiring an identical published tuple before controller-first, mixed, full, downgrade/forward, and recovery checks; ADR 0049 |
| 2.2 | Incompatible tuple rejection | **Verified** | `make kind-incompatible-version-test` passed from clean revision `6d7dd28`: local ABI 4 rejected the configured v3 directory before BPF access, repeated policy-schema 5 snapshots left agent policy state and pinned policy maps unchanged, enforcement stayed continuous, and the current tuple reconverged; ADR 0050 |
| 2.3 | Persistent-state migration contract | **Verified** | `make kind-clean-rebuild-test` passed from clean revision `e39ac5c`: fresh ABI state committed identity and policy snapshots before attachment, v3→v4 and reverse node-serial handoffs retained continuous enforcement, old state was retired only after convergence, and exact scoped cleanup restored v3; ADR 0051 |
| 2.4 | Downgrade behavior | **Verified** | Same-tuple N+2→N agent/controller rollback is supported by 2.1; `make kind-unsupported-downgrade-test` passed from clean revision `cc52ac5`, proving a v3 agent rejects `/v4` before BPF access, all eleven v4 maps remain digest-identical, enforcement stays continuous, v4 recovers, and clean-rebuild rollback restores v3; ADR 0052 |
| 2.5 | Rollback reporting | **Verified** | `make kind-rollback-reporting-test` passed on its first attempt from clean revision `1bf83f7`: local status, controller aggregation, metrics, and logs classified blocked rollback, recovery, and compatible rollback; rejection preserved the eleven-map v4 digest and continuous enforcement; final v3 convergence restored `normal`; ADR 0053 |

## 3. OpenShift cl02 upgrade qualification

| ID | Deliverable | State | Required evidence |
|---|---|---|---|
| 3.1 | Immutable development images | **Verified** | The closure publisher recorded six Quay digest references for adjacent N=`6fcea31` and N+1=`43320db`, covering controller, agent, and test tools with exact revision/distance provenance; ADR 0056 |
| 3.2 | Controller-first rollout | **Verified** | N+1 controller served two N agents with an identical compatibility tuple, two fresh authenticated converged reports, dual-stack enforcement/provenance, and advancing telemetry |
| 3.3 | Worker-serial agent rollout | **Verified** | Each RHCOS worker transitioned alone through deterministic mixed/full states; continuous IPv4/IPv6 probes reported no sustained allow gap or deny breach |
| 3.4 | OpenShift rollback | **Verified** | Both agents rolled back serially, the controller returned to exact N/N, then controller-first and worker-serial recovery restored full N+1 with policy state, provenance, and telemetry at every stage |
| 3.5 | Platform invariants | **Verified** | Full N and N+1 endpoint gates plus every transition retained Enforcing SELinux, constrained SCC, Service CA, TokenReview, OVN/stateful replies, native legacy filters, and 34 healthy operators; ADR 0054 |

cl02 is first required by milestone 3. Milestones 1 and 2 run against Kind.

## 4. Broader platform/version coverage

| ID | Deliverable | State | Required evidence |
|---|---|---|---|
| 4.1 | Support-matrix schema | **Verified** | Schema-v1 `support-matrix.json` records the exact platform, Kubernetes/OpenShift, OS, kernel, runtime, CNI, address families, attachment modes, architecture, cluster shape, full evidence revision, commands, records, decisions, and scope; `make support-matrix-check` validates structure and references |
| 4.2 | Existing fixtures | **Verified** | Separate exact rows retain Kind dual-stack TCX/legacy evidence at `9dc6023`, cl01 IPv4 OpenShift legacy evidence at `4f213c7`, and cl02 dual-stack OpenShift legacy plus digest-pinned transitions at `43320db` |
| 4.3 | Additional release | **Verified** | `make kind-platform-matrix-test` passed on Kubernetes 1.34.8 from clean revision `da73359`, independently of the existing Kubernetes 1.35.0 Kind row; schema-v1 result and append-only attempt history are retained; ADR 0055 |
| 4.4 | Additional kernel/attachment coverage | **Verified** | The additional Debian 13/containerd 2.3.1/kindnetd tuple passed full dual-stack endpoint and recovery gates in both TCX and legacy-netlink modes plus adjacent-revision upgrade/rollback on its actual Linux 7.1.4 host kernel |
| 4.5 | Unsupported boundaries | **Verified** | Seven normative dimensions explicitly leave unlisted releases, kernels/OSes, architectures, CNIs, cluster shapes, and production artifact paths unqualified; matrix semantics prohibit transitive claims |

## 5. Phase 3 closure

| ID | Deliverable | State | Required evidence |
|---|---|---|---|
| 5.1 | Complete regression suite | **Verified** | Formatting, lint, 170 workspace tests, eBPF, base/OpenShift renders, complete Kind, scale/failure, adjacent-upgrade, and digest-pinned cl02 gates passed for implementation revision `43320db`; ADR 0056 |
| 5.2 | Requirements audit | **Verified** | ADR 0056 maps every master-prompt §103 requirement one-to-one and confirms all 42 Phase 3 tracker rows are Verified |
| 5.3 | Limitation audit | **Verified** | Status, roadmap, ADR 0056, and support matrix consistently retain bounded L4, exact-platform, development-artifact, OpenShift-platform-upgrade, incompatible-ABI migration, production-scale, and full-CNI limits |
| 5.4 | Release-readiness record | **Verified** | ADR 0056 records exact revisions, all six current cl02 image digests, cluster/runtime facts, commands, outcomes, and retained retry history |
| 5.5 | Gate transition | **Verified** | Items 5.1–5.4 passed and Phase 3 is **Verified** in `project-status.md`; later authorization started the separately tracked full-CNI foundation |

## 6. Full-CNI foundation entry

This milestone started after the Phase 3 gate and explicit architecture entry
approval. It must not silently change the current overlay deployment into a CNI.

| ID | Deliverable | State | Required evidence |
|---|---|---|---|
| 6.1 | CNI architecture and ownership | **Verified** | ADR 0057 accepts the versioned local transaction/state model, exact host ownership, overlay/primary coexistence, node-drain cutover/rollback, scoped uninstall, and Kind-first qualification boundary |
| 6.2 | CNI executable/configuration | **In progress** | `make cni-protocol-test` verifies bounded CNI 1.0/1.1 VERSION/ADD/DEL/CHECK/STATUS/GC inputs and structured results; lifecycle creation remains fail closed until IPAM and link operations are connected through the local transaction API |
| 6.2a | Local agent transaction state/API | **Verified** | `make cni-transaction-test` verifies schema-v1 bounded JSON, UID-0 Unix peer authentication, owner-only socket permissions, opt-in startup, deterministic attachment identity, atomic mode-0600 persistence, exact replay/conflict/transition behavior, durable preparing/ready/aborting/deleting restart recovery, and scoped shutdown/stale-socket handling; ADR 0058 |
| 6.3 | IPAM | **Verified** | `make cni-ipam-test` verifies modular bounded dual-stack allocation plus schema-v2 attachment/lease persistence, v1 migration, exact provider provenance, collision/exhaustion rejection, cleanup retention/release, and restart recovery; ADRs 0059–0060. Controller node-block distribution remains part of cluster networking, not this local IPAM gate |
| 6.3a | Dual-stack node-block allocation core | **Verified** | `make cni-ipam-test` verifies canonical block validation, network/gateway/broadcast reservation, deterministic lowest-free dual-stack allocation, a 65,536-lease node bound, family-specific exhaustion, collision-checked restoration, atomic release/reuse, provider mismatch rejection, strict serialization, and routing-independent trait use; ADR 0059 |
| 6.3b | Durable attachment/lease integration | **Verified** | Transaction/journal schema v2 allocates on prepare, returns the same lease on exact replay, retains it through ready/aborting/deleting and restart, releases only on complete abort/delete, atomically migrates sorted schema-v1 state, stores exact node-block provenance, and rejects failed migration, block drift, duplicate leases, and family exhaustion without mutating last-known-good state; `make cni-ipam-test`; ADR 0060 |
| 6.4 | Link lifecycle | **Verified** | `make cni-veth-test` verifies a typed-netlink `unf-link` plan derived from the durable attachment record, deterministic bounded names and locally administered ownership addresses, exact aliases, portable veth creation, namespace-FD movement on a disposable thread, rename/MTU/up/dual-stack address application, independent readback, replay and partial-state recovery, idempotent exact cleanup, and foreign-link preservation; ADR 0061. Netkit remains separately gated |
| 6.5 | Routing and MTU | **Verified** | `make cni-routing-test` verifies the provider-independent plan, typed native kernel lifecycle, scoped rollback, isolated dual-stack forwarding, exact 1400-byte IPv4/IPv6 boundaries, permitted source fragmentation, and MTU drift rejection; ADR 0062 |
| 6.5a | Native route and MTU plan | **Verified** | `make cni-routing-test` proves zero-overhead native MTU derivation with the dual-stack minimum, durable MTU/readback drift rejection, `/32` and `/128` workload addressing, direction-scoped host endpoint plus container gateway/default route IR, permanent peer-MAC neighbor IR, and a currently unassigned node-local route-protocol convention without reusing Open/R or BGP; ADR 0062 |
| 6.5b | Native route kernel lifecycle | **Verified** | `make cni-routing-test` proves typed-netlink preflight/apply/readback/delete, exact protocol/table/scope/interface/MAC ownership, idempotent replay and cleanup, injected post-container failure rollback with link preservation, foreign default-route and gateway-neighbor rejection/preservation, and real IPv4/IPv6 forwarding across isolated pod, host, and remote namespaces; ADR 0062 |
| 6.5c | MTU and fragmentation qualification | **Verified** | The isolated native gate uses 1400-byte workload and underlay links: IPv4 DF payload 1372 and IPv6 no-fragment payload 1352 pass, the next byte fails, larger IPv4 and IPv6 payloads pass only with source fragmentation allowed, and independent host/peer MTU drift fails strict readback. Unit gates reject provider/durable underlay-MTU drift and invalid overhead bounds; post-container rollback remains exact |
| 6.6 | Node-to-node networking | **Planned** | Cross-node dual-stack lifecycle, failure recovery, observability, and coexistence qualification |

## Updating this plan

Every milestone change updates this file and `project-status.md` in the same
commit. Evidence records retries and partial failures; rerunning a failed check
does not erase its history. External dependencies, especially a new cluster
version, are marked explicitly and do not become implicit support claims.
