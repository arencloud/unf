# Project status and requirements traceability

Last verified: **2026-08-26**

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
| Phase 2 — identity and policy enforcement | **Verified** | §102: BPF policy maps, allowed flow passes, denied flow drops, denial event has identity/policy/rule/reason, and accurate `unfctl explain` | `make fmt-check lint test`, `make ebpf`, and `make kind-test` verify the complete gate; `make openshift-test` qualifies both IPv4-only and dual-stack platform slices, while focused rotation, acknowledgement-retention, admission, and uninstall/redeploy gates cover the planned OpenShift hardening |
| Phase 3 — compatibility and simulation | **In progress** | §103: NetworkPolicy adapter, simulation foundation, improved topology, and historical export | The supported ingress adapter with a dual-stack upstream-aligned matrix, history-aware read-only policy simulation with optional last-received windows, EndpointSlice-aware topology schema v3, and bounded dual-stack historical export with restart recovery are live verified; broader compatibility remains open |
| Full CNI and later fabric capabilities | **Planned** | §104 and later roadmap gates | Explicitly out of current scope |

Sections 98–99 describe the richer first enforcement and enriched-observability
scenario. Those scenarios span the Phase 2 gate because they require a real deny
and nonzero identity/policy provenance from the dataplane. They are not counted as
completed by Phase 1's observation-only shadow evaluation.

## Latest verification record

| Check | Result on 2026-08-26 |
|---|---|
| Stable userspace formatting, lint, and tests | Passed: `make fmt-check lint test` |
| eBPF target build and manifest rendering | Passed: `make ebpf` and `kubectl kustomize deploy` |
| Two-node cluster integration | Passed: `make kind-test` |
| Dual-stack cluster fixture | Both kindnet Pods stayed Ready with zero restarts through the complete verifier; `kind-up` applies the reproducible nftables compatibility setup and `make kind-test` gates CNI readiness at start and finish |
| Demo dataplane | On the dual-stack two-node fixture, native policy allowed TCP/8080 and explicitly denied open TCP/9090 over both IPv4 and IPv6; real UDP packets carrying Hop-by-Hop, Destination Options, and combined extension headers allowed 8087–8089 and explicitly denied 9097 with revisioned provenance. Selector-based NetworkPolicy allowed 8081 and default-denied open 9091 over both families. Existing shadow, range, dual-stack block/exception, omitted-default, SCTP, lifecycle, and upstream-aligned dual-stack ingress scenarios also passed |
| Agent state | Two ready agents with BPF loaded; both converged on the same controller epoch and identity/policy revisions with 14 identity entries each (7 IPv4 + 7 IPv6), 151 active policy entries, zero queued/dropped exports at capture, and `tcx_pinned` attachment mode on the Linux 7.1 kind host |
| Controller state | Ready with 2 watched Nodes, 17 watched Pods, 8 watched Namespaces, 5 watched Services, 5 watched EndpointSlices, 15 admitted identities, 14 indexed non-host-network Pod IPs, one native policy, one accepted NetworkPolicy, zero rejected NetworkPolicies, 151 resolved identity/IPv4/IPv6 entries, zero reported telemetry drops, and Pod-bound TokenReview-authenticated acknowledgements proving both expected agents converged |
| Topology state | Schema v3 returned 2 ready Nodes, 17 placed workloads, 5 Services, and 7 dual-stack non-host-network workloads; the EndpointSlice readiness/deletion lifecycle passed without policy-revision mutation |
| Flow history | Snapshot schema v3 retained bounded IPv4, IPv6, and SCTP logical flows; the newest bounded subset survived controller replacement through checkpoint schema v1 with its original first-received time, absolute/relative last-received windows and newest-first limits passed, persistence errors stayed zero, and neither agent was replaced. Direct IPv6 `frontend/client` → `backend/server` TCP/8080 was enriched with both workload references and exact addresses, while agent export remained schema v2 |
| Policy simulation | Schema v3 kept the revision-fenced topology matrix independent while applying optional absolute/relative last-received bounds and newest-first limits to historical impact. The live gate selected a newly emitted TCP/8080 flow and predicted its weighted denial, reported bounded query metadata, proved a future window evaluated zero historical flows while topology impact remained populated, and left the live policy revision and forwarding unchanged |
| Transactional policy update | The verifier switched enforce → shadow → enforce and exercised TCP/SCTP protocol-wildcard plus IPv4/IPv6 block mutations, requiring a higher revision and opposite bank on every agent for single-resource transitions; snapshot schema v3 stages all three policy maps before one activation write |
| Transactional identity update | Identity ABI v2 staged IPv4 and IPv6 in inactive physical maps and activated both with one `IDENTITY_CONFIG` write; repeated Pod/label lifecycle mutations remained dual-stack enforced, and both nodes exposed the complete nine-pin `/sys/fs/bpf/unf/v2` set after the suite |
| Interruption recovery | With the controller scaled to zero, the server-node agent was deleted and its replacement became Ready from 14 pinned identity entries plus validated identity epoch/revision/active bank and active policy revision; parallel TCP/9090 probes ran continuously through deletion and replacement with zero successful requests, then both agents accepted the restarted controller epoch and reconverged |
| TC attachment handoff | Each agent exposed direction-specific pins below `/sys/fs/bpf/unf/v2/links`; the replacement agent atomically updated existing TCX links and reported `tcx_pinned`. A second gate selected `legacy_netlink`, confirmed reserved priority 21838/handle `0x554e0001` filters, removed all UNF ingress TCX pins, and required uninterrupted deny enforcement plus `replaced=true` across offline-controller replacement. It restored TCX pins before removing the reserved legacy filters |
| Scoped host-state cleanup | The deployed agent refused current v2 removal without confirmation and rejected unknown content injected into recognized v1 state without removing six known pins. Its dry run preserved those pins; execution removed v1 on both nodes while all nine v2 maps remained. After TCX restoration, the legacy gate proved another dry run preserved the reserved filters before the command removed only UNF-named ingress filters |
| Agent acknowledgement authentication | Both agents converged with schema v2 Pod name/UID reports and dedicated-audience projected tokens accepted through Kubernetes TokenReview. The live gate rejected missing and invalid credentials with 401, accepted the real Pod token with 204, rejected the same valid token carrying a forged Node claim with 403, and required three authentication failures to be accounted without creating an unexpected agent |
| Internal transport security | Agent-only routes were absent from public HTTP, the dedicated HTTPS port rejected the development CA when it was not explicitly trusted, and the real CA plus projected Pod token read a snapshot and submitted an acknowledgement. Both agents converged and exported retained flow history through the same CA-pinned, TokenReview-authenticated transport; management-port filtering prevented recursive telemetry from displacing workload provenance |
| OpenShift IPv4 qualification | Passed: `make openshift-test` on OpenShift 4.22.9 / Kubernetes 1.35.6 with two RHCOS 9.8 workers on Linux 5.14. The controller ran under `restricted-v2`; worker-only agents used the dedicated `unf-agent` SCC and a non-privileged three-capability container. SELinux remained Enforcing, BTF/bpffs/cgroup v2 and native `legacy_netlink` filters were verified, OpenShift Service CA TLS and Pod-bound TokenReview positive/negative paths passed, exactly two selected agents converged, cross-worker TCP/8080 allowed while TCP/9090 dropped with retained provenance, and all 34 cluster operators remained healthy |
| OpenShift dual-stack qualification | Passed: the adaptive `make openshift-test` gate on a separate OpenShift 4.22.9 / Kubernetes 1.35.6 cluster with two RHCOS 9.8 Linux 5.14 workers. Both agents converged with populated IPv4 and IPv6 identity maps, the authenticated snapshot contained both families, cross-worker IPv4 and IPv6 TCP/8080 allowed while TCP/9090 dropped, retained history carried allow/deny policy provenance for each family, and the same SCC, SELinux, native legacy-filter, Service CA, TokenReview, selected-worker, and 34-operator health assertions passed |
| OpenShift agent security boundary | Passed on both OpenShift fixtures: the service account can use only the dedicated `unf-agent` SCC, not `privileged`; agents run root in `spc_t` but are non-privileged with host PID/IPC disabled, runtime-default seccomp, `NoNewPrivs`, read-only root filesystems, and exact effective capabilities `BPF`, `NET_ADMIN`, and `PERFMON`. Removing `SYS_RESOURCE` succeeded; removing `PERFMON` produced a kernel verifier rejection and disabling host-port admission rejected the host-network health port, documenting both retained requirements |
| OpenShift host-mount admission | Passed on dual-stack OpenShift with `make openshift-host-mount-policy-test`: both native policies were observed without type warnings, the deployed DaemonSet and an unrelated Pod were admitted, all live agents exposed only the exact bpffs/BTF mounts, and service-account replacement, alternate paths/types/modes, subPath/propagation, sidecar/init, direct-agent-Pod, and ephemeral-container access were denied by server dry run |
| Certificate and trust rotation | Passed on dual-stack OpenShift with `make openshift-tls-rotation-test`: an overlapping CA bundle was projected to both agents, the controller switched to an external-PKI leaf, authenticated snapshots succeeded under the new issuer, trust contracted to the new CA, malformed CA and leaf updates were rejected while last-known-good transport and convergence remained active, and the original Service CA contract was restored. Controller/agent reload and error metrics advanced as expected and every Pod UID/restart count remained unchanged |
| Durable agent acknowledgement retention | Passed on dual-stack OpenShift with `make openshift-agent-report-retention-test`: two authenticated reports were schema-versioned in the exact-name ConfigMap checkpoint, the controller Pod was replaced, the new process reported exactly two restored entries before agents reconverged to its new epoch, checkpoint receive times advanced, persistence errors stayed zero, and both agent Pod UID/restart tuples remained unchanged |
| Coordinated OpenShift uninstall | Passed on dual-stack OpenShift with `make openshift-uninstall-test`: a two-node dry run planned exactly 18 current-v2 map pins without Pod mutation, incorrect context confirmation was refused, all agents stopped before constrained cleanup Jobs removed host pins and UNF ingress/egress filters, the dedicated Namespace and exact cluster resources disappeared, the CRD UID was preserved, and a clean redeploy passed the complete dual-stack qualification |
| Persistent-state fault rejection | A short-lived bpffs helper built isolated map sets for eight-of-nine pins, malformed `POLICY_CONFIG`, and corrupt inactive-bank `POLICY_RULES` debris. The exact deployed agent exited nonzero with each expected cause, the primary pins were untouched, established allow/deny traffic remained correct, and the later offline replacement still recovered |
| Physical map-pressure rollback | The helper filled the shared real `POLICY_RULES` map to its 262,144-entry physical limit with reserved synthetic keys tagged for the inactive bank. A Shadow update advanced desired state but the pressured agent retained its applied revision and bank, incremented `unf_policy_sync_errors_total`, logged the staging failure, and preserved active TCP/8080 allow plus TCP/9090 deny. Releasing pressure let the same waiting revision activate on the opposite bank; Shadow traffic passed and restored Enforce traffic denied again |
| Dataplane provenance | ABI v2 TCP and SCTP events matched the applied revision and carried nonzero identities plus actual/shadow policy and explicit-deny rule provenance |
| NetworkPolicy lifecycle | Named port `allowed` resolved to TCP/8081; one `web` name resolved independently to TCP/8087 and TCP/8088 across two destination Pods while each opposite open port stayed denied; exact and protocol-only UDP rules allowed request/response traffic without broadening same-port TCP or non-matching peers, and deletion restored both protocols; explicit empty source/port lists behaved as wildcards while two port entries remained a protocol-safe OR; the inclusive 8082–8083 range enforced both boundaries and excluded 8084; a protocol-only TCP entry allowed arbitrary TCP/9091 without allowing UDP/9091 and removal restored isolation; exact IPv4 and prefix IPv6 blocks allowed the client, nested exceptions denied it, and exception removal recovered; Namespace relabel removed/restored the allow without identity churn; oversized range/block updates removed stale state and recovered; deletion allowed 9091 and recreation restored the drop; omitted `podSelector`, `policyTypes`, and protocol produced namespace-wide/default-ingress/default-TCP behavior, while target narrowing restored non-isolated traffic; named SCTP and protocol-only SCTP rules enforced and reconverged across nodes |
| Upstream-aligned ingress matrix | A disposable three-Namespace matrix proved explicit empty source/port wildcard semantics, multi-port OR, exact/protocol-only UDP peer and TCP isolation with deletion recovery, destination-specific named-port resolution across two server Pods, nonexistent named-port fail-closed isolation, destination Pod match-label and all-four-expression-operator selection/isolation/recovery, broad/narrow overlapping destination-selector additivity with ordered deletion recovery, remote target-specific allow over namespace-wide default deny with combined empty peer selectors, same-object allow-all/default-deny update and rollback, default deny, empty/labeled same-Namespace PodSelector scope, homogeneous multiple-PodSelector peer OR, empty/exact-name NamespaceSelector selection, all four peer Pod/Namespace selector operators, multi-value Pod `In` AND Namespace-name `NotIn`, selector AND, heterogeneous peer OR, source/Namespace-label deny/recovery, source/port pairing across multiple ingress rules, stacked per-source/per-port additive allows, and allow-all precedence. Every claimed traffic transition passed against direct IPv4 and IPv6 Pod addresses before truthful explanation and exact cleanup checks; the stateful same-Namespace return-flow leg remains excluded |
| Policy explanation | Native 8080/9090, compatibility exact/range/protocol-only TCP/UDP/SCTP ports, bounded block/exception transitions, and namespace-wide target/defaulting transitions reported the expected explicit/default/no-applicable-policy provenance with dataplane enforcement truthfully enabled |
| Policy simulation | Schema v3 evaluated the revision-fenced topology matrix independently from optional absolute/relative last-received history windows. It selected a newly emitted TCP/8080 flow and predicted weighted denial impact, reported bounded query metadata, proved a future window evaluated zero historical flows while topology impact remained populated, left live policy state unchanged, and TCP/8080 remained allowed |

The kind fixture and the two temporary OpenShift qualification Namespaces are
disposable, and object counts can change as system Pods roll. The OpenShift
product deployment intentionally remains in `unf-system`; its host filters must
be removed with `hack/uninstall-openshift.sh` before its cluster resources are
deleted. The repeatable commands, rather than these snapshot counts, are the
release gate.

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
| TC observation | **Verified** | Bounded Ethernet and IPv4/IPv6 TCP/UDP/SCTP parsing, including bounded IPv6 extension-header traversal, counters, ring buffer, allow/drop verdict | Cross-node IPv4/IPv6 TCP/8080, SCTP/8086, and real IPv6 extension-header UDP events asserted by `hack/verify-kind.sh` |
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
| Versioned BPF identity map schema | **Verified** | ABI tests plus `make kind-test` require populated IPv4 and IPv6 kernel maps on both agents |
| Controller-to-agent revisioned distribution | **Verified** | Both node agents report desired/applied epoch and revision convergence; controller-restart recovery exercised live |
| Controller-aggregated node acknowledgements | **Verified** | Schema v2 reports carry Node and Pod identity. A dedicated-audience projected token is authenticated through TokenReview, then bound to the `unf-agent` service account, watched Pod UID, and authoritative Node placement before storage. Controller/CLI status distinguishes expected, missing, stale, unexpected, and converged agents; an optional exact label selector defines the expected agent population. Unit, kind, and OpenShift tests reject missing/invalid credentials and cross-Node claims while all selected agents converge |
| Durable agent acknowledgement checkpoint | **Verified** | ADR 0027 defines a schema-versioned 1,024-entry ConfigMap, exact-name `get`/`patch` RBAC, two-second coalesced writes, strict startup validation, future-time rejection, Node deletion cleanup, and fail-closed capacity. Unit tests cover round-trip/rejection/cleanup; `make openshift-agent-report-retention-test` proves exact restore count, new-epoch reconvergence, continued writes, zero errors, and no agent replacement across controller restart |
| Encrypted authenticated internal transport | **Verified** | Public HTTP exposes no snapshot or agent-write routes. Dedicated HTTPS serves identity/policy snapshots, acknowledgements, and telemetry; agents trust only `unf-internal-ca` and reread their projected token for every request. The controller bounds Kubernetes API load with a 64-entry/30-second successful-review cache while rechecking authoritative Pod identity and placement on every request; invalid credentials are not cached. Agent userspace counts but excludes the configured management TCP port from logs/export to prevent telemetry recursion. `make kind-test` covers the supplied-Secret CA mode; `make openshift-test` covers OpenShift Service CA injection. Both gates cover plaintext isolation, missing CA, missing/invalid/valid credentials, forged Node claims, convergence, workload provenance, and flow export |
| Certificate and CA-bundle hot rotation | **Verified** | The controller validates changed keypairs and atomically reloads Rustls every five seconds; agents parse changed PEM bundles and replace their CA-only client before internal requests. Both retain last-known-good state on unreadable or malformed input and expose success/error counters. Unit tests cover valid/malformed CA updates and plaintext refusal; `make openshift-tls-rotation-test` proves overlap → external leaf → trust contraction → malformed updates → Service CA restoration with authenticated traffic, convergence, exact mounts, and zero Pod replacements |
| OpenShift IPv4 and dual-stack platform qualification | **Verified** | `make openshift-test` detects the cluster families and repeatably verifies restricted controller execution, worker-only agents under the dedicated constrained SCC, the exact three-capability process boundary, native Linux 5.14 legacy TC attachment under Enforcing SELinux, OpenShift Service CA and TokenReview transport, selected-node convergence, required-family identity state, cross-worker allow/drop provenance, and healthy cluster operators on separate IPv4-only and dual-stack OpenShift fixtures |
| Constrained OpenShift agent SCC | **Verified** | ADR 0025 defines the explicit SCC/RBAC and safe legacy-binding migration. `make openshift-test` requires no built-in privileged-SCC authorization, non-privileged execution, host PID/IPC disabled, read-only root, runtime-default seccomp, `NoNewPrivs`, `spc_t`, and only `BPF`, `NET_ADMIN`, and `PERFMON` effective on every worker before enforcement checks |
| Path-specific OpenShift host-mount admission | **Verified** | ADR 0028 defines fail-closed native DaemonSet and Pod/ephemeral policies scoped to `unf-system`, the named DaemonSet, and the `unf-agent` service account. The focused gate proves exact writable bpffs and read-only BTF admission, rejects service-account/path/type/mode/subPath/container-ownership violations, and is invoked by the full dual-stack OpenShift gate |
| Coordinated OpenShift uninstall | **Verified** | ADR 0029 defines dry-run-first planning, Ready-node coverage, exact context confirmation, agent shutdown, constrained per-node cleanup Jobs, post-cleanup host inspection, ordered exact resource removal, default CRD preservation, and explicit CRD data-loss authority. The disruptive cl02 gate proves complete uninstall and full dual-stack redeploy recovery |
| Transactional identity map set | **Verified** | Identity ABI v2 stages separate inactive IPv4/IPv6 maps, validates both, and selects them with one `IDENTITY_CONFIG` write; ABI/agent tests cover the fixed config and recovery rules, while `make kind-test` exercises repeated identity changes, dual-stack enforcement, and offline restart recovery |
| Selector-to-identity policy lowering | **Verified** | Unit tests cover exact/default, shadow provenance, conflicts, and deterministic ordering; `make kind-test` requires nonzero resolved entries |
| Transactional policy map set | **Verified** | `make kind-test` stages a changed policy on the opposite bank, verifies a higher applied revision, restores it, and verifies reconvergence |
| TC identity lookup | **Verified** | Cross-node IPv4 and IPv6 demo flows carry nonzero source and destination IDs |
| L3/L4 policy decision | **Verified** | Exact/fallback active-bank lookup plus ABI v2 revision, verdict, reason, policy, rule, and shadow provenance |
| Enforcement | **Verified** | `make kind-test` proves IPv4/IPv6 8080 allow and open-port 9090 drop, shadow pass-through, and restored drop |
| Accurate live explanation | **Verified** | CLI actual decisions and IDs are checked while every traffic-path agent reports the active revision applied |
| Pinned last-known-good restart recovery | **Verified** | Nine-map all-or-none ABI v2 directory, capacity/content and active-config validation, two-bank cache reconstruction, and fresh-start readiness fencing; `make kind-test` replaces the server-node agent with the controller offline, requires recovered identity epoch/revisions/active-bank validation, and rechecks allow/drop before controller restoration |
| Persistent TC attachment handoff | **Verified** | `make kind-test` on Linux 7.1 continuously probes an explicitly denied flow through both pinned TCX atomic replacement and an explicitly selected legacy netlink replacement. The legacy gate confirms the fixed tuple, removes TCX coverage, requires in-place replacement evidence, then restores TCX before scoped cleanup. `make openshift-test` verifies native legacy selection and reserved filters on OpenShift/RHCOS Linux 5.14 with Enforcing SELinux; broader kernel/platform coverage remains portability work |
| Scoped host-state cleanup | **Verified** | `unf-agent cleanup` is dry-run-first, recognizes only v1/v2 map and numeric TCX pin names, refuses unknown/symlink state, gates current v2 behind `--allow-current-abi`, and removes only UNF-named legacy filters without deleting clsact. Unit tests cover its ownership boundary; `make kind-test` proves refusal and non-mutation, removes v1 across both nodes while preserving nine v2 maps, then dry-runs and executes legacy cleanup only after TCX restoration |
| Persistent-state corruption failure injection | **Verified** | `make kind-test` uses isolated bpffs aliases and cloned fault maps to prove partial-pin, malformed active-config, and invalid inactive-stage rejection through the exact deployed agent; every probe exits nonzero with an actionable cause, leaves the primary pin set untouched, and preserves established allow/deny traffic |
| Physical map-pressure failure injection | **Verified** | `make kind-test` fills the shared real `POLICY_RULES` map with inactive-bank synthetic keys, requires a kernel staging failure plus sync-error telemetry while the applied revision, selected bank, and active allow/deny traffic remain unchanged, then removes only those reserved keys and proves the waiting revision activates on the opposite bank before enforcement is restored |

## Current limitations

- Enforcement currently covers resolved-identity IPv4/IPv6 TCP/UDP/SCTP exact
  and wildcard decisions. IPv6 traversal is limited to six headers and 256
  extension bytes: Hop-by-Hop (first only), Routing, Destination Options,
  initial/atomic Fragment, and AH are supported. Non-initial IPv4/IPv6
  fragments, IPv6 jumbograms, ESP/No Next Header, malformed or over-limit
  chains, and other protocols fail open.
- Enforcement is currently stateless. Forward and reverse packets are evaluated
  independently, so a source Pod selected by an ingress-isolation policy can drop
  return packets for a connection whose forward direction was allowed. The
  same-Namespace leg of upstream's namespace-wide default-deny plus target-specific
  exception scenario remains excluded until established/related flow tracking is
  designed for TCP/UDP, IPv4/IPv6, timeouts, map lifecycle, and future NAT state.
- Identity and compiled policy desired state remain in-memory, but their nine
  dual-bank enforcement maps are pinned and strictly validated across agent
  restart. Linux 6.6+ TCX links are pinned and atomically updated during agent
  replacement; the legacy netlink fallback reserves priority `0x554e` and handles
  `0x554e:1`/`0x554e:2`. Its forced-mode path and scoped migration cleanup are
  live-verified on Linux 7.1. Native legacy selection and compatibility are also
  live-verified on OpenShift/RHCOS Linux 5.14 with Enforcing SELinux. Broader
  kernel/platform combinations remain. ABI v1 and known stale ABI directories
  can be removed with the dry-run-first cleanup command after a validated
  rollout. Standalone current-v2 cleanup still requires explicit confirmation;
  ADR 0029 now coordinates and live-verifies it for OpenShift uninstall.
- Partial pin sets, malformed active policy config, and invalid inactive-stage
  values are live-verified as rejected using isolated bpffs fault sets. Physical
  inactive-bank exhaustion, rollback, active-traffic preservation, scoped
  cleanup, and retry are live-verified against the real pinned policy map.
- Unknown destination identities, missing/incompatible map config, invalid
  values, and absent identity/IP decisions fail open with revision-zero
  observed/identity-unknown provenance. Unknown source identities can be enforced
  by a valid exact or external-fallback IPv4 policy entry.
- Agent acknowledgements are freshness-aware, controller-aggregated, and use a
  dedicated TLS service plus Pod-bound Kubernetes TokenReview identity. Reports
  older than ten seconds are marked stale. A bounded single-controller ConfigMap
  checkpoint preserves them across restart without allowing old-epoch convergence.
  OpenShift Service CA integration and encrypted IPv4/IPv6 flow export
  are live-verified. Certificate hot reload/rotation is separately gated;
  HA report-store coordination and NetworkPolicy isolation remain.
- Policy simulation currently accepts one native `SecurityPolicy`, uses current
  Pods plus representative policy-derived TCP/UDP/SCTP probes, and rejects matrices
  above 10,000 flows. It separately evaluates retained history and observation
  frequency with optional inclusive last-received bounds and a newest-first limit.
  Windows select aggregate entries rather than bucketing individual observations;
  simulation cannot evaluate external sources without a current identity and
  accepts no user-supplied flow sets.
- Flow history is advisory and destination-resolved. Agent export uses the
  authenticated internal TLS boundary; channels, pending state, controller
  retention, and a newest-1,024/900,000-byte ConfigMap checkpoint are bounded with
  explicit drop, eviction, and omission counters. Query windows select aggregate
  entries by last-received time rather than bucketing observations. History is not
  an HA database, sampled, or deduplicated across interface-level observations.
- Topology schema v3 reports current in-memory Node, dual-stack Pod workload,
  Service intent, and EndpointSlice runtime relationships. Conditions are
  Kubernetes-reported state rather than active traffic health; topology history,
  filtering,
  pagination, and routing/load-balancing behavior are not implemented.
- The NetworkPolicy adapter intentionally accepts only the documented ingress
  subset. Omitted target selectors, policy types, and port protocols follow the
  supported Kubernetes namespace-wide/ingress/TCP defaults. Numeric ranges are
  limited to 1,024 inclusive ports, and complete
  identity-keyed snapshots to 131,072 entries per bank. IPv4 blocks support
  `except` but are limited to 1,024 addresses each and 131,072 IPv4 entries per
  bank. IPv6 blocks retain CIDRs in a prefix trie, support `except`, allow at
  most 1,024 boundaries per block, and share the 131,072-entry bank bound;
  unbounded compiler output remains unsupported. Unsupported or oversized
  objects are counted as rejected but rejection details do not yet have a
  dedicated API endpoint.
- Interface index is currently zero in emitted events.
- Dynamic attachment can observe one packet on multiple interfaces; flow
  history aggregates identical logical keys but does not deduplicate one packet's
  interface-level observations.
- The portable Kubernetes DaemonSet remains privileged. The OpenShift overlay is
  non-privileged and constrained to `BPF`, `NET_ADMIN`, and `PERFMON`, but still
  requires root, `spc_t`, host networking/ports, and hostPath permission. SCC
  cannot restrict hostPath prefixes; native fail-closed admission now enforces
  the exact bpffs/BTF paths, mount modes, and agent-only ownership on OpenShift.
- Dual-stack kind and dual-stack OpenShift are separate verified fixtures for
  Linux 7.1 TCX and RHCOS Linux 5.14 legacy attachment respectively. Broader
  kernel, platform, scale, and upgrade combinations remain unqualified.

## Phase 3 work breakdown

| Deliverable | State | Exit evidence |
|---|---|---|
| NetworkPolicy ingress translator foundation | **Verified** | Unit tests cover allow/default isolation, omitted namespace-wide target/default ingress/default TCP, explicit omitted/empty source and port wildcards, pod/Namespace expressions, named and protocol-only TCP/UDP/SCTP ports, bounded numeric ranges, bounded IPv4/IPv6 blocks and exceptions, local/exact-namespace peers, and explicit unsupported-feature errors; `make kind-test` exercises each supported peer/port form |
| Additive compatibility semantics | **Verified** | Multiple selecting policies combine allows in the shared evaluator and lower through the shared dataplane compiler; the live adapter uses that same engine |
| NetworkPolicy controller watch and live enforcement | **Verified** | `make kind-test` covers reconciliation/status, explicit allow, isolation drop, revisioned provenance, rejection/removal/recovery, and deletion/recreation |
| Full ingress peer/port compatibility | **Verified** | Every bounded ingress peer/port form in the supported compatibility slice is covered by compiler/evaluator/lowering tests and live IPv4/IPv6 traffic: selector expressions and Boolean composition, omitted/empty wildcards and defaults, exact/protocol-only/named/ranged ports, TCP/UDP/SCTP isolation, bounded IPv4/IPv6 `ipBlock`, additive and replacement semantics, label lifecycle, and recovery. The pinned one-to-one upstream audit has no unclassified scenario; stateful established/related replies, unbounded output, and egress remain explicit boundaries outside this peer/port claim |
| Upstream-aligned ingress matrix | **Verified** | `hack/verify-networkpolicy-ingress.sh` maps supported upstream scenarios—including explicit empty source/port wildcards, multi-port OR, exact/protocol-only UDP isolation, multi-destination valid and nonexistent named ports, destination Pod match-label/expression isolation and recovery, overlapping target-selector additivity, remote target-specific exceptions over namespace-wide isolation, same-object policy replacement, empty/labeled same-Namespace PodSelectors, homogeneous multiple-PodSelector peer OR, multi-value Pod `In` with Namespace-name `NotIn`, exact Namespace-name selection, all four peer Pod/Namespace selector operators, multiple ingress rules, and source/Namespace-label recovery—to revision-converged cross-node/same-node IPv4 and IPv6 traffic plus explanation checks, then deletes its three exact test Namespaces and requires baseline policy counts; the stateful same-Namespace leg and other exclusions are recorded in `docs/development/networkpolicy-conformance.md` |
| One-to-one upstream ingress audit | **Verified** | Kubernetes commit `9aac5f741fa6095594cdfed4756a52cf0bf4b191` contributes 49 scenarios across its primary, UDP, and SCTP contexts. The authoritative audit classifies 35 as verified, 13 as unsupported because they require the planned egress milestone, and one target-exception scenario as intentionally excluded in full because its same-Namespace leg requires stateful return-flow tracking; there are no unclassified scenarios |
| IPv4 SCTP ingress dataplane | **Verified** | Protocol 132 is parsed, explained, simulated, accepted in telemetry, and lowered through exact/protocol-wildcard keys; `make kind-test` proves cross-node named allow, default drop, wildcard activation/removal, revisioned provenance, and enriched history |
| Resolved-identity IPv6 dataplane | **Verified** | Identity snapshot v2 and `IDENTITY_V6` distribute Pod identities; TCP/UDP/SCTP reuse family-neutral policy keys; topology v3 and flow export v2 carry IPv6. `make kind-test` requires dual-stack native/NetworkPolicy allow-drop, per-family map counts, provenance, and enriched IPv6 history |
| OpenShift dual-stack platform qualification | **Verified** | The adaptive `make openshift-test` gate requires dual-family Pod assignment, populated IPv4/IPv6 agent maps and authenticated snapshots, cross-worker allow/drop enforcement, retained per-family policy provenance, selected-worker convergence, Service CA/TokenReview transport, Enforcing SELinux, native Linux 5.14 legacy filters, and healthy operators whenever the cluster advertises an IPv6 cluster CIDR |
| Bounded IPv6 extension-header traversal | **Verified** | TC traverses at most six headers and 256 bytes, accepts Hop-by-Hop only first plus Routing, Destination Options, initial/atomic Fragment, and AH, and fails open for unsupported, malformed, non-initial, jumbogram, and over-limit packets. Shared parser unit tests cover every branch; `make ebpf` proves the verifier-safe build; `make kind-test` requires real Hop-by-Hop/Destination Options UDP allow and explicit-deny provenance |
| IPv4 `ipBlock` dataplane | **Verified** | Snapshot schema v3 carries exact/fallback source-IP decisions alongside IPv6 prefixes; `POLICY_IPV4` and `POLICY_RULES` stage under one bank/revision; unit tests cover CIDR validation/lowering and `make kind-test` covers allow, exception deny, recovery, provenance, and oversized-block rejection |
| IPv6 `ipBlock` dataplane | **Verified** | Snapshot schema v3 and policy ABI v2 add `POLICY_IPV6`; compact LPM keys combine exact destination/protocol/port/bank dimensions with source prefixes, `/128` Pod overrides, `/0` external isolation, and more-specific exceptions. Unit/ABI tests cover lowering and `make kind-test` proves exact allow, exception deny, and atomic recovery |
| Dataplane policy capacity safety | **Verified** | Shared lowering and agent snapshot validation cap identity, IPv4, and IPv6 transactional banks at 131,072 entries; IPv6 additionally limits one block to 1,024 CIDR boundaries, staging deletes stale inactive keys before insertions, and unit tests exercise bounds |
| Direction-aware policy IR and decisions | **Verified** | Shared ABI-stable ingress/egress direction, source-selected egress evaluation, cross-direction isolation, explicit decision serialization with legacy ingress defaults, and typed rejection at every ingress-only dataplane lowerer are covered by focused unit and workspace gates; ADR 0031 records the boundary |
| Egress NetworkPolicy compatibility | **In progress** | The direction-aware userspace IR/evaluator foundation is verified. `spec.egress` translation and `policyTypes` defaulting, destination peers/ports/`ipBlock`, source-side lowering and TC enforcement, simulation/status integration, dual-stack kind lifecycle/provenance/recovery, and OpenShift qualification remain open |
| Policy simulation foundation | **Verified** | Versioned read-only add/replace API and `unfctl policy simulate` compare current/proposed provenance over a bounded topology-derived matrix and retained flow history. Schema v3 adds optional inclusive last-received bounds, newest-first limits, matched/returned observation metadata, and explicit truncation while preserving the unfiltered request default. Unit tests prove exact/empty selection and no mutation; `make kind-test` proves recent weighted denial impact, bounded and empty-future windows, revision stability, and unchanged live forwarding |
| Better topology state | **Verified** | Topology schema v3 preserves selector intent, adds per-workload IPv6 addresses, and retains EndpointSlice-derived address/port, Pod target, Node/zone, and ready/serving/terminating backend state; unit tests prove normalization, idempotence, stale-state removal, and revision isolation, while `make kind-test` exercises dual-stack state and not-ready → ready → deleted backend transitions without policy-revision mutation |
| Historical flow export | **Verified** | Agent export schema v2, non-blocking 4,096-record channel, 2,048-key pending aggregation, 512-entry authenticated HTTPS batches, 4,096-key revisioned controller retention, dual-stack validation, and explicit drop/eviction accounting. Snapshot schema v3 adds inclusive last-received bounds, newest-first limits, query metadata, and bounded checkpoint/restoration metadata; checkpoint schema v1 preserves the newest 1,024 keys within 900,000 bytes. Unit tests cover query, restoration, validation, and drop baselines; `make kind-flow-history-retention-test` proves exact RBAC and restart continuity without agent replacement, and is included in `make kind-test` |

## Updating this tracker

Every phase-affecting change must update the relevant table in the same change.
Moving a row to **Verified** requires a repeatable command or test. Known gaps stay
visible here and in user-facing status output; planned work is never described as
implemented.
