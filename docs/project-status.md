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
| Phase 3 — compatibility and simulation | **In progress** | §103: NetworkPolicy adapter, simulation foundation, improved topology, and historical export | The supported ingress adapter, resolved-identity IPv6 dataplane, history-aware read-only policy simulation, EndpointSlice-aware topology schema v3, and bounded dual-stack historical export are live verified; broader compatibility remains open |
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
| Dual-stack cluster fixture | Both kindnet Pods stayed Ready with zero restarts through the complete verifier; `kind-up` applies the reproducible nftables compatibility setup and `make kind-test` gates CNI readiness at start and finish |
| Demo dataplane | On the dual-stack two-node fixture, native policy allowed TCP/8080 and explicitly denied open TCP/9090 over both IPv4 and IPv6; real UDP packets carrying Hop-by-Hop, Destination Options, and combined extension headers allowed 8087–8089 and explicitly denied 9097 with revisioned provenance. Selector-based NetworkPolicy allowed 8081 and default-denied open 9091 over both families. Existing shadow, range, dual-stack block/exception, omitted-default, SCTP, lifecycle, and upstream-aligned ingress scenarios also passed |
| Agent state | Two ready agents with BPF loaded; both converged on the same controller epoch and identity/policy revisions with 14 identity entries each (7 IPv4 + 7 IPv6), 151 active policy entries, and zero queued/dropped exports at capture |
| Controller state | Ready with 2 watched Nodes, 17 watched Pods, 8 watched Namespaces, 5 watched Services, 5 watched EndpointSlices, 15 admitted identities, 14 indexed non-host-network Pod IPs, one native policy, one accepted NetworkPolicy, zero rejected NetworkPolicies, 151 resolved identity/IPv4/IPv6 entries, zero reported telemetry drops, and freshness-aware acknowledgements proving both expected agents converged |
| Topology state | Schema v3 returned 2 ready Nodes, 17 placed workloads, 5 Services, and 7 dual-stack non-host-network workloads; the EndpointSlice readiness/deletion lifecycle passed without policy-revision mutation |
| Flow history | Schema v2 retained bounded IPv4, IPv6, and SCTP logical flows; direct IPv6 `frontend/client` → `backend/server` TCP/8080 was enriched with both workload references and exact addresses, while both agents reported zero export drops |
| Transactional policy update | The verifier switched enforce → shadow → enforce and exercised TCP/SCTP protocol-wildcard plus IPv4/IPv6 block mutations, requiring a higher revision and opposite bank on every agent for single-resource transitions; snapshot schema v3 stages all three policy maps before one activation write |
| Interruption recovery | With the controller scaled to zero, the active bank continued allowing 8080 and denying 9090; both agents then accepted the restarted controller epoch and reconverged |
| Dataplane provenance | ABI v2 TCP and SCTP events matched the applied revision and carried nonzero identities plus actual/shadow policy and explicit-deny rule provenance |
| NetworkPolicy lifecycle | Named port `allowed` resolved to TCP/8081; one `web` name resolved independently to TCP/8087 and TCP/8088 across two destination Pods while each opposite open port stayed denied; exact and protocol-only UDP rules allowed request/response traffic without broadening same-port TCP or non-matching peers, and deletion restored both protocols; the inclusive 8082–8083 range enforced both boundaries and excluded 8084; a protocol-only TCP entry allowed arbitrary TCP/9091 without allowing UDP/9091 and removal restored isolation; exact IPv4 and prefix IPv6 blocks allowed the client, nested exceptions denied it, and exception removal recovered; Namespace relabel removed/restored the allow without identity churn; oversized range/block updates removed stale state and recovered; deletion allowed 9091 and recreation restored the drop; omitted `podSelector`, `policyTypes`, and protocol produced namespace-wide/default-ingress/default-TCP behavior, while target narrowing restored non-isolated traffic; named SCTP and protocol-only SCTP rules enforced and reconverged across nodes |
| Upstream-aligned ingress matrix | A disposable three-Namespace matrix proved exact/protocol-only UDP peer and TCP isolation with deletion recovery, destination-specific named-port resolution across two server Pods, destination Pod-label selection/isolation/recovery, default deny, same-Namespace PodSelector scope, empty/exact-name NamespaceSelector selection, Namespace `NotIn` exclusion, selector AND, peer OR, Pod/Namespace `matchExpressions`, source-label deny/recovery, source/port pairing across multiple ingress rules, stacked per-source/per-port additive allows, allow-all precedence, truthful explanations, and cleanup to the baseline policy counts |
| Policy explanation | Native 8080/9090, compatibility exact/range/protocol-only TCP/UDP/SCTP ports, bounded block/exception transitions, and namespace-wide target/defaulting transitions reported the expected explicit/default/no-applicable-policy provenance with dataplane enforcement truthfully enabled |
| Policy simulation | Schema v2 evaluated 85 topology-derived flows and the bounded dual-stack history, predicted the TCP/8080 denial, reported `backend/server` affected, explicitly counted stale-identity history, left live policy state unchanged, and TCP/8080 remained allowed |

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
| Controller-aggregated node acknowledgements | **Verified** | Schema v1 agent reports are validated and timestamped; controller/CLI status distinguishes expected, missing, stale, unexpected, and converged agents, while `make kind-test` requires both watched Nodes to match current identity/policy epoch and revisions |
| Selector-to-identity policy lowering | **Verified** | Unit tests cover exact/default, shadow provenance, conflicts, and deterministic ordering; `make kind-test` requires nonzero resolved entries |
| Transactional policy map set | **Verified** | `make kind-test` stages a changed policy on the opposite bank, verifies a higher applied revision, restores it, and verifies reconvergence |
| TC identity lookup | **Verified** | Cross-node IPv4 and IPv6 demo flows carry nonzero source and destination IDs |
| L3/L4 policy decision | **Verified** | Exact/fallback active-bank lookup plus ABI v2 revision, verdict, reason, policy, rule, and shadow provenance |
| Enforcement | **Verified** | `make kind-test` proves IPv4/IPv6 8080 allow and open-port 9090 drop, shadow pass-through, and restored drop |
| Accurate live explanation | **Verified** | CLI actual decisions and IDs are checked while every traffic-path agent reports the active revision applied |
| Failure behavior | **In progress** | Last-known-good enforcement survived a controller interruption; pinned map recovery, agent restart fencing, and pressure/fault injection remain |

## Current limitations

- Enforcement currently covers resolved-identity IPv4/IPv6 TCP/UDP/SCTP exact
  and wildcard decisions. IPv6 traversal is limited to six headers and 256
  extension bytes: Hop-by-Hop (first only), Routing, Destination Options,
  initial/atomic Fragment, and AH are supported. Non-initial IPv4/IPv6
  fragments, IPv6 jumbograms, ESP/No Next Header, malformed or over-limit
  chains, and other protocols fail open.
- Identity and compiled policy desired state remain in-memory and their BPF maps
  are unpinned. Agent restart therefore has a resynchronization window where the
  overlay intentionally fails open.
- Unknown destination identities, missing/incompatible map config, invalid
  values, and absent identity/IP decisions fail open with revision-zero
  observed/identity-unknown provenance. Unknown source identities can be enforced
  by a valid exact or external-fallback IPv4 policy entry.
- Agent acknowledgements are freshness-aware and controller-aggregated, but use
  unauthenticated in-cluster HTTP and current-process storage. Reports older than
  ten seconds are marked stale; durable history and node authentication remain.
- Policy simulation currently accepts one native `SecurityPolicy`, uses current
  Pods plus representative policy-derived TCP/UDP/SCTP probes, and rejects matrices
  above 10,000 flows. It separately evaluates retained history and observation
  frequency, but has no time-window filtering, cannot evaluate external sources
  without a current identity, and accepts no user-supplied flow sets.
- Flow history is advisory, destination-resolved, current-process telemetry. Agent
  channels/pending state and controller retention are bounded with explicit drop
  and eviction counters, but history is not durable, authenticated, sampled, or
  deduplicated across interface-level observations.
- Topology schema v3 reports current in-memory Node, dual-stack Pod workload, Service intent,
  and EndpointSlice runtime relationships. Conditions are Kubernetes-reported
  state rather than active traffic health; topology history, filtering,
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
- The development DaemonSet is privileged; narrow capabilities and OpenShift SCC/
  SELinux validation remain required.
- kind verification is Kubernetes evidence, not an OpenShift support claim.

## Phase 3 work breakdown

| Deliverable | State | Exit evidence |
|---|---|---|
| NetworkPolicy ingress translator foundation | **Verified** | Unit tests cover allow/default isolation, omitted namespace-wide target/default ingress/default TCP, pod/Namespace expressions, named and protocol-only TCP/UDP/SCTP ports, bounded numeric ranges, bounded IPv4/IPv6 blocks and exceptions, wildcards, local/exact-namespace peers, and explicit unsupported-feature errors; `make kind-test` exercises each supported peer/port form |
| Additive compatibility semantics | **Verified** | Multiple selecting policies combine allows in the shared evaluator and lower through the shared dataplane compiler; the live adapter uses that same engine |
| NetworkPolicy controller watch and live enforcement | **Verified** | `make kind-test` covers reconciliation/status, explicit allow, isolation drop, revisioned provenance, rejection/removal/recovery, and deletion/recreation |
| Full ingress peer/port compatibility | **In progress** | Pod/Namespace expressions, namespace-wide omitted targets, implicit ingress policy type for egress-omitted objects, default TCP protocol, destination selection lifecycle and non-selected Pod behavior, destination-specific named and protocol-only TCP/UDP/SCTP ports with cross-protocol isolation, inclusive numeric ranges up to 1,024 ports, bounded IPv4 and IPv6 blocks with `except`, same/all/exact-Namespace peer scope, Namespace `NotIn` exclusion, selector AND, peer OR, multiple ingress rules with preserved source/port pairing, stacked additive allows, allow-all precedence, label-driven recovery, and resolved-identity IPv6 traffic are live verified; unbounded compiler output, egress, and remaining upstream conformance remain |
| Upstream-aligned ingress matrix | **Verified** | `hack/verify-networkpolicy-ingress.sh` maps supported upstream scenarios—including exact/protocol-only UDP isolation, multi-destination named ports, destination Pod-label isolation/recovery, exact Namespace-name selection, Namespace `NotIn` exclusion, Pod/Namespace `matchExpressions`, multiple ingress rules, and source-label recovery—to revision-converged cross-node/same-node traffic and explanation checks, then deletes its three exact test Namespaces and requires baseline policy counts; scope and exclusions are recorded in `docs/development/networkpolicy-conformance.md` |
| IPv4 SCTP ingress dataplane | **Verified** | Protocol 132 is parsed, explained, simulated, accepted in telemetry, and lowered through exact/protocol-wildcard keys; `make kind-test` proves cross-node named allow, default drop, wildcard activation/removal, revisioned provenance, and enriched history |
| Resolved-identity IPv6 dataplane | **Verified** | Identity snapshot v2 and `IDENTITY_V6` distribute Pod identities; TCP/UDP/SCTP reuse family-neutral policy keys; topology v3 and flow export v2 carry IPv6. `make kind-test` requires dual-stack native/NetworkPolicy allow-drop, per-family map counts, provenance, and enriched IPv6 history |
| Bounded IPv6 extension-header traversal | **Verified** | TC traverses at most six headers and 256 bytes, accepts Hop-by-Hop only first plus Routing, Destination Options, initial/atomic Fragment, and AH, and fails open for unsupported, malformed, non-initial, jumbogram, and over-limit packets. Shared parser unit tests cover every branch; `make ebpf` proves the verifier-safe build; `make kind-test` requires real Hop-by-Hop/Destination Options UDP allow and explicit-deny provenance |
| IPv4 `ipBlock` dataplane | **Verified** | Snapshot schema v3 carries exact/fallback source-IP decisions alongside IPv6 prefixes; `POLICY_IPV4` and `POLICY_RULES` stage under one bank/revision; unit tests cover CIDR validation/lowering and `make kind-test` covers allow, exception deny, recovery, provenance, and oversized-block rejection |
| IPv6 `ipBlock` dataplane | **Verified** | Snapshot schema v3 and policy ABI v2 add `POLICY_IPV6`; compact LPM keys combine exact destination/protocol/port/bank dimensions with source prefixes, `/128` Pod overrides, `/0` external isolation, and more-specific exceptions. Unit/ABI tests cover lowering and `make kind-test` proves exact allow, exception deny, and atomic recovery |
| Dataplane policy capacity safety | **Verified** | Shared lowering and agent snapshot validation cap identity, IPv4, and IPv6 transactional banks at 131,072 entries; IPv6 additionally limits one block to 1,024 CIDR boundaries, staging deletes stale inactive keys before insertions, and unit tests exercise bounds |
| Egress NetworkPolicy compatibility | **Planned** | Direction-aware IR and dataplane enforcement evidence |
| Policy simulation foundation | **Verified** | Versioned read-only add/replace API and `unfctl policy simulate` compare current/proposed provenance over a bounded topology-derived matrix and retained flow history; unit tests prove no state mutation and historical weighting, while `make kind-test` proves predicted deny, revision stability, and unchanged live forwarding |
| Better topology state | **Verified** | Topology schema v3 preserves selector intent, adds per-workload IPv6 addresses, and retains EndpointSlice-derived address/port, Pod target, Node/zone, and ready/serving/terminating backend state; unit tests prove normalization, idempotence, stale-state removal, and revision isolation, while `make kind-test` exercises dual-stack state and not-ready → ready → deleted backend transitions without policy-revision mutation |
| Historical flow export | **Verified** | Schema v2, non-blocking 4,096-record agent channel, 2,048-key pending aggregation, 512-entry HTTP batches, 4,096-key revisioned controller retention, dual-stack address validation, drop/eviction metrics, `unfctl flows`, and history-aware simulation; unit tests cover bounds/aggregation/eviction and `make kind-test` requires enriched IPv4 and IPv6 cross-node flows |

## Updating this tracker

Every phase-affecting change must update the relevant table in the same change.
Moving a row to **Verified** requires a repeatable command or test. Known gaps stay
visible here and in user-facing status output; planned work is never described as
implemented.
