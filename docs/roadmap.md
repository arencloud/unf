# Roadmap

Status is evidence-based: **implemented** means present and locally tested;
**prototype** means the path exists but is not yet connected to enforcement.

## Phase 1 — observation foundation

**Gate: verified.** See [project-status.md](project-status.md) for the acceptance
matrix and reproducible evidence.

- Implemented: workspace, typed IDs/ABI, SecurityPolicy API, policy IR/evaluator,
  unit/property tests, health/status/metrics surfaces, kube-rs watchers, and
  provisional identity resolution.
- Implemented and two-node kind verified: CRD/controller/DaemonSet deployment,
  Aya object loading, dynamic TC attachment, IPv4 flow ring-buffer events, and
  controller-backed shadow explanations with rule/default provenance.
- Known limitation: interface-level flow events are not yet deduplicated.

## Phase 2 — identity and policy enforcement

**Gate: verified.** The planned OpenShift hardening slice is complete.

- Implemented foundation: collision-checked identity admission, Pod-IP desired-
  state index, update/removal garbage collection, and controller status counts.
- Implemented and dual-stack two-node kind verified: versioned IPv4/IPv6 BPF identity maps,
  epoch/revision-based controller-to-agent snapshot distribution, enriched flow
  identities, and reconvergence after a controller epoch change;
- Implemented and two-node kind verified: selector-to-identity lowering,
  versioned dual-bank policy maps, atomic revision activation/restoration, and
  agent desired/applied policy status. Schema-versioned agent acknowledgements
  give the controller and CLI freshness-aware convergence for every watched Node;
- Implemented: active-bank TC lookup and IPv4/IPv6 TCP/UDP/SCTP allow/drop,
  including verifier-bounded IPv6 Hop-by-Hop, Routing, Destination Options,
  initial/atomic Fragment, and AH traversal. Dual-stack two-node kind verifies
  IPv6 TCP and real extension-header UDP allow/deny plus existing IPv4 TCP/SCTP
  scenarios, shadow pass-through, Flow ABI v2 actual/shadow provenance, and
  enforcement-aware `unfctl explain`;
- Verified manually: the last active bank continued enforcing across a controller
  interruption and agents reconverged to the restarted controller epoch;
- Implemented and two-node kind verified: ABI-versioned pinned enforcement maps,
  strict recovery validation, and readiness fencing; the verifier restarts a
  node agent with the controller offline before checking allow/deny state;
- Implemented and two-node kind verified: transactional dual-bank IPv4/IPv6
  identity staging, read-back validation, single-write activation, rollback, and
  offline-controller restart recovery through the ABI v3 eleven-map pin set;
- Implemented and two-node kind verified on Linux 7.1: per-interface pinned TCX
  links, atomic replacement-program handoff, and continuous deny enforcement
  while an offline-controller agent is replaced. The same gate explicitly selects
  the stable-priority/handle legacy netlink path, removes TCX coverage, proves
  in-place replacement with continuous deny enforcement, and safely restores TCX
  before scoped legacy cleanup. Native automatic legacy selection, reserved
  filters, BTF/bpffs access, SCC admission, enforcing SELinux, and IPv4
  enforcement are also verified on OpenShift 4.22/RHCOS 9.8 kernel 5.14;
- Implemented and two-node kind verified: isolated live-kernel fault sets prove
  ten-of-eleven pins, malformed active policy config, and corrupt inactive-bank
  debris are rejected with actionable errors while primary allow/deny state
  remains unchanged; permanent dataplane startup failure exits for orchestrator
  retry;
- Implemented and two-node kind verified: deterministic reserved-key pressure
  fills the shared physical `POLICY_RULES` map with inactive-bank keys, forces a
  real kernel staging failure, and proves rollback preserves the active
  revision/bank and traffic; after scoped cleanup, the waiting revision activates
  and enforcement restores;
- Implemented and two-node kind verified: dry-run-first host-state cleanup removes
  only recognized ABI v1/v2/v3 map pins, TCX link pins, and UNF-named legacy filters;
  unknown ABI content is refused, current v3 requires explicit confirmation, and
  live cleanup preserves the active v3 map set and restores TCX before removing
  legacy filters;
- Implemented and two-node kind verified: acknowledgement schema v2 uses a
  dedicated-audience projected service-account token, Kubernetes TokenReview,
  Pod name/UID binding, and watched Node placement. Anonymous, invalid-token, and
  valid-token/cross-Node claims fail closed without changing convergence state;
- Implemented and two-node kind verified: agent-only state, acknowledgement, and
  telemetry routes use a separate TLS Service port, agents trust only the mounted
  UNF CA, and every request uses Pod-bound TokenReview identity. Plaintext route
  isolation, CA failure, credential failure, and live convergence/export are gated;
- Implemented and OpenShift IPv4/dual-stack verified: a worker-scoped overlay uses
  `restricted-v2` for the controller and a dedicated constrained agent SCC. The
  agent is non-privileged, cannot use the built-in privileged SCC, drops all but
  `BPF`, `NET_ADMIN`, and `PERFMON`, and requires runtime-default seccomp,
  `NoNewPrivs`, and a read-only root filesystem. Service CA injection, exact
  worker convergence, Pod-bound TokenReview, populated per-family identities,
  and cross-worker IPv4/IPv6 policy provenance are gated;
- Implemented and OpenShift verified: controller serving keypairs and agent CA
  bundles reload without Pod replacement. Content-based detection handles atomic
  projected-volume swaps; malformed updates retain last-known-good material. A
  repeatable gate proves overlapping-root external-PKI rotation, authenticated
  traffic under the new issuer, malformed leaf/CA rejection, and restoration to
  OpenShift Service CA ownership with unchanged Pod UIDs;
- Implemented and OpenShift verified: authenticated agent reports are retained in
  a schema-versioned, 1,024-entry ConfigMap checkpoint with exact-name RBAC and
  coalesced two-second writes. Startup validates and restores the checkpoint
  before watchers begin, but the new controller epoch keeps restored reports
  non-converged until agents acknowledge current desired state. A restart gate
  proves both reports restore, reconverge, and advance without agent replacement;
- Implemented and OpenShift verified: native fail-closed admission validates the
  agent DaemonSet before rollout plus direct/generated Pods and ephemeral updates.
  Only the exact existing `/sys/fs/bpf` and `/sys/kernel/btf` directories are
  admitted, with writable bpffs, read-only BTF, no subpaths/propagation, and no
  sidecar/init/ephemeral access. The focused negative gate is also part of the
  complete dual-stack qualification;
- Implemented and OpenShift verified: coordinated uninstall is dry-run-first,
  requires exact context confirmation, stops every agent before host mutation,
  runs one SCC/admission-constrained cleanup Job per selected worker, verifies
  v2 pins and UNF filters are absent, then removes namespaced and exact
  cluster-scoped resources. The CRD is preserved by default. A disruptive gate
  proves clean two-node uninstall, CRD UID preservation, redeploy, and complete
  dual-stack recovery.

## Phase 3 — compatibility and simulation

**Gate: verified.**

- Implemented and two-node kind verified: supported ingress `NetworkPolicy`
  translation, additive semantics, controller reconciliation/status, shared
  dataplane enforcement/provenance, pod/Namespace label-expression selectors,
  explicit empty `from`/`ports` wildcard semantics, multi-port OR without
  protocol broadening, empty same-Namespace peer PodSelectors,
  destination-aware named-port lowering, namespace relabel convergence without
  identity churn, protocol-only TCP/UDP/SCTP wildcard lowering, bounded numeric
  `endPort` ranges with map-capacity guards, bounded IPv4 exact-source and IPv6
  LPM `ipBlock`/`except` enforcement with atomic three-map activation, namespace-wide
  targets from omitted `podSelector`, implicit ingress `policyTypes` for
  egress-omitted objects, default TCP ports, and non-selected Pod behavior, plus
  rejection/deletion recovery; IPv4 SCTP parsing/enforcement, live explanation,
  revisioned provenance, and historical export; an upstream-aligned live ingress
  matrix for default deny, same/all/exact-Namespace peers, Namespace `NotIn`
  exclusion, all four Pod/Namespace selector operators, selector AND,
  multi-value Pod `In` with Namespace-name `NotIn`, homogeneous
  multiple-PodSelector and heterogeneous peer OR,
  explicit empty source/port lists, multi-port OR,
  multiple ingress-rule source/port pairing,
  exact/protocol-only UDP isolation, destination-specific named ports and
  nonexistent named-port fail-closed behavior,
  destination match-label and all-four-expression-operator selection lifecycle,
  broad/narrow overlapping destination-selector additivity and ordered recovery,
  remote and stateful same-Namespace target-specific allow over namespace-wide
  default deny with combined empty peer selectors and established provenance,
  same-object allow-all/default-deny policy replacement and rollback,
  source-label recovery, stacked additive policies, and allow-all precedence/recovery,
  all against direct IPv4 and IPv6 Pod addresses;
  revision-fenced, read-only native policy simulation over a bounded
  current-topology probe matrix; versioned Node,
  workload-placement, Service, and selector-membership topology snapshots;
  EndpointSlice-backed runtime relationships with readiness, serving,
  termination, Node/zone, Pod target, address, and port provenance;
  destination-resolved agent flow export through bounded non-blocking queues,
  revisioned 4,096-key controller history, bounded ConfigMap restart recovery,
  last-received-time queries and newest-first limits through `unfctl flows`, and
  observation-weighted historical simulation impact with matching absolute or
  relative last-received windows and newest-first limits; resolved-identity IPv6
  distribution, enforcement, provenance, topology schema v3, and flow-export
  schema v2; bounded IPv6 extension-header traversal with real packet fixtures;
  separate dual-stack OpenShift cross-worker enforcement and history evidence on
  RHCOS Linux 5.14 under Enforcing SELinux;
- Completed: a one-to-one audit pinned to Kubernetes commit
  `9aac5f741fa6095594cdfed4756a52cf0bf4b191` classifies all 49 primary/UDP/SCTP
  scenarios as verified through shared unit evidence and the complete ingress and
  focused egress gates, with no unclassified or excluded bounded L4 scenario;
- Implemented and unit verified: ABI-stable direction-aware policy IR and
  decisions, destination-selected ingress/source-selected egress evaluation,
  cross-direction isolation, backward-compatible ingress deserialization, and
  fail-closed rejection of egress IR by the existing ingress-only dataplane
  lowerers;
- Implemented and unit verified: independent `spec.egress` IR, Kubernetes
  implicit/explicit `policyTypes` defaulting, source-targeted `to` peer/port
  translation, and a controller admission test proving egress remains outside
  ingress-only snapshots;
- Implemented and unit verified: bounded IPv4/IPv6 egress `ipBlock` translation
  and destination-address evaluation, including exceptions and fail-closed
  absent/mixed-family input;
- Implemented and unit verified: source-selected exact-destination IPv4 and
  destination-prefix IPv6 lowering, including selector/named-port metadata,
  isolation fallbacks, exception behavior, capacity limits, and strict
  direction separation;
- Implemented and rebuilt-kind verified: snapshot schema v4 and
  policy ABI v3 stage dedicated IPv4/IPv6 egress maps in the same validated,
  rollback-safe inactive-bank transaction as ingress;
- Implemented and rebuilt-kind verifier-qualified: source-selected IPv4/IPv6 TC
  egress lookup, ingress/egress deny composition, and policy-direction event
  provenance;
- Implemented and two-node kind verified: controller distribution of independent
  ingress/egress IR into one transactional snapshot plus a self-cleaning
  dual-stack egress matrix covering selected-source default isolation,
  non-selected pass-through, Namespace/Pod selector AND, named TCP/UDP,
  protocol-only SCTP, bounded IPv4/IPv6 `ipBlock` exceptions, direction-correct
  provenance, policy deletion recovery, and baseline reconvergence;
- Implemented and two-node kind verified: direction- and address-family-aware
  `unfctl explain` for egress selector/default/`ipBlock` decisions, plus separate
  resolved ingress/egress entry counts in controller status;
- Implemented and two-node kind verified: direction-aware flow export schema v3,
  history schema v4, legacy-ingress checkpoint migration to schema v2, external
  egress selected-identity validation, and direction-correct historical
  evaluation;
- Implemented and two-node kind verified: read-only `NetworkPolicy` add/replace
  simulation with source-selected dual-stack egress topology, retained-history
  impact, direction/address reporting, and revision/forwarding immutability;
- Implemented and two-node kind verified: source-node agent replacement with the
  controller offline retains populated IPv4/IPv6 egress maps, the exact policy
  revision, and direct-Pod allow/deny forwarding before clean reconvergence;
- Implemented and two-node kind verified: bounded, revision-scoped TCP/UDP/SCTP
  reply state, including the formerly excluded same-Namespace target-exception
  path over both address families and explicit established provenance;
- Completed on dual-stack OpenShift: source-selected egress and stateful replies,
  including OVN host-network gateway identity, same-node router replies, named
  TCP/UDP, protocol-only SCTP, bounded IPv4/global IPv6 `ipBlock` exceptions,
  explanation, history, simulation, deletion recovery, and operator health;
- Implemented and two-node Kind verified: observation-weighted live shadow
  rollout reporting plus schema-validated offline analysis of saved bounded flow
  history, including controller-independent JSON/YAML/table output, affected
  workloads, shadow policy IDs, and per-flow provenance;
- Implemented and two-node Kind verified: bounded, durable full-snapshot
  topology history with inclusive time/revision queries, newest-first limits,
  watcher-replay coalescing, exact ConfigMap RBAC, and restart fencing;
- Implemented and two-node Kind verified: optional external HTTP flow export
  with a versioned epoch/sequence/topology envelope, HTTPS and private-CA trust,
  rotating token-file authentication, bounded non-blocking queue, at-least-once
  retry, exact queue capacity/depth/high-water telemetry, explicit delivery/loss
  metrics, concurrent publication ordering, receiver-outage recovery, and
  sustained slow-receiver saturation without interrupting authenticated
  ingestion or local history;
- Implemented and two-node Kind verified: observable adjacent-version
  controller-first upgrades with an explicit persistent-BPF/wire-schema tuple,
  deterministic mixed-agent rollout, authenticated reconvergence, continuous
  forwarding/telemetry, and reversible agent/controller rollback;
- Implemented and two-node Kind verified for one exact window: a strict
  two-commit same-tuple skipped upgrade requires version metadata from every N
  and N+2 component, then repeats controller-first mixed rollout, agent and
  controller downgrade/forward recovery, forwarding, and telemetry checks;
- Implemented and two-node Kind verified: deliberately incompatible persistent
  ABI and policy-schema images fail before persistent-map access or policy-bank
  mutation, retain canonical pinned-state digests and continuous enforcement,
  expose actionable errors/counters, and recover to the current tuple;
- Implemented and bounded two-node Kind verified: deterministic 24-workload
  ingress/egress scale generation, measured Namespace/Pod/policy churn,
  simultaneous two-agent pinned-state recovery with the controller offline,
  continuous dual-stack forwarding, bounded queue/error behavior, exact cleanup,
  and schema-versioned environment/provenance evidence;
- Completed and two-node Kind verified: status, controller aggregation, metrics,
  and logs classify compatible rollback, blocked rollback, and recovery while a
  bounded fail-closed window preserves rejection visibility before retry;
- Completed on dual-stack OpenShift cl02: six immutable N/N+1 development
  artifacts, full endpoint platform gates, controller-first and worker-serial
  rollout, complete rollback/forward recovery, sustained dual-stack policy
  enforcement, provenance/telemetry continuity, and healthy operators;
- Completed on an isolated two-node Kind fixture: Kubernetes 1.34.8 on Debian
  13/containerd 2.3.1 independently passed full dual-stack endpoint/recovery,
  TCX and legacy attachment, and adjacent-revision upgrade/rollback, creating a
  fourth exact support-matrix row alongside Kubernetes 1.35 and OpenShift 4.22.

Phase 3 is closed by the committed-revision regression, one-to-one requirements
and limitations audit, and immutable release-readiness evidence in ADR 0056.
Full CNI/IPAM, routing, service load balancing, encryption, L7, and multi-cluster
transport remain gated or planned after these foundations. Additional external
transport adapters remain conditional on product requirements.

The ordered milestones and their evidence-bearing subpoints are maintained in
[the Phase 3 completion and full-CNI entry plan](development/phase3-completion-plan.md).
That matrix is the working checklist; `project-status.md` remains the
authoritative record of verified results.

## Full-CNI foundation

**Gate: in progress.**

- Architecture and ownership are accepted in ADR 0057: the current overlay is
  unchanged, primary ownership is opt-in and Kind-first, durable attachment/IPAM
  state belongs to the local agent, and cutover/rollback requires node drain.
- The initial Rust `unf-cni` executable implements bounded CNI 1.0/1.1 request
  validation and VERSION behavior. ADD/CHECK/STATUS remain explicitly unavailable
  until IPAM and link operations are connected through the versioned local API.
- The opt-in local agent transaction service now enforces kernel UID-0 peer
  authentication and schema-v1 64-KiB messages. Its atomic mode-0600 journal
  durably reloads deterministic preparing/ready/aborting/deleting attachment
  records and rejects conflicting or invalid replays; ADR 0058.
- Next: dual-stack node-block IPAM, then connect ADD/DEL/CHECK to veth lifecycle,
  native routing/MTU, and cross-node Kind qualification.
- Netkit, OpenShift primary-CNI installation, service load balancing,
  kube-proxy replacement, BGP, encryption, L7, and multi-cluster remain outside
  this foundation slice.
