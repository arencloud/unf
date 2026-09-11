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
- Implemented with the original two paths OpenShift verified: native fail-closed
  admission validates the agent DaemonSet before rollout plus direct/generated
  Pods and ephemeral updates. Writable bpffs, read-only BTF, no
  subpaths/propagation, and no sidecar/init/ephemeral access were live-qualified.
  Phase 4.3 adds the exact `/var/lib/unf/cni` durable-state path under the same
  rules and renders it statically; Phase 4.8 live-qualified that additive path
  through controller-offline agent replacement on five OpenShift Nodes;
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
- Implemented and expanded primary-CNI Kind verified: bounded TCP/UDP/SCTP
  reply state survives unrelated policy revision churn, primary mode observes
  both TC directions for translated tuples through one authoritative ingress
  enforcement point and a supplemental egress state-seeding point, exact Node
  traffic exceptions scale linearly, and replies retain explicit established
  provenance; ADR 0070 records the refined boundary;
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
  fourth exact support-matrix row alongside Kubernetes 1.35 and OpenShift 4.22;
- Completed on the five-node dual-stack cl02 fixture: OpenShift 4.22.10 with UNF
  as the installer-time primary CNI passed bootstrap, clean reboot, deliberate
  CRI-O cache-loss recovery, exact worker teardown/no-CNI failure, and clean
  worker reprovision, creating a fifth non-transitive support-matrix row.

Phase 3 is closed by the committed-revision regression, one-to-one requirements
and limitations audit, and immutable release-readiness evidence in ADR 0056.
Advanced Service modes, routing providers, encryption, L7, and multi-cluster
transport remain gated or planned. Additional external
transport adapters remain conditional on product requirements.

The ordered milestones and their evidence-bearing subpoints are maintained in
[the Phase 3 completion and full-CNI entry plan](development/phase3-completion-plan.md).
That matrix is the working checklist; `project-status.md` remains the
authoritative record of verified results.

## Full-CNI foundation

**Gate: Verified for the bounded foundation scope.**

- Architecture and ownership are accepted in ADR 0057: the current overlay is
  unchanged, primary ownership is opt-in and Kind-first, durable attachment/IPAM
  state belongs to the local agent, and cutover/rollback requires node drain.
- The Rust `unf-cni` executable implements bounded CNI 1.0/1.1 request handling
  and a one-request local-agent client. Atomic ADD prepares durable allocation,
  applies and reads back links/routes, then commits; CHECK validates prevResult
  and exact durable/kernel state; route-first DEL retains its lease until cleanup
  completes. Restart and conflict recovery are Verified by ADR 0063.
- The opt-in local agent transaction service now enforces kernel UID-0 peer
  authentication and schema-v2 64-KiB messages. Its atomic mode-0600 journal
  durably reloads deterministic preparing/ready/aborting/deleting attachment and
  lease records and rejects conflicting or invalid replays; ADRs 0058 and 0060.
- The first `unf-ipam` provider now validates canonical dual-stack node blocks
  and returns one deterministic, bounded, collision-checked lease without owning
  routing or Kubernetes state. Exhaustion and release/reuse are verified; ADR
  0059.
- Schema-v2 attachment records now allocate a complete lease on prepare, retain
  it through cleanup intent and restart, and release it only on completed cleanup.
  Schema-v1 state migrates atomically and exact node-block provenance prevents
  silent configuration drift; ADR 0060.
- The `unf-link` primitive derives exact ownership from the durable record and
  uses typed netlink plus a disposable namespace thread to create, move,
  configure, recover, read back, and exactly delete a dual-stack veth. The real
  namespace gate also proves foreign-link preservation; ADR 0061.
- Native routing now has a provider boundary and deterministic dual-stack IR:
  routed `/32` and `/128` workload addresses, exact host endpoint routes,
  explicit container gateway/default routes, permanent MAC-bound neighbors, and
  zero-overhead MTU derivation; ADR 0062. Typed kernel apply/readback/delete,
  scoped rollback, conflict preservation, isolated IPv4/IPv6 forwarding, exact
  MTU boundaries, source-fragment behavior, and MTU drift rejection are
  Verified.
- Controller node-block distribution is now Verified by ADR 0064. Only Nodes
  explicitly labeled `network.unf.io/primary-cni=enabled` receive their own
  authenticated, revisioned IPv4+IPv6 `spec.podCIDRs` snapshot. Overlaps and
  malformed assignments fail closed; agents validate durable provenance,
  persist mode-0600 state, and acknowledge desired/applied revisions.
- Provider-neutral remote Node/block intent and native lowering are Verified by
  ADR 0065. The typed kernel lifecycle supports independent IPv4/IPv6 next hops,
  deterministic bounded planning, replay/readback/repair, scoped rollback,
  exact cleanup, and foreign-route preservation. The current-product design
  inputs are tracked in the [competitive routing evaluation](development/competitive-routing-evaluation.md).
- Complete cross-node reconciliation is Verified by ADR 0066. The authenticated
  schema-v1 snapshot binds controller epoch/global routing revision to local and
  remote Node/block provenance plus exact dual-stack `InternalIP` transports.
  Explicit per-family native uplinks, owner-only last-known-good restore,
  atomic route-set replacement, stale retirement, persistence rollback, and
  desired/applied/error acknowledgement are covered by
  `make cni-route-reconciliation-test`.
- The complete primary-CNI path is now Verified in a separate disposable
  three-Node dual-stack Kind cluster, including two-worker lifecycle,
  coexistence refusal/recovery, outage restart, and exact rollback; ADR 0067.
- The OpenShift installation boundary and candidate audit are Verified by ADR
  0068. The audited cl02 is a healthy OVN installation and is intentionally
  rejected: OpenShift custom-CNI qualification requires a new disposable
  `networkType: None` cluster, not an unsafe post-install provider conversion.
- ADR 0069 now verifies the reinstall and activation package: DNS-independent
  controller bootstrap, immutable development images, forwarding
  MachineConfigs, exact SCC/admission/host paths, socket-fenced installation,
  and replay/foreign/drift fixtures. The five-Node cl02 reinstall, operator
  closure, zero-workaround dual-stack traffic, terminal same-IP reuse, and
  controller-outage recovery now pass.
- ADR 0071 adds bounded CNI 1.1 valid-attachment GC after cl02 reboot evidence
  found 26 journal records whose pre-reboot sandboxes had vanished. Local
  privileged verification passes, including continue-on-error cleanup with
  conflicted leases retained. Immutable cl02 rollout, exact stale-state
  reconciliation is live-verified across all five Nodes. The following clean
  reboot exposed CRI-O issuing DEL before the agent socket existed and then
  discarding its cache. ADR 0072 adds a durable exact deferred-delete queue that
  fences later ADD/CHECK/GC work. Its digest-pinned rollout and second clean
  reboot now pass with ten early DELs drained before replacement ADDs and exact
  five-Node state restored without manual GC. A committed self-cleaning fault
  gate now also verifies CHECK, socket-offline CRI-O DEL, exact deferred
  ownership, recovery ADD ordering, dual-stack lease reuse, zero-leak cleanup,
  and 5/5 reconvergence. ADR 0073 and the committed node-reprovision gate now
  additionally prove exact CRI-O drain before agent stop, route/BPF/artifact
  teardown, a genuine no-CNI sandbox failure, host-network reinstall from zero,
  exact recovered state, platform health, and dual-stack forwarding.
- Netkit, Service handling beyond the separately qualified Phase 4 ClusterIP
  contract, BGP, encryption, L7, and multi-cluster remain outside this
  foundation slice.

## Phase 4 — service-fabric foundation

**Gate: Verified for the bounded ClusterIP foundation.** The ordered evidence
matrix is maintained in the
[Phase 4 service-fabric plan](development/phase4-service-fabric-plan.md).

- Implemented and locally verified: strongly typed `ServiceId` and `BackendId`;
  a Kubernetes-independent schema-v1 service snapshot; bounded service,
  frontend, backend, and per-service cardinalities; strict epoch/revision,
  protocol, address, port, provenance, and uniqueness validation; deterministic
  normalization; deterministic Kubernetes Service/EndpointSlice compilation;
  stable collision-checked IDs; exact family/name/protocol/port and appProtocol
  provenance; lifecycle retention; ambiguous-source rejection; controller
  last-valid retention; and truthful status. `make service-compiler-test`; ADRs
  0074–0075. Authenticated internal-TLS distribution, service-schema
  compatibility fencing, bounded polling, atomic mode-0600 agent persistence,
  restart/outage recovery, desired/applied/failed state, metrics, and controller
  convergence are also verified by `make service-distribution-test` and ADR 0076.
- Implemented and locally/kernel verified: ADR 0077 accepts the source-side
  Pod-veth TC hook, reverse path, and bounded persistent flow-state contract;
  ABI v4 adds fixed dual-stack frontend/backend/slot/config tables and the
  reserved connection LRU. The agent capacity-checks before mutation, stages and
  reads back every inactive table, atomically activates, couples the durable
  checkpoint to config/map rollback, exactly recovers, and garbage-collects the
  old bank. `make service-dataplane-test` includes a real-kernel partial/capacity
  failure with exact active-bank preservation.
- Implemented and verifier/kernel-execution verified: ADR 0078 adds exact
  IPv4/IPv6 TCP/UDP frontend lookup, deterministic ready/non-terminating backend
  selection, DNAT and checksum repair, reverse-key-first paired state and SNAT,
  revision-independent persistence, protocol expiry/reselection, and fail-closed
  exact backendless behavior. The privileged packet gate checks all four
  family/protocol combinations and reads fixed provenance from the real map.
- Verified by `make service-operations-test`: fixed translation/failure events,
  bounded metrics and status, retained history, and service explanation.
- Verified by `make service-kind-test`: a dedicated three-node Kubernetes 1.35
  dual-stack primary-CNI fixture with kube-proxy absent proves native TCP/UDP
  ClusterIP on both families, DNS and endpoint lifecycle, controller-offline
  worker-agent replacement, durable/pinned recovery, exact cleanup, and
  restoration to the no-CNI baseline; ADR 0080.
- Verified by `make openshift-service-deploy` and
  `make openshift-service-test`: the exact digest-pinned candidate recovered a
  preserved legacy checkpoint, moved five cl02 agents serially to ABI v4, then
  removed kube-proxy and proved the complete dual-stack ClusterIP lifecycle,
  controller-offline source/destination agent replacement, observability,
  exact cleanup, and operator-health boundary on RHCOS/SELinux/CRI-O; ADR 0081.
- Subsequent service slices: Phase 5 now independently verifies NodePort and
  `externalTrafficPolicy`; LoadBalancer, session affinity,
  `internalTrafficPolicy`, topology-aware routing, Maglev, and optional DSR
  remain separate. None is implied by the Phase 4 foundation gate.

## Phase 5 — NodePort exposure

**Gate: Verified.** The ordered evidence matrix is maintained in the
[Phase 5 NodePort plan](development/phase5-nodeport-plan.md).

- Verified by `make service-ir-test` and focused controller tests: service
  snapshot schema v2 carries deterministic address-family-aware NodePort intent,
  exact Service-port/backend linkage, and explicit `Cluster`/`Local` external
  traffic policy. Duplicate port/protocol ownership, inexact links, unknown
  policy, and silent ClusterIP-only dataplane lowering fail closed; ADR 0082.
- Verified by `make service-distribution-test`: explicit v1/v2 negotiation,
  all four old/new controller-agent pairings, read-time v1 migration with
  rollback-safe v1 persistence, and capability-aware convergence fencing keep
  NodePort intent away from legacy consumers; ADR 0083.
- Verified by `make nodeport-host-state-test`: Pod-bound TokenReview scope,
  independently revisioned local Node address intent, last-valid/relist
  behavior, and a fixed dual-stack two-bank compiler ABI establish the bounded
  host-state contract without exposing an uncommitted map; ADR 0084.
- Verified by `make nodeport-transaction-test`: persistent ABI v5 separates the
  21-map runtime from historical 18-map v4 state; composite checkpoints,
  independent service/NodePort banks, real-map failure injection, address-only
  switching, dual-pointer crash repair, and scoped cleanup pass; ADR 0085.
- Verified by `make nodeport-cluster-dataplane-test`: exact coherent NodePort
  lookups perform dual-stack TCP/UDP `Cluster` DNAT/reverse SNAT, retain
  connection selection across churn, preserve checksums/provenance, and apply
  ingress policy to the translated backend tuple; `Local` cannot broaden to
  Cluster; ADR 0086.
- Verified by `make nodeport-local-dataplane-test`: disjoint node-scoped slots
  admit only ready non-terminating backends placed on the receiving Node; Local
  preserves the external source and proves exact reverse translation,
  no-local-backend behavior, placement/readiness churn, recovery, and policy
  ordering; ADR 0087. LoadBalancer health-check NodePorts remain separate.
- Verified by `make nodeport-operations-test`: service-event ABI v2 adds an
  explicit fixed-width ClusterIP/NodePort-Cluster/NodePort-Local dimension;
  label-free metrics, agent-status schema v5, flow-export schema v5, history
  schema v6/checkpoint v5, filtered explanation, and read-only exact-Node
  simulation retain bounded evidence across churn and restart; ADR 0088.
- Verified by `make nodeport-kind-test`: runtime/qualification revision
  `bc03d5c` passed the 820-second three-Node Kubernetes v1.35.0 dual-stack gate
  with kube-proxy absent, all-node host-origin ClusterIP, both NodePort traffic
  policies, lifecycle, offline recovery, cleanup, and exact rollback.
- Verified by guarded `make nodeport-openshift-deploy` and
  `make nodeport-openshift-test`: runtime revision `bc03d5c`, qualifier
  `76828c3`, and three immutable public image digests passed the 3,803-second
  five-Node OpenShift 4.22.10 cl02 gate with exact cleanup and no new unhealthy
  ClusterOperator beyond baseline disconnected `insights`; ADR 0092.
- LoadBalancer, session affinity, topology-aware selection, Maglev, and DSR
  remain separate future milestones.

## Phase 6 — LoadBalancer exposure

**Gate: Verified.** The ordered evidence matrix is maintained in the
[Phase 6 LoadBalancer plan](development/phase6-loadbalancer-plan.md).

- Verified architecture boundary: ADR 0093 separates VIP allocation,
  advertisement, and eBPF translation into independently revisioned ownership
  domains. Default admission requires the explicit
  `network.unf.io/load-balancer` class, and Kubernetes status cannot promise a
  VIP before reachability plus dataplane convergence.
- Verified domain/compiler boundary: schema v3 carries bounded dual-stack
  requested-VIP/frontend/class/family/policy/source-range intent with exact
  backend linkage, safe v2/v1 projections, retained-last-valid Kubernetes
  compilation, and explicit rejection by pre-VIP lowerers; ADR 0094.
- Verified allocation/provider contract: deterministic conflict-safe dual-stack
  leases, exact pool/provider/Service provenance, complete revisioned
  direct-Node reachability and acknowledgements, fail-closed finalizer/status
  ordering, recovery/withdrawal, and foreign-state preservation; ADR 0095.
- Verified compatible distribution and transactional host state: explicit
  negotiation, durable allocation production, authenticated per-Node intent,
  capability-aware convergence, and independent ABI-v6 inactive-bank
  activation/recovery pass `make loadbalancer-host-state-test`; ADR 0096.
- Verified `externalTrafficPolicy: Cluster` dataplane: coherent independently
  banked VIP state drives dual-stack TCP/UDP translation, bounded
  collision-safe VIP source translation and reverse restoration, established
  flow retention, backendless drop, ingress-policy ordering, and fresh-flow
  withdrawal. The verifier-loaded release object retains full NodePort and
  ClusterIP behavior under `make loadbalancer-cluster-dataplane-test`; ADR 0097.
- Verified `externalTrafficPolicy: Local`, source ranges, and health: exact
  receiving-Node slots preserve client source, fail closed without a local
  ready endpoint, enforce revision-bound dual-stack CIDRs, reconstruct runtime
  tries from durable state, and serve placement-sensitive dual-stack
  `healthCheckNodePort` 200/503 responses. The inherited Cluster, NodePort, and
  ClusterIP regressions pass `make loadbalancer-local-dataplane-test`; ADR 0098.
- Verified operations, simulation, upgrade, and recovery: fixed-cardinality
  metrics, validated status, durable Cluster/Local history, exact
  allocation/provider/reachability explanation, source-aware read-only VIP
  simulation, durable provider replay, agent reconstruction, and adjacent
  compatibility pass `make loadbalancer-operations-test`; ADR 0099.
- Verified kube-proxy-free Kind qualification: runtime/qualifier `830771c`
  re-passed the 280-second three-Node Kubernetes v1.35.0 dual-stack
  external-client matrix, controller/provider/agent recovery, exact ABI-v7/CNI
  cleanup, and no-CNI rollback; `make loadbalancer-kind-test`; ADR 0100.
- Verified OpenShift qualification: runtime `830771c`, qualifier `ade286b`, and
  three immutable public Quay digests passed guarded deployment plus the
  973-second five-Node OpenShift 4.22.10 cl02 gate. Kube-proxy-free
  RHCOS/SELinux/CRI-O, workstation cross-worker dual-stack Cluster/Local VIPs,
  source semantics, lifecycle, operations, provider/controller/agent recovery,
  ABI-v7 reconstruction, exact cleanup, final convergence, and unchanged
  baseline/final unhealthy operators passed; ADR 0101.
- Production BGP/cloud takeover, session affinity, internal traffic policy,
  topology-aware selection, Maglev, DSR, SCTP, Gateway API, multi-cluster, and
  production availability/scale remain independent future gates.

## Phase 7 — advanced Service selection

**Gate: verified.** The ordered evidence matrix is maintained in the
[Phase 7 service-selection plan](development/phase7-service-selection-plan.md).

- Verified architecture boundary: strict `Local` eligibility takes precedence
  over topology preferences; `ClientIP` affinity can reuse only a currently
  eligible backend; connection persistence remains separately revisioned.
- Verified schema/compiler boundary: schema v4 normalizes internal policy,
  ClientIP timeout, topology preference, algorithm, and forwarding mode;
  Kubernetes defaulting, v1/v2/v3 migration/projection, legacy fencing, and
  explicit pre-transaction lowerer rejection pass
  `make service-selection-ir-test`; ADR 0103.
- Verified Network Behavior Contract boundary: canonical schema-v1 per-Node
  plans bind source/topology/contract revisions, exact intent, strict-policy-first
  eligibility, backend placement, and advertised capabilities. Independent
  validation reproduces domain-separated SHA-256 digests and bounded explicit
  endpoint/Node/zone failure outcomes; compact witnesses join later decisions
  to retained evidence. Mutation, property, golden, compatibility, and replay
  tests pass `make service-selection-contract-test`; ADR 0104.
- Verified compatible distribution and transactional state: explicit schema
  negotiation and authenticated UID/zone projection admit only advertised
  StableHash/NAT capabilities; agents independently verify, stage, read back,
  activate, checkpoint, roll back, recover, and acknowledge the exact per-Node
  digest. Owner-only contract+Node state and exact rollback cleanup pass
  `make service-selection-state-test`; that gate left ABI-v7 packet behavior unchanged;
  ADR 0105.
- Verified locality/topology dataplane: userspace resolves the first non-empty
  verified SameNode/SameZone/Cluster tier and atomically activates fixed-width
  ABI-v8 state. Strict internal/external Local, ordered preference fallback,
  independent ClusterIP/NodePort/LoadBalancer origins, dual-stack TCP/UDP,
  lifecycle filtering, tier provenance, topology-only changes, and exact
  recovery pass `make service-selection-dataplane-test`; ADR 0106.
- Verified ClientIP affinity and graceful draining: original-client/frontend
  keys reuse only the same eligible immutable bank+revision, bounded timeout
  expiry reselects through StableHash, established connections precede affinity,
  and terminating endpoints leave new-flow slots without breaking existing
  flows. Persistent ABI-v9 recovery, event provenance, strict Clippy, and
  real-kernel IPv4/IPv6 packets pass `make service-affinity-dataplane-test`;
  ADR 0107.
- Measured Maglev is verified for 2–4,096 eligible backends through bounded
  deterministic prime tables, actual-algorithm fallback/provenance, and the
  existing one-map packet path. The committed fixture records balance,
  disruption including table boundaries, memory, compile/update time, and map
  writes; `make service-maglev-dataplane-test` and ADR 0108.
- Explicit LoadBalancer DSR is verified under persistent ABI v11. Dual
  annotations acknowledge backend VIP ownership; equal Service/backend tuples,
  per-family capabilities, existing selection/policy/source-range/lifecycle
  order, FIB route/neighbor/MTU proof, VIP-preserving direct or neighbor output,
  runtime-bound transport topology, forward-only state/direct return,
  fail-closed verifier-isolated tail stages, provenance, recovery, and cleanup
  pass `make service-dsr-dataplane-test`; ADR 0109.
- Verified bounded operations preserve exact tier, actual StableHash/Maglev,
  affinity reuse/create/reselection, backend, revision, and NAT/DSR outcomes in
  fixed-name metrics, validated status-v8, export-v6, and durable
  history-v7/checkpoint-v6. Explanation distinguishes current drain state from
  observed decisions; digest-bound read-only simulation covers ClusterIP,
  NodePort, and LoadBalancer. Explicit unknown migration, adjacent compatibility,
  inherited ABI-v11 recovery, CLI queries, and strict Clippy pass
  `make service-selection-operations-test`; ADR 0110.
- Kube-proxy-free Kind qualification is verified. Runtime/qualifier `06fc937`
  passed the 463-second three-Node Kubernetes v1.35.0
  dual-stack gate: strict locality/fallback, affinity/drain, measured
  StableHash/Maglev provenance, acknowledged cross-worker DSR, operations,
  controller-offline agent replacement, exact ABI-v11/CNI cleanup, and no-CNI
  rollback; `hack/verify-kind-service-selection.sh`; ADR 0111.
- OpenShift qualification is independently verified. Runtime `06fc937`,
  qualifier `018f14c`, and three immutable public Quay digests passed the
  1,670-second five-Node OpenShift 4.22.10/Kubernetes 1.35.6 cl02 gate. The
  complete Phase 6 regression, RHCOS/SELinux/CRI-O and kube-proxy absence,
  cross-worker/node/zone dual-stack selection, affinity/draining,
  Maglev/StableHash provenance, acknowledged DSR source/return semantics and
  source ranges, controller-offline worker-agent replacement, exact cleanup,
  five-agent convergence, and unchanged unhealthy-operator baseline passed;
  ADR 0112. Kind and OpenShift evidence remain non-transitive.
- Weighted traffic splitting, latency/load feedback, cross-cluster selection,
  SCTP Services, fragments, generic NAT `RELATED`, and production scale remain
  separate gates.

## Phase 8 — identity-aware egress fabric

**Gate: verified.** The ordered evidence matrix is maintained in the
[Phase 8 egress-fabric plan](development/phase8-egress-fabric-plan.md).

- Verified architecture boundary: source identity and security policy precede
  explicit egress intent, address allocation, gateway placement, steering, and
  NAT. A gateway or address lease never grants permission.
- The controller will translate Kubernetes/OpenShift inputs into one
  provider-neutral domain. OpenShift EgressIP compatibility does not create a
  second policy, allocation, or dataplane engine.
- Canonical per-source/per-Node Egress Behavior Contracts bind identity,
  destination constraints, policy, allocation, gateway candidates,
  capabilities, and revisions and require independent agent replay before
  activation.
- Gateway ownership is lease- and epoch-fenced. Placement/failover algorithms
  require committed disruption and convergence measurements before adoption.
- Allocation, gateway readiness, reachability, dataplane state, and publication
  have independent revisions and last-known-good recovery. Native egress remains
  unchanged unless explicit admitted intent owns the flow.
- FQDN controls use bounded TTL/staleness/provenance-aware address sets; DNS
  names and answers never become workload identity.
- Phase 8.7d verifies explicit wildcard discovery names and resolver-address
  authority per view. Two Node-owned batches must form quorum before dual-stack
  authority exists. Equivalent contracts from replicas sharing one identity
  retain per-Node provenance and coalesce into one gateway behavior; conflicts
  fail closed. Two source activation grants, authoritative empty state, observer
  replacement, recovery, and final withdrawal pass the dedicated Kind lifecycle
  gate (ADR 0145).
- Phase 8.7e verifies Authority-Carved Internet classification. Complete
  provider-neutral dual-stack prefix evidence binds classifier epoch/revision,
  validity, and per-rule provenance; unknown space denies and bounded policy
  exceptions are absolute even against a more-specific provider allow. `Deny`
  is the default fallback; opt-in last-known-good snapshots link the exact prior
  digest and expire autonomously. Source and gateway map compilers replay the
  same decision under `make egress-internet-classification-test`; ADR 0146.
- Phase 8.7f verifies authenticated durable classifier lifecycle. A
  cluster-scoped API and opt-in publisher role separate publication from agent
  authority; canonical checkpointing retains current input, replay positions,
  and exact per-intent snapshots before replacement distribution. The
  three-Node dual-stack Kind gate proves current, exception, private, unknown,
  loss, early-LKG, restart, autonomous expiry, replay/mutation rejection, and
  higher-revision recovery under `make egress-internet-lifecycle-test`; ADR
  0147.
- Phase 8.8a verifies Diversity-Quorum Reachability. Exact digest-sealed
  lease/path plans require complete finite IPv4/IPv6 route observations across
  every declared vantage, count independent failure domains rather than
  replicas, and require exact path agreement. Correlated, conflicting, partial,
  foreign, missing, and expired evidence denies closed; verified withdrawal
  requires the same diverse empty view under `make
  egress-reachability-contract-test`; ADR 0148.
- Phase 8.8b verifies authenticated durable DQR lifecycle. Controller-owned
  plans and namespaced observer identities expose only a status publication
  surface to independently bound observers. Exact embedded-plan replay,
  transactional relist, retained monotonic positions, canonical checkpoint
  recovery, persistence-before-acknowledgement, and autonomous expiry feed the
  existing gateway and safe-forgetting transactions. A two-failure-domain Kind
  gate proves RBAC, restart, denial, replay/mutation rejection, recovery, and
  cleanup under `make egress-reachability-lifecycle-test`; ADR 0149.
- Phase 8.8c verifies the live native reference provider. The controller owns
  exact lease-bound DQR plans and cleanup; agents answer nonce-bound probes only
  for kernel-read-back addresses, but cannot authorize themselves. One explicit
  provider receipt and two separately authorized fabric failure domains must
  agree. The dual-stack Kind lifecycle proves real external route mutation,
  wrong-view denial, expiry fencing/recovery, restart, positive withdrawal,
  safe reuse, and exact cleanup under `make egress-native-reachability-test`;
  ADR 0150.
- Phase 8.8d verifies causal-constrained BGP convergence. A pinned GoBGP typed
  gRPC adapter applies digest-sealed default-deny export policy, bounded peers,
  ECMP, graceful restart, and exact RIB readback. Every route carries a Causal
  Route Capsule binding its owner, lease, gateway, and DQR plan; persistence
  failure rolls back only the transaction and durable snapshots reconstruct a
  missing daemon RIB. A live dual-stack four-speaker gate proves two independent
  gateway paths at two fabric failure domains, stale-capsule rejection, finite
  DQR authority, partial/complete withdrawal, recovery, and cleanup under `make
  egress-bgp-test`; ADR 0151.
- Phase 8.8e verifies bounded BFD and dependency-aware failure correlation. The
  default Causal Failure Lattice binds authenticated Node-UID evidence to the
  exact DQR path set, transitively collapses shared fault dependencies, requires
  two distinct evidence planes before exact-path suppression, and uses a
  recovery hold plus flap budget. All-path loss can request source fencing but
  the schema cannot authorize ownership or promotion. A live four-speaker gate
  injects a real gateway failure, withdraws both protected route families, and
  preserves the independent path under `make egress-bfd-test`. IPv6 BFD
  transport remains explicitly unqualified and rejected; ADR 0152.
- Phase 8.9a–8.9b verify loss-explicit causal operations. The Chronicle retains
  exact NAT witnesses and explicit loss barriers; explanation and simulation
  join policy, intent, allocation, gateway, contract, reachability, source
  activation, observations, transport, and HA without inferring private NAT
  state. Terminal failovers enter a bounded hash-chained ledger under `make
  egress-operations-causal-test`; ADRs 0153–0154.
- Phase 8.9c verifies the Causal Egress Recovery Vector. Additive compatibility
  fields expose every egress wire/map contract; restart rejects derived-ahead
  and same-revision-divergent state, accepts only desired-ahead reconciliation,
  migrates checkpoint v5, refuses evidence-losing rollback, and removes only an
  explicitly authorized exact ABI directory under `make
  egress-upgrade-recovery-test`; ADR 0155.
- Phase 8.10 composes the complete runtime on one three-Node dual-stack
  kube-proxy-free Kind cluster. Runtime and qualifier `2f404ed` passed
  all six digest-bound lifecycle components, zero-churn warm-standby rejoin, and exact no-CNI rollback in 1,013
  seconds. The aggregate SHA-256 is
  `c364a99a05f1bd9a1b0416bf3305feabc3de58d25119bfc20b0fc66bb7efbc88`;
  ADR 0156.
- Phase 8.11 independently qualifies the same runtime through immutable public
  images on five-Node dual-stack OpenShift 4.22.10/Kubernetes 1.35.6 cl02.
  Runtime `2f404ed` and qualifier `baf2bb0` passed the 411-second gate with
  RHCOS/SELinux/CRI-O, kube-proxy absence, external IPv4/IPv6 source
  observation, exclusive four-address/three-gateway HA, graceful drain,
  zero-churn warm-standby restoration, controller and agent recovery, exact
  cleanup, five-agent convergence, and an unchanged `network` unhealthy
  baseline. Evidence SHA-256 is
  `a2f8cb2279a3e1417ad1533575b644487e64cbfd1d8afafe351e99fad7e126d3`;
  ADR 0157. The independent 8.10 and 8.11 results close Phase 8.
- Milestone 8.2 is verified: bounded provider-neutral Namespace, workload, and
  ServiceAccount selectors; canonical destinations and non-overlapping
  dual-stack pools; pool-family/multiple-address intent; strict OpenShift
  EgressIP translation/defaulting; and foreign status preservation pass
  `make egress-intent-test`; ADR 0114. It changes no BPF ABI, host routing,
  address ownership, watcher/RBAC behavior, packet behavior, or platform claim.
- Milestone 8.2a is verified. Schema-v1 exact-Node Egress Behavior Contracts
  independently replay identity/intent selection, source-policy allow, exact
  allocation and lease epoch, ready/reachable gateway ranking, capabilities,
  and six revision domains. Domain-separated SHA-256 commitments, compact
  witnesses, mutation rejection, and bounded single-gateway failure outcomes
  pass `make egress-contract-test`; ADR 0115.
- Milestone 8.3 is verified. Schema-v1 checkpoints replay atomic deterministic
  multiple-address dual-stack allocation, provider/pool ownership, monotonic
  lease epochs, release/reuse, and collision/exhaustion failure. Independent
  gateway/readiness and reachability provider acknowledgements fence epochs and
  revisions, retain addresses through safe withdrawal, and gate contract/status
  publication; `make egress-allocation-test`; ADR 0116.
- Milestone 8.4 is verified. Schema-v1 projections bind the existing
  authenticated Pod/Node principal, negotiate exact schemas/capabilities, and
  require independent contract replay before an admitted-only compiler can
  create isolated userspace ABI-v1 gateway host state. Two-bank
  stage/readback/prepare/activate, last-known-good rollback, current/pending
  crash repair, cold reconstruction, strict checkpoints, and version-scoped
  cleanup pass `make egress-host-state-test`; ADR 0117. Live endpoint/storage
  integration and packet behavior begin in milestone 8.5.
- Milestone 8.4a is verified. The default Egress Proof Chain fences explicit
  intent before activation and during withdrawal, deterministically selects a
  same-family address and ready gateway with rendezvous hashing, and commits the
  authoritative identity, original tuple, full contract/revisions, lease,
  choice, and witness for independent selected-gateway replay. Mutation and
  unsupported inputs fail closed under `make egress-proof-test`; ADR 0118. It
  defines reference/control semantics and makes no live packet-path claim.
- Milestone 8.5 is verified. Its first slice distributes complete
  admitted source contracts to each authenticated selected gateway, certifies
  source-local route/interface/next-hop/transport/MTU paths before activation,
  and lowers identity admission plus shared per-intent address, primary/
  standby, 251-bucket rendezvous, connection, and event state into asserted
  fixed-width layouts. Proof and table selection are identical under
  `make egress-dataplane-contract-test`; ADR 0119. The next verified slice moves
  persistent state to the then-current exact 40-pin ABI v14 (superseded by
  ABI v15 temporal semantics in milestone 8.7c): the agent owns source, destination,
  candidate and selection banks, source and aggregate gateway pointers,
  dedicated gateway-NAT projection banks, and the connection LRU,
  with inactive readback,
  capacity rollback, pointer-authoritative recovery, and historical-v13 cleanup
  separation proven by `make egress-dataplane-map-test`; ADR 0120. Authenticated
  live source distribution now derives the recipient from Pod-bound TokenReview
  plus authoritative Node UID, carries complete replay material, and stages
  only fail-closed source fences through the owned maps. Absence and every
  validation/transaction failure retain last-known-good state under `make
  egress-live-distribution-test`; ADR 0121. Structural native EgressPool and
  EgressPolicy watches plus optional read-only OpenShift EgressIP compatibility
  now feed one canonical revisioned ConfigMap checkpoint. Whole-model
  transactions, exact relists, restart replay, foreign-status non-adoption, and
  stale source-authority withdrawal pass `make egress-desired-state-test`; ADR
  0122. Authenticated selected-gateway distribution now filters only exact
  ready/reachable lease-fenced candidates, independently admits the digest-bound
  projection, and uses a monotonic empty projection for withdrawal under `make
  egress-gateway-distribution-test`; ADR 0123. The watched canonical revision now also drives one
  schema-v2 durable orchestration checkpoint: deterministic bounded allocation,
  Ready primary-CNI Node/UID gateway intent, exact restart replay, pool
  tombstones, and dual-provider withdrawal-before-release pass `make
  egress-control-plane-test`; ADR 0124. Exact schema-v1 application evidence now
  separates delivery from source-map commit and gateway-ledger adoption. Only
  an acknowledged source becomes distributable, every selected gateway must
  acknowledge the exact active projection, explicit withdrawal is positively
  acknowledged, and Pod replacement, mutation, invalidation, or stale replay
  fails closed. Runtime status exposes bilateral readiness under `make
  egress-application-ack-test`; ADR 0125. Egress ABI v3 now binds every source
  to banked IPv4/IPv6 destination prefixes and exact contract/intent state.
  The workload-veth ingress path evaluates NetworkPolicy first, preserves
  service and nonmatching native traffic, drops fenced/incoherent matches, and
  hands allowed exact TCP/UDP flows unchanged to a certified direct neighbor.
  Compiler, recovery, verifier, and dual-stack real-kernel packets pass `make
  egress-source-steering-test`; ADR 0126. Digest-bound activation and native
  path proof then make source state active, while exact Node-UID-bound
  `unf-egress0` ownership and all-selected-gateway quorum acquire lease-fenced
  `/32` and `/128` addresses; ADRs 0127–0128. Identity-namespaced heterogeneous
  gateway banks now admit exact contract/lease/destination/proof chains.
  Proof-salted odd-stride port candidates plus reverse-first and forward-second
  no-overwrite insertion provide collision-safe dual-stack TCP/UDP state;
  privileged recovery, checksum, reverse, and collision packets pass `make
  egress-gateway-nat-test`; ADR 0129. Checkpoint-v2 retirement manifests and a
  domain-separated Proof of Safe Forgetting now require the exact source set,
  zero-flow gateway drains, and withdrawn reachability before atomic address
  release under `make egress-safe-forgetting-test`; ADR 0130. Live evidence
  transport now captures admitted membership before invalidation and accepts
  source fences only from exact current Pod/Node/epoch challenges under `make
  egress-source-retirement-test`; ADR 0131. Exact gateway drain challenges,
  explicit static reachability withdrawal, release-authorized host subsets, and
  atomic final lease retirement pass the gateway-retirement and
  `egress-release-authority-test` gates; ADRs 0132–0133. A fixed proof-bound
  first-flow NAT event ABI, strict agent decoding, fixed-cardinality metrics,
  and exact non-blocking ring-loss accounting pass `make
  egress-nat-observability-test`; ADR 0134. The closing production join derives
  exact per-source-Node contracts from watched Pods, identities, egress policy,
  intent, allocation, explicitly eligible gateways, and reachability; stale
  revisions invalidate both sides. Exact proxy-NDP ownership makes leased IPv6
  host addresses reachable without weakening Node-UID/address fencing. The
  repeatable three-Node kube-proxy-free Kind gate exercises dual-stack UDP NAT
  and reverse traffic, exact sparse witnesses, unaffected native sources,
  controller/agent restart, withdrawal/drain/removal, monotonic same-address
  reuse, final release, and retained diagnostics under `make
  egress-kind-lifecycle-test`; ADR 0135. Measured HA/failover and complete Kind
  composition are now verified; independent OpenShift qualification remains.
- Milestone 8.6 is verified. Its first slice introduces
  Continuity-Certified Rendezvous (CCR): same-ordinal IPv4/IPv6 addresses form
  exclusive ownership shards; exact integer capacity targets bound imbalance;
  the compiler retains the mathematical maximum prior ownership; and
  failure-domain diversity precedes rendezvous score when a failed owner's
  shards move. A complete digest-bound capacity-exact contingency is compiled
  for each single-gateway failure, and replay verifies that actual movement
  equals its lower bound. Candidate ordering, malformed membership, duplicate
  identity, stale lease, foreign prior state, and certificate mutation fail
  closed under `make egress-ha-planner-test`; ADR 0136. The verified 8.6b
  proof-carrying protocol fences every exact source before it accepts either
  graceful old-owner address absence or positive independent infrastructure
  isolation. Kubernetes readiness/Lease is never a fence. Exact replacement
  ownership and reachability compare-and-swap evidence seal the activation
  capability under `make egress-ha-promotion-test`; ADR 0137. Acknowledged Flow
  Twins then replicate complete NAT pairs through sequence-checked hash chains;
  exact standby watermark/readback permits only live lease- and shard-valid
  pairs into a promotion-bound atomic cutover. The asynchronous unacknowledged
  tail remains explicit and measurable under `make egress-ha-continuity-test`;
  ADR 0138. Checkpoint-v3/v4 then aligns exclusive shard ownership with the
  packet proof and makes the complete promotion transaction restart-replayable;
  ADRs 0139–0140. The closing authenticated live path uses checkpoint-v5,
  canonical source-cutover persistence, exact AFT BPF snapshot/import/readback,
  old-owner revocation, replacement acquisition, reachability CAS, and atomic
  source-bank activation. A verifier-isolated tail dispatcher supports mixed
  source/gateway Nodes. `make egress-ha-kind-test` recorded 45 acknowledged
  twins, 10.860-second graceful promotion, exclusive ownership, stable rejoin,
  and 80.428-second abrupt recovery without treating Kubernetes health as fence
  authority; ADR 0141. Production availability/scale and OpenShift remain
  independent gates.
- Production BGP/EVPN/ECMP/BFD, cloud adapters, cross-cluster egress,
  overlapping-CIDR translation, WireGuard, L7/Gateway API, SCTP NAT, fragments,
  generic NAT `RELATED`, arbitrary ICMP translation, and production HA/scale
  remain independent gates; ADR 0113.

## Phase 9 — attested encryption fabric

**Gate: in progress; milestones 9.1–9.8 verified.** The ordered evidence
matrix is maintained in the
[Phase 9 encryption-fabric plan](development/phase9-attested-encryption-fabric-plan.md).

- Phase 9.1 fixes policy-before-encryption precedence and kernel WireGuard as
  the initial L3 provider. UNF manages configuration and proof in Rust but does
  not implement cryptographic primitives or expose private keys through the
  controller, Kubernetes APIs, telemetry, or diagnostics.
- Phase 9.2 adds the Kubernetes-independent `unf-encryption` domain. A canonical
  Native/Required baseline plus monotonic identity-pair intent feeds schema-v1
  exact-source-Node contracts. Policy-allowed Required pairs bind exact
  workload/Node/cluster identities, public-key digests and epoch/lifetime,
  bidirectional peer endpoints and Pod CIDR `AllowedIPs`, interface/route/
  fwmark/MTU facts, capabilities, and five revisions. Independent replay,
  frozen domain-separated digest/witness bytes, bounded deny-only failure
  envelopes, adversarial mutation, property, and strict-wire tests pass
  `make encryption-contract-test`; ADR 0159. No private key or runtime state is
  introduced.
- Phase 9.3 adds non-serializable Node-local key authority. Fresh X25519/
  WireGuard keys come directly from the OS CSPRNG into zeroizing buffers; only
  an atomic, digest-checked, mode-0600 checkpoint can retain them. The Causal
  Epoch Barrier seals the exact affected peer frontier and topology revision,
  requiring every authenticated peer acknowledgement without coupling rotation
  to unrelated Nodes. Public-only monotonic publication, two-epoch prepare/
  attest/activate/drain/retire, positive drain proof, emergency revocation,
  restart recovery, and replay/replacement fencing pass
  `make encryption-key-authority-test`; ADR 0160. No kernel state changes yet.
- Phase 9.4 adds the typed Linux WireGuard kernel provider. Canonical bounded
  plans configure complete peer sets through generic netlink and exact links/
  isolated dual-stack routes through rtnetlink. Proof-Carrying Kernel
  Transactions bind secret-free before/desired/readback digests to deterministic
  restart actions; version aliases, `O(P log P)` overlap validation, indexed
  route readback, safe MTU derivation, foreign-state refusal, injected rollback,
  replay, and positive cleanup pass `make encryption-kernel-provider-test` and
  the privileged live-kernel gate; ADR 0161. Workload selection remains 9.5.
- Phase 9.5a–9.5z now provide the canonical coalesced compiler and Causal Epoch
  Lease, Causal Commit Vector, isolated fixed-shape Aya ABI, Proof-Carrying Aya
  Map Mirror with delta-minimal recovery, and Cooperative Route-Mark Lease. The
  latter gives every admitted outer `WireGuard` bypass mark a collision-free
  complementary plaintext selector inside an isolated 16-bit field while
  preserving all neighboring `skb->mark` ownership. Focused gates and ADRs
  0162–0166 pass. Route-Before-Authority then binds self-verified kernel
  snapshots to deterministic masked IPv4/IPv6 rules and permits Aya publication
  only after exact route/rule readback; its model and isolated live-kernel gate
  pass under ADR 0167. Node-Sealed Generation Capsules then bind each
  authenticated pull to a fresh nonce, authoritative Node UID, opaque
  controller incarnation, and exact durable predecessor. Secure agent
  persistence occurs before cursor adoption, while the non-serializable local
  route permit cannot cross the API; `make
  encryption-generation-distribution-test` and ADR 0168. The Tri-Plane Causal
  Activation Latch then consumes only an exact join of that capsule, renewed
  Node-local route proof, and the applied/pending Aya transaction. Restarted
  serialized authority remains quarantined before TC attachment until proof is
  recreated; `make encryption-activation-latch-test` and ADR 0169.
  The Causal Generation Frontier then makes a complete Node-UID/trust-domain-
  bound cluster cut the controller publication unit. Exact durable cursor
  receipts impose slowest-member backpressure, preventing partial revisions,
  skipped predecessors, and unbounded history; `make
  encryption-generation-frontier-test` and ADR 0170. Producer persistence is
  now exact across restart: a domain-separated
  checkpoint binds the active cut plus every Node UID, published generation,
  and frontier receipt; restore occurs before readiness and corrupt state fails
  closed under `make encryption-generation-recovery-test` and ADR 0171. The
  Complete-Cut Fact Reconciler now ingests strict Node-local prepared facts over
  the Pod-bound authenticated endpoint, atomically discards all staged facts on
  topology/UID drift, rejects regression and same-generation equivocation, and
  publishes only when every exact Kubernetes member agrees on one generation.
  The final predecessor receipt retries a ready successor; `make
  encryption-generation-reconciler-test` and ADR 0172. The Capability-Typed
  Causal Proof Ladder then makes the local proposal, exact controller return,
  fresh route permit, and Aya latch consuming types. It rejects controller
  substitution and makes unsafe stage ordering structurally unavailable under
  `make encryption-local-proof-ladder-test`; ADR 0173. The Proof-Carrying Linux
  Convergence Capsule now preflights
  the complete checkpoint/plan/key cut, stages real WireGuard epochs in a
  deterministic order, joins permutation-independent exact kernel readback,
  and allows controller-returned intent to reach real policy-route and Aya
  adapters only through consuming authority. Partial or foreign state remains
  inert under `make encryption-linux-convergence-test`; ADR 0174. The
  Echo-Sealed Agent Anti-Entropy Loop now owns at most one volatile convergence
  capability, publishes its authenticated fact before each nonce-bound pull,
  retains it across retry/`204`, and persists only a byte-exact returned echo.
  With no local capability, blind controller polling is disabled by default;
  `make encryption-agent-anti-entropy-test` and ADR 0175. Proof-Rehydrating
  Activation Escrow persists only a digest-bound secret-free fact/plan recipe,
  recreates fresh authority from complete real Linux readback after restart,
  consumes exact admission through policy-route and Aya current/pending
  recovery, and clears quarantine before TC attachment only on success. The
  inherited gate passes under `make encryption-activation-rehydration-test` and
  ADR 0176. The Snapshot-First Causal Plan Compiler then folds identity-pair
  authority into one peer per destination Node/epoch, preflights all local keys,
  stages real kernel state, and derives map authority only from exact readback;
  `make encryption-local-plan-compiler-test` and ADR 0177. Authenticated running
  inputs are now represented by one strict Node-scoped Causally Sealed Input
  Manifold: contracts, readiness, decisions, and cross-domain revisions cannot
  tear independently, and every required plan has exact coverage;
  `make encryption-plan-manifold-test` and ADR 0178. Authenticated controller/
  agent delivery is protected by a Nonce-Bound Plan Relay whose exact durable cursor,
  Node name/UID, controller incarnation, and monotonic revisions prevent replay
  or replacement without conveying local activation authority;
  `make encryption-plan-distribution-test` and ADR 0179. Runtime controller/agent
  adoption is now wired through the internal Pod-bound endpoint into an atomic
  owner-only Persist-Before-Compile Plan Inbox that validates before BPF access;
  `make encryption-plan-runtime-test` and ADR 0180. Complete-cut catalog
  visibility now passes through a Fleet-Synchronous Plan Cut: explicit exact
  membership, common causal revisions, and one atomic catalog swap prevent
  partial fleet publication; `make encryption-plan-catalog-test` and ADR 0181.
  Node-local key ownership now feeds a public-only transparency ledger that
  exposes facts only after every exact current member is present at one topology
  revision; `make encryption-key-transparency-test` and ADR 0182. Runtime key
  publication is now live: stable cluster identity comes from the `kube-system`
  UID, exact Pod-bound bootstrap creates or restores a private Node authority,
  and only its durable public projection reaches the ledger;
  `make encryption-key-runtime-test` and ADR 0183. Fleet readiness now passes
  through an immutable Reciprocal Witness Matrix: deterministic authenticated
  rows release no Node column until every exact member participates, and agents
  durably apply the independently replayed result; `make
  encryption-key-attestation-test` and ADR 0184. The Demand-Sparse Fleet Plan
  Forge derives readiness from that cut and atomically emits active plans plus
  explicit authority-free dormant members instead of fake idle tunnels;
  `make encryption-fleet-plan-producer-test` and ADR 0185. The Policy-Truth
  Transport Quotient then maps mixed L4 outcomes to L3 transport demand without
  turning transport into authorization or fabricating default-allow policy IDs;
  `make encryption-policy-quotient-test` and ADR 0186. Adaptive Address-Exact
  Replica Binding retains direct lookup for single-Node identities and invokes
  a witnessed dual-stack LPM lookup only for multi-Node replicas after final
  destination translation; `make encryption-address-binding-test` and ADR 0187.
  Placement-Truth Demand Projection then rejects stale UID/readiness/IPAM cuts,
  excludes host-network workloads, preserves effective policy truth, and emits
  only required bidirectional Node paths; `make
  encryption-kubernetes-projection-test` and ADR 0188. The Pull-Synchronized
  Causal Catalog captures one revision/key cut on authenticated agent demand,
  evaluates both policy directions at semantic port boundaries and concrete
  addresses, coalesces unchanged polls, and atomically publishes the fleet;
  `make encryption-controller-plan-test` and ADR 0189. Agents consume active
  plans only through local key/Linux proof, while Authority-Free Quiescent
  Generations let idle members contribute exact zero-authority facts without
  fake tunnels; `make encryption-agent-plan-compile-test` and ADR 0190.
  Proof-Carrying Deferred Encryption then places a family-specific verifier
  island after policy, Service translation, and explicit egress ownership. It
  consumes exact decision/path/transport proof, changes only UNF's cooperative
  mark field, retains bounded Causal Epoch Leases, and drops missing Required
  authority; real verifier loading plus IPv4 direct and IPv6 late-bound packet
  execution pass `make encryption-tc-consumer-test` and ADR 0191.
  Flow-Adaptive Secure DSR then preserves Native VIP/direct-return behavior but
  morphs only a Required flow into an atomic reversible NAT pair using its
  already selected backend, so WireGuard sees a peer-owned inner destination.
  Explicit external egress remains prior and cannot acquire a Pod lease, while
  active-to-draining flow continuity and immediate revocation pass real packet
  execution under `make encryption-composition-test` and ADR 0192. A separate
  disposable two-namespace live-kernel gate completes 9.5 by carrying both
  inner families through real WireGuard, requiring positive transfer counters
  and UDP ciphertext with no inner address on the underlay, denying after peer
  removal, and recovering after exact restoration; `make
  encryption-ciphertext-live-test` and ADR 0193.
- Milestone 9.6 is verified. Causal Duplex Path Quorum binds an exact short-lived
  controller nonce, both authenticated Node UIDs, contract/decision/epoch,
  required families, kernel readback and positive peer-counter movement into a
  two-ended receipt consumed only at map activation. Workload-independent
  beacons need no Pod or new CIDR; the live gate corrected IPv4 to a
  collision-fenced unicast reserve and provider schema v3 now owns exact
  per-interface reverse-path acceptance. Two production socket engines complete
  marked dual-stack WireGuard rounds, deny after peer removal, recover with a
  distinct round, and expose ciphertext only under `make
  encryption-path-live-test`; ADRs 0194–0199.
- The Attested Encryption Path Contract binds exact source/destination cluster,
  workload, and Node identities to policy/routing revisions, public-key epochs,
  peer endpoint, disjoint AllowedIPs, interface/route/fwmark/MTU facts,
  capabilities, deadlines, and compact provenance. Both endpoint agents must
  independently replay the contract, read back owned kernel state, and complete
  a nonce-bound encrypted challenge; handshake recency alone is insufficient.
- The Intent-Coalesced Cryptographic Fast Path keeps authority per identity and
  destination while sharing only an identical trust-domain/destination-Node/
  key-epoch/path-class transport. Bounded eBPF lookup and marking select the
  transport; all cryptography remains in kernel WireGuard. There is no tunnel,
  peer, or userspace packet path per workload or policy.
- Flow-Stable Epoch Rotation admits at most two epochs. New flows move only
  after mutual evidence, established flows drain within a bounded deadline, and
  exact positive evidence precedes old route/interface/key retirement. Required
  traffic fails closed and never silently downgrades to plaintext.
- Fresh Phase 9-qualified primary-CNI installations will default managed
  cross-Node Pod paths to Required. Existing clusters retain their previously
  qualified path until an explicitly acknowledged staged migration proves
  complete encrypted reachability; milestone 9.1 itself changes no runtime.
- Performance is an acceptance gate, not a slogan. Committed native-versus-
  encrypted fixtures must report IPv4/IPv6 throughput, p50/p95/p99 latency,
  CPU, memory, map activity, peer scale, MTU cost, convergence, drops,
  retransmits, and rotation disruption before any advantage is claimed.
- Milestones 9.2–9.7 implement the intent/contract model, Node-local key and
  rotation authority, transactional WireGuard provider, coalesced fast path,
  bidirectional live proof, secret-free operations, recovery, and benchmarks.
  Milestone 9.8 passed its independent kube-proxy-free three-Node dual-stack
  Kind gate at runtime `6fe2a92`, qualified by `e1fc112`, with evidence SHA-256
  `f35a0ede…035`. Milestone 9.9 now requires the same immutable runtime on the
  independent five-Node OpenShift gate; ADRs 0158 and 0212.
- Cross-cluster networking, overlapping CIDRs, global services, mTLS,
  post-quantum cryptography, TPM attestation, IPsec/MACsec, L7, Gateway API,
  transparent host/control-plane encryption, and production availability/scale
  remain separate gates.
