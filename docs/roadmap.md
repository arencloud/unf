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

**Gate: In progress.** The ordered evidence matrix is maintained in the
[Phase 7 service-selection plan](development/phase7-service-selection-plan.md).

- Verified architecture boundary: strict `Local` eligibility takes precedence
  over topology preferences; `ClientIP` affinity can reuse only a currently
  eligible backend; connection persistence remains separately revisioned.
- Per-Node eligibility and selection plans are compiled in userspace and must
  activate transactionally. The eBPF path performs bounded lookups and does not
  interpret Kubernetes topology or affinity configuration.
- Maglev is a measured candidate, not a label-only claim. Adoption requires
  deterministic balance/disruption, bounded memory and compile cost, stable
  upgrades, and verifier-visible packet-cost evidence against the current hash.
- DSR is opt-in and cannot bypass route/neighbor/MTU safety, backend VIP
  ownership, policy, source ranges, health, reverse telemetry, or exact cleanup.
- Schema/compiler, distribution/state, locality, affinity/draining, Maglev,
  DSR, operations, Kind, and OpenShift remain ordered independent milestones;
  ADR 0102 and `make service-selection-boundary-test` define the first gate.
- Weighted traffic splitting, latency/load feedback, cross-cluster selection,
  SCTP Services, fragments, generic NAT `RELATED`, and production scale remain
  separate gates.
