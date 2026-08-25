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

**Initial enforcement gate: verified.** Production hardening remains in progress.

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
  offline-controller restart recovery through the ABI v2 nine-map pin set;
- Implemented and two-node kind verified on Linux 7.1: per-interface pinned TCX
  links, atomic replacement-program handoff, and continuous deny enforcement
  while an offline-controller agent is replaced. The same gate explicitly selects
  the stable-priority/handle legacy netlink path, removes TCX coverage, proves
  in-place replacement with continuous deny enforcement, and safely restores TCX
  before scoped legacy cleanup. Native automatic legacy selection, reserved
  filters, BTF/bpffs access, SCC admission, enforcing SELinux, and IPv4
  enforcement are also verified on OpenShift 4.22/RHCOS 9.8 kernel 5.14;
- Implemented and two-node kind verified: isolated live-kernel fault sets prove
  eight-of-nine pins, malformed active policy config, and corrupt inactive-bank
  debris are rejected with actionable errors while primary allow/deny state
  remains unchanged; permanent dataplane startup failure exits for orchestrator
  retry;
- Implemented and two-node kind verified: deterministic reserved-key pressure
  fills the shared physical `POLICY_RULES` map with inactive-bank keys, forces a
  real kernel staging failure, and proves rollback preserves the active
  revision/bank and traffic; after scoped cleanup, the waiting revision activates
  and enforcement restores;
- Implemented and two-node kind verified: dry-run-first host-state cleanup removes
  only recognized ABI v1/v2 map pins, TCX link pins, and UNF-named legacy filters;
  unknown ABI content is refused, current v2 requires explicit confirmation, and
  live cleanup preserves the active v2 map set and restores TCX before removing
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
  `restricted-v2` for the controller, an explicit privileged agent SCC binding,
  OpenShift Service CA certificate/bundle injection, exact worker convergence,
  Pod-bound TokenReview, populated per-family identities, and cross-worker
  IPv4/IPv6 policy provenance;
- Next: automated certificate/trust rotation, durable agent acknowledgement
  retention, and a narrower production SCC/capability profile.

## Phase 3 — compatibility and simulation

**Gate: in progress.**

- Implemented and two-node kind verified: supported ingress `NetworkPolicy`
  translation, additive semantics, controller reconciliation/status, shared
  dataplane enforcement/provenance, pod/Namespace label-expression selectors,
  destination-aware named-port lowering, namespace relabel convergence without
  identity churn, protocol-only TCP/UDP/SCTP wildcard lowering, bounded numeric
  `endPort` ranges with map-capacity guards, bounded IPv4 exact-source and IPv6
  LPM `ipBlock`/`except` enforcement with atomic three-map activation, namespace-wide
  targets from omitted `podSelector`, implicit ingress `policyTypes` for
  egress-omitted objects, default TCP ports, and non-selected Pod behavior, plus
  rejection/deletion recovery; IPv4 SCTP parsing/enforcement, live explanation,
  revisioned provenance, and historical export; an upstream-aligned live ingress
  matrix for default deny, same/all/exact-Namespace peers, Namespace `NotIn`
  exclusion, selector AND, peer OR, Pod/Namespace `matchExpressions`,
  multiple ingress-rule source/port pairing,
  exact/protocol-only UDP isolation, destination-specific named ports,
  destination selection lifecycle, source-label recovery, stacked additive
  policies, and allow-all precedence/recovery;
  revision-fenced, read-only native policy simulation over a bounded
  current-topology probe matrix; versioned Node,
  workload-placement, Service, and selector-membership topology snapshots;
  EndpointSlice-backed runtime relationships with readiness, serving,
  termination, Node/zone, Pod target, address, and port provenance;
  destination-resolved agent flow export through bounded non-blocking queues,
  revisioned 4,096-key controller history, `unfctl flows`, and
  observation-weighted historical simulation impact; resolved-identity IPv6
  distribution, enforcement, provenance, topology schema v3, and flow-export
  schema v2; bounded IPv6 extension-header traversal with real packet fixtures;
  separate dual-stack OpenShift cross-worker enforcement and history evidence on
  RHCOS Linux 5.14 under Enforcing SELinux;
- Next: remaining upstream ingress conformance, plus durable telemetry retention
  with time-window queries;
- shadow rollout and offline impact analysis;
- topology history and external flow-export backends;
- failure, scale, upgrade, and broader OpenShift version validation.

Full CNI/IPAM, routing, service load balancing, egress, encryption, L7, and
multi-cluster transport remain research/planned work after these foundations.
