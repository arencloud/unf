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

**Gate: in progress.**

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
  exclusion, all four Pod/Namespace selector operators, selector AND, peer OR,
  explicit empty source/port lists, multi-port OR,
  multiple ingress-rule source/port pairing,
  exact/protocol-only UDP isolation, destination-specific named ports and
  nonexistent named-port fail-closed behavior,
  destination match-label and all-four-expression-operator selection lifecycle,
  broad/narrow overlapping destination-selector additivity and ordered recovery,
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
- Next: remaining upstream ingress conformance;
- shadow rollout and offline impact analysis;
- topology history and external flow-export backends;
- failure, scale, upgrade, and broader OpenShift version validation.

Full CNI/IPAM, routing, service load balancing, egress, encryption, L7, and
multi-cluster transport remain research/planned work after these foundations.
