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
  agent desired/applied policy status;
- Implemented: active-bank TC lookup and IPv4/IPv6 TCP/UDP/SCTP allow/drop,
  including verifier-bounded IPv6 Hop-by-Hop, Routing, Destination Options,
  initial/atomic Fragment, and AH traversal. Dual-stack two-node kind verifies
  IPv6 TCP and real extension-header UDP allow/deny plus existing IPv4 TCP/SCTP
  scenarios, shadow pass-through, Flow ABI v2 actual/shadow provenance, and
  enforcement-aware `unfctl explain`;
- Verified manually: the last active bank continued enforcing across a controller
  interruption and agents reconverged to the restarted controller epoch;
- Next: applied node status aggregation, pinned last-known-good recovery, agent
  restart fencing, and pressure/fault-injection tests.

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
  matrix for default deny, same/all-Namespace peers, selector AND, peer OR,
  Pod/Namespace `matchExpressions`, multiple ingress-rule source/port pairing,
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
- Next: remaining upstream ingress conformance, plus
  authenticated/durable telemetry transport with time-window queries;
- shadow rollout and offline impact analysis;
- topology history and external flow-export backends;
- failure, scale, and OpenShift validation.

Full CNI/IPAM, routing, service load balancing, egress, encryption, L7, and
multi-cluster transport remain research/planned work after these foundations.
