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

**Gate: in progress.**

- Implemented foundation: collision-checked identity admission, Pod-IP desired-
  state index, update/removal garbage collection, and controller status counts.
- Implemented and two-node kind verified: versioned IPv4 BPF identity map,
  epoch/revision-based controller-to-agent snapshot distribution, enriched flow
  identities, and reconvergence after a controller epoch change;
- Implemented and two-node kind verified: selector-to-identity lowering,
  versioned dual-bank policy maps, atomic revision activation/restoration, and
  agent desired/applied policy status;
- Next: applied node status aggregation and TC policy lookup;
- L3/L4 allow/deny with explicit reason codes;
- denied flow telemetry and accurate live `unfctl explain`;
- last-known-good and fail-safe behavior tests.

## Phase 3 — compatibility and simulation

- Kubernetes NetworkPolicy adapter into the same IR;
- shadow rollout and offline impact analysis;
- topology snapshots and flow exporter interface;
- failure, scale, and OpenShift validation.

Full CNI/IPAM, routing, service load balancing, egress, encryption, L7, and
multi-cluster transport remain research/planned work after these foundations.
