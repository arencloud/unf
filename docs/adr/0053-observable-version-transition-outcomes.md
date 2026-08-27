# ADR 0053: Version-transition outcomes are observable before retry

Status: Accepted and live verified on dual-stack Kind

## Context

The compatibility matrix distinguishes same-tuple rollback, snapshot-driven
persistent-state rebuild, direct unsupported downgrade, and recovery. Before
this decision, the successful paths were visible through convergence and the
blocked path through startup logs and Kubernetes restart state, but operators
could not query one stable classification across agent status, controller
aggregation, metrics, and logs.

The blocked downgrade is rejected before BPF access. Exiting immediately after
that rejection would make its structured status difficult to observe between
orchestrator retries, while remaining alive indefinitely would weaken the
existing fail-fast startup contract.

## Decision

Agent status schema v2 gains an additive, defaulted `version_transition` field.
Old schema-v2 reports deserialize as `normal`, so the published compatibility
tuple does not change. The values are:

- `normal`: no rollout transition is being reported;
- `compatible_rollback`: an operator-selected same-tuple or clean-rebuild
  rollback is running;
- `blocked_rollback`: the agent automatically rejected a newer persistent-state
  directory before BPF access; and
- `recovery`: an operator-selected compatible agent is recovering after a
  blocked transition.

`compatible_rollback` and `recovery` are explicit rollout intent supplied by
`--version-transition` or `UNF_VERSION_TRANSITION`. Operators cannot select
`blocked_rollback`; the agent derives it only from the local newer-directory
preflight failure.

The local `/v1/status` response and the controller `/v1/state/agents` aggregate
carry the same classification. The agent exports:

- `unf_version_transition_state`, with values 0 normal, 1 compatible rollback,
  2 blocked rollback, and 3 recovery;
- `unf_version_transition_compatible_rollbacks_total`;
- `unf_version_transition_blocked_rollbacks_total`; and
- `unf_version_transition_recoveries_total`.

Every non-normal transition logs `version transition state changed` with its
classification. A blocked rollback starts the status reporter before dataplane
startup, stays not Ready and fail closed, reports for a bounded 30-second
window, and then exits for orchestrator retry. It cannot open or mutate the
incompatible map set during that window.

## Qualification gate

`make kind-rollback-reporting-test` runs the complete ABI v3→v4 clean-rebuild
lifecycle with the unsupported downgrade assertion enabled. It requires:

1. the v3 agent pointed at `/v4` to report `blocked_rollback` through local
   status, controller aggregation, the state gauge, the blocked counter, and
   logs before retry;
2. the compatible v4 replacement to report `recovery` through all four
   surfaces and reconverge without changing the retained v4 maps;
3. each node-serial reverse v4→v3 rebuild to report `compatible_rollback`
   through all four surfaces;
4. uninterrupted TCP/8080 allow and TCP/9090 deny enforcement through every
   transition; and
5. scoped v4 cleanup plus two converged current agents reporting `normal`.

The gate retains the map-digest, pre-attachment population, convergence, and
cleanup assertions from ADRs 0051 and 0052.

## Evidence

On 2026-08-27, the complete gate passed on its first attempt from clean revision
`1bf83f780ecbada8287c78bcb74c2025616cfe07` on Kubernetes 1.35.0. Both Kind
nodes used Linux `7.1.4-204.fc44.x86_64`.

The current controller and agent image IDs were
`4e37302491ff92583c97365764582c0ed0f317f79f83523dc15edd0052b37ff2`
and `45c19b5ffcd61385d79798d407b59e432a9cb1c16d6f5e242ee32b35936c918f`.
The source-derived ABI-v4 controller and agent image IDs were
`19e06de59282a9332251e4797d76a9df481045e86ba3496dc10dfd449ecf0aba`
and `7d00018d644c8d059b9c017f9c8dbed7c0a42ff8915ae714493dc1ed33084c05`.

All status, metric, and log classifications passed; the canonical v4 map digest
remained unchanged during rejection; enforcement recorded no outage or breach;
and the final controller reported two of two agents converged, both with the
`normal` transition and no v4 state remaining.

Before the live run, the workspace passed formatting, strict Clippy, all 170
workspace tests, shell syntax, manifest rendering, and a clean diff check. The
target rebuilt the release eBPF object and all current/derived images from the
committed revision.

## Consequences

Milestone 2 now has one queryable vocabulary for normal operation, compatible
rollback, blocked rollback, and recovery without changing the wire
compatibility tuple. The bounded blocked-state window preserves both operator
visibility and orchestrator retry behavior.

Transition counters are process-local and reset when a Pod is replaced. The
controller retains only the latest report rather than a durable transition
history. Long-term audit history and alert rules can be added separately; they
are not implied by this decision.
