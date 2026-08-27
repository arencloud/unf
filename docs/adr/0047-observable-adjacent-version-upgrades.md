# ADR 0047: Observable adjacent-version upgrades

Status: Accepted and live verified on dual-stack Kind

## Context

UNF already preserves last-known-good maps and attachment links across process
replacement, but restart safety alone does not establish a supported software
upgrade. A networking rollout must prove the controller and agents do not need
to change simultaneously, that the active version pairing is observable, and
that a bounded rollback does not open enforcement or stop telemetry. Map and
wire-schema changes must remain an explicit migration boundary.

## Decision

The controller and agent expose `GET /v1/version` with component-compatibility
schema v1. It reports the component and software version, build revision,
persistent BPF-state ABI, identity and policy snapshot schemas, agent-status
schema, and flow-export schema. Container builds embed the exact Git revision;
the endpoint contains no credentials or mutable runtime state.

The first supported window is one adjacent committed revision, N to N+1, while
the published compatibility tuple remains unchanged. The rollout order is:

1. establish healthy controller N with agents N;
2. replace the controller with N+1 and require every N agent to reconverge;
3. update agents one Node at a time, requiring an explicit mixed N/N+1 state;
4. require all N+1 agents to converge before completing the rollout.

Within the same tuple, one agent may roll back to N and forward again while the
controller stays N+1. The controller may also roll back to N while agents remain
N+1, then return to N+1. Each controller process has a new epoch, so restored
reports never satisfy convergence until the running agents acknowledge that
epoch. Agents continue to validate and adopt the complete pinned v3 BPF state
and use persistent TCX or legacy-netlink attachment handoff.

An ABI or listed schema change is not covered by this window. Such a change must
define dual-read/write or state migration, cleanup, downgrade behavior, and a
new mixed-version gate before it can be called upgrade compatible.

## Verification

`make kind-upgrade-test` builds current N+1 images with embedded revision
metadata and independently archives/builds N from `HEAD^` by default. The
baseline ref and image names are overrideable for release qualification. Both
generations are loaded into the two-node Kind cluster.
When N exposes compatibility schema v1, the gate requires the controller and
both N agents to publish the same tuple and requires N+1 to match it. The initial
N baseline predates this endpoint, so its unchanged ABI/wire compatibility is
established by successful pinned-state adoption, bidirectional mixed-version
convergence, and telemetry exchange rather than a self-reported tuple.

The focused gate proves N/N, controller N+1 with agents N, a deterministic
one-agent N/N+1 mix, all N+1, agent rollback and forward recovery, controller N
with agents N+1, and final N+1 convergence. Every pairing requires two fresh,
authenticated, revision-converged agents and increasing flow telemetry. A
continuous workload probe requires TCP/8080 to remain allowed and TCP/9090 to
remain denied through every controller and agent replacement. Current agents
must report recovered nonzero identity/policy maps, equal desired/applied
epochs and revisions, and a persistent attachment mode. The final deployment is
restored to the current images and rolling DaemonSet strategy.

Unit tests fix the compatibility tuple and component-specific version response.
Workspace formatting, strict lint/tests, the eBPF release build, and the normal
Kind regression gate remain required alongside the focused upgrade test.

## Consequences

UNF has repeatable evidence for an observable, reversible adjacent-version
window without a simultaneous node transition. The evidence is deliberately
narrow: it does not claim skips across multiple revisions, incompatible map or
wire schemas, large clusters, OpenShift/RHCOS rolling upgrades, Kubernetes
version skew, or HA-controller coordination. Those require separate matrices.
