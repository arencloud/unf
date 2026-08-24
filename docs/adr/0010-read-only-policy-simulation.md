# ADR 0010: Revision-fenced read-only policy simulation

Status: Accepted and live verified for the Phase 3 simulation foundation

## Context

Operators need to inspect a proposed policy before rollout without creating a
Kubernetes object or changing the active dataplane revision. The first simulation
slice must reuse the enforcement evaluator, identify the exact state it examined,
bound its control-plane cost, and avoid claiming historical impact before a flow
store exists.

## Decision

`POST /v1/policy/simulate` accepts one candidate native `SecurityPolicy`. A
candidate with the same namespace/name as an admitted native policy replaces that
policy only in an in-memory proposed policy set; any other candidate is added. The
controller compiles it through `PolicyCompiler`, combines it with the current
native and compatibility IR, and never writes watched state, revisions, snapshots,
or BPF maps.

The simulation captures the controller identity epoch, identity revision, policy
revision, and current Pod topology under the policy-state read fence. It evaluates
every current Pod as a source against destinations selected by either the existing
or candidate policy. Probe tuples include concrete ports referenced by current and
proposed policy, resolved named ports, bounded range members, and one unmatched TCP
and UDP port for wildcard/default behavior. The complete matrix is limited to
10,000 flows; larger requests fail explicitly instead of returning partial counts.

The response schema is versioned independently at version 1. It reports
remain-allowed, remain-denied, would-be-allowed, and would-be-denied counts;
verdict and full-decision change counts; affected workloads; and each changed
flow with current/proposed provenance. `unfctl policy simulate <file>` exposes the
API in table, JSON, or YAML form.

## Alternatives

Applying a temporary shadow CRD would mutate live desired state and revisions.
Implementing simulation in the CLI would duplicate policy semantics and require
shipping topology and policy state to the client. Evaluating only candidate rule
ports would miss default-action changes. Calling topology probes historical flows
would overstate evidence that does not yet exist.

## Consequences

The foundation provides deterministic, read-only what-if evaluation against an
identified live snapshot and uses exactly the same IR/evaluator as enforcement.
It is not yet historical impact analysis: external sources, user-supplied flow
sets, services, observed frequency, and time windows are absent. The topology
matrix is representative for wildcard/default ports rather than an enumeration of
all 65,535 ports. Historical flow export and richer versioned topology remain
separate Phase 3 work.
