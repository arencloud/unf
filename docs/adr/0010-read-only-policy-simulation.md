# ADR 0010: Revision-fenced read-only policy simulation

Status: Accepted and live verified for the Phase 3 simulation foundation

## Context

Operators need to inspect a proposed policy before rollout without creating a
Kubernetes object or changing the active dataplane revision. The first simulation
slice must reuse the enforcement evaluator, identify the exact state it examined,
and bound its control-plane cost. [ADR 0012](0012-bounded-flow-history-export.md)
subsequently added bounded historical input without changing this read-only model.

## Decision

`POST /v1/policy/simulate` accepts one candidate native `SecurityPolicy`. A
candidate with the same namespace/name as an admitted native policy replaces that
policy only in an in-memory proposed policy set; any other candidate is added. The
controller compiles it through `PolicyCompiler`, combines it with the current
native and compatibility IR, and never writes watched state, revisions, snapshots,
or BPF maps.

The simulation captures the controller identity epoch, identity revision, policy
revision, topology revision, flow-history revision, and current Pod topology under
the policy-state read fence. It evaluates
every current Pod as a source against destinations selected by either the existing
or candidate policy. Probe tuples include concrete ports referenced by current and
proposed policy, resolved named ports, bounded range members, and one unmatched TCP
and UDP port for wildcard/default behavior. The complete matrix is limited to
10,000 flows; larger requests fail explicitly instead of returning partial counts.

Response schema v2 reports
remain-allowed, remain-denied, would-be-allowed, and would-be-denied counts;
verdict and full-decision change counts; affected workloads; and each changed
flow with current/proposed provenance. `unfctl policy simulate <file>` exposes the
API in table, JSON, or YAML form. It also evaluates the bounded ADR 0012 history,
reports observation-weighted impact and unresolved-flow skips separately, and
identifies Services affected through selector intent or ready EndpointSlice Pod
backends. Schema v1 was the representative-matrix-only foundation.

## Alternatives

Applying a temporary shadow CRD would mutate live desired state and revisions.
Implementing simulation in the CLI would duplicate policy semantics and require
shipping topology and policy state to the client. Evaluating only candidate rule
ports would miss default-action changes. Calling topology probes historical flows
would overstate evidence; schema v2 keeps the two sources separate.

## Consequences

Simulation provides deterministic, read-only what-if evaluation against identified
live topology and history snapshots and uses exactly the same IR/evaluator as
enforcement. The topology matrix is representative for wildcard/default ports
rather than an enumeration of all 65,535 ports. History remains bounded,
process-local, and without time-window filtering; external sources without a
current identity and user-supplied flow sets cannot yet be evaluated.
