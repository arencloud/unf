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

Response schema v3 reports
remain-allowed, remain-denied, would-be-allowed, and would-be-denied counts;
verdict and full-decision change counts; affected workloads; and each changed
flow with current/proposed provenance. `unfctl policy simulate <file>` exposes the
API in table, JSON, or YAML form. It also evaluates the bounded ADR 0012 history,
reports observation-weighted impact and unresolved-flow skips separately, and
identifies Services affected through selector intent or ready EndpointSlice Pod
backends. An optional nested `flow_history` request selects aggregate entries by
inclusive `since_unix_ms`/`until_unix_ms` bounds and a newest-first limit from 1
through 4,096. The response includes matched and returned flows, matched
observations, applied bounds, and truncation state. Omitting the selector preserves
the schema-v2 behavior of evaluating the complete retained set; schema v1 was the
representative-matrix-only foundation.

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
rather than an enumeration of all 65,535 ports. ADR 0030 makes the newest bounded
history restart-durable; schema v3 applies its exact last-received-time query
contract to historical impact without changing topology evaluation. Because flow
entries aggregate observations, a matching entry can include observations older
than the window. External sources without a current identity and user-supplied
flow sets cannot yet be evaluated.

ADR 0040 subsequently extends request/response schema v4 to Kubernetes
`NetworkPolicy`, adds source-selected dual-stack egress matrix evaluation, and
retains the same read-only revision fence.
