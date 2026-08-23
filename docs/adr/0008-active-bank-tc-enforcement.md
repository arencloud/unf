# ADR 0008: Active-bank TC enforcement and fail-open bootstrap

Status: Accepted for the Phase 2 enforcement gate

## Context

Agents already activate complete policy revisions transactionally, but TC must
consume them without admitting partially staged or schema-incompatible state.
Shadow evaluation must remain non-blocking. The project also needs an explicit
bootstrap and invalid-state behavior rather than an accidental default.

## Decision

For a flow with two known identities, TC copies `POLICY_CONFIG[0]`, validates its
schema, bank, and nonzero revision, then looks up the exact identity/protocol/port
key. If absent, it tries the identity-pair wildcard key. A value is usable only
when its schema and revision match the copied config and its provenance flags are
consistent with its reason.

A validated actual deny returns `TC_ACT_SHOT`; all other outcomes return
`TC_ACT_PIPE`. Shadow fields are copied into telemetry but never influence the TC
action. Flow ABI v2 records the applied revision and both actual and shadow
provenance. Ring-buffer reservation failure does not change the computed action.

The initial overlay fails open for unknown identities, missing/incompatible
config, missing entries, and malformed values. It reports revision zero with an
observed or identity-unknown reason. An already active valid bank remains usable
during controller interruption.

## Alternatives

Failing closed during bootstrap would turn controller/agent startup ordering into
a cluster outage risk before durable last-known-good state exists. Reading the
staging bank would expose partial revisions. Treating shadow deny as an actual
deny would violate the API contract. Re-evaluating selectors in BPF would expand
the verifier surface and duplicate userspace semantics.

## Consequences

Phase 2 can enforce deterministic IPv4 TCP/UDP identity decisions and correlate
events with the exact applied revision. The fail-open choice is suitable only for
incremental prototype adoption: agent restart recreates unpinned maps, unknown
traffic is allowed, and node status is not aggregated. Production fail-closed or
graceful-degradation behavior requires pinned last-known-good maps, explicit
readiness fencing, and failure-injection tests.
