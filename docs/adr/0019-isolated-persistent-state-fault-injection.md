# ADR 0019: Isolated persistent-state fault injection

Status: Accepted for Phase 2 recovery validation

## Context

The agent validates the all-or-none pinned map set, map capacities, value schemas,
active configuration pointers, entry counts, and active-bank revisions before
adopting last-known-good state. Unit tests exercised the decoders, but the kind
gate only demonstrated successful recovery. Directly corrupting an active map to
test rejection would change the classifier's live inputs and could itself create
the enforcement gap the recovery design is intended to prevent.

A permanent dataplane startup error also left the agent API alive and NotReady
indefinitely. Kubernetes could not retry automatically after an operator repaired
the persistent state.

## Decision

The kind verifier deploys a short-lived, privileged test helper only in the
disposable cluster. The helper mounts bpffs and creates fault directories below
`/sys/fs/bpf/unf/fault-tests-v2`. Unmodified maps are pinned into those directories
as aliases to the real objects; the deliberately faulted map is omitted or
created as an isolated replacement. The production `/sys/fs/bpf/unf/v2` pin set
is never renamed, deleted, or mutated.

Three secondary-agent startup probes are required:

- an eight-of-nine pin set must fail with the partial-set diagnostic;
- a cloned `POLICY_CONFIG` containing an invalid committed pointer must fail the
  active-config validation;
- a replacement `POLICY_RULES` containing structurally invalid debris in the
  inactive bank must fail value validation before adoption.

Each probe runs the exact deployed agent and eBPF object on the target node. It
must exit nonzero and expose the expected actionable cause. The verifier then
rechecks the established allowed and denied flows through the untouched primary
agent, deletes the scoped aliases and helper, and proceeds to the existing
offline-controller replacement test.

Permanent dataplane task failure now cancels the agent API and terminates the
process after readiness is fenced. Kubernetes can therefore apply its normal
restart backoff and retry after the underlying state is repaired. Intentional
process shutdown remains graceful.

## Consequences

Recovery rejection is now kernel-level integration evidence rather than only
decoder unit coverage, without risking the active last-known-good state. The
test helper is intentionally privileged because bpffs mutation requires it; it
is an explicit example fixture and is not part of the production kustomization.

These scenarios validate structural recovery boundaries without altering the
primary maps. Physical inactive-bank exhaustion and transactional rollback are
covered separately by ADR 0020.
