# ADR 0315: Phase 9 Rollout Staging Fault Guard

Date: 2026-09-13

Status: local gate and retained cl02 observation replay verified; next rollout pending

## Decision

ADR 0314 exposed a deployment containment gap: the pre-attachment management
API was reachable before the candidate failed kernel loading. Check every
current candidate-image agent before a Node transition, during replacement
and staging polling, and before writing successful deployment evidence.
Reject container restarts, current/prior termination, terminal Pod phases,
deletion and fatal waiting states. An unsuccessful API/JSON observation also
stops the rollout instead of implying health. Both agent and installer
container statuses participate.

Pending or Running-but-not-Ready is still permitted during staging: the exact
fleet barrier can require every replacement member to join before attachment.
Do not turn readiness into an impossible serial-admission prerequisite. The
existing full-convergence exit check remains mandatory. This polling guard
does not promise that a later failure can never overlap another transition;
isolated platform kernel loading remains necessary before rollout.

## Verification

The new gate accepts healthy pending and pre-admission states, scopes checks
to the candidate image, and rejects eleven malformed/failure mutations. Replay
of the actual failed cl02 Pod snapshot rejects `5505d00`; the restored previous
image snapshot passes. The complete Phase 9 OpenShift gate suite passes.
No runtime source/image, timeout, Pod liveness probe or admission barrier is
changed by this deployment-only milestone.
