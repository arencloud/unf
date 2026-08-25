# ADR 0023: Pod-bound agent acknowledgement authentication

Status: Accepted and live verified for Phase 2 acknowledgement integrity

## Context

Freshness-aware agent reports drive cluster convergence status, but schema v1
accepted any syntactically valid HTTP request. A workload able to reach the
controller could forge a Node name and applied revision, making an unauthenticated
report appear converged. A static shared secret would add rotation and distribution
work while still allowing any holder to impersonate every Node.

Kubernetes already issues short-lived, automatically rotated, Pod-bound
service-account tokens and provides the TokenReview API for their validation.

## Decision

Agent acknowledgement schema v2 adds the reporting Pod name and UID. The agent
DaemonSet disables automatic API-token mounting and explicitly projects one token
with audience `unf-controller.unf-system.svc`, a one-hour lifetime, and no API
audience. The agent rereads the token file for every report so kubelet rotation
does not require a process restart, sends it as a bearer credential, and never
logs its contents.

The controller's `unf-controller` ClusterRole may create TokenReviews. Before
validating or storing a report, the controller requires all of the following:

- TokenReview authenticated the dedicated audience;
- the username is exactly `system:serviceaccount:unf-system:unf-agent`;
- the token's bound Pod name and UID exactly match schema v2;
- the watched `unf-system` Pod has that UID and service account; and
- authoritative Pod placement matches the reported Node name.

Missing and invalid credentials return 401, authenticated identity/placement
mismatches return 403, and an unavailable TokenReview dependency fails closed
with 503. Rejections never update convergence state and increment
`unf_agent_authentication_failures_total`. Offline controller mode has no
TokenReview client and therefore cannot accept agent reports.

## Verification

Unit tests cover strict bearer parsing plus audience, service-account, Pod, and
cross-Node binding. The two-node kind gate requires schema v2 convergence from
both deployed agents, rejects an anonymous request, rejects an invalid token,
accepts the actual projected Pod token, rejects that valid token with a forged
Node claim, and checks rejection accounting. Later offline-controller agent
replacement also obtains a new Pod-bound credential and reconverges after the
controller returns.

## Consequences

No static credential is checked into manifests or distributed by UNF, and one
agent Pod cannot use its valid token to claim another Node. Token rotation and
revocation follow Kubernetes service-account behavior.

This secures acknowledgement identity, not transport confidentiality. The
prototype controller endpoint remains internal HTTP, so bearer tokens and state
traffic require an encrypted transport boundary before production use. Identity
and policy snapshot reads and flow telemetry authentication are also outside this
decision. Native OpenShift validation must confirm projected audience tokens,
TokenReview extras/RBAC, SCC behavior, and the eventual encrypted service path.
