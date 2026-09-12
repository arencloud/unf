# ADR 0262: Causal Startup Admission Retry

## Status

Accepted for Phase 9.9 implementation and requalification

## Context

The ADR 0261 cl02 transition proved that Cut-Fenced Single-Flight Authority
Admission prevents the controller OOM: five cold agents converged while its RSS
remained 136 MiB and restart count remained zero. The official node-serial
rollout then replaced the agent colocated with the controller. Its node-block
request correctly retried transient `403`/`503` admission, but its immediately
following encryption identity preflight made only one request. A controller
`503` was fatal even though it represented intentional bounded backpressure.

Kubelet restart backoff is not a useful authority protocol. It obscures the
causal retry budget, delays readiness, and can starve a replacement behind the
steady agents whose authenticated anti-entropy work remains valid.

## Decision

The agent applies one **Causal Startup Admission Retry** contract to both
pre-persistent-BPF authority reads:

1. `403 Forbidden` and `503 Service Unavailable` mean current Pod authority is
   not yet admitted or the controller's one materialization permit is busy.
2. The agent retries at one-second intervals for the existing bounded 120-call
   startup budget. It keeps TC attachment and persistent BPF access fenced for
   the entire interval.
3. Authentication failures other than the explicitly transient `403`, invalid
   payloads, and an exhausted budget remain fatal and fail closed.
4. Transport outage retains the separately qualified last-known-good offline
   recovery behavior; it is not reclassified as admission backpressure.

The retry holds no controller permit, creates no client-side work queue, and
mutates no key, route, map, or durable encryption state before a verified
bootstrap arrives. The implementation reuses one status/attempt predicate so
node-block and encryption preflight cannot drift again.

## Consequences

- A replacement Pod responds to the controller's intentional load shedding
  inside its own explicit causal budget instead of delegating retry to kubelet.
- Controller work remains one materialization with zero queued requests; agent
  memory and retry state remain constant.
- Exhaustion is visible and fatal rather than silently admitting stale or
  unauthenticated authority.
- Focused agent tests, full workspace validation, a new completely fresh Kind
  lifecycle, new immutable images, and the complete cl02 gate are mandatory.
