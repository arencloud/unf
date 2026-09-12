# ADR 0260: Cut-Fenced Single-Flight Authority Admission

## Status

Accepted for Phase 9.9 implementation and requalification

## Context

The cl02 gate rejected the ADR 0259 tuple even though its public readiness
barrier worked. OpenShift primary-CNI bootstrap intentionally gives every
host-network agent a `hostAliases` entry for
`unf-primary-controller.internal`, resolving directly to the controller Node
address. Internal TLS traffic on port 9964 therefore does not traverse the
controller Service or its EndpointSlice readiness.

The gate restored Native after the first failure and repeated the observation
under a recovery hold. Releasing all five agents OOM-killed the controller.
Releasing one agent after a complete informer cut still produced an OOM kill.
The remaining failure is overlapping materialization from one agent's
independent identity, policy, service, egress, encryption, and status loops;
it is neither an incomplete informer cut nor five-agent steady-state load.

## Decision

The controller enforces a **Cut-Fenced Single-Flight Authority Admission**
boundary on the host-network internal API itself:

1. Every internal request receives `503 Service Unavailable` until the fixed
   authoritative informer mask is complete. Direct bootstrap and Service
   traffic now share the same admission truth.
2. Exactly one internal authority request may materialize at a time. A
   nonblocking one-permit semaphore rejects concurrent requests immediately
   instead of retaining an unbounded waiter or allocation queue. Agents retry
   from their independent anti-entropy loops and preserve last-known-good
   kernel state.
3. Every informer `Init` and `InitDone` advances a monotonic cut revision. The
   middleware captures that revision after admission and discards the response
   if readiness or the revision changes before materialization finishes. A
   response can therefore never publish across an informer-cut transition.

This is constant-space overload control: one materialization, zero queued
authority work, one fixed informer mask, and one atomic cut revision. It adds
no BPF ABI or wire-schema change and is enabled unconditionally.

## Consequences

- Direct host-network bootstrap no longer bypasses readiness.
- Synchronized retry herds shed load with a bounded 503 response instead of
  multiplying peak RSS.
- Large immutable snapshots cannot overlap in controller memory, while agents
  converge eventually through existing retries.
- A completely fresh Kind lifecycle, new public immutable images, preserved
  cl02 deployment, and the complete platform gate are mandatory. The
  controller must stay within 2 GiB during one-agent and five-agent cold
  admission before Phase 9.9 can close.
