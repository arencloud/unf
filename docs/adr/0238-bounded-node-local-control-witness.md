# ADR 0238: Bounded Node-Local Control Witness

## Status

Accepted

## Context

The cl02 gate's causal generation loop had an outer retry count, but each
`oc exec` used to inspect Node-local state could wait indefinitely in the
Kubernetes streaming transport. The apparent timeout was therefore not a real
wall-clock bound. During a Required-baseline transition, API-server Pod proxy
requests to the controller could also depend on the dataplane whose readiness
the request was intended to establish. A slow or denied stream could obstruct
its own proof and leave failure diagnostics hanging.

## Decision

Every streaming `exec`, log collection, and direct Pod-proxy version read in
the Phase 9 OpenShift gate receives an explicit process timeout. A timeout is
an unavailable observation, never affirmative evidence; the surrounding
bounded convergence loop may retry it.

Controller state used by the causal join is read through the already-required
stable host-network witness on the controller's current Node. That witness
contacts `127.0.0.1:9962`, so the observation does not cross UNF-managed Pod
routes, Services, or the encryption finalizer. The controller Pod-to-Node
placement and witness Pod are resolved afresh for every sample, preserving
replacement correctness without creating new observer Pods.
After the witness has been exactly deleted, only the final Native-baseline
agent-convergence read may use the former bounded API-server Pod proxy; no
causal generation join or Required/selective stage can reach that fallback.

## Consequences

- A declared readiness bound now includes individual Kubernetes streaming
  operations instead of merely counting loop iterations.
- Required dataplane convergence cannot block observation of the controller
  state needed to prove that same convergence.
- Missing, moved, slow, or unreachable witnesses fail closed and remain
  diagnosable; no cached state is treated as current.
- This changes qualification only. Runtime revision and the ADR 0237 image
  tuple remain byte-for-byte unchanged.
