# ADR 0075: Kubernetes service compilation retains last-valid fabric intent

Status: Accepted and implemented for controller compilation

## Context

ADR 0074 established a Kubernetes-independent service IR but deliberately did
not translate watched Services and EndpointSlices. Translation must not leak
Kubernetes resource versions into semantic revisions, silently combine IPv4 and
IPv6 backends, lose named-port or lifecycle provenance, or replace known-good
intent when one source becomes malformed or ambiguous.

## Decision

`unf-service` accepts provider-neutral Service and EndpointSlice source records.
The controller is the Kubernetes adapter: it normalizes ClusterIPs, Service
ports, EndpointSlice address families, resolved endpoint ports, appProtocol,
workload/Node/zone provenance, and ready/serving/terminating conditions before
calling the domain compiler.

Service and backend IDs use separate FNV-1a provisional namespaces over
length-delimited canonical keys. Service keys contain namespace/name; backend
keys contain the Service key, address, resolved port, and protocol. Numeric IDs
are admitted through collision registries, and a different canonical owner of
an occupied ID rejects the complete candidate snapshot. These IDs are stable
prototype identities, not permission to skip collision admission in later
controller or agent state.

Each ClusterIP and Service port creates one exact frontend. Endpoint ports match
only the same optional name and protocol. Frontends reference only same-family
backends. Headless Services are omitted; a ClusterIP frontend with no backend is
valid and explicit. Equivalent duplicate endpoints merge their sorted
EndpointSlice provenance, while conflicting lifecycle or placement provenance,
duplicate frontend ownership, family lies, unresolved matching ports, invalid
protocols, and bounded-IR violations reject the candidate.

The controller advances service revision only on semantic source changes. A
successful compile atomically replaces its userspace snapshot. Source-admission
or whole-snapshot compilation failure retains the previous valid snapshot and
appears in controller status alongside observed, compiled frontend/backend, and
compiled-revision counts. Kubernetes resource-version-only churn changes
neither topology nor service revision.

## Verification

`make service-compiler-test` runs 14 common/service tests, focused controller
Service collision/last-valid/status and EndpointSlice lifecycle/rejection tests,
and strict Clippy. The tests cover deterministic input-order independence,
dual-stack family separation, exact TCP/UDP named-port resolution, appProtocol
and lifecycle provenance, backendless and headless behavior, equivalent-slice
merge, conflicting provenance, explicit collision admission, controller status,
and resource-version non-regression.

## Consequences

Phase 4.2 is Verified. This decision creates no agent endpoint, compatibility
claim, BPF map, packet translation, backend-selection policy, connection state,
or kube-proxy replacement. Phase 4.3 must distribute the same validated snapshot
with authentication, epoch/revision fencing, desired/applied/error reporting,
and durable last-known-good recovery before any service map ABI is accepted.
