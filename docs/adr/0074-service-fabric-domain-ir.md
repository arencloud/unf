# ADR 0074: Service fabric starts with a bounded provider-neutral domain IR

Status: Accepted and implemented for the domain contract

## Context

UNF now owns a bounded dual-stack primary-CNI path, but Service traffic still
depends on the platform kube-proxy implementation. The controller already
watches Services and EndpointSlices and advances independent service/topology
revisions. Directly lowering those Kubernetes objects into eBPF maps would bind
API watch details, backend lifecycle, load-balancing algorithm, conntrack/NAT
semantics, and a persistent kernel ABI in one change.

UNF is a Universal Network Fabric powered by eBPF. eBPF is the intended local
Service fast path, while the service model must remain usable by simulation,
explanation, gateways, multi-cluster services, and future non-eBPF providers.

## Decision

`unf-common` defines distinct `ServiceId` and `BackendId` newtypes. The new
Kubernetes-independent `unf-service` crate defines schema-v1 `ServiceSnapshot`,
`ServiceIr`, `ServiceFrontend`, and `ServiceBackend` types. Snapshot state binds
one nonzero controller epoch and service revision to provenance-preserving
frontend/backend intent. Every frontend carries an explicit sorted backend-ID
set, allowing one Service's ports and protocols to resolve different targets
without duplicating or ambiguously sharing Service-wide backend selection.

Validation is deterministic and bounded. It admits at most 65,536 Services,
131,072 frontends, 262,144 total backends, and 4,096 backends for one Service.
It rejects schema mismatch, revision-zero state, reserved zero IDs, duplicate
Service IDs or namespace/name provenance, frontend ownership conflicts,
duplicate backend IDs/endpoints, unspecified/multicast addresses, zero ports,
unsupported ICMP frontends, duplicate or unknown frontend/backend references,
cross-family references, and unbounded provenance. TCP, UDP, and SCTP remain the
admitted L4 protocols.

Normalization sorts Services, frontends, and backends without discarding
readiness, serving, terminating, or Node provenance. A Service with no backends
is valid because no-backend behavior must be explicit in the later compiler and
dataplane rather than hidden as invalid control-plane input.

This slice does not assign numeric IDs, consume Kubernetes types, select a
backend, define eligibility/draining semantics, create a BPF map ABI, implement
conntrack/NAT, or replace kube-proxy. Those decisions require evidence and a
separate hook/connection-state ADR before they become persistent interfaces.

## Alternatives

Reusing topology response types would couple query presentation to an agent
wire contract. Using Kubernetes Service/EndpointSlice types in the agent would
violate the core-domain boundary. Freezing Maglev, random selection, DSR, or NAT
maps now would decide connection semantics before the first kube-proxy-free
traffic gate. A generic plugin system remains premature because there is not yet
a second service provider.

## Verification

`make service-ir-test` runs common/service unit tests and strict Clippy. Tests
prove deterministic normalization across input order, dual-stack intent,
readiness/termination retention, valid backendless state, duplicate frontend
rejection, exact same-family frontend/backend references, unsupported protocol
and zero-ID rejection, revision fencing, and strict unknown-field
deserialization.

## Consequences

Phase 4 is In progress and its first domain-contract row is Verified. The next
slice must translate the already watched Service/EndpointSlice state into this
IR with collision-checked IDs and explicit rejected-state reporting. No Service
forwarding or kube-proxy replacement claim exists until transactional agent/eBPF
state and a dedicated cluster gate pass.
