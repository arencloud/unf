# ADR 0082: Add an address-family-aware NodePort domain boundary

Status: Accepted and implemented for Phase 5.1

## Context

Phase 4 qualified a bounded dual-stack ClusterIP fabric, but NodePort is a
different exposure surface. A ClusterIP frontend owns one virtual address,
whereas a NodePort is reachable through eligible Node addresses and must later
respect source-preservation and `externalTrafficPolicy` behavior. Encoding a
NodePort as a synthetic ClusterIP would lose that distinction and make later
host-facing attachment, policy, observability, and multi-cluster decisions
unsafe.

The Kubernetes Service watcher already retained the Service type for topology,
but the platform-neutral service compiler intentionally discarded `nodePort`
and `externalTrafficPolicy`. Extending the snapshot changes the controller-agent
wire contract and must not be silently accepted by the Phase 4 dataplane.

## Decision

Service snapshot schema v2 adds a separate `ServiceNodePort` collection to each
service. One record represents one address family and carries:

- IPv4 or IPv6 family;
- allocated NodePort and linked ClusterIP Service port;
- TCP, UDP, or SCTP protocol intent;
- optional port name and appProtocol;
- explicit `Cluster` or `Local` external traffic policy; and
- the exact same-family backend IDs selected for that Service port.

The compiler derives one record per configured family from the API-allocated
`ServicePort.nodePort`. It does not hard-code the API server's configurable
allocation range; it requires a nonzero `u16` value. The controller defaults an
omitted external policy to `Cluster`, preserves `Local`, and rejects unknown
values. Headless Services remain outside this first boundary because the
compiler still requires a concrete ClusterIP frontend to establish exact
family and Service-port linkage.

Normalization is deterministic and bounded. It rejects duplicate family/port/
protocol records inside one Service, port/protocol ownership by multiple
Services, absent exact ClusterIP linkage, unknown or repeated backend IDs,
backend family/protocol mismatch, invalid provenance, and aggregate capacity
overflow. Backend references count against the existing global reference bound;
NodePort frontends have an independent 131,072-entry bound.

Schema v2 is an explicit compatibility break from the Phase 4 schema-v1 release.
The existing ClusterIP eBPF lowerer rejects every nonempty NodePort collection
with an actionable error. Phase 5.2 must define and test the controller-first
schema transition and agent distribution boundary before any rollout. Later
slices must derive exact Node-address frontends from authenticated Node intent,
add transactional host-facing maps, and separately implement `Cluster` and
`Local` forwarding semantics.

## Verification

`make service-ir-test` and focused controller tests require:

- deterministic dual-stack NodePort compilation;
- exact family, NodePort, Service port, name, appProtocol, protocol, policy, and
  backend preservation;
- cluster-wide NodePort/protocol collision rejection;
- inexact frontend linkage rejection;
- Kubernetes `NodePort` and `externalTrafficPolicy: Local` translation;
- unknown traffic-policy rejection; and
- explicit rejection by the Phase 4 ClusterIP dataplane compiler.

Strict Clippy covers the changed common, service, controller, and consumer
surfaces. Service snapshot schema v2 is exposed through the existing component
compatibility tuple, so mixed schema-v1/v2 binaries cannot claim compatibility.

## Consequences

Phase 5.1 can carry and explain NodePort intent without pretending to forward
host traffic. Node-address ownership, host-network ingress hooks, source
preservation, local endpoint selection, health-check NodePorts, SCTP dataplane,
LoadBalancer exposure, session affinity, topology-aware selection, Maglev, DSR,
and cluster qualification remain unimplemented until their tracked slices pass.
