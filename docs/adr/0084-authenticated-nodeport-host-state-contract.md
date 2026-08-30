# ADR 0084: Authenticate NodePort host state before runtime activation

Status: Accepted and implemented for Phase 5.3a

## Context

NodePort exposure combines two independently changing inputs: cluster-wide
Service/backend state and addresses owned by the local Kubernetes Node. Reusing
the verified ClusterIP activation pointer would make a Node address update churn
all backend maps. Trusting an agent-supplied node name or host address would also
allow one node to request another node's host-facing state.

The runtime hook, map mutation, durable agent recovery, and packet behavior are
not yet implemented. A fixed admission and lowering contract is required before
those operations can safely begin.

## Decision

The controller derives NodePort address intent only from Kubernetes Node
`InternalIP` and `ExternalIP` status records. The Node must have an authoritative
UID and at least one usable address. Unspecified, loopback, multicast, IPv4
broadcast, link-local, duplicate, malformed, and over-limit inputs fail closed.
Canonical state is bounded to 64 addresses.

The internal TLS endpoint `/v1/state/node-port-node` uses the existing
TokenReview authentication and returns only the Node whose name is bound to the
calling agent's service-account identity. It never accepts a node name from a
query or request body. Each node has an independent nonzero revision. Semantic
no-ops and unchanged watch relists retain that revision; changes advance it;
invalid updates retain last-valid state; completed relists retire absent nodes.
The snapshot also carries the controller epoch, Node UID, and schema version 1.

The fixed eBPF ABI defines separate IPv4 and IPv6 NodePort frontend keys, a
32-byte frontend value, and a 40-byte activation record. The compiler takes a
validated service snapshot, the authenticated local-node snapshot, the active
ClusterIP service bank, and an inactive NodePort bank. It emits exact
address/port/protocol keys and values containing Service ID, frontend index,
eligible-backend count, service revision, traffic-policy flag, and referenced
service bank. Epoch skew, invalid banks, invalid linkage, and per-family capacity
overflow fail before activation.

NodePort has an independent two-bank activation pointer. This lets a node-only
address change switch host-facing state without rewriting ClusterIP maps. A
future service transition must stage both families against the new service bank,
read them back, activate the service bank, then activate the NodePort pointer;
rollback must preserve the previously coherent pair.

No BPF maps are declared and no agent mutation or packet hook consumes this
contract in Phase 5.3a. `externalTrafficPolicy: Local` is preserved as a flag,
but node-local backend eligibility and source preservation remain Phase 5.5.
The existing ClusterIP lowerer continues to reject any NodePort intent.

## Consequences

- A compromised or misconfigured agent cannot select another Node's host state.
- Controller watch relists cannot reuse one epoch/revision tuple for changed
  content.
- Node address churn and Service/backend churn have separate activation domains.
- Fixed sizes and capacity limits are testable before privileged map creation.
- Phase 5.3 remains in progress until agent polling, inactive-bank mutation,
  readback, atomic activation, rollback, durable recovery, and cleanup pass a
  real-map fault gate.

## Verification

`make nodeport-host-state-test` exercises authenticated scope construction,
revision/relist/last-valid behavior, bounded node intent, fixed ABI sizes,
dual-stack lowering, traffic-policy typing, bank linkage, capacity validation,
strict Clippy, schema compatibility prerequisites, and every supported
deployment render.
