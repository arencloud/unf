# ADR 0086: Cluster NodePort dataplane

- Status: Accepted
- Date: 2026-08-30
- Phase: 5.4

## Context

ADR 0085 made local NodePort frontends durable and transactionally coherent with
the ClusterIP backend bank, but no packet hook consumed them. Phase 5.4 must add
host-facing forwarding without allowing an independently switched Node-address
bank to reference stale service state, weakening NetworkPolicy ordering, or
silently treating `externalTrafficPolicy: Local` as `Cluster`.

## Decision

On an ingress ClusterIP miss, the TC program may consult the active NodePort
bank only when its schema, epoch, service revision, Node revision, bank, flags,
and reserved bytes are valid. An exact IPv4 or IPv6 Node-address, destination
port, protocol, and active-bank key must exist. Its value must reference the
currently active service bank and revision.

A valid `Cluster` value is projected into the existing service-frontend path.
The established hash-slot selection, ready/non-terminating backend validation,
connection pair, timeout, checksum rewrite, reverse translation, and bounded
service event are reused. Forward packets are also source-translated to the
receiving Node address and a deterministic high port. Up to 32 atomic
`BPF_NOEXIST` probes prevent a colliding reverse tuple from being overwritten;
exhaustion drops the new flow. The original client and NodePort frontend remain
in the connection value. Replies restore both tuples on the ordinary egress
hook for a local backend or on the receiving Node's ingress hook after a remote
backend routes the packet back to the Node SNAT address.

The policy observation retains the original external source while using the
post-DNAT destination. NetworkPolicy therefore evaluates that source against the
selected workload backend identity and backend port.
An exact `Local` value is recognized but dropped; it cannot fall through to
Cluster selection. Phase 5.5 owns the separate node-local and source-preserving
semantics.

## Verification

`make nodeport-cluster-dataplane-test` builds and verifier-loads the eBPF object,
retains the complete ClusterIP packet regression, and executes NodePort packets
through the kernel for IPv4/IPv6 TCP/UDP. It checks forward and reverse address,
port, transport checksum, IPv4 header checksum, Node source translation and
egress/remote-ingress reverse client restoration, forced source-port collision probing, connection
persistence through backend replacement, new-flow reselection, backendless
drop, unrelated-port pass-through, and non-broadening of `Local`.

The test activates an external-source ingress deny for the backend identity and
port. The packet reaches the Node address and NodePort but is denied with a flow
event containing the translated backend tuple and policy provenance. Service
events retain the exact Node frontend tuple and nonzero service, backend, and
revision provenance. The stable hash unit gate covers all family and port input
dimensions.

## Consequences

- No persistent-map ABI change is required; Phase 5.3 already introduced the
  NodePort maps in ABI v5.
- Existing translations intentionally survive desired-state revision churn;
  new connections use the newly active service bank.
- Service event schema still describes a generic frontend tuple. Explicit
  NodePort classification in metrics, status, history, explanation, and
  simulation belongs to Phase 5.6.
- Kernel packet execution proves the program and map contract, but live host
  attachment, routing, kube-proxy-free lifecycle, and platform recovery remain
  Phase 5.7 Kind and Phase 5.8 OpenShift gates.
