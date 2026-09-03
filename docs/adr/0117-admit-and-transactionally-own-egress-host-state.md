# ADR 0117: Admit and transactionally own egress host state

**Status:** Accepted and implemented for Phase 8.4

## Context

Phase 8.3 can allocate addresses and accept independent gateway-readiness and
reachability acknowledgements, but an agent must not consume those controller
facts directly. A response for another Node, an overstated capability, a stale
controller epoch, or a crash between host-state staging and durable commit
could otherwise activate an unverifiable egress path. Egress state must also
remain isolated from the already verified policy, Service, NodePort, and
LoadBalancer transactions.

## Decision

The controller-side domain receives an `AuthenticatedEgressAgent` only after
the existing audience-scoped, Pod-bound `TokenReview` and authoritative
Pod/Node checks. Schema-v1 distribution binds the resulting Node name and UID,
controller epoch, projection revision, exact behavior contract, and the
agent-advertised capabilities. Distribution and host-state schemas negotiate
explicitly. Selected egress has no schema-zero fallback: an incompatible agent
fails closed instead of silently using native egress.

The agent admits a projection only after rebinding it to its local authenticated
principal, comparing the complete negotiated capability set, and independently
replaying the Phase 8.2a contract against the normalized model and all six fact
domains. The resulting `AdmittedEgressProjection` is the only input accepted by
the host-state compiler. A monotonic ledger permits byte-identical replay and
rejects epoch/revision regression or mutation at an accepted tuple.

Gateway host state uses a domain-separated schema-v1/ABI-v1 commitment over the
complete verified behavior contract, not reconstructed metadata. It is owned in
two independent userspace banks behind `EgressHostStateStore`. The transaction:

1. verifies current pointer/checkpoint/readback agreement;
2. writes and exactly reads back the inactive bank;
3. prepares and reads back a strict pending checkpoint;
4. switches the active pointer;
5. commits the pending checkpoint; and
6. retires the previous bank after commit.

Any failure before activation preserves the active bank. A checkpoint failure
after activation rolls the pointer back; inability to prove rollback returns an
explicit recovery-required state. Startup uses only the active pointer plus
exact current/pending evidence: it commits a prepared winner, retains the
current winner, reconstructs a missing winning bank, or fails closed on
ambiguity. Cleanup refuses unknown versions and removes only ABI-v1 banks and
checkpoints.

The storage trait is the boundary for the agent's persistent-map and mode-0600
checkpoint adapter. Phase 8.4 verifies the protocol and reference state machine;
the live HTTP loop, filesystem/map adapter, and agent status fields are added
with the first consumable dataplane in Phase 8.5 so an empty placeholder
endpoint cannot be mistaken for functioning egress.

## Consequences

- Authentication, schema negotiation, contract replay, host activation, and
  recovery are separate fail-closed checks.
- A different Pod cannot select another Node, and a Node cannot acknowledge a
  capability it did not advertise.
- Checkpoint or inactive-bank mutation cannot become active through recovery.
- Egress host state cannot alter existing policy or service banks.
- The host ABI is userspace-only. This milestone adds no Kubernetes/OpenShift
  watcher, CRD/RBAC, live address/route, filesystem/map adapter, BPF map,
  steering, NAT, packet, availability, or platform qualification claim.
- `make egress-host-state-test` is the repeatable milestone gate.
