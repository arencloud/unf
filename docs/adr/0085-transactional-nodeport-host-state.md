# ADR 0085: Activate NodePort host state as a recoverable dual-bank transaction

Status: Accepted and implemented for Phase 5.3

## Context

ADR 0084 fixed the authenticated local-Node input and host-map ABI without
declaring maps or allowing an agent to mutate them. Runtime ownership adds three
persistent maps to the 18-map Phase 4 set. Treating those additions as ABI v4
would make a legitimate old set indistinguishable from a corrupt partial new
set. Service and Node addresses also advance independently, while each NodePort
frontend must reference one exact ClusterIP service bank.

## Decision

Persistent BPF-state ABI v5 owns 21 all-or-none pins below
`/sys/fs/bpf/unf/v5`. It adds `NODE_PORT_FRONTENDS_V4`,
`NODE_PORT_FRONTENDS_V6`, and `NODE_PORT_CONFIG`. ABI v4 remains an explicitly
recognized 18-map cleanup boundary and is never opened as v5. A v5 rollout uses
the established parallel-directory clean-rebuild model; it does not mutate or
delete qualified v4 state automatically.

The dataplane agent retrieves the service snapshot first. It requests the
TokenReview-scoped local-Node snapshot only when NodePort intent exists, then
requires the returned Node name and controller epoch to match the authenticated
agent and service state. Same-epoch revision regression or mutation without a
revision change fails while applied state remains selected.

Service changes stage and read back the inactive ClusterIP and NodePort banks.
The NodePort values name the new service bank. The agent prepares one owner-only
composite checkpoint, activates `SERVICE_CONFIG`, activates
`NODE_PORT_CONFIG`, and atomically renames the checkpoint. A Node-address-only
change stages and switches only the NodePort bank, leaving the service pointer
and all ClusterIP maps unchanged. Removing the last NodePort activates an empty
NodePort config without requiring Node-address availability.

Every pre-commit failure restores both destination banks, both activation
pointers, the prior checkpoint, and pending-file state. Startup reconstructs
both banks from kernel maps, validates every fixed-layout entry and capacity,
and recompiles the active tuple from the durable checkpoint. A crash after both
pointers but before rename commits the matching prepared checkpoint. A crash
between the two pointers verifies both old and new banks, restores the prior
service pointer, clears the abandoned staging banks, and retains the prior
checkpoint before any TC program attaches.

Only TCP and UDP NodePort records lower into host maps. Other Kubernetes Service
protocol intent remains representable in schema v2 but fails explicitly at this
dataplane boundary. The eBPF program declares and persists the maps but does not
read them in Phase 5.3; packet behavior begins only with Phase 5.4.

## Consequences

- v4 and v5 have unambiguous ownership and cleanup rules.
- Address churn cannot disturb active ClusterIP connections or map banks.
- No restart can accept maps that do not exactly match a durable
  service/Node/revision/bank tuple.
- The dual-pointer window has an explicit deterministic crash repair path.
- Downgrade across v5 requires the clean-rebuild workflow; same-ABI source
  rollback remains a separate compatibility claim.

## Verification

`make nodeport-transaction-test` runs the schema/distribution prerequisites,
composite checkpoint and transition tests, ABI v4/v5 cleanup tests, strict
Clippy, the release eBPF build, and privileged real-kernel-map tests. The kernel
tests prove partial NodePort capacity rollback, complete activation,
address-only bank switching without a service-pointer change, restart recovery,
rollback of a crash between pointers, commit recovery after both pointers, and
the existing ClusterIP packet regression.
