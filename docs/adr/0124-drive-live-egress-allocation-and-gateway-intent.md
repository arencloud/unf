# ADR 0124: Drive live egress allocation and gateway intent

**Status:** Accepted and implemented for the Phase 8.5 live control-plane slice

## Context

The watched native and OpenShift-compatible desired model was durable, and the
allocation and gateway registries were independently verified, but no live
transaction joined them. Consequently the controller could only distribute
manually constructed test contracts. Directly treating a watched address or a
Ready Node as usable would collapse allocation, gateway application,
reachability, source application, and publication into one unsafe signal.

## Decision

`EgressControlPlane` atomically reconciles one canonical desired revision into
the allocator and gateway registry. It validates exact explicit-provider
ownership, allocates bounded pool or explicit addresses, and emits lease-fenced
gateway Ensure state over a canonical set of Ready, primary-CNI-enabled Nodes
with authoritative UIDs. This ordering is deterministic input only; it makes no
HA placement-quality claim.

The schema-v1 checkpoint binds the desired revision and normalized model to the
complete allocation and gateway checkpoints. Restore rejects unsupported,
noncanonical, or cross-domain-incoherent state. Pool additions and unleased
changes are transactional. A removed pool definition remains as a tombstone
while one of its leases is fenced.

Intent removal or immutable address/provider change produces Withdraw before
release. The allocator retains every address until both the gateway-host and
reachability providers acknowledge the exact withdrawal. Only then may the
record be removed and the address reused with a greater lease epoch. Missing
gateway candidates retain a valid allocation but create no gateway state.

The controller reconciles after accepted desired-model and Node changes. It
persists the watched checkpoint before the derived control-plane checkpoint in
one ordered persistence loop, so a crash may leave derivation behind but never
durably ahead of its authority. Restart validates that ordering and safely
reconciles a lagging derived checkpoint forward.

## Consequences

Live Kubernetes intent now creates durable allocation and gateway desired
state, and Node loss or intent deletion drives explicit fenced withdrawal. It
does not configure an address, assert provider readiness/reachability, build a
source contract, acknowledge agent application, activate maps, change routes,
or process packets. Those signals remain independent by design.

`make egress-control-plane-test` inherits every prior Phase 8.5 gate and adds
domain atomicity, deterministic ordering, candidate absence, exact restart,
revision rejection, dual-ack withdrawal/reuse, controller watch integration,
deployment/RBAC assertions, and strict Clippy.
