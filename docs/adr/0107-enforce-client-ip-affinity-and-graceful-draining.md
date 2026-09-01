# ADR 0107: Enforce ClientIP affinity and graceful draining

**Status:** Accepted and implemented for Phase 7.5

**Date:** 2026-09-01

## Context

The verified Phase 7.4 dataplane selects the first non-empty eligible
SameNode, SameZone, or Cluster tier, but every new flow still uses the stable
flow hash. Kubernetes `ClientIP` affinity requires flows from one original
client to reuse a backend for a bounded timeout. That reuse must never restore
an endpoint excluded by strict locality, topology, readiness, or termination.
At the same time, graceful draining requires established connections to keep
their translated tuple while new sessions stop selecting a terminating
endpoint.

## Decision

The schema-v4 Service intent remains authoritative. `None` is unchanged;
`ClientIp { timeout_seconds }` is enabled whenever a verified Network Behavior
Contract requests it. The compiler encodes one affinity bit and a timeout from
1 through 86,400 seconds into every ClusterIP, NodePort, and LoadBalancer
frontend. Unknown flags, zero/out-of-range timeouts, and nonzero reserved bytes
fail closed before lookup.

The TC dataplane owns one bounded 262,144-entry LRU `SERVICE_AFFINITY` map. Its
exact key is original client address plus frontend address, frontend port,
protocol, address family, affinity role, and active service bank; transport
source port is deliberately zero. Its compact value records last use, service
revision, stable BackendId, selected slot, selected tier, schema, and zeroed
reserved bytes.

Existing validated connections win before affinity lookup. A new flow may
reuse an affinity slot only when schema, service revision, active immutable
bank, selected tier, slot bound, and timeout all match. A service/topology or
endpoint-lifecycle transaction changes the bank or revision, so stale affinity
cannot cross into a different eligible set. Reuse refreshes last use; absence
creates affinity; an expired or structurally invalid current-bank entry is
removed and reselected through StableHash.

Ready and non-terminating endpoints alone enter new-flow slots. Marking an
endpoint terminating therefore publishes a new eligible bank immediately:
new affinity cannot select it, while previously persisted forward/reverse
connection pairs continue until their protocol timeout. Endpoint removal has
the same new-flow behavior. Affinity state, connection state, and desired
endpoint state remain separate state machines.

Affinity outcomes are encoded compactly with the selected tier in connection
provenance and emitted as `none`, `reused`, `created`, or `reselected` in
service-event ABI v4. The affinity map is the twenty-fifth persistent map in
BPF-state ABI v9. Its bank-plus-revision proof makes restart reuse safe; older
v6, v7, and v8 24-map ownership remains independently recognizable for scoped
cleanup and is never opened as partial v9 state.

Verifier safety is part of the implementation contract. Affinity and service
pair keys use per-CPU scratch maps, backend values are copied directly into
per-CPU connection scratch, and NodePort hash preparation occurs outside the
deep connection-insertion call chain. Both classifiers pass the real kernel
verifier without disabling affinity or increasing the kernel limits.

## Consequences

- Default Kubernetes Services retain no session affinity. A Service that asks
  for `ClientIP` gets the implemented behavior without an additional feature
  switch.
- Strict internal/external locality and the selected topology tier always
  precede affinity; affinity cannot broaden availability.
- Affinity is exact per original client and frontend, shared across source
  ports, dual-stack, origin-aware, bounded, recoverable, and observable.
- Any eligibility transaction may reset affinity for affected bank/revision
  tuples. This intentionally prefers correctness over preserving affinity
  across a changed eligible set.
- The LRU bound may evict inactive clients under pressure; the next flow safely
  creates a new choice.
- Maglev and DSR remain independently gated by milestones 7.6 and 7.7.

## Verification

`make service-affinity-dataplane-test` runs inherited schema, contract,
transaction, and locality gates; strict Rust linting; eBPF compilation; ABI-v9
ownership tests; and a privileged real-kernel dual-stack packet test. The
packet test proves exact-client reuse, forced timeout reselection, established
flow survival after termination, new-flow withdrawal from the terminating
backend, bounded affinity-map state, and outcome provenance for IPv4 and IPv6.
