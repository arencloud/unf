# State management

Independent revision domains prevent a single opaque version from hiding partial
state:

```text
identity | policy | service | routing | topology | telemetry
```

Phase 1 incremented identity and policy revisions as watcher events changed the
controller's in-memory snapshots. In Phase 2, identity revision ownership moved
into the collision-checked registry so entries and revision are snapshotted under
one lock. The snapshot also carries a controller-process epoch, allowing agents to
distinguish a restart from a stale lower revision.

Topology schema v3 is a controller query snapshot with the same process epoch. It
joins semantic Node readiness/labels, Pod identity and placement, Service
configuration/selector intent, and EndpointSlice runtime backends. Each backend
retains address type/addresses, resolved Pod target, Node/zone, ports, and
ready/serving/terminating conditions. Pod, Node, Service, and normalized
EndpointSlice changes advance the topology revision; Service and EndpointSlice
changes also advance the service revision. Kubernetes resource-version churn
outside this model is ignored. Topology-only changes do not advance policy
revision. Schema v3 adds per-workload IPv6 addresses to schema v2's
EndpointSlice-aware model; schema v1 remains the selector-intent-only
predecessor. See
[ADR 0011](../adr/0011-versioned-topology-snapshots.md).

Backend readiness is current Kubernetes control-plane state, not an active
traffic probe or load-balancing implementation. Historical snapshot persistence,
pagination, and routing relationships remain future state domains.

Telemetry revision advances when the controller accepts a changed node export.
Flow export schema v2 requires exactly one complete IPv4 or IPv6 address pair.
The current flow-history store retains 4,096 deterministic logical keys and
tracks observation totals, controller evictions, and cumulative agent-side drops.
It is a bounded current-process analysis window, not durable storage. See
[ADR 0012](../adr/0012-bounded-flow-history-export.md).

Agents poll internal identity and policy snapshot endpoints and publish each
desired/applied epoch and revision. Identity schema v2 is written to inactive
physical IPv4/IPv6 maps, read back, and activated together by one
`IDENTITY_CONFIG` write. Policy reconciliation similarly populates inactive
identity-keyed, IPv4-keyed, and IPv6-prefix banks before one `POLICY_CONFIG` write
selects all three. See ADRs 0006, 0007, and 0017.

Each agent also posts a schema v1 acknowledgement containing its Node name,
readiness, BPF load state, desired/applied identity and policy epoch/revisions,
active policy bank, and map counts. The controller timestamps reports on receipt
and compares them with its watched Node set and current desired revisions.
Controller and CLI status classify expected agents as missing, stale after ten
seconds, or converged; fresh reports from unknown Nodes remain visible as
unexpected without permanently degrading status after Node removal.

The identity and policy node update lifecycle is now implemented as:

```text
compile N+1 -> populate all staging maps -> read back and validate
            -> atomically select N+1 -> acknowledge applied revision -> retire N
```

Existing applied state must remain usable if the controller or Kubernetes API is
temporarily unavailable. New identity and policy state never partially
overwrites active maps; each prior bank remains selected through any pre-switch
failure. Nine enforcement maps are pinned under the `/sys/fs/bpf/unf/v2` ABI
directory, reopened with strict all-or-none validation, and reconstructed into
userspace caches after restart. Fresh startup readiness is fenced until identity
and policy both reconcile, while a complete validated last-known-good set may
restore service without the controller. On Linux 6.6+, per-interface TCX links
are pinned and atomically updated to the replacement program; older kernels use
stable legacy netlink filter identities for in-place replacement. Explicit
ABI-directory cleanup operations and acknowledgement authentication/durability
remain hardening work. See ADRs 0016, 0017, and 0018.

Kubernetes watches remain the controller input. Internal HTTP snapshots are the
smallest Phase 2 distribution mechanism; gRPC will not be added until measured
scale, streaming, or transport-security requirements justify it.
