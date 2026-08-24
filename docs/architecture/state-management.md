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
desired/applied epoch and revision. Identity schema v2 reconciles separate IPv4
and IPv6 maps and rolls both back to cached state if either update fails. Policy
reconciliation uses two banks: the
inactive identity-keyed and IPv4-keyed banks are populated and read back before
one `POLICY_CONFIG` write selects both. See ADRs 0006 and 0007.

The policy node update lifecycle is now implemented as:

```text
compile N+1 -> populate staging maps -> validate -> atomically select N+1
            -> agent acknowledges applied revision -> retire N
```

Existing applied state must remain usable if the controller or Kubernetes API is
temporarily unavailable. New state must never partially overwrite active maps.
The prior bank remains active through any pre-switch failure. Pinned map
ownership, schema migrations, persistence across agent restart, and controller
acknowledgement aggregation remain Phase 2 design gates.

Kubernetes watches remain the controller input. Internal HTTP snapshots are the
smallest Phase 2 distribution mechanism; gRPC will not be added until measured
scale, streaming, or transport-security requirements justify it.
