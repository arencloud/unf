# State management

Independent revision domains prevent a single opaque version from hiding partial
state:

```text
identity | policy | service | routing | topology
```

Phase 1 incremented identity and policy revisions as watcher events changed the
controller's in-memory snapshots. In Phase 2, identity revision ownership moved
into the collision-checked registry so entries and revision are snapshotted under
one lock. The snapshot also carries a controller-process epoch, allowing agents to
distinguish a restart from a stale lower revision.

Topology schema v1 is a controller query snapshot with the same process epoch.
It joins semantic Node readiness/labels, Pod identity and node placement, and
Service configuration. Service membership is derived from selectors against the
watched Pod labels. Pod, Node, and Service changes advance the topology revision;
Service changes also advance the service revision. Kubernetes resource versions
and status fields outside this normalized model do not create revision churn.
Topology-only placement and Service changes do not advance policy revision.

This relationship is selector intent, not an EndpointSlice readiness report.
Runtime backend readiness and historical snapshot persistence remain future
state domains. See [ADR 0011](../adr/0011-versioned-topology-snapshots.md).

Agents poll internal identity and policy snapshot endpoints and publish each
desired/applied epoch and revision. Identity reconciliation retains its
observation-safe rollback behavior. Policy reconciliation uses two banks: the
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
