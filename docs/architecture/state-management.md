# State management

Independent revision domains prevent a single opaque version from hiding partial
state:

```text
identity | policy | service | routing
```

Phase 1 incremented identity and policy revisions as watcher events changed the
controller's in-memory snapshots. In Phase 2, identity revision ownership moved
into the collision-checked registry so entries and revision are snapshotted under
one lock. The snapshot also carries a controller-process epoch, allowing agents to
distinguish a restart from a stale lower revision.

Agents poll the internal identity snapshot endpoint and publish desired/applied
epoch and revision. A revision is acknowledged only after the versioned
`IDENTITY_V4` map is reconciled. This first identity update path validates before
mutation and restores the cached prior contents after an error, but it is not the
atomic active/staging mechanism required before enforcement. See ADR 0006.

The planned node update lifecycle is:

```text
compile N+1 -> populate staging maps -> validate -> atomically select N+1
            -> agent acknowledges applied revision -> retire N
```

Existing applied state must remain usable if the controller or Kubernetes API is
temporarily unavailable. New state must never partially overwrite active maps.
Pinned map ownership, schema migrations, persistence, and last-known-good recovery
are Phase 2 design gates, not claims of the current prototype.

Kubernetes watches remain the controller input. Internal HTTP snapshots are the
smallest Phase 2 distribution mechanism; gRPC will not be added until measured
scale, streaming, or transport-security requirements justify it.
