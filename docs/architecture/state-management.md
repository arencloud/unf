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
Flow snapshot schema v3 supports inclusive `last_received_unix_ms` bounds and
newest-first limits. A separate schema-v1 ConfigMap checkpoint preserves the
newest 1,024 keys within a 900,000-byte payload across controller restart and
reports every capacity omission. See
[ADR 0012](../adr/0012-bounded-flow-history-export.md) and
[ADR 0030](../adr/0030-durable-flow-history-checkpoint-and-time-windows.md).

Agents poll internal identity and policy snapshot endpoints and publish each
desired/applied epoch and revision. Identity schema v2 is written to inactive
physical IPv4/IPv6 maps, read back, and activated together by one
`IDENTITY_CONFIG` write. Policy reconciliation similarly populates inactive
ingress identity-keyed, IPv4-source, IPv6-source, egress IPv4-destination, and
egress IPv6-destination banks before one `POLICY_CONFIG` write selects all five.
See ADRs 0006, 0007, 0017, 0035, and 0037.

Each agent also posts a schema v2 acknowledgement containing its Node and Pod
identity, readiness, BPF load state, desired/applied identity and policy
epoch/revisions, active policy bank, and map counts. A dedicated-audience,
short-lived projected service-account token authenticates the request through
Kubernetes TokenReview. The controller binds its service account and Pod name/UID
to watched Pod placement before accepting the reported Node. It timestamps reports
on receipt and compares them with its watched Node set and current desired revisions.
Controller and CLI status classify expected agents as missing, stale after ten
seconds, or converged; fresh reports from unknown Nodes remain visible as
unexpected without permanently degrading status after Node removal.

The controller coalesces accepted reports into one schema-versioned ConfigMap
checkpoint at most every two seconds. The store is capped at 1,024 node keys and
the controller has only exact-name `get`/`patch` access. Startup rejects an
unsupported schema, malformed report, mismatched node key, zero timestamp, or an
unreasonable future timestamp before restoring any entry. Restored reports keep
their original receive time and prior controller epoch: they preserve last-known
status but cannot report convergence for the new process until fresh authenticated
agent reports arrive. Node deletion removes its checkpoint entry, and initial
Node-list reconciliation removes entries deleted while the controller was down.

The identity and policy node update lifecycle is now implemented as:

```text
compile N+1 -> populate all staging maps -> read back and validate
            -> atomically select N+1 -> acknowledge applied revision -> retire N
```

Existing applied state must remain usable if the controller or Kubernetes API is
temporarily unavailable. New identity and policy state never partially
overwrites active maps; each prior bank remains selected through any pre-switch
failure. Eleven enforcement maps are pinned under the `/sys/fs/bpf/unf/v3` ABI
directory, reopened with strict all-or-none validation, and reconstructed into
userspace caches after restart. Fresh startup readiness is fenced until identity
and policy both reconcile, while a complete validated last-known-good set may
restore service without the controller. On Linux 6.6+, per-interface TCX links
are pinned and atomically updated to the replacement program; older kernels use
stable legacy netlink filter identities for in-place replacement. Automatic mode
selection has an explicit compatibility-test override; kind removes TCX coverage,
proves the legacy filter alone survives offline-controller agent replacement,
then restores TCX before scoped legacy cleanup. A separate dry-run-first cleanup
command recognizes only the v1/v2/v3 map names, numeric UNF TCX link-pin names, and
UNF legacy program names. It refuses unknown ABI content and requires explicit
confirmation for current v3 removal. ADRs 0023 and 0024 place snapshots,
acknowledgements, and telemetry behind dedicated TLS plus Pod-bound TokenReview;
serving certificates and CA bundles reload with last-known-good fallback and an
overlapping-trust rotation gate. Agent reports and the newest bounded flow
history survive controller replacement; desired-state and identity allocation
remain current-process state.

Isolated live-kernel probes verify that partial pin sets,
invalid active config, and corrupt inactive-stage debris are rejected before
adoption without mutating the primary pin set. A separate live pressure probe
fills only the inactive identity-keyed policy bank, proves a staging insertion
failure cannot advance applied state or alter active traffic, and verifies retry
after scoped cleanup. Permanent startup validation failures terminate for
orchestrator retry. See ADRs 0016 through 0030.

Kubernetes watches remain the controller input. Internal HTTPS snapshots are the
smallest Phase 2 distribution mechanism; gRPC will not be added until measured
scale or streaming requirements justify it.
