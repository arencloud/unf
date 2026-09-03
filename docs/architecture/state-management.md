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
Flow export schema v5 requires exactly one complete IPv4 or IPv6 address pair.
Policy records retain the decisive direction and require the selected
destination identity for ingress or selected source identity for egress,
permitting external egress without a fabricated destination identity. Service
records instead carry a validated optional service outcome containing stable
ServiceId/BackendId, service revision, backend tuple, action/reason, and an
explicit ClusterIP, NodePort/Cluster, or NodePort/Local frontend kind.
The current flow-history store retains 4,096 deterministic logical keys and
tracks observation totals, controller evictions, and cumulative agent-side drops.
Flow snapshot schema v6 supports inclusive `last_received_unix_ms` bounds,
newest-first limits, and distinct ingress/egress keys. A separate schema-v5
ConfigMap checkpoint preserves the newest 1,024 keys within
a 900,000-byte payload across controller restart while reporting every capacity
omission. The reader accepts every prior schema, migrates schema-v1 records to
ingress, defaults absent service outcomes, and classifies pre-NodePort service
outcomes as ClusterIP. See
[ADR 0012](../adr/0012-bounded-flow-history-export.md) and
[ADR 0030](../adr/0030-durable-flow-history-checkpoint-and-time-windows.md), and
[ADR 0039](../adr/0039-direction-aware-flow-history.md). Service outcome
extension and migration are defined by
[ADR 0079](../adr/0079-bounded-service-outcome-observability.md).
NodePort classification and migration are defined by
[ADR 0088](../adr/0088-nodeport-operations-and-simulation.md).

Agents poll internal identity and policy snapshot endpoints and publish each
desired/applied epoch and revision. Identity schema v2 is written to inactive
physical IPv4/IPv6 maps, read back, and activated together by one
`IDENTITY_CONFIG` write. Policy reconciliation similarly populates inactive
ingress identity-keyed, IPv4-source, IPv6-source, egress IPv4-destination, and
egress IPv6-destination banks before one `POLICY_CONFIG` write selects all five.
See ADRs 0006, 0007, 0017, 0035, and 0037.

Opted-in primary-CNI agents additionally poll one authenticated complete
remote-route snapshot. Schema v1 binds the controller epoch and global routing
revision to local Node/block provenance and every remote Node's stable assignment,
blocks, and exact dual-stack transport. The agent repairs its owner-only durable
last-known-good snapshot before polling, rejects same-epoch regression or silent
mutation, applies complete route replacements before stale retirement, and
commits persistence only after kernel readback. ADR 0066 defines this recovery
transaction.

Each agent also posts a schema v5 acknowledgement containing its Node and Pod
identity, readiness, BPF load state, desired/applied identity and policy
epoch/revisions, optional primary-CNI Node-block revision, desired/applied remote
route epoch/revision, route/error counts, active policy bank, and map counts.
Service outcome totals, NodePort desired/applied and Cluster/Local counts,
Cluster/Local translation and no-backend totals, and the last bounded
ServiceId/BackendId/revision/action/reason tuple are included without introducing
per-Service metric labels. A dedicated-audience,
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
temporarily unavailable. New identity, policy, and service state never partially
overwrites active maps; each prior bank remains selected through any pre-switch
failure. Thirty-one maps are pinned under the `/sys/fs/bpf/unf/v12` ABI directory,
reopened with strict all-or-none validation, and reconstructed into userspace
caches after restart. ABI v4, v5, v6–v8, and v9–v11 remain explicitly recognized
as 18-map, 21-map, 24-map, and 25-map cleanup boundaries; none is interpreted as
partial v12 state. These historical boundaries are never adopted as current
state. The active service, NodePort,
and LoadBalancer banks must exactly recompile from
their owner-only durable checkpoints. A Service checkpoint retains the current
schema whenever LoadBalancer intent is present; rollback-compatible legacy
projection is limited to state with no NodePort or LoadBalancer intent.
LoadBalancer source-range LPM tries are
runtime-only maps outside that exact 31-map persistent set; the agent rebuilds
and reads them back from the same authenticated active Service/reachability
tuple before attaching TC. A crash between the service and NodePort
activation pointers restores the prior
coherent tuple; a crash after both pointers commits the prepared tuple. A fresh
or incomplete map set must receive and
commit identity, policy, and available service snapshots before any TC program is attached;
failure leaves the new ABI state unattached for safe retry. A complete validated
last-known-good set may restore service without the controller.
Phase 6.7 keeps the established compatibility tuple and makes LoadBalancer
operations fields additive. Durable flow history retains explicit Cluster/Local
frontend kinds, while controller replacement restores only leases whose pool
UID and provider identity exactly match configured ownership. Explanation and
simulation read snapshots of these revision domains without advancing or
persisting any of them.

On Linux 6.6+,
per-interface TCX links
are pinned and atomically updated to the replacement program; older kernels use
stable legacy netlink filter identities for in-place replacement. Automatic mode
selection has an explicit compatibility-test override; kind removes TCX coverage,
proves the legacy filter alone survives offline-controller agent replacement,
then restores TCX before scoped legacy cleanup. A separate dry-run-first cleanup
command recognizes every ABI from v1 through the binary's compiled current
version, numeric UNF TCX link-pin names, and UNF legacy program names. It refuses
unknown ABI content and requires explicit confirmation for current-ABI removal.
ADRs 0023 and 0024 place snapshots,
acknowledgements, and telemetry behind dedicated TLS plus Pod-bound TokenReview;
serving certificates and CA bundles reload with last-known-good fallback and an
overlapping-trust rotation gate. Agent reports and the newest bounded flow
history survive controller replacement. The agent's applied primary-CNI
Node-block, remote-route, and LoadBalancer reachability provenance also survives
locally. The controller persists bounded LoadBalancer allocation and
reachability revision state before distributing it; other desired state and
identity allocation remain current-process state.

Controller and agent `GET /v1/version` responses publish compatibility schema
v1: embedded build revision, persistent BPF-state ABI, identity/policy snapshot
schemas, agent-status schema, and flow-export schema. Adjacent revisions with an
unchanged tuple are live-qualified in controller-first order with a deliberate
mixed-agent interval and both agent/controller rollback. ABI or listed-schema
changes require an explicit migration and cannot inherit that claim. ADR 0047
defines the window and its repeatable Kind gate.

Agent status also carries an additive `version_transition` classification:
`normal`, `compatible_rollback`, `blocked_rollback`, or `recovery`. The same
value is visible in controller aggregation, metrics, and structured logs.
Blocked newer-state adoption is derived by the local ABI preflight, remains not
Ready and fail closed, and reports for a bounded 30-second window before exit;
operators explicitly label compatible rollback and recovery rollouts. ADR 0053
defines and live-qualifies this reporting contract.

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

Phase 8 egress host state has an independent schema-v1/ABI-v1 userspace
transaction. An exact-Node response is bound to the existing Pod-bound
authentication result and negotiated capabilities, then independently replayed
before it can become an admitted projection. The agent-facing store contract
stages and reads back an inactive complete-contract bank, persists and reads
back a pending checkpoint, switches one pointer, commits, and only then retires
the previous bank. Startup commits a prepared winner or retains/reconstructs
the current winner solely from pointer plus current/pending evidence; ambiguity
fails closed. This userspace host checkpoint remains distinct from persistent
BPF ABI v12; Phase 8.5 lowers it into independently versioned fixed-width ABI-v1
kernel banks without treating either representation as interchangeable; ADRs
0117 and 0120.

Phase 8.4a adds an identity-indexed egress admission state machine outside the
packet ABI. Explicit intent is installed as `Fenced` before it can become
`Active`; withdrawal returns through the fence before an owner-matched release
to native routing. An active state binds controller/projection/contract
revisions, contract digest, and lease epoch. The accompanying flow proof is a
deterministic commitment independently reproduced at the selected gateway, not
stored authority or a bearer credential. Phase 8.5 must lower these semantics
into bounded fixed-width state without weakening this ordering; ADR 0118.

The Phase 8.5 contract slice defines that fixed state as an independent egress
ABI v1. Identity-keyed source entries retain all contract revision domains,
lease, digest, admission, intent index, candidate counts, and family/standby
flags. Address, gateway-path, and 251-bucket selection entries are keyed by the
shared intent index; this avoids multiplying candidates for every selected
workload. Path certificates must form one coherent path revision and unused,
foreign, missing, or duplicate evidence is rejected. Connection and event
layouts reserve exact original/translated tuples plus primary/standby proof
provenance. Persistent ABI v12 now owns these tables. The agent explicitly
encodes, stages, reads back, activates, reconstructs, and garbage-collects them
as one pointer-selected transaction. A live authenticated source endpoint now
carries the exact normalized model/facts/contract envelope; the agent resolves
its Node UID independently, replays it, applies monotonic projection fencing,
and lowers every selected source as `Fenced` without path candidates. Native
EgressPool/EgressPolicy and OpenShift EgressIP watch sources now transact their
owned prefixes through a single canonical model revision. A schema-v1
ConfigMap checkpoint restores exact source ownership before watches start;
failed/incomplete relists preserve last-known-good state, while accepted model
changes clear stale source distribution authority. Gateway application
acknowledgement and packet consumption remain separate Phase 8.5 gates. A distinct in-process
gateway ledger now owns digest-bound exact-Node source-contract projections and
explicit empty withdrawals. It fences controller epoch/revision regression and
same-revision mutation; restart reacquires it before any future activation
because no gateway host or packet state exists yet. See ADRs 0119–0123.
