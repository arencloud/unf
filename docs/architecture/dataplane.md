# Dataplane

## Initial hook

UNF starts with TC classifier programs because TC works with an existing CNI and
provides both ingress and egress attachment without owning the pod lifecycle. XDP,
cgroup, and socket hooks will only be introduced for measured feature needs.

The parser accepts Ethernet with IPv4 or IPv6 TCP, UDP, and SCTP. It validates
the IPv4 header length, skips non-initial IPv4 fragments, validates the fixed
IPv6 header, and traverses at most six IPv6 extension headers and 256 extension
bytes. Hop-by-Hop is accepted only first; Routing, Destination Options,
initial/atomic Fragment, and AH are supported. Jumbograms, ESP/No Next Header,
non-initial fragments, malformed or over-limit chains, and unsupported protocols
fail open. The parser reads the flow tuple with bounded helpers, increments a
per-CPU counter, reads the active identity configuration once per packet, resolves
both endpoints from that bank, and reads the atomically active policy bank.
Ingress and egress policy direction is derived from the selected workload and
map family, not from the TC attachment direction. Both directions are evaluated;
either deny drops the packet. A selected policy decision carries its direction
in the flow event, while an event with no applicable policy retains the observed
hook direction.
An actual deny returns `TC_ACT_SHOT`; allow and shadow-only deny return
`TC_ACT_PIPE`.
SCTP's common header exposes source and destination ports in the same first four
transport bytes, so protocol 132 uses the existing exact/protocol-wildcard policy
key layout without an ABI change.

## Maps

| Name | Key | Value | Owner | Update/lifetime | Capacity/failure |
|---|---|---|---|---|---|
| `FLOW_COUNTERS` | constant `u32` slot 0 | per-CPU `u64` | eBPF program | increment per parsed flow; program lifetime | one entry; forwarding continues if lookup fails |
| `FLOW_EVENTS` | none (ring) | `FlowEvent` ABI v2 | eBPF producer, agent consumer | ephemeral, unpinned | 256 KiB; events drop under pressure without changing the already-computed forwarding decision |
| `CONNECTIONS` | complete IPv4/IPv6 L4 tuple | last-seen time and admission revision | authoritative ingress and supplemental egress TC programs | runtime-only LRU; primary-CNI mode seeds pre/post-NAT tuples from both hooks, while only ingress attachments enforce and emit telemetry; protocol-bounded and reset on program replacement | 65,536 entries; an entry requires active policy state but survives unrelated revision churn; misses fall through to current policy |
| `IDENTITY_V4`, `IDENTITY_V4_B` | IPv4 network-order bytes | identity ID, schema version, flags, revision | controller desired state; agent transactional writer; TC reader | physical banks 0/1; inactive map is replaced and validated before activation; pinned under `/sys/fs/bpf/unf/v6` | 65,536 entries per bank; unknown/mismatched identity resolves to ID zero and forwarding continues |
| `IDENTITY_V6`, `IDENTITY_V6_B` | 16 IPv6 network-order bytes | identity ID, schema version, flags, revision | controller desired state; agent transactional writer; TC reader | physical banks 0/1 stage with their IPv4 counterpart; pinned under the same ABI directory | 65,536 entries per bank; unknown/mismatched identity resolves to ID zero and forwarding continues |
| `IDENTITY_CONFIG` | constant `u32` slot 0 | controller epoch, identity revision, combined entry count, schema, active bank | agent writer; TC reader | one atomic write activates both address-family maps; pinned | one entry; failed activation preserves the previous pointer |
| `POLICY_RULES` | source/destination identity, protocol, destination port, bank | actual/shadow verdict and policy/rule/reason provenance, schema, revision | controller compiler; agent transactional writer | stale inactive keys are removed, then populated and validated before activation; pinned | 262,144 entries across two banks; compiler and agent cap each bank at 131,072 entries, and the active bank remains selected when staging fails |
| `POLICY_IPV4` | exact/fallback source IPv4, destination identity, protocol, destination port, bank | same policy decision/provenance value as `POLICY_RULES` | controller IPv4-aware compiler; agent transactional writer | staged and validated alongside `POLICY_RULES`; pinned | 262,144 entries across two banks; compiler and agent cap each bank at 131,072 entries |
| `POLICY_IPV6` | destination identity, port, protocol, bank, and source IPv6 prefix | same policy decision/provenance value as `POLICY_RULES` | controller IPv6-aware compiler; agent transactional writer; TC LPM reader | staged and validated alongside the other policy maps; pinned | 262,144 entries across two banks; compiler and agent cap each bank at 131,072 entries |
| `EGRESS_IPV4` | exact/fallback destination IPv4, source identity, protocol, destination port, bank | same policy decision/provenance value as `POLICY_RULES` | controller egress compiler; agent transactional writer; TC reader | exact destination then arbitrary-destination fallbacks in the active bank; staged and validated with ingress | 262,144 entries across two banks; compiler and agent cap each bank at 131,072 entries |
| `EGRESS_IPV6` | source identity, port, protocol, bank, and destination IPv6 prefix | same policy decision/provenance value as `POLICY_RULES` | controller egress compiler; agent transactional writer; TC LPM reader | longest-prefix destination lookup for exact, protocol-wildcard, then global-wildcard dimensions; staged and validated with ingress | 262,144 entries across two banks; compiler and agent cap each bank at 131,072 entries |
| `POLICY_CONFIG` | constant `u32` slot 0 | controller epoch, policy revision, combined entry count, schema, active bank | agent writer; TC reader | one atomic write activates matching banks; pinned | one entry; failed activation preserves the previous pointer |
| `SERVICE_FRONTENDS_V4`, `SERVICE_FRONTENDS_V6` | exact address, network-order port, protocol, bank | ServiceId, revision-local frontend index, eligible backend count, schema, revision | service compiler; agent transactional writer; TC reader | both families stage/read back together; pinned under ABI v6 | 262,144 physical entries each, capped at 131,072 per bank; an exact zero-backend frontend drops new flows while an unrelated tuple passes |
| `SERVICE_BACKENDS_V4`, `SERVICE_BACKENDS_V6` | ServiceId, BackendId, bank | revision, address, network-order port, protocol, lifecycle flags, schema | service compiler; agent transactional writer; TC reader | all endpoint lifecycle records stage with frontends; pinned | 524,288 physical entries each, capped at 262,144 per bank; new-flow slots admit only ready, non-terminating entries |
| `SERVICE_BACKEND_SLOTS` | ServiceId, revision-local frontend index, ordered slot, bank | stable BackendId, schema, revision | service compiler; agent transactional writer; TC reader | deterministic eligible membership stages with both families; Local NodePort entries use a disjoint high-index namespace and merge into the same service transaction; pinned | 1,048,576 physical entries, capped at 524,288 per bank |
| `SERVICE_CONFIG` | constant `u32` slot 0 | controller epoch, service revision, frontend/backend/slot counts, schema, active bank | agent writer; TC reader | one write activates all five service tables; durable-checkpoint failure restores the prior pointer | one entry; absent/invalid config means no desired service lookup, while an existing valid connection remains usable until timeout |
| `SERVICE_CONNECTIONS` | complete IPv4/IPv6 L4 tuple plus forward/reverse role | last-seen, service revision, client/frontend/backend tuples, ServiceId, BackendId, schema/flags | TC writer/reader | persistent ABI v6; reverse inserts first, forward second, partial failure removes reverse; lookups validate the complete peer tuple and refresh both entries | bounded 262,144-entry LRU; valid TCP/UDP pairs survive desired-state churn until protocol timeout; corrupt/expired pairs are removed |
| `NODE_PORT_FRONTENDS_V4`, `NODE_PORT_FRONTENDS_V6` | local Node address, network-order NodePort, protocol, bank | ServiceId, frontend index, eligible-backend count, service revision/bank, schema, traffic-policy flag | service compiler; agent transactional writer; ingress TC reader | both families stage/read back together under a NodePort-specific bank and pin under ABI v6; exact Cluster matches use global service slots, while Local matches use receiving-Node-only slots | 262,144 physical entries each, capped at 131,072 per bank; arithmetic address × NodePort preflight fails before allocation |
| `NODE_PORT_CONFIG` | constant `u32` slot 0 | controller epoch, service and local-Node revisions, family counts, schema, active NodePort bank | agent writer; ingress TC reader | independent pointer references values that must name the exact active service epoch, revision, and bank; address-only changes do not churn ClusterIP maps | one entry; dual-pointer crash recovery either commits the complete prepared tuple or restores the prior durable tuple before attachment |
| `LOAD_BALANCER_FRONTENDS_V4`, `LOAD_BALANCER_FRONTENDS_V6` | VIP address, network-order Service port, protocol, bank | ServiceId, frontend index, eligible-backend count, service/reachability/allocation revisions, referenced service bank, schema, traffic-policy flag | LoadBalancer compiler; agent transactional writer; TC reader begins in Phase 6.5 | both families stage and read back under an independent bank in ABI v6; current Phase 6.4 packet path does not consume them | 262,144 physical entries each, capped at 131,072 per bank; collision or partial stage preserves the active bank |
| `LOAD_BALANCER_CONFIG` | constant `u32` slot 0 | controller epoch, service/reachability/allocation revisions, family counts, schema, active VIP bank, referenced service bank | agent writer; TC reader begins in Phase 6.5 | one atomic write activates exact owner-only VIP state after readback and prepared-checkpoint persistence | one entry; restart completes or rolls back from exact map/checkpoint evidence |

`FlowEvent` carries no Kubernetes strings. ABI v2 records the applied policy
revision, actual verdict/reason/policy/rule, and optional shadow
verdict/reason/policy/rule. In `POLICY_RULES`, TC looks up the exact protocol/port,
then the same protocol with port zero, then the protocol/port-zero global fallback
in the bank selected by `POLICY_CONFIG`.
Identity, policy, and service config/value pairs must have the expected schema and an
identical nonzero revision.
Event and map ABIs use fixed C layouts, explicit schema/version fields, and
compile-time size assertions.

`ServiceEvent` ABI v2 remains 96 bytes. One formerly reserved byte records only
the bounded frontend class (ClusterIP, NodePort/Cluster, or NodePort/Local), and
the other nine bytes must remain zero. New-connection failures receive the class
from the exact validated frontend; forward, reverse, and expiry events derive it
from the persistent connection flags. This keeps classification correct through
snapshot churn and restart without adding Kubernetes strings to the ABI. Agent
status schema v5, flow export schema v5, and history schema v6 then preserve the
dimension through fixed-cardinality metrics, bounded status, durable history,
explanation, and read-only NodePort simulation; ADR 0088 defines the contract.

On a ClusterIP lookup miss, ingress may perform an exact NodePort lookup only
when both active pointers form a coherent epoch/revision/service-bank tuple.
An uplink egress reverse-connection miss also performs the exact ClusterIP
frontend lookup. This covers host-network and Node-origin traffic that never
traverses a workload-veth ingress hook; workload traffic is already translated
before uplink egress and therefore cannot match the frontend a second time.
Replies use the same paired reverse connection and ingress-side source
restoration as workload-originated Service traffic.
`Cluster` forwarding stores the original client and Node frontend, selects a
bounded collision-safe high source port, and rewrites the forward source to the
receiving Node so cross-node replies return through the owning connection. The
egress path restores same-node replies; the receiving Node's ingress path also
recognizes the exact reverse role and restores cross-node replies before local
delivery. Both restore the NodePort source and original client destination.
Policy retains the original external source while evaluating the selected
backend identity and backend port after DNAT.

Local NodePort compilation filters the linked backend IDs by readiness,
non-termination, and exact EndpointSlice `nodeName`, then writes those slots in
a disjoint high frontend-index namespace in the referenced service bank. Local
forwarding performs destination translation only, so the backend sees the
external source; the same-node egress hook restores the NodePort source tuple.
An empty local slot set is an exact new-flow drop, while established connection
pairs retain their bounded timeout behavior across placement churn.

Runtime-only per-CPU scratch arrays hold flow observations, service keys/values,
policy decisions, connection keys, and event construction state. They are not
persistent ownership pins; they keep every verifier call chain within the
512-byte eBPF stack bound.

Userspace flow export preserves forwarding priority. Direction-selected events
enter a 4,096-record non-blocking channel and a 2,048-key pending aggregator. A
full bound increments `unf_telemetry_dropped_events_total` and discards telemetry
immediately; it never blocks TC consumption or changes the verdict already
returned by eBPF. HTTP batches contain at most 512 logical flows. Controller
retention is independently capped at 4,096 keys with eviction accounting. Flow
export schema v3 carries the decisive policy direction and exactly one complete
IPv4 or IPv6 address pair per key; ingress requires a resolved destination while
egress requires a resolved source, so external egress can be retained. Flow
history snapshot schema v4 aggregates direction as part of the logical key;
topology schema v3 exposes both address families for each workload.

Bounded NetworkPolicy `endPort` ranges are expanded into exact keys before
distribution. The compatibility compiler caps one inclusive range at 1,024
ports, while the shared lowering path caps the complete snapshot at the physical
131,072-entry allocation for one bank. The agent validates the same snapshot
bound before encoding or mutating the inactive bank.

Bounded IPv4 `ipBlock` peers use `POLICY_IPV4`. For an exact source and then the
arbitrary-external source, TC checks exact protocol/port, protocol-specific
port-zero, and global protocol/port-zero entries before consulting
`POLICY_RULES`. The controller emits exact entries for known Pod addresses and
bounded block addresses, preserving the shared evaluator's native/compatibility
precedence.

IPv6 ingress `ipBlock` peers use `POLICY_IPV6`, an LPM trie whose fixed destination,
port, protocol, and bank dimensions precede the source address. Snapshot schema
v4 carries ingress identity, exact IPv4/source-prefix IPv6, and egress exact
IPv4/destination-prefix IPv6 decisions; the agent stages and validates all five
inactive policy banks before the single `POLICY_CONFIG` activation write.
More-specific exception decisions and known-Pod `/128` decisions override
broader external prefixes in their respective direction. See ADRs 0014 and 0036.

## Failure behavior

An interrupted identity, policy, or service stage cannot replace its active
bank, and controller interruption leaves the last activated revisions in use.
The eleven historical enforcement maps plus seven service maps are an
eighteen-pin, all-or-none set in an ABI-versioned bpffs
directory. On startup the agent checks map capacities, reconstructs both banks'
rollback caches, validates each config-selected bank's count and uniform
revision, and refuses partial or malformed persistent state. Debris from an
interrupted inactive-bank stage is structurally validated but need not share one
revision. A controller-managed fresh process stays NotReady until both initial
snapshots apply; a complete validated last-known-good set may restore readiness
while the controller is unavailable. Recovery logs expose active-bank counts for
all five policy maps; the Kind gate requires populated IPv4 and IPv6 egress maps
plus preserved direct-Pod allow/deny forwarding after source-node replacement.

This overlay prototype deliberately
fails open when the selected workload identity is unknown, config is absent or
incompatible, an IPv6 extension chain is unsupported, malformed, or exceeds its
bounds, or no valid direction-specific entry exists. An ingress source without
an identity can still be enforced when a valid IPv4 exact/fallback or IPv6
source-prefix entry exists; egress requires the selected source identity.
Fail-open events are marked observed/identity-unknown with revision zero. TC
attachments use persistent replacement identities. On Linux 6.6 and newer, the
agent pins one TCX link per interface index in the configured direction below the
current ABI v6 link directory and atomically updates that link to the newly loaded
program. On older kernels, it owns a fixed priority/handle tuple per direction
and replaces the legacy netlink filter in place. The old program therefore
remains attached until the replacement program is loaded and handed over.
Automatic selection can be overridden explicitly with `--tc-attachment-mode`
for compatibility validation and controlled migration. The kind gate selects
legacy mode on the TCX-capable development kernel, removes the old UNF TCX pins,
and proves that the reserved netlink filter alone preserves enforcement through
replacement before restoring TCX and removing the legacy tuple.
Operators can inspect and remove recognized persistent state with `unf-agent
cleanup`. Planning is the default; `--execute` applies the plan. ABI cleanup
accepts only the known v1/v2/v3/v4/v5/v6 map names and numeric UNF TCX link-pin names,
refuses unknown directory content, and requires `--allow-current-abi` for v6. Legacy
cleanup matches only UNF program names and leaves clsact and unrelated filters
untouched.
Invalid map state never becomes a deny by accident. The kind gate also fills the
shared physical `POLICY_RULES` map using reserved keys tagged for the inactive
bank, requires the staging failure to preserve the selected bank and applied
revision, then removes only those keys and verifies that the waiting revision
activates.
Old ABI pin directories are not removed automatically; operators may use the
scoped cleanup command only after validating the replacement ABI rollout. See ADRs 0008
and 0016 through 0022.
Permanent startup validation failures terminate the agent after readiness is
fenced so the orchestrator can retry after repair.

## Build boundary

The TC package is excluded from the host workspace and built for
`bpfel-unknown-none` with an isolated nightly `build-std=core` command. Shared ABI
tests still run on stable in the host workspace. See ADR 0002.

## Next dataplane milestone

The legacy netlink path, encrypted internal transport, and IPv4/IPv6 policy
provenance now have repeatable evidence on separate OpenShift 4.22 IPv4-only and
dual-stack clusters running RHCOS 9.8 kernel 5.14. Path-specific admission,
durable agent acknowledgement retention, and certificate/trust hot rotation are
now live-verified across rejected unsafe workload changes, controller
replacement, an overlapping external-PKI handoff, and OpenShift Service CA
restoration.
Coordinated uninstall now stops agents, cleans and verifies each worker, removes
the exact cluster resources, and proves full redeploy recovery. The OpenShift
agent uses the constrained three-capability boundary defined by ADR 0025, the
exact mount boundary in ADR 0028, and the uninstall ordering in ADR 0029. The
Phase 3 NetworkPolicy compatibility is complete at its documented bounded L4
scope. Full-CNI dataplane ownership, link/routing lifecycle, and exact Kind and
OpenShift recovery are Verified under ADRs 0057–0073. Phase 4 adds a
Kubernetes-independent service IR and deterministic retained-last-valid
Kubernetes compiler, authenticated durable agent distribution, transactional
service state, verifier-executed dual-stack TCP/UDP service translation,
bounded operations, and kube-proxy-free Kind and OpenShift qualification under
ADRs 0074–0081.
