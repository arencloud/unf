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
| `IDENTITY_V4`, `IDENTITY_V4_B` | IPv4 network-order bytes | identity ID, schema version, flags, revision | controller desired state; agent transactional writer; TC reader | physical banks 0/1; inactive map is replaced and validated before activation; pinned under `/sys/fs/bpf/unf/v14` | 65,536 entries per bank; unknown/mismatched identity resolves to ID zero and forwarding continues |
| `IDENTITY_V6`, `IDENTITY_V6_B` | 16 IPv6 network-order bytes | identity ID, schema version, flags, revision | controller desired state; agent transactional writer; TC reader | physical banks 0/1 stage with their IPv4 counterpart; pinned under the same ABI directory | 65,536 entries per bank; unknown/mismatched identity resolves to ID zero and forwarding continues |
| `IDENTITY_CONFIG` | constant `u32` slot 0 | controller epoch, identity revision, combined entry count, schema, active bank | agent writer; TC reader | one atomic write activates both address-family maps; pinned | one entry; failed activation preserves the previous pointer |
| `POLICY_RULES` | source/destination identity, protocol, destination port, bank | actual/shadow verdict and policy/rule/reason provenance, schema, revision | controller compiler; agent transactional writer | stale inactive keys are removed, then populated and validated before activation; pinned | 262,144 entries across two banks; compiler and agent cap each bank at 131,072 entries, and the active bank remains selected when staging fails |
| `POLICY_IPV4` | exact/fallback source IPv4, destination identity, protocol, destination port, bank | same policy decision/provenance value as `POLICY_RULES` | controller IPv4-aware compiler; agent transactional writer | staged and validated alongside `POLICY_RULES`; pinned | 262,144 entries across two banks; compiler and agent cap each bank at 131,072 entries |
| `POLICY_IPV6` | destination identity, port, protocol, bank, and source IPv6 prefix | same policy decision/provenance value as `POLICY_RULES` | controller IPv6-aware compiler; agent transactional writer; TC LPM reader | staged and validated alongside the other policy maps; pinned | 262,144 entries across two banks; compiler and agent cap each bank at 131,072 entries |
| `EGRESS_IPV4` | exact/fallback destination IPv4, source identity, protocol, destination port, bank | same policy decision/provenance value as `POLICY_RULES` | controller egress compiler; agent transactional writer; TC reader | exact destination then arbitrary-destination fallbacks in the active bank; staged and validated with ingress | 262,144 entries across two banks; compiler and agent cap each bank at 131,072 entries |
| `EGRESS_IPV6` | source identity, port, protocol, bank, and destination IPv6 prefix | same policy decision/provenance value as `POLICY_RULES` | controller egress compiler; agent transactional writer; TC LPM reader | longest-prefix destination lookup for exact, protocol-wildcard, then global-wildcard dimensions; staged and validated with ingress | 262,144 entries across two banks; compiler and agent cap each bank at 131,072 entries |
| `POLICY_CONFIG` | constant `u32` slot 0 | controller epoch, policy revision, combined entry count, schema, active bank | agent writer; TC reader | one atomic write activates matching banks; pinned | one entry; failed activation preserves the previous pointer |
| `EGRESS_SOURCES` | source identity and bank | lease plus six revision domains, contract/intent commitments, shared intent index, candidate counts, admission and family/standby flags | egress compiler; agent transactional writer; source TC reader | inactive entries are replaced/read back before the shared egress pointer changes; persistent ABI v14 | 131,072 entries across two banks; an explicit source is only fenced or active |
| `EGRESS_DESTINATIONS_V4`, `EGRESS_DESTINATIONS_V6` | exact intent index and bank followed by destination prefix | contract revision, intent digest, schema | egress compiler; agent transactional writer/reconstructor; source TC LPM reader | both families stage, read back, recover, roll back, and retire with source/candidate state under one pointer in persistent ABI v14 | 262,144 entries each; prefix length is 64 plus the network prefix, so `Any` remains isolated to its intent and bank |
| `EGRESS_ADDRESSES`, `EGRESS_GATEWAYS`, `EGRESS_SELECTIONS` | shared intent index, candidate or bucket, family, bank | exact egress address witness; certified route/neighbor/tunnel path; or 251-bucket primary/pre-certified-standby choice | egress compiler; agent transactional writer; source TC reader | all three tables stage and recover with `EGRESS_SOURCES` under one bank | 131,072 addresses, 262,144 gateway paths, and 4,112,384 no-preallocate selections; any partial stage preserves the active pointer |
| `EGRESS_CONFIG` | constant `u32` slot 0 | controller/projection/contract/path revisions, source/address/gateway/selection/destination counts, ABI schema, active bank | agent writer; source TC reader | sole atomic pointer; restart validates exact counts and removes uncommitted inactive state | one entry; zero config removes orphan staging state |
| `EGRESS_GATEWAY_NAT_SOURCES`, `EGRESS_GATEWAY_NAT_DESTINATIONS_V4/V6`, `EGRESS_GATEWAY_NAT_ADDRESSES`, `EGRESS_GATEWAY_NAT_GATEWAYS`, `EGRESS_GATEWAY_NAT_SELECTIONS` | source identity plus bank, followed by destination prefix, candidate, or bucket dimensions | exact heterogeneous contract/lease/intent/digest, local-primary gateway, address, and proof-witness projection | gateway compiler; agent transactional writer/reconstructor; gateway TC reader | seven dedicated maps stage/read back/recover/retire under one aggregate pointer in persistent ABI v14; identity namespacing prevents cross-contract revision/index aliasing | same bounded capacities as the source tables; malformed aggregate or owned state fails closed |
| `EGRESS_GATEWAY_NAT_CONFIG` | constant `u32` slot 0 | controller/projection revisions, aggregate counts, ABI schema, active bank, gateway-NAT flag | agent writer; gateway TC reader | sole aggregate gateway activation pointer; contract/path revisions are zero because one bank contains heterogeneous contracts | one entry; invalid state with any staged ownership is routed to a fail-closed NAT tail |
| `EGRESS_CONNECTIONS` | complete original or translated dual-stack L4 tuple, source identity, family, role | last-seen, contract/lease, original and translated tuples, chosen indexes, contract digest, proof witness, primary/standby gateway digests | gateway TC writer/reader; agent persistent owner | persistent ABI-v14 LRU; reverse key is reserved first and forward key second with `BPF_NOEXIST`, partial pairs roll back, and valid state survives projection churn until protocol timeout | 262,144 entries; 32 proof-salted full-cycle permutation candidates bound per-packet work and drop a new flow without overwriting an existing reverse tuple |
| `SERVICE_FRONTENDS_V4`, `SERVICE_FRONTENDS_V6` | exact address, network-order port, protocol, bank | ServiceId, revision-local frontend index, selected-tier slot count/code, ClientIP timeout/flag, actual StableHash/Maglev flag, schema, revision | verified-contract compiler; agent transactional writer; TC reader | both families and all origin-specific slot groups stage/read back together under ABI v14 | 262,144 physical entries each, capped at 131,072 per bank; an exact empty strict/fallback tier drops new flows while an unrelated tuple passes |
| `SERVICE_BACKENDS_V4`, `SERVICE_BACKENDS_V6` | ServiceId, BackendId, bank | revision, address, network-order port, protocol, lifecycle flags, schema | service compiler; agent transactional writer; TC reader | all endpoint lifecycle records stage with frontends; pinned | 524,288 physical entries each, capped at 262,144 per bank; new-flow slots admit only ready, non-terminating entries |
| `SERVICE_BACKEND_SLOTS` | ServiceId, revision-local frontend index, ordered slot, bank | stable BackendId, schema, revision | verified-contract compiler; agent transactional writer; TC reader | userspace materializes only the first non-empty SameNode/SameZone/Cluster tier; NodePort and per-Node LoadBalancer use disjoint high-index namespaces so internal and external policy cannot alias | 1,048,576 physical entries, capped at 524,288 per bank |
| `SERVICE_CONFIG` | constant `u32` slot 0 | controller epoch, service revision, frontend/backend/slot counts, schema, active bank | agent writer; TC reader | one write activates all five service tables; durable-checkpoint failure restores the prior pointer | one entry; absent/invalid config means no desired service lookup, while an existing valid connection remains usable until timeout |
| `SERVICE_CONNECTIONS` | complete IPv4/IPv6 L4 tuple plus forward/reverse role | last-seen, service revision, client/frontend/backend tuples, Cluster translated-source tuple, selected tier, affinity outcome, actual algorithm and NAT/DSR mode, ServiceId, BackendId, schema/flags | TC writer/reader | persistent ABI v14; NAT inserts reverse then forward and removes partial pairs, while DSR inserts and refreshes only the forward key; every lookup validates the complete mode-specific tuple before affinity | bounded 262,144-entry LRU; valid TCP/UDP state survives desired-state churn and endpoint draining until protocol timeout; corrupt/expired state is removed |
| `SERVICE_AFFINITY` | original client/frontend address, frontend port, protocol, family, active service bank; source port zero; affinity role | last-seen, service revision, stable BackendId, selected slot/tier, schema | TC writer/reader | persistent ABI v14; bank+revision identifies one immutable eligible table, timeout refresh is exact, and stale/current-invalid records are removed before actual-algorithm reselection | bounded 262,144-entry LRU; used only when the verified frontend requests ClientIP, while `None` creates no affinity state |
| `NODE_PORT_FRONTENDS_V4`, `NODE_PORT_FRONTENDS_V6` | local Node address, network-order NodePort, protocol, bank | ServiceId, dedicated frontend index, selected-tier slot count/code, ClientIP timeout/flag, actual StableHash/Maglev flag, service revision/bank, schema, external-policy flag | verified-contract compiler; agent transactional writer; ingress TC reader | both families stage/read back under a NodePort-specific bank and reference an origin-independent service slot namespace in ABI v14 | 262,144 physical entries each, capped at 131,072 per bank; external Local is resolved before soft topology and never aliases ClusterIP internal policy |
| `NODE_PORT_CONFIG` | constant `u32` slot 0 | controller epoch, service and local-Node revisions, family counts, schema, active NodePort bank | agent writer; ingress TC reader | independent pointer references values that must name the exact active service epoch, revision, and bank; address-only changes do not churn ClusterIP maps | one entry; dual-pointer crash recovery either commits the complete prepared tuple or restores the prior durable tuple before attachment |
| `LOAD_BALANCER_FRONTENDS_V4`, `LOAD_BALANCER_FRONTENDS_V6` | VIP address, network-order Service port, protocol, bank | ServiceId, dedicated per-Node frontend index, selected-tier slot count/code, ClientIP timeout/flag, actual StableHash/Maglev and explicit DSR flags, service/reachability/allocation revisions, referenced service bank, schema, policy/source-range flags | verified-contract compiler; agent transactional writer; TC reader | both families stage and read back under an independent bank in persistent ABI v14 and reference disjoint coherent service slots | 262,144 physical entries each, capped at 131,072 per bank; collision or partial stage preserves the active bank |
| `LOAD_BALANCER_SOURCE_RANGES_V4`, `LOAD_BALANCER_SOURCE_RANGES_V6` | ServiceId, VIP bank, source IPv4/IPv6 prefix | exact service/reachability/allocation revisions and schema | LoadBalancer compiler; agent transactional writer/reconstructor; TC LPM reader | runtime-only tries stage/read back/rollback with VIP state and reconstruct from authenticated durable checkpoints before attachment; deliberately excluded from persistent ABI v14 ownership | 262,144 entries each; an enabled frontend with no coherent longest-prefix match drops with bounded provenance |
| `LOAD_BALANCER_CONFIG` | constant `u32` slot 0 | controller epoch, service/reachability/allocation revisions, family counts, schema, active VIP bank, referenced service bank | agent writer; TC reader | one atomic write activates exact owner-only VIP state after frontend and source-range readback plus prepared-checkpoint persistence | one entry; restart completes or rolls back from exact map/checkpoint evidence |

`FlowEvent` carries no Kubernetes strings. ABI v2 records the applied policy
revision, actual verdict/reason/policy/rule, and optional shadow
verdict/reason/policy/rule. In `POLICY_RULES`, TC looks up the exact protocol/port,
then the same protocol with port zero, then the protocol/port-zero global fallback
in the bank selected by `POLICY_CONFIG`.
Identity, policy, and service config/value pairs must have the expected schema and an
identical nonzero revision.
Event and map ABIs use fixed C layouts, explicit schema/version fields, and
compile-time size assertions.

`ServiceEvent` ABI v3 remains 96 bytes. Two formerly reserved bytes record the
bounded frontend class and selected SameNode/SameZone/Cluster tier; the other
eight bytes must remain zero. New-connection failures receive both dimensions
from the exact validated frontend; forward, reverse, and expiry events derive
them from persistent connection state. This keeps classification correct through
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

`SERVICE_DATAPLANE_TAIL_CALLS` is a runtime-only six-entry program array. The agent
loads IPv4/IPv6 policy, DSR FIB, and gateway-NAT stages into it before either
main TC hook attaches. Per-CPU post-lookup scratch transfers only fixed-width
observation and mode flags between stages. Missing policy, DSR, or owned-gateway
targets fail closed; neither runtime map belongs to the persistent 40-map
ABI-v14 set.

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
current ABI v14 link directory and atomically updates that link to the newly loaded
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
accepts only the known v1–v14 map names and numeric UNF TCX link-pin names,
refuses unknown directory content, and requires `--allow-current-abi` for v14. Legacy
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

## Egress dataplane state

Phase 8.5 now has a verified fixed-width egress ABI contract. Persistent ABI
v14 owns its source, destination, candidate and selection banks, source config,
dedicated aggregate gateway-NAT banks, and connection LRU; v13 remains an exact
historical 33-map cleanup boundary.
Explicit source entries are only fenced or active; absence remains native.
Source-local path certificates bind gateway
transport, next hop, interface, MTU, mode, revision, and lease before active
lowering. Candidate and 251-bucket rendezvous tables are shared per intent and
store a primary plus pre-certified standby when available. Fixed connection and
event layouts retain the original/translated tuple and bilateral proof
provenance. Inactive-bank replacement/readback, atomic activation, capacity
rollback, pointer-authoritative recovery, and exact cleanup now pass agent,
eBPF, and privileged real-kernel tests. An authenticated exact-Node source
endpoint feeds independently replayed contracts into fenced map banks, while
destination-exact source TC steering executes only after egress policy allows
the original flow. The controller issues a digest-bound activation grant only
after every selected gateway application is current; the source separately
reads back the exact native route set, Node identity, transport, interface
index, MTU, and stable dual-stack route revision before atomically entering
`Active`. Loss of either proof and restart return through a destination-preserving
fence. A separate authenticated projection now drives Node-UID-bound `/32` and
`/128` ownership on `unf-egress0`; exact proxy-NDP ownership on the configured
IPv6 uplink, whole-host collision preflight, exact kernel readback, and
all-selected-gateway quorum precede readiness. Withdrawal
quarantines those addresses until a checkpoint-v2 retirement manifest has
frozen the exact source/gateway/lease set and a schema-v1 Proof of Safe
Forgetting joins complete source fences, zero-flow gateway drains, and the exact
reachability withdrawal. Reconciliation, time, and leadership cannot infer
release. Collision-safe dual-stack SNAT/reverse processing now validates the
full contract/lease/digest/witness chain, reserves reverse then forward state
without overwrite, and performs checksum-safe family-specific translation.
Production watched-state joining, live release-evidence transport, sparse NAT
events, and a complete dual-stack Kind lifecycle now close milestone 8.5.
ADRs 0119–0135 record the verified boundary; measured HA/failover begins 8.6.

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
