# Universal Network Fabric (UNF)

UNF is an early-stage, Rust-first Universal Network Fabric for Kubernetes and
OpenShift, powered by an eBPF node dataplane. Its goal is one identity-aware,
explainable, programmable fabric spanning policy, services, routing, egress,
encryption, observability, and eventually multiple clusters. eBPF is the primary
high-performance local execution engine; it does not force control-plane,
routing-protocol, encryption, gateway, or L7 responsibilities into kernel
programs where another bounded provider is safer.

Phase 1 established observation, Phase 2 added identity-aware L3/L4 enforcement,
Phase 3 completed bounded Kubernetes compatibility and simulation, the full-CNI
foundation owns dual-stack Pod networking, and Phases 4–6 provide native eBPF
dual-stack ClusterIP, NodePort, and explicit-class LoadBalancer fabrics on exact
kube-proxy-free Kind and OpenShift tuples. Phase 7 has verified locality,
affinity, scalable selection, opt-in DSR, and their bounded operations contracts;
the exact kube-proxy-free Kind and OpenShift tuples are independently
live-qualified.
UNF is **not production-ready**; these results are bounded development
qualifications, not a general production support claim.

## Project status

Phase 1's observation gate and Phase 2's first enforcement gate are verified in
a two-node kind cluster. Collision-checked identities and transactional policy
revisions now drive TC allow/drop decisions with actual and shadow provenance.
The supported ingress `NetworkPolicy` slices are live-verified through the same
controller, policy engine, and dataplane. Read-only what-if simulation compares
candidate native or Kubernetes NetworkPolicy resources against revision-fenced,
direction-aware dual-stack topology and retained history without applying them.
Versioned topology snapshots expose Nodes, workload placement,
Services, selector intent, and EndpointSlice-derived runtime backend readiness.
Node agents also export direction-selected flow observations into bounded,
revisioned history for operator queries and policy impact analysis. Ingress and
egress decisions remain distinct logical keys, including external egress from a
resolved source. The controller
checkpoints the newest bounded subset across restarts, and `unfctl flows` supports
inclusive last-received-time windows and newest-first limits. Agents publish revisioned status
acknowledgements using Pod-bound, audience-scoped Kubernetes tokens; TokenReview
and authoritative Pod placement prevent anonymous or cross-Node claims. Controller
and CLI status report freshness-aware cluster convergence for every watched Node.
The controller checkpoints the bounded authenticated report set to a dedicated
ConfigMap every two seconds and restores it before watchers start, so a restart
preserves last-known status while the new epoch still requires fresh agent
acknowledgements before convergence can become true.
Identity/policy snapshots, acknowledgements, and flow telemetry use a separate
TLS-only controller port; agents trust only the mounted UNF CA and authenticate
every internal request with their rotating Pod credential. The reserved internal
port is filtered from workload logs/export so management traffic cannot create a
recursive telemetry loop.
An optional external HTTP backend forwards only authenticated and validated flow
batches in a versioned epoch/sequence/topology envelope. Its bounded non-blocking
queue, at-least-once retry, dedicated delivery/loss metrics, HTTPS/private-CA
trust, and rotating token-file authentication keep receiver outages independent
from local history and agent ingestion. Capacity, current-depth, and lifetime
high-water gauges make saturation directly observable. The focused Kind gate
removes and restores the receiver, then applies sustained receiver latency to
prove the queue bound, monotonic delivery sequence, explicit loss accounting,
and uninterrupted internal ingestion.
The resolved-identity fast path
is now dual-stack for IPv4/IPv6 TCP/UDP/SCTP, including verifier-bounded IPv6
extension-header traversal; native policy and selector-based NetworkPolicy IPv6
decisions are live-verified. The upstream-aligned three-Namespace ingress matrix
now runs its supported selector, additive-policy, named-port, and TCP/UDP
protocol-isolation transitions against direct IPv4 and IPv6 Pod addresses. The
selector coverage includes multi-value Pod `In` combined with Namespace `NotIn`
and homogeneous multi-`podSelector` peer OR.
A separate self-cleaning egress matrix now live-verifies source-selected default
isolation, non-selected pass-through, Namespace/Pod destination selector AND,
named TCP/UDP ports, protocol-only SCTP, bounded dual-stack `ipBlock` exceptions,
direction-correct dataplane provenance, deletion recovery, and final state
reconvergence. The same matrix is part of the dual-stack OpenShift gate, where it
also verifies RHCOS/SELinux cross-worker behavior, OVN host-network replies,
explanation, retained history, read-only simulation, and healthy operators.
A one-to-one audit pinned to Kubernetes commit
`9aac5f741fa6095594cdfed4756a52cf0bf4b191` now classifies all 49 primary TCP,
UDP, and SCTP scenarios as verified with no unclassified or excluded bounded L4
case; the complete evidence and explicit runtime-state boundaries are tracked in the
[conformance matrix](docs/development/networkpolicy-conformance.md).
Identity, policy, and service updates use independent transactional banks
selected by atomic configuration-map writes. All eighteen desired-state and
reserved service-connection maps persist in the ABI-v4 bpffs directory;
replacement agents validate and adopt last-known-good identity/policy/service
state—including populated dual-stack egress banks on the source Node—while
fresh or incompatible startup remains fenced from readiness until
reconciliation.
TC attachments now survive agent replacement: kernels supporting TCX use
per-interface pinned links and atomic link updates, while older kernels use a
stable legacy netlink filter tuple for in-place replacement. The two-node kind
gate continuously probes an explicitly denied flow through TCX agent handoff.
Both components now expose a versioned compatibility endpoint containing their
embedded Git revision, persistent BPF-state ABI, and controller-agent wire
schemas. A focused two-node Kind gate builds adjacent committed revisions and
proves controller-first N+1/N operation, deterministic one-Node-at-a-time agent
rollout, agent and controller rollback, fresh epoch convergence, telemetry
continuity, and uninterrupted allow/deny enforcement. This support applies only
while the published compatibility tuple is unchanged.
A separate skipped-revision gate requires a baseline at least two commits behind
the current revision and exact tuple equality before repeating the complete
controller-first, node-serial, rollback, forwarding, and telemetry matrix.
The Phase 3 gate and all 42 deliverables are Verified. Exact closure evidence,
limits, and the separately tracked full-CNI entry are maintained in the
[Phase 3 completion and full-CNI entry plan](docs/development/phase3-completion-plan.md)
and ADR 0056.
The bounded full-CNI foundation is Verified under ADRs 0057–0073. The `unf-cni`
executable now composes dual-stack IPAM, exact veth, and native routing through
atomic ADD/CHECK/DEL transactions and reconciles reboot-stale ownership from the
CNI 1.1 `cni.dev/valid-attachments` authority. GC uses bounded network-scoped
pages, retains conflicting records and leases for retry, and continues cleaning
independent stale attachments. When the agent socket is unavailable during
reboot, DEL first journals its exact key in an owner-only bounded queue; the next
ADD/CHECK/DEL/GC drains that queue through the same exact lifecycle before it can
proceed. The default path also protects compatible CRI-O caches written before
the setting existed. A committed OpenShift fault gate verifies pre/post CHECK,
socket-offline CRI-O DEL persistence, serialized cleanup before recovery ADD,
exact dual-stack lease reuse, and final zero-leak state. An explicitly enabled
local-agent Unix service provides the root-authenticated, bounded schema-v2
transaction boundary and atomic durable attachment/dual-stack lease journal
beneath that lifecycle. Its
modular IPAM provider allocates deterministically from explicit node blocks, migrates
schema-v1 attachment state, and releases leases only after abort/delete
completion. A typed-netlink `unf-link` primitive now creates, moves, configures,
recovers, reads back, and exactly removes dual-stack veth pairs from those durable
records. A typed native route/neighbor primitive now adds exact dual-stack
endpoint routing with scoped rollback, conflict preservation, and verified
MTU/fragmentation boundaries. An explicitly opted-in Node now receives its own
authenticated, revisioned dual-stack `spec.podCIDRs` snapshot from the controller;
the agent validates durable provider provenance, persists owner-only state, and
acknowledges application before convergence. Provider-neutral remote Node/block
intent now lowers into deterministic, exact native IPv4/IPv6 block routes with
independent family paths, typed-netlink replay/readback/repair/delete, scoped
rollback, and foreign-state preservation. The controller now distributes complete,
authenticated epoch/revision-fenced remote-route snapshots, and an explicitly
configured agent reconciler restores owner-only last-known-good state, applies
atomic route-set replacements, retires stale routes after replacement, and
reports desired/applied/error state. A five-Node dual-stack OpenShift 4.22.10
Agent-based installation now runs UNF as the primary Pod network with zero
temporary policies, healthy operators, five converged agents, and cross-worker
IPv4/IPv6 forwarding. Digest-pinned clean reboot, socket-offline CRI-O DEL,
runtime-fault cleanup, exact worker teardown to no CNI, and host-network
reprovision from zero all pass committed gates. Qualification remains limited
to the exact recorded development tuple; production repositories and other
platform versions are not inferred. Existing overlay deployments are unchanged.
See the [cl02 installation checkpoint](docs/development/openshift-primary-cni-cl02-install.md).
Phase 4 is Verified across all eight bounded milestones. It adds strongly typed
`ServiceId`/`BackendId` values and a bounded, schema-versioned,
Kubernetes-independent dual-stack service IR, plus deterministic Kubernetes
Service/EndpointSlice compilation with collision-checked IDs, exact family and
port matching, lifecycle provenance, last-valid retention, and explicit status.
Agents retrieve that snapshot over the authenticated internal TLS channel and
reject compatibility or epoch/revision violations. Dataplane agents compile
fixed dual-stack frontend/backend/slot tables, read back an inactive bank,
atomically activate it, couple the mode-0600 last-known-good checkpoint to
rollback, and expose desired/applied/failed state. ABI v4 also reserves the
bounded persistent service-flow layout accepted by ADR 0077. The source-side TC
dataplane now performs exact IPv4/IPv6 TCP/UDP ClusterIP DNAT, paired reverse
SNAT, checksum repair, deterministic ready/non-terminating backend selection,
connection persistence through service churn, protocol-bounded expiry, and
explicit backendless drop. A privileged repeatable gate executes packets through
the verifier-loaded release object and validates fixed ServiceId/BackendId/
revision provenance. A fixed service-event ABI now carries translation, drop,
expiry, selected backend, tuple, and revision evidence into low-cardinality
metrics, agent status, non-blocking flow export, durable history, and
`unfctl service-explain`; malformed events and inconsistent provenance fail
closed. Platform qualification is tracked by the
[Phase 4 service-fabric plan](docs/development/phase4-service-fabric-plan.md).
A dedicated three-node Kubernetes 1.35 dual-stack Kind fixture now runs UNF as
the sole primary CNI with kube-proxy absent. Its repeatable gate proves direct
Pod and DNS continuity, native IPv4/IPv6 TCP/UDP ClusterIP lifecycle,
backendless provenance, controller-offline replacement of both worker agents
from durable/pinned state, exact workload cleanup, and restoration to the saved
no-CNI baseline. The five-node OpenShift 4.22.10 gate then migrates the preserved
service state controller-first, replaces agents serially, removes kube-proxy,
and repeats the dual-stack TCP/UDP/DNS lifecycle plus controller-offline source
and destination agent recovery on RHCOS/SELinux/CRI-O. It leaves all five agents
converged on persistent ABI v4, retires only ABI v3, and introduces no new
unhealthy operator. ADRs 0080–0081 record the non-transitive Kind and OpenShift
boundaries.
Phase 5 advances the verified ClusterIP fabric with bounded NodePort exposure. Service
snapshot schema v2 preserves the allocated NodePort per address family, its
exact ClusterIP Service-port and backend linkage, and explicit `Cluster` or
`Local` external traffic policy. Collision, malformed linkage/policy, and
capacity failures are rejected deterministically; see the
[Phase 5 NodePort plan](docs/development/phase5-nodeport-plan.md) and ADR 0082.
The distribution transition is now verified: agents explicitly negotiate
schema v2, new controllers project an exact schema-v1 ClusterIP view for old
agents, new agents read old-controller v1 state without rewriting rollback-safe
checkpoints, and capability-aware acknowledgements prevent a legacy agent from
claiming convergence when NodePort intent exists. ADR 0083 records the four-way
mixed-version contract. The first transactional host-state slice is also
verified: the controller derives bounded Node `InternalIP`/`ExternalIP` intent,
serves only the TokenReview-authenticated agent's Node with independent
revision/relist/last-valid semantics, and compiles it into a fixed dual-stack,
independently banked NodePort ABI referencing an exact ClusterIP service bank.
At that 5.3a boundary no agent mutated those maps. ADR 0084 and
`make nodeport-host-state-test` define it. Phase 5.3 is now complete:
persistent ABI v5 owns an exact 21-map set, and the agent uses a composite
service/Node checkpoint plus independently banked NodePort maps for transactional
staging, readback, address-only switching, rollback, dual-pointer crash repair,
restart recovery, and v4/v5 cleanup. `make nodeport-transaction-test` and ADR
0085 verify that lifecycle. Phase 5.4 is now verified by
`make nodeport-cluster-dataplane-test`: exact Node-address/port/protocol matches
perform dual-stack TCP/UDP DNAT and paired NodePort reverse SNAT through the
coherent service bank, retain connections across backend churn, preserve
checksums and provenance, use bounded collision-safe Node source ports so
cross-node replies return to the owning connection, and apply ingress policy to
the original source plus translated backend identity and port. The bounded
allocator now uses a per-flow odd-stride permutation of the complete dynamic
port range, avoiding correlated adjacent-port exhaustion across compatible
agent replacement without increasing verifier work; ADR 0091 records this
recovery invariant. Phase 5.5 is
also verified: `Local` uses transactionally merged receiving-Node slots, admits
only ready non-terminating local backends, preserves the external source, and
returns exact no-local-backend evidence through placement/readiness loss and
recovery. `make nodeport-local-dataplane-test` and ADR 0087 define that gate.
Phase 5.6 is verified by `make nodeport-operations-test`: fixed-size service
events explicitly classify ClusterIP, NodePort/Cluster, and NodePort/Local;
fixed-cardinality metrics and schema-v5 agent status expose desired/applied and
outcome counts; schema-v5 export plus schema-v6 history retain the class across
bounded schema-v5 checkpoint recovery; explanation can filter it; and
`unfctl service-simulate` predicts exact current Node/address/port/protocol
eligibility without mutation. ADR 0088 records the schema and restart boundary.
Phase 5.7's repeatable `make nodeport-kind-test` gate is verified as a strict
superset of the kube-proxy-free dual-stack Service fixture. It covers both
traffic policies through exact worker addresses, source/reverse tuple behavior,
retained UDP flows across readiness withdrawal, lifecycle failure and recovery,
classified operations, controller-offline worker-agent replacement, empty-map
cleanup, exact ABI-v5 rollback, and immutable evidence. The fixture also
captures, applies, and restores the exact IPv4 reverse-path/local-source host
settings needed by NodePort; OpenShift persists the same settings through both
MachineConfigPools. Runtime and qualification revision `bc03d5c` passed the
uninterrupted gate in 820 seconds on Kubernetes v1.35.0 with kube-proxy absent,
including all-node host-origin ClusterIP and both controller-offline
worker-agent replacements, empty-map audit, and exact no-CNI/sysctl rollback.
ADRs 0089–0091 define and record the gate, host contract, and restart allocation
invariant. Phase 5.8 independently verifies the OpenShift boundary.
`make nodeport-openshift-deploy` followed by `make nodeport-openshift-test`
persists the host contract through both
MachineConfigPools, stages ABI v5 controller-first and one agent at a time from
digest-only Quay images while kube-proxy remains absent, then repeats the
cross-worker lifecycle, source/reverse, offline-recovery, operations, cleanup,
and platform-health matrix. Runtime revision `bc03d5c` and committed qualifier
`76828c3` passed that 3,803-second gate on five-Node dual-stack OpenShift 4.22.10
cl02 with five converged agents, exact cleanup, and no new unhealthy operator
beyond baseline disconnected `insights`. ADR 0092 records this non-transitive
boundary. All Phase 5 milestones are Verified; LoadBalancer, affinity, topology
hints, Maglev, DSR, host-origin NodePort, SCTP, fragments, generic NAT `RELATED`,
and production availability/scale retain independent gates.
Phase 6 completes bounded LoadBalancer exposure. Its architecture milestone
is the ownership and acceptance boundary: UNF admits the explicit
`network.unf.io/load-balancer` class by default and models VIP allocation,
network advertisement, and eBPF translation as independent revisioned
transactions. Status may publish a VIP only after the admitted provider and
dataplane converge, direct delivery cannot depend on a traffic NodePort, and
foreign controller/network state must survive reconciliation. The
[Phase 6 LoadBalancer plan](docs/development/phase6-loadbalancer-plan.md) and
ADRs 0093–0101 define the ordered schema, provider, dataplane, operations,
Kind, and OpenShift gates. Milestone 6.2 is verified: schema v3 carries exact
dual-stack class/family/policy/source-range/requested-VIP intent, projects safe
v2/v1 views, retains last-valid Kubernetes compilation, and makes existing
lowerers reject VIP intent. Milestone 6.3 is also verified: deterministic
conflict-safe dual-stack leases retain exact pool/provider/Service ownership;
complete revisioned direct-Node intent, acknowledgements, withdrawal, durable
recovery, publication ordering, and foreign Kubernetes state preservation pass
`make loadbalancer-control-plane-test`. Milestone 6.4 is also verified:
explicit compatibility negotiation, epoch-fenced durable allocation,
finalizer-safe withdrawal, Pod-bound per-Node state, capability-aware
acknowledgements, private checkpoints, and independent transactional ABI-v6 VIP
maps pass `make loadbalancer-host-state-test`. Milestone 6.5 is verified as
well: the TC path consumes only a coherent Service/reachability/allocation
tuple, performs dual-stack TCP/UDP VIP DNAT plus bounded collision-safe source
translation and reverse restoration, retains established flows through churn,
evaluates ingress policy against the selected backend, and stops intercepting
fresh flows after transactional VIP withdrawal. The release object and all
ClusterIP/NodePort regressions pass `make loadbalancer-cluster-dataplane-test`.
Milestone 6.6 is verified too: receiving-Node-only Local selection preserves
external client tuples, exact dual-stack source CIDRs fail closed, runtime
source-range state reconstructs before attachment, and dual-stack
`healthCheckNodePort` listeners follow local placement with HTTP 200/503. The
release verifier and every Cluster/NodePort/ClusterIP regression pass
`make loadbalancer-local-dataplane-test`. Milestone 6.7 is verified:
fixed-cardinality metrics and validated status,
durable Cluster/Local history, lease/provider/reachability-aware explanation,
source-aware read-only VIP simulation, exact recovery, and adjacent additive
compatibility pass `make loadbalancer-operations-test`. Milestone 6.8 is verified:
runtime/qualifier `830771c` re-passed the 280-second three-Node
Kubernetes v1.35.0 dual-stack gate with kube-proxy absent. External and
host-origin IPv4/IPv6 TCP/UDP Cluster/Local paths, source ranges, health,
lifecycle, controller/provider/agent recovery, exact ABI-v7/CNI cleanup, and
no-CNI rollback pass `make loadbalancer-kind-test`; ADR 0100 records the
non-transitive evidence. Milestone 6.9 and Phase 6 are verified: runtime
`830771c`, qualifier `ade286b`, and three immutable public Quay digests passed
the guarded rollout plus 973-second five-Node OpenShift 4.22.10 cl02 gate.
Workstation cross-worker dual-stack Cluster/Local traffic, source semantics,
source ranges, health, lifecycle, operations, recovery, ABI-v7 reconstruction,
exact owned-state cleanup, convergence, and unchanged unhealthy-operator
baseline passed; ADR 0101 records the platform boundary.
Phase 7 now begins advanced Service selection. Strict `internalTrafficPolicy`
eligibility precedes topology preferences; `ClientIP` affinity may select only
from the currently eligible set; existing connection persistence remains a
separate, stronger per-flow contract. Selection tables are compiled in
userspace and consumed through bounded eBPF lookups. Maglev has earned bounded
adoption through deterministic disruption, balance, memory, update-cost, and
packet-cost measurements. DSR is now an explicit UNF LoadBalancer-only mode
whose route, neighbor, MTU, backend-VIP ownership, policy, source-range,
telemetry, recovery, and cleanup invariants pass a separate real-kernel gate. The
[Phase 7 service-selection plan](docs/development/phase7-service-selection-plan.md)
and ADR 0102 define the ordered implementation and qualification gates.
Milestone 7.2 is verified: service schema v4 carries normalized internal policy,
ClientIP affinity timeout, topology preference, selection algorithm, and
forwarding mode. Kubernetes defaults and aliases are canonicalized, timeout and
unknown values fail closed, schemas v1/v2/v3 migrate only default state, and
legacy projection refuses advanced intent. Existing lowerers explicitly reject
advanced behavior until transactional state exists; `make
service-selection-ir-test` and ADR 0103 record this non-dataplane boundary.
Milestone 7.2a is verified: every future per-Node selection plan can be wrapped
in a canonical Network Behavior Contract that binds its exact source, topology,
Node, frontend, intent, eligibility tiers, and capabilities. Independent replay
reproduces domain-separated SHA-256 plan/contract digests and bounded explicit
endpoint/Node/zone failure outcomes; compact witnesses provide revision-exact
decision provenance. Mutation, property, golden encoding, JSON replay, and
strict Clippy pass `make service-selection-contract-test`; ADR 0104 records that
this is a pre-activation control-plane contract, not packet behavior or a formal
correctness proof.
Milestone 7.3 is verified: the controller negotiates and serves an authenticated
UID/zone-bound contract for the requesting Node and the agent advertises only
its implemented StableHash/NAT capabilities. The agent independently verifies
the source and digest, stages and reads back one of two userspace banks, commits
owner-only contract+Node state with the Service transaction, repairs crash
boundaries, reconstructs cold state, and acknowledges the exact revision and
digest required for convergence. Safe legacy fallback is restricted to default
intent; advanced intent fails closed. `make service-selection-state-test` and
ADR 0105 record the gate.
Milestone 7.4 is verified: the agent lowers each verified contract to the first
non-empty strict/topology tier and atomically activates fixed-width ABI-v8
frontend and slot state. ClusterIP, NodePort, and LoadBalancer retain independent
origin policy, strict internal/external `Local` never broadens, and
`PreferSameNode`/`PreferSameZone` fall back in the contracted order. IPv4/IPv6
TCP/UDP lowering, topology-only bank changes, lifecycle filtering, exact
recovery, fail-closed validation, and tier-bearing event ABI v3 pass `make
service-selection-dataplane-test`; ADR 0106 records the packet boundary.
Milestone 7.5 is verified: exact original-client/frontend `ClientIP` affinity
uses a bounded persistent LRU, honors the Kubernetes timeout, reuses only the
same immutable eligible bank+revision, and yields to existing per-flow state.
Ready non-terminating endpoints alone receive new sessions, while established
connections survive termination until protocol expiry. Dual-stack real-kernel
packets, timeout reselection, create/reuse/reselection provenance, ABI-v9
recovery/cleanup ownership, inherited 7.4 gates, and strict Clippy pass `make
service-affinity-dataplane-test`; ADR 0107 records the boundary. Milestone 7.6
is verified: userspace materializes measured Maglev tables in the existing slot
map, keeps the same one-map packet path, records actual algorithm/fallback, and
advances persistent ownership to ABI v10. Enable it per Service with
`network.unf.io/service-selection-algorithm: maglev`; the committed fixture,
`make service-maglev-dataplane-test`, and ADR 0108 record the evidence.
StableHash/NAT remain absence defaults for rolling compatibility. DSR remains
opt-in: set both annotations below only after every admitted backend is prepared
to own every advertised VIP and listen on the unchanged Service port.

```yaml
network.unf.io/service-forwarding-mode: dsr
network.unf.io/dsr-backend-vip-ownership: acknowledged
```

Milestone 7.7 is verified. The controller rejects DSR on non-LoadBalancer
Services or changed backend ports, per-Node contracts require dual-stack DSR
capabilities, and ClusterIP/NodePort frontends for the same Service stay NAT.
The eBPF path retains the VIP tuple, applies the existing selection, lifecycle,
source-range, and policy contracts, proves route/neighbor/MTU through a backend
FIB lookup, and uses direct or kernel neighbor output without changing the VIP
tuple. Runtime-bound transport topology keeps stacked VLAN and checksum work in
the device path and fails closed without per-flow NAT fallback. Forward-only
connection state and a direct-return packet are
real-kernel tested under persistent ABI v11. `make service-dsr-dataplane-test`
and ADR 0109 record the focused boundary. Actual cross-worker backend-VIP
ownership, original-source preservation, and return routing are independently
verified on Kind and stacked-VLAN RHCOS OpenShift.
Milestone 7.8 is verified by `make service-selection-operations-test` and ADR
0110. Fixed-name metrics and validated status-v8 expose the selected tier,
actual StableHash/Maglev algorithm, affinity reuse/create/reselection, and
NAT/DSR mode without Service/backend labels. Flow export v6 and durable history
v7/checkpoint v6 retain the same backend and revision witness; older evidence
migrates explicitly as `unknown`. `unfctl service-explain` correlates current
intent and drain state with observation-weighted revision history, while
`unfctl cluster-ip-simulate`, `unfctl service-simulate`, and `unfctl
load-balancer-simulate` return
the digest-bound per-Node eligibility plan without mutating state or guessing
private connection/affinity entries. That gate used ABI v11; current egress map
ownership now uses the all-or-none persistent ABI v15 boundary; v14 remains a
recognized historical 40-map cleanup scope and v13 a historical 33-map scope.
Milestone 7.9 is verified. Runtime/qualifier `06fc937` passed the 463-second
three-Node Kubernetes v1.35.0 dual-stack gate with kube-proxy absent.
Real traffic proved strict SameNode/SameZone/Cluster fallback, ClientIP
creation/reuse/timeout/reselection, graceful endpoint withdrawal, measured
Maglev and StableHash provenance, and acknowledged cross-worker IPv4/IPv6
LoadBalancer DSR with direct return. Controller-offline agent replacement,
status/history/simulation, exact fixture cleanup, scoped ABI-v11 cleanup,
fingerprinted CNI removal, CoreDNS restoration, and no-CNI rollback passed
`hack/verify-kind-service-selection.sh`; ADR 0111.
Milestone 7.10 is verified independently. Runtime `06fc937` and qualifier
`018f14c` passed the 1,670-second digest-pinned five-Node OpenShift 4.22.10 /
Kubernetes 1.35.6 cl02 gate on RHCOS, Enforcing SELinux, and CRI-O without
kube-proxy. The complete Phase 6 regression, dual-stack node/zone/cluster
fallback, affinity/draining, Maglev/StableHash provenance, acknowledged
cross-worker DSR source/return tuples and source ranges, controller-offline
worker-agent replacement, exact cleanup, five-agent convergence, and unchanged
`insights`/`network` unhealthy baseline passed
`hack/verify-openshift-service-selection.sh`; ADR 0112.
Phase 8 implements a verified identity-aware enterprise egress fabric. All
milestones 8.1 through 8.11 are verified. Source-side security policy precedes steering and NAT, while
`unf-egress` now canonically validates bounded Namespace, workload, and
ServiceAccount selectors, destinations, non-overlapping dual-stack pools, and
pool or explicit multiple-address intent. The controller strictly translates
OpenShift `k8s.ovn.org/v1` EgressIP into that same model and preserves foreign
status ownership. Native egress remains the safe default until explicit intent
is admitted. The [Phase 8 plan](docs/development/phase8-egress-fabric-plan.md)
and ADRs 0113–0157 record the architecture and evidence. Milestone 8.2a adds schema-v1 exact-Node
Egress Behavior Contracts: independent replay binds source identity, original
destinations, policy allow, exact allocation, lease-fenced ready/reachable
gateways, capabilities, and six revision domains, with SHA-256 commitments,
compact witnesses, and bounded failure outcomes. `make egress-contract-test`
passes. Milestone 8.3 now adds schema-v1 durable atomic multi-address
allocation, exact pool/provider provenance, monotonic lease epochs, checkpoint
replay, separate gateway/readiness and reachability acknowledgements, safe
withdrawal, and publication only after both providers acknowledge the exact
revision. Milestone 8.4 then binds schema/capability negotiation to an existing
authenticated Pod/Node principal, independently replays each exact-Node
contract, and admits only that result into separate digest-bound userspace
gateway banks. Staged readback, pointer rollback, strict checkpoints, crash
repair, cold reconstruction, and version-scoped cleanup pass `make
egress-host-state-test`; ADRs 0116–0117. Before freezing the packet ABI,
milestone 8.4a adds the default Egress Proof Chain: explicitly managed
identities transition through a fail-closed fence, the original flow
deterministically chooses a same-family address and ready gateway, and that
gateway independently reproduces a strict contract-, lease-, identity-, and
tuple-bound proof. Ten adversarial tests pass `make egress-proof-test`; ADR
0118. The proof is provenance, never an identity credential. Milestone 8.5
adds authenticated gateway projections that aggregate only admitted
source contracts selecting that gateway, and exact route/interface/next-hop/
transport/MTU certificates lower into asserted fixed-width ABI-v1 source,
candidate, selection, connection, and event state. Userspace compiles 251
rendezvous buckets shared per intent, including a precomputed standby path by
default when two gateways exist; packets will need only one stable hash and map
lookup. The contract gate passes `make egress-dataplane-contract-test`; ADR
0119. Persistent ABI v15 now owns and transactionally recovers the source,
destination, candidate and selection banks, atomic source and aggregate gateway
pointers, dedicated heterogeneous gateway-NAT banks, and connection LRU;
capacity rollback is proven on real kernel maps while v14 remains a historical
exact 40-map cleanup boundary and v13 a historical 33-map boundary (ADRs 0120,
0126, 0129, and 0144). The internal
TLS API now distributes a
self-contained source envelope only after Pod-bound TokenReview authentication
and authoritative Node-UID binding. The agent independently replays it and
atomically stages explicit intent only as `Fenced`; absence or any validation /
transaction failure retains last-known-good state. This passes `make
egress-live-distribution-test`; ADR 0121. Structural cluster-scoped
`EgressPool`/`EgressPolicy` APIs and the optional read-only OpenShift EgressIP
watcher now feed one transactional, revisioned, schema-v1 ConfigMap-backed
canonical model. Invalid updates/relist or restart drift retain last-known-good
state, foreign status is ignored, and accepted model changes withdraw stale
source authority. This passes `make egress-desired-state-test`; ADR 0122.
The POST-only gateway endpoint now derives its exact Node from the same
Pod-bound authentication, publishes only controller-admitted contracts that
name that ready/reachable lease-fenced candidate, and sends a monotonic empty
projection for explicit withdrawal. The gateway agent independently validates
and fences that state under `make egress-gateway-distribution-test`; ADR 0123.
The watched revision now drives a separate schema-v4 durable control-plane
checkpoint that atomically allocates bounded addresses and emits deterministic
lease-fenced gateway Ensure/Withdraw intent over Ready primary-CNI Nodes with
authoritative UIDs. Pool tombstones and dual-provider withdrawal retain an
address until safe reuse with a newer lease epoch, while ordered
desired-before-derived persistence makes restart replay fail closed. This passes
`make egress-control-plane-test`; ADR 0124. Delivery is now explicitly separate
from application: the source acknowledges the exact revision/digest only after
transactional map activation, which alone admits it for gateway distribution;
every selected gateway then acknowledges exact monotonic ledger adoption or
withdrawal. Pod replacement, mutation, invalidation, and stale replay fail
closed, while status exposes issued applications and bilateral readiness under
`make egress-application-ack-test`; ADR 0125. Egress ABI v2 now adds banked
intent-prefixed IPv4/IPv6 destination LPM state, and the source TC path runs
NetworkPolicy first, leaves service and nonmatching traffic on their native
paths, drops fenced or incoherent exact targets, then uses the original-tuple
bucket to hand an unchanged packet to a certified direct neighbor. The
real-kernel dual-stack gate passes `make egress-source-steering-test`; ADR 0126.
The source now crosses `Fenced -> Active` only when a digest-bound controller
grant proves every selected gateway has applied the exact contract and the
source independently reads back a stable native dual-stack route snapshot,
Node UID, next-hop transport, interface index, and MTU. Withdrawal, loss of
either proof, synchronization failure, and restart atomically restore
destination-preserving fences and purge egress connection state. This passes
`make egress-path-activation-test`; ADR 0127. Every selected gateway now also
receives an authenticated digest-bound address projection and owns canonical
`/32` and `/128` host addresses on a Node-UID-bound `unf-egress0` dummy link.
Whole-host collision preflight, partial-apply rollback, independent kernel
readback, and an exact all-selected-Node acknowledgement quorum prevent
split-brain readiness. Withdrawal enters explicit quarantine: address and
allocator ownership remain fenced until future source-fence and reachability
proof authorizes release, never because a timer expired. The isolated
real-kernel gate passes `make egress-gateway-address-test`; ADR 0128. Gateway
NAT now uses source-identity-namespaced heterogeneous banks and validates the
exact contract, lease, destination, local-primary gateway, digest, and proof
witness before creating TCP/UDP state. A proof-salted odd-stride full-cycle
ephemeral-port permutation supplies 32 bounded candidates; reverse-first then
forward `BPF_NOEXIST` insertion never overwrites a colliding flow. Established
state survives projection churn until protocol timeout, and family-specific
tail programs perform checksum-safe IPv4/IPv6 SNAT and exact reverse restore.
Privileged restart, packet, collision, and first-flow-preservation evidence
passes `make egress-gateway-nat-test`; ADR 0129. The release barrier now has a
verified **Proof of Safe Forgetting** contract: checkpoint-v4 retirement
manifests freeze the exact source/gateway/lease set, and address reuse requires
complete source-fence, zero-flow gateway-drain, and exact
withdrawn-reachability evidence. Provider acknowledgements, elapsed time,
leadership, or inferred absence cannot release a lease. The domain/controller
gate passes `make egress-safe-forgetting-test`; ADR 0130. Source-side transport
is the first live component:
the controller freezes admitted membership before invalidation and serves
Pod/Node-bound retirement challenges; an agent responds only after atomically
fencing its active bank and clearing source connection state. Replacement Pods,
foreign Nodes, and stale controller epochs fail closed under `make
egress-source-retirement-test`; ADR 0131. Gateways now receive their own
Node/Pod/epoch-bound challenges and retire only one absent lease at a time.
They preserve every forward/reverse record if any is active, use the eBPF
`CLOCK_BOOTTIME` lifetimes, and publish zero-flow evidence only after removing
the entirely expired lease set and rescanning. This passes `make
egress-gateway-retirement-test`; ADR 0132. Finally, explicit `static`
reachability produces strict durable withdrawal evidence and the controller
assembles the exact proof union. Schema-v2 address projections authorize only
a monotonic host-address subset; all selected gateways must remove and read
back the lease as absent before one atomic transaction releases gateway,
allocation, and retirement state. The privileged gate passes `make
egress-release-authority-test`; ADR 0133. Other reachability providers and HA
failover remain explicit later gates, so missing proof still quarantines rather
than releasing optimistically.
Gateway NAT events are now a loss-explicit first-flow channel rather than a
per-packet stream. ABI-v1 witnesses bind the original/translated tuple,
identity, contract, lease, selected address/gateways, and proof; closed semantic
validation rejects ambiguous records. Per-CPU attempted/drop counters make ring
pressure measurable, and a real-kernel undersized-ring test proves telemetry
loss cannot change forwarding. Fixed-cardinality agent metrics and the focused
`make egress-nat-observability-test` gate verifies this boundary; ADR 0134.
The production reconciler now joins watched Pod/Namespace/ServiceAccount,
identity, policy, allocation, gateway, and reachability facts into exact
source-Node contracts. Explicit gateway labels prevent accidental scheduling,
and leased IPv6 `/128`s gain lease-fenced proxy-NDP ownership on the native
uplink. `make egress-kind-lifecycle-test` proves dual-stack UDP NAT and reverse
traffic, exact translated witnesses, unrelated native source preservation,
controller/agent recovery, complete withdrawal/drain, monotonic same-address
reuse, and final cleanup on three-Node kube-proxy-free Kind. ADR 0135 closes
milestone 8.5; durable enriched history, measured HA/failover, FQDN controls,
production reachability providers, the full Phase 8 platform matrix, and
OpenShift qualification remain later milestones.
Phase 8.6 starts with Continuity-Certified Rendezvous (CCR), a provider-neutral
HA planner for multiple egress addresses. It pairs same-ordinal IPv4/IPv6
addresses into exclusive ownership shards, computes exact integer
capacity-weighted targets without floating point, retains the mathematical
maximum legal prior ownership, and prefers failure-domain-diverse replacements.
Every single-gateway failure is compiled ahead of time into a digest-bound,
capacity-exact contingency with an independently replayable minimum-disruption
certificate. Five adversarial suites pass `make egress-ha-planner-test`; ADR
0136. The next verified slice adds proof-carrying promotion: every source fences
first, then exact old-owner address absence or an independent infrastructure
fence is mandatory; Kubernetes health is never isolation evidence. Exact new
ownership and an atomic reachability compare-and-swap seal one activation
capability. Five adversarial suites pass `make egress-ha-promotion-test`; ADR
0137. Acknowledged Flow Twins add established-flow continuity without opaque
conntrack copying: complete NAT pairs travel through sequence-checked hash
chains, the standby acknowledges an exact snapshot watermark, and promotion
imports only live lease/address/shard-valid state into its atomic source-bank
cutover. The unacknowledged asynchronous tail stays explicit and measurable.
Five adversarial suites pass `make egress-ha-continuity-test`; ADR 0138.
Checkpoint-v3 then persists CCR plans, freezes ordinary health-driven
membership, distributes one exact owner per shard, and makes proof and compiled
selection consume the same plan. Prior acknowledged ownership makes empty,
subset, and superset address transitions readback-safe, while new connections
cannot claim a flow twin was certified before standby acknowledgement. The
complete domain/controller/agent gate passes `make
egress-ha-live-ownership-test`; ADR 0139. Checkpoint-v4 then composes the prior
plan, source/old-owner fences, staged survivor placement, replacement readback,
reachability CAS, acknowledged flow twins, and source-specific inactive-bank
cutovers into one restart-replayable ordered transaction. Kubernetes health
cannot advance it, and the three-gateway adversarial gate passes `make
egress-ha-transaction-test`; ADR 0140. Milestone 8.6f closes the live path:
authenticated Node-UID-bound challenges drive source fencing, complete AFT
snapshot/import/readback, exact old-owner revocation, replacement address and
reachability acquisition, mandated-bank source activation, and terminal durable
finalization. Checkpoint-v5 canonically persists structured source cutovers and
terminal activation, while a verifier-isolated V2 tail-call dispatcher permits
one Node to act as source and gateway without bypassing either role. The
three-Node dual-stack kube-proxy-free Kind gate recorded 45 acknowledged flow
twins, a 10.860-second graceful promotion with one bounded probe failure,
exclusive ownership, stable rejoin, and an 80.428-second abrupt recovery whose
Kubernetes NotReady signal never served as fence authority. `make
egress-ha-kind-test` and ADR 0141 complete milestone 8.6 at this bounded Kind
scope; production availability/scale, OpenShift qualification, and non-static
reachability providers remain separate gates.
Phase 8.7a introduces Provenance-Leased Resolution (PLR) for bounded FQDN
destination evidence. Exact and label-bounded wildcard queries compile into
short-lived address leases only after an explicit resolver-view-scoped quorum
of distinct observers. The quorum-th latest capped expiry controls new flows;
an optional bounded tail admits established flows only. Complete CNAME,
observer, resolver, epoch, revision, TTL, and timestamp provenance supports
independent replay and explanation. Split-horizon answers never merge, zero-TTL
and below-quorum answers grant nothing, and capacity overflow rejects the whole
snapshot instead of silently evicting entries. DNS remains address evidence,
not workload or application identity, and no unrestricted IP fallback is
inferred. Eight focused tests and strict Clippy pass under
`make egress-fqdn-evidence-test`; ADR 0142. Slice 8.7b adds the native mutually
exclusive FQDN destination API with bounded safe defaults and an authenticated
current-Pod/Node-owned complete observation ledger. Epoch/revision monotonicity,
authoritative-empty versus observation-loss semantics, and canonical
digest-checked ConfigMap recovery prevent refresh ambiguity across restart.
Before evidence is compiled, source and gateway banks own IPv4/IPv6 catch-all
destinations and remain fenced, closing the absent-LPM native-routing escape.
`make egress-fqdn-control-test` and ADR 0143 verify that control boundary. Slice
8.7c adds bounded Node-local exact-name A/AAAA observation, CNAME-minimum TTL,
complete loss-explicit batches, deadline-aware controller materialization, and
transactional source/gateway bank refresh. Its autonomous dual-clock lease
firewall stores conservative monotonic new-flow and established-flow deadlines
in egress ABI v4: source tuple memory and persistent gateway NAT state expire
even while the controller is unavailable. AFT schema v2 carries portable UNIX
deadlines and safely re-anchors them on the standby Node. Real-kernel packet
tests pass `make egress-fqdn-dataplane-test`; ADR 0144.
Phase 8.7d adds Explicit DNS Discovery Authority: wildcard members are concrete
bounded `discoveryNames`, custom views bind `resolverAddresses`, and PLR rejects
evidence outside either commitment. Independent per-view producers never query
`*` and issue final authenticated empty batches. The three-Node Kind gate proves
two-observer custom-view A/AAAA quorum, dual-stack traffic, observer replacement,
two activation grants for cross-Node replicas sharing one safely coalesced
gateway identity, authoritative-empty denial, recovery, and final withdrawal
under `make egress-fqdn-lifecycle-test`; ADR 0145. DNSSEC and passive capture
remain separate. Phase 8.7e
adds Authority-Carved Internet classification: native policy names a
provider-neutral classifier, absolute CIDR exceptions, and either default
fail-closed behavior or an explicitly bounded last-known-good interval. Complete
dual-stack prefix evidence commits provider epoch/revision, validity, and
per-rule provenance. Unknown space denies, policy exceptions cannot be
overridden by a more-specific provider allow, and source/gateway eBPF maps share
one autonomously expiring replayed decision. `make
egress-internet-classification-test` and ADR 0146 verify this contract. Slice
8.7f closes the lifecycle with a cluster-scoped authenticated publication API,
an opt-in unbound publisher role, transactional relist, and a canonical
digest-checked checkpoint that retains both replay positions and exact
per-intent snapshots. Persistence precedes replacement distribution. Publication
loss can enter bounded digest-linked LKG before source validity expires without
extending the absolute deadline; controller restart preserves it and packet
authority still expires autonomously. The three-Node dual-stack Kind gate also
proves agent publish denial, absolute exceptions, provider-negative and unknown
denial, replay/mutation rejection, higher-revision recovery, and exact cleanup
under `make egress-internet-lifecycle-test`; ADR 0147. Milestone 8.8,
provider-neutral reachability and advertisement providers, is now in progress.
Its first verified slice introduces Diversity-Quorum Reachability (DQR): a
provider may mutate routes but cannot certify its own success. Digest-sealed
plans bind the exact allocation lease, IPv4/IPv6 addresses, permitted
gateway/forwarding identities, ECMP bounds, network vantages, and finite
evidence lifetime. Complete observers count by independent failure domain—not
replica count—and must agree exactly within every vantage. Correlated-only,
conflicting, partial, foreign, missing, or expired views deny closed; withdrawal
requires the same diverse complete evidence of absence. Only an opaque result
constructed or independently replayed from the complete evidence set can reach
the consumer deadline check. `make
egress-reachability-contract-test` and ADR 0148 verify 8.8a. Slice 8.8b adds
controller-owned cluster plans, namespaced status-only observer identities, and
a canonical durable evidence ledger that preserves current inputs, retained
replay positions, exact assessments, and explanation provenance. New evidence
is persisted before it can change an acknowledgement; absolute deadlines deny
independently and are also rematerialized without a Kubernetes event. Exact
desired/plan replay bridges only verified Ready or Withdrawn authority into the
existing gateway and safe-forgetting transactions. The two-failure-domain Kind
gate proves least-privilege RBAC, restart recovery, autonomous expiry,
replay/mutation rejection, higher-revision recovery, and cleanup under `make
egress-reachability-lifecycle-test`; ADR 0149. Slice 8.8c then removes
self-attestation from the live reference path. The controller automatically
owns exact lease-bound `native` plans; agents expose a nonce-bound proof only
for addresses present in their latest kernel readback, while one provider
receipt and two independently authorized fabric failure domains must agree
before activation. The probe is deliberately non-authoritative: only durable
DQR evidence can unlock traffic. The dual-stack Kind lifecycle proves real
external route mutation, conflicting-view denial, autonomous expiry fencing,
restart recovery, positive route withdrawal, safe address reuse, and exact
cleanup under `make egress-native-reachability-test`; ADR 0150. The legacy
explicit `static` self-acknowledgement remains compatibility-only for earlier
gates. Slice 8.8d adds a pinned GoBGP v4.9.0 typed-gRPC adapter rather than a
new protocol implementation. Digest-sealed node policy bounds peers, AFIs,
prefixes, ECMP, graceful restart, total routes, and transaction blast radius;
local and every relevant Adj-RIB-Out must read back exactly before persistence.
Each route carries a default-on Causal Route Capsule binding the owner, lease,
gateway, next hop, and DQR plan, preventing a stale advertisement from
impersonating a reused IP. The live four-speaker dual-stack gate verifies two
gateway paths at two independent external fabric domains, stale-capsule denial,
finite DQR authority, partial and complete withdrawal, scoped rollback, durable
RIB reconstruction, and cleanup under `make egress-bgp-test`; ADR 0151. Phase
8.8e adds bounded native GoBGP BFD and the default Causal Failure Lattice (CFL):
authenticated digest-sealed liveness is correlated with route/dataplane planes,
shared dependencies collapse into one incident, and recovery holds plus flap
budgets prevent optimistic restoration. BFD alone cannot suppress, fence,
promote, or claim ownership. `make egress-bfd-test` injects a real gateway fault,
withdraws protected IPv4/IPv6 routes, and preserves the independent path. IPv6
BFD transport itself remains fail-closed and unqualified; ADR 0152. See the [BGP provider guide](docs/development/egress-bgp-provider.md)
for the sealed node policy and opt-in agent wiring.
Milestone 8.9 now exposes a loss-explicit Causal Egress Chronicle plus an
evidence-complete counterfactual. `unfctl egress-explain` and
`egress-simulate` join the exact policy, intent, allocation, gateway, contract,
reachability, source-activation, NAT-observation, transport, and HA snapshots,
classifying each layer as authoritative, observed, derived, expired,
unavailable, or loss-affected. They distinguish denial, native routing,
fail-closed fencing, and eligibility but cannot grant authority or invent a
private NAT mapping. Completed HA transactions enter a bounded hash-chained
ledger with explicit eviction anchoring, available through `unfctl
egress-failovers`; `make egress-operations-history-test` and `make
egress-operations-causal-test` verify ADRs 0153–0154.
Phase 8.9c adds a Causal Egress Recovery Vector to `/v1/version`, covering the
egress distribution, host-state, HA-promotion, map, and event schemas before
persistent BPF state is opened. Adjacent responses predating those additive
fields remain accepted only behind exact per-payload validation; any advertised
drift fails preflight. Restart rejects derived state ahead of desired state and
same-revision model divergence, while desired-ahead persistence can only
reconcile forward. Checkpoint-v5 migration, evidence-preserving rollback
refusal, provider/agent last-known-good replay, and exact current-v15 cleanup
pass `make egress-upgrade-recovery-test`; ADR 0155.
Phase 8.10 composes the complete egress runtime rather than inferring success
from focused gates. Runtime and qualifier `2f404ed` passed a 1,013-second,
three-Node dual-stack Kubernetes v1.35.0 Kind run covering watched
steering/NAT, measured HA with zero-churn warm-standby rejoin, FQDN and Internet authority, DQR/native reachability,
causal operations, restart recovery, exact cleanup, and no-CNI rollback. The
digest-bound aggregate is `.artifacts/phase8-egress-complete-kind.json`; ADR
0156. The independent milestone 8.11 gate then passed in 411 seconds on
five-Node dual-stack OpenShift 4.22.10/Kubernetes 1.35.6 cl02 using runtime
`2f404ed` and qualifier `baf2bb0`. It verified immutable public images,
RHCOS/SELinux/CRI-O, kube-proxy absence, externally observed IPv4/IPv6 egress
sources, four-address exclusive ownership across three gateways, graceful drain
and zero-churn standby restoration, controller/agent recovery, operations,
exact cleanup, five-agent convergence, and an unchanged `network` unhealthy
baseline. Evidence SHA-256 is
`a2f8cb2279a3e1417ad1533575b644487e64cbfd1d8afafe351e99fad7e126d3`;
ADR 0157. These independent Kind and OpenShift results close Phase 8.
Phase 9 begins the attested encryption fabric. Milestones 9.1–9.8 are verified;
the independent OpenShift milestone 9.9 remains in progress.
The architecture requires that source policy and Service/egress ownership precede
encryption; kernel WireGuard owns all cryptography; private keys remain on their
Node; and an independently replayed Attested Encryption Path Contract requires
matching Node identities, public-key epochs, routes, MTU, kernel readback, and a
two-ended encrypted path witness before Required traffic activates. The
Intent-Coalesced Cryptographic Fast Path preserves per-identity authority while
sharing bounded Node/epoch tunnels, avoiding an interface or peer per policy.
Flow-Stable Epoch Rotation admits at most two epochs, shifts new flows only
after mutual evidence, drains established flows for a bounded interval, and
never falls back to plaintext. No performance claim is accepted before
committed native-versus-encrypted measurement. The new Kubernetes-independent
`unf-encryption` domain canonically resolves a Native/Required cluster baseline
plus monotonic identity-pair intent. Schema-v1 contracts admit only
policy-allowed Required pairs and bind exact workload/Node/cluster identity,
public-key digests and epoch/lifetime, bidirectional endpoints and Pod CIDR
`AllowedIPs`, interface/route/fwmark/MTU facts, capabilities, and revisions.
Independent replay, frozen witnesses, deny-only failure envelopes, and strict
unknown-field rejection pass `make encryption-contract-test`; ADR 0159. Node-
local key authority now generates fresh X25519/WireGuard keys directly from the
OS CSPRNG into zeroizing buffers and persists at most two epochs through an
atomic, digest-checked, mode-0600 checkpoint. A Causal Epoch Barrier seals only
the exact affected peer frontier and topology revision, so unrelated Nodes do
not stall rotation while every affected authenticated peer must acknowledge
before activation. Public-only monotonic publication, bounded drain/retirement,
emergency revocation, restart recovery, and replay/replacement fencing pass
`make encryption-key-authority-test`; ADR 0160. This slice creates no interface,
route, BPF state, or packet behavior. The Phase 9.4 typed Linux provider now
programs and independently reads back exact WireGuard peers plus isolated
dual-stack routes. Its Proof-Carrying Kernel Transaction binds secret-free
before/desired/readback digests to deterministic restart actions, while exact
version aliases, derived MTU, sorted conflict detection, foreign-state refusal,
injected rollback, idempotent replay, and positive cleanup pass
`make encryption-kernel-provider-test` and the privileged
`make encryption-kernel-provider-live-test`; ADR 0161. Phase 9.5a now adds the
canonical Intent-Coalesced compiler and fixed-width eBPF ABI. Explicit identity
decisions bind policy plus Service/egress revisions while identical exact
Node/epoch/readback transports share one ID. Its Causal Epoch Lease preserves
an admitted established flow across `Active -> Draining`, rejects cross-flow
reuse, and denies immediately on policy failure, expiry, or revocation instead
of falling back to plaintext. Canonical ordering, committed-kernel-readback
fencing, atomic generation state, rotation, and ABI layouts pass
`make encryption-fast-path-contract-test`; ADR 0162. The persistent map
transaction contract now adds a Causal Commit Vector that binds policy,
Service, egress, active/draining epochs, the compiled bank, and every committed
kernel-configuration digest. Persist-before-mutate phases and exact readback
make every pointer-flip crash boundary deterministic, while rollback requires
the previous bank plus positive target-bank absence. This passes
`make encryption-fast-path-transaction-test`; ADR 0163. The Aya persistence
foundation now places six fixed-shape maps in a separately versioned
`/sys/fs/bpf/unf/encryption/v2` ABI island, leaving the qualified 40-map core ABI
unchanged. Quarantine-First Activation accepts only an exact all-or-none pin
inventory and refuses foreign, symlinked, partial, or non-quiescent recovered
state before attach. `make encryption-map-persistence-test` passes; ADR 0164.
The Proof-Carrying Aya Map Mirror now durably retains the complete secret-free
authority needed to reconstruct those fixed-width records. Causal Delta Staging
skips unchanged records, reads the inactive bank back exactly, performs one
config flip, and resolves every prepared/staged/pointer-flipped/committed crash
state without trusting truncated map evidence. This passes
`make encryption-map-transaction-test`; ADR 0165. The Cooperative Route-Mark
Lease then derives an O(1), collision-free plaintext selector from each
`WireGuard` outer bypass mark inside an isolated 16-bit field. It preserves all
neighboring `skb->mark` bits, rejects ambiguous mark-to-table authority, and
releases only its own field for Native traffic. Exhaustive proof over all
65,534 admitted values passes `make encryption-route-mark-contract-test`; ADR
0166. Route-Before-Authority now reconstructs exact kernel witnesses, installs
deterministic masked IPv4/IPv6 rules only after route readback, and gives the Aya
transaction boundary a generation-bound publication permit only after exact
normalized rule readback. Its model and isolated rtnetlink gate pass
`make encryption-route-authority-test` and
`make encryption-route-authority-live-test`; ADR 0167. The controller
and agent now exchange Node-Sealed Generation Capsules over the existing
TokenReview-authenticated TLS channel. Every prepared generation is bound to a
fresh nonce, the authoritative Node UID, controller incarnation, and the exact
durable predecessor; the agent atomically persists it as desired state before
advancing its cursor. Route permits remain non-serializable and Node-local, so
remote delivery cannot manufacture kernel authority. Replay, replacement,
mutation, recovery, and no-change behavior pass
`make encryption-generation-distribution-test`; ADR 0168. The Tri-Plane Causal
Activation Latch now makes the controller capsule, a freshly recreated local
route permit, and the exact Aya predecessor/quarantined transaction agree at
one consuming boundary. Serialized active or pending state cannot resume or
reach TC attachment after restart until local kernel proof is renewed. Cross-
plane mutation and staged-crash recovery pass
`make encryption-activation-latch-test`; ADR 0169. The Causal Generation
Frontier additionally makes one
digest-bound, complete Node
cut the controller's unit of publication. Exact durable cursor receipts apply
slowest-member backpressure before the next cut, preventing mixed revisions,
skipped predecessors, and unbounded per-Node history; Node-UID and trust-domain
drift fail closed under `make encryption-generation-frontier-test`; ADR 0170.
The Proof-Carrying Frontier Recovery checkpoint now persists the exact active
cut plus Node-UID, published-generation, and frontier-digest-bound receipts.
Strict replay happens before controller readiness; retrying dirty writes and
shutdown flushes preserve safe progress without treating a cursor as kernel
proof. Deployment/RBAC and corruption gates pass
`make encryption-generation-recovery-test`; ADR 0171. The Complete-Cut Fact
Reconciler now accepts each Node-local prepared checkpoint
only from the current Pod-bound agent and authoritative Node UID. A topology or
UID change atomically invalidates every staged fact; regression, equivocation,
missing members, and mixed generations cannot publish. Only unanimous exact
membership feeds the durable frontier, and the final predecessor receipt
retries an already prepared successor. This all-or-nothing safety property
passes `make encryption-generation-reconciler-test`; ADR 0172. Agent-side fact
production is now constrained by the Capability-Typed Causal Proof Ladder: the
controller must return the byte-exact local proposal, then a fresh consuming
route permit is required to create the single-use Aya latch. Controller
substitution and unsafe proof reordering fail structurally under `make
encryption-local-proof-ladder-test`; ADR 0173. The Proof-Carrying Linux
Convergence Capsule now preflights ready Node-local keys and the entire
generation, stages real WireGuard state deterministically, accepts complete
kernel readback in any order, then joins exact controller admission and Linux
policy-route readback to the Aya adapter. Equivalent two-epoch observations
produce one compact witness without making it authority; partial, foreign, or
active-before-publication state fails `make encryption-linux-convergence-test`;
ADR 0174. The Echo-Sealed Agent Anti-Entropy Loop now makes that local
capability the mandatory prerequisite for controller exchange: every retry
publishes the exact fact first, uses a fresh predecessor-bound nonce, retains
the single-owner capability on `204`, and persists only a byte-exact controller
echo. With no local proof the default loop performs no blind pull. This passes
`make encryption-agent-anti-entropy-test`; ADR 0175. Proof-Rehydrating
Activation Escrow then persists only the secret-free fact plus canonical public
WireGuard plans. On restart it rereads the entire real kernel cut, recreates a
fresh non-serializable capability, binds it to the exact durable admission, and
completes current or pending Aya recovery before TC attachment. Newly admitted
capabilities use the same fail-stop consuming boundary; `make
encryption-activation-rehydration-test`; ADR 0176. The running local plan
path now starts with the Snapshot-First Causal Plan Compiler: it coalesces
identity-pair contracts into one peer per destination Node/epoch, preflights all
local keys before mutation, stages real WireGuard state, and lets exact readback
produce the map checkpoint instead of predicting kernel facts. This passes
`make encryption-local-plan-compiler-test`; ADR 0177. Its inputs now travel as
one Causally Sealed Input Manifold: a strict Node-scoped digest atomically binds
every contract, readiness proof, identity decision, and policy/Service/egress
revision, with exact bidirectional decision-to-plan coverage and no private or
reusable activation authority. `make encryption-plan-manifold-test`; ADR 0178.
Its Nonce-Bound Plan Relay adds a fresh challenge, exact durable predecessor,
Node UID, controller incarnation, and monotonic revision fences without turning
desired state into local authority; `make encryption-plan-distribution-test`;
ADR 0179. The running Pod-bound controller endpoint and agent now use a
Persist-Before-Compile Plan Inbox: owner-only atomic durability precedes cursor
adoption and startup validates it before BPF access;
`make encryption-plan-runtime-test`; ADR 0180. Complete-cut catalog visibility
is protected by a Fleet-Synchronous Plan Cut: explicit membership and common
causal revisions become visible with one atomic catalog swap, never per-Node
partial publication; `make encryption-plan-catalog-test`; ADR 0181.
Node-local public epochs now join through an exact-membership transparency cut;
topology changes clear observations and incomplete fleets expose nothing, while
private keys never cross the Node boundary;
`make encryption-key-transparency-test`; ADR 0182. Runtime key publication
now uses a stable `kube-system` UID cluster identity plus an exact Pod-bound
bootstrap. Each agent creates or restores only its own mode-0600 CSPRNG key
authority, durably prepares before publishing, and sends only public state;
`make encryption-key-runtime-test`; ADR 0183. Mutual readiness now uses a
Reciprocal Witness Matrix: one immutable transparency round, exact authenticated
N×(N-1) rows, complete-column release, and durable Node-local adoption prevent
partial-fleet key advancement; `make encryption-key-attestation-test`; ADR
0184. The Demand-Sparse Fleet Plan Forge now derives key facts and readiness
from that one cut, emits a single atomic catalog, and gives idle members an
explicit authority-free dormant plan instead of a fabricated tunnel;
`make encryption-fleet-plan-producer-test`; ADR 0185. Its Policy-Truth Transport
Quotient preserves mixed L4 allow/deny semantics while provisioning shared L3
transport and represents default allow without inventing a policy ID; policy
remains the first packet authority; `make encryption-policy-quotient-test`; ADR
0186. Adaptive Address-Exact Replica Binding keeps the one-lookup direct path
for a single remote Node and adds a banked, witnessed IPv4/IPv6 LPM lookup only
when one identity spans several Nodes; the final translated backend address
then selects the exact coalesced transport without per-Pod tunnels;
`make encryption-address-binding-test`; ADR 0187. Kubernetes fact projection
then validates UID-bound Ready Nodes, Pod-to-block placement, effective policy,
and emits only demanded bidirectional Node paths through Placement-Truth Demand
Projection; `make encryption-kubernetes-projection-test`; ADR 0188. Controller
invocation now uses a Pull-Synchronized Causal Catalog: authenticated polls
capture one revision/key cut, evaluate both policy directions at every semantic
port boundary and concrete dual-stack address, coalesce retries, and atomically
publish one fleet successor; `make encryption-controller-plan-test`; ADR 0189.
The agent now consumes that durable input through exact local key and Linux
readback proof. Authority-Free Quiescent Generations let idle fleet members
contribute a digest-bound zero-tunnel/zero-route fact without fabricated
authority or fleet deadlock; `make encryption-agent-plan-compile-test`; ADR
0190. Proof-Carrying Deferred Encryption now runs as a family-specific verifier
island after policy, final Service translation, and explicit egress ownership.
It consumes exact active-bank decision/path/transport proof, applies only UNF's
leased mark field, retains bounded active/draining flow epochs, and drops any
missing Required authority. Real kernel verifier loading plus IPv4 direct,
IPv6 address-bound, and transport-removal packet execution pass
`make encryption-tc-consumer-test`; ADR 0191. Flow-Adaptive Secure DSR now
preserves Native VIP/direct-return behavior while morphing only a Required flow
to an atomic reversible NAT pair using its already selected backend. WireGuard
therefore sees a peer-owned inner destination, return traffic restores the VIP,
and explicit external egress cannot borrow a Pod epoch lease. Real packet tests
also prove bounded old-epoch drain and immediate no-downgrade revocation under
`make encryption-composition-test`; ADR 0192. The independent Phase 9.5 closure
gate then carries IPv4 and IPv6 inner traffic between two real kernel
WireGuard peers while capturing only the underlay. It requires WireGuard UDP,
positive bidirectional counters, and positive absence of every inner address;
peer removal denies without plaintext fallback and exact restoration recovers
both families. `make encryption-ciphertext-live-test`; ADR 0193. The [Phase 9
plan](docs/development/phase9-attested-encryption-fabric-plan.md) and
ADRs 0158–0193 define the ordered implementation and independent Kind/OpenShift
gates.
Phase 9.6a adds the Causal Duplex Path Quorum. A short-lived nonce binds the
exact contract, decision witness, Node UIDs, key epoch, address families,
before/after kernel readback, positive per-peer counter movement, and the
encrypted request/response transcript independently observed by both
authenticated endpoints. A handshake timestamp or one healthy endpoint can
never activate the path. Replay, roaming, counter stall, mutation, expiry, and
unknown wire authority deny closed under `make encryption-path-proof-test`;
ADR 0194. Runtime evidence collection and consuming activation are tracked as
9.6b. The Pull-Synchronized Duplex Proof Exchange now atomically derives
challenge assignments from the active fleet plan, scopes every read and write
to the current Pod-bound Node identity, rejects generation equivocation, clears
old evidence on successor publication, renews expired rounds, and exposes only
current completed receipts to involved endpoints. `make
encryption-path-runtime-test`; ADR 0195. Evidence-Carrying Activation then
requires exact current receipt coverage to survive as a consuming capability
through the final map boundary; `make encryption-path-activation-test`; ADR
0196. Workload-Independent In-Fabric Proof Beacons reserve deterministic
IPAM-excluded IPv4/IPv6 identities inside each full Pod CIDR and bind their
installation/readback to provider schema v3; `make encryption-proof-beacon-test`;
ADR 0197. The Mark-Multiplexed Duplex Rendezvous now runs strict fixed-width
nonce exchanges from those beacons, selects the isolated epoch route per send,
captures before/after kernel evidence, preserves exact retry identity, and
consumes the joined proof without adding `NET_RAW`; `make
encryption-path-executor-test`; ADR 0198. A live two-agent executor and failure
gate then found and eliminated IPv4 broadcast and reverse-path-filter ambiguity:
the beacon is now a collision-fenced unicast reserve, legacy leases are retained
but cannot alias proof, and the owned WireGuard interface carries exact
reverse-path acceptance. Two production socket engines complete both families,
deny on peer loss, recover only with a fresh round, advance counters, and expose
only ciphertext on the underlay under `make encryption-path-live-test`; ADR
0199. Milestone 9.6 is Verified. Phase 9.7a then adds the Causal Evidence
Watermark: a fixed 54-cell stage/outcome matrix prevents metrics cardinality
from scaling with Nodes, peers, contracts, or epochs, while a separate bounded
hash-chained history records exact secret-free provenance. Both upstream loss
and retention eviction remain explicit across checkpoint restore, so missing
evidence cannot look like healthy silence. Phase 9.7b publishes that watermark
and bounded history through controller APIs and preallocates exactly 54
Prometheus series with only closed stage/outcome labels. Causal cut changes and
accepted proof transitions advance counters; polling and idempotent retries do
not. Phase 9.7c persists the bounded chain in an exact-name ConfigMap, rejects
damaged replay, retries coalesced writes, flushes on shutdown, and resumes all
54 metric cells at the durable watermark after controller replacement. `make
encryption-operations-recovery-test`; ADRs 0200–0202. Phase 9.7d reports actual
post-map activation through an authenticated one-item agent outbox. Current
Node/generation/state/path truth is revalidated, outage retries cannot block or
broaden dataplane authority, and durable per-Node cursors deduplicate both
delivery retry and same-generation restart revalidation. `make
encryption-activation-report-test`; ADR 0203. Phase 9.7e adds policy-first Minimum Causal
Cut Explanation: current queries identify the earliest absent assignment,
two-ended proof, quorum, or durable activation, while loss remains visible.
Counterfactual queries may withhold one stage or advance expiry time but are
explicitly non-authoritative and side-effect free. Dedicated `unfctl`
encryption status/history/explain/simulate commands pass
`make encryption-operations-query-test`; ADR 0204. Adjacent compatibility,
outage/replacement/cleanup, and performance evidence remain. Phase 9.7f adds a
Bidirectional Compatibility Sextant: five additive encryption coordinates let
old/new readers interoperate in either rollout order, while partial or foreign
tuples fail before persistent BPF access and strict endpoint schemas prevent
the compatibility document from becoming authority. The exact N baseline and
N+1 transition pass `make encryption-adjacent-compatibility-test`; ADR 0205.
Outage/replacement/cleanup and performance evidence remain.
Phase 9.7g adds the Survivable Authority Envelope. A controller outage retains
only independently replayable last-known-good state; when the controller is
reachable, its Pod-authenticated Node UID must match every durable plan,
generation, recovery, and private-key owner before persistent BPF access.
Current cleanup preflights both shared and encryption map islands, removes
encryption authority first, and preserves foreign and adjacent versions.
`make encryption-recovery-cleanup-test`; ADR 0206. Performance evidence remains.
Phase 9.7h completes the milestone with a Regression-First Performance Ledger.
Committed native/kernel-WireGuard IPv4/IPv6 evidence includes throughput,
p50/p95/p99, loss/retransmits, CPU/RSS, fixed map activity, 1–128-peer cost,
exact MTU, handshake convergence, ciphertext-only capture, and prewarmed
rotation disruption. The much slower encrypted same-host throughput remains
visible rather than becoming a selective claim. `make encryption-performance-test`
validates the digest; `make encryption-performance-live` reproduces it; ADR
0207. Phase 9.8a–d then close restart-safe membership, positive secret rollback,
continuous attested rotation, and the Kubernetes selective-encryption gap. A
namespaced `EncryptionPolicy` materializes exact bidirectional identity intent;
its Proof-Carrying Native Exception makes every allowed plaintext pair an
explicit revision-bound decision, while absent authority still drops and
native-only Nodes create no fake tunnel. Required remains the installation
default. `make encryption-selective-policy-test`; ADRs 0208–0211. Phase 9.8e
turns the remaining Kind closure into one dedicated-cluster transaction:
immutable provenance, both encryption modes, IPv4/IPv6 PodIP and Service paths,
ciphertext-only Required capture, simultaneous Native exception, link-failure
denial, natural rotation, controller/agent recovery, causal operations,
performance, egress coexistence, exact cleanup, and optional primary-CNI
rollback. `make encryption-phase9-kind-gate-test`; ADR 0212. Runtime `6d29ac3`,
qualified by the same committed revision, passed that fresh three-Node
dual-stack Kubernetes v1.35.0 transaction. Evidence JSON SHA-256 is
`c432111d…fde`; the independently hashed packet capture recorded 409 WireGuard
frames and zero Required-path plaintext frames. Controller replacement also
reconstructed its missing activation history without generation churn or
plaintext fallback. Milestone 9.8 is Verified; 9.9 independently qualifies the
same immutable runtime on five-Node dual-stack OpenShift.
The first OpenShift transition also added the Causal Pre-Attachment Fleet
Barrier: a new agent may publish authenticated Node-local facts while its prior
persistent TC path remains authoritative, but cannot expose the new tail graph
or become Ready until the complete fleet commits a proof-carrying generation.
Interrupted pre-activation key state now heals through a Monotonic Fleet Key
Epoch Floor: an expired never-active epoch is durably tombstoned, its public
successor raises a controller-signed floor, and lagging members converge without
key reuse, private-key exchange, or lifetime-scale waiting; ADR 0215.
Controller recovery also preserves duplex-proof liveness through a Reciprocal
Active-Generation Proof Service. Already-committed Nodes answer only fresh,
authenticated rounds for their byte-matched durable generation, publish normal
two-ended kernel/ciphertext evidence, and discard the resulting receipts. They
gain no new authority, while a peer still holding activation escrow can finish
without replaying pre-restart nonces or waiting for another generation; ADR
0216.
If replacement instead restores a fleet cut immediately before a successor
already admitted by one Node, that authenticated cursor becomes a monotonic
high-watermark: the controller publishes one complete cut beyond it and all
members converge forward. Equal or older cursors remain non-mutating
acknowledgements; ADR 0217.
Proof participation also self-heals exact owned Linux drift. If a down/up event
removes IPv6 proof addresses or policy routes while retaining the WireGuard
link, the agent replays only its digest-bound durable plan with its local key,
requires independent exact readback, and reconstructs a fresh single-use proof
capability. It never accepts a partial interface or creates avoidable fleet
churn; ADR 0218.
Replacement-controller history also self-heals without forcing a dataplane
generation. A Demand-Driven Reciprocal Activation Testimony request stays idle
once the exact fleet cursor cut is complete; while any cursor is missing, all
active peers answer fresh duplex rounds and only the missing member reconstructs
its controller acknowledgement. Exact generation/state/path validation remains
mandatory, duplicate acknowledgement causes no checkpoint churn, and testimony
cannot mutate Node-local packet authority; ADR 0219.
The first cl02 Phase 9 transition then exposed a host-boundary ownership bug
before qualification: unmanaged TCP crossed the encryption finalizer and lost
foreign bits 8–23 from its existing packet mark, while unparsed ICMP remained
reachable. Identity-Scoped Packet-Mark Ownership now requires a complete
managed identity pair before Phase 9 may mutate that field. A privileged kernel
test sends unmanaged TCP/6443 through the release tail graph with a nonzero
foreign mark and proves byte-exact preservation; managed Native/Required,
dual-stack, rotation, revocation, Service, and egress behavior remain covered.
ADR 0220 records the failed gate and remediation; fresh Kind and cl02 runs are
still required before milestone 9.9 or Phase 9 can be marked Verified.
The first fresh Kind rerun then found a separate recovery/rotation liveness
boundary: an exact journaled interface with some already-missing owned routes
could not pass pristine readback, so its retired key occupied the bounded
two-epoch window indefinitely. Proof-Carrying Monotonic Retirement now proves
that every remaining local field, peer, proof address, and route is within the
authenticated plan before deleting the interface; missing planned state is
safe progress, while any mutation or addition is preserved and refused. The
privileged kernel regression passes; complete fresh Kind and cl02 evidence is
still required. See ADR 0221.
This avoids both mixed-version management-path loss and the tempting but unsafe
alternative of treating absent Required authority as Native; ADR 0214.
A focused incompatible-version gate builds deliberately schema/ABI-skewed test
images, requires the local ABI-directory invariant to reject agent startup
before persistent BPF access, requires live policy-schema rejection before
staging or active-bank mutation, and keeps a continuous allow/deny probe running
through compatible recovery. This rejection boundary is verified by ADR 0050;
the deliberate snapshot-driven ABI clean rebuild and reverse recovery are
verified separately by `make kind-clean-rebuild-test` and ADR 0051.
Direct downgrade of an older binary against newer persistent state is rejected
before BPF access and qualified by `make kind-unsupported-downgrade-test` and
ADR 0052. `make kind-rollback-reporting-test` additionally requires local
status, controller aggregation, metrics, and logs to distinguish compatible
rollback, blocked rollback, and recovery, then restore both agents to `normal`;
ADR 0053 records that observable transition contract.
The OpenShift compatibility gate publishes separate N/N+1 controller, agent,
and test-tool images to the development repositories, records immutable digest
references, and qualifies full dual-stack RHCOS endpoints around a
controller-first, worker-serial rollout plus complete rollback and recovery:

```bash
make openshift-upgrade-images UNF_OPENSHIFT_UPGRADE_BASELINE_REF=<committed-N>
make openshift-upgrade-test \
  OPENSHIFT_KUBECONFIG="$PWD/.tools/cl02-audit.kubeconfig"
```

ADR 0054 records the exact cl02 window, image digests, platform invariants, and
append-only attempt history.

Exact qualified platform tuples and their non-transitive boundaries are tracked
in `docs/development/support-matrix.json`. Validate its schema, Git evidence,
and ADR references with:

```bash
make support-matrix-check
```

Qualify the pinned additional Kubernetes 1.34.8 tuple in a disposable two-node
dual-stack Kind cluster with:

```bash
make kind-platform-matrix-test
```

The gate requires a clean committed tree, records every attempt, runs complete
endpoint/recovery and adjacent-revision upgrade/rollback checks, then removes
only its dedicated cluster and restores its bounded host prerequisite. ADR 0055
records the verified tuple and retry history.

A bounded Kind failure/scale gate adds deterministic workload generation,
measured churn and recovery budgets, simultaneous two-agent last-known-good
recovery with the controller offline, continuous dual-stack policy probes, and
a machine-readable environment/result record.
Additional IPv4-only and dual-stack OpenShift gates are live-verified on
OpenShift 4.22/RHCOS 9.8 with enforcing SELinux and a 5.14 kernel: the controller
runs under `restricted-v2`, while worker-only agents use a dedicated constrained
SCC with a non-privileged container, runtime-default seccomp, read-only root
filesystem, and exactly `BPF`, `NET_ADMIN`, and `PERFMON`. Native validating
admission policies additionally restrict the agent to writable `/sys/fs/bpf` and
read-only `/sys/kernel/btf`, rejecting alternate paths, unsafe mount modes, and
sidecar/init/ephemeral access before Pod admission. Native automatic
selection installs legacy netlink filters, OpenShift Service CA secures the
internal Service, and cross-worker IPv4/IPv6 allow/drop scenarios retain
authenticated provenance. Controller leaf certificates and agent CA bundles now
reload in place with last-known-good fallback. A separate OpenShift gate rotates
through overlapping external-PKI trust, rejects malformed updates, restores the
platform Service CA, and proves that no controller or agent Pod is replaced.
The agent also provides a dry-run-first cleanup command for ABI directories from
v1 through the binary's compiled current version, TCX link pins, and UNF-named
legacy filters; current ABI removal requires an additional explicit confirmation
and unknown directory content is refused. The
OpenShift uninstall orchestrator reviews that plan on every selected worker,
requires exact cluster-context confirmation, stops agents before mutation,
verifies host cleanup, preserves all UNF CRDs by default, and removes its temporary
cleanup authority only after the hosts are clean.
See the authoritative
[project status and requirements traceability](docs/project-status.md) for phase
gates, evidence, limitations, and current work. The shorter
[roadmap](docs/roadmap.md) describes future direction, and the
[upstream-aligned ingress matrix](docs/development/networkpolicy-conformance.md)
records the exact compatibility behaviors exercised against the dataplane.
The [OpenShift qualification guide](docs/development/openshift-qualification.md)
documents the platform overlay, certificate modes, development images, evidence,
and cleanup boundary.

## Current scope

Implemented in the repository:

- versioned userspace/eBPF flow ABI and strongly typed numeric IDs;
- `SecurityPolicy`, `EgressPool`, and `EgressPolicy`
  `network.unf.io/v1alpha1` APIs and generated structural CRDs;
- deterministic L3/L4 policy compiler, shadow decisions, and property tests;
- direction-aware policy IR and userspace decisions with destination-selected
  ingress, source-selected egress, cross-direction isolation, and explicit
  direction provenance at the TC decision boundary;
- multi-direction Kubernetes NetworkPolicy translation with exact `policyTypes`
  defaulting and source-targeted egress peer/port IR, distributed as independent
  ingress/egress records by the controller;
- addressed userspace egress evaluation for bounded IPv4/IPv6 `ipBlock`
  destinations and exceptions;
- source-selected IPv4 exact-destination and IPv6 destination-LPM egress
  lowering, including selector metadata, named ports, and isolation fallbacks,
  with transactional agent staging, populated controller snapshots, and
  verifier-qualified TC lookup;
- a supported ingress `NetworkPolicy` adapter that reuses the same IR, additive
  evaluator semantics, controller snapshots, and dataplane lowering as native
  policy, including pod/Namespace expressions, named and protocol-only
  TCP/UDP/SCTP ports, bounded inclusive TCP/UDP/SCTP `endPort` ranges, bounded
  IPv4 exact-source and IPv6 prefix `ipBlock` peers with `except`, namespace-wide targets from an omitted
  `podSelector`, Kubernetes ingress/TCP defaults, deterministic exact/wildcard-key
  lowering, and explicit compiler/dataplane capacity limits;
- a kube-rs controller watching Nodes, Pods, Namespaces, Services, EndpointSlices,
  SecurityPolicies, and NetworkPolicies, with accepted/rejected compatibility
  status;
- a validated service-fabric domain boundary with strongly typed service/backend
  IDs, deterministic dual-stack frontend/backend normalization, EndpointSlice
  readiness-state retention, exact per-frontend same-family backend references,
  strict schema/revision fencing, and bounded snapshot cardinalities; this is not
  yet distributed to agents or enforced by eBPF;
- controller health, readiness, metrics, status, and userspace explanation APIs;
- controller-aggregated per-node desired/applied identity and policy convergence;
- bounded, schema-validated ConfigMap persistence for authenticated agent reports,
  with startup recovery that cannot satisfy a new controller epoch by itself;
- schema v2 agent acknowledgements authenticated through audience-scoped,
  Pod-bound Kubernetes TokenReview identity and authoritative Node placement;
- a split controller surface with public operator HTTP and CA-pinned,
  TokenReview-authenticated internal HTTPS for agent snapshots and writes;
- in-place server-certificate and CA-bundle reload with overlapping-root support,
  last-known-good fallback, reload/error metrics, and an OpenShift rotation gate;
- OpenShift-native fail-closed admission for the agent's exact
  bpffs/BTF/durable-state host paths, mount modes, and single-container ownership;
- revision-fenced, read-only native policy simulation through the shared evaluator;
- bounded non-blocking agent telemetry export and a 4,096-flow controller history
  with explicit drop/eviction accounting, schema-validated ConfigMap restart
  recovery, and last-received-time queries;
- an Aya agent capable of loading and attaching the TC observation program;
- IPv4/IPv6 TCP/UDP/SCTP TC parsing, including bounded IPv6 extension-header
  traversal, with counters, bounded ring-buffer events, and active-bank L3/L4
  allow/drop decisions;
- revisioned controller-to-agent dual-stack identity snapshots and transactional
  dual-bank IPv4/IPv6 BPF maps selected by one atomic configuration write;
- selector-resolved policy snapshots and dual-bank transactional BPF policy maps;
- eighteen pinned identity/policy/service maps with all-or-none validation,
  active-bank and revision checks, exact durable service recompilation,
  userspace cache recovery, and controller-independent replacement-agent
  readiness;
- persistent TC attachment handoff using pinned, atomically updated TCX links on
  Linux 6.6+ and stable legacy netlink filters on older kernels, with the active
  attachment mode exposed by each agent;
- explicit `auto`, `tcx-pinned`, and `legacy-netlink` attachment selection, with
  kind verification that removes TCX coverage, continuously probes enforcement
  through legacy in-place replacement, then restores TCX before scoped cleanup;
- dry-run-first `unf-agent cleanup` planning for map and TCX pins from ABI v1
  through the binary's compiled current version plus UNF-named legacy filters,
  with unknown-content refusal and an explicit current-ABI confirmation gate;
- an isolated, default-CNI-disabled three-Node dual-stack Kind gate for
  fingerprinted UNF primary-CNI installation, two-worker ADD/CHECK/DEL and
  direct forwarding, outage recovery, coexistence refusal, and exact rollback;
- a fail-closed OpenShift primary-CNI candidate audit that records the real
  RHCOS/CRI-O/CNO ownership boundary and rejects post-install conversion of an
  OVN cluster; installer-time `networkType: None` inputs are tracked separately;
- a statically verified OpenShift reinstall package with immutable images,
  DNS-independent host-network bootstrap, forwarding MachineConfigs, exact
  SCC/admission/host ownership, and socket-fenced fingerprinted CNI publication;
- coordinated dry-run-first OpenShift uninstall with all-agent shutdown,
  admission-constrained per-node cleanup Jobs, post-cleanup host verification,
  exact resource removal, CRD preservation, and full redeploy qualification;
- isolated kind fault injection proving partial pin sets, malformed active
  configuration, and corrupt inactive-stage values are rejected without
  disturbing the live last-known-good dataplane;
- deterministic kind map-pressure injection using inactive-bank synthetic keys
  to fill the shared physical policy map, proving capacity failure cannot advance
  the applied revision or disturb active traffic and that retry succeeds after
  scoped cleanup;
- `unfctl status`, `unfctl topology`, `unfctl flows`, and direction-/family-aware
  `unfctl explain` against live controller state, including separate resolved
  ingress/egress status counts;
- `unfctl policy simulate <policy.yaml>` for `SecurityPolicy` or `NetworkPolicy`,
  with table/JSON/YAML output
  representative and historical impact summaries, optional last-received-time
  windows and newest-first limits, plus current/proposed provenance;
- `unfctl policy shadow-impact` for observation-weighted live rollout evidence,
  or `--flows-file <snapshot>` for schema-validated analysis that performs no
  controller request and can run after the snapshot is moved off-cluster;
- `unfctl topology-history` for bounded, revision- and time-filtered topology
  schema-v3 snapshots with restart-safe checkpoint fencing and explicit
  eviction/omission accounting;
- a reproducible dual-stack two-node kind demo covering native and NetworkPolicy
  cross-node IPv4/IPv6 allow/drop, bounded IPv6 extension-header allow/drop,
  namespace-selector convergence,
  rejection/deletion recovery, shadow
  pass-through, protocol-only port activation/recovery, bounded range and
  IPv4/IPv6 `ipBlock`
  enforcement and rejection recovery, named/protocol-only SCTP enforcement,
  namespace-wide target isolation/defaulting, same-Namespace and all-Namespace
  peers, explicit empty source/port wildcards, multi-port OR, empty/labeled
  same-Namespace PodSelectors, multiple same-Namespace PodSelector peer OR,
  exact Namespace-name selection, all four Pod/Namespace selector operators,
  multi-value Pod `In` with Namespace `NotIn`, peer OR/selector AND semantics,
  multiple
  ingress rules,
  exact/protocol-only UDP isolation, per-destination named-port resolution and
  nonexistent named-port fail-closed behavior, all four destination-selector
  expression operators, overlapping destination-selector additivity, source,
  destination, and Namespace label-driven recovery, stacked additive allows and
  remote target-specific exceptions over namespace-wide isolation, same-object
  allow-all/default-deny replacement, allow-all recovery, revisioned eBPF
  provenance, and live policy explanations, plus a versioned EndpointSlice
  backend-readiness lifecycle; a separate egress fixture covers selected-source
  isolation, selector/named-port/protocol forms, IPv4/IPv6 blocks and exceptions,
  direction-correct provenance, deletion recovery, and exact cleanup.

Phase 7 is complete for its exact recorded Kind and OpenShift development
tuples. Not yet implemented: production-scale routing/CNI qualification;
workload/data-plane encryption, generic related-flow/ICMP/NAT tracking,
multi-cluster transport, IPv6 jumbograms/ESP/reassembly, or production
fail-closed recovery. Bounded TCP/UDP/SCTP reply state survives unrelated policy
revision churn, and primary-CNI mode observes both TC directions for translated
tuples; runtime state resets when the eBPF program is replaced.

## Repository layout

```text
crates/                 Domain, API, policy, service, and state libraries
bins/                   controller, node agent, and unfctl
ebpf/                   shared ABI and separately-built Aya TC program
deploy/                 generated CRDs and initial Kubernetes manifests
docs/                   architecture, ADRs, roadmap, and development guides
tests/                   future integration/e2e test suites
hack/                    local development configuration
```

## Build and test

The host workspace uses pinned stable Rust:

```bash
make build
make test
make lint
make fmt-check
make cni-route-reconciliation-test
make nodeport-operations-test
```

The reconciliation gate requires passwordless `sudo` and Linux network
namespaces. Native remote routing remains disabled unless the agent receives both
`--cni-native-ipv4-uplink` and `--cni-native-ipv6-uplink`; the default overlay
manifests do not set them. IPv4 and IPv6 on-link behavior is independently
selectable and never inferred from one family.

The eBPF program has a separate target build because it cannot be compiled as a
normal host test binary:

```bash
rustup toolchain install nightly-2026-07-15 --component rust-src
# Install bpf-linker for the LLVM major version available on the build host.
cargo install bpf-linker --locked
make ebpf
```

Nightly is isolated to `bpfel-unknown-none`; all userspace code uses stable Rust.

For the full local cluster path (Podman, `sudo`, Go, and `kubectl` required):

```bash
make kind-up
make kind-deploy
make kind-test
```

## Local API demo

Run a controller without Kubernetes:

```bash
cargo run -p unf-controller -- --offline
cargo run -p unfctl -- status
```

Offline mode reports real process health but has no Pods or policies, so explain
requests cannot resolve endpoints. See
[getting started](docs/development/getting-started.md) for Kubernetes and eBPF
requirements.

## Design principles

- Observe before enforcing.
- Keep Kubernetes types out of the dataplane and core evaluator.
- Preserve policy provenance so every decision can be explained.
- Use compact numeric identities in the fast path; IP is only a lookup index.
- Keep existing dataplane state operating through control-plane interruption.
- Add capabilities incrementally and never report planned features as complete.

The architecture starts at [docs/architecture/overview.md](docs/architecture/overview.md).
Significant decisions are recorded under [docs/adr](docs/adr), and progress is
tracked in [docs/project-status.md](docs/project-status.md).

## License

Apache-2.0. See [LICENSE](LICENSE).
