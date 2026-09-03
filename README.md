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
ownership now uses the all-or-none persistent ABI v14 boundary; v13 remains a
recognized historical 33-map cleanup scope.
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
Phase 8 begins an identity-aware enterprise egress fabric. Milestones 8.1
through 8.5 are verified. Source-side security policy precedes steering and NAT, while
`unf-egress` now canonically validates bounded Namespace, workload, and
ServiceAccount selectors, destinations, non-overlapping dual-stack pools, and
pool or explicit multiple-address intent. The controller strictly translates
OpenShift `k8s.ovn.org/v1` EgressIP into that same model and preserves foreign
status ownership. Native egress remains the safe default until explicit intent
is admitted. The [Phase 8 plan](docs/development/phase8-egress-fabric-plan.md)
and ADRs 0113–0130 track the work. Milestone 8.2a now adds schema-v1 exact-Node
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
rendezvous buckets shared per intent, including a pre-certified standby by
default when two gateways exist; packets will need only one stable hash and map
lookup. The contract gate passes `make egress-dataplane-contract-test`; ADR
0119. Persistent ABI v14 now owns and transactionally recovers the source,
destination, candidate and selection banks, atomic source and aggregate gateway
pointers, dedicated heterogeneous gateway-NAT banks, and connection LRU;
capacity rollback is proven on real kernel maps while v13 remains a historical
exact 33-map cleanup boundary (ADRs 0120, 0126, and 0129). The internal
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
The watched revision now drives a separate schema-v2 durable control-plane
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
verified **Proof of Safe Forgetting** contract: checkpoint-v2 retirement
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
0136. Live promotion and established-flow continuity remain the next 8.6 gates,
so the planning result is not presented as availability evidence.
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
