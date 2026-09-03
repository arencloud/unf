# Components

| Component | Responsibility | Must not own |
|---|---|---|
| `unf-common` | IDs, revisions, protocols, verdicts, policy reasons | Kubernetes or Aya clients |
| `unf-cni-state` | Versioned local CNI transaction schema, inspectable attachment/lease state machine, schema migration, and atomic durable journal | Kubernetes access, namespace/link mutation, IPAM allocation policy, or remote transport |
| `unf-ipam` | Modular, bounded dual-stack lease types, collision-safe node-block allocation, overlap validation, and strict distribution snapshot schema | Kubernetes watches, routing policy, durable attachment storage, or namespace/link mutation |
| `unf-link` | Deterministic, ownership-safe veth planning, namespace movement, dual-stack address application, readback, recovery, and exact cleanup | Kubernetes access, durable transactions, route policy, controller state, or shell-command mutation |
| `unf-route` | Routing-provider abstraction, strict complete remote-route snapshot/Node-block intent, native endpoint and cross-node route IR, typed kernel lifecycle/repair/replacement, scoped rollback, and provider-declared MTU derivation | IP allocation, link mutation, durable transactions, Kubernetes access, or policy enforcement |
| `unf-ebpf-common` | Versioned fixed-layout flow and BPF map ABIs, including independently banked dual-stack NodePort and LoadBalancer frontend contracts | Variable strings or allocation |
| `unf-api` | CRD schema and serialization | Policy evaluation |
| `unf-policy` | Native and NetworkPolicy conversion, shared IR, deterministic evaluation, identity-tuple lowering | Kubernetes watches or BPF map mutation |
| `unf-service` | Bounded revisioned schema-v4 service IR, typed ClusterIP/NodePort/LoadBalancer plus internal policy, affinity, topology preference, algorithm, and forwarding intent; provider-neutral Service/EndpointSlice and authenticated local-Node inputs; stable collision-checked IDs; deterministic normalization/validation; fixed dual-stack lowering with explicit advanced-intent fencing | Kubernetes watches, Node-address discovery, runtime connection tracking, or BPF map mutation |
| `unf-state` | Revision snapshots, bounded flow-history contract, Service/backend topology schema, and identity metadata | Transport or controller loops |
| `unf-controller` | Watches, EndpointSlice-aware desired-state/topology reconciliation, retained-last-valid service compilation, durable explicit-class LoadBalancer allocation/finalizer orchestration, TokenReview-scoped Node intent, authenticated snapshot distribution, explicit Node block and complete remote-route distribution, bounded durable agent-report and flow-history checkpointing, non-blocking external HTTP flow handoff, time-window flow queries, explanation, and read-only simulation orchestration | Packet parsing |
| `unf-agent` | Capability detection, Aya lifecycle, events, non-blocking telemetry export, authenticated transactional service/NodePort/LoadBalancer maps and durable node-block/reachability adoption, exact service/NodePort/LoadBalancer/identity/policy recovery, remote-route reconciliation, and opt-in root-authenticated local CNI transaction service | Kubernetes policy semantics or CNI namespace mutation |
| `unf-cni` | Bounded CNI protocol/socket handling and atomic durable-IPAM plus link/route ADD/CHECK/DEL orchestration | Kubernetes access, policy compilation, durable IPAM storage, routing protocols, or telemetry aggregation |
| `unf-loadbalancer` | Deterministic dual-stack VIP allocation, exact pool/provider ownership, complete revisioned direct-Node reachability intent/acknowledgement, and fail-closed Kubernetes publication/withdrawal transactions | Kubernetes API calls, host-state mutation, routing protocols, or packet translation |
| `unfctl` | Operator-facing status, topology, flow history, explanation, and simulation | Fabric state ownership |
| `unf-ebpf-tc` | Bounded packet parsing, active-bank L3/L4 decisions, telemetry, source-side and host-origin dual-stack TCP/UDP ClusterIP translation, `Cluster`/`Local` NodePort translation, and coherent `Cluster`/`Local` LoadBalancer VIP translation with source-range policy and paired connection state | Selectors, enrichment strings, LoadBalancer allocation or advertisement, health serving, host-origin NodePort translation, or L7 processing |

The allowed dependency direction is from binaries toward libraries and from API
conversion toward domain types. Kernel ABI types depend only on `no_std`
primitives. No core library calls the Kubernetes API.

The accepted Phase 6 extension keeps LoadBalancer ownership split across
components. `unf-service` now owns bounded provider-neutral schema-v3 VIP
intent, and `unf-controller` owns explicit-class Kubernetes admission plus
retained-last-valid compilation. Existing service lowerers reject that intent.
`unf-loadbalancer` now owns deterministic allocation, the provider-neutral
reachability contract, and exact publication ordering. The controller now owns
durable explicit-pool production and finalizer-safe withdrawal; the agent owns
authenticated, independently banked host adoption and recovery. `unf-ebpf-tc`
now owns coherent `Cluster`/`Local` VIP translation, paired reverse state, and
exact source-range lookup. The agent owns transactional runtime trie
reconstruction and dual-stack Node-local health listeners. Bounded metrics,
status, history, provenance-aware explanation, exact read-only simulation, and
durable recovery are now implemented and independently qualified on Kind and
OpenShift. Allocation,
advertisement, translation, health, and published readiness are not
interchangeable. ADRs 0093–0101 define the implemented boundary.

The accepted Phase 7 boundary assigns Kubernetes semantic conversion and
bounded normalized affinity/locality/algorithm/forwarding intent to
`unf-service`; the controller supplies authoritative Node placement and zone
inputs. `unf-service` now also owns the Network Behavior Contract reference
validator: it independently binds exact intent, per-Node eligibility tiers,
capabilities, revisions, bounded failure observations, and canonical digests.
The agent transactionally owns verified per-Node contract state through
authenticated projection, two userspace banks, independent readback, private
contract+Node checkpoints, recovery, and exact digest acknowledgements. Phase
7.4 lowers the first non-empty ordered tier into origin-specific slots, 7.5
adds ABI-v9 exact-client affinity plus graceful-draining lifecycle separation,
and 7.6 adds bounded measured ABI-v10 Maglev tables with actual-algorithm
fallback/provenance. Phase 7.7 advances connection ownership to ABI v11 and
admits DSR only for explicit acknowledged LoadBalancer VIPs with unchanged
backend tuples. The agent loads verifier-isolated IPv4/IPv6 policy and DSR FIB
tail stages before hook attachment; topology and eligibility changes remain
dataplane transactions. `unf-ebpf-tc` may
consume only fixed-width selected tiers, affinity records, algorithm tables,
and compact decision witnesses; it does not interpret Kubernetes strings,
topology, or contract logic. DSR preserves the VIP tuple, retains existing
selection/policy/source-range/lifecycle order, requires route/neighbor/MTU proof,
and writes forward-only Service state for direct return. ADRs 0102 and 0104–0109
record the boundary; Kind/OpenShift return-path claims remain independent.

The accepted Phase 8 boundary keeps egress policy, allocation, gateway
placement, reachability, NAT, and publication as separate coherent
transactions. Normalized identity-aware intent and the Egress Behavior Contract
belong in domain libraries; Kubernetes and OpenShift EgressIP conversion remains
in the controller adapter. The dedicated egress domain owns conflict-safe
pools/leases, provider-neutral gateway candidates, and readiness contracts. The
agent will independently verify exact-Node plans and transactionally own host
steering/NAT state; `unf-ebpf-tc` may consume only fixed-width decisions after
source-side policy. Static, BGP, cloud, and cross-cluster reachability providers
must not fork policy or NAT semantics. ADR 0113 defines this architecture-only
boundary. Milestone 8.2 now implements the `unf-egress` model with canonical
bounded selectors, destinations, pools, and address requests. The controller's
strict OpenShift EgressIP adapter feeds that same model and exposes a
foreign-preserving status merge without watching or mutating cluster state yet;
ADR 0114. Schema-v1 Egress Behavior Contracts then compile exact-Node plans
only for intent-selected identities with source-policy allow, binding original
destinations, exact allocation, lease-fenced acknowledged gateways,
capabilities, and independent revisions. Agents can replay those facts before a
future staging path; compact witnesses and bounded failure envelopes are
provenance, not authority; ADR 0115. Phase 8.2a changes no current BPF ABI, host
state, or packet behavior. Schema-v1 egress allocation checkpoints now own
atomic multiple-address leases with pool/provider provenance and monotonic
epochs. A separate gateway registry versions desired state, gateway readiness,
and external reachability independently, retains address fences through
dual-acknowledged withdrawal, and projects only completely acknowledged facts
into behavior contracts. These are durable domain records; controller storage
and host-state integration begin in milestone 8.4; ADR 0116. Schema-v1
distribution now binds that complete contract to the existing authenticated
Pod/Node principal and exact negotiated capabilities. Only an independently
replayed projection can compile isolated userspace ABI-v1 gateway host banks;
stage/readback/prepare/activate, last-known-good rollback, strict current/pending
checkpoints, crash repair, cold reconstruction, and version-scoped cleanup are
owned behind a storage trait. Live controller/agent adapters and the consumable
BPF layout remain milestone 8.5 work; ADR 0117.
Before that layout is frozen, the default Egress Proof Chain gives every
explicitly managed identity a `Native -> Fenced -> Active` admission lifecycle.
The source deterministically selects a same-family address and ready gateway
from the admitted contract and commits the authoritative identity, original
tuple, contract/revisions, lease, selection, and witness. The selected gateway
must independently reproduce the exact proof; proof bytes never establish
identity. This reference/control contract changes no packet path; ADR 0118.
The first Phase 8.5 slice closes the other half of that path: an authenticated
gateway projection aggregates complete admitted source contracts only when the
gateway is their exact ready/reachable lease-fenced candidate. Source-local path
certificates bind route, interface, next hop, transport, MTU, mode, revision,
and lease before a pure compiler can emit fixed-width ABI-v1 state. Candidate
and 251-bucket primary/pre-certified-standby selection tables are shared per
intent rather than duplicated per identity. ADR 0119 records this contract;
live endpoint, persistent-map, and TC ownership remain next.

Long-running binaries supervise their API server and watcher/dataplane tasks with
a shared cancellation token. Phase 1 state uses explicit locks around small,
control-plane-only collections; packet processing and event records do not
allocate.
