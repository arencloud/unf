# Components

| Component | Responsibility | Must not own |
|---|---|---|
| `unf-common` | IDs, revisions, protocols, verdicts, policy reasons | Kubernetes or Aya clients |
| `unf-cni-state` | Versioned local CNI transaction schema, inspectable attachment/lease state machine, schema migration, and atomic durable journal | Kubernetes access, namespace/link mutation, IPAM allocation policy, or remote transport |
| `unf-ipam` | Modular, bounded dual-stack lease types, collision-safe node-block allocation, overlap validation, and strict distribution snapshot schema | Kubernetes watches, routing policy, durable attachment storage, or namespace/link mutation |
| `unf-link` | Deterministic, ownership-safe veth planning, namespace movement, dual-stack address application, readback, recovery, and exact cleanup | Kubernetes access, durable transactions, route policy, controller state, or shell-command mutation |
| `unf-route` | Routing-provider abstraction, strict complete remote-route snapshot/Node-block intent, native endpoint and cross-node route IR, typed kernel lifecycle/repair/replacement, scoped rollback, and provider-declared MTU derivation | IP allocation, link mutation, durable transactions, Kubernetes access, or policy enforcement |
| `unf-ebpf-common` | Versioned fixed-layout flow and BPF map ABIs, including the independently banked dual-stack NodePort frontend contract | Variable strings or allocation |
| `unf-api` | CRD schema and serialization | Policy evaluation |
| `unf-policy` | Native and NetworkPolicy conversion, shared IR, deterministic evaluation, identity-tuple lowering | Kubernetes watches or BPF map mutation |
| `unf-service` | Bounded revisioned service IR, typed ClusterIP and address-family-aware NodePort/frontend/backend intent, provider-neutral Service/EndpointSlice and authenticated local-Node inputs, stable collision-checked provisional IDs, deterministic normalization/validation, fixed dual-stack ClusterIP lowering, and node-scoped NodePort map compilation | Kubernetes watches, Node-address discovery, runtime backend selection, connection tracking, or BPF map mutation |
| `unf-state` | Revision snapshots, bounded flow-history contract, Service/backend topology schema, and identity metadata | Transport or controller loops |
| `unf-controller` | Watches, EndpointSlice-aware desired-state/topology reconciliation, retained-last-valid service compilation, TokenReview-scoped local Node-address intent, authenticated snapshot distribution, explicit Node block and complete remote-route distribution, bounded durable agent-report and flow-history checkpointing, non-blocking external HTTP flow handoff, time-window flow queries, explanation, and read-only simulation orchestration | Packet parsing |
| `unf-agent` | Capability detection, Aya lifecycle, events, non-blocking telemetry export, authenticated transactional service/NodePort-map and durable node-block adoption, exact service/NodePort/identity/policy recovery, remote-route reconciliation, and opt-in root-authenticated local CNI transaction service | Kubernetes policy semantics or CNI namespace mutation |
| `unf-cni` | Bounded CNI protocol/socket handling and atomic durable-IPAM plus link/route ADD/CHECK/DEL orchestration | Kubernetes access, policy compilation, durable IPAM storage, routing protocols, or telemetry aggregation |
| `unfctl` | Operator-facing status, topology, flow history, explanation, and simulation | Fabric state ownership |
| `unf-ebpf-tc` | Bounded packet parsing, active-bank L3/L4 decisions, telemetry, source-side and host-origin dual-stack TCP/UDP ClusterIP translation, and `Cluster`/`Local` NodePort translation with paired persistent connection state | Selectors, enrichment strings, LoadBalancer translation, host-origin NodePort translation, or L7 processing |

The allowed dependency direction is from binaries toward libraries and from API
conversion toward domain types. Kernel ABI types depend only on `no_std`
primitives. No core library calls the Kubernetes API.

The accepted Phase 6 extension keeps LoadBalancer ownership split across
components. `unf-service` now owns bounded provider-neutral schema-v3 VIP
intent, and `unf-controller` owns explicit-class Kubernetes admission plus
retained-last-valid compilation. Existing service lowerers reject that intent.
The controller's allocation/status/provider orchestration, authenticated agent
host adoption and health state, provider-owned advertisement artifacts, and
`unf-ebpf-tc` VIP translation remain separate ordered milestones. Allocation,
advertisement, translation, and published readiness are not interchangeable.
ADRs 0093–0094 define the implemented boundary.

Long-running binaries supervise their API server and watcher/dataplane tasks with
a shared cancellation token. Phase 1 state uses explicit locks around small,
control-plane-only collections; packet processing and event records do not
allocate.
