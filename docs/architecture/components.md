# Components

| Component | Responsibility | Must not own |
|---|---|---|
| `unf-common` | IDs, revisions, protocols, verdicts, policy reasons | Kubernetes or Aya clients |
| `unf-cni-state` | Versioned local CNI transaction schema, inspectable attachment/lease state machine, schema migration, and atomic durable journal | Kubernetes access, namespace/link mutation, IPAM allocation policy, or remote transport |
| `unf-ipam` | Modular, bounded dual-stack lease types, collision-safe node-block allocation, overlap validation, and strict distribution snapshot schema | Kubernetes watches, routing policy, durable attachment storage, or namespace/link mutation |
| `unf-link` | Deterministic, ownership-safe veth planning, namespace movement, dual-stack address application, readback, recovery, and exact cleanup | Kubernetes access, durable transactions, route policy, controller state, or shell-command mutation |
| `unf-route` | Routing-provider abstraction, strict complete remote-route snapshot/Node-block intent, native endpoint and cross-node route IR, typed kernel lifecycle/repair/replacement, scoped rollback, and provider-declared MTU derivation | IP allocation, link mutation, durable transactions, Kubernetes access, or policy enforcement |
| `unf-ebpf-common` | Versioned fixed-layout flow and BPF map ABIs | Variable strings or allocation |
| `unf-api` | CRD schema and serialization | Policy evaluation |
| `unf-policy` | Native and NetworkPolicy conversion, shared IR, deterministic evaluation, identity-tuple lowering | Kubernetes watches or BPF map mutation |
| `unf-service` | Bounded revisioned service IR, typed ClusterIP and address-family-aware NodePort/frontend/backend intent, provider-neutral Service/EndpointSlice compiler inputs, stable collision-checked provisional IDs, deterministic normalization, validation, and fixed dual-stack ClusterIP map lowering | Kubernetes watches, Node-address selection, runtime backend selection, connection tracking, host-facing NodePort lowering, or BPF map mutation |
| `unf-state` | Revision snapshots, bounded flow-history contract, Service/backend topology schema, and identity metadata | Transport or controller loops |
| `unf-controller` | Watches, EndpointSlice-aware desired-state/topology reconciliation, retained-last-valid service compilation and authenticated snapshot distribution, explicit Node block and complete remote-route distribution, bounded durable agent-report and flow-history checkpointing, non-blocking external HTTP flow handoff, time-window flow queries, explanation, and read-only simulation orchestration | Packet parsing |
| `unf-agent` | Capability detection, Aya lifecycle, events, non-blocking telemetry export, authenticated transactional service-map and durable node-block adoption, exact service/identity/policy recovery, remote-route reconciliation, and opt-in root-authenticated local CNI transaction service | Kubernetes policy semantics or CNI namespace mutation |
| `unf-cni` | Bounded CNI protocol/socket handling and atomic durable-IPAM plus link/route ADD/CHECK/DEL orchestration | Kubernetes access, policy compilation, durable IPAM storage, routing protocols, or telemetry aggregation |
| `unfctl` | Operator-facing status, topology, flow history, explanation, and simulation | Fabric state ownership |
| `unf-ebpf-tc` | Bounded packet parsing, active-bank L3/L4 decisions, telemetry, and source-side dual-stack TCP/UDP ClusterIP translation with paired persistent connection state | Selectors, enrichment strings, host-network/NodePort/LoadBalancer service translation, or L7 processing |

The allowed dependency direction is from binaries toward libraries and from API
conversion toward domain types. Kernel ABI types depend only on `no_std`
primitives. No core library calls the Kubernetes API.

Long-running binaries supervise their API server and watcher/dataplane tasks with
a shared cancellation token. Phase 1 state uses explicit locks around small,
control-plane-only collections; packet processing and event records do not
allocate.
