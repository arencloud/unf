# Components

| Component | Responsibility | Must not own |
|---|---|---|
| `unf-common` | IDs, revisions, protocols, verdicts, policy reasons | Kubernetes or Aya clients |
| `unf-ebpf-common` | Versioned fixed-layout flow and BPF map ABIs | Variable strings or allocation |
| `unf-api` | CRD schema and serialization | Policy evaluation |
| `unf-policy` | Conversion, IR, deterministic evaluation, identity-tuple lowering | Kubernetes watches or BPF map mutation |
| `unf-state` | Revision snapshots and identity metadata | Transport or controller loops |
| `unf-controller` | Watches and desired-state reconciliation | Packet parsing |
| `unf-agent` | Capability detection, Aya lifecycle, events | Kubernetes policy semantics |
| `unfctl` | Operator-facing status and explanation | Fabric state ownership |
| `unf-ebpf-tc` | Bounded packet parsing and telemetry | Selectors or enrichment strings |

The allowed dependency direction is from binaries toward libraries and from API
conversion toward domain types. Kernel ABI types depend only on `no_std`
primitives. No core library calls the Kubernetes API.

Long-running binaries supervise their API server and watcher/dataplane tasks with
a shared cancellation token. Phase 1 state uses explicit locks around small,
control-plane-only collections; packet processing and event records do not
allocate.
