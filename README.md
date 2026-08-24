# Universal eBPF Network Fabric (UNF)

UNF is an early-stage, Rust-first network observability and policy project for
Kubernetes and OpenShift. Its long-term goal is an identity-aware, explainable,
multi-cluster eBPF network fabric. Phase 1 established observation; Phase 2 added
the first identity-aware L3/L4 enforcement path, and Phase 3 is adding Kubernetes
compatibility. UNF is **not production-ready or
a CNI replacement**.

## Project status

Phase 1's observation gate and Phase 2's first enforcement gate are verified in
a two-node kind cluster. Collision-checked identities and transactional policy
revisions now drive TC allow/drop decisions with actual and shadow provenance.
The supported ingress `NetworkPolicy` slices are live-verified through the same
controller, policy engine, and dataplane. A read-only policy simulation foundation
now compares candidate native policy against revision-fenced live topology without
applying it. Versioned topology snapshots expose Nodes, workload placement,
Services, selector intent, and EndpointSlice-derived runtime backend readiness.
Node agents also export
destination-resolved flow observations into bounded, revisioned in-memory history
for operator queries and policy impact analysis. Agents publish revisioned status
acknowledgements, allowing controller and CLI status to report freshness-aware
cluster convergence for every watched Node. The resolved-identity fast path
is now dual-stack for IPv4/IPv6 TCP/UDP/SCTP, including verifier-bounded IPv6
extension-header traversal; native policy and selector-based NetworkPolicy IPv6
decisions are live-verified.
Identity and policy updates now use independent transactional banks selected by
atomic configuration-map writes. All nine enforcement maps persist in an
ABI-versioned bpffs directory; replacement agents validate and adopt
last-known-good identity/policy state, while fresh or incompatible startup
remains fenced from readiness until reconciliation.
See the authoritative
[project status and requirements traceability](docs/project-status.md) for phase
gates, evidence, limitations, and current work. The shorter
[roadmap](docs/roadmap.md) describes future direction, and the
[upstream-aligned ingress matrix](docs/development/networkpolicy-conformance.md)
records the exact compatibility behaviors exercised against the dataplane.

## Current scope

Implemented in the repository:

- versioned userspace/eBPF flow ABI and strongly typed numeric IDs;
- `SecurityPolicy` `network.unf.io/v1alpha1` API and generated CRD;
- deterministic L3/L4 policy compiler, shadow decisions, and property tests;
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
- controller health, readiness, metrics, status, and userspace explanation APIs;
- controller-aggregated per-node desired/applied identity and policy convergence;
- revision-fenced, read-only native policy simulation through the shared evaluator;
- bounded non-blocking agent telemetry export and a 4,096-flow controller history
  with explicit drop/eviction accounting;
- an Aya agent capable of loading and attaching the TC observation program;
- IPv4/IPv6 TCP/UDP/SCTP TC parsing, including bounded IPv6 extension-header
  traversal, with counters, bounded ring-buffer events, and active-bank L3/L4
  allow/drop decisions;
- revisioned controller-to-agent dual-stack identity snapshots and transactional
  dual-bank IPv4/IPv6 BPF maps selected by one atomic configuration write;
- selector-resolved policy snapshots and dual-bank transactional BPF policy maps;
- nine pinned enforcement maps with all-or-none validation, active-bank and
  revision checks, userspace cache recovery, and controller-independent
  replacement-agent readiness;
- `unfctl status`, `unfctl topology`, `unfctl flows`, and `unfctl explain` against live
  controller state;
- `unfctl policy simulate <security-policy.yaml>` with table/JSON/YAML
  representative and historical impact summaries plus current/proposed provenance;
- a reproducible dual-stack two-node kind demo covering native and NetworkPolicy
  cross-node IPv4/IPv6 allow/drop, bounded IPv6 extension-header allow/drop,
  namespace-selector convergence,
  rejection/deletion recovery, shadow
  pass-through, protocol-only port activation/recovery, bounded range and
  IPv4/IPv6 `ipBlock`
  enforcement and rejection recovery, named/protocol-only SCTP enforcement,
  namespace-wide target isolation/defaulting, same-Namespace and all-Namespace
  peers, exact Namespace-name and Namespace `NotIn` selection, peer OR/selector
  AND semantics, Pod/Namespace expressions, multiple ingress rules,
  exact/protocol-only UDP isolation, per-destination named-port
  resolution, source and destination label-driven recovery, stacked additive
  allows and allow-all recovery, revisioned eBPF provenance, and live policy
  explanations, plus a
  versioned EndpointSlice backend-readiness lifecycle.

Not implemented yet: service load balancing, routing, IPAM/CNI, encryption,
multi-cluster transport, IPv6 jumbograms/ESP/reassembly, or production
fail-closed recovery.

## Repository layout

```text
crates/                 Domain, API, policy, and state libraries
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
```

The eBPF program has a separate target build because it cannot be compiled as a
normal host test binary:

```bash
rustup toolchain install nightly --component rust-src
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
