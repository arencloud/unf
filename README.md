# Universal eBPF Network Fabric (UNF)

UNF is an early-stage, Rust-first network observability and policy project for
Kubernetes and OpenShift. Its long-term goal is an identity-aware, explainable,
multi-cluster eBPF network fabric. Phase 1 is an observation foundation and the
current Phase 2 work is deliberately incremental. UNF is **not production-ready
or a CNI replacement**.

## Project status

Phase 1's observation gate is verified in a two-node kind cluster. Phase 2 is now
in progress: collision-checked identities are revisioned, distributed into each
node's BPF map, and attached to observed flows; enforcement is not implemented
yet. See the authoritative
[project status and requirements traceability](docs/project-status.md) for phase
gates, evidence, limitations, and current work. The shorter
[roadmap](docs/roadmap.md) describes future direction.

## Current scope

Implemented in the repository:

- versioned userspace/eBPF flow ABI and strongly typed numeric IDs;
- `SecurityPolicy` `network.unf.io/v1alpha1` API and generated CRD;
- deterministic L3/L4 policy compiler, shadow decisions, and property tests;
- a kube-rs controller watching Pods, Namespaces, and SecurityPolicies;
- controller health, readiness, metrics, status, and userspace explanation APIs;
- an Aya agent capable of loading and attaching the TC observation program;
- an IPv4 TCP/UDP TC parser with counters and bounded ring-buffer events;
- revisioned controller-to-agent IPv4 identity snapshots and a versioned BPF map;
- `unfctl status` and `unfctl explain` against live controller state;
- a reproducible two-node kind demo covering cross-node traffic, live eBPF
  observation, and shadow-policy explanations.

Not implemented yet: policy distribution to BPF maps, dataplane enforcement,
service load balancing, routing, IPAM/CNI, encryption, or multi-cluster transport.

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
