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
Node agents also export destination-resolved flow observations into bounded,
revisioned history for operator queries and policy impact analysis. The controller
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
The resolved-identity fast path
is now dual-stack for IPv4/IPv6 TCP/UDP/SCTP, including verifier-bounded IPv6
extension-header traversal; native policy and selector-based NetworkPolicy IPv6
decisions are live-verified. The upstream-aligned three-Namespace ingress matrix
now runs every supported selector, additive-policy, named-port, and TCP/UDP
protocol-isolation transition against direct IPv4 and IPv6 Pod addresses.
Identity and policy updates now use independent transactional banks selected by
atomic configuration-map writes. All nine enforcement maps persist in an
ABI-versioned bpffs directory; replacement agents validate and adopt
last-known-good identity/policy state, while fresh or incompatible startup
remains fenced from readiness until reconciliation.
TC attachments now survive agent replacement: kernels supporting TCX use
per-interface pinned links and atomic link updates, while older kernels use a
stable legacy netlink filter tuple for in-place replacement. The two-node kind
gate continuously probes an explicitly denied flow through TCX agent handoff.
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
The agent also provides a dry-run-first cleanup command for known ABI v1/v2 pins,
TCX link pins, and UNF-named legacy filters; current ABI removal requires an
additional explicit confirmation and unknown directory content is refused. The
OpenShift uninstall orchestrator reviews that plan on every selected worker,
requires exact cluster-context confirmation, stops agents before mutation,
verifies host cleanup, preserves the CRD by default, and removes its temporary
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
- bounded, schema-validated ConfigMap persistence for authenticated agent reports,
  with startup recovery that cannot satisfy a new controller epoch by itself;
- schema v2 agent acknowledgements authenticated through audience-scoped,
  Pod-bound Kubernetes TokenReview identity and authoritative Node placement;
- a split controller surface with public operator HTTP and CA-pinned,
  TokenReview-authenticated internal HTTPS for agent snapshots and writes;
- in-place server-certificate and CA-bundle reload with overlapping-root support,
  last-known-good fallback, reload/error metrics, and an OpenShift rotation gate;
- OpenShift-native fail-closed admission for the agent's exact bpffs/BTF host
  paths, mount modes, and single-container ownership;
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
- nine pinned enforcement maps with all-or-none validation, active-bank and
  revision checks, userspace cache recovery, and controller-independent
  replacement-agent readiness;
- persistent TC attachment handoff using pinned, atomically updated TCX links on
  Linux 6.6+ and stable legacy netlink filters on older kernels, with the active
  attachment mode exposed by each agent;
- explicit `auto`, `tcx-pinned`, and `legacy-netlink` attachment selection, with
  kind verification that removes TCX coverage, continuously probes enforcement
  through legacy in-place replacement, then restores TCX before scoped cleanup;
- dry-run-first `unf-agent cleanup` planning for recognized ABI v1/v2 map and
  TCX pins plus UNF-named legacy filters, with unknown-content refusal and an
  explicit current-ABI confirmation gate;
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
- `unfctl status`, `unfctl topology`, `unfctl flows`, and `unfctl explain` against live
  controller state;
- `unfctl policy simulate <security-policy.yaml>` with table/JSON/YAML
  representative and historical impact summaries, optional last-received-time
  windows and newest-first limits, plus current/proposed provenance;
- a reproducible dual-stack two-node kind demo covering native and NetworkPolicy
  cross-node IPv4/IPv6 allow/drop, bounded IPv6 extension-header allow/drop,
  namespace-selector convergence,
  rejection/deletion recovery, shadow
  pass-through, protocol-only port activation/recovery, bounded range and
  IPv4/IPv6 `ipBlock`
  enforcement and rejection recovery, named/protocol-only SCTP enforcement,
  namespace-wide target isolation/defaulting, same-Namespace and all-Namespace
  peers, explicit empty source/port wildcards, multi-port OR, empty/labeled
  same-Namespace PodSelectors, exact Namespace-name selection, all four
  Pod/Namespace selector operators, peer OR/selector AND semantics, multiple
  ingress rules,
  exact/protocol-only UDP isolation, per-destination named-port resolution and
  nonexistent named-port fail-closed behavior, all four destination-selector
  expression operators, source, destination, and Namespace label-driven
  recovery, stacked additive allows and allow-all recovery, revisioned eBPF
  provenance, and live policy explanations, plus a
  versioned EndpointSlice backend-readiness lifecycle.

Not implemented yet: service load balancing, routing, IPAM/CNI, workload/data-plane encryption,
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
