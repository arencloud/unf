# Universal eBPF Network Fabric (UNF)

UNF is an early-stage, Rust-first network observability and policy project for
Kubernetes and OpenShift. Its long-term goal is an identity-aware, explainable,
multi-cluster eBPF network fabric. Phase 1 established observation, Phase 2 added
the first identity-aware L3/L4 enforcement path, and Phase 3 completed its
bounded Kubernetes compatibility and simulation gate. UNF is **not production-ready or
a CNI replacement**.

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
Identity and policy updates now use independent transactional banks selected by
atomic configuration-map writes. All eleven enforcement maps persist in an
ABI-versioned bpffs directory; replacement agents validate and adopt
last-known-good identity/policy state—including populated dual-stack egress banks
on the source Node—while fresh or incompatible startup remains fenced from
readiness until reconciliation.
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
The full-CNI foundation is now in progress under ADRs 0057–0064. The `unf-cni`
executable now composes dual-stack IPAM, exact veth, and native routing through
atomic ADD/CHECK/DEL transactions. An explicitly enabled local-agent Unix service
provides the root-authenticated, bounded schema-v2 transaction boundary and
atomic durable attachment/dual-stack lease journal beneath that lifecycle. Its
modular IPAM provider allocates deterministically from explicit node blocks, migrates
schema-v1 attachment state, and releases leases only after abort/delete
completion. A typed-netlink `unf-link` primitive now creates, moves, configures,
recovers, reads back, and exactly removes dual-stack veth pairs from those durable
records. A typed native route/neighbor primitive now adds exact dual-stack
endpoint routing with scoped rollback, conflict preservation, and verified
MTU/fragmentation boundaries. An explicitly opted-in Node now receives its own
authenticated, revisioned dual-stack `spec.podCIDRs` snapshot from the controller;
the agent validates durable provider provenance, persists owner-only state, and
acknowledges application before convergence. Cross-node networking and cluster
CNI installation are not implemented; existing overlay deployments are unchanged.
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
- eleven pinned enforcement maps with all-or-none validation, active-bank and
  revision checks, userspace cache recovery, and controller-independent
  replacement-agent readiness;
- persistent TC attachment handoff using pinned, atomically updated TCX links on
  Linux 6.6+ and stable legacy netlink filters on older kernels, with the active
  attachment mode exposed by each agent;
- explicit `auto`, `tcx-pinned`, and `legacy-netlink` attachment selection, with
  kind verification that removes TCX coverage, continuously probes enforcement
  through legacy in-place replacement, then restores TCX before scoped cleanup;
- dry-run-first `unf-agent cleanup` planning for map and TCX pins from ABI v1
  through the binary's compiled current version plus UNF-named legacy filters,
  with unknown-content refusal and an explicit current-ABI confirmation gate;
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

Not implemented yet: service load balancing, production routing/CNI integration,
workload/data-plane encryption, generic related-flow/ICMP/NAT tracking,
multi-cluster transport, IPv6 jumbograms/ESP/reassembly, or production
fail-closed recovery. Bounded revision-scoped TCP/UDP/SCTP reply state is
implemented; it resets when the eBPF program is replaced.

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
