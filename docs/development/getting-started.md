# Development environment

## Host workspace

Install the Rust version declared in `rust-toolchain.toml`, then run:

```bash
make fmt-check lint test
```

The host workspace is portable. Kernel attachment requires Linux and privileges.

Render the initial manifests with:

```bash
kubectl kustomize deploy
```

The checked-in manifests reference local `:dev` images. The Make targets below
build and load them; no published image is implied.

## Kernel requirements for the prototype

- Linux with eBPF syscall and TC classifier support;
- BTF at `/sys/kernel/btf/vmlinux` for future portable kernel types;
- bpffs mounted at `/sys/fs/bpf`;
- cgroup v2 recommended;
- `CAP_BPF`, `CAP_NET_ADMIN`, and possibly `CAP_PERFMON`/`CAP_SYS_RESOURCE`
  depending on kernel policy.

Check the local machine with `unf-agent` capability-only mode and its `/v1/status`
endpoint. Do not disable SELinux. OpenShift deployment must eventually supply the
required SCC/SELinux policy and host mounts explicitly.

## Build the eBPF object

```bash
rustup toolchain install nightly --component rust-src
cargo install bpf-linker --locked
make ebpf
```

`bpf-linker` features track LLVM majors. If its default LLVM does not match the
host, select the matching feature. For example, the Fedora LLVM 22 development
host used for the initial verification required:

```bash
cargo install bpf-linker --version 0.11.0 \
  --no-default-features --features llvm-22 --locked
```

This produces a target-specific object under
`ebpf/unf-ebpf-tc/target/bpfel-unknown-none/release/`. Attach it only on a disposable
development interface or cluster node:

```bash
sudo target/debug/unf-agent \
  --interface eth0 \
  --ebpf-object ebpf/unf-ebpf-tc/target/bpfel-unknown-none/release/unf-ebpf-tc
```

TC attachment changes host network state. The agent currently leaves the clsact
qdisc in place when it exits; use a disposable environment for testing.

## kind

The local workflow currently uses Podman, `sudo`, Go, and `kubectl`. It installs a
workspace-local pinned kind binary, keeps kubeconfig under `.tools/`, and creates
a rootful two-node cluster so the agent can load BPF programs:

```bash
make kind-up
make kind-deploy
make kind-test
```

`kind-deploy` builds the userspace images and eBPF object, loads both images into
the nodes, and applies the CRD and workloads. `kind-test` installs the demo,
proves cross-node port 8080 allow and open-port 9090 deny, switches the same
policy through shadow pass-through and back, and validates revisioned event and
CLI provenance. It also exercises a supported ingress `NetworkPolicy`: cross-node
allow and default-isolation drop, unsupported-update rejection and recovery, and
named-port resolution, protocol-only TCP activation/removal without UDP
broadening, bounded `endPort` boundary enforcement and oversized-range rejection,
bounded IPv4 `ipBlock` allow/exception behavior and oversized-block rejection,
Namespace relabel, and deletion/recreation convergence.
The verifier also queries topology schema v1, creates and removes a selector
Service, and requires both Service membership and independent topology revision
transitions. It also requires agents to export the live frontend-to-backend flow,
queries bounded history, and verifies observation-weighted historical policy
impact.
The host kernel is shared with kind nodes. `make kind-down`
deletes only the named `unf-dev` cluster.

To inspect the checked-in deny proposal without applying it:

```bash
target/debug/unfctl --controller-url http://127.0.0.1:9962 \
  policy simulate deploy/examples/simulation-deny.yaml
```

The result is fenced to the reported identity epoch/revision, policy revision,
and topology revision. Inspect the same current Node/workload/Service
relationships with:

```bash
target/debug/unfctl --controller-url http://127.0.0.1:9962 topology
target/debug/unfctl --controller-url http://127.0.0.1:9962 flows
```

Simulation reports its bounded current-topology probe matrix separately from the
revisioned, 4,096-key in-memory history. `make kind-test` verifies the predicted
8080 denial in both inputs, unchanged policy revision, and continued live 8080
allow after simulation.

The DaemonSet attaches ingress classification to every non-loopback node interface
and discovers newly created pod veths. A packet can therefore produce multiple
interface-level events. Logical-key aggregation is implemented, but cross-interface
deduplication and durable history remain later telemetry work.

## Fedora, RHEL, and OpenShift

Do not assume Ubuntu paths or AppArmor. Validate RHEL CoreOS, CRI-O, SELinux, SCC,
bpffs mounts, and capability availability in a real OpenShift test suite; kind is
not evidence of OpenShift support.
