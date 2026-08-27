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

Connected deployment also requires Secret `unf-internal-tls` with `tls.crt` and
`tls.key`, plus ConfigMap `unf-internal-ca` with `ca.crt`, in `unf-system`.
Provision them from an approved issuer before applying the workloads. The kind
target below creates disposable development credentials automatically; those
credentials are not a production certificate mechanism.

## Kernel requirements for the prototype

- Linux with eBPF syscall and TC classifier support;
- BTF at `/sys/kernel/btf/vmlinux` for future portable kernel types;
- bpffs mounted at `/sys/fs/bpf`;
- cgroup v2 recommended;
- `CAP_BPF` and `CAP_NET_ADMIN`, plus any verifier capability required by the
  compiled program. The qualified RHCOS 9.8 Linux 5.14 path additionally requires
  `CAP_PERFMON` but not `CAP_SYS_RESOURCE`.

Check the local machine with `unf-agent` capability-only mode and its `/v1/status`
endpoint. Do not disable SELinux. The OpenShift overlay supplies and verifies the
dedicated SCC, explicit `spc_t` domain, and exact host mounts.

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

TC attachment changes host network state. On Linux 6.6+, the agent leaves its
per-interface TCX links pinned below `/sys/fs/bpf/unf/v3/links` so a replacement
can update them atomically. On older kernels it leaves the clsact qdisc and its
stable legacy filters in place for in-place replacement. Use a disposable
environment for testing.
Selection defaults to `auto`; `--tc-attachment-mode tcx-pinned` and
`--tc-attachment-mode legacy-netlink` are explicit compatibility-test or
controlled-migration overrides. An explicit mode that the host cannot support
fails during attachment rather than silently changing modes.

## Scoped host-state cleanup

`unf-agent cleanup` plans removal by default and changes nothing without
`--execute`. Retire ABI v1 only after validating the v2 rollout on the node:

```bash
sudo target/debug/unf-agent cleanup --abi-version 1
sudo target/debug/unf-agent cleanup --abi-version 1 --execute
```

The planner derives `/sys/fs/bpf/unf/v1` from the fixed version argument. It
accepts only the six known v1 map pins and recognized numeric UNF TCX link-pin
names. It refuses symbolic links, non-directory targets, and any unknown direct
content instead of recursively deleting it. A missing target is an idempotent
no-op.

Removing current v3 state is an uninstall or controlled-reset operation. First
stop every agent using that node so no process is reading or recreating the maps
or attachments, inspect the dry run, and provide the additional confirmation:

```bash
sudo target/debug/unf-agent cleanup \
  --abi-version 3 --allow-current-abi \
  --legacy-attachments --all-interfaces --legacy-direction both
sudo target/debug/unf-agent cleanup \
  --abi-version 3 --allow-current-abi \
  --legacy-attachments --all-interfaces --legacy-direction both --execute
```

Legacy cleanup may instead target repeated `--interface NAME` values. It removes
filters matching UNF's ingress/egress program names, treats absence as success,
and never removes clsact or unrelated filters. Cleanup is a privileged per-node
operation; the command does not coordinate a DaemonSet rollout or validate that
replacement enforcement is active. During migration, restore and verify the new
attachment mode before removing the old one.

For OpenShift uninstall, do not invoke current-ABI cleanup independently. Review
the coordinated plan on every selected worker first:

```bash
OPENSHIFT_KUBECONFIG="$PWD/.tools/cl02-audit.kubeconfig" make openshift-uninstall
```

After reviewing the reported context, nodes, pins, interfaces, and resource
scope, execution requires that exact context. Namespace deletion is separately
explicit; the CRD and `SecurityPolicy` objects remain by default:

```bash
OPENSHIFT_KUBECONFIG="$PWD/.tools/cl02-audit.kubeconfig" \
OPENSHIFT_UNINSTALL_ARGS="--execute --confirm-context 'CURRENT_CONTEXT' --delete-namespace" \
make openshift-uninstall
```

The orchestrator stops every agent, uses constrained per-node Jobs for cleanup,
verifies host state is absent, and only then removes SCC, admission, and RBAC
authority. CRD deletion additionally needs `--delete-crd`; if custom resources
exist it also needs `--confirm-crd-data-loss`.

## kind

The local workflow currently uses Podman, `sudo`, Go, and `kubectl`. It installs a
workspace-local pinned kind binary, keeps kubeconfig under `.tools/`, and creates
a rootful dual-stack two-node cluster so the agent can load BPF programs:

```bash
make kind-up
make kind-deploy
make kind-test
```

`make kind-deploy` runs `hack/configure-internal-tls.sh` before applying the
workloads. The script keeps its private CA and leaf key below ignored `.tools/`,
publishes only the serving Secret and CA ConfigMap to the disposable cluster, and
reuses an unexpired leaf on later deploys. Removing `.tools/kind-internal-tls`
rotates the development trust on the next deploy. Running processes accept
validated leaf and trust changes in place; use an overlapping CA bundle when the
issuer changes so clients trust both the old and new leaf during the handoff.

`kind-up` mounts bpffs at `/sys/fs/bpf` inside every disposable kind node,
matching the agent DaemonSet's host prerequisite. It also selects the nftables
IPv6 frontend inside the pinned kindnet image and waits for that DaemonSet to
become ready. This keeps the dual-stack fixture
reproducible on development kernels without the legacy IPv6 NAT table.

`kind-deploy` builds the userspace images, eBPF object, and test-tools image with
SCTP `socat`, the IPv6 extension-header probe, BPF fault utilities, and `tc`,
loads them into the nodes, and applies the CRD and workloads. `kind-test`
installs the demo, proves cross-node IPv4/IPv6 port 8080 allow and open-port 9090
deny,
switches the same policy through shadow pass-through and back, and validates
revisioned event and CLI provenance. Real UDP packets carrying Hop-by-Hop,
Destination Options, and combined IPv6 extension headers must also produce the
expected native allow/explicit-deny decisions and provenance. It also exercises
a supported ingress `NetworkPolicy`: cross-node IPv4/IPv6 allow and
default-isolation drop,
unsupported-update rejection and recovery, and
per-destination named-port resolution and nonexistent-port fail-closed isolation,
protocol-only TCP activation/removal without UDP
broadening, bounded `endPort` boundary enforcement and oversized-range rejection,
bounded IPv4/IPv6 `ipBlock` allow/exception behavior and oversized-block rejection,
all four destination `podSelector` expression operators, overlapping target
selectors with ordered deletion recovery, remote target-specific exceptions over
namespace-wide isolation, same-object allow-all/default-deny replacement and rollback,
Namespace relabel, and deletion/recreation convergence. Stateful same-Namespace
return traffic when both endpoints are ingress-isolated remains outside this claim.

The base deployment also pre-creates `unf-agent-acknowledgements`,
`unf-flow-history`, and `unf-topology-history`. Exact-name RBAC allows the
controller to get and patch these stores but not create or delete ConfigMaps. It
owns their `reports.json`, `flows.json`, and `history.json` data fields and
checkpoints at most once every two seconds; later `kubectl apply -k deploy`
operations do not claim or clear those fields. If an administrator corrupts a
checkpoint, startup fails instead of trusting partial state. Repair or recreate
the affected ConfigMap, then restart the controller.

It then applies `deploy/examples/networkpolicy-conformance.yaml`, whose policy
deliberately omits `podSelector`, `policyTypes`, and port protocol. The verifier
requires the namespace-wide target to isolate the probe's non-allowed port while
allowing default-TCP 8085, narrows the target selector, and requires the
no-longer-selected probe Pod to return to the Kubernetes non-isolated default
before cleaning up the fixture.
Finally, `deploy/examples/networkpolicy-sctp.yaml` creates a cross-node SCTP echo
pair. The verifier requires named SCTP/8086 to pass, SCTP/9093 to drop by default,
a protocol-only SCTP rule to activate 9093, removal to restore the drop, and the
allowed protocol-132 flow to carry revisioned provenance into bounded history.
The disposable `deploy/examples/networkpolicy-upstream-ingress.yaml` matrix then
checks default isolation, same-Namespace PodSelector scope, an empty
NamespaceSelector, exact Namespace-name selection, Namespace `NotIn` exclusion,
selector AND including multi-value Pod `In` with Namespace-name `NotIn`,
homogeneous multiple-PodSelector and heterogeneous peer OR, Pod/Namespace
`matchExpressions`,
multiple ingress-rule source/port pairing, source-label deny/recovery,
destination Pod-label isolation/recovery, stacked additive policies, and
temporary allow-all precedence across three source contexts and two ports. Its
two selected servers also map one `web` port name to different numeric ports;
the verifier requires destination-specific allow/deny and deletion recovery.
A dual-protocol echo target proves exact and protocol-only UDP rules do not
broaden TCP or non-matching peers and recover after deletion. Every selector and
additive-policy transition targets direct IPv4 and IPv6 Pod addresses; the named
port and dual-protocol targets also bind and verify both families. The verifier
requires every mutation to converge on both agents and deletes its three test
Namespaces before returning.
The exact scope and upstream mapping are tracked
in [networkpolicy-conformance.md](networkpolicy-conformance.md).
That document also pins a one-to-one 49-scenario audit to upstream Kubernetes
commit `9aac5f741fa6095594cdfed4756a52cf0bf4b191`; all scenarios are verified
through shared unit evidence and the complete ingress and focused egress gates.
The same-Namespace target-exception leg additionally requires dual-stack
established-reply provenance.
The verifier also queries topology schema v3, requires dual-stack workload
addresses and populated per-family identity maps, and creates a selectorless Service
with a manually managed EndpointSlice. It requires the backend to transition from
not ready to ready, verifies deletion removes runtime state while selector intent
stays empty, and proves the independent topology/service revisions advance without
changing policy revision. It also requires agents to export the live
frontend-to-backend flow, queries bounded history, and verifies
observation-weighted historical policy impact. Flow snapshot schema v4 must retain
direction-separated IPv4/IPv6 flow keys; agent export uses schema v3 and the
durable checkpoint migrates schema-v1 records to ingress before writing schema v2.
The host kernel is shared with kind nodes. `make kind-down`
deletes only the named `unf-dev` cluster.

To inspect the checked-in deny proposal without applying it:

```bash
target/debug/unfctl --controller-url http://127.0.0.1:9962 \
  policy simulate deploy/examples/simulation-deny.yaml
target/debug/unfctl --controller-url http://127.0.0.1:9962 \
  policy simulate deploy/examples/simulation-deny.yaml --last 15m --limit 100
target/debug/unfctl --controller-url http://127.0.0.1:9962 \
  policy simulate deploy/examples/simulation-networkpolicy-egress-deny.yaml
```

Both native `SecurityPolicy` and Kubernetes `NetworkPolicy` manifests use the
same read-only command. Schema v4 reports the resource kind and expands
NetworkPolicy impact by ingress/egress direction and each shared IPv4/IPv6 family.
The result is fenced to the reported identity epoch/revision, policy revision,
and topology revision.

During a native `SecurityPolicy` shadow rollout, summarize retained
counterfactual decisions directly from the controller:

```bash
target/debug/unfctl --controller-url http://127.0.0.1:9962 \
  policy shadow-impact --last 15m --limit 100
```

For controller-independent review, first export a bounded schema-v4 snapshot,
then analyze that file locally. The second command does not use the controller
URL and accepts JSON or YAML:

```bash
target/debug/unfctl --controller-url http://127.0.0.1:9962 \
  --output json flows --last 15m --limit 100 > shadow-flows.json
target/debug/unfctl --controller-url http://127.0.0.1:1 \
  policy shadow-impact --flows-file shadow-flows.json
```

The report is observation-weighted because one retained logical flow can
aggregate many dataplane events. It distinguishes actual-allow/shadow-deny,
actual-deny/shadow-allow, equal verdicts, and other verdict changes while
retaining policy/rule provenance and the snapshot query boundary.

Inspect the current Node/workload/Service and runtime backend relationships with:

```bash
target/debug/unfctl --controller-url http://127.0.0.1:9962 topology
target/debug/unfctl --controller-url http://127.0.0.1:9962 \
  topology-history --last 15m --limit 10
target/debug/unfctl --controller-url http://127.0.0.1:9962 \
  topology-history --since-revision 100 --until-revision 120 --output json
target/debug/unfctl --controller-url http://127.0.0.1:9962 flows
target/debug/unfctl --controller-url http://127.0.0.1:9962 flows --last 15m --limit 100
target/debug/unfctl --controller-url http://127.0.0.1:9962 flows \
  --since-unix-ms 1787688000000 --until-unix-ms 1787688900000
target/debug/unfctl --controller-url http://127.0.0.1:9962 status
target/debug/unfctl --controller-url http://127.0.0.1:9962 explain \
  --from frontend/client --to backend/server --direction ingress \
  --ip-family ipv6 --protocol tcp --port 8080
```

Ingress is the backward-compatible explanation default. For egress policy, pass
`--direction egress`; on dual-stack Pods, pass `--ip-family ipv4` or `ipv6` so
the reported `ipBlock` result is tied to the concrete address pair shown in the
response.

Topology history contains complete topology schema-v3 snapshots rather than
object-level patches. The controller retains the newest 32 semantic revisions,
coalesces Kubernetes watcher initialization into one snapshot, and checkpoints
the newest subset that fits below the ConfigMap data ceiling. Query bounds are
inclusive, results are newest first, and the response reports memory eviction,
durable omission, matching, and truncation explicitly. A restored entry keeps
its original controller epoch and capture timestamp.

Flow bounds are inclusive and select aggregate entries by their exact
`last_received_unix_ms`; they do not bucket each observation by event time. The
newest bounded checkpoint survives controller restart. Run its focused gate with
`make kind-flow-history-retention-test`.

The controller can also forward each validated agent batch to one external HTTP
receiver. HTTPS is mandatory unless the explicit development-only plaintext flag
is enabled. A private CA augments normal platform trust, and a bearer token is
reread from its mounted file for every attempt:

```yaml
env:
  - name: UNF_CONTROLLER_FLOW_EXPORT_HTTP_URL
    value: https://collector.example/v1/unf/flows
  - name: UNF_CONTROLLER_FLOW_EXPORT_HTTP_CA
    value: /var/run/secrets/collector/ca.crt
  - name: UNF_CONTROLLER_FLOW_EXPORT_HTTP_BEARER_TOKEN_FILE
    value: /var/run/secrets/collector/token
  - name: UNF_CONTROLLER_FLOW_EXPORT_HTTP_QUEUE_CAPACITY
    value: "256"
  - name: UNF_CONTROLLER_FLOW_EXPORT_HTTP_MAX_ATTEMPTS
    value: "3"
  - name: UNF_CONTROLLER_FLOW_EXPORT_HTTP_TIMEOUT_SECONDS
    value: "10"
```

Envelope schema v1 contains `controller_epoch`, epoch-scoped
`export_sequence`, `topology_revision`, `received_unix_ms`, and the complete
flow-export schema-v3 `batch`. Receivers should deduplicate on
`(controller_epoch, export_sequence)`. Delivery is at least once, redirects are
disabled, and 408, 429, 5xx, or network failures retry with bounded backoff.
Queue pressure and exhausted delivery affect only the external copy; the seven
delivery/loss counters report enqueue, attempt, success, error, and
batch/observation loss. Three gauges report configured queue capacity, current
depth, and the process-lifetime high-water mark. No endpoint is configured by
default. Use `make kind-external-flow-export-test` for the focused retry,
outage/recovery, sustained-pressure, and ordering gate.

Simulation reports its bounded current-topology probe matrix separately from the
revisioned, 4,096-key retained history. Its `--last`, `--since-unix-ms`,
`--until-unix-ms`, and `--limit` options apply only to historical impact; topology
evaluation is unchanged. The response exposes the applied bounds, matched and
returned flows, observations, and truncation state. `make kind-test` verifies a
recent 8080 denial impact, an empty future history window, unchanged policy
revision, and continued live 8080 allow after simulation. Status reports
per-node desired/applied identity and
policy revisions and marks the watched Node set converged only while every agent
has a fresh matching acknowledgement. Agent acknowledgement schema v2 includes
the reporting Pod name/UID. The DaemonSet disables the general API token mount and
projects only an automatically rotated one-hour token for audience
`unf-controller.unf-system.svc`; the controller uses its narrowly added
`tokenreviews.create` permission to bind that credential to the `unf-agent`
service account, watched Pod UID, and Node placement. Missing, invalid, or
cross-Node credentials fail closed and are counted by
`unf_agent_authentication_failures_total`. Each agent also reports
`tc_attachment_mode` as `tcx_pinned` or `legacy_netlink`. During offline
replacement, the verifier continuously probes the denied TCP/9090 path and
requires zero successful requests before the replacement is Ready.

Both controller and agent expose `GET /v1/version`. Compatibility schema v1
reports the embedded Git revision and the persistent-BPF, identity snapshot,
policy snapshot, agent-status, and flow-export schema versions. Use the focused
adjacent-version gate after the normal Kind deployment:

```bash
make kind-upgrade-test
```

The target archives and builds `HEAD^` as N, builds the working tree as N+1,
loads both generations, and proves N/N, controller N+1 with agents N, a
one-Node-at-a-time mixed agent state, all N+1, agent rollback, controller
rollback with N+1 agents, and final recovery. It continuously requires 8080
allow plus 9090 deny and checks authenticated convergence and telemetry in every
pairing. Override `UNF_UPGRADE_BASELINE_REF` to pin a release baseline. The gate
supports only adjacent revisions with the same published compatibility tuple;
ABI/schema changes require a dedicated migration plan and qualification.

The projected credential is never written to logs or checked into the repository.
Agent snapshots, acknowledgements, and flow telemetry use the controller's
dedicated HTTPS port and a client trust store containing only `unf-internal-ca`;
the public operator API remains HTTP. Serving keypairs and CA bundles reload in
place with last-known-good fallback and dedicated success/error metrics. The
[OpenShift qualification workflow](openshift-qualification.md) uses the platform
Service CA while preserving the external-PKI Secret/ConfigMap contract. Its IPv4
and dual-stack gates verify projected custom-audience tokens, TokenReview Pod
extras, controller RBAC, Service CA TLS, SCC admission, enforcing SELinux, native
legacy attachment, the encrypted Service path, and per-family cross-worker
enforcement/history. Its dedicated rotation gate also proves an overlapping
external-PKI issuer handoff and restoration without Pod replacement.

After the primary gate, `hack/verify-kind-legacy-netlink.sh` explicitly selects
legacy mode when the host would normally choose TCX, confirms the reserved
priority/handle filters, removes every UNF ingress TCX pin, and repeats the
offline-controller replacement under a continuous deny probe. It requires the
replacement to report in-place netlink replacement, then rolls back to automatic
TCX mode and confirms pins exist before deleting only the reserved legacy
filters through the production dry-run-first cleanup command. On a pre-6.6 host
already using legacy mode, the same script exercises
the native selection without the transition or cleanup step.

The primary Kind gate also performs a second offline replacement with a populated
dual-stack egress policy. It replaces the source-node agent, requires nonzero
recovered IPv4/IPv6 egress-bank counts and the exact policy revision, and proves
direct Pod-address allow/deny continuity before controller restoration and policy
cleanup. Service ClusterIPs are intentionally not used for this proof because
UNF does not own CNI service-NAT behavior.

Before that replacement, `make kind-test` temporarily deploys the privileged
[BPF fault helper](../../deploy/examples/bpf-fault-helper.yaml) fixture. It builds
isolated bpffs alias sets and requires the exact agent binary to reject partial
pins, malformed active policy config, and invalid inactive-bank debris. The
same helper then uses reserved inactive-bank keys to fill the shared physical
`POLICY_RULES` map until the kernel rejects staging. The verifier requires the
desired revision to advance while the applied revision and selected bank stay
fixed, rechecks the established allow/deny flows, releases pressure, and requires
that waiting revision to activate before restoring enforcement. Cleanup removes
only the scoped synthetic keys and fault aliases. It also adds unknown content to
a recognized v1 directory to prove refusal, verifies dry-run preservation, then
uses the deployed agent command to remove v1 state on both nodes while all eleven
v3 pins remain. The helper is removed before offline replacement and is not part
of the production kustomization.

The DaemonSet attaches ingress classification to every non-loopback node interface
and discovers newly created pod veths. A packet can therefore produce multiple
interface-level events. Logical-key aggregation is implemented, but cross-interface
deduplication and durable history remain later telemetry work.

## Fedora, RHEL, and OpenShift

Do not assume Ubuntu paths or AppArmor. `make openshift-test` now provides
separate RHEL CoreOS/CRI-O IPv4-only and dual-stack evidence for SELinux, SCC,
BTF, bpffs, Service CA, TokenReview, native legacy attachment, and enforcement.
The dual-stack gate includes the complete ingress and egress matrices. SCTP must
be available and loaded on every selected worker; the gate checks `/proc/modules`
up front and reports the affected Node. On RHCOS where the shipped module is not
loaded yet, an authorized administrator can load it with `modprobe sctp` from the
host environment (for example through an approved node-debug workflow).
Agents use a non-privileged, runtime-default-seccomp, read-only-root profile with
only `BPF`, `NET_ADMIN`, and `PERFMON`; their service account cannot use the
built-in privileged SCC. Native validating admission additionally restricts that
service account to the exact writable `/sys/fs/bpf` and read-only
`/sys/kernel/btf` mounts and rejects host-volume access from sidecars, init
containers, or ephemeral containers. The kind gate remains separate
dual-stack/TCX evidence; broader versions, scale, and upgrade behavior are not
inferred from these fixtures.
