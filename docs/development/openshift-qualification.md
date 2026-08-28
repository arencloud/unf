# OpenShift qualification

The OpenShift overlay extends the portable Kubernetes manifests without changing
their certificate contract. It is a development and qualification path, not a
production installer.

## Certificate modes

UNF supports both deployment models through the same runtime paths:

- Kubernetes and external-PKI installations provide Secret `unf-internal-tls`
  with `tls.crt`/`tls.key` and ConfigMap `unf-internal-ca` with `ca.crt`.
- The OpenShift overlay annotates the controller Service for a serving
  certificate and injects the Service CA bundle into `unf-internal-ca`. The
  agent maps the injected `service-ca.crt` key to its portable `ca.crt` path.

The controller and agent do not contain OpenShift-specific certificate code.
The controller polls the mounted serving certificate/key and atomically swaps a
validated Rustls configuration. Agents compare CA-bundle contents before every
internal request and replace their CA-only client when valid content changes.
Malformed or incomplete updates are rejected while the last-known-good serving
or trust configuration remains active.

## Development images and credentials

The checked-in overlay uses these mutable development references:

```text
quay.io/arencloud/unf-controller-dev:dev
quay.io/arencloud/unf-agent-dev:dev
quay.io/arencloud/unf-test-tools-dev:dev
```

Authenticate only before publishing images, without placing credentials in the
repository:

```bash
mkdir -p .tools
chmod 700 .tools
podman login --authfile .tools/quay-auth.json quay.io
chmod 600 .tools/quay-auth.json
```

Use an ignored, permission-restricted kubeconfig. A trusted cluster CA is
preferred; insecure API TLS is acceptable only for an explicitly designated lab:

```bash
chmod 600 .tools/cl01-audit.kubeconfig
chmod 600 .tools/cl02-audit.kubeconfig
```

The Quay robot credential is used only by image publication targets. All three
development repositories are public, so deploy and qualification workflows pull
anonymously and create no Quay pull Secret. Robot credentials and projected Pod
tokens are never rendered or logged.

## Deploy and verify

```bash
make openshift-images
make openshift-deploy
make openshift-test
make openshift-upgrade-images UNF_OPENSHIFT_UPGRADE_BASELINE_REF=<committed-N>
make openshift-upgrade-test
make openshift-tls-rotation-test
make openshift-agent-report-retention-test
make openshift-host-mount-policy-test
make openshift-uninstall
make openshift-uninstall-test
```

Select a non-default qualification cluster explicitly:

```bash
OPENSHIFT_KUBECONFIG="$PWD/.tools/cl02-audit.kubeconfig" make openshift-deploy
OPENSHIFT_KUBECONFIG="$PWD/.tools/cl02-audit.kubeconfig" make openshift-test
OPENSHIFT_KUBECONFIG="$PWD/.tools/cl02-audit.kubeconfig" make openshift-upgrade-test
OPENSHIFT_KUBECONFIG="$PWD/.tools/cl02-audit.kubeconfig" make openshift-tls-rotation-test
OPENSHIFT_KUBECONFIG="$PWD/.tools/cl02-audit.kubeconfig" make openshift-agent-report-retention-test
OPENSHIFT_KUBECONFIG="$PWD/.tools/cl02-audit.kubeconfig" make openshift-host-mount-policy-test
OPENSHIFT_KUBECONFIG="$PWD/.tools/cl02-audit.kubeconfig" make openshift-uninstall
OPENSHIFT_KUBECONFIG="$PWD/.tools/cl02-audit.kubeconfig" make openshift-uninstall-test
```

Override `OPENSHIFT_KUBECONFIG` when qualifying another environment.
`QUAY_AUTH_FILE` is required only by `openshift-images` and
`openshift-upgrade-images`. The image publishing variables may also be
overridden, but a different repository or tag must be reflected in the overlay
before deployment. `openshift-deploy` applies the CRD, RBAC, `unf-system`
workloads, and Service CA objects, then rolls both components so mutable
development tags are picked up. Certificate changes after startup do not
require that rollout.

The overlay:

- schedules agents only on Nodes carrying `node-role.kubernetes.io/worker`;
- configures controller convergence with the same exact Node-label selector;
- grants the agent service account only the dedicated `unf-agent` SCC, not the
  built-in privileged SCC;
- installs fail-closed native admission for the exact bpffs/BTF source paths,
  mount modes, and container ownership;
- runs the agent as a non-privileged root process in `spc_t`, with runtime-default
  seccomp, `NoNewPrivs`, a read-only root filesystem, and only `BPF`,
  `NET_ADMIN`, and `PERFMON`;
- lets `restricted-v2` assign the controller UID, GID, fsGroup, and SELinux
  context; and
- uses the OpenShift Service CA instead of the disposable kind CA.

`make openshift-test` detects IPv4 and IPv6 cluster CIDRs, creates two exact
temporary qualification Namespaces, and removes them on success or failure. It
requires IPv4 plus at least two Ready workers; when IPv6 is configured, every
IPv6 assertion becomes mandatory rather than optional. The gate proves:

- restricted controller and dedicated constrained worker-agent SCC admission;
- exact SCC/RBAC, Pod security context, effective capability mask, seccomp,
  `NoNewPrivs`, UID/GID, and SELinux-domain assertions on every worker;
- enforcing host SELinux, readable BTF, bpffs, cgroup v2, and the reserved
  legacy netlink filter on every worker;
- Service CA certificate validity and DNS identity;
- plaintext route isolation, CA-only trust, missing/invalid credential rejection,
  a real projected-token snapshot, and cross-Node claim rejection;
- freshness-aware convergence for exactly the selected workers;
- cross-worker IPv4 TCP allow/drop with policy provenance and retained history;
- on dual-stack clusters, dual-family Pod addresses, identity maps, authenticated
  snapshots, IPv6 allow/drop, and retained IPv6 policy provenance; and
- healthy OpenShift cluster operators before and after the gate.

The same adaptive command is live-verified against separate IPv4-only and
dual-stack OpenShift 4.22/RHCOS 9.8 clusters. One family does not silently satisfy
the other: IPv4 is always required and a configured IPv6 cluster CIDR requires
IPv6 Pod assignment, state distribution, enforcement, and history evidence.

`make openshift-tls-rotation-test` is a disruptive-but-reversible lab gate for
the `unf-system` certificate objects. It records the original OpenShift-managed
keypair and CA, transitions through an overlapping external CA, switches the
serving leaf, contracts trust, injects malformed CA and leaf updates, and then
restores Service CA ownership. It requires authenticated traffic under the new
issuer, last-known-good continuity, agent convergence, reload/error metrics,
exact projected bundles, unchanged Pod UIDs, and a final platform-issued chain.
An exit trap restores the original certificate contract on failure.

`make openshift-agent-report-retention-test` verifies the controller service
account can get/patch the exact `unf-agent-acknowledgements` ConfigMap but cannot
create or delete ConfigMaps, waits for one validated report per selected worker,
replaces only the controller, and
requires the new process to expose the exact restored count. It then requires a
new controller epoch to converge, the checkpoint receive time to advance, zero
persistence errors, and unchanged agent Pod UIDs and restart counts.

`make openshift-host-mount-policy-test` verifies both native policies and their
deny bindings are type-checked and active. It admits the current DaemonSet and an
unrelated Pod, then uses non-mutating server dry runs to reject alternate paths,
service-account replacement, host-path creation, incorrect read/write modes,
subPath, mount propagation, sidecar/init, direct-agent-Pod, and
ephemeral-container host-volume access.

`make openshift-test` invokes this gate before its dataplane qualification.

## Digest-pinned upgrade qualification

The upgrade gate is separate from the mutable `:dev` deployment workflow. Run
it only from a clean committed revision. First publish controller, agent, and
test-tool images for an ancestor N and the current N+1 revision:

```bash
make openshift-upgrade-images \
  UNF_OPENSHIFT_UPGRADE_BASELINE_REF=<committed-N>
```

The publisher uses unique revision tags but resolves and records immutable
repository digests in
`.artifacts/phase3-openshift-upgrade-images.json`. The record includes both
full Git revisions and their commit distance. The transition gate rejects a
dirty tree, a record that does not name the current revision, a non-ancestor N,
or an image that is not addressed by digest.

Qualify the recorded pair against an explicitly selected lab cluster:

```bash
make openshift-upgrade-test \
  OPENSHIFT_KUBECONFIG="$PWD/.tools/cl02-audit.kubeconfig"
```

The gate runs the full adaptive endpoint suite at N and N+1. Between those
endpoints it proves controller-first compatibility, one-worker-at-a-time agent
rollout, complete agent/controller rollback, and controller-first plus
worker-serial recovery. Every transition checks exact revisions, authenticated
convergence, compatibility tuples, dual-stack policy enforcement and
provenance, advancing telemetry, platform security invariants, and cluster
operator health.

Direct stage assertions are strict. The background continuity monitor fails
immediately if a denied flow succeeds and reports an allowed-flow breach after
three consecutive one-second failures, so an isolated transport loss is
retained as diagnostic noise rather than misclassified as a sustained
dataplane gap. Its diagnostics include UTC time and the probed address.

The latest result is written to
`.artifacts/phase3-openshift-upgrade-result.json`; every attempt is appended to
`.artifacts/phase3-openshift-upgrade-attempts.jsonl`. A failure trap removes
qualification fixtures and restores the recorded N+1 Deployment and rolling
DaemonSet. These local artifacts contain no registry credential, kubeadmin
password, projected token, or kubeconfig content. ADR 0054 records the exact
live-verified cl02 window and the non-transitive support boundary.

`make openshift-uninstall` is always a non-mutating plan unless explicit
execution arguments are supplied. It inventories all Ready agents, runs the
ownership-checked current-ABI/legacy cleanup planner on each node, and reports
the host plus resource disposition. Execution requires `--execute` and the exact
current context. Agents stop before constrained cleanup Jobs run; hosts must be
free of v2 pins and UNF ingress/egress filters before namespaced, admission, SCC,
and RBAC resources are removed. Namespace and CRD deletion are separate flags;
the CRD is preserved by default and existing custom resources add another
data-loss confirmation.

An execution failure after agent shutdown leaves the cleanup Jobs and remaining
authority in place for inspection; it does not silently restart enforcement
against partially cleaned state. Repair the reported node or ownership issue and
rerun the reviewed plan. The self-restoring qualification wrapper is a lab gate,
not the production failure policy.

`make openshift-uninstall-test` is destructive but self-restoring. It proves
dry-run non-mutation and wrong-context refusal, removes the dedicated Namespace
and exact cluster resources only after two-node host cleanup, preserves the CRD
UID, redeploys, and runs the complete dual-stack qualification. Once destructive
execution starts, its exit trap attempts redeployment after any failure.

## Operational boundary

The agent attaches to every non-loopback worker interface, including OVN and
workload interfaces, and persistent legacy filters survive Pod deletion by
design. Do not remove the DaemonSet as an uninstall procedure; use the
dry-run-first coordinated uninstall so every agent stops before per-node cleanup
and host verification.

The SCC still permits root, `spc_t`, host networking/ports, and the `hostPath`
volume class. Its RBAC is limited to the agent service account; ADR 0028's native
admission policy closes SCC's path-prefix gap for the exact bpffs/BTF contract.
Immutable digest-pinned release images and issuer-specific production automation
remain production-hardening requirements.

The report checkpoint is deliberately single-controller and is not an HA
database. See [ADR 0025](../adr/0025-constrained-openshift-agent-scc.md),
[ADR 0026](../adr/0026-hot-certificate-and-trust-rotation.md),
[ADR 0027](../adr/0027-durable-agent-acknowledgement-checkpoint.md),
[ADR 0028](../adr/0028-path-specific-openshift-host-mount-admission.md), and
[ADR 0029](../adr/0029-coordinated-openshift-uninstall.md). Digest-pinned
version-transition qualification is specified by
[ADR 0054](../adr/0054-digest-pinned-openshift-upgrade-qualification.md).
