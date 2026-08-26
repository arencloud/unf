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

Authenticate without placing credentials in the repository:

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

The deploy workflow creates only a namespaced pull Secret from the dedicated
auth file. Robot credentials and projected Pod tokens are never rendered or
logged.

## Deploy and verify

```bash
make openshift-images
make openshift-deploy
make openshift-test
make openshift-tls-rotation-test
make openshift-agent-report-retention-test
```

Select a non-default qualification cluster explicitly:

```bash
OPENSHIFT_KUBECONFIG="$PWD/.tools/cl02-audit.kubeconfig" make openshift-deploy
OPENSHIFT_KUBECONFIG="$PWD/.tools/cl02-audit.kubeconfig" make openshift-test
OPENSHIFT_KUBECONFIG="$PWD/.tools/cl02-audit.kubeconfig" make openshift-tls-rotation-test
OPENSHIFT_KUBECONFIG="$PWD/.tools/cl02-audit.kubeconfig" make openshift-agent-report-retention-test
```

Override `OPENSHIFT_KUBECONFIG` or `QUAY_AUTH_FILE` when qualifying another
environment. The image publishing variables may also be overridden, but a
different repository or tag must be reflected in the overlay before deployment.
`openshift-deploy` applies the CRD, RBAC, `unf-system` workloads, Service CA
objects, and pull Secret, then rolls both components so mutable development tags
are picked up. Certificate changes after startup do not require that rollout.

The overlay:

- schedules agents only on Nodes carrying `node-role.kubernetes.io/worker`;
- configures controller convergence with the same exact Node-label selector;
- grants the agent service account only the dedicated `unf-agent` SCC, not the
  built-in privileged SCC;
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
account can only get/patch the exact `unf-agent-acknowledgements` ConfigMap, waits
for one validated report per selected worker, replaces only the controller, and
requires the new process to expose the exact restored count. It then requires a
new controller epoch to converge, the checkpoint receive time to advance, zero
persistence errors, and unchanged agent Pod UIDs and restart counts.

## Operational boundary

The agent attaches to every non-loopback worker interface, including OVN and
workload interfaces, and persistent legacy filters survive Pod deletion by
design. Do not remove the DaemonSet as an uninstall procedure. A coordinated
uninstall must first use the agent's dry-run-first cleanup command and verify the
exact owned filters and bpffs paths before deleting workloads.

The SCC still permits root, `spc_t`, host networking/ports, and the `hostPath`
volume class. Its RBAC is limited to the agent service account and the workload
mounts only `/sys/fs/bpf` plus read-only `/sys/kernel/btf`, but SCC itself cannot
restrict hostPath prefixes. Admission policy for those exact paths, immutable
digest-pinned release images, issuer-specific production automation, and complete
uninstall orchestration remain production-hardening requirements. The report
checkpoint is deliberately single-controller and is not an HA database. See
[ADR 0025](../adr/0025-constrained-openshift-agent-scc.md) and
[ADR 0026](../adr/0026-hot-certificate-and-trust-rotation.md), and
[ADR 0027](../adr/0027-durable-agent-acknowledgement-checkpoint.md).
