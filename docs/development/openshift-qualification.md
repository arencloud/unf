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
Certificates are still loaded at process startup, so rotation requires a
controller rollout and, when trust changes, an agent rollout.

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
```

The deploy workflow creates only a namespaced pull Secret from the dedicated
auth file. Robot credentials and projected Pod tokens are never rendered or
logged.

## Deploy and verify

```bash
make openshift-images
make openshift-deploy
make openshift-test
```

Override `OPENSHIFT_KUBECONFIG` or `QUAY_AUTH_FILE` when qualifying another
environment. The image publishing variables may also be overridden, but a
different repository or tag must be reflected in the overlay before deployment.
`openshift-deploy` applies the CRD, RBAC, `unf-system` workloads, Service CA
objects, and pull Secret, then rolls both components so mutable development tags
and certificate changes are picked up.

The overlay:

- schedules agents only on Nodes carrying `node-role.kubernetes.io/worker`;
- configures controller convergence with the same exact Node-label selector;
- grants the agent service account the built-in privileged SCC for this
  development gate;
- lets `restricted-v2` assign the controller UID, GID, fsGroup, and SELinux
  context; and
- uses the OpenShift Service CA instead of the disposable kind CA.

`make openshift-test` creates two exact temporary qualification Namespaces and
removes them on success or failure. It requires at least two Ready workers and
proves:

- restricted controller and privileged worker-agent SCC admission;
- enforcing host SELinux, readable BTF, bpffs, cgroup v2, and the reserved
  legacy netlink filter on every worker;
- Service CA certificate validity and DNS identity;
- plaintext route isolation, CA-only trust, missing/invalid credential rejection,
  a real projected-token snapshot, and cross-Node claim rejection;
- freshness-aware convergence for exactly the selected workers;
- cross-worker IPv4 TCP allow/drop with policy provenance and retained history;
  and
- healthy OpenShift cluster operators before and after the gate.

The IPv4 gate does not claim OpenShift IPv6 compatibility. Run a separate
dual-stack qualification before making that claim.

## Operational boundary

The agent attaches to every non-loopback worker interface, including OVN and
workload interfaces, and persistent legacy filters survive Pod deletion by
design. Do not remove the DaemonSet as an uninstall procedure. A coordinated
uninstall must first use the agent's dry-run-first cleanup command and verify the
exact owned filters and bpffs paths before deleting workloads.

The built-in privileged SCC is intentionally limited to the lab qualification
overlay. A narrower custom SCC/capability profile, immutable digest-pinned release
images, automated certificate rotation, and complete uninstall orchestration
remain production-hardening requirements.
