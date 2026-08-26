# ADR 0028: Path-specific OpenShift host-mount admission

Status: Accepted and live verified on dual-stack OpenShift 4.22

## Context

ADR 0025 replaced the built-in privileged SCC with a dedicated, constrained
agent SCC. OpenShift SCC can allow or deny the `hostPath` volume class, but it
cannot restrict allowed source paths. A user able to alter or create an agent
workload could therefore request another host directory while still satisfying
the SCC. The agent needs only writable bpffs state at `/sys/fs/bpf` and read-only
kernel BTF metadata at `/sys/kernel/btf`.

This boundary must fail before an unsafe DaemonSet rollout, protect direct Pod
creation and ephemeral-container updates, and avoid an external admission
controller dependency.

## Decision

The OpenShift overlay installs two stable Kubernetes
`ValidatingAdmissionPolicy` resources and fail-closed `Deny` bindings. Both are
limited by the `unf-system` Namespace label. The Pod policy selects the
`unf-agent` service account. The DaemonSet policy selects either that service
account or the exact `unf-agent` name, preventing a single update from escaping
validation by replacing its service account:

- the DaemonSet policy validates `apps/v1` create and update requests so an
  invalid template is rejected before the controller replaces healthy agents;
  the named DaemonSet must retain the `unf-agent` service account;
- the Pod policy validates Pod create/update and `pods/ephemeralcontainers`
  updates, covering controller-generated Pods, direct Pods, and debug-container
  injection.

Both policies require exactly two `hostPath` volumes:

- `bpffs` must be an existing `Directory` at `/sys/fs/bpf`;
- `btf` must be an existing `Directory` at `/sys/kernel/btf`.

The container named `agent` must mount bpffs read/write at `/sys/fs/bpf` and BTF
read-only at `/sys/kernel/btf`. Subpaths, subpath expressions, and mount
propagation are rejected. Sidecars, init containers, and ephemeral containers
cannot mount either host volume. The policy is deliberately scoped by workload
identity; unrelated workloads are not forced to adopt the UNF mount contract.

The admission policies complement rather than replace SCC. SCC continues to
control host-volume eligibility, capabilities, privilege, SELinux, seccomp,
UID/GID, host networking, and host ports. Admission validates only the source and
mount contract that SCC cannot express.

## Verification

`make openshift-host-mount-policy-test` requires both policies to be observed
without type-check warnings and both bindings to use `Deny`. Server dry runs must
admit the deployed DaemonSet and an unrelated Pod, while rejecting:

- `/etc` in place of bpffs;
- replacement of the named DaemonSet's service account;
- `DirectoryOrCreate` in place of an existing BTF directory;
- a writable BTF mount;
- a read-only bpffs mount;
- a bpffs `subPath`;
- bpffs mount propagation;
- a sidecar mounting BTF;
- an init container mounting BTF;
- a direct `unf-agent` Pod with an alternate host path; and
- an ephemeral container mounting BTF.

The gate also checks every live agent Pod has exactly the admitted paths and
mount modes. The full `make openshift-test` gate invokes this qualification
before its SCC, SELinux, transport, convergence, dual-stack enforcement,
provenance, and cluster-operator assertions.

## Consequences

An SCC-authorized agent workload can no longer broaden its host filesystem view
without a cluster administrator changing or removing the admission policy. A bad
DaemonSet update is rejected without disrupting running agents, and debug
containers cannot inherit the admitted host volumes.

The policy uses the cluster-scoped `admissionregistration.k8s.io/v1` API and is
live-qualified on OpenShift 4.22 / Kubernetes 1.35. Installers targeting clusters
without stable `ValidatingAdmissionPolicy` must provide an equivalent fail-closed
path policy. Cluster administrators remain capable of changing this boundary;
immutable release images and coordinated host-state cleanup/uninstall remain
separate work.
