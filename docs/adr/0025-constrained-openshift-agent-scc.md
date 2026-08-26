# ADR 0025: Constrained OpenShift agent SCC

Status: Accepted and live verified on IPv4-only and dual-stack OpenShift 4.22

## Context

The portable DaemonSet originally used a privileged container, and the first
OpenShift overlay granted its service account the built-in `privileged` SCC.
That proved kernel and SELinux compatibility but also granted every Linux
capability, unrestricted seccomp, host PID/IPC eligibility, arbitrary volume
types, and privileged-container admission. The agent actually needs a much
smaller boundary to load and attach its TC program and preserve pinned state.

## Decision

OpenShift installs a dedicated `unf-agent` SCC plus an exact `use` ClusterRole
and service-account binding. The SCC:

- allows host networking and host ports, because the host-network agent exposes
  its health port;
- allows only `configMap`, `projected`, and `hostPath` volume classes;
- forbids privileged containers, host PID/IPC, and privilege escalation;
- requires a read-only container root filesystem and runtime-default seccomp;
- drops `ALL` capabilities, then permits only `BPF`, `NET_ADMIN`, and `PERFMON`;
  and
- permits the explicit root UID/GID and `spc_t` SELinux type required to manage
  the root-owned `bpf_t` bpffs state and host TC attachments.

The workload manifest mounts only `/sys/fs/bpf` read/write and
`/sys/kernel/btf` read-only. The SCC API cannot constrain `hostPath` prefixes,
so ADR 0028 adds a native path-specific admission boundary around those exact
volumes and mount modes.

The deployment migration applies the new SCC/RBAC before changing workloads. It
removes the old
`unf-agent-scc` binding only after confirming that its immutable role reference
is exactly `system:openshift:scc:privileged`; any unexpected binding is refused.

## Verification

The OpenShift gate requires the service account to be authorized for `unf-agent`
and unauthorized for `privileged`. It validates the complete SCC, Pod security
context, SCC annotation, UID/GID, SELinux domain, `NoNewPrivs`, seccomp mode, and
the exact effective capability mask `000000c000001000` on every worker.

Capability reduction was measured on RHCOS 9.8 Linux 5.14. `SYS_RESOURCE` was
removed successfully. Removing `PERFMON` made the kernel apply unprivileged BPF
verifier rules and reject the current ring-buffer pointer arithmetic, so it is
retained. Disabling host-port permission caused SCC admission to reject port 9963
under host networking, so that permission is also retained.

Both the IPv4-only and dual-stack OpenShift gates then passed agent restart,
pinned-state adoption, native legacy-filter presence, Service CA and TokenReview
transport, selected-worker convergence, cross-worker allow/drop enforcement,
retained provenance, and cluster-operator health.

## Consequences

The OpenShift agent is no longer a privileged container and its service account
cannot request the built-in privileged SCC. Root, `spc_t`, host networking,
host-port admission, and hostPath volume permission remain powerful but explicit
requirements. ADR 0028 now constrains the exact host paths and mount semantics;
ADR 0029 uses the same boundary for per-node uninstall Jobs before removing the
SCC. Broader OpenShift/kernel versions remain separate portability work.

The portable Kubernetes manifest remains privileged because upstream Kubernetes
does not provide SCC. Installers for other platforms must supply an equivalent
policy rather than infer the OpenShift SCC contract.
