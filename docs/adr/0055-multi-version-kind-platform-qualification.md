# ADR 0055: Multi-version Kubernetes support requires an isolated full Kind gate

Status: Accepted and live verified on Kubernetes 1.34.8 and 1.35.0

## Context

The existing Kind evidence qualified one Kubernetes release. The OpenShift rows
exercise Kubernetes 1.35 as shipped by OpenShift, but they do not establish a
second upstream Kubernetes/Kind tuple or TCX behavior on another Kind node
image. Claiming broader platform/version coverage therefore required one more
exact, independently exercised release rather than inferring compatibility from
an adjacent version.

The qualification also needed to preserve the developer's existing `unf-dev`
cluster and host settings, retain unsuccessful attempts, and bind every result
to a clean committed revision.

## Decision

`make kind-platform-matrix-test` creates a dedicated two-node cluster named with
the `unf-matrix-` prefix. Its Kubernetes 1.34 fixture pins the Kind v0.32.0 node
image published for Kubernetes 1.34.8:

`kindest/node:v1.34.8@sha256:02722c2dedddcfc00febf5d27fbeb9b7b2c14294c82109ff4a85d89ac9ba3256`.

The wrapper rejects a dirty tree or an existing cluster with the same name. It
records the exact Git revision and node environment, gives the isolated nodes
stable placement labels without changing their real identities, and runs:

1. the complete dual-stack Kind endpoint suite, including upstream-aligned
   ingress, source-side egress, simulation, topology/history, authenticated
   export, persistence, fault injection, TCX, and legacy-netlink recovery; and
2. the adjacent committed-revision controller/agent upgrade, mixed rollout,
   rollback, and forward-recovery gate on the same Kubernetes release.

The host's inotify instance limit is a bounded prerequisite. When its original
value is below 512, the wrapper temporarily raises only
`fs.inotify.max_user_instances`, records both values, and restores the original
value in its exit trap. The same trap removes only the dedicated matrix cluster.
The latest result and append-only attempt history are written under
`.artifacts/`; a retry never replaces prior failure evidence.

Support remains row-specific. A pass adds the exact platform, Kubernetes, OS,
kernel, architecture, runtime, CNI, address-family, attachment, and evidence
tuple to `docs/development/support-matrix.json`. It does not qualify adjacent
releases, other kernels, architectures, CNIs, or larger cluster shapes.

## Evidence

On 2026-08-27, `make kind-platform-matrix-test` passed from clean revision
`da733591b23618bff1001769ae02d30dc1c3e2ce`. The run started at 20:05:36 UTC
and completed at 20:41:13 UTC. Its environment was:

- Kubernetes 1.34.8 on Kind v0.32.0;
- two amd64 Debian GNU/Linux 13 (trixie) nodes;
- host kernel `7.1.4-204.fc44.x86_64`;
- containerd 2.3.1;
- kindnetd `v20260528-9350166c`;
- IPv4 Pod CIDRs `10.244.0.0/24` and `10.244.1.0/24`;
- IPv6 Pod CIDRs `fd00:10:244::/64` and `fd00:10:244:1::/64`; and
- both `tcx_pinned` and `legacy_netlink` attachment modes.

The endpoint gate passed the complete dual-stack ingress and egress matrices,
including the namespace-wide default-deny target exceptions and homogeneous
PodSelector peer OR cases. It also passed transactional BPF fault rollback,
map-pressure recovery, controller-offline pinned-state agent recovery, durable
topology and exact-key flow-history restore, external export pressure/recovery,
and TCX/legacy attachment handoff.

The transition gate used N=`a36c9594b947ad785d191cf00aba81ee02a39663`
and N+1=`da733591b23618bff1001769ae02d30dc1c3e2ce` at commit distance one. It
passed N/N, controller-first N+1/N, deterministic one-agent mixed rollout, full
N+1, agent rollback/forward recovery, controller rollback with N+1 agents, and
final N+1 convergence with uninterrupted allow/deny enforcement and telemetry.

The result recorded all endpoint, attachment, and upgrade gates as true. The
dedicated cluster was removed, the pre-existing `unf-dev` cluster remained, and
the inotify limit was restored from the qualification value 512 to its original
value 128.

The append-only history retains six unsuccessful attempts before the pass:

- `edd8341` exposed host inotify exhaustion during cluster creation;
- `b693a49` exposed hard-coded development-node placement in the endpoint
  fixtures;
- `0239079` proved that the isolated policy restoration needed a longer bounded
  convergence window than 30 seconds;
- `c3e15da` reached full ingress and egress but exposed stale fault-fixture paths
  that did not name the current v3 BPF ABI directory;
- `aaeacb4` passed the principal endpoint gate but the separate flow-history
  helper failed without actionable stage diagnostics; and
- `a36c959` localized the remaining failure to a post-restart comparison that
  matched only identities and port, allowing distinct high-volume flow keys to
  be compared after hash-map order changed.

The final revision retains bounded retry behavior, exact failing-stage
diagnostics, and complete-key flow matching. Failed attempts are diagnostic
history and do not count as support evidence.

## Consequences

The support matrix now contains independently qualified upstream Kubernetes
1.34.8 and 1.35.0 Kind rows, so the Phase 3 broader platform/version milestone
is Verified. Both rows remain exact, non-transitive claims.

The additional release does not broaden OpenShift support beyond 4.22.9, does
not qualify a second host kernel or architecture, and does not cover CNIs other
than the exact kindnetd and OVN-Kubernetes rows. Production image publication,
signatures, attestations, larger clusters, and mixed-platform fleets remain
explicitly outside this qualification.
