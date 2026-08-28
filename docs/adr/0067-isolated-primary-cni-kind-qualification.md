# ADR 0067: Isolated primary-CNI Kind installation and rollback are qualified

Status: Accepted and Verified for the disposable Kind fixture

## Context

ADRs 0057–0066 established explicit primary-CNI ownership, durable local
transactions, dual-stack node-block IPAM, veth and endpoint routing, remote route
distribution, and last-known-good reconciliation. None of those gates installed
UNF as a cluster's only CNI. Qualification had to preserve the existing overlay
fixture, avoid an in-place takeover, exercise two real worker nodes, and prove a
reviewable rollback before any OpenShift installation design could begin.

The first live CHECK also exposed a runtime normalization boundary: containerd
omits an empty `dns: {}` object when it caches ADD output. The kernel and durable
attachment matched, but byte-semantic JSON comparison rejected the valid cached
result.

## Decision

Primary-CNI qualification uses a separate `unf-cni-dev` Kubernetes 1.35 Kind
cluster with one control-plane, two workers, dual-stack PodCIDRs and InternalIPs,
and `disableDefaultCNI: true`. The ordinary deployment remains overlay-only.
The dedicated Kustomize overlay:

- bootstraps the controller and CoreDNS on host networking during the no-CNI
  window and saves the exact original CoreDNS Pod template for rollback;
- labels only fixture Nodes for primary ownership and runs the privileged agent
  with host PID, netns, socket, state, CNI binary/configuration, bpffs and BTF
  boundaries;
- installs `/opt/cni/bin/unf` and `10-unf.conflist` atomically, stores mode-0600
  SHA-256 ownership metadata, and refuses foreign configurations, unowned paths,
  symlinks, malformed markers, or fingerprint drift; and
- selects explicit IPv4 and IPv6 `eth0` native uplinks while keeping the base
  Kubernetes/OpenShift manifests unchanged.

CHECK now canonicalizes only the runtime-equivalent omission of an empty DNS
object. It continues to compare every interface, address, route, gateway,
namespace, MTU, and durable/kernel attachment result exactly.

Rollback first removes ordinary Pods so kubelet can issue DEL while the local
socket exists. It refuses non-empty journals, stops reconcilers, runs the
product's scoped current-ABI BPF/TC cleanup once per Node, and validates every
protocol-196 route against the durable remote snapshot before exact deletion.
Installer fingerprints are revalidated before removing the exact binary,
configuration, socket and known state files. The saved CoreDNS template and
local-path replica count are restored; Nodes return to the expected no-CNI
NotReady baseline. Unknown host state causes refusal instead of broad deletion.

## Verification

`make primary-cni-kind-test` passed from the rebuilt image and produced
schema-v1 evidence at `.artifacts/phase3-primary-cni-kind.json`. The gate proves:

1. exclusive fingerprinted installation and three-Node route convergence;
2. dual-stack ADD and containerd-normalized CHECK on both worker Nodes;
3. direct cross-worker IPv4 and IPv6 HTTP forwarding plus A/AAAA Service
   discovery;
4. uninterrupted direct forwarding while the controller is absent and the
   server-side agent restarts from durable node-block and route snapshots;
5. fail-closed foreign-CNI detection followed by exact recovery;
6. DEL, lease return, exact veth removal, and baseline attachment counts; and
7. scoped BPF/TC cleanup, snapshot-exact remote-route deletion, fingerprinted
   artifact removal, CoreDNS restoration, and no-CNI baseline recovery.

The preflight records the host requirement for at least 512 inotify instances;
the observed workstation default of 128 could not bootstrap three Kind nodes.
The existing `unf-dev` overlay fixture remained Ready throughout qualification.

## Consequences and limits

Milestone 6.6d is Verified, while aggregate node networking remains In progress
until 6.6e. This result is bounded to the pinned Kind/Kubernetes tuple and native
two-worker routing. Explicit IPv6 Service ClusterIP forwarding is not claimed;
service load balancing and kube-proxy replacement remain later milestones.

No OpenShift CNI replacement is authorized by this ADR. An OpenShift-specific
Network Operator/MachineConfig installation, drain, recovery, rollback and
SELinux design must be accepted before bounded dual-stack cl02 qualification.
