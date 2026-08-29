# ADR 0073: OpenShift primary-CNI node teardown and reprovision

Status: Accepted, implemented, and live verified on cl02

## Context

The five-Node OpenShift primary-CNI checkpoint had already passed bootstrap,
traffic, controller and agent recovery, CNI 1.1 reconciliation, clean reboot,
and deliberate CRI-O transaction failure. Its final lifecycle gap was exact
teardown to a no-CNI baseline followed by clean bootstrap from that baseline.

A whole-cluster uninstall would unnecessarily remove a working lab control
plane. Ordinary `oc adm drain` is also insufficient because OpenShift retains
networked DaemonSet Pods. Removing the agent first would lose their final DEL
transactions. Qualification therefore needs a worker-scoped maintenance order
that preserves CRI-O cleanup before removing local ownership.

## Decision

`make openshift-primary-cni-node-reprovision-test` is the guarded destructive
gate. It requires a mode-0600 kubeconfig, an exact worker, pinned SSH known
hosts, exact context/Node confirmation, and an acknowledgement matching the
OpenShift infrastructure name. It refuses control-plane Nodes, non-`None`
network ownership, an unhealthy platform, a non-converged baseline, foreign
fixture state, or unequal Pod/attachment/cache/link ownership.

The gate cordons and drains the selected worker, stops kubelet to freeze
DaemonSet replay, and removes the Node from agent scheduling while retaining
its durable controller assignment. It enumerates only CRI-O caches owned by
`unf-primary`, stops those exact sandboxes while the agent socket remains live,
and requires zero attachments, caches, links, and deferred deletes. It then
uses the product cleanup command to remove the exact current-ABI BPF maps and
UNF filters, stops the host-network agent, validates every persisted remote
route against its last-known-good document, and removes only matching routes.

Fingerprint validation precedes removal of the installed CNI binary and
configuration. Only the exact owner marker, attachment, Node-block,
remote-route, queue-lock, and socket state is removed. Kubelet is restarted
with the Node still cordoned and unselected. Empty `DirectoryOrCreate` roots
replayed from the terminating DaemonSet are accepted only when verified empty
and then removed.

The no-CNI checkpoint requires zero artifacts, routes, maps, CNI configs, and
runtime ownership. A restricted Pod pinned directly to the Node must remain
Pending without a container ID, and its event must report
`FailedCreatePodSandBox` caused by missing CNI configuration. Reprovision then
restores the selection label. The existing host-network agent and installer
must recreate the socket, fingerprints, CNI configuration, durable state, BPF
maps, and routes from zero before the Node is uncordoned. The gate requires
exact workload/state cardinality, five-agent convergence, kubelet and DNS
health, platform health, and cross-worker IPv4/IPv6 HTTPS before success.

The exit trap restores the label, kubelet, scheduling, and fixture cleanup on
every failure path. It cannot broaden deletion beyond the validated worker and
recognized UNF ownership.

## Verification

The final cl02 run targeted worker `bc-24-11-74-2b-8d`. Its schema-v1 evidence
records attachment/cache/link/pending/map/IPv4-route/IPv6-route as:

- baseline: `9/9/9/0/11/13/13`;
- no CNI: `0/0/0/0/0/0/0`; and
- recovered: `9/9/9/0/11/13/13`.

The no-CNI probe remained `ContainerCreating` with no address or container ID.
CRI-O reported that no CNI configuration existed. Reprovision created new agent
Pod `unf-agent-frd2f` with both containers Ready and zero restarts. All five
agents became fresh and exactly converged, the target kubelet and DNS paths
passed, 34 operators other than the retained external Insights condition were
healthy, and direct cross-worker canary HTTPS returned 200 over IPv4 and IPv6.

Two rejected attempts remain part of the evidence. The first expected the
controller to reduce its durable assignment from five to four during
maintenance; live status correctly retained five expected agents, marked the
target stale, and kept the other four converged. The second required an absent
`containerStatuses` array even though OpenShift truthfully published a waiting
entry without a container ID. Both attempts invoked the recovery trap and
returned the Node to Ready, schedulable, five-agent convergence before the next
run. The final gate codifies both platform behaviors.

Static and package verification include syntax validation of the destructive
gate. Runtime evidence is written to
`.artifacts/phase3-openshift-primary-cni-node-reprovision.json`.

## Consequences

UNF now has repeatable proof that one RHCOS worker can reach a genuine no-CNI
state and bootstrap the same digest-pinned primary-CNI package from zero without
reinstalling OpenShift or disrupting the remaining control plane. This is
qualification of the exact recorded cl02 tuple, not a claim for arbitrary
OpenShift releases, kernels, architectures, cluster sizes, or production image
repositories.

The controller deliberately retains the unavailable Node as expected during
maintenance. Status therefore exposes the outage instead of silently shrinking
the desired topology. The remaining agents must stay converged until the target
returns.
