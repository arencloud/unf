# OpenShift cl02 primary-CNI installation checkpoint

Date: **2026-08-29**

This record captures the first completed Agent-based OpenShift installation with
UNF owning the primary Pod network. It is a live lab checkpoint for the full-CNI
milestone, not a production-support claim or completion of the primary-CNI
lifecycle gate.

## Result

`openshift-install agent wait-for install-complete` returned `Install complete!`.
At the final checkpoint:

- ClusterVersion `4.22.10` was Available, not Progressing, and not Failing;
- every ClusterOperator was Available, not Progressing, and not Degraded;
- all three control-plane and two worker Nodes were Ready and linked to Running
  bare-metal Machine objects;
- the master and worker MachineConfigPools completed the persistent forwarding
  MachineConfigs;
- the UNF controller was available and all five agents were Ready, reporting
  exact convergence with zero remote-route reconciliation errors;
- the external canary route passed over IPv4 and IPv6; and
- direct cross-worker canary traffic passed in both directions over IPv4 and
  IPv6 Pod addresses.

The exact source revision was
`09e8a35e7d45efb1afb6b17acc0ca0b855172cb0`. The controller image was
`quay.io/arencloud/unf-controller-dev@sha256:b4df5645ac3a2ea9552f7a21d2d0d81c7d7c4aa1ea8355e2c6f304c2f2be3d56`
and the agent/CNI image was
`quay.io/arencloud/unf-agent-dev@sha256:e94e58150d3bb8756ab3c298db7d36dd0b9a1bd7bec1ffc6bb03f6e986a60fb9`.

## Platform tuple

| Dimension | Value |
|---|---|
| OpenShift / Kubernetes | 4.22.10 / 1.35.6 |
| Cluster shape | Three control-plane Nodes and two workers |
| OS | RHCOS 9.8.20260812-0 |
| Kernel | 5.14.0-687.39.1.el9_8.x86_64 |
| Runtime | CRI-O 1.35.6 |
| Architecture | amd64 |
| Pod networks | Five non-overlapping IPv4 `/23` and IPv6 `/64` Node blocks |
| Primary CNI | UNF native veth, IPAM, and direct-underlay routes |

## Installation recovery evidence

The installation exercised more than the success path:

1. Persistent forwarding MachineConfigs rolled across both pools, including
   controlled drains and reboots, and all five Nodes returned Ready.
2. A controller restart changed its routing epoch. Three agents correctly
   retained their last-known-good routes but rejected the new snapshot because
   their durable local assignment revision came from the prior epoch. A bounded
   agent rollout refreshed the Node-block snapshot; all five agents then
   converged on the same epoch and revision with zero route errors.
3. Restoring DNS, Thanos TokenReview, Ironic, ingress-canary, and API return paths
   allowed every ClusterOperator and the ClusterVersion payload to close.
4. The CVO replayed all 1,022 payload objects and marked 4.22.10 complete before
   the installer completion gate was accepted.

## Observed UNF gaps

The cluster required 24 live NetworkPolicies annotated with
`network.unf.io/temporary-reason`. They are explicit qualification scaffolding
and must not be treated as a production configuration. The install exposed four
product gaps:

1. Terminal `Succeeded` and `Failed` Pods keep their IP identity in the
   controller. When CRI-O reuses that IP, admission of the active replacement is
   rejected until the terminal installer or revision-pruner Pod is deleted.
2. Reply state is revision-scoped and does not cover every OpenShift bootstrap
   path under rapid policy churn, TokenReview, DNS, API Service NAT, and
   host-network traffic. Targeted bidirectional return policies were required.
3. Physical Node source addresses used by host-network routers are not always
   recovered as the originating Pod/Namespace identity. The ingress-canary gate
   required explicit Node-address peers.
4. A controller epoch change can renumber otherwise unchanged Node-block
   assignments. Running agents do not refresh that durable snapshot and reject
   the new remote-route snapshot until restarted.

The temporary policies cover only selected OpenShift control-plane operands and
the canary. Their count and reason can be audited without relying on this record:

```bash
oc get networkpolicy -A -o json | jq '
  [.items[] | select(
    .metadata.annotations["network.unf.io/temporary-reason"] != null
  )]'
```

## Remediation status

ADR 0070 implements fixes for all four observed gaps. Its expanded isolated
dual-stack primary-CNI Kind lifecycle passes, including the kubelet-probe and
exact Node-traffic regressions exposed by the first rollout. The fixes are not
credited as live cl02 evidence until corrected immutable images are deployed,
all temporary policies are removed, and operator, canary, convergence, outage,
and reboot checks pass without recreating them.

### First remediation rollout attempt

The first agent-only rollout used revision `58e4deb` and agent digest
`sha256:3f6426bd0ee205ca539b7655a5768c55be992a306cce6f64a43c05ce57a4dd87`.
It exposed a missing gate: treating both TC directions as policy enforcement
points blocked kubelet HTTP probes to CoreDNS ports 8080 and 8181, which in turn
degraded authentication. The new controller image was never deployed.

All five agents were returned to the checkpoint digest. Because legacy TC
filters persist independently of the Pod that installed them, a dry-run-first,
per-Node cleanup removed only `unf_observe_egress` attachments; ingress filters,
routes, CNI files, leases, and workload links were untouched. Authentication,
console, and DNS recovered. Insights remained degraded on its pre-existing
timeout to `console.redhat.com`, which is outside UNF dataplane qualification.
The 24 original policies remain installed. One additional exact Node-address
return policy was added to `openshift-dns` after the rollback so CoreDNS could
re-establish API watches with the old controller; all five DNS Pods then became
Ready. The live temporary-policy count is therefore 25. The rejected image tag
and digest will not be reused; the next attempt requires a new committed
revision and new immutable digests.

### Corrected remediation rollout

Revision `be501c0` passed the expanded isolated Kind gate and was published as
controller digest
`sha256:02a719b79c7e6f9c27e7ae7a63ee70fa2d02a17734a765d9cf41e5576d0a6e0c`
and agent digest
`sha256:d958d99fbdc09fb1f72c9949f3cc9ce533dedb0dfab0ce4a7634c34aa7b059bf`.
The five corrected agents converged during a 75-second old-controller hold with
zero restarts and all five DNS Pods Ready. After the corrected controller
started, its state endpoint reported five expected, reporting, fresh, and
converged agents with one shared epoch and exact desired/applied identity,
policy, Node-block, and route revisions.

The controller update retained one failed packaging attempt. The host-network
singleton inherited `RollingUpdate`; its replacement could not share fixed
ports on the pinned control-plane Node, and OpenShift retained 340 failed Pods
with reason `NodePorts`. Patching the Deployment to `Recreate` stopped the old
revision before starting the corrected controller. The healthy replacement was
not manually altered, and only the 340 terminal failed-Pod records were then
deleted. The runtime package and package check now require `Recreate`. This
retry remains part of the qualification record.

### Workaround removal and lifecycle recovery

All 25 policies carrying `network.unf.io/temporary-reason` were removed in
seven guarded batches. Each batch retained a sanitized in-memory rollback copy,
required a changed compiled policy revision with exact desired/applied state on
all five agents, and passed API, five-Node kubelet proxy, DNS, operator, and
IPv4/IPv6 ingress-canary checks before and after a 60-second hold. No rollback
was required. The final count is zero; native OpenShift policies were not
removed, and DNS/canary restart counts did not change during policy removal.

A disposable retained terminal Pod released its CNI attachment while its API
object remained. A live replacement on the same worker received the same IPv4
and IPv6 addresses, passed direct cross-worker traffic, and self-cleaned to the
exact pre-test attachment counts. A separate controller-outage gate replaced
the server-node agent while the controller was absent. The replacement restored
last-known-good Node-block and eight-route state, uninterrupted dual-stack
traffic passed, and all five agents adopted the restored controller's new exact
epoch before fixture cleanup.

The Node reboot gate retains two unsuccessful attempts. The first correctly
rejected a stale pre-reboot Pod readiness condition and self-cleaned. The second
rebooted the worker, reconstructed all eleven BPF maps and four remote routes
per family, but could not close controller convergence because the generic
one-second liveness probe restarted the controller six times during post-churn
state replay. A live primary-specific startup/readiness/liveness patch restored
five-agent convergence and held the controller Ready with zero restarts for 120
seconds. That probe contract is now package-checked.

The retained reboot evidence then exposed a separate CNI lifecycle defect.
Attachment records on the rebooted worker grew from 14 before the attempts to
25 and then 36. All 36 records were unique and Ready, but only ten corresponding
UNF host links existed, exactly matching the ten running non-host-network Pods;
26 records referred to vanished pre-reboot sandboxes. The journal correctly
retained their leases because CRI-O had not delivered DEL, but GC was still a
no-op and could not reclaim them.

ADR 0071 implements CNI 1.1 `cni.dev/valid-attachments` reconciliation through
network-scoped, ordered eight-record transaction pages. Stale records use the
existing route-first exact cleanup and two-step durable deletion. A conflicted
record and lease remain retryable while GC continues with other stale records.
`make cni-lifecycle-test` and the complete static/eBPF/package gate pass. This
fix is local evidence only until a new immutable agent/CNI image is rolled out,
the 26 observed stale records are reconciled, and a clean reboot returns exact
journal/link/Pod cardinality.

The rollout candidate is exact source revision `221168c`, controller digest
`sha256:45737844f39bd84b0e1929013ee01e8f364aa8d90fd8eb20430ad8d60e3cdb45`,
and agent/CNI digest
`sha256:822f79780fc28d46ff9a7e1a9127d43319a6b7368ece225cfcd883d8c5a74c52`.
Both public Quay references were resolved anonymously after publication. They
remain candidate evidence until the staged rollout and live reconciliation
gates pass.

## Remaining exit criteria

The live primary-CNI lifecycle remains **In progress** until repository changes
and repeatable gates prove the remaining items:

- immutable GC image rollout, reconciliation of the retained reboot-stale
  records, and Node reboot last-known-good recovery with exact
  journal/link/Pod cardinality;
- CRI-O ADD/CHECK/DEL and lease/link cleanup under deliberate failure;
- exact artifact, route, and BPF teardown, no-CNI baseline behavior, and clean
  reprovision recovery; and
- a committed, self-cleaning qualification command and evidence artifact.
