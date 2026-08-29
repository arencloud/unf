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

ADR 0070 implements fixes for all four observed gaps and the complete isolated
dual-stack primary-CNI Kind lifecycle passes with those changes. The fixes are
not credited as live cl02 evidence until immutable images are deployed, all 24
temporary policies are removed, and operator, canary, convergence, outage, and
reboot checks pass without recreating them.

## Remaining exit criteria

The live primary-CNI lifecycle remains **In progress** until repository changes
and repeatable gates eliminate the temporary policies and prove:

- terminal-Pod identity release and same-IP replacement without manual cleanup;
- reply handling across DNS, API, Service NAT, TokenReview, Ironic, monitoring,
  and router host-network paths without workload-specific exceptions;
- automatic Node-block/remote-route recovery across controller epoch changes;
- controller outage plus agent and Node reboot last-known-good recovery;
- CRI-O ADD/CHECK/DEL and lease/link cleanup under deliberate failure;
- exact artifact, route, and BPF teardown, no-CNI baseline behavior, and clean
  reprovision recovery; and
- a committed, self-cleaning qualification command and evidence artifact.
