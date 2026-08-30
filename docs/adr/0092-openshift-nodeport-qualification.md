# ADR 0092: Qualify NodePort independently on OpenShift

**Status:** Accepted and implemented; live evidence pending (2026-08-30)

## Context

Phase 5.7 verifies NodePort on a disposable three-Node Kind fixture, but that
evidence is not transitive to RHCOS, SELinux, CRI-O, MachineConfig rollouts, or
the five-Node OpenShift topology. The cl02 lab cluster already runs UNF as its
exclusive dual-stack primary CNI with kube-proxy absent and retains the
live-verified Phase 4 ABI-v4 service state.

Phase 5.8 therefore needs both a guarded ABI transition and an independent live
NodePort gate. A mutable tag, an all-at-once DaemonSet rollout, or a test that
re-enables kube-proxy would make the result ambiguous.

## Decision

The Phase 5.8 workflow requires a clean committed source revision, the accepted
schema-v2 Phase 5.7 Kind result, and public Quay images resolved by digest. It:

1. persists the IPv4 NodePort host contract through the master and worker
   MachineConfigs and waits for both pools to finish rolling;
2. verifies SELinux enforcement and every current interface's `rp_filter=0`
   and `accept_local=1` values;
3. deploys the controller first, then replaces the `OnDelete` agent on one Node
   at a time while kube-proxy remains absent;
4. requires five-Node schema-v5 status convergence and ABI-v5 service/NodePort
   state while retaining ABI v4 only as a bounded rollback boundary;
5. runs dual-stack TCP/UDP Cluster and Local NodePort through both workers,
   including Node-SNAT versus client-source preservation, reverse tuples,
   readiness/termination/deletion recovery, and Local fail-closed behavior;
6. replaces both worker agents independently while the controller is offline
   and continuously probes ClusterIP and NodePort paths;
7. verifies classified metrics/history/explanation, exact read-only simulation,
   empty NodePort maps and legacy checkpoint after fixture cleanup; and
8. retires only the historical ABI-v4 maps, requires five-Node convergence, and
   permits no new unhealthy ClusterOperator beyond the recorded baseline.

Evidence is written locally as schema-v2
`.artifacts/phase5-nodeport-openshift.json`. Registry credentials, kubeconfig
contents, projected tokens, and kubeadmin credentials are never included.

## Consequences

- The MachineConfig change may reboot all five lab Nodes in pool-controlled
  order before the product rollout begins.
- The disconnected Insights operator may remain in the baseline; any additional
  unavailable, degraded, or progressing operator fails the final comparison.
- A live failure preserves kube-proxy absence and restores only temporary test
  resources/controller replicas. Operators inspect and repair the exact failed
  stage rather than silently widening the dataplane.
- This remains a bounded NodePort claim. LoadBalancer, session affinity,
  topology hints, Maglev, DSR, host-network clients, SCTP, fragments, generic
  NAT `RELATED` tracking, and production availability/scale need later gates.

## Verification

After publishing and recording exact image digests, run:

```text
make nodeport-openshift-deploy OPENSHIFT_KUBECONFIG=.tools/cl02-audit.kubeconfig
make nodeport-openshift-test OPENSHIFT_KUBECONFIG=.tools/cl02-audit.kubeconfig
```

This ADR and milestone 5.8 become live verified only after both commands pass
on one exact source/image/platform tuple and their artifacts are audited.
