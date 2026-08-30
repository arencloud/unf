# ADR 0089: Qualify NodePort on the kube-proxy-free Kind fixture

**Status:** Accepted and implemented; live evidence pending (2026-08-30)

## Context

Phase 5.1–5.6 prove NodePort intent, compatibility, transactional state,
Cluster and Local packet behavior, and operations in bounded unit and real-kernel
gates. Those checks do not prove that the complete product works through live
Pod, host, routing, CNI, controller, and agent lifecycles without kube-proxy.

The existing Phase 4 Kind fixture already provides the exact prerequisite: one
control-plane and two workers, dual-stack Kubernetes 1.35, UNF as the sole CNI,
and kube-proxy disabled. Replacing it with an unrelated fixture would lose the
verified ClusterIP regression and rollback boundary.

## Decision

`make nodeport-kind-test` runs an opt-in strict superset of the existing Service
qualification on that fixture. It creates separate dual-stack NodePort Services
for `externalTrafficPolicy: Cluster` and `Local`, with fixed TCP, UDP, and source
observation ports. The gate requires:

- Cluster TCP/UDP success through both workers and both address families;
- Local TCP/UDP success only through the backend worker, with exact drops on the
  worker without a local backend;
- observed Cluster Node source translation, Local Pod-source preservation, and
  successful reverse tuple restoration;
- fixed-source-port UDP flows retained across readiness withdrawal while new
  connections fail closed;
- readiness, termination, deletion, backend recovery, controller outage, and
  replacement of both worker agents from durable and pinned state;
- schema-v5 status, schema-v6 history, fixed-cardinality metrics, filtered
  explanations, and exact read-only simulations without revision mutation;
- zero desired NodePort frontends, empty host frontend maps, legacy-format
  ClusterIP-only checkpoints, CNI attachment/veth cleanup, and scoped ABI-v5
  platform rollback; and
- explicit IPv4 NodePort host prerequisites with exact pre-activation sysctl
  capture and rollback restoration; and
- schema-v2 evidence binding the exact product and qualification-harness
  revisions, image IDs, Kubernetes, Node addresses, kernel/runtime/OS tuple,
  duration, assertions, and exclusions.

The Phase 4 `service-kind-test` mode remains available. Its schema assertions
are updated to the current operations contracts, and the shared rollback accepts
both the legacy ClusterIP checkpoint and the composite NodePort checkpoint.

## Consequences

- Kind evidence is non-transitive: OpenShift still requires an independent
  digest-pinned RHCOS/SELinux/CRI-O gate.
- The qualification intentionally excludes SCTP, LoadBalancer, session
  affinity, topology hints, Maglev, DSR, host-network clients, fragments,
  generic NAT `RELATED` tracking, and production availability or scale.
- The milestone is Implemented, not Verified, until committed images complete
  the gate and the resulting immutable evidence is audited.
- ADR 0090 records the host-kernel contract discovered by the first live run.

## Verification

Build and deploy the exact committed revision, then run:

```text
make service-kind-up
make service-kind-deploy
make nodeport-kind-test
```

The final command writes `.artifacts/phase5-nodeport-kind.json` and restores the
fixture to its saved no-CNI baseline.
