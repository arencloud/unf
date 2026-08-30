# ADR 0080: Qualify ClusterIP on a dedicated kube-proxy-free Kind fixture

Status: Accepted and implemented for Phase 4.7

## Context

The Phase 4 userspace, transactional-map, packet-execution, and operations
gates did not prove that UNF could replace kube-proxy for real cross-node
Service traffic. Reusing the general Kind fixture would leave kube-proxy rules
available and make ownership ambiguous. A primary-CNI cluster also has bootstrap
cycles: CoreDNS normally reaches the API through the Kubernetes Service, while
agents normally resolve the controller through cluster DNS.

## Decision

Phase 4.7 owns a separate one-control-plane/two-worker Kubernetes 1.35 Kind
fixture. It is dual stack, disables the default CNI, and sets kube-proxy mode to
`none`. UNF is the only CNI. The controller Service is headless so the test does
not use the dataplane under qualification to bootstrap that dataplane.

CoreDNS and the controller receive the exact control-plane host IP and API port
in this disposable fixture. Agent Pods receive an exact host alias for the
controller's TLS names. These exceptions carry only bootstrap control traffic;
ordinary Service traffic continues to use native UNF ClusterIP translation.
Every helper refuses a non-Kind or mismatched context, and the verifier rejects
a kube-proxy DaemonSet, kube-proxy Pods, `KUBE-SVC` rules, extra CNI files, or a
non-headless controller Service.

The gate creates cross-worker client/server Pods and one dual-stack TCP/UDP
Service. It requires direct Pod forwarding, DNS continuity, all four
family/protocol ClusterIP paths, repeated connection translation, readiness
withdrawal, terminating endpoint exclusion, backend deletion and recovery, and
explicit no-backend provenance. Metrics, schema-v4 agent status, schema-v5
history, and `unfctl service-explain` must agree on the active Service.

With the controller offline, the gate replaces the source and destination
worker agents while continuous dual-stack TCP/UDP probes run. Each replacement
must become ready from matching desired/applied service state, a private
schema-v1 durable snapshot, and the complete pinned IPv4/IPv6 service map set.
Interrupted private regular temporary state is removed safely on restart;
symlinks, non-files, or owner-access violations remain fail closed.

Finally, the gate deletes its exact namespace, requires attachment counts and
host veths to return to baseline, waits for the desired service maps to shed the
fixture, writes schema-v1 evidence, and invokes scoped primary-CNI rollback.
Rollback validates recognized snapshots and interrupted-write files, drains
empty exact-hash attachment directories below the network-scoped pending-delete
directory, removes only current ABI state,
restores CoreDNS, and proves the saved no-CNI baseline.

## Verification

The repeatable workflow is:

```console
make service-kind-up
make service-kind-deploy
make service-kind-test
```

`service-kind-test` includes `make service-operations-test` before the cluster
gate. The successful cluster run records Kubernetes version, Git revision,
dual-stack Node CIDRs/addresses, Service IDs and revisions, converged agent
reports, kube-proxy absence, and the explicit verification list in
`.artifacts/phase4-service-kind.json`. Success leaves the existing Kind cluster
at its no-CNI bootstrap baseline; redeploy or remove it deliberately.

## Consequences

Kube-proxy-free IPv4 and IPv6 TCP/UDP ClusterIP is Verified on the exact Kind
tuple, including endpoint lifecycle, operations evidence, controller outage,
both worker-agent replacements, and rollback. This does not qualify OpenShift,
SCTP Services, NodePort, LoadBalancer, session affinity, traffic policies,
topology-aware routing, Maglev, DSR, host-network clients, fragments, or generic
NAT/RELATED tracking. Phase 4.8 must independently qualify the bounded
ClusterIP contract on the dedicated OpenShift primary-CNI environment.
