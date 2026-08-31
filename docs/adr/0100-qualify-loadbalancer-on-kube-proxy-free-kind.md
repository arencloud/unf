# ADR 0100: Qualify LoadBalancer on kube-proxy-free Kind

**Status:** Accepted and live verified for Phase 6.8 (2026-08-31)

## Context

Milestones 6.1–6.7 proved LoadBalancer ownership, intent, allocation,
reachability, transactional host state, Cluster and Local packet behavior,
source ranges, health, operations, compatibility, and bounded recovery. Those
gates did not prove the complete product across an external client, Kubernetes
lifecycle, host routing, primary CNI, controller and agent replacement, and
platform rollback without kube-proxy.

The existing Phase 4/5 service fixture is the appropriate isolated boundary:
one control-plane and two workers, dual-stack Kubernetes v1.35.0, UNF as the
sole CNI, and kube-proxy absent. The Kind direct-Node provider is deliberately a
qualification adapter; it proves provider/reachability transactions without
claiming production BGP, EVPN, cloud routing, or OpenShift behavior.

## Decision

`make loadbalancer-kind-test` is the repeatable Phase 6.8 gate. It requires:

- explicit `network.unf.io/load-balancer` ownership, conflict-safe dual-stack
  allocation, stable pool/provider/Service provenance, and zero traffic
  NodePorts;
- external-container IPv4 and IPv6 TCP/UDP through Cluster VIPs on both workers
  and Local VIPs on the backend worker;
- receiving-Node source translation for Cluster, client-source preservation for
  Local, paired reverse restoration, and Local non-backend fail-closed behavior;
- dual-stack `loadBalancerSourceRanges`, host-origin Cluster and Local traffic,
  and placement-sensitive `healthCheckNodePort` HTTP 200/503 transitions;
- readiness withdrawal, no-backend behavior, recovery, fixed-cardinality
  metrics, validated status, durable history, explanation, and read-only
  simulation;
- controller/direct-Node provider restart with stable allocation ownership and
  monotonic allocation/reachability revisions;
- controller-offline replacement of both worker agents with uninterrupted
  probes and exact reconstruction from current-schema private checkpoints,
  persistent service/VIP banks, and runtime-only source-range tries;
- privileged in-cluster readback of the exact ABI-v7 LoadBalancer and shared
  BPF map ownership boundary; and
- exact lease, frontend, source-range, listener, external-client, Namespace,
  route, CNI, checkpoint, socket, BPF, and CoreDNS cleanup followed by
  restoration of the saved no-CNI baseline.

The gate writes schema-v1 evidence before invoking rollback. The record binds
the product revision, qualification revision, image IDs, Kubernetes/Node/kernel
tuple, provider and pool identity, allocated VIPs, duration, converged reports,
stable allocation digest, monotonic recovery revisions, verified assertions,
and explicit exclusions.

Kubernetes ingress status remains intentionally unpublished for the Kind
direct-Node qualification adapter. Phase 6 does not treat a lab-only route as a
production reachability promise; publication remains part of the independent
platform/provider qualification boundary.

## Verification

The accepted run used product revision
`dd11ae3f46b68571b013599577b0258bf3b99729` and qualification revision
`793273f96e9edff1a64593aab613d66a9cf316a1`. It completed in 285 seconds on
three-Node Kubernetes v1.35.0 with kube-proxy absent. The controller image ID
was `sha256:3ef234ccd4e728db5a2c566b7d416bd3ffe58d1f2c3b4743cd97074b9e60de5a`;
all agents used
`sha256:777475e22bed2b0a21b8b537551c900efba1a92e220aa8fa9f5ccc28df252ea5`.
The evidence file `.artifacts/phase6-loadbalancer-kind.json` had SHA-256
`fb819d5169c1af384a924b57b6348b85ecf67fefacc5e7e9929c349df71917c8`
immediately after the successful run.

An independent post-gate audit found no `unf-system` Namespace, UNF bpffs root,
private CNI state, runtime socket directory, CNI binary, or CNI configuration on
any Node. All three Nodes were at the expected NotReady no-CNI baseline.

## Consequences

Phase 6.8 is Verified for this exact Kind tuple. The result is non-transitive:
OpenShift still requires digest-pinned images and an independent five-Node
RHCOS/SELinux/CRI-O gate with cross-worker traffic, provider recovery, exact
cleanup, final convergence, and ClusterOperator health comparison. Production
advertisement protocols, cloud-provider adapters, classless ownership, session
affinity, internal/topology-aware traffic policy, Maglev, DSR, SCTP Services,
fragments, generic NAT `RELATED` tracking, and production availability/scale
remain explicit exclusions.
