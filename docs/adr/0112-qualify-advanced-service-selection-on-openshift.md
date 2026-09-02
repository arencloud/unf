# ADR 0112: Qualify advanced Service selection independently on OpenShift

**Status:** Accepted and live verified for Phase 7.10 (2026-09-02)

## Context

The Phase 7.9 Kind result does not qualify RHCOS, Enforcing SELinux, CRI-O, the
OpenShift host network, stacked VLAN transport, or the five-Node cl02 topology.
Phase 7 therefore remains open until the exact Kind-qualified runtime and
immutable public images pass an independent kube-proxy-free OpenShift gate.

During qualification, source-to-remote-backend DSR exposed a compiler boundary:
an immutable all-zero load-time topology global allowed LLVM to remove the
neighbor-output branch before the agent could override it. The runtime now uses
a volatile load of the mutable loader-owned symbol, and the focused gate checks
the optimized object for `bpf_redirect_neigh`. The loaded RHCOS program was also
inspected before qualification and contained both direct and neighbor redirect
helpers. IPv6 source assertions canonicalize textual forms before comparison;
the underlying addresses must still be exactly equal.

## Decision

`make service-selection-openshift-deploy` followed by
`make service-selection-openshift-test` is the repeatable Phase 7.10 gate. It
requires:

- a clean committed source revision and controller, agent, and test-tool images
  resolved to immutable public Quay digests;
- guarded staged persistent-ABI-v11 rollout with all five agents converged,
  kube-proxy absent, and the pre-existing ClusterOperator baseline captured;
- the complete Phase 6 five-Node dual-stack LoadBalancer regression on the same
  images;
- real IPv4 and IPv6 SameNode, SameZone, and Cluster fallback across workers and
  control-plane Nodes;
- ClientIP affinity creation, reuse, timeout, ineligible-backend reselection,
  and graceful draining;
- actual Maglev and StableHash packet-path provenance with three eligible
  backends;
- explicitly acknowledged cross-worker dual-stack DSR from a third-Node Pod,
  including backend VIP ownership, VIP return tuples, original client source,
  source-range denial, re-allow, and fresh history evidence;
- status-v8, history-v7, fixed-cardinality metrics, and digest-bound simulations;
- controller-offline replacement of both worker agents from validated ABI-v11
  private checkpoints, followed by exact five-agent reconvergence; and
- exact VIP, address, route, lease, Pod, Namespace, and fixture cleanup with no
  newly unhealthy ClusterOperator.

The record contains no kubeconfig, registry credential, projected token, or
kubeadmin secret.

## Live evidence

Product revision `06fc937987fcfacc2809003381782f905e203d16` and qualification
revision `018f14c5c1812fd199149da9fe11caaa538b7c6b` passed the 1,670-second
schema-v1 gate on infrastructure `cl02-st7gq`. The platform was OpenShift
4.22.10/Kubernetes 1.35.6 with five RHCOS 9.8.20260812-0 Nodes, Linux
5.14.0-687.39.1, CRI-O 1.35.6, Enforcing SELinux, UNF as primary CNI,
persistent BPF ABI 11, and no kube-proxy. Baseline and final unhealthy operator
sets both contained only `insights` and `network`.

The immutable images were:

- controller: `quay.io/arencloud/unf-controller-dev@sha256:2b3d5768fffbc24cc1e6271973eb91d836111175bfc478dce156db1fbfaeab8c`;
- agent: `quay.io/arencloud/unf-agent-dev@sha256:f2e8ee988d7e2a64f5fe3b73eac1c2d9b2332b809c7fb79a0f2e54a0470e1493`;
- test tools: `quay.io/arencloud/unf-test-tools-dev@sha256:ff5b88163fc2ea9e68d6ce8885cda92ba9a7a6f8e94c18f8110af1c4ab571542`.

Immediately after the successful run,
`.artifacts/phase7-service-selection-openshift.json` had SHA-256
`0126297256a07f5505f1addf1a1253674743d4cf9c3c1488aa59499af1599fbb`.
The inherited Phase 6 regression record had SHA-256
`2536bac93a76c845d126d46fb60624f9184357de44e37285ed01a93c74ca0a11`,
and the guarded deployment record had SHA-256
`3ba393f08583344612ad311ecc8a19cbc8ebf5cf1c47587056c397aee6685fa6`.

## Consequences

All Phase 7 milestones are Verified for the exact recorded Kind and OpenShift
tuples. The result is non-transitive: weighted or feedback-driven selection,
cross-cluster selection, production BGP/EVPN/ECMP/BFD, cloud adapters, SCTP
Service forwarding, fragments, generic NAT `RELATED`, Gateway API, L7 proxying,
production HA, availability, and scale require independent design and
qualification gates.
