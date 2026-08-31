# ADR 0101: Qualify LoadBalancer independently on OpenShift

**Status:** Accepted and live verified for Phase 6.9 (2026-08-31)

## Context

The Phase 6.8 Kind result does not qualify RHCOS, SELinux, CRI-O, the OpenShift
host network, or the five-Node cl02 topology. Phase 6 therefore remains open
until an exact committed runtime and immutable images pass an independent
kube-proxy-free OpenShift gate without broadening ownership or hiding platform
limitations.

Linux 5.14 does not provide the newer BPF FIB source-selection facility used on
the Kind host. The runtime consequently derives a private, transactional local
Node-address map from the authenticated Node projection, preferring canonical
InternalIP addresses for receiving-Node Cluster translation. This is runtime
state, not new Kubernetes ownership, and must reconstruct before attachment.

## Decision

`make loadbalancer-openshift-deploy` followed by
`make loadbalancer-openshift-test` is the repeatable Phase 6.9 gate. It requires:

- a clean committed product revision and controller, agent, and test-tool
  images resolved to immutable public Quay digests;
- a controller-first five-Node rollout with UNF remaining the primary CNI,
  kube-proxy absent, SELinux enforcing, and CRI-O/RHCOS unchanged;
- explicit `network.unf.io/load-balancer` ownership, conflict-safe dual-stack
  allocation, zero traffic NodePorts, and exact provider/pool provenance;
- temporary owner-scoped `/32` and `/128` `br-ex` reachability fixtures whose
  address lifecycle is stable per worker and whose withdrawal is exact;
- workstation-origin IPv4/IPv6 TCP/UDP Cluster traffic through both workers and
  Local traffic through the backend worker, with Cluster receiving-Node source
  translation, Local client-source preservation, and Local non-backend drop;
- dual-stack source-range allow/deny, health-check 200/503 placement behavior,
  readiness withdrawal, no-backend evidence, and recovery;
- metrics, status, history, explanation, and read-only simulation with bounded
  Service, allocation, provider, reachability, backend, and revision evidence;
- controller/provider recovery with stable allocation identity and monotonic
  fencing, then controller-offline replacement of both worker agents from
  validated last-known-good state;
- current checkpoint and exact ABI-v7 map reconstruction/audit; and
- exact lease, map, runtime trie, health listener, temporary address, Pod, and
  Namespace cleanup, five-agent convergence, and no new unhealthy
  ClusterOperator compared with the captured baseline.

The evidence record contains no registry credentials, kubeconfig contents,
projected tokens, or kubeadmin credentials.

## Live evidence

The gate passed on cl02 using product revision
`830771c87f52be2d41ce7d700a6c670690e7e516` and qualification revision
`ade286bbb2bba050559b1bcd85290aae7fd4dcf1`. The 973-second schema-v1 record
captures OpenShift 4.22.10/Kubernetes 1.35.6, five RHCOS
9.8.20260812-0 Nodes on Linux 5.14.0-687.39.1, CRI-O 1.35.6, persistent ABI 7,
kube-proxy absence, and matching baseline/final unhealthy sets containing
`insights` and `network`. No additional ClusterOperator became unhealthy.

The immutable images were:

- controller: `quay.io/arencloud/unf-controller-dev@sha256:b727c5a259d5317303c142e4fff6a20caa5cf9d1e202b32642fab2edf067ad8e`;
- agent: `quay.io/arencloud/unf-agent-dev@sha256:b2449e9fa78bdb32ccf87b9d711e8c1221a41b34440762dd52c1594ff8a25de3`;
- test tools: `quay.io/arencloud/unf-test-tools-dev@sha256:ff5b88163fc2ea9e68d6ce8885cda92ba9a7a6f8e94c18f8110af1c4ab571542`.

Immediately after the successful run,
`.artifacts/phase6-loadbalancer-openshift.json` had SHA-256
`2ea06eddb48065654cf2d5bcd51177ade5e581b3c3aa1c222c74208528340ab4`.
The preceding guarded-deployment record had SHA-256
`2623539d0e27d08aeb6e1eb026bcf022a009803354cd0a9ffc8704c908cf2fa3`.

## Consequences

All Phase 6 milestones are Verified for the exact recorded Kind and OpenShift
tuples. The result is non-transitive. Production BGP/EVPN/ECMP/BFD and cloud
adapters, classless ownership, session affinity, `internalTrafficPolicy`,
topology-aware selection, Maglev, DSR, SCTP Service forwarding, fragments,
generic NAT `RELATED` tracking, production availability, and scale require
separate design and qualification gates.
