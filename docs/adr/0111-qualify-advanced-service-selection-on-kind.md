# ADR 0111: Qualify advanced Service selection on kube-proxy-free Kind

**Status:** Accepted and live verified for Phase 7.9 (2026-09-02)

## Context

Milestones 7.1–7.8 proved the advanced Service-selection schema, independently
verified per-Node Network Behavior Contracts, transactional state, locality and
topology lowering, ClientIP affinity and draining, measured Maglev, explicit
LoadBalancer DSR, and bounded operations. Those focused gates did not prove the
complete tuple across real cross-Node dual-stack traffic, controller-offline
agent replacement, primary-CNI lifecycle, and exact platform rollback.

The existing isolated service fixture provides one control-plane and two worker
Nodes on Kubernetes v1.35.0, dual-stack Pod and Service networks, UNF as the sole
CNI, and no kube-proxy. It is the required pre-OpenShift boundary, but its result
does not transfer to RHCOS, Enforcing SELinux, CRI-O, or production routing.

## Decision

`hack/verify-kind-service-selection.sh` is the repeatable Phase 7.9 live gate,
and `make service-selection-kind-test` composes it with all inherited static,
verifier, privileged packet, operations, and installer gates. The live gate
requires:

- the complete Phase 6 external, Pod, host, LoadBalancer lifecycle, operations,
  recovery, cleanup, and kube-proxy-absence regression;
- real IPv4 and IPv6 traffic through strict SameNode selection, SameZone and
  Cluster fallback, and ready/serving/terminating endpoint transitions;
- original-client/frontend ClientIP affinity creation, reuse, timeout, and
  reselection after the previous backend becomes ineligible;
- actual Maglev and StableHash packet-path provenance across three eligible
  backends, with measurements retained by the focused benchmark gate;
- explicitly acknowledged dual-stack LoadBalancer DSR after backend VIP
  ownership and host routes are installed, including direct return;
- status-v8, durable history-v7, fixed-cardinality metrics, and digest-bound
  read-only simulation for the same active contracts;
- serial replacement of both worker agents while the controller is offline,
  recovered desired/applied selection revisions and digests before controller
  return, and uninterrupted traffic from private checkpoints and pinned maps;
- controller recovery, exact Namespace/VIP/route/container cleanup, and zero
  leaked LoadBalancer ownership; and
- current ABI-v11 BPF cleanup, exact remote-route deletion, fingerprinted CNI
  artifact removal, CoreDNS restoration, and the saved no-CNI baseline on all
  three Nodes.

Recovery publishes the durable verified contract as both desired and applied
before a replacement agent becomes Ready. The platform rollback resolves the
current persistent ABI from the canonical source constant, safely recreates an
owned failed cleanup Job, validates/removes the private readiness lease, and
remains resumable only from exact owned boundaries.

The schema-v1 evidence record binds the product revision, qualification
revision, image IDs, Kubernetes/Node/kernel tuple, allocated ClusterIP and DSR
VIPs, simulations, duration, verified assertions, and exclusions. It is written
before rollback and extended only after rollback succeeds.

## Verification

Runtime and qualification revision
`06fc937987fcfacc2809003381782f905e203d16` passed the complete live gate in
463 seconds. The controller image ID was
`sha256:49ee023367fbbb53b38ca985e42ba6dc3d041b68b6f4e7b595fabb06ac46e85c`;
all three agents used
`sha256:f717a9889e257bb807588c0fa818fbaf969b0b4e7a5645e84d39d1bbbd0ebfc9`.

The fixture ran Kubernetes v1.35.0 on three Debian 12 Nodes with Linux
7.1.4-204.fc44.x86_64. Evidence was written to
`.artifacts/phase7-service-selection-kind.json`; its SHA-256 was
`adb4d6ed663b0e2cb97d99fc8625e6a14ede08f06d35fa2adb53ff9ffe7fa45c`
immediately after the successful run.

The final rollback completed all three ABI-v11 cleanup Jobs and independently
verified absence of the UNF CNI binary/configuration, private CNI/runtime state,
UNF bpffs root, and protocol-196 IPv4/IPv6 routes on every Node. The cluster was
restored to the intentional NotReady no-CNI baseline.

## Consequences

Milestone 7.9 is Verified for this exact Kind tuple. This promotes no OpenShift
or production claim; the independent five-Node cl02 result is recorded by ADR
0112. Neither platform result promotes a production claim.

Weighted traffic splitting, load- or latency-feedback routing, cross-cluster
selection, SCTP Service forwarding, fragments, generic NAT `RELATED`, Gateway
API, L7 proxying, production HA, and production availability/scale remain
explicitly excluded.
