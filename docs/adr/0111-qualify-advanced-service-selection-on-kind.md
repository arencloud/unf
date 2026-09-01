# ADR 0111: Qualify advanced Service selection on kube-proxy-free Kind

**Status:** Accepted and live verified for Phase 7.9 (2026-09-01)

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

Runtime revision `481ee8899b903d049d0fa5859ff3fa3787b9adb7` and qualification
revision `1f25e1384fb92c5f9b81214b17ba42af41855340` passed the complete live gate
in 467 seconds. The controller image ID was
`sha256:35701d8bec6431bf4670c875ea8caf85fe34b6b0baf27b6ec3c463cede5b039e`;
all three agents used
`sha256:a7906d555d4073d48031940d21b06e5593da1040372da51c26cb2470711ee190`.

The fixture ran Kubernetes v1.35.0 on three Debian 12 Nodes with Linux
7.1.4-204.fc44.x86_64. Evidence was written to
`.artifacts/phase7-service-selection-kind.json`; its SHA-256 was
`b4aa51c99987bfd1ee82737c8fcaf60209a85d5c485007c7c01461bdaa59de4d`
immediately after the successful run.

The final rollback completed all three ABI-v11 cleanup Jobs and independently
verified absence of the UNF CNI binary/configuration, private CNI/runtime state,
UNF bpffs root, and protocol-196 IPv4/IPv6 routes on every Node. The cluster was
restored to the intentional NotReady no-CNI baseline.

## Consequences

Milestone 7.9 is Verified for this exact Kind tuple. This promotes no OpenShift
or production claim. Phase 7 remains In progress until the independent 7.10
digest-pinned five-Node cl02 gate proves cross-worker and cross-zone behavior,
source and return tuples, acknowledged backend VIP ownership, recovery, exact
cleanup, convergence, and ClusterOperator health on RHCOS/SELinux/CRI-O.

Weighted traffic splitting, load- or latency-feedback routing, cross-cluster
selection, SCTP Service forwarding, fragments, generic NAT `RELATED`, Gateway
API, L7 proxying, production HA, and production availability/scale remain
explicitly excluded.
