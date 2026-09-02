# ADR 0114: Normalize egress intent and OpenShift EgressIP compatibility

**Status:** Accepted and implemented for Phase 8.2

## Context

The egress fabric needs one deterministic input model before allocation,
gateway placement, reachability, or NAT can be implemented. Native UNF intent
must select Namespace, workload, and ServiceAccount identity and may request
multiple addresses from dual-stack pools. OpenShift compatibility must retain
the established `k8s.ovn.org/v1` EgressIP contract without creating a parallel
policy or dataplane engine.

The authoritative OpenShift 4.22 API requires `egressIPs` and
`namespaceSelector`, permits IPv4 and IPv6, makes `podSelector` optional and
intersects it with the Namespace selector when present, and reports assigned
address/Node pairs in status. These semantics are documented by the
[OpenShift 4.22 EgressIP API](https://docs.redhat.com/en/documentation/openshift_container_platform/4.22/html/network_apis/egressip-k8s-ovn-org-v1)
and the upstream
[OVN-Kubernetes EgressIP type](https://github.com/ovn-kubernetes/ovn-kubernetes/blob/master/go-controller/pkg/crd/egressip/v1/types.go).

## Decision

`unf-egress` is the Kubernetes-independent domain boundary. It defines:

- bounded canonical Namespace and workload label selectors plus an explicit
  ServiceAccount set, combined with logical AND;
- explicit `Any` or canonical dual-stack network destinations;
- provider-neutral address pools with immutable UID/provider provenance and
  non-overlapping canonical prefixes;
- either named-pool requests with explicit families and addresses per family,
  or explicit address requests;
- cluster-scoped or namespaced owner identity and nonzero deterministic
  priority; and
- complete-model validation that rejects duplicate owners/UIDs, unknown pools,
  missing address families, malformed selector syntax, duplicate state, and all
  configured capacity violations.

Input order is not semantic. Valid pools, prefixes, expressions, families,
addresses, and intents are deterministically ordered before they can enter a
later contract. Empty label selectors match all labels. An empty
ServiceAccount set means any ServiceAccount; an empty explicit address or
network set is invalid. Requested addresses never imply allocation, gateway
readiness, reachability, dataplane application, or publication.

The controller adapter owns the OpenShift schema. It parses requested strings
to typed IP addresses, maps the mandatory Namespace selector and optional Pod
selector into the same source selector, defaults a missing Pod selector to all
Pods in matching Namespaces, and emits an explicit-address `EgressIntent`.
Status is not an input to normalization. A separate merge helper can replace
only addresses previously owned by UNF, preserves every foreign or unparseable
status item byte-for-byte and in observed order, and rejects attempted adoption
of a foreign address.

## Consequences

- Native and OpenShift sources will feed the same allocation, behavior
  contract, gateway, and dataplane engine.
- Compatibility translation is strict and fail closed for malformed addresses,
  unknown selector operators, invalid label syntax, duplicates, and bounds.
- OpenShift's optional Pod-selector behavior and Namespace/Pod intersection are
  covered directly by tests.
- Pool reference and address-family coherence are proved before allocation.
- Phase 8.2 adds no watcher, native EgressPolicy/EgressPool CRD, RBAC, status
  writer, allocator, BPF ABI, host state, or packet-path behavior. Those remain
  later milestones.
- `make egress-intent-test` is the repeatable milestone gate.
