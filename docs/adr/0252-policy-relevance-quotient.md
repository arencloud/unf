# ADR 0252: Policy-Relevance Quotient

## Status

Accepted

## Context

The first preserved-state `0590d9b` cl02 deployment recovered the consecutive
tombstone chain and brought every agent to Ready without deleting host state.
The complete gate then changed the five-Node cluster baseline from Native to
Required. Encryption planning sampled every port from every cluster policy for
every cross-Node workload pair, even when a policy could not select either
endpoint. On cl02's 116 running non-host-network workloads and 133 Kubernetes
NetworkPolicies, repeated exact evaluations drove the controller to between
12 and 27 GiB of anonymous memory and kubelet evicted it under MemoryPressure.
No Required generation committed and the active Native predecessor remained
authoritative.

The dataplane policy evaluator already defines policy applicability solely by
direction and the selected endpoint: ingress selects the destination and
egress selects the source. Applying unrelated policy port partitions to a pair
adds work but cannot change its decision.

## Decision

Before enumerating exact protocol, port, and address classes for one identity
pair, compute its Policy-Relevance Quotient:

- retain only ingress policies whose target selects the exact destination and
  egress policies whose target selects the exact source;
- cache namespace-enriched endpoint metadata once per observed workload cut;
- represent a pair with no applicable policy as the existing truthful implicit
  `NoApplicablePolicy` allow, without manufacturing observations;
- evaluate every address, protocol, and boundary-port class against the
  relevance quotient with the unchanged policy evaluator; and
- reject before allocation if the complete cut exceeds 8,388,608 exact classes.

The quotient removes no applicable rule and performs no probabilistic,
sampled, or cached authorization. A unit proof compares full-set and quotient
decisions across matching, nonmatching, protocol, and port cases. Strict
Clippy, 108 controller tests, and the transitive Phase 9 runtime gates pass.

## Consequences

- Work scales with policies that can affect a pair rather than the product of
  all cluster policies and all workload pairs.
- Clusters with many namespace-local NetworkPolicies no longer amplify
  unrelated encryption planning work or starve health/API tasks.
- Adversarially complex relevant policy cuts fail closed at an explicit work
  boundary instead of risking node-wide memory eviction.
- The ADR 0251 image tuple remains historical Kind evidence but is not eligible
  for final qualification. This runtime change requires a new complete fresh
  Kind lifecycle, immutable publication, preserved-state cl02 deployment, and
  full OpenShift gate.
