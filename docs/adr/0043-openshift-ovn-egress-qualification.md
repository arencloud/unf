# ADR 0043: OpenShift OVN and large-snapshot egress qualification

Status: Accepted and live verified on dual-stack OpenShift

## Context

The complete egress matrix exposed platform conditions not present in the Kind
fixture. The cl02 controller compiles roughly 50 MB of policy state from more
than one hundred native NetworkPolicies. OpenShift Service DNS can itself depend
on the dataplane being healthy. OVN represents host-network router traffic with
the per-node gateway address, and a same-node route can bypass the TC point that
records the initial packet for bounded reply state.

OpenShift also uses global IPv4 CIDRs and full numeric port ranges in native
policies. Those valid Kubernetes forms must lower without unbounded expansion.

## Decision

The controller caches one compiled dataplane snapshot by policy revision, and
agents use a 30-second management request timeout. In-cluster agents resolve only
the configured controller Service hostname to the Kubernetes-injected
`UNF_CONTROLLER_SERVICE_HOST` address while retaining the original TLS hostname
for certificate verification. External controller URLs retain ordinary DNS.

IPv4 `0.0.0.0/0` uses the existing arbitrary-destination fallback plus bounded
exact exceptions. A numeric range covering ports 1 through 65535 normalizes to
the protocol wildcard instead of expanding every port.

The controller derives each OVN gateway as address `+2` from the Node's
`k8s.ovn.org/node-subnets` annotation and publishes it as a virtual endpoint in
the real `openshift-host-network` Namespace label domain. For a workload selected
by Kubernetes egress isolation, an ingress rule that explicitly allows that
virtual peer produces an exact gateway return entry for the rule's protocol.
The entry uses the ingress policy/rule provenance, destination-port wildcard,
and only that source identity and gateway address. This narrowly implements the
Kubernetes reply-traffic contract when same-node OVN routing bypasses runtime
connection observation; it does not create a general host-network bypass.

The OpenShift verifier requires the SCTP kernel module to be loaded on each
selected worker before starting protocol fixtures. Test `ipBlock` ranges use the
smallest CIDR containing the two same-worker destinations so conformance evidence
does not consume capacity unrelated to the scenario.

## Verification

Controller tests cover gateway derivation, virtual Namespace labels, IPv4/IPv6
reply entry generation, protocol scoping, source isolation, and provenance.
Policy tests cover IPv4 global fallback/exceptions and full-range normalization;
agent tests cover DNS-independent Service resolution with preserved TLS hostname.

`make openshift-test OPENSHIFT_KUBECONFIG=.tools/cl02-audit.kubeconfig` passes on
two dual-stack OpenShift 4.22/RHCOS 9.8 workers. It requires the platform canary
route and every cluster operator to remain healthy while the full ingress and
egress matrices verify TCP, UDP, SCTP, IPv4/IPv6 exceptions, explanation,
history, simulation, provenance, recovery, and exact cleanup.

## Consequences

OpenShift management recovery no longer depends on cluster DNS, and repeated
agent polling does not repeatedly compile the same large revision. OVN router
replies retain explicit policy provenance on both cross-node and same-node paths.
The SCTP module remains a documented host prerequisite, and arbitrary bounded
CIDR expansion plus the per-bank entry limit remain deliberate fail-closed
capacity boundaries.
