# Upstream-aligned NetworkPolicy ingress conformance

This document tracks the supported Kubernetes `NetworkPolicy` ingress behaviors
that UNF verifies against its real two-node dataplane. It complements unit tests
with repeatable policy transitions and traffic assertions. It is not a claim that
UNF passes the complete Kubernetes NetworkPolicy end-to-end suite.

The behavioral reference is the Kubernetes
[NetworkPolicy documentation](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
and the upstream
[network policy e2e scenarios](https://github.com/kubernetes/kubernetes/blob/master/test/e2e/network/netpol/network_policy.go).

## Verified matrix

| Ingress contract | Local transition | Evidence |
|---|---|---|
| A selecting policy with no ingress rules isolates the destination | `ingress: []` denies all three sources | Unit matrix and two-node traffic |
| Destination Pod label changes activate and remove policy isolation | The accepted policy initially selects no target and traffic is allowed; adding the target label produces default deny, while removing it with two policies still present restores non-isolated traffic | Unit lifecycle test, revision-converged Pod mutations, explanations, and two-node traffic |
| A peer with only `podSelector` is scoped to the policy Namespace | Empty and label-selecting PodSelectors allow the eligible same-Namespace Pod; remote Pods are denied | Unit matrix, revision-converged mutation, and two-node traffic |
| An empty `namespaceSelector` selects every Namespace | All three source Namespaces reach TCP/8087 while TCP/8088 remains isolated | Unit matrix and two-node traffic |
| The built-in Namespace-name label selects one exact Namespace | `kubernetes.io/metadata.name=unf-np-source-a` allows only source Namespace A on TCP/8087 | Unit matrix, explanations, and two-node traffic |
| Namespace `NotIn` expressions exclude matching label values | Excluding the target and source-B Namespace names allows source A while denying both excluded sources | Unit matrix, explanations, and two-node traffic |
| `podSelector` and `namespaceSelector` in one peer are ANDed | Only the selected Pod in source Namespace A is allowed | Unit matrix, explanation, and two-node traffic |
| Separate peers in one `from` list are ORed | The same-Namespace Pod or any Pod from source Namespace B is allowed | Unit matrix and two-node traffic |
| Pod and Namespace `matchExpressions` retain selector semantics | `In`, `NotIn`, `Exists`, and `DoesNotExist` combine within peers; adding/removing excluded Pod and Namespace labels denies and restores traffic after revision convergence | Unit matrix, two-node Pod/Namespace label mutation, explanations, and recovery traffic |
| Separate ingress rules are additive without mixing their peer/port pairs | Namespace A reaches only TCP/8087 while Namespace B reaches only TCP/8088; the same-Namespace source reaches neither | Unit matrix, explanations, and two-node traffic |
| An explicitly empty `from` list matches every source, and port entries are ORed | Every source reaches UDP/8090 and TCP/8091, while TCP/8090 and UDP/8091 remain denied | Unit wildcard assertion, revision-converged dual-protocol traffic, and explanations |
| An explicitly empty `ports` list matches every supported port and protocol | Namespace A reaches TCP and UDP on 8090 and 8091 while Namespace B remains denied by the peer selector | Unit wildcard assertion, revision-converged dual-protocol traffic, and explanations |
| A named port resolves independently for every selected destination Pod | One `web` rule allows TCP/8087 on the worker-node server and TCP/8088 on the control-plane server; each opposite open port and the non-matching source remain denied, and policy deletion restores both | Destination-aware lowering test, revision-converged explanations, cross-node/same-node traffic, and deletion recovery |
| A nonexistent named port fails closed | A `no-such-port` rule isolates both selected destinations without allowing either open TCP port; default-deny explanations remain truthful and deletion restores forwarding | Dedicated evaluator/lowering test plus revision-converged IPv4/IPv6 traffic against both Nodes |
| UDP rules preserve protocol and peer isolation | An exact UDP/8090 rule allows source Namespace A while UDP/8091, TCP/8090, and Namespace B remain denied; removing the numeric port activates protocol-only UDP/8091 without allowing TCP/8091, and policy deletion restores both protocols | Compiler test, dual-protocol echo fixture, revision-converged explanations, cross-node request/response traffic, and deletion recovery |
| Selecting policies combine allows additively | One policy allows Namespace A on TCP/8087 and another allows Namespace B on TCP/8088 | Existing additive evaluator test plus two-node traffic |
| An allow-all policy takes precedence over other isolation policies | A temporary `ingress: [{}]` permits both ports from every source; deletion restores the stacked rules | Two-node mutation and recovery traffic |

The disposable fixture is
[`deploy/examples/networkpolicy-upstream-ingress.yaml`](../../deploy/examples/networkpolicy-upstream-ingress.yaml).
[`hack/verify-networkpolicy-ingress.sh`](../../hack/verify-networkpolicy-ingress.sh)
owns its exact three test Namespaces, waits for controller/agent revision
convergence after each policy change, validates live forwarding and explanation,
and requires cleanup back to the pre-test accepted/rejected policy counts.

Every HTTP allow/deny transition above is sent directly to both IPv4 and IPv6 Pod
addresses. The valid and nonexistent multi-destination named-port checks cover
both families on both Nodes. The dual-protocol target binds separate IPv4/IPv6
TCP and UDP sockets, so exact ports, protocol-only rules, explicit empty lists,
peer isolation, and cross-protocol denial are also exercised over both families.
Explanations remain family-neutral because both paths resolve to the same
workload identities and shared policy IR.

## Running the evidence

The supported entry point is:

```bash
make kind-test
```

The main verifier starts the controller connection and invokes the dedicated
matrix after the other compatibility fixtures. The matrix script can also be run
against an existing connection by setting `KUBECONFIG`, `KUBE_CONTEXT`,
`UNF_CONTROLLER_URL`, and `UNFCTL`.

## Deliberate exclusions

The matrix covers only behavior already represented faithfully by the current
ingress IR and probes direct Pod addresses rather than Service-family selection.
The main kind verifier separately proves bounded IPv4/IPv6 `ipBlock`
allow/default-deny/exception recovery and bounded extension-header traversal.
Egress, non-initial fragments, IPv6 jumbograms/ESP/reassembly, malformed or
over-limit extension chains, unbounded compiler output, and complete upstream
suite execution remain outside this claim. Those gaps stay visible in the authoritative
[project tracker](../project-status.md).
