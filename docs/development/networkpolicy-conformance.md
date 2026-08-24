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
| A peer with only `podSelector` is scoped to the policy Namespace | Same-Namespace matching Pod is allowed; identically eligible remote Pods are denied | Unit matrix, explanation, and two-node traffic |
| An empty `namespaceSelector` selects every Namespace | All three source Namespaces reach TCP/8087 while TCP/8088 remains isolated | Unit matrix and two-node traffic |
| `podSelector` and `namespaceSelector` in one peer are ANDed | Only the selected Pod in source Namespace A is allowed | Unit matrix, explanation, and two-node traffic |
| Separate peers in one `from` list are ORed | The same-Namespace Pod or any Pod from source Namespace B is allowed | Unit matrix and two-node traffic |
| Selecting policies combine allows additively | One policy allows Namespace A on TCP/8087 and another allows Namespace B on TCP/8088 | Existing additive evaluator test plus two-node traffic |
| An allow-all policy takes precedence over other isolation policies | A temporary `ingress: [{}]` permits both ports from every source; deletion restores the stacked rules | Two-node mutation and recovery traffic |

The disposable fixture is
[`deploy/examples/networkpolicy-upstream-ingress.yaml`](../../deploy/examples/networkpolicy-upstream-ingress.yaml).
[`hack/verify-networkpolicy-ingress.sh`](../../hack/verify-networkpolicy-ingress.sh)
owns its exact three test Namespaces, waits for controller/agent revision
convergence after each policy change, validates live forwarding and explanation,
and requires cleanup back to the pre-test accepted/rejected policy counts.

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
ingress IR and IPv4 dataplane. Egress, IPv6, unbounded CIDRs, fragments after the
initial fragment, and complete upstream suite execution remain outside this
claim. Those gaps stay visible in the authoritative
[project tracker](../project-status.md).
