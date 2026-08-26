# Upstream-aligned NetworkPolicy ingress conformance

This document tracks the supported Kubernetes `NetworkPolicy` ingress behaviors
that UNF verifies against its real two-node dataplane. It complements unit tests
with repeatable policy transitions and traffic assertions. It is not a claim that
UNF passes the complete Kubernetes NetworkPolicy end-to-end suite.

The behavioral reference is the Kubernetes
[NetworkPolicy documentation](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
and the upstream
[network policy e2e scenarios](https://github.com/kubernetes/kubernetes/blob/master/test/e2e/network/netpol/network_policy.go).

## Pinned upstream scenario audit

The one-to-one audit below covers upstream commit
[`9aac5f741fa6095594cdfed4756a52cf0bf4b191`](https://github.com/kubernetes/kubernetes/blob/9aac5f741fa6095594cdfed4756a52cf0bf4b191/test/e2e/network/netpol/network_policy.go),
committed on 2026-08-26. It inventories all 43 scenarios in the primary
server/client context plus the three UDP and three SCTP scenarios. There are no
unclassified scenarios: 35 are verified, 13 are unsupported because they require
egress, and one is intentionally excluded pending stateful return-flow tracking.

Evidence abbreviations are:

- **M** — the dual-stack upstream-aligned matrix in
  [`hack/verify-networkpolicy-ingress.sh`](../../hack/verify-networkpolicy-ingress.sh);
- **K** — the complete two-node gate in
  [`hack/verify-kind.sh`](../../hack/verify-kind.sh), including TCP, UDP, SCTP,
  lifecycle, provenance, and recovery;
- **U** — compiler, evaluator, and dataplane-lowering tests in
  [`crates/unf-policy/src/network_policy.rs`](../../crates/unf-policy/src/network_policy.rs).

"Verified" may use compositional evidence where the upstream scenario combines
selector semantics already exercised by M/U with a protocol path exercised by K.
The compiler lowers those combinations through the same policy IR and map keys.
This audit does not claim that the upstream test binary itself was executed.

| # | Upstream context and scenario | Classification | UNF evidence or boundary |
|---:|---|---|---|
| 1 | TCP — should support a `default-deny-ingress` policy | **Verified** | M + U: selecting empty ingress rules deny all tested source scopes |
| 2 | TCP — should support a `default-deny-all` policy | **Unsupported** | The exact scenario includes egress isolation; userspace translation/evaluation exists but enforcement remains gated |
| 3 | TCP — should allow same-Namespace traffic based on PodSelector | **Verified** | M + U: policy-local PodSelector scope and non-matching remote denial |
| 4 | TCP — should allow ingress traffic for a target | **Intentionally excluded** | M + U verify the target-specific exception, combined empty Pod/Namespace peer, both remote scopes, and ordered recovery. The same-Namespace live leg needs established/related return-flow tracking because the broad policy also ingress-isolates the source |
| 5 | TCP — should allow ingress from Pods in all Namespaces | **Verified** | M + U: empty NamespaceSelector across all source scopes |
| 6 | TCP — should allow only a different Namespace selected by labels | **Verified** | M + U: exact Namespace selection and denial of same/other Namespaces |
| 7 | TCP — should enforce PodSelector with MatchExpressions | **Verified** | M + U: all four operators, mutation, and recovery |
| 8 | TCP — should enforce NamespaceSelector with MatchExpressions | **Verified** | M + U: all four operators, Namespace mutation, and recovery |
| 9 | TCP — should enforce PodSelector OR NamespaceSelector | **Verified** | M + U: heterogeneous peers in one `from` list |
| 10 | TCP — should enforce PodSelector AND NamespaceSelector | **Verified** | M + U: both selectors in one peer |
| 11 | TCP — should enforce multiple PodSelectors and NamespaceSelectors | **Verified** | M + U: multi-value Pod `In [b,c]` AND Namespace-name `NotIn` with each independent failure |
| 12 | TCP — should enforce any PodSelectors | **Verified** | M + U: two homogeneous PodSelector peers in one `from` list |
| 13 | TCP — should allow only a selected Pod in a different selected Namespace | **Verified** | M + U: exact combined remote Pod/Namespace selection |
| 14 | TCP — should enforce policy based on ports | **Verified** | M + U: exact port allow and adjacent-port isolation |
| 15 | TCP — should enforce stacked policies with overlapping PodSelectors | **Verified** | M + U: broad/narrow destination overlap and ordered recovery |
| 16 | TCP — should support allow-all policy | **Verified** | M: `ingress: [{}]`, precedence, and deletion recovery |
| 17 | TCP — should allow ingress on one named port | **Verified** | M + U: destination-resolved named port and opposite-port denial |
| 18 | TCP — should allow ingress from a Namespace on one named port | **Verified** | M + U: peer-restricted, per-destination named-port lowering |
| 19 | TCP — should allow egress on one named port | **Unsupported** | Named-port egress IR translates through the shared parser, but source-side enforcement is not implemented |
| 20 | TCP — should not allow all ports for a nonexistent named port | **Verified** | M + U: fail-closed isolation on both selected destinations |
| 21 | TCP — should enforce updated policy | **Verified** | M + U: same-object allow-all/default-deny replacement and rollback |
| 22 | TCP — should allow ingress from an updated Namespace | **Verified** | M: Namespace-label deny/recovery with revision convergence |
| 23 | TCP — should allow ingress from an updated Pod | **Verified** | M: source-label deny/recovery with revision convergence |
| 24 | TCP — should deny ingress from Pods in other Namespaces | **Verified** | M + U: empty PodSelector remains policy-Namespace-local |
| 25 | TCP — should deny ingress access to an updated target Pod | **Verified** | M + U: destination-label selection, isolation, and recovery |
| 26 | TCP — should deny egress from Pods based on PodSelector | **Unsupported** | Source-selected userspace isolation exists, but egress dataplane enforcement is not implemented |
| 27 | TCP — should deny egress from all Pods in a Namespace | **Unsupported** | Source-selected userspace isolation exists, but egress dataplane enforcement is not implemented |
| 28 | TCP — should work with Ingress and Egress together | **Unsupported** | The exact scenario requires direction-aware policy composition |
| 29 | TCP — should deny client-side egress even when the server allows ingress | **Unsupported** | Egress enforcement is not implemented |
| 30 | TCP — should allow egress to a selected Pod in a selected Namespace | **Unsupported** | Egress peer translation/evaluation exists, but source-side enforcement is not implemented |
| 31 | TCP/UDP — should allow any port on one ingress protocol | **Verified** | K + U: protocol-only TCP wildcard without UDP broadening |
| 32 | TCP — should let an ingress allow-all policy take precedence | **Verified** | M + U: additive allow-all over selecting policies |
| 33 | TCP — should let an egress allow-all policy take precedence | **Unsupported** | The shared additive evaluator is direction-aware, but egress dataplane enforcement is not implemented |
| 34 | TCP — should stop enforcing policies after deletion | **Unsupported** | The exact upstream object contains ingress and egress. M/K verify ingress deletion and recreation independently |
| 35 | TCP — should allow egress to a server in a CIDR block | **Unsupported** | Bounded destination-CIDR evaluation exists, but egress dataplane enforcement is not implemented |
| 36 | TCP — should enforce an egress `ipBlock` exception | **Unsupported** | Destination exceptions evaluate correctly in userspace, but egress dataplane enforcement is not implemented |
| 37 | TCP — should allow an IP covered by overlapping egress CIDR policies | **Unsupported** | Addressed/additive userspace semantics exist, but egress dataplane enforcement is not implemented |
| 38 | TCP — should control ingress and egress independently by PodSelector | **Unsupported** | Cross-direction userspace isolation exists, but egress dataplane enforcement is not implemented |
| 39 | TCP/SCTP — should not treat SCTP policy as TCP | **Verified** | K + U: SCTP keys and TCP isolation |
| 40 | TCP/SCTP — should isolate Pods selected by an SCTP policy | **Verified** | K + U: named SCTP allow with default-isolated open port |
| 41 | TCP/UDP — should not allow TCP when policy specifies only UDP | **Verified** | M + U: exact and protocol-only UDP with same-port TCP denial |
| 42 | TCP — should select a Namespace using the built-in name label | **Verified** | M + U: exact `kubernetes.io/metadata.name` matching |
| 43 | TCP — should select Namespaces by expression over the built-in name label | **Verified** | M + U: Namespace-name `NotIn` selection |
| 44 | UDP — should support a `default-deny-ingress` policy | **Verified** | M + U: UDP non-matching peers/ports receive the shared default deny |
| 45 | UDP — should enforce policy based on ports | **Verified** | M + U: exact UDP port and peer isolation over IPv4/IPv6 |
| 46 | UDP — should allow only a selected Pod in a selected Namespace | **Verified** | M + U compositional evidence: combined selector semantics plus direct exact/protocol-only UDP enforcement |
| 47 | SCTP — should support a `default-deny-ingress` policy | **Verified** | K + U: selected SCTP destination default-denies an open non-allowed port |
| 48 | SCTP — should enforce policy based on ports | **Verified** | K + U: destination-resolved exact SCTP port and protocol-only activation/recovery |
| 49 | SCTP — should allow only a selected Pod in a selected Namespace | **Verified** | M/K/U compositional evidence: combined selector semantics plus direct SCTP enforcement |

## Verified matrix

| Ingress contract | Local transition | Evidence |
|---|---|---|
| A selecting policy with no ingress rules isolates the destination | `ingress: []` denies all three sources | Unit matrix and two-node traffic |
| Destination Pod label changes activate and remove policy isolation | The accepted policy initially selects no target and traffic is allowed; adding the target label produces default deny, while removing it with two policies still present restores non-isolated traffic | Unit lifecycle test, revision-converged Pod mutations, explanations, and two-node traffic |
| Destination `podSelector.matchExpressions` control policy applicability | `In`, `NotIn`, `Exists`, and `DoesNotExist` select the worker-node server; violating and restoring each requirement independently switches between non-isolated and isolated traffic while the alternate server remains non-selected | Unit operator lifecycle assertions, revision-converged target-label mutations, explanations, and IPv4/IPv6 traffic |
| A peer with only `podSelector` is scoped to the policy Namespace | Empty and label-selecting PodSelectors allow the eligible same-Namespace Pod; remote Pods are denied | Unit matrix, revision-converged mutation, and two-node traffic |
| An empty `namespaceSelector` selects every Namespace | All three source Namespaces reach TCP/8087 while TCP/8088 remains isolated | Unit matrix and two-node traffic |
| The built-in Namespace-name label selects one exact Namespace | `kubernetes.io/metadata.name=unf-np-source-a` allows only source Namespace A on TCP/8087 | Unit matrix, explanations, and two-node traffic |
| Namespace `NotIn` expressions exclude matching label values | Excluding the target and source-B Namespace names allows source A while denying both excluded sources | Unit matrix, explanations, and two-node traffic |
| `podSelector` and `namespaceSelector` in one peer are ANDed | Only the selected Pod in source Namespace A is allowed | Unit matrix, explanation, and two-node traffic |
| Multi-value Pod selection remains ANDed with Namespace exclusion | One peer combines Namespace-name `NotIn` with Pod-label `In [b,c]`: remote Pods `b` and `c` reach TCP/8087, while same-Namespace `b`, remote `a`, and TCP/8088 remain denied | Dedicated evaluator/lowering test, four source roles, revision-converged explanations, IPv4/IPv6 traffic, and final recovery |
| Separate peers in one `from` list are ORed | The same-Namespace Pod or any Pod from source Namespace B is allowed | Unit matrix and two-node traffic |
| Multiple `podSelector` peers in one `from` list are ORed within the policy Namespace | Either of two differently selected same-Namespace Pods reaches TCP/8087; both remote sources and TCP/8088 remain denied, while the non-selected destination remains non-isolated | Dedicated evaluator/lowering test, revision-converged explanations, IPv4/IPv6 traffic, and deletion recovery |
| Pod and Namespace `matchExpressions` retain selector semantics | `In`, `NotIn`, `Exists`, and `DoesNotExist` combine within peers; adding/removing excluded Pod and Namespace labels denies and restores traffic after revision convergence | Unit matrix, two-node Pod/Namespace label mutation, explanations, and recovery traffic |
| Separate ingress rules are additive without mixing their peer/port pairs | Namespace A reaches only TCP/8087 while Namespace B reaches only TCP/8088; the same-Namespace source reaches neither | Unit matrix, explanations, and two-node traffic |
| An explicitly empty `from` list matches every source, and port entries are ORed | Every source reaches UDP/8090 and TCP/8091, while TCP/8090 and UDP/8091 remain denied | Unit wildcard assertion, revision-converged dual-protocol traffic, and explanations |
| An explicitly empty `ports` list matches every supported port and protocol | Namespace A reaches TCP and UDP on 8090 and 8091 while Namespace B remains denied by the peer selector | Unit wildcard assertion, revision-converged dual-protocol traffic, and explanations |
| A named port resolves independently for every selected destination Pod | One `web` rule allows TCP/8087 on the worker-node server and TCP/8088 on the control-plane server; each opposite open port and the non-matching source remain denied, and policy deletion restores both | Destination-aware lowering test, revision-converged explanations, cross-node/same-node traffic, and deletion recovery |
| A nonexistent named port fails closed | A `no-such-port` rule isolates both selected destinations without allowing either open TCP port; default-deny explanations remain truthful and deletion restores forwarding | Dedicated evaluator/lowering test plus revision-converged IPv4/IPv6 traffic against both Nodes |
| UDP rules preserve protocol and peer isolation | An exact UDP/8090 rule allows source Namespace A while UDP/8091, TCP/8090, and Namespace B remain denied; removing the numeric port activates protocol-only UDP/8091 without allowing TCP/8091, and policy deletion restores both protocols | Compiler test, dual-protocol echo fixture, revision-converged explanations, cross-node request/response traffic, and deletion recovery |
| Selecting policies combine allows additively | One policy allows Namespace A on TCP/8087 and another allows Namespace B on TCP/8088 | Existing additive evaluator test plus two-node traffic |
| Stacked policies with overlapping destination selectors combine only on their intersection | A broad policy allows Namespace A on TCP/8087 to both servers; a narrow policy additionally allows Namespace B on TCP/8088 only to the worker-node server. Deleting narrow then broad restores the intermediate isolation and final non-isolated state | Destination-specific evaluator/lowering test, revision-converged explanations, ordered deletion, and IPv4/IPv6 traffic |
| A target-specific allow is additive over namespace-wide default deny for remote sources | A broad policy isolates the target Namespace, while a second policy selects only the worker-node server and allows every Pod through one peer containing both empty Pod and Namespace selectors. Remote sources reach only that server; deleting narrow then broad restores broad isolation and final non-isolated traffic | Destination-specific evaluator/lowering test, both remote source scopes, revision-converged explanations, ordered deletion, and IPv4/IPv6 traffic |
| An allow-all policy takes precedence over other isolation policies | A temporary `ingress: [{}]` permits both ports from every source; deletion restores the stacked rules | Two-node mutation and recovery traffic |
| Updating one policy replaces its ingress rules | One accepted policy changes from `ingress: [{}]` to `ingress: []`, switching both selected servers from allow-all to default deny without changing the accepted-policy count; restoring the rule and deleting the policy recover allow-all and non-isolated traffic | Same-identity compiler/evaluator test, exact revision convergence, explanations, and direct IPv4/IPv6 traffic from all source scopes |

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
Egress, established/related return-flow tracking when both endpoints are selected
by ingress policies, non-initial fragments, IPv6 jumbograms/ESP/reassembly,
malformed or over-limit extension chains, unbounded compiler output, and complete
upstream suite execution remain outside this claim. In particular, the same-Namespace
source leg of upstream's namespace-wide default-deny plus target-exception scenario
requires stateful return handling and is not claimed here. Those gaps stay visible
in the authoritative [project tracker](../project-status.md).
