# Policy model

`SecurityPolicy` is converted to domain selectors and then compiled into `PolicyIr`.
Each compiled rule retains policy ID/name/namespace and source rule index. CRD
objects are never interpreted in eBPF.

## Phase 1 semantics

- Policies are namespaced; an omitted target namespace means the policy namespace.
- An empty source selector is a wildcard. Labels use exact key/value matching.
- An empty protocol list matches all protocols and destination ports.
- Lower numeric priority has higher precedence.
- Every applicable policy contributes either its matching explicit rules or its
  default action.
- At equal priority, `Deny` precedes `Allow`; stable policy/rule IDs break any
  remaining tie. Watch arrival order never affects a result.
- `Audit` records provenance but never changes forwarding.
- `Shadow` policies produce `shadowVerdict` but do not change the actual verdict.
- With no enforcing policy applicable, Phase 1 allows traffic. This is intentional
  for incremental overlay adoption, not an implicit failure-mode decision.

Port zero is rejected. Only TCP and UDP are in the first CRD. The evaluator is
pure and accepts resolved endpoints, making it usable by the controller, tests,
future simulation, and eventually a digital-twin query layer.

The Phase 2 lowering step resolves selectors against admitted identities and
precomputes deterministic exact and fallback decisions. Actual and shadow
verdicts retain policy/rule/reason provenance in the versioned BPF value. Dual
banks make distribution transactional. TC reads only the active bank: enforce
decisions can allow or drop, while shadow decisions are emitted as counterfactual
telemetry and never change forwarding.

## Kubernetes NetworkPolicy compatibility foundation

Phase 3 starts with a translator from the supported ingress subset of Kubernetes
`NetworkPolicy` into the same `PolicyIr`. `PolicyOrigin` lets the evaluator apply
Kubernetes' additive rule semantics across multiple selecting policies: any
matching compatibility allow wins over the other compatibility policies'
isolation defaults. The result then passes through the existing identity-tuple
and BPF map compiler; there is no second enforcement engine.

The first slice supports pod `matchLabels`, same-namespace peers, exact namespace
selection through `kubernetes.io/metadata.name`, numeric TCP/UDP ports, wildcard
sources/ports, and ingress default isolation. It deliberately rejects egress,
IP blocks, match expressions, general namespace-label selectors, named ports,
port ranges, SCTP, and protocol-only port entries. These errors prevent a policy
from being accepted with weaker or different semantics. Native policy has the
higher default precedence; the compatibility baseline uses reserved priority
`1_000_000`.
