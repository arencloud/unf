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
