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

## Kubernetes NetworkPolicy compatibility

Phase 3 starts with a translator from the supported ingress subset of Kubernetes
`NetworkPolicy` into the same `PolicyIr`. `PolicyOrigin` lets the evaluator apply
Kubernetes' additive rule semantics across multiple selecting policies: any
matching compatibility allow wins over the other compatibility policies'
isolation defaults. The result then passes through the existing identity-tuple
and BPF map compiler; there is no second enforcement engine.

The current slice supports pod `matchLabels` and `matchExpressions` (`In`,
`NotIn`, `Exists`, and `DoesNotExist`), same-namespace peers, exact namespace
selection through `kubernetes.io/metadata.name`, general Namespace `matchLabels`
and `matchExpressions`, numeric TCP/UDP/SCTP ports, explicit protocol-only
TCP/UDP/SCTP entries, wildcard sources/ports, and ingress default isolation.
Protocol-only entries remain `DestinationPort::Any` for their concrete protocol
and lower to a protocol/port-zero BPF key. Named TCP/UDP/SCTP ports are preserved
in IR, resolved against each selected destination Pod's declared container ports,
and lowered to numeric BPF keys. Inclusive numeric `endPort` ranges of at most
1,024 ports are preserved in IR and expanded deterministically into exact keys
during dataplane lowering. Wider ranges are rejected before they can multiply across
identity pairs. The shared compiler also rejects a snapshot that would exceed
one bank's 131,072-entry allocation, and the agent independently validates the
same bound.
At the translation boundary, an omitted target `podSelector` becomes the empty
selector for all Pods in the policy Namespace. For the supported ingress-only
shape with `egress` omitted, omitted `policyTypes` defaults to ingress, and an
omitted port protocol defaults to TCP. The evaluator's existing
no-applicable-policy behavior keeps Pods outside every ingress policy target
non-isolated.
IPv4 `ipBlock` peers and nested `except` CIDRs are preserved in IR and expanded
into an exact-source IPv4 policy map. One block may contain at most 1,024
addresses. IPv6 blocks remain compact CIDR boundaries in an LPM policy map,
support nested exceptions, and permit at most 1,024 boundaries per block; known
Pod addresses become `/128` overrides and `/0` represents arbitrary external
sources. `0.0.0.0`, wider IPv4 blocks, out-of-block or mixed-family exceptions,
and peers that combine `ipBlock` with selectors are rejected. A source-IP fallback represents
arbitrary external sources, so compatibility isolation does not silently fail
open merely because the source has no workload identity. The adapter deliberately
rejects egress and named ports combined with `endPort`. These errors
prevent a policy from being accepted with weaker or different semantics. Native
policy has the higher default precedence; the compatibility baseline uses
reserved priority `1_000_000`.

The controller watches these objects cluster-wide, keeps accepted and rejected
compatibility state separate, and combines accepted IR with native policy in each
revisioned agent snapshot. A rejected update or deletion removes any previously
compiled version and advances the policy revision when the effective dataplane
state changes. Namespace metadata is joined into endpoints during policy lowering
and explanation; a label change advances policy state without changing workload
identity. Controller status exposes accepted and rejected object counts.

Because the fast path is identity-keyed, named-port mappings participate in the
canonical identity key. Pods with the same labels but different mappings receive
different identities; changing a mapping intentionally advances identity and
policy state rather than widening an allow across both workloads.

## Read-only policy simulation

The Phase 3 simulation foundation compiles a candidate native `SecurityPolicy`
through the same `PolicyCompiler` and compares the current policy set with an
in-memory add-or-replace proposal. The controller captures the identity epoch,
identity revision, policy revision, topology revision, and Pod topology under one
read fence. It
evaluates current and proposed policy over all Pod sources, affected destinations,
every referenced concrete port, and representative TCP/UDP/SCTP fallback ports.

The versioned response retains both decisions and provenance, separates verdict
changes from provenance-only changes, and reports affected workloads. Simulation
is read-only: it does not update controller collections, policy revisions, agent
snapshots, or BPF maps. The matrix is capped at 10,000 flows. A separate result
evaluates the controller's bounded retained history, reports unique logical flows
and observation-weighted impact, skips identities no longer resolvable in current
topology, and reports Services affected through selectors or ready EndpointSlice
Pod backends. External sources that lack a
current source identity and user-supplied flow sets remain excluded. See
[ADR 0010](../adr/0010-read-only-policy-simulation.md).
