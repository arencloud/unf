# ADR 0009: NetworkPolicy compatibility through the shared policy engine

Status: Accepted and live verified for the first Phase 3 compatibility slice

## Context

Kubernetes `NetworkPolicy` is an additive allow-list API: when multiple ingress
policies select a destination, a match in any of them allows the flow. Native UNF
policy has priorities, explicit deny, defaults, audit, and shadow behavior. A
compatibility implementation must preserve Kubernetes semantics without creating
a separate evaluator or silently approximating unsupported fields.

## Decision

`NetworkPolicyCompiler` translates the supported ingress subset directly into
`PolicyIr`. `PolicyOrigin` distinguishes native and compatibility inputs inside
the shared evaluator. Selecting compatibility policies are evaluated as one
additive group: matching rules contribute allow candidates; their default denies
contribute one deterministic isolation decision only when no compatibility rule
matches. The resulting decision uses the existing provenance model and
identity-tuple/BPF lowering.

Compatibility policy uses reserved priority `1_000_000`, below the native policy
default range, so an explicitly managed native policy can override the baseline.
The translator accepts pod and Namespace `matchLabels` plus normalized
`matchExpressions`, local pod peers, exact `kubernetes.io/metadata.name`
selectors, numeric TCP/UDP ports, and wildcards. Core policy IR represents `In`,
`NotIn`, `Exists`, and `DoesNotExist` independently of Kubernetes types. Named
TCP/UDP ports remain named in IR, resolve per destination from watched Pod
container metadata, and lower to numeric dataplane entries. Inclusive numeric
`endPort` ranges remain ranges in IR and lower to exact dataplane entries. A
range may span at most 1,024 ports, and the shared compiler refuses more than
131,072 entries in either transactional bank; the agent validates that bank
limit again before staging a snapshot. It returns typed errors for egress, IP
blocks, oversized/reversed ranges, named ports combined with `endPort`,
protocol-only entries, SCTP, and malformed metadata/ports or selector
requirements.

The controller watches `NetworkPolicy` objects cluster-wide and assigns each a
stable compatibility policy ID. Accepted IR joins native policy in the revisioned
snapshot. Rejected objects are counted separately; a rejected update or deletion
removes any stale accepted IR and advances the policy revision when effective
state changed. The controller RBAC grants read-only watch access to the resource.
Watched Namespace labels are joined into endpoint selector metadata during policy
lowering. Label changes advance policy state without changing identity IDs.
Named-port mappings are policy-relevant endpoint metadata and therefore
participate in the canonical identity key; different mappings cannot alias in an
identity-keyed dataplane.

## Alternatives

A separate NetworkPolicy evaluator would allow behavior to diverge before BPF
lowering. Translating every policy to an independent default-deny native policy
would violate additive union semantics. Silently dropping unsupported selectors
or port forms would weaken policy. Treating compatibility objects as native
priority policies would give isolation defaults incorrect precedence.

## Consequences

The supported compatibility slice is deterministic, explainable, and verified
through the same Phase 2 dataplane compiler in a two-node cluster. Rejection
details do not yet have a dedicated API endpoint. Exact-key range expansion is
simple and matches the existing fast path, but intentionally trades map entries
for range support; per-range and per-bank limits make that cost explicit and
fail compilation instead of weakening policy. IP blocks still need a richer
dataplane representation, and egress needs a direction-aware IR and hook. These
remain visible Phase 3 work rather than broader support claims.
