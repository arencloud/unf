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
The translator accepts pod `matchLabels` and normalized `matchExpressions`, local
pod peers, empty or exact `kubernetes.io/metadata.name` namespace selectors,
numeric TCP/UDP ports, and wildcards. Core policy IR represents `In`, `NotIn`,
`Exists`, and `DoesNotExist` independently of Kubernetes types. It returns typed
errors for egress, IP blocks, namespace-selector expressions, general namespace-
label selectors, named/ranged ports, protocol-only entries, SCTP, and malformed
metadata/ports or selector requirements.

The controller watches `NetworkPolicy` objects cluster-wide and assigns each a
stable compatibility policy ID. Accepted IR joins native policy in the revisioned
snapshot. Rejected objects are counted separately; a rejected update or deletion
removes any stale accepted IR and advances the policy revision when effective
state changed. The controller RBAC grants read-only watch access to the resource.

## Alternatives

A separate NetworkPolicy evaluator would allow behavior to diverge before BPF
lowering. Translating every policy to an independent default-deny native policy
would violate additive union semantics. Silently dropping unsupported selectors
or port forms would weaken policy. Treating compatibility objects as native
priority policies would give isolation defaults incorrect precedence.

## Consequences

The supported compatibility slice is deterministic, explainable, and verified
through the same Phase 2 dataplane compiler in a two-node cluster. General
namespace labels are absent from endpoint identity metadata, rejection details
do not yet have a dedicated API endpoint, and egress needs a direction-aware IR
and hook. These remain visible Phase 3 work rather than broader support claims.
