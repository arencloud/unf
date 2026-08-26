# ADR 0009: NetworkPolicy compatibility through the shared policy engine

Status: Accepted and live verified for the supported Phase 3 ingress slices

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
selectors, numeric TCP/UDP/SCTP ports, and wildcards. Core policy IR represents
`In`, `NotIn`, `Exists`, and `DoesNotExist` independently of Kubernetes types.
Named TCP/UDP/SCTP ports remain named in IR, resolve per destination from watched
Pod container metadata, and lower to numeric dataplane entries. Inclusive
numeric `endPort` ranges remain ranges in IR and lower to exact dataplane entries.
Protocol-only TCP/UDP/SCTP entries remain protocol-scoped wildcards in IR and
lower to fixed-size `(protocol, port=0)` keys; `(protocol=0, port=0)` remains the
all-protocol global fallback. SCTP uses its IANA protocol number 132 and the same
source/destination port positions as the other supported transports. A range may
span at most 1,024 ports, and the shared compiler refuses more than 131,072
entries in either transactional bank;
the agent validates that bank limit again before staging a snapshot. It returns
typed errors for egress, IP blocks wider than 1,024 IPv4 addresses, IPv6 blocks
with more than 1,024 CIDR boundaries, reserved IPv4 blocks, out-of-block exceptions, oversized/reversed port
ranges, named ports combined with `endPort`, and malformed metadata/ports or
selector requirements. Bounded
IPv4 `ipBlock` peers, including `except`, remain in IR and expand into
exact-source keys plus an external-source fallback in a separate dual-bank map.
ADR 0014 extends the same IR with bounded IPv6 prefix boundaries and LPM lowering.

Kubernetes API defaults are resolved at the compatibility boundary. An omitted
`spec.podSelector` is the empty selector and therefore selects every Pod in the
policy Namespace. For the supported ingress-only shape with `egress` omitted,
omitted `policyTypes` implies ingress, and an omitted port protocol means TCP. A
Pod not selected by any ingress policy remains non-isolated. Omitted and
explicitly empty ingress `from` or `ports` lists compile to source and
protocol/port wildcards respectively; non-empty list entries retain Kubernetes
OR semantics. These defaults compile into ordinary shared IR selectors and
rules; they are not special cases in the evaluator or dataplane.

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
fail compilation instead of weakening policy. ADR 0014 subsequently added compact
bounded IPv6 prefix representation; egress still needs a direction-aware IR and
hook. The live verifier also creates a policy with omitted target selector,
policy types, and port protocol, proves namespace-wide TCP isolation, then
narrows the target and proves the no-longer-selected Pod is non-isolated. A
separate cross-node fixture proves named SCTP allow/default isolation,
protocol-only SCTP wildcard activation/removal, revisioned dataplane provenance,
and enriched historical export. An upstream-aligned three-Namespace matrix proves
same-Namespace PodSelector scope, empty NamespaceSelector behavior, selector AND,
peer OR, explicit empty-list wildcards, multi-port OR, all selector operators,
Pod/Namespace label recovery, stacked additive allows, and allow-all deletion
recovery. Direct IPv4 and IPv6 Pod traffic now exercises every transition,
including destination-specific named ports and TCP/UDP protocol isolation. These
remain bounded compatibility claims rather than full upstream conformance.
