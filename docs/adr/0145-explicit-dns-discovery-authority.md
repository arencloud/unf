# ADR 0145: Bind wildcard discovery to explicit DNS authority

**Status:** Accepted and implemented for Phase 8 milestone 8.7d

## Context

ADR 0144 makes exact-name PLR authority autonomous in the packet path, but it
deliberately refuses to query wildcard strings or assign semantics to an
unconfigured resolver-view label. DNS has no safe operation that enumerates all
members of `*.example.test`; querying the wildcard itself can return a synthetic
record, omit valid members, or leak an operator's namespace. Likewise, answers
from an arbitrary resolver must not become trusted merely because an observer
labels them with the policy's view.

The remaining design must support useful wildcard policy and split-horizon DNS
without turning a broad suffix into discovery authority, without merging views,
and without allowing one authenticated agent to choose an untrusted resolver.

## Decision

1. Native DNS controls add two independently bounded sets:
   `discoveryNames` lists concrete names eligible for observation under a
   wildcard pattern, and `resolverAddresses` lists the resolver identities
   authoritative for the named view. Both sets are canonical, unique, ordered,
   and part of the normalized desired model and PLR snapshot digest.
2. Every discovery name must match at least one policy pattern. Exact patterns
   remain self-authorizing and need not be duplicated. A custom view requires
   at least one explicit non-unspecified resolver address. The
   `cluster-default` view may retain an empty resolver set and then uses the
   Node's configured resolver.
3. The agent observes only the exact union of self-authorizing exact patterns
   and declared discovery names. It groups complete replacement batches by
   view, binds each view to one deterministic configured resolver on that Node,
   rejects conflicting resolver authority, and preserves the existing atomic
   observation bound. It never sends a DNS query containing `*`.
4. PLR compilation independently checks both authorities. An otherwise matching
   wildcard answer is excluded when its concrete query name was not declared;
   an answer is also excluded when its resolver is outside the policy allowlist.
   Dedicated report counters distinguish wrong-view, wrong-resolver,
   unmatched-name, and unauthorized-name evidence.
5. Each observer/view has an independent monotonic producer position and refresh
   schedule. Removing a view publishes one authenticated complete empty batch.
   Losing the final source projection also attempts this withdrawal; publication
   failure cannot extend authority because existing leases still expire by their
   autonomous deadline.
6. Gateway aggregation retains every independently admitted source-Node
   contract when workload replicas on different Nodes share one identity. It
   admits the duplicate identity only when all policy, destination, allocation,
   gateway, capability, and revision behavior agrees, then lowers one canonical
   identity-keyed NAT entry. A conflicting replica fails closed. This separates
   Node provenance cardinality from dataplane identity cardinality.
7. A dedicated three-Node kube-proxy-free Kind lifecycle uses two source Nodes,
   one gateway Node, a custom resolver view, a declared wildcard member, and a
   resolver returning A and AAAA. It requires two distinct Node observations,
   dual-stack packet enforcement, observer restart with a new source epoch,
   authoritative-empty denial, answer recovery, and final empty withdrawal.

This primitive is **Explicit DNS Discovery Authority**: pattern authority,
discovery authority, resolver authority, and temporal packet authority are
separate commitments. Broad policy syntax therefore does not grant broad name
discovery or let resolver provenance become an unchecked string.

## Consequences

- Wildcard FQDN controls are useful with GitOps-managed, inventory-derived, or
  future passive discovery names while remaining deterministic and auditable.
- Split-horizon views can select explicit resolvers without merging evidence
  between views or silently falling back to the Node default.
- Updating discovery or resolver authority changes the desired-model digest and
  causes normal fail-closed re-materialization.
- Replica count no longer makes a valid identity impossible to install on a
  shared gateway. Every Node-bound contract remains covered by the gateway
  acknowledgement and source activation grant, while equivalent behavior is
  coalesced only after structural verification.
- Multiple resolver addresses are an allowlist. The current producer selects the
  first canonical address per view; resolver failover and consensus are later
  provider work and are not inferred here.
- This milestone does not claim DNSSEC validation, passive workload DNS capture,
  arbitrary wildcard enumeration, internet classification, scale, or OpenShift
  qualification.

## Verification

`make egress-fqdn-lifecycle-test` inherits the complete Phase 8.7c gate. Focused
tests prove normalization, name/resolver rejection, custom-view dual-stack
observation, CRD equality, translation, and strict linting. The live gate builds
the deterministic DNS fixture into the test-tools image and records immutable
observation checkpoints for initial quorum, observer recovery, authoritative
empty state, restored authority, and final withdrawal. It also requires both
source Nodes that share one identity to receive activation grants while the
third Node installs one coalesced gateway behavior.
