# ADR 0115: Verify per-Node Egress Behavior Contracts

**Status:** Accepted and implemented for Phase 8.2a

## Context

Validated egress intent alone must not authorize host steering or NAT. Before
distribution, every selected source needs one reproducible statement connecting
its workload identity and original destination constraints to an already
allowed policy decision, exact address lease, ready reachable gateways,
required capabilities, and current revision tuple. Agents must be able to reject
controller compilation defects or mutated state before staging it.

The contract is not formal verification and its witness is not an authorization
token. It is a deterministic, independently replayable safety boundary and
provenance join for later distribution, dataplane events, status, history,
explanation, and simulation.

## Decision

`unf-egress` schema v1 defines one Egress Behavior Contract per exact Node. Its
canonical plans bind:

- a nonzero source identity, Namespace, workload UID, ServiceAccount, label
  facts, exact source Node UID, and normalized intent owner;
- original destination constraints and a nonempty, sorted source-side policy
  allow set;
- exact explicit addresses or pool name/UID/provider provenance, family/count
  coherence, address containment, and a nonzero allocation lease epoch;
- uniquely ranked, bounded gateway candidates whose lease epoch matches the
  allocation and whose readiness and reachability are acknowledged;
- source steering, original-tuple witness, lease fencing, and IPv4/IPv6 TCP/UDP
  NAT capabilities derived from the exact plan; and
- nonzero intent, identity, policy, allocation, gateway, reachability, and
  contract revisions.

Issuance normalizes the complete egress model, validates bounded external fact
sets, filters exact-Node sources, sorts every semantic set, and derives a
domain-separated SHA-256 commitment. Verification recompiles the contract from
the normalized model plus independently supplied current facts and compares
every field. Wrong local Node identity, unsupported schema, stale facts, denied
policy, foreign/out-of-pool addresses, split lease epochs, unready or unreachable
gateways, missing family capabilities, and any contract mutation fail closed.

A 16-byte decision witness commits the contract, source identity, intent UID,
selected address, selected gateway UID/epoch, and revision tuple. It resolves
only against the retained contract. The bounded failure envelope enumerates
single-gateway loss for every admitted source: another ranked candidate is
reported as available or the source becomes unavailable. Truncation is explicit
and digest-bound.

## Consequences

- Policy allow is a prerequisite for a plan; allocation and gateway state never
  grant connectivity.
- The same contract path applies to native and translated OpenShift intent.
- Input ordering cannot alter the plan, contract digest, witness, or failure
  outcome.
- Gateway placement quality and failover disruption are not claimed here; a
  later measured algorithm supplies the ranked facts.
- This milestone adds no authenticated distribution, checkpoint, allocator,
  gateway election, host state, BPF ABI, packet behavior, or platform claim.
- `make egress-contract-test` is the repeatable milestone gate.
