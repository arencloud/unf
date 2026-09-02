# ADR 0113: Bound the identity-aware enterprise egress fabric

**Status:** Accepted and implemented for the Phase 8.1 architecture boundary

## Context

UNF already enforces Kubernetes NetworkPolicy egress at the selected source and
provides a verified dual-stack primary CNI. That does not implement enterprise
egress identity: it does not allocate stable external addresses, place HA
gateways, steer selected sources, perform gateway NAT, publish reachability, or
explain failover. Master-prompt §24 requires these capabilities to become one of
UNF's strongest domains.

Collapsing policy, EgressIP compatibility, allocation, gateway election, NAT,
and BGP into one controller flag would make ownership, split-brain behavior,
rollback, and explanations ambiguous. Treating a translated IP or DNS name as
trust identity would also violate the existing identity model.

## Decision

Phase 8 separates five coherent transactions:

1. source identity and security-policy decision;
2. egress intent plus destination constraints;
3. conflict-safe address allocation;
4. lease-fenced gateway placement and reachability acknowledgement; and
5. source steering plus bounded NAT/flow state.

Security policy always evaluates the original tuple before steering. An address
lease or gateway placement cannot grant connectivity. Ordinary Pod egress stays
native unless explicit admitted intent selects the source and a UNF-owned pool
and provider. Unsatisfied explicit intent fails closed; it never leaks through a
different source address.

The controller produces a canonical per-source/per-Node Egress Behavior
Contract binding identity, destinations, policy revision, address lease,
gateway candidates, provider capabilities, and all relevant revisions. Agents
independently replay validation before staging. A compact decision witness joins
packet events, status, history, explanation, and simulation without becoming an
authority or exposing high-cardinality metric labels.

Gateway ownership uses monotonic epochs and bounded leases. Deterministic
placement is measured before an algorithm is selected; the design may use
weighted rendezvous hashing, but no algorithm or disruption claim is accepted
without a committed fixture. Failover distinguishes new flows, established
flows, graceful drain, hard gateway loss, and split-brain rejection.

Allocation, gateway readiness, reachability, dataplane application, and status
publication have independent desired/applied revisions. Allocation never means
advertisement, and advertisement never means NAT readiness. Provider interfaces
allow a static development backend, OpenShift compatibility, and future BGP or
cloud adapters without changing normalized intent or packet semantics.

FQDN policy consumes bounded DNS-derived address sets with TTL, staleness,
capacity, wildcard, and source provenance. A name or answer is not workload
identity. Simulation reports uncertainty and private-state limits rather than
guessing active NAT bindings.

Every schema and persistent-state transition uses capability negotiation,
last-known-good retention, inactive staging, exact readback, atomic activation,
rollback, crash repair, and versioned cleanup. Kind and OpenShift remain
independent non-transitive gates.

## Consequences

- Phase 8.1 changes no CRD, BPF ABI, host route, address, packet behavior, or
  platform support claim.
- The design supports Namespace, workload, and ServiceAccount targeting without
  conflating source IP with identity.
- Determinism is required, but no HA-placement algorithm is declared superior
  before measurement.
- OpenShift EgressIP is a compatibility input to the same egress engine, not a
  second implementation.
- Static reachability can qualify development behavior; production BGP, cloud,
  cross-cluster, overlapping-CIDR, and encryption backends remain independent.
- SCTP NAT, fragments, generic NAT `RELATED`, arbitrary ICMP translation,
  production HA, availability, and scale remain explicitly excluded.
