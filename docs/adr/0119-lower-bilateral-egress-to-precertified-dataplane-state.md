# ADR 0119: Lower bilateral egress to pre-certified dataplane state

**Status:** Accepted and implemented for the Phase 8.5 contract slice

## Context

Phase 8.4a proved source-side admission and deterministic bilateral decisions,
but its exact-Node contract was addressed to the source Node. A remote gateway
could validate an individual contract if it somehow received one, yet the
distribution model did not provide an authenticated, bounded aggregation of all
source contracts selecting that gateway. The contract also intentionally lacked
source-local route, interface, neighbor/tunnel, and MTU evidence.

Directly placing variable-length contracts or SHA-256-per-candidate selection in
eBPF would create an expensive, unverifiable packet ABI. Waiting to discover a
standby path after the primary fails would also preserve the ordinary
control-plane convergence window that the Egress Proof Chain is intended to
remove.

## Decision

Phase 8.5 begins with a bilateral distribution and fixed-width compilation
contract.

1. The controller constructs an `EgressGatewayProjection` only from typed
   `AdmittedEgressProjection` values. It canonically aggregates their complete
   contracts for one authenticated gateway recipient. The gateway verifies the
   envelope digest, schema/capabilities, contract commitments, ready/reachable
   lease-fenced membership, bounds, and ordering before admission. It can then
   reproduce a source flow proof from the one exact retained contract.
2. A source agent creates an `EgressPathCertificate` only after it resolves and
   reads back the gateway transport address, next hop, output interface, MTU,
   forwarding mode, path revision, gateway identity, and lease epoch. Active
   lowering requires one exact certificate for every allocated family and every
   ready gateway. Missing, duplicate, stale, incoherent, unused, or foreign path
   evidence fails closed.
3. eBPF ABI v1 defines explicit source/admission, address, gateway-path,
   selection, connection, configuration, and event layouts. Every layout has
   compile-time size/alignment assertions and explicit reserved bytes. Absence
   means native egress; an explicit source entry is only `Fenced` or `Active`.
4. Selection algorithm v2 compiles a 251-bucket rendezvous table in userspace.
   The packet path hashes the original tuple and authoritative identity with a
   fixed verifier-friendly function, then performs one table lookup. SHA-256
   ranks address and gateway candidates per bucket and remains the commitment
   algorithm for full proofs. This makes source, gateway, simulation, and packet
   selection identical without running SHA-256 for every candidate per packet.
5. Each bucket stores the primary and independently certified standby gateway.
   Candidate and selection tables are shared per intent, while source admission
   stays identity-specific. Thousands of identities selected by one intent do
   not duplicate the expensive candidate tables. Standby certification is the
   default whenever at least two ready gateways exist; it is not an opt-in.

The connection ABI retains original and translated tuples, contract/lease,
primary and standby transports, compact proof witness, and exact candidate
indexes. This is sufficient for later forward/reverse NAT and handoff without
guessing private state. Event records retain the same bounded provenance for
userspace enrichment.

## Consequences

- A gateway now receives exactly the source contracts that name it and can
  reproduce their bilateral decisions without trusting packet proof bytes.
- Route, interface, MTU, transport, and gateway readiness are certified before
  an identity becomes active.
- Standby readiness becomes part of the installed decision, enabling Phase 8.6
  to hand off without waiting for a new policy/selection distribution cycle.
- Fixed layouts do not depend on Kubernetes strings or variable-length state.
- Rendezvous computation remains userspace work; the packet path is one bounded
  hash and lookup.
- This slice defines and verifies the ABI and pure compiler only. It creates no
  BPF maps, attachments, addresses, routes, tunnels, NAT entries, packets, or
  platform claim. Phase 8.5 remains in progress until live agent distribution,
  transactional map ownership, TC steering, SNAT/reverse translation, and
  kernel packet tests pass.

## Verification

`make egress-dataplane-contract-test` runs all inherited Phase 8 gates, layout
and hash tests, gateway distribution/proof tests, six adversarial lowering
tests, formatting-sensitive source checks, and strict Clippy.
