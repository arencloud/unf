# ADR 0187: Adaptive Address-Exact Replica Binding

- Status: Accepted and implemented for Phase 9.5z
- Date: 2026-09-10

## Context

Encryption policy authority is keyed by source and destination identity, while
a kernel WireGuard transport terminates at a Node. A destination identity may
have replicas on several Nodes. Binding one identity decision directly to one
transport therefore either rejects legitimate replicas or sends some packets
to the wrong Node. Expanding policy state per Pod address would discard
identity semantics and scale map churn with replica count.

## Decision

UNF uses **Adaptive Address-Exact Replica Binding**:

1. Policy and post-Service/post-egress identity selection remain the first
   authority.
2. An identity pair backed by one remote Node retains the existing direct
   decision-to-transport lookup and pays no additional packet-path cost.
3. A pair backed by several Nodes carries an `ADDRESS_BOUND` decision. Only
   then does a second, banked dual-stack LPM lookup use the final translated
   destination address to choose the Node transport.
4. Prefix entries are derived from contract-bound WireGuard `AllowedIPs`, carry
   contract revision, key epoch, transport ID, and a content witness, and are
   published in the same inactive-bank transaction as decisions and transports.
5. Missing, mixed-revision, noncanonical, ambiguous, or unbacked prefix state
   fails closed. Established flows retain their exact Causal Epoch Lease and do
   not reselect during rotation.

The persistent encryption map ABI and proof-carrying checkpoint move to version
2. Old pinned state is intentionally incompatible and must follow the existing
clean-rebuild path.

## Consequences

- Replica placement can change independently of identity policy without
  creating a tunnel or transport per Pod.
- Single-Node destinations keep the minimum lookup count; only ambiguous
  identities pay for LPM resolution.
- IPv4 and IPv6 share the same causal generation and fail-closed semantics.
- The map adapter now stages and reads back both path families atomically.
- TC consumption and verifier/live-traffic proof remain separate subsequent
  milestones; this ADR does not claim encrypted packet forwarding.

## Verification

`make encryption-address-binding-test` inherits all earlier Phase 9 encryption
gates, proves two replicas of one identity select different transports across
IPv4 and IPv6, proves unknown addresses fail closed, verifies fleet snapshots
preserve every replica, checks fixed-width Aya encoding, and runs strict lint.
