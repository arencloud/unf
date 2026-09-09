# ADR 0168: Node-Sealed Generation Capsule

**Status:** Accepted and implemented for Phase 9.5g

## Context

Phase 9.5f proved that only exact local route and rule readback may authorize an
encryption map generation. The controller must now transport compiled,
secret-free desired authority to the correct agent without turning network
delivery into kernel proof. Ordinary snapshot polling is insufficient: a
response can be replayed to a recreated Node, delivered after a newer response,
or join the wrong predecessor after an outage. Sending route permits would be
worse because the controller cannot observe the recipient's kernel.

Controller incarnations are opaque identities rather than ordered counters.
Monotonicity therefore belongs to the generation and its exact predecessor,
not to the numeric value of the controller epoch.

## Decision

UNF introduces the **Node-Sealed Generation Capsule**, a pull-based causal
delivery protocol over the existing internal TLS and Pod-bound TokenReview API:

1. the agent generates a 256-bit OS-CSPRNG nonce and submits its Node name plus
   the exact durable accepted cursor, if any;
2. the controller revalidates the authenticated agent Pod and authoritative
   Node UID, then selects only that Node's secret-free prepared checkpoint;
3. the controller returns only an exact successor whose prior published
   generation equals the request cursor, bound to the request nonce, Node
   name/UID, controller incarnation, revisions, counts, and canonical digest;
4. the agent independently verifies schema, bounds, checkpoint integrity,
   nonce, recipient, controller incarnation, predecessor, generation, and
   digest before mutation;
5. the agent atomically persists a mode-0600 admitted-generation record before
   advancing its in-memory cursor; and
6. `204 No Content`, transport failure, restart, or rejection retains the exact
   durable predecessor.

The controller epoch is included for provenance but is not numerically ordered.
A restarted controller may have any nonzero epoch; the generation and exact
predecessor chain prevent rollback and skipped-state adoption.

The capsule never contains a private key or
`EncryptionRoutePublicationPermit`. Its canonical digest detects storage and
payload mutation; authenticated TLS and TokenReview provide peer identity. The
agent alone may reconstruct WireGuard state, prove local routes and rules, mint
the non-serializable permit, and apply the Aya transaction. The admitted record
is therefore named and logged as desired state, never applied state.

This slice deliberately leaves the controller's prepared-generation producer
empty until the live encryption orchestration path owns the complete inputs.
That makes deployment inert by default while establishing and testing the
real authenticated endpoint, polling, durable recovery, and successor
protocol. TC consumption and live encrypted packets remain later 9.5 slices.

## Consequences

Reconnect cost is constant in history size: the controller either returns the
one exact successor or no content. Node-name reuse cannot inherit authority
because UID disagreement fails before delivery. A captured response cannot
satisfy a fresh nonce, a same-position mutation cannot join the digest chain,
and a skipped generation cannot attach to the durable predecessor. Corrupt or
cross-Node durable state stops before persistent BPF access.

The mechanism does not make the controller a kernel oracle and does not claim
packet encryption, activation, or performance. A future producer must publish
only prepared checkpoints with exact per-Node predecessor state; a future local
orchestrator must still pass Route-Before-Authority before map publication.

## Verification

`make encryption-generation-distribution-test` inherits the Phase 9.5f contract
and checks exact-successor admission, opaque controller-incarnation changes,
nonce replay, Node UID replacement, predecessor/generation regression,
checkpoint and unknown-field mutation, strict count/bank bounds, authenticated
controller scoping, secure agent recovery and no-change retention, static
non-transferability of the route permit, and strict Clippy.
