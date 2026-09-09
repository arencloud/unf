# ADR 0184: Reciprocal Key Witness Matrix

- Status: Accepted and implemented for Phase 9.5w
- Date: 2026-09-10

## Context

Independent pairwise acknowledgement can split a fleet: early Nodes may mark a
key ready while a slow or replaced peer still observes another public frontier.
An acknowledgement also loses its authenticated origin if the controller
blindly relays an unsigned payload.

## Decision

Phase 9.5w introduces the **Reciprocal Witness Matrix**.

The controller freezes one complete public-key transparency cut into an
immutable, digest-bound round. Every current TokenReview-authenticated Node
submits exactly one deterministic row acknowledging every other member's exact
Node UID, key epoch, barrier digest, and its own public epoch. The controller
binds the transport-authenticated identity to that row and rejects foreign,
partial, reordered, mutated, expired, or topology-stale input.

No recipient column is released until all N rows exist. Each column contains
exactly N-1 acknowledgements and embeds the complete round, so an agent can
independently replay membership and all acknowledgement fields. The round
issuance time makes retries and process restarts byte-identical.

The agent durably applies its complete column to the private Node-local key
authority before publishing the `MutuallyAttested` public phase. A crash between
acknowledgements recovers exact prior progress; incomplete matrices convey no
readiness authority and private key material never enters the protocol.

## Consequences

- Slowest-member backpressure prevents partial-fleet key readiness.
- Controller relay preserves authenticated origin instead of trusting a claimed
  peer UID in an acknowledgement body.
- Deterministic rows make retries idempotent without a second private journal.
- The O(N²) control-plane evidence is bounded to 4,096 members and never enters
  the packet path; runtime transport remains one coalesced peer per Node.
- This milestone proves mutual key readiness, not kernel activation or encrypted
  traffic. Those remain independently gated.

## Verification

`make encryption-key-attestation-test` inherits the durable bootstrap gate and
tests exact matrix withholding/release, authenticated row admission, stable
retry, immutable rounds, independent cut verification, durable agent recovery,
public phase republishing, and strict Clippy across all affected binaries and
the encryption domain.
