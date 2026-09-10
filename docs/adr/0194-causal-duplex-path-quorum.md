# ADR 0194: Causal Duplex Path Quorum

- Status: Accepted and implemented for Phase 9.6a
- Date: 2026-09-10

## Context

A configured WireGuard peer and a recent handshake do not prove that the exact
policy-authorized workload path currently carries encrypted packets in both
directions. One endpoint's view can also remain apparently healthy during
asymmetric routing, stale endpoint state, counter stalls, or Node replacement.

## Decision

Phase 9.6a introduces the **Causal Duplex Path Quorum** (CDPQ). One short-lived,
OS-CSPRNG nonce binds the exact contract digest, decision witness, Node
name/UID pair, key epoch, and required address families. Each authenticated
endpoint independently joins four evidence planes:

1. byte-exact interface, peer endpoint/key, AllowedIPs, routes, fwmark, MTU,
   and configuration-digest readback before and after the challenge;
2. positive receive and transmit counter movement for the exact peer;
3. the same domain-separated request/response transcript over every required
   inner family; and
4. a fresh Pod-bound Node identity matching the endpoint role.

The ledger is append-only for a round. It rejects same-role equivocation and
does not issue an activation receipt until both distinct roles are present.
Every proof and the final receipt has a separate domain, digest, and deadline.
Handshake time is deliberately excluded as admission authority.

This is useful beyond simple tunnel health: failures remain attributable to an
evidence plane, asymmetric paths cannot be hidden by the healthy endpoint, and
proof lifetime bounds the interval in which topology or roaming drift could
invalidate a result.

## Consequences

The receipt is secret-free and durable for provenance, but is not itself map or
route mutation authority. Phase 9.6b wires authenticated runtime collection and
consuming activation so a serialized receipt cannot be replayed after restart.

## Verification

`make encryption-path-proof-test` inherits the complete Phase 9.5 live gate and
proves dual-ended completion, one-sided refusal, expiration, endpoint roaming,
counter stall, nonce replay, mutation, and strict unknown-field rejection.
