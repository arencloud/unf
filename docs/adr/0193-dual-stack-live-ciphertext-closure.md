# ADR 0193: Dual-stack live ciphertext closure

- Status: Accepted and implemented for Phase 9.5af
- Date: 2026-09-10

## Context

The verifier and packet-execution gates prove that Required workload packets
receive only an exact, proof-carrying WireGuard route mark. Kernel-provider
readback separately proves the interface, peer, route, and MTU configuration.
Neither proof alone demonstrates that a real kernel transports both inner
address families as ciphertext or that loss of peer authority cannot expose
plaintext.

## Decision

Phase 9.5 closes with an independently observed live-kernel experiment:

- two disposable network namespaces own separate WireGuard interfaces, keys,
  underlay endpoints, and IPv4/IPv6 inner addresses;
- both inner families must complete bidirectional delivery while a capture is
  taken only from the source namespace's underlay device;
- the capture must contain WireGuard UDP and no inner source or destination;
- positive WireGuard transmit and receive counters are required;
- removing the authenticated peer must stop delivery while the only remaining
  inner route still targets WireGuard, so there is no plaintext fallback;
- restoring the exact peer must recover both families; and
- a scoped trap removes both namespaces and all transient keys and capture
  evidence on success or failure.

This gate deliberately does not treat a recent handshake as delivery proof.
The independently captured packet shape and successful inner challenge are
both required. Milestone 9.6 will bind equivalent two-ended evidence to an
authenticated, nonce-bound path witness before production activation.

## Consequences

Phase 9.5 now has a complete proof chain from policy-first TC selection through
real kernel WireGuard ciphertext. The test changes no host route, interface, or
namespace outside its unique disposable names and leaves no key material.

## Verification

`make encryption-ciphertext-live-test` inherits the complete Phase 9.5 packet
composition gate and then proves dual-stack live ciphertext, counter movement,
deny-only peer removal, exact recovery, and cleanup.
