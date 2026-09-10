# ADR 0198: Mark-Multiplexed Duplex Rendezvous

- Status: Accepted and implemented for Phase 9.6e
- Date: 2026-09-10

## Context

The controller can assign a fresh two-ended proof round and the kernel provider
can install non-workload beacon addresses, but neither is packet evidence. A
live agent must exchange the exact nonce through the isolated WireGuard route,
read counters around that exchange, and retain the resulting authority until
map activation. Rotation may temporarily expose two epochs that share the same
local beacon and UDP port. Binding one socket per interface would also add an
unnecessary `NET_RAW` capability to the constrained OpenShift agent.

## Decision

Phase 9.6e adds the **Mark-Multiplexed Duplex Rendezvous**:

- a strict 72-byte request/response frame carries only magic, schema, kind,
  required family, exact round digest, and the controller nonce;
- each agent resolves assignments only against its pending generation, exact
  Node UID, contract path, epoch, interface, fwmark, and derived beacon pair;
- isolated policy routes are installed and independently read back before any
  socket can send, while encryption maps remain unpublished;
- one UDP socket is bound per local family/beacon, and `SO_MARK` is selected per
  exchange immediately before sending. Active and draining epochs can therefore
  share the fixed rendezvous port without listeners, port growth, or `NET_RAW`;
- independently scheduled agents symmetrically request, respond, retry at a
  bounded cadence, and remain responsive for a peer retry grace interval;
- only an exact peer address, family, round, nonce, and response kind seals the
  non-cloneable delivery object; its transcript digest becomes endpoint-proof
  authority together with positive kernel counter movement;
- concurrent address-family groups avoid serial dual-stack delay, while all
  work is bounded by the earliest round expiry and a four-second local ceiling;
- the first exact endpoint proof for a round is held only in volatile memory and
  reused on controller retry, preventing a retry from manufacturing different
  counter authority for the same nonce; and
- complete current controller receipts, route authority, and path authority are
  consumed together at the final inactive-bank mutation boundary. Any error is
  retryable and leaves Required traffic unpublished rather than falling back to
  plaintext.

This is not a userspace data path. The socket carries only short-lived proof
frames; workload encryption and cryptography remain entirely in kernel
WireGuard.

## Consequences

The agent retains its established `BPF`, `NET_ADMIN`, and `PERFMON` capability
boundary. Proof traffic uses the exact full-Pod-CIDR WireGuard route and cannot
grant policy, Service, egress, or encryption-map authority by itself. Process
restart intentionally discards volatile proof objects and repeats a fresh
controller round; no reusable activation credential is persisted.

The focused gate proves protocol, orchestration, mutation refusal, retry, and
capability structure. A two-agent live runtime exchange and failure injection
are still required before milestone 9.6 is marked Verified.

## Verification

`make encryption-path-executor-test` inherits all prior encryption gates,
including real dual-stack beacon ciphertext, then tests strict fixed-frame and
delivery semantics, path-proof joins, agent recovery invariants, source wiring,
capability preservation, and strict Clippy.
