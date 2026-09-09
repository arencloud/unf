# ADR 0167: Route-Before-Authority

**Status:** Accepted and implemented for Phase 9.5f

## Context

Phase 9.5e separated the mark on a plaintext workload packet from the bypass
mark placed on the encrypted WireGuard outer packet. A valid selector alone is
not route authority. Publishing it in Aya before the corresponding route table
and masked Linux policy rule exist can transiently send Required traffic to an
unintended route or blackhole it. Treating a successful netlink acknowledgement
as proof also misses normalized or competing kernel state.

## Decision

UNF introduces **Route-Before-Authority**, a proof-carrying activation barrier:

1. reconstruct and verify the complete fast-path generation;
2. match every referenced transport to a self-verified WireGuard snapshot;
3. independently read back every exact dual-stack route, interface index,
   table, scope, and UNF route protocol;
4. preflight all rule priorities and masked selectors before mutation;
5. install only missing exact IPv4/IPv6 rules and roll back rules created by a
   failed attempt;
6. read every rule back with its mark, mask, table, priority, protocol, action,
   and kernel-normalized attributes; and
7. issue a digest-bound publication permit for exactly one generation and
   fast-path image.

The agent's Aya transaction boundary now requires that local, non-deserializable
capability before it can stage or flip the generation. Only the Linux readback
provider can mint it; controller or checkpoint bytes cannot manufacture one. A
permit cannot authorize another generation or another fast-path digest.
Identical coalesced transports share the minimal rule
per family. Priorities are a deterministic injection of the 16-bit route-mark
lease into the reserved `0x554e0000` priority domain, avoiding an allocator and
making collision diagnosis reproducible.

Pre-existing exact rules are replayed. A same-family priority or masked-selector
collision is foreign state and is preserved. Rules staged successfully before
a later Aya failure remain inert because no packet can emit the unpublished
selector; recovery can safely replay them. Retirement removes only exact rules
after the corresponding generation is no longer authoritative, then proves
their absence. Interfaces and routes remain owned by the separate WireGuard
transaction.

## Consequences

The route, rule, and map domains now form a fail-closed dependency instead of a
timing convention. Kernel normalization is explicitly modeled, partial
readback cannot mint authority, adjacent mark owners remain untouched, and a
crash can resume from exact evidence without broad cleanup. This is a useful
operational property, not a live encrypted-packet claim: controller
distribution and TC consumption remain to complete milestone 9.5.

## Verification

`make encryption-route-authority-test` inherits the Phase 9.5e chain and checks
canonical dual-stack coalescing, snapshot/digest mutation, missing evidence,
partial readback, stale-generation refusal, the Aya permit boundary, static
drift, and strict Clippy. `make encryption-route-authority-live-test` runs in an
isolated user/network namespace and proves real rtnetlink route-first ordering,
masked IPv4/IPv6 rule readback, idempotent replay, exact cleanup, and preservation
of a deliberately conflicting rule.
