# ADR 0091: Disperse bounded NodePort SNAT allocation

**Status:** Accepted and implemented; live restart evidence pending (2026-08-30)

## Context

The first complete Phase 5.7 recovery run preserved the service connection map
while replacing a worker agent. The replacement attached successfully and
reported converged state, but new `Cluster` NodePort flows were dropped with
`PAIR_INSERT_FAILED`. The original allocator inspected 32 adjacent ports in the
dynamic/private half of the port space. Ordinary short-flow churn occupied that
correlated window, so a free port elsewhere in the 32,768-port allocation range
could not be reached.

Increasing the adjacent probe count is not a sound remedy. It retains the
clustering behavior and can also push the verifier's bounded analysis over its
instruction limit.

## Decision

`Cluster` NodePort SNAT keeps a verifier-bounded 32-probe budget, but each flow
walks the complete 32,768-port range using a deterministic odd stride derived
from the upper half of its service-flow hash. An odd stride is coprime with the
power-of-two range, so the candidate sequence is a full-cycle permutation and
does not repeatedly inspect an adjacent correlated window.

The algorithm is shared between the no-std eBPF crate and host tests. It does
not alter persistent ABI v5, map layouts, connection keys, timeout semantics,
or reverse translation.

## Consequences

- A bounded allocation attempt samples dispersed ports while preserving a hard
  verifier and latency budget.
- Existing connection pairs remain valid across compatible agent replacement.
- Exhausting all 32 candidates still fails closed with
  `PAIR_INSERT_FAILED`; production-scale sizing remains a later qualification.
- Changing the hash or probe sequence in the future requires explicit churn,
  verifier, and restart-regression evidence.

## Verification

The shared unit test proves unique, in-range candidates and simulates 4,096
sequential short TCP flows without exhausting the bounded search. The focused
privileged gate proves that the release eBPF object passes the kernel verifier
and retains collision-safe dual-stack NodePort translation. The full
`make nodeport-kind-test` gate must additionally reproduce controller-offline
agent replacement with live traffic before this ADR and milestone 5.7 become
live verified.
