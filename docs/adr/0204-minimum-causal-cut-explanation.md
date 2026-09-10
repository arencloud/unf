# ADR 0204: Minimum Causal Cut Explanation

- Status: Accepted and implemented for Phase 9.7e
- Date: 2026-09-10

## Context

An operator should not have to mentally join policy, placement, plan, endpoint
proof, remote quorum, activation, expiry, and evidence-loss state to understand
why a required path is unavailable. A simple last-error field is misleading:
later evidence cannot repair an earlier missing prerequisite, and retained
history may be incomplete. Simulation must also be useful without acquiring
authority or changing the evidence it evaluates.

## Decision

Phase 9.7e introduces **Minimum Causal Cut Explanation**:

- policy is evaluated first for the exact Pod pair, family, protocol, and port;
- same-Node paths explicitly report that no underlay encryption hop exists;
- cross-Node required paths walk the ordered causal ladder: assignment, both
  endpoint proofs, remote quorum, and both durable post-map activations;
- the first absent, expired, withheld, or loss-affected prerequisite is emitted
  as `minimumMissingStage` with one bounded `nextAction`, while exact generation,
  contract, epoch, policy revision, and retained-evidence count preserve context;
- `/v1/encryption/explain` is a current-state explanation. `/v1/encryption/simulate`
  can withhold one stage or advance evaluation time, is marked non-authoritative,
  and cannot write the ledger, activation cursors, desired state, or dataplane;
  and
- `unfctl encryption-status`, `encryption-history`, `encryption-explain`, and
  `encryption-simulate` expose the evidence without private keys, probe nonces,
  route permits, or reusable activation authority.

## Consequences

The result is a causally minimal repair hint rather than a dump of symptoms.
Bounded evaluation is independent of packet rate, and counterfactual diagnosis
cannot perturb the system being diagnosed. Loss is never converted into proof;
when retained evidence cannot establish a prerequisite, the explanation stays
conservative and marks the result loss-affected.

## Verification

`make encryption-operations-query-test` inherits the complete live encryption
and durable evidence chain, checks policy-first and same-Node outcomes, ordered
missing-stage selection, expiry and withholding, exact CLI request encoding,
strict deserialization, simulation immutability, and strict Clippy.
