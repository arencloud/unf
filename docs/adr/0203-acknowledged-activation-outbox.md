# ADR 0203: Acknowledged Activation Outbox

- Status: Accepted and implemented for Phase 9.7d
- Date: 2026-09-10

## Context

Remote quorum proves an encrypted path but does not prove that a Node consumed
the receipt and published the corresponding map generation. Inferring
activation from receipt delivery would overstate runtime state. Sending a
best-effort event after map publication would instead lose evidence during a
controller outage, while retrying without identity would inflate counters.

## Decision

Phase 9.7d adds the **Acknowledged Activation Outbox**:

- only after the agent publishes/readbacks the exact map transaction and commits
  its existing recovery escrow does it seal an activation report;
- the report binds authenticated Node name/UID, generation, fast-path state
  digest, activation time, and the canonical exact multiset of contract, epoch,
  and duplex activation-receipt digests. It contains no key, nonce, challenge,
  route permit, or map capability;
- the agent retains one in-memory outbox item until the authenticated controller
  returns `202`. Controller failure leaves it queued and does not revoke or
  broaden dataplane authority;
- no successor activation proceeds while the prior report is pending. Agent
  restart reconstructs active authority through the existing proof-rehydration
  path and reseals a report before accepting a successor;
- the controller validates the Node identity, complete current generation,
  published state digest, plan generation, and exact path multiset before
  recording activation; and
- a durable per-Node cursor makes identical retries idempotent. A fresh proof
  after same-generation restart refreshes the cursor without incrementing
  activation again; regression is rejected. The adjacent 9.7c bare checkpoint
  migrates with empty cursors.

## Consequences

Operational status now distinguishes proven quorum from observed map
activation without placing telemetry on the packet path. Controller outage does
not lose a running agent's acknowledgement, and restart revalidation cannot
manufacture activation volume. The report and cursor remain observational; they
cannot activate traffic.

## Verification

`make encryption-activation-report-test` inherits the live durable-operations
gate, verifies strict secret-free report sealing/mutation refusal, exact outbox
retry/equivocation behavior, current generation/path validation, adjacent
checkpoint migration, durable cursor validation, and strict Clippy across the
encryption library, controller, and agent.
