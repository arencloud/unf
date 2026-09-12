# ADR 0272: Atomic bounded endpoint proof publication

Date: 2026-09-12

Status: Implemented; full cl02 qualification pending

## Context and decision

Thousands of independently authenticated endpoint proofs previously required
one HTTP request and token-file read apiece. That transport overhead consumed
the same finite lifetime needed for duplex activation.

The additive internal `/v1/state/encryption-path-proof-batches` endpoint accepts
schema v1, one exact generation and 1–64 independently valid proofs. The agent
publishes sequential bounded chunks and reads its token once per publication
pass. No unbounded request fan-out or larger HTTP body limit is introduced.
The old single-proof endpoint remains for controller-first rollout; new agents
require the successor controller and fail closed if it is unavailable.

The coordinator stages only the touched endpoint ledgers, not contracts or the
fleet catalog. It rejects invalid schema, size, generation, duplicate/unknown
round, foreign endpoint and expired/mutated evidence before committing anything.
A rejected tail cannot retain a valid prefix. Successful retry is idempotent;
each newly admitted proof still emits its normal operational observation and
two-ended completion still requires the independently authenticated peer.

## Verification and remaining gates

The regression verifies atomic rejection, duplicate refusal, empty/over-limit
bounds, generation/schema fencing, foreign endpoint, expiry, pending/complete
admission, idempotent retry and strict JSON shape. This batches transport, not
trust: existing single-proof validation and receipt schemas remain unchanged.

The complete successor must pass local checks, immutable publication, the cl02
gate first and fresh Kind second. ADR 0269's transient checkpoint-size failure
also remains a tracked recovery risk. Phase 9 and heavy-load readiness remain
unverified until their respective exit criteria pass.
