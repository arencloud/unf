# ADR 0218: Proof-Time Exact Kernel Self-Healing

- Status: Accepted and implemented for Phase 9.9
- Date: 2026-09-11

## Context

The post-high-watermark Kind run exercised its intentional WireGuard link fault
while natural rotation remained live. Linux retained the owned link after it was
raised but removed its IPv6 proof address and connected policy-table routes.
UNF correctly rejected the resulting non-exact readback. The controller had
already admitted the successor, however, so the agent retained its original
single-use convergence capability and retried proof without invoking the
existing digest-bound restart repair. One endpoint therefore failed readback
while its peer timed out at rendezvous.

Treating a merely present interface as healthy would weaken kernel truth.
Creating another generation would turn repairable local drift into fleet churn.
Restarting the agent just to reach the startup repair path would add disruption
and operational coupling.

## Decision

Before every admitted pending proof attempt, the agent replays the exact durable
recovery plan through the idempotent Linux provider using its Node-local private
key authority. The provider may restore only the recorded UNF-owned link,
addresses, peers, routes, MTU, mark, and port. Fresh readback must reconstruct a
new non-serializable convergence capability and byte-match the existing
controller admission; the original route permit and admission remain fenced
through the repair.

An exactly revalidated active Node performs the same repair before serving a
fresh reciprocal proof round. It discards the reconstructed capability and all
receipts, retaining no new packet authority. Empty local transport plans require
no key or kernel mutation.

## Consequences

- External down/up events heal in place without accepting partial Linux state,
  restarting the agent, or manufacturing a generation.
- Repair is constrained by the durable plan digest, exact ownership alias,
  current Node UID, local private/public key match, and independent readback.
- Foreign state, missing key authority, mutated admission, partial convergence,
  or rollback failure remains fail closed with the predecessor authoritative.
- Pending and already-active proof participants share one exact repair boundary,
  preventing one-sided rendezvous loops.

## Verification

The activation-rehydration gate requires both pending and active proof-time
repair paths and the existing provider repair primitive. Agent tests and strict
Clippy must pass. The full Kind gate deliberately lowers the exact owned link,
then requires natural rotation, agent and controller recovery, ciphertext,
traffic continuity, cleanup, and rollback before publication.
