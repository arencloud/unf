# ADR 0231: Expired Authority Recovery

- Status: Accepted and implemented for Phase 9.9 recovery
- Date: 2026-09-11

## Context

A simultaneous reboot of all five cl02 Nodes restored an explicit Native
encryption generation whose map selector was bound to policy revision 428. The
replacement controller reconstructed policy revision 425 and had no retained
fleet-plan payload after the acknowledged frontier had compacted it. The TC
finalizer correctly denied managed identity pairs because the revisions did not
match, while host-network and identity-incomplete traffic remained reachable.

Every Node key checkpoint contained an expired Active epoch and an expired
Prepared successor. Bootstrap recovery handled an abandoned transition only
when no Active predecessor existed. With both slots present it retained them
forever; the controller could not open a current reciprocal-attestation round,
could not reconstruct a fresh Native plan, and returned retryable `503`
responses. Agent and controller service/policy revisions still matched, so the
general convergence view did not expose the encryption-specific deadlock.

## Decision

Add **Expired Authority Recovery** to the Node-local key synchronizer. Before
normal fleet-floor catch-up, it checks the sealed lifetime of an Active epoch.
If that authority has expired, the agent atomically revokes and zeroizes every
retained epoch through the newest transition, advances the monotonic revoked
frontier, and prepares a fresh epoch at or beyond the authenticated controller
floor. A distinct public revocation reason makes this recovery auditable.

The recovery never revokes a still-current Active key, never transfers private
material, and preserves a still-current Prepared or MutuallyAttested successor
even when its Active predecessor has expired. It never treats stale authority
as Native. Existing fail-closed map behavior remains unchanged until a complete
fresh public-key cut, reciprocal attestation, plan, generation, and activation
replace the stale selector.

## Consequences

- An outage longer than both key lifetimes cannot permanently consume the
  bounded two-epoch window.
- A replacement controller can rebuild even an all-Native generation without
  reusing expired key material.
- Recovery may keep managed traffic denied while the fresh fleet proof closes;
  it cannot silently downgrade Required traffic or accept an expired key.
- The fix adds no packet-path work and changes no persistent BPF ABI.

## Verification

`encryption_key_epoch_floor_replaces_fully_expired_active_authority` constructs
an Active predecessor plus Prepared successor, expires both, and proves durable
revocation through epoch two followed by a fresh epoch three. The same test
first proves that an unexpired successor is retained. The complete
`unf-encryption` and `unf-agent` suites (222 passing tests, 20 privileged tests
explicitly deferred) and strict all-feature Clippy pass. The accepting platform
test is a digest-pinned five-Node cl02 reboot recovery followed by the complete
Phase 9.9 qualification gate.
