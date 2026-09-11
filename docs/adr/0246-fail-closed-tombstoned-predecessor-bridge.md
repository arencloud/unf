# ADR 0246: Fail-Closed Tombstoned Predecessor Bridge

## Status

Accepted

## Context

The ADR 0245 cl02 rollout reconstructed the exact durable admission for pending
generation `1789160696724`, but its only key epoch, 12, had already been
durably revoked through epoch 31 by expired-authority recovery. Recreating or
activating that key would violate revocation. Erasing the admission would also
break the controller frontier, while compiling its successor directly would
skip the map transaction's physical predecessor.

All five Nodes stopped before TC startup with no plaintext fallback. Their
state agreed: physical active generation `1789160626300`, admitted pending
generation `1789160696724`, desired generation `1789161534529`, and current
key epochs 32/33.

## Decision

Introduce a Fail-Closed Tombstoned Predecessor Bridge. It is available only
when the exact durable admission and recovery plan agree, the plan precedes the
authenticated desired generation, every referenced local key is durably
tombstoned, and the admitted transaction immediately extends the physical map
checkpoint.

The transition:

1. persists the complete verified admitted predecessor in an owner-only map
   bridge before mutation;
2. zeros the shared encryption config and removes connection leases, making
   every identity-complete packet fail closed even if an older TC link remains
   attached;
3. removes only the tombstoned pending routes and WireGuard stage, while moving
   its recovery plan to a distinct durable tombstone slot;
4. retains that admission as the controller's logical predecessor while the
   prior committed map remains the physical recovery checkpoint; and
5. lets only an exactly admitted, route-proven, duplex-path-proven successor
   consume the bridge. Its commit removes both bridge records and sends the old
   physical transport through ordinary bounded retirement.

Every write boundary is restartable. A bridge with an active old config is
fenced again; a bridge with zero config remains denied; a successor pending
checkpoint binds the logical predecessor; and a completed successor retires a
leftover bridge only after exact map readback. Mixed available/tombstoned,
unknown, empty, non-adjacent, conflicting, or malformed authority fails closed.

## Consequences

- Revoked key material is never regenerated, reused, or treated as path proof.
- Controller ancestry and physical map recovery can advance without pretending
  the skipped generation ever carried live packet authority.
- The ADR 0245 tuple remains valid Kind evidence but is not eligible to resume
  cl02. This runtime requires fresh full Kind qualification, immutable public
  images, and the complete five-Node OpenShift gate.
