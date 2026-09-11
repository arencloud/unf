# ADR 0240: Tombstone-Aware Generation Handoff

## Status

Accepted

## Context

During the cl02 simultaneous-reboot recovery, one worker restarted CRI-O after
its fully expired key authority had been durably revoked. Its active generation
journal still named the predecessor epoch. Exact Linux readback could no longer
reconstruct that volatile proof, and repair correctly rejected the now-unknown
private key. Repeating repair indefinitely kept the Node fail closed, but also
prevented the authenticated successor generation from using the newly prepared
fleet-aligned epoch.

The journal is still valuable rollback and ownership evidence. Treating every
missing epoch as stale, deleting the journal, or attaching the old dataplane
would weaken recovery safety.

## Decision

Classify every epoch/public-key pair referenced by a verified Node-local
recovery plan against the verified Node key publication:

- an exact non-Prepared live epoch is available;
- an absent epoch at or below the durable retired/revoked frontier is
  tombstoned; and
- a key mismatch, Prepared current epoch, or unknown epoch above that frontier
  is an error.

When, and only when, the volatile `ControllerAdmitted` reconstruction of the
active slot references a tombstoned authority, discard that volatile object and
its path-proof escrow. Preserve the durable admitted predecessor, recovery
journal, map checkpoint, Linux journal, and kernel attachment. Exact rehydration
also refuses to repair a tombstoned plan.

The agent may then compile the authenticated current plan and advance it through
the ordinary generation exchange, path proof, controller admission, route
permit, map commit, and retirement sequence. Until that successor completes,
the restored dataplane remains fenced and Required traffic cannot fall back to
plaintext.

## Consequences

- A durably revoked/retired key cannot be recreated or revalidated.
- Unknown or equivocal key state remains a hard startup failure.
- Recovery does not erase durable ownership evidence or mutate kernel state by
  inference.
- A fresh successor is the only route back to readiness, and it must carry the
  complete normal proof chain.
- Fresh full Kind qualification and independent cl02 qualification remain
  mandatory before Phase 9.9 can be Verified.
