# ADR 0271: Lifetime-bound proof catalog reuse

Date: 2026-09-12

Status: Implemented; full cl02 qualification pending

## Context and decision

Every assignment pull, endpoint proof POST and receipt pull previously cloned
and verified the full fleet-plan cut before the coordinator could decide that
nothing had changed. ADR 0269's live cut was approximately 22 MiB with 5,972
selections. Compact storage alone did not remove this repeated work.

A serialized synchronization boundary now retains only a fixed-size stamp:
generation, exact cut digest, and the current proof-round time interval. The
catalog independently verifies publication, rejects same-generation
equivocation and exposes only immutable references. An exact live stamp can
therefore return before cloning or replaying that already-admitted cut.

Changed generation/digest, unavailable catalog, backward time or expiry cannot
use the fast path. Slow-path contract ownership, time checks, complete-cut
integrity verification, coordinator generation fencing and operational evidence
remain intact. The stamp is published only after successful synchronization;
renewal remains serialized and the stamp grants no endpoint or map authority.
Its expiry is bounded by both the proof lifetime and every active contract.

## Verification and remaining work

The controller regression runs 1,000 unchanged requests without replacing the
stamp, rejects altered generation/digest and out-of-window time, and confirms
expiry re-enters synchronization. Strict all-target/all-feature controller
Clippy passes. This does not replace the pending cl02 proof-exchange gate or
subsequent Kind qualification. Bounded batched proof publication and the
transient checkpoint-size gap remain separate follow-ups.
