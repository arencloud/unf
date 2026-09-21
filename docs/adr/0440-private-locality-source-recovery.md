# ADR 0440: Private locality source recovery

Date: 2026-09-21

Status: implemented; local checks pass; cl02-first qualification pending

Retain the authenticated placement response and its original request as bounded
compiler input, not as a serialized bank or capability. Offline replay requires
the complete independently current applied context and independently replays
the original source projection and certificate. Unknown fields/schema, changed
nonce, source or context are rejected. The original nonce is never reused for
a new request. File provenance, not a JSON checksum, authenticates saved input.

The agent uses a root-owned, single-link, private regular file in a validated
directory chain. Reads use NOFOLLOW/NONBLOCK and a 32-MiB bound; FIFO, symlink,
hard-link, writable-parent and oversized files are rejected. Saves use an
exclusive mode-0600 temporary, streaming byte limit, file fsync, rename and
directory fsync. Foreign cluster/Node and incompatible saved headers are
preserved and refused. Only the exact owned temporary can be cleaned on error.

Disk I/O and replay share the existing single bounded background worker slot.
Cancellation does not release that slot while blocking work is still running.
Recovery is attempted once per process, never rearmed by clearing a failed
candidate. Missing/stale input falls back to a fresh authenticated fetch.
The event-loop handoff rechecks the full current cut; the real journal join,
fresh incarnation gate, device/route observations and bank publisher remain
mandatory. Saved input restores no kernel or packet authority.

Status distinguishes controller versus private-checkpoint input and checkpoint
durability. Persistence failure warns but does not invalidate an independently
authenticated online candidate. A same-context candidate currently does not
retry failed persistence until another fetch/restart; bounded retry remains an
explicit follow-up, not an asserted disk-fault recovery guarantee.

Local verification: 912 workspace tests pass, 31 privileged tests remain ignored;
strict agent/encryption all-target Clippy passes. The expanded main-composition
gate adds the real root-filesystem and offline acquisition-worker test before
the existing publisher/socket matrix. Those privileged checks must pass on
cl02 before the identical immutable image runs on Kind.

This is source recovery, not a complete process-restart traffic proof. Fresh
bank reconstruction after restart, crash-stage pin cleanup, actual authenticated
fleet reconciliation, DSR/mixed/remote Required traffic and consuming status
remain open. No production runtime or release pin changes. Phase 9 L3/L4/L5/Q
and stabilization S1–S5 are not promoted.
