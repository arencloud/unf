# ADR 0209: Secret-Aware Positive Rollback

- Status: Accepted and implemented for Phase 9.8
- Date: 2026-09-10

## Context

The Phase 9 Kind rollback removed encryption programs, links, maps, routes, and
ordinary CNI state, but the first live attempt proved that owner-only key and
plan checkpoints remained. Besides preventing an exact no-CNI baseline, blindly
deleting the parent directory would weaken UNF's foreign-state preservation.

## Decision

The primary-CNI rollback has a **Secret-Aware Positive Rollback** boundary. It
recognizes only the four exact encryption checkpoint names, their exact secure
temporary names, and the `encryption-keys/authority.json` island. Before removal
it validates real non-symlink files/directories, mode 0600/0700, the 64 MiB
bound, positive schema, exact Node name/UID, bounded epoch count, fixed key and
checkpoint-digest shapes, and absence of unknown siblings.

Private material is never printed, copied into qualification artifacts, or sent
to the controller. Any unknown, malformed, foreign, over-sized, or differently
owned state stops rollback.

## Consequences

Successful rollback now positively proves absence of both packet authority and
durable secret/recovery authority. Interrupted rollback is resumable from the
same exact boundary. Foreign state remains untouched because deletion follows
validation rather than pathname globbing.

## Verification

The installer contract checks the encryption cleanup boundary statically. The
Phase 9.8 gate runs the real three-Node rollback after encryption activation and
requires no UNF link, route, pin, CNI artifact, checkpoint, or key directory to
remain before accepting the no-CNI baseline.
