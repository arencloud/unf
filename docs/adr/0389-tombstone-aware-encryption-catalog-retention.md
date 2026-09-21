# ADR 0389: Tombstone-Aware Encryption Catalog Retention

Date: 2026-09-21

Status: implemented; local verification recorded below; live qualification pending

ADR 0387's Required admission failed while a Node could no longer supply epoch
6117. ADR 0388 preserves the later Native recovery and missing successful-key
timeline. A deterministic regression now reproduces one concrete retention gap:
a contract remains wall-clock-valid after the local authority positively retires
its key, but the controller's unactivated-catalog barrier still considers that
contract current. This is not yet proof that it was the sole live failure cause.

The controller now checks authenticated local key tombstones when deciding
whether to retain an unactivated plan. A borrowed transparency-ledger lookup
binds cluster ID and exact Node name/UID and recognizes only a nonzero epoch at
or below its monotonically admitted retirement/revocation frontier. It does not
clone key cuts or enumerate workload pairs. Missing publications, another Node
incarnation, another cluster and ordinary rotation are not tombstone evidence.
Native/dormant plans remain key-independent. The existing current-membership
check, catalog monotonicity and exact successor admission remain authoritative.

This only removes an impossible catalog-retention barrier. It does not revive a
key, extend expiry/drain windows, bypass pending-generation ownership or path
proofs, activate a map, authorize plaintext, or reset a journal. All those
consuming boundaries remain unchanged.

The regression uses real Node key authority, activation, rotation, zero-state
drain proof and authenticated public-ledger admission. Before the repair it
fails at post-retirement retention; after the repair it passes. It also covers
revocation, valid draining-key retention, absent publications, validity edges,
foreign cluster/name/UID, epoch zero, a still-resident successor, Native/dormant
independence and publication invalidation after membership replacement.

Successful key activation/retirement and adopted plan generation/epoch summaries
now use `unf_agent::encryption_lifecycle`. The OpenShift log filter enables that
target at INFO while retaining WARN for ordinary agent/per-packet events. It
logs no key bytes or credentials and does not turn packet observations into INFO
output. Exact live timing still requires reviewed complete log streams.

Local evidence under `.artifacts/p9-retired-catalog-*`: red regression exit 101,
green regression, workspace 821 passed / 26 ignored, strict all-target Clippy,
formatting and OpenShift package validation. Privileged and platform gates are
not included in those unit-test counts. Build immutable committed-revision
images next, qualify on cl02 first, then matching Kind. Required locality
consumption, L4/L5/Q, Phase 9.8/9.9 and stabilization remain open.
