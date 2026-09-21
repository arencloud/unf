# ADR 0409: Preserve Progress of a Viable Attested Key Transition

Date: 2026-09-21

Status: regression-backed repair; immutable cl02-before-Kind runtime qualification pending

## Reproduced failure

ADR 0407's cl02 log audit found repeated transition-below-fleet-floor errors.
A deterministic two-member regression reproduces one cause using actual durable
key authorities and complete reciprocal cuts, without a live key-state reset:

1. Both members activate epoch 1 and prepare epoch 2.
2. Both reciprocal rows exist, but only the faster member consumes its epoch-2
   cut. It drains/retires epoch 1 and proactively prepares epoch 3.
3. The real transparency ledger therefore reports issuance floor 3. The slower
   member still has active epoch 1 and a valid prepared epoch 2.
4. Previously, bootstrap reconciliation returned an error before publication
   and consumption of the already-complete epoch-2 cut. The member was stranded
   despite having valid evidence for progress, until expiration recovery.

The retained red test fails with `active encryption transition epoch 2 is behind
fleet floor 3` in `.artifacts/p9-key-progress-red.log`. This reproducer does not
claim to explain every rejected-witness warning from the live fleet.

## Decision and safety boundary

For an existing active authority plus a **nonexpired** Prepared/MutuallyAttested
successor, a higher issuance frontier no longer prevents the ordinary
publication/attestation exchange. The floor includes another member's highest
issued epoch; it is not itself revocation of every lower retained epoch.
Reconciliation changes no key state at this boundary and mints no activation
permission. Complete-cut, exact recipient/membership, lifetime, barrier, causal
acknowledgement and predecessor-drain checks remain unchanged.

The regression performs 64 unchanged reconciliations, verifies byte-identical
durable state, rejects incomplete and expired cuts without mutation, then
finishes the exact epoch-2 cut and converges both members through epoch 3 with
no emergency revocation. A separate shorter-successor-lifetime case preserves
rejection of an expired below-floor transition without revoking its still-valid
active predecessor. Existing abandoned-initial-epoch, full-expiry recovery,
drain deferral, UID fencing and complete-cut-only tests remain required.

The key-publication warning now retains the error cause chain, instead of only
an outer context string. It does not dump requests, authentication or private
key state. No key wire schema, map ABI, encryption baseline or packet-enforcement
rule changes in this repair.

## Verification boundary

All 865 workspace tests pass (26 privileged ignored), as do strict all-target
Clippy, formatting and diff checks. Evidence is retained in
`.artifacts/p9-key-progress-{workspace,clippy-2}.log`. The rebuilt
runtime must be qualified on cl02 first, then the identical images on persistent
Kind, preserving CNI/key journals and reviewing all current/retired logs.
Require actual key-transition progress and the complete scoped Required
traffic/reply/ciphertext gate; a Ready Pod is not sufficient.

This does not close the other ADR 0407 warning causes, production locality-bank
publication/consumption, migration, L3/L4/L5/Q or Phase 9.
