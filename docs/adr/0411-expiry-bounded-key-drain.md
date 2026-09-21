# ADR 0411: Bound Key Drain by the Predecessor's Sealed Expiry

Date: 2026-09-21

Status: regression-backed repair; cl02-before-Kind runtime qualification pending

ADR 0410 exposes a second obstacle after viable transition progress is restored.
The actual durable-agent regression reproduces its exact `epoch drain window
is invalid` failure when a fully attested successor is consumed near or after
the predecessor's expiry. Red evidence is retained in
`.artifacts/p9-drain-expiry-red.log`.

## Decision

The requested drain duration remains positive and bounded by the existing
maximum. Its resulting deadline is now capped at the predecessor's original
`valid_until_unix_ms`. The successor still requires complete attestation, exact
topology and a valid activation lifetime. A late valid successor can activate
without pretending that the predecessor has a fresh positive lifetime.

An expired predecessor becomes Draining with its original, already-expired
deadline. It remains in the bounded two-epoch authority until positive
zero-flow/zero-route retirement is proved. There is no immediate key deletion,
emergency revocation, lifetime extension, Native fallback, or state reset.
Normal early rotation retains the exact existing requested drain deadline.

Durable activation continues to clone, validate, persist, then publish state.
A failed write leaves the prior authority unchanged. Public/private schemas,
causal acknowledgement checks, map ABIs and packet programs are unchanged.
Existing readers already accept the resulting bounded drain timestamps.

## Verification

New regression coverage includes:

- actual two-member durable activation 500 ms before, exactly at and after
  predecessor expiry; checkpoint restoration preserves the same deadline;
- a 16-case arrival/window matrix proving the deadline never exceeds either
  the requested window or original key expiry, without changing key material;
- unchanged rejection of zero/oversized windows, expired or not-yet-valid
  successors, missing attestation and foreign topology;
- injected durable-write failure preserving the original publication and
  write count, followed by a successful retry; and
- refusal to retire while either a flow or owned route remains, with exact
  checkpoint preservation until a positive zero-state proof is provided.

All 870 workspace tests pass (26 privileged ignored), along with strict
all-target Clippy, formatting and diff checks. Evidence is retained in
`.artifacts/p9-drain-expiry-{workspace,clippy}.log`. Rebuild immutable images and repeat
cl02 provenance, recovery, traffic/ciphertext and live key-progress qualification
before testing the matching images on Kind. Preserve ADR 0410's failed attempt.

This repairs a key-lifecycle boundary, not production locality-bank publication
or consumption. L3/L4/L5/Q, Phase 9 and S1–S5 remain open.
