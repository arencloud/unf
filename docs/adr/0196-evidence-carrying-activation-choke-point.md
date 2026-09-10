# ADR 0196: Evidence-Carrying Activation Choke Point

- Status: Accepted and implemented for Phase 9.6c
- Date: 2026-09-10

## Context

A completed duplex receipt is evidence, not durable activation authority. If an
agent merely checks receipts before Linux convergence, a delayed operation can
publish after expiry, a controller response can cover only a subset of the
generation, or a legacy call path can bypass proof entirely.

## Decision

Phase 9.6c adds the **Evidence-Carrying Activation Choke Point**:

- a non-cloneable, non-serializable permit joins the complete desired fast-path
  digest and exact Node recipient to current duplex receipts;
- every `Required` identity decision must be covered exactly once, while extra,
  duplicate, expired, foreign, wrong-revision, wrong-epoch, wrong-witness, or
  kernel-divergent receipts deny the entire generation;
- the receipt's source kernel-configuration digest must equal the digest already
  bound to that generation's selected transport;
- dormant and native-only generations require an empty proof set;
- the permit is carried through exact Linux convergence beside the consuming
  route permit, then revalidated immediately before inactive-bank staging;
- the former activation API rejects every generation containing a `Required`
  decision, leaving no agent runtime bypass; and
- failed receipt retrieval or validation retains the pending controller-admitted
  capability so retry cannot accidentally discard recoverable authority.

The result is an evidence-carrying transaction rather than a health flag. It
prevents time-of-check/time-of-use drift without putting signatures, variable
objects, or controller calls into the packet path.

## Consequences

Required encryption now stays fail closed until the runtime exchange contains
a current two-ended proof for every selected path. This slice deliberately does
not synthesize proof: the agent-side encrypted nonce executor is the next Phase
9.6 slice. Existing native/dormant recovery retains its established route/map
activation semantics.

## Verification

`make encryption-path-activation-test` inherits the independent ciphertext and
runtime-exchange gates, exercises empty-proof denial and positive exact receipt
consumption, checks that the old activation route denies Required state, tests
agent recovery behavior, and applies strict Clippy to the encryption domain and
agent.
