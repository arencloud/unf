# ADR 0385: Live Journal Inventory Candidate Observer

Date: 2026-09-21

Status: qualifier verified locally; cl02-first runtime gate pending

Extend the existing Required reply gate with opt-in
`UNF_REQUIRED_REPLY_REQUIRE_LOCALITY_INVENTORY=true`. It requires both existing
locality-candidate and CNI UID/nonce ownership gates; it cannot replace either.
The runtime candidate is ADR 0384's committed source `d007071`.

Require fresh observations after each polling stage starts, positive integral
attachment/address/payload counts during Required admission, address counts
covering the dual-stack fixture population, no more than two addresses per
attachment, no more selected addresses than replayed placement, and a logical
payload within the implementation's 16-MiB limit. Native baseline and retirement
must positively report zero for all three counters. HTTP/API errors fail the
run; every failed poll and its exact status remain in evidence.

The counters establish an aggregate candidate-inventory observation, not a
per-record kernel proof, atomic journal/API snapshot or packet-time permission.
Separate real fixture UID/nonce checks, policy denials, ciphertext capture,
traffic and cleanup remain required. The full Phase 9 locality matrix and
production consumer remain open even when this bounded gate passes.

Local validation: four positive and 47 negative inventory cases pass, including
missing/wrong-type/fractional/negative fields, impossible cardinalities, payload
overflow and incomplete retirement. The previous locality gate still passes
two positive and 105 negative cases. Shell syntax checks pass. Live cl02 must
precede independent matching Kind; an unavailable retained cluster is not a pass.
