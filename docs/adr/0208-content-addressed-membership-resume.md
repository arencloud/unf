# ADR 0208: Content-Addressed Membership Resume

- Status: Accepted and implemented for Phase 9.8
- Date: 2026-09-10

## Context

The initial live Kind deployment found that encryption epochs were bound to the
controller's general topology revision. Agent Pod replacement, controller
restart, Service changes, and readiness events advance that revision even when
the cryptographic membership—Node name and immutable Node UID—does not change.
An independently valid Node-local key could therefore become impossible to
republish after harmless control-plane churn. A restarted controller also has
no reason to reopen a reciprocal witness round when every agent already holds a
verifiable mutually-attested readiness certificate.

## Decision

UNF uses **Content-Addressed Membership Resume**:

- the encryption membership coordinate is a domain-separated SHA-256 digest of
  the canonical, length-delimited, sorted Node-name/Node-UID set;
- Pod, controller, readiness, Service, and unrelated topology churn leave the
  coordinate unchanged;
- Node replacement, addition, or removal necessarily changes the coordinate
  and therefore invalidates the prior exact cut;
- a restarted controller reconstructs an already-ready public transparency cut
  directly from mutually-attested agent publications; and
- a new Prepared epoch still requires the complete reciprocal witness matrix.

The coordinate is an opaque causal fingerprint represented in the existing
nonzero revision field. It is not a chronological counter and must never be
used to weaken required encryption or infer freshness without exact membership,
key lifetime, and readiness verification.

## Consequences

Encryption survives controller and agent churn without centralized private-key
escrow, reattestation storms, or plaintext fallback. Node UID replacement still
fails closed before persistent BPF access. The 64-bit wire coordinate is derived
from a full 256-bit digest; exact member comparison remains authoritative in
controller ledgers, so the coordinate is an index rather than sole collision
proof.

## Verification

Controller tests prove that topology/readiness churn preserves the coordinate,
Node UID replacement changes it, a complete Prepared cut still requires all
witness rows, and a fresh controller accepts an already mutually-attested cut
without creating an impossible new round. The Phase 9.8 Kind gate additionally
restarts the live controller and agents before proving encrypted traffic again.
