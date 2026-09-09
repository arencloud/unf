# ADR 0165: Proof-Carrying Aya Map Mirror

**Status:** Accepted and implemented for Phase 9.5d

## Context

The Causal Commit Vector identifies a fast-path generation, but a digest alone
cannot reconstruct its fixed-width BPF records after an agent crash. The BPF
values deliberately retain only bounded witness and kernel-digest prefixes, so
accepting them from counts or a config pointer would lose the full authority
used by the compiler. Rewriting every unchanged record during rotation would
also waste map syscalls and increase convergence time.

## Decision

UNF adds a **Proof-Carrying Aya Map Mirror**. Its owner-only checkpoint stores
the complete secret-free decision and transport authority beside the existing
map transaction and CCV. Independent replay reconstructs the canonical config,
decision records, transport records, state digest, active/draining frontier,
and full kernel commitments. Any changed field breaks the checkpoint digest or
the reconstructed CCV.

The agent persists `encryption-fast-path.json.pending` before touching the
inactive bank. It then performs **Causal Delta Staging**: sorted current and
desired images retain identical entries, update changed entries, insert new
entries, and remove stale entries. This preserves full-bank semantics while
avoiding redundant writes. Exact byte-for-byte readback is required before the
single `ENCRYPTION_CONFIG[0]` update. Published config and bank are read back
again before the pending checkpoint atomically replaces the committed one.

Restart recovery handles every durable phase:

- Prepared state clears/reconciles and restages only the inactive bank.
- Staged state activates only an exact desired bank.
- A crash after the pointer flip reconstructs the missing staged proof and
  commits only when both config and bank match.
- Committed pending state is adopted idempotently.
- Rolled-back state is removed only with prior-state and positive-absence
  evidence.
- Every mixed, foreign, corrupt, or unbound state refuses startup.

The durable mirror defaults to
`/var/lib/unf/cni/v1/encryption-fast-path.json`, which is already on the
qualified owner-only host-state mount. It contains no private key.

## Consequences

UNF can now recover the exact kernel map image without waiting for the
controller and without trusting truncated dataplane records as authority.
Rotations whose identity-pair policy is mostly unchanged perform work
proportional to the delta while retaining atomic generation publication.

The adapter is wired into startup recovery and exposes the mutation boundary
for the upcoming encryption distribution loop. No TC program consumes these
maps yet, so this milestone does not claim encrypted workload traffic. The next
slice must implement the post-policy/post-Service/post-egress packet selector,
skb-mark preservation, and policy-route enforcement.

## Verification

`make encryption-map-transaction-test` runs the complete Phase 9.5 prerequisite
chain, reconstructs and mutates durable mirrors, checks fixed-width encodings
and recovery rejection, builds the real eBPF object, and applies strict Clippy.
The separate privileged `make encryption-map-backend-live-test` proves that the
kernel accepts all four exact Aya map shapes and that their fresh state recovers
only as quiescent. Packet execution remains a later gate.
