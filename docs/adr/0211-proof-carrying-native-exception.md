# ADR 0211: Proof-Carrying Native Exception

- Status: Accepted and implemented for Phase 9.8d
- Date: 2026-09-10

## Context

The Phase 9 domain model could express a `Native` cluster baseline plus
identity-pair encryption intent, but the Kubernetes runtime always produced a
`Required` model with no intents. Merely allowing every pair absent from an
encryption selector to bypass the encryption map would turn missing or stale
authority into plaintext permission. Creating empty WireGuard epochs for such
pairs would waste kernel state and misrepresent transport proof.

## Decision

UNF implements a **Proof-Carrying Native Exception**:

- a namespaced `EncryptionPolicy` selects source and destination workloads by
  namespace, ServiceAccount, application, and labels; destinations default to
  the policy namespace and bidirectional intent defaults on;
- the fresh-install default remains cluster-wide `Required`; an operator must
  explicitly set the `Native` baseline to use selective encryption;
- the controller materializes selectors against the current immutable workload
  identities and publishes their own monotonic intent revision;
- informer relists use a staging map and atomically replace the complete policy
  cut, preventing a transient plaintext window;
- every policy-authorized cross-Node pair receives an explicit, revision-bound
  `Required` or `Native` decision; absence, ambiguity, or stale revisions still
  fail closed; and
- a Node containing only Native decisions activates a transport-free causal
  generation with zero epochs, routes, peers, and keys. This is positive packet
  authority, not a dormant or missing-authority shortcut.

Kernel WireGuard remains the sole cryptographic provider. Required intent is
monotonic and cannot weaken a Required cluster baseline.

## Consequences

Selective encryption is now usable from Kubernetes without a tunnel per
policy or workload. It is safe for incremental adoption because the plaintext
case is explicit and auditable, while controller outage or relist cannot turn
unknown pairs into Native. Selector and decision capacity remain deliberately
bounded. Phase 9.8 still requires one immutable Kind runtime to prove both the
default-required and explicit-selective modes with ciphertext capture,
composition, rotation, failure/recovery, observability, and exact rollback.

## Verification

`make encryption-selective-policy-test` validates the checked-in CRD, atomic
watch behavior, identity materialization, native-only causal generation, packet
selection, missing-authority denial, prior Phase 9 evidence, and strict Clippy.
