# ADR 0300: Native Transport Key-Readiness Isolation

Date: 2026-09-13

Status: observed coupling; implementation and qualification pending

ADR 0299 retains the failed `b5bf6c6` cl02 packet gate. Readiness, all-node
generation agreement and policy/Service convergence did not imply traffic
health. The retained Native generation was bound to the previous controller's
causal revisions while new policy/Service maps advanced. Normal key rotation
and catch-up warnings accompanied a plan endpoint that returned no successor.

The controller currently obtains a complete public key cut and a common ready,
unexpired epoch before considering the encryption model. The producer likewise
requires ready keys even when every emitted decision is Native and every
Node plan has zero epochs, transports and paths. Consequently a key readiness
gap can prevent publication of unrelated, explicitly Native transport decisions.
Revision mismatch remains fail-closed in the dataplane; do not bypass it or
seed arbitrary revisions to disguise the missing publication.

Introduce a separate key-independent publication path only for a complete,
normalized Native model with no Required intents. It must preserve exact
authoritative membership, placement/IPAM validation, policy-first behavior,
locality/isolated-return coverage, capacity bounds, complete fleet publication,
predecessor receipts and activation/retirement proof. It must emit no fabricated
key, epoch, route, path or cryptographic capability. Required baseline or any
materialized Required intent must continue through the strict keyed path;
unready keys must never cause a fallback from Required to Native.

Separate placement/policy projection from cryptographic path projection so the
Native path does not invent a dummy epoch or compute unused WireGuard paths.
Keep key lifecycle/attestation active independently. Ignore key-only changes in
the Native plan's causal cache key, but retain membership, identity, policy,
Service, routing and intent changes. Reuse the existing generation and wire
contracts where their zero-epoch Native semantics already suffice.

Add deterministic regressions before implementation: Native publication without
key readiness, unchanged/key-only input coalescing, exact revision updates,
Required refusal without keys, and transition back to Required without Native
downgrade. Then rerun local checks and commit/push; build immutable images and
qualify cl02 before recovering retained Kind. Traffic continuity under metadata
churn and Required locality/replica/reply coverage remain separate open gates.
Any performance improvement requires equal-workload measurements, not inference
from eliminating a code path.
