# ADR 0300: Native Transport Key-Readiness Isolation

Date: 2026-09-13

Status: key-independent Native path implemented; live qualification pending

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

## Implementation and local verification

The new Native producer accepts a separate placement input with no epoch, key,
route table, mark or interface coordinate. Both projection paths reuse Node,
IPAM, workload and policy validation; duplicate workload UIDs are explicitly
rejected. The Native factory rejects a noncanonical model, any intent, Required
baseline, mismatched cluster, invalid placement and revision/capacity overflow.
Its plans contain only Native decisions or explicit dormant membership; exact
map compilation proves zero epochs, transports and paths.

The controller chooses the model and captures revisions/placement under the
same informer guard. Fully Native plans use an explicit absent key dependency
in the internal cache key; ready-key publication and expiry therefore do not
create another Native generation. All other causal inputs and existing
activation/predecessor barriers remain. The Required path still requires the
complete valid key cut. Shared catalog publication keeps persistence and
generation accounting identical across both paths. No wire schema or BPF ABI
changes are needed.

The new controller regression fails on the old implementation's missing first
Native publication. Six added tests cover key-independent controller progress,
activation backpressure, Service revision changes, key-only coalescing/expiry,
Required baseline/intent refusal and transition, exact equivalence to the
existing keyed Native semantics, canonical ordering, zero-epoch map compilation,
invalid authority, and the 65,536-decision bound. All 745 workspace tests pass;
25 environment-dependent tests remain explicitly ignored. Formatting and strict
all-target/all-feature workspace Clippy pass. Private logs are retained under
`.artifacts/s1-native-key-*`.

This isolates only a wholly Native model. A model with any materialized
Required intent still takes the keyed path, including its Native portions;
there is no per-policy best-effort fallback. Key lifecycle recovery, continuous
traffic across metadata churn, Required locality/replica/reply coverage and
the measured resource/scale envelope remain unverified. The new runtime still
needs cl02-first packet/recovery qualification before retained or fresh Kind.
