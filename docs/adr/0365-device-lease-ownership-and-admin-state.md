# ADR 0365: Device-Lease Ownership and Administrative-State Checks

Date: 2026-09-14

Status: locally verified implementation; expanded cl02-before-Kind gates pending

Extend the separate two-ended diagnostic without changing live UNF programs,
maps or authority. Schema 2 adds exact alias checks on all four veth endpoints
and `IFF_UP` checks on both host and peer devices. A down target host must not
be bypassed merely because peer redirect avoids its ordinary egress path.

Expected aliases come from the real `VethPlan::from_attachment` derivation,
through a bounded fixture-only adapter. It requires a Ready record with UID and
nonzero creation nonce and rejects oversized input. Its two explicit tests
exercise all owner-key fields, UID/nonce changes, unbound/unready records and
the actual maximum 96-byte alias. These are synthetic private fixture records,
not authenticated Kubernetes objects or independently verified CNI journals;
the adapter alone confers no authority.

The classifier reads each kernel alias using the bounded string helper and
compares all bytes as thirteen aligned words, including termination/padding.
Reading beyond the maximum valid string length distinguishes an exact alias
from a longer string sharing its prefix. No shortened digest/prefix comparison
or raw kernel pointer export is introduced. Wordwise comparison bounds the
loop work; no CPU/throughput improvement is claimed without measurement.
Linux's alias replacement uses RCU-delayed reclamation; see the primary
[device implementation](https://github.com/torvalds/linux/blob/v5.14/net/core/dev.c).

The checked BTF decoder preserves the original observation schema and adds a
separate ownership layout. It validates flags, the alias pointer and the trailing
flexible byte array, and requires agreement across all base/module variants
(at most 32 combinations). Four positive and 52 negative layout cases pass;
retained cl02/Kind inventories both resolve flags/alias-pointer/string offsets
176/312/16. Metadata replay is not kernel execution. BPF compilation, strict
example Clippy, formatting, 807 workspace tests (26 ignored) and two separate
adapter tests pass locally.

The expanded serial platform gate requires 62 exact attempts: 28 delivered and
34 denied. It retains all previous lifetime cases and adds missing/modified
aliases at each endpoint, first/middle/last digest and role changes, a longer
prefix collision, maximum-length positive controls, and target host down/up.
All denials now require classifier rejection; peer-down is checked before
requesting redirect. Recreated targets deliberately clone indices, MACs and
aliases, so metadata equality cannot implicitly rearm a retired device binding.

A new immutable fixture must pass cl02 before retained Kind. The prior serial
mechanism gates remain valid only for their older images/matrix. Concurrent
movement, immutable publication/retirement, exact packet address/placement joins,
real attachment readback, policy/Service/egress composition and the production
consumer remain open. Neither this implementation nor matching synthetic aliases
enable a live plaintext exception or close full Phase 9/stabilization S1–S5.
