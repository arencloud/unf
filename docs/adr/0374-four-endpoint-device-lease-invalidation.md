# ADR 0374: Four-Endpoint Device-Lease Invalidation

Date: 2026-09-14

Status: locally checked experiment; cl02-before-Kind qualification pending

The two-host-reference baseline in ADRs 0372–0373 detects a peer's current
namespace, but allows it again after it returns. A userspace snapshot can miss
the entire move/return interval. Investigate a stronger kernel-owned lifetime
boundary: hold device-map references to all four actual veth endpoints, including
both peers, and require every binding before packet consumption.

The upstream [device-map notifier](https://github.com/torvalds/linux/blob/v5.14/kernel/bpf/devmap.c)
removes entries by the actual device object on `NETDEV_UNREGISTER`, with deferred
RCU reclamation. The [namespace movement implementation](https://github.com/torvalds/linux/blob/v5.14/net/core/dev.c)
closes/unregisters the moved device before changing its namespace. This suggests
sticky peer invalidation without polling or a lossy tracing notification. The
deployed kernels still require explicit qualification; upstream source is not
a substitute for those tests.

The disposable map now has four slots: source host, target host, source peer,
target peer. Each peer is bound from its own exact fixture namespace. Diagnostic
configuration schema 3 requires all four entries before packet-time readback;
the seed requires both target entries. The old two-reference schema 2 is rejected.
Kernel-layout metadata remains schema 2 because its field layout is unchanged.

The context adapter can read the four public device indices, returning null
only for an actual missing key. Wrong map type/capacity, unexpected program
binding and syscall failures remain errors. It never reads or exports the
private cached kernel pointer. This gives direct evidence of which reference
was invalidated, independently of a failed traffic probe.

The expanded 70-attempt serial/recovery gate requires 30 exact deliveries and
40 denials. Both source and target peer movement must remove only the expected
slot. Returning unchanged must leave it missing and traffic denied; an explicit
idle rebind must restore delivery. During the 40,000-packet concurrent target
move/return run, all twenty slot readbacks must retain the missing target-peer
entry. After traffic ends, another denied pair and explicit-rebind positive pair
prove no implicit recovery. All eight context seeds and the foreign positive
control remain mandatory; current cookie/alias/index checks are retained too.

The fixture deliberately keeps the baseline address-restoration order unchanged
to isolate this mechanism change. Requested but unobserved redirects remain
reported, not called lossless delivery. Disposable entries are explicitly rebound
only while senders are idle; this is not a production bank-publication protocol.

The separate BPF object builds with SHA-256
`dd3af7874c760527fbe2de36a2aaa802cfce06b4d1ba8677731ddd825f04cc04`.
Two context-adapter tests, three-positive/141-negative concurrency gate checks,
four-positive/52-negative layout checks, formatting and strict workspace/all-target
Clippy pass. Full workspace tests retain 807 passes and 26 ignored tests.
cl02 must pass the complete immutable fixture before matching retained Kind.

This investigation does not yet close production lifetime, authenticated CNI /
placement/address joins, immutable generation pairing, packet composition,
source-side concurrency or full Phase 9/S1–S5. Holding four references has a
bounded structural cost; CPU/memory and kernel-unregister scale remain unmeasured.
