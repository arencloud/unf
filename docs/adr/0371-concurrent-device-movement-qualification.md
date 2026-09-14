# ADR 0371: Bounded Concurrent Device Movement Qualification

Date: 2026-09-14

Status: locally verified fixture; cl02-before-Kind kernel qualification pending

Extend the isolated device-lease gate with simultaneous sequenced IPv4/IPv6
traffic during ten target-peer move/return cycles. This tests the next lifetime
boundary without enabling live plaintext or changing either UNF fleet.

A separate classifier calls the same two-ended redirect checks but records
attempts, redirect requests and classifier rejections in per-CPU counters.
Userspace sums them only after senders finish. Serial seed/status counters
remain separate; no shared last-stage field is treated as a concurrent ledger.
The fixture never rebinds the device map or changes its expected cookies while
the movement senders run. All twenty post-move link snapshots must preserve
the exact peer index, complete owner alias and administrative-up state.

Four receivers are bound in the original and foreign namespaces before traffic.
They validate run tokens, family, exact sender, bounded sequence and complete
payload shape, rejecting duplicates and malformed/foreign packets. They retain
the exact live UDP socket inode and require zero kernel socket drops and an
empty receive queue before closing. Missing accounting is an observer failure.
The fixed 32-byte payload and bounded sequence storage avoid per-packet logs.

A separate private positive control explicitly names the foreign namespace's
cookie, seeds its context, and must deliver all twenty packets per family there
with zero original-namespace deliveries. The original cookie is then restored
and re-seeded while idle. This diagnostic control proves the foreign receiver
and path work; it is never a production permission or an implicit fallback.

The movement phase sends 20,000 packets per family at a requested one-millisecond
interval without catch-up bursts. Both original receivers must observe positive
delivery; neither foreign receiver may receive a packet. All 40,000 attempts
must reconcile exactly with classifier requests/rejections, with both outcomes
present. Requested but unobserved redirects are reported separately rather
than called deliveries or silently hidden as receiver loss. The result explicitly
keeps lossless handoff and complete concurrent lifetime unverified.

The six observers are joined by an exact run token; control and stress tokens
must differ. Bounded subprocess deadlines, owned-PID cleanup and retained final
counter/link/route evidence apply on failure too. The runner observation budget
is extended to 360 seconds for the serial gate plus concurrent windows, still
inside the existing Pod deadline. No live maps, journals or history are reset.

Three observer tests and a gate with three positive / 141 negative cases pass
locally. All 807 workspace tests pass (26 ignored), strict workspace/all-target
Clippy and formatting pass, and the separate BPF object builds. Diagnostic object
SHA-256: `966550be9202456e8268e028c1f8c8ba90d1453f50e66af01cfb3566daaf880f`.
Kernel loading, socket accounting and the complete traffic gate still require
cl02 first, then identical-image retained Kind.

This is a bounded target-peer race experiment, not production scalability,
source-peer concurrency, immutable bank publication or authenticated placement /
attachment integration. Packet composition, full Phase 9 and S1–S5 remain open.
