# ADR 0368: Non-Transmitting Device Context Acquisition

Date: 2026-09-14

Status: locally verified adapter; cl02-before-Kind qualification pending

Replace packet-based target seeding in the isolated device-lease fixture with
a private classifier invocation through `BPF_PROG_TEST_RUN`. This removes the
need to attach a seed filter to the target's egress path or send a special UDP
packet through it. The seed classifier itself remains unchanged and always
returns drop; actual delivery qualification still uses real IPv4/IPv6 traffic.

The Linux skb test-run implementation resolves a requested device index in the
caller's network namespace, holds a device reference, builds the actual kernel
skb and invokes the classifier inside RCU. It returns packet/context buffers
without running a networking transmit path. See the primary
[kernel implementation](https://github.com/torvalds/linux/blob/v5.14/net/bpf/test_run.c).
This is used to acquire a device context, not to simulate evidence of delivery.

The bounded adapter uses Aya's existing API, a zero-filled stable `__sk_buff`
prefix containing only the requested index, and one complete synthetic IPv4/UDP
frame. It checks the drop return value, unchanged frame, bounded output context,
exact returned index and the private seed program's ownership-check result.
It does not export kernel pointers or report test-run timing as network
performance. Only the disposable candidate pointer/seed-status fields are
cleared before acquisition and on an unsuccessful invocation; live maps,
journals, history and authority are never reset.

The fixture requires four successful non-transmitting seeds and two rejected
contexts (wrong device and an absent device in a foreign namespace), including
cleared old seed status and explicit recovery. Target qdisc inspection must
show no ingress/clsact seed attachment before or after acquisition. The full
62 real traffic attempts remain mandatory: 28 exact deliveries, 34 classifier
denials and all per-probe counters. No failed observer is counted as a denial.

Two explicit adapter tests cover context bounds/encoding and the complete frame
checksum/header shape. All 807 workspace tests pass (26 ignored), along with
strict workspace/all-target Clippy and formatting. The diagnostic BPF object
is unchanged from the qualified ownership/admin-state mechanism. Runtime
qualification must start on cl02 and then use the identical image on retained
Kind; local tests and upstream source inspection do not qualify deployed kernels.

This remains a private experiment, not the production publisher. Concurrent
movement, immutable generation/entry pairing, authenticated live attachment and
address joins, packet composition and consuming integration remain open. Full
Phase 9 and stabilization S1–S5 are not verified by this adapter.
