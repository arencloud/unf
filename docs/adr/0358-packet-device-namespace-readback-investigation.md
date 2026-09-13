# ADR 0358: Isolated Packet Device/Namespace Readback Investigation

Date: 2026-09-14

Status: diagnostic implemented; kernel verifier and platform evidence pending

L3's continuous source/peer lifetime boundary cannot be closed by retained
namespace snapshots or delayed userspace link notifications alone. Investigate
reading the current packet device and its veth peer's namespace identity inside
the TC program. This is a proposed prerequisite, not yet a production design
or permission to deliver local Required plaintext.

Linux 5.14's base helper dispatch offers fault-checked kernel reads subject to
capability and lockdown checks. Its TC helper path and namespace-move ordering
motivate testing the actual cl02 verifier, rather than assuming that current
kernel introspection is either unavailable or sufficient. Relevant primary
sources: [helper dispatch](https://github.com/torvalds/linux/blob/v5.14/kernel/bpf/helpers.c),
[TC helper/redirect implementation](https://github.com/torvalds/linux/blob/v5.14/net/core/filter.c),
[namespace move ordering](https://github.com/torvalds/linux/blob/v5.14/net/core/dev.c).
The diagnostic follows the kernel's
[netdev private-data alignment](https://github.com/torvalds/linux/blob/v5.14/include/linux/netdevice.h)
and [veth private peer field](https://github.com/torvalds/linux/blob/v5.14/drivers/net/veth.c),
with actual field offsets checked against running-kernel BTF, not copied from
workstation headers.

The separate Rust/Aya example copies a bounded skb prefix, validates its device
index against the ordinary TC context, then reads current device/peer namespace
cookies. Faults or invalid configuration produce an explicit failure stage.
The private result map exports indices, cookies, serial diagnostic counters
and stage only: no kernel pointers. Every packet returns `TC_ACT_SHOT`. This
object is distinct from the live UNF object and has no production attachment,
generation authority, forwarding or plaintext-exception branch.

A bounded isolated layout decoder validates structures, aliases, pointers,
integer widths, field offsets and ambiguity, with at most 64 visited member
containers per lookup and bounded queue/depth. It currently supports explicitly
checked little-endian x86-64 fixtures only. One positive and twenty malformed
layout tests plus two cyclic/wide-work-budget mutations pass. Actual cl02
metadata resolves skb-device offset 16, device
index 224, device-network pointer 264, namespace cookie 4096 and private peer
pointer 2816 bytes. Local decoding of that captured 16.8-MB JSON inventory
uses 332,092 KiB maximum RSS / 1.38 seconds in one run; this is diagnostic
tooling cost, not a packet-path or production resource benchmark. Allocate a
separate bounded fixture budget accordingly; do not change live resource limits.

The standalone Rust socket helper checks the fixed-size Linux
[SO_NETNS_COOKIE ABI](https://github.com/torvalds/linux/blob/v5.14/include/uapi/asm-generic/socket.h).
Its narrow, documented FFI is confined to the qualification example because
the current safe socket dependencies do not expose this option. Cookies are
compared as little-endian hexadecimal bytes, avoiding JSON integer rounding.

The pending isolated gate requires nine exact packet observations across
IPv4/IPv6 baseline, peer move/return, host rename and configuration recovery,
plus one invalid-configuration rejection. Each cookie must equal an independent
socket observation in the corresponding private namespace. No positive result
is emitted without the complete gate and cleanup. The program uses diagnostic
serial counters, not concurrent/lossless telemetry. Full delivery lifetime,
concurrent movement, source/target ownership, banked generation/policy/Service/
egress composition, verifier portability and performance remain separate work.
Run cl02 first, then the identical immutable image on retained Kind.
