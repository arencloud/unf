# ADR 0397: Bounded Native Kernel Device Layout Discovery

Date: 2026-09-21

Status: implemented and locally verified; cl02-before-Kind live gate pending

L3's isolated device-lifetime programs currently obtain offsets with bpftool
and jq. The production agent image does not contain either tool. Introduce
`unf_link::kernel_layout::KernelDeviceLayout`: a safe, read-only native reader
of the current kernel's base and optional split-veth BTF. It borrows binary
payloads and indexes type offsets, avoiding an expanded JSON object inventory
or subprocess dependency in the future consuming integration.

The parser follows [Linux BTF encoding](https://docs.kernel.org/bpf/btf.html)
and [libbpf's split type/string coordinates](https://github.com/libbpf/libbpf/blob/master/src/btf.c).
It bounds base/module bytes at 32/4 MiB, combined types at 200,000, alias depth
at eight, member visits/queue at 64, members per traversed container at 512,
and identifier scans at 4,096 bytes. These are logical work/input bounds, not
an allocator RSS promise. Only the covered little-endian v1 24-byte header is
accepted; unknown encodings and extended headers fail closed.

All base/module definitions of the five required structures must agree in
sizes and offsets. Duplicate names within one inventory, wrong pointer targets,
integer widths, bitfields, anonymous-member ambiguity, invalid references,
cycles and out-of-container reads are rejected. On newer metadata a flexible
`net_device.priv` member must agree with the qualified historical aligned-tail
geometry. That geometry is a kernel implementation assumption, not stable UAPI:
[Linux 5.14 netdev_priv](https://github.com/torvalds/linux/blob/v5.14/include/linux/netdevice.h)
uses the aligned tail, while newer kernels expose `priv` directly. The real
kernel device probe remains mandatory; offsets alone cannot prove it works.

The result is immutable and not deserializable. Its domain-separated digest
binds the input bytes for diagnostics, not authenticity, boot identity or
packet permission. Live discovery is restricted to x86-64 little endian and
must run off the asynchronous event loop. Missing module metadata is accepted
only if the required veth type is present in base BTF; no guessed fallback exists.

Ten unit tests cover built-in and split layouts, relocated duplicate types,
malformed header/record/field mutations, every truncation, byte/type/traversal
budgets, private-tail disagreement and every single-bit input mutation without
panic. The workspace suite passes 835 tests (26 privileged tests ignored);
strict all-target Clippy, format and shell syntax
checks pass. The existing independent jq oracle's four positives and 52
negatives also pass.

The separate immutable qualification image reuses ADR 0379's digest-pinned
device fixture and rebuilds only the native reader. The fixture now uses its
offsets for actual BPF configuration, requires equality with independently
derived bpftool/jq offsets and repeats native discovery with an identical digest.
Complete delivery, denial, lifetime and publication checks still apply.
No production image, wire schema, map ABI, live packet path or release pin
changes in this milestone. Live qualification follows cl02 first, then Kind.

L3 still needs the production attachment/placement/route join and immutable
packet consumer, including pure-local Required demand and policy/Service/egress
composition. L4/L5/Q and stabilization remain open. No CPU/memory saving or
performance-superiority claim is made without equal-workload measurements.
