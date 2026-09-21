# ADR 0399: Kernel Attribute-Tag Layout Compatibility

Date: 2026-09-21

Status: Kind failure retained; parser repair locally verified, live reruns pending

ADR 0398's exact image reaches persistent Kind but fails before BPF loading,
at native layout discovery. The parser rejects a legitimate kind flag in
Linux `7.2.5-200.fc44.x86_64` metadata. Base type 82007 is a TYPE_TAG named
`address_space(1)` referencing void; its raw info word is `0x92000000`.
The independent reference parser had already completed. No device classifier
is installed by this failed attempt.

[Linux's BTF specification](https://docs.kernel.org/bpf/btf.html#btf-kind-type-tag)
defines kind flag one for compiler-attribute TYPE_TAG and DECL_TAG records.
It changes annotation interpretation, not binary record size. The native reader
incorrectly allowed the flag only on composite/enum/forward records.

Add a red regression reproducing the exact unsupported-flag rejection, then
accept only these two additional documented flag/kind combinations. Tagged
references retain the same depth, target-type and shape checks. Declaration
tags retain their fixed four-byte payload; both kinds require bounded nonempty
names. Invalid vlens, names, target/cycle mutations and truncation remain errors.
This interprets layout metadata, not pointer permissions or packet authority.

The repaired parser passes eleven layout tests, 836 workspace tests (26
privileged tests ignored), strict all-target Clippy and formatting. Offline
public-metadata replay reproduces cl02's previous offsets and Kind's independent
reference offsets, including their different namespace-cookie positions. That
replay is not live kernel/traffic qualification. Rebuild the immutable fixture
and rerun the complete cl02 gate before retrying Kind.

Failed evidence: `.artifacts/p9-device-lease-e2e98ad-kind`; archive SHA-256
`71d7a6796710ec77586111507c3bbcd1faf9d974e40a44849cf1119b99261d59`.
Private namespaces and the exact fixture Namespace are removed; both existing
Kind CNI journals are byte-identical. All three fresh reports converge at policy
38 / Service 19. Current/init and retained CRI log review completes with one
proof-assistance warning and no ERROR. The live fleet remains `6d71a30`.
L3, L4/L5/Q and stabilization remain open; no failed result is promoted.
