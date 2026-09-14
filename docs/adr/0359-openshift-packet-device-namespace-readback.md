# ADR 0359: cl02 Packet-Time Device/Peer Namespace Readback

Date: 2026-09-14

Status: verified for the isolated drop-only readback primitive; Kind pending

Source `6fc49da` passes the complete cl02 gate on immutable image
`quay.io/arencloud/unf-test-tools-dev@sha256:1db67d8051aa15e1c10b5ad883c4f921b90f86ff670e145cf2b01151023b5351`.
Anonymous registry inspection confirms the full source-revision label.
Separate diagnostic BPF object SHA-256:
`f49e36ee72db18521455de2a008c4babbd7f26c5d1d0c7b470f54d8efe7d07e9`.
The prior jq and verifier failures remain recorded in ADR 0358.

The RHCOS kernel accepts the corrected schema-2 word-index program. Actual
program readback reports a 3,304-byte translated classifier and 2,176-byte JIT
body; these sizes are not a CPU or throughput benchmark. The classifier is
attached only to the owned disposable fabric veth, with two one-entry maps
on a separate private bpffs mount. Live UNF interfaces/maps are unchanged.

Nine successful observations match exact context/read-back interface indices
and independently opened socket namespace cookies: IPv4/IPv6 baseline, peer
move into the foreign namespace, peer return, host rename, and configuration
recovery. A deliberately invalid configuration reports the exact failure stage
with no stale namespace data. All ten probes are counted individually. Cookies
are compared as bytes, without floating-point conversion. Every packet is
dropped; neither forwarding nor a local Required exception is exercised.

Evidence: `.artifacts/p9-device-observation-6fc49da-cl02`.
Raw fixture archive SHA-256:
`77d27ed0adcbf3ac4b3c57591e8d6ae2567349c1f08430613de74d389e04d8a0`.
All private network namespaces, diagnostic attachments and the private bpffs
mount are cleaned up, and the Kubernetes fixture Namespace is absent. The Node
UID is preserved. Current UNF containers remain Ready with zero restarts;
all five reports finish fresh/converged at policy 460 / Service 203.

Controller, every agent and installer logs are reviewed before/during/after.
The final window includes all diagnostic attempts and cleanup. Live UNF logs
contain bounded-history warnings, proof-assistance retries and one key-
publication rejection; no live UNF ERROR, panic, OOM or verifier rejection is
observed. This does not erase the earlier isolated diagnostic verifier failure
or claim operationally clean logs. Runtime remains `f984db9`, Native by default.

This qualifies current packet-device/peer namespace introspection on cl02,
not continuous safe delivery or authenticated ownership. Source/target alias
and incarnation binding, target discovery/lifetime, concurrent movement,
banked generation publication, post-policy/Service/egress forwarding and measured
cost remain open. `kernelAdmitted` and `observedDelivery` stay false. The same
immutable fixture must pass retained Kind next; full Phase 9/S1–S5 stays open.
