# ADR 0375: cl02 Four-Endpoint Invalidation Gate

Date: 2026-09-14

Status: verified for the isolated sticky-invalidation mechanism; Kind pending

Source `01c5d11` passes the complete cl02 fixture on anonymously verified image
`quay.io/arencloud/unf-test-tools-dev@sha256:dfdbde13b5da8d094106abf7b12cbd998e69ba5003dca42e08ec88d3ad82f5bf`.
Diagnostic object SHA-256:
`dd3af7874c760527fbe2de36a2aaa802cfce06b4d1ba8677731ddd825f04cc04`.
All three classifiers load; concurrent translated/JIT sizes are 9,888/6,149 bytes.

At 02:24:22 UTC all seventy serial/recovery attempts pass: thirty exact delivered
payloads and forty armed-receiver denials, with every counter matching. All eight
non-transmitting context seeds, both wrong-context rejections, full aliases,
administrative state, old-schema rejection and cloned-index replacement checks
also pass. The foreign positive control again delivers all forty packets there.

Initial bindings read `[201,301,202,302]`. Target-peer movement changes this to
`[201,301,202,null]`; returning unchanged leaves it missing. Source-peer movement
similarly leaves `[201,301,null,302]` after return. Both cases deny traffic until
explicit idle rebind, which restores the positive controls. This is direct
kernel-map slot evidence, not an inferred missed userspace notification.

The 40,000-packet concurrent run observes 996 IPv4 / 998 IPv6 original deliveries,
1,994 redirect requests and 38,006 classifier rejections. Both foreign receivers
receive zero; all receivers have zero socket drops and an empty final queue.
Every one of the twenty move/return binding snapshots retains the missing
target-peer slot. Traffic remains denied after the final return, and explicit
post-race rebind restores both families. No entry is rebound during senders.

This run has **zero unobserved redirects**, with the baseline address-restoration
ordering unchanged. It obtains that result by staying revoked after the first
move, not by transparently delivering through all returns. Recovery availability
therefore depends on explicit verification/republication. It is not a throughput
improvement, a global lossless-handoff guarantee, or attribution of every earlier
two-reference loss. Those baseline observations remain retained.

Evidence: `.artifacts/p9-device-lease-01c5d11-cl02`; raw archive SHA-256
`fe33761407cfe3e0e31643827dce14fd5dba3aac019ba6767782da22f91ef810`.
Independent gate replay, all payloads and exact slot snapshots pass. Private
resources and the fixture Namespace are removed; Node UID is unchanged. All five
reports finish fresh/converged at policy 483 / Service 203. UNF containers remain
Ready with zero restarts on unchanged live runtime `f984db9`.

Before/during/after controller, every agent and installer logs are reviewed.
The final complete window includes 433 bounded flow-history warnings, nineteen
proof-assistance retries, four bounded topology-history warnings, one reciprocal
key-attestation publication rejection and one clsact exclusivity warning. No
live UNF ERROR, panic, OOM or verifier rejection is observed. Existing Insights
upload failure and network-operator configuration degradation remain visible.

Matching retained Kind must pass this exact image next. Production immutable
publication, source-side concurrent traffic, authenticated attachment/address
joins and policy-first composition remain open, as do full Phase 9 and S1–S5.
