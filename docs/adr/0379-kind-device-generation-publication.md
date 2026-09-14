# ADR 0379: Matching Kind Whole-Program Generation Publication Gate

Date: 2026-09-14

Status: verified for the isolated publication mechanism

After ADR 0378's cl02 pass, retained Kind passes source `628d26b` on the identical
image `quay.io/arencloud/unf-test-tools-dev@sha256:67fc08aa4825e0002bc5b23d602282e571cd627d50de0a99d3a334ce684879fc`.
The imported manifest and exact digest reference are checked before execution.
Diagnostic BPF SHA-256 remains
`4ce81c6b2606eceb75330d933de977cffac3e450456a83fc0cc463fad6a2d47a`.
Concurrent translated/JIT sizes are 11,256/7,121 bytes, not throughput results.

At 03:39:44 UTC all seventy serial checks pass: thirty exact deliveries and forty
denials, with final counters `[70,30,40,0]`. Nine non-transmitting seeds, two
wrong-context negatives, sticky source/target peer invalidation and explicit
recovery pass. The earlier movement matrix has 2,004 delivered / 37,996 rejected
packets, zero foreign delivery, socket loss or unobserved redirects. All twenty
move/return slot readbacks retain the missing peer reference.

Map sealing, unsealed-publication rejection, frozen-write rejection and forty
empty-dispatch denials pass. All 22 publication IDs match their program/dispatch
readbacks. The separate 40,000-packet publication matrix records 5,018 exact
allow-generation deliveries and 34,982 deny-generation rejections. Independent
ledger replay assigns every sequence exactly once; observed receiver sequences
equal the allow ledger. Foreign delivery, socket drops, final queued bytes and
unobserved redirects are zero.

A's last program reference is replaced while both senders remain active. All
five old authority-map IDs become unavailable with exact-ID ENOENT observations.
This is not an instantaneous-memory-reclamation claim. The remaining frozen
bank still loses its target-peer device slot when that peer moves.

Evidence: `.artifacts/p9-device-lease-628d26b-kind`; archive SHA-256
`dcbff25d9c5bcad5a527d4fd5dcbd76aeb9aeb4d4288b536e2a3e2590a372816`.
Independent payload/counter/binding/publication/retirement checks and both gate
replays pass. Private mounts, network namespaces and the fixture Kubernetes
Namespace are removed, with Node UID unchanged. All three reports finish fresh
and converged at policy 70 / Service 19. Regular UNF containers remain Ready
with zero restarts; init installers remain completed. Both fleets still run
live runtime `f984db9`.

Before/during/publication/after controller, agent and installer logs are reviewed.
The current during window contains one proof-assistance retry; the final current
window has no WARN/ERROR. Retained current/rotated agent CRI is read during and
after; the after audit spans 307,492 lines / 182,202,416 decoded bytes and retains
eleven proof-assistance and three older activation warnings. No ERROR, observer
failure or current byte cap is observed. Rotation and per-packet INFO volume
remain stabilization findings; the final current tail alone is not full evidence.

Both deployed kernels now pass the isolated generation-publication mechanism.
Production authenticated attachment/address/route joins, source-side concurrent
traffic, restart/migration, policy/Service/egress composition, full Phase 9
lifecycle and S1–S5 remain open. No production locality permission is enabled by
this experiment, and no resource-efficiency or superiority claim follows.
