# ADR 0378: cl02 Whole-Program Generation Publication Gate

Date: 2026-09-14

Status: verified for the isolated publication mechanism; matching Kind pending

Following both preserved fixture failures in ADR 0377, source `628d26b` passes
the complete cl02 gate on anonymously verified immutable image
`quay.io/arencloud/unf-test-tools-dev@sha256:67fc08aa4825e0002bc5b23d602282e571cd627d50de0a99d3a334ce684879fc`.
Diagnostic BPF SHA-256 remains
`4ce81c6b2606eceb75330d933de977cffac3e450456a83fc0cc463fad6a2d47a`.
The concurrent classifier translates/JITs to 11,256/7,099 bytes; this is not a
throughput or resource-efficiency measurement.

At 03:33:39 UTC all seventy serial attempts pass: thirty exact payload deliveries,
forty armed-receiver denials, final counters `[70,30,40,0]`. Nine non-transmitting
context seeds and two wrong-context rejections pass. Both source and target peer
movement invalidate their exact device-map slots; return does not rearm them.
The earlier 40,000-packet movement matrix delivers 2,004 and rejects 37,996,
with zero foreign delivery, socket loss or unobserved redirects. All twenty
move/return snapshots retain the missing peer slot; explicit recovery succeeds.

The publication gate rejects an unsealed bank and writes to both frozen device
maps. An empty dispatcher rejects forty armed-receiver packets. All 22 published
program IDs match their readbacks; each publisher requires exact sealed authority
map identities held through the syscall. The dispatch program references only
its dispatch table and counters, not an old bank's authority maps.

During the separate 40,000-packet publication matrix, the allow generation
delivers exactly 8,634 packets and the deny generation rejects 31,366. Independent
replay of the complete per-generation sequence ledgers assigns every sequence
exactly once, and actual receiver sequences equal the allow ledger. Foreign
delivery, receiver socket drops, queued bytes and unobserved redirects are zero.

While both senders are still running, removal of A's owned pins followed by the
final B publication retires all five old authority-map IDs. Each lookup fails
with the exact requested ID's JSON ENOENT. This proves ID unavailability, not
instantaneous physical reclamation. Moving the remaining bank's target peer
still produces `[201,301,202,null]` despite user freezing.

Evidence: `.artifacts/p9-device-lease-628d26b-cl02`; archive SHA-256
`095c4f988ec773cc333d371fdee65e86fc362ff27f18fd565d1b981b5dab78f4`.
Independent payload, counter, binding, publication, retirement and gate replay
checks pass. Both private mounts, all owned network namespaces and the fixture
Kubernetes Namespace are removed. Node UID is unchanged. All five live reports
finish fresh/converged at policy 501 / Service 203; UNF containers remain Ready
with zero restarts on unchanged live runtime `f984db9`.

Controller, every agent and installer logs are reviewed before, during,
publication and after. No log-read failure or byte cap occurs. The final window
contains 417 bounded flow-history, 26 proof-assistance, three bounded topology
and two key-publication warnings, with no ERROR entries. These remain explicit
stabilization findings, not a clean-log claim.

The same immutable image must pass retained Kind next. This is an isolated
two-bank diagnostic, not a production publisher or authenticated live
attachment/address/route consumer. Source-side concurrent traffic, production
restart/migration, policy/Service/egress composition, full Phase 9 lifecycle and
S1–S5 remain open. No unlimited-scale or superiority claim follows.
