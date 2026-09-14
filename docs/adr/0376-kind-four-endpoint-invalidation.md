# ADR 0376: Matching Kind Four-Endpoint Invalidation Gate

Date: 2026-09-14

Status: verified for the isolated sticky-invalidation mechanism

After ADR 0375's cl02 pass, retained Kind passes the identical source `01c5d11`
image `quay.io/arencloud/unf-test-tools-dev@sha256:dfdbde13b5da8d094106abf7b12cbd998e69ba5003dca42e08ec88d3ad82f5bf`.
The imported manifest and digest reference are checked. Diagnostic object SHA-256
remains `dd3af7874c760527fbe2de36a2aaa802cfce06b4d1ba8677731ddd825f04cc04`.

At 02:30:22 UTC all seventy serial/recovery attempts pass: thirty exact payload
deliveries and forty denials, with every counter matching. Eight non-transmitting
context seeds, two rejected contexts and the forty-packet foreign positive control
pass. Both source and target peer movement remove their specific device-map slot;
return leaves it missing. Explicit idle rebind restores delivery.

The 40,000-packet concurrent run observes 1,001 unique deliveries per family,
2,002 redirect requests and 37,998 classifier rejections. Both foreign receivers
observe zero, all socket-drop/queue counters are zero, and there are zero
unobserved redirects. All twenty move/return readbacks retain the missing target
peer slot. The post-race denied pair and explicit-rebind positive pair pass.
Concurrent translated/JIT sizes are 9,888/6,171 bytes, not a throughput result.

This mechanism deliberately remains revoked after movement. These bounded results
therefore do not mean transparent handoff, unlimited scale or production lifetime
closure. They demonstrate kernel-owned sticky invalidation without depending on
userspace observing the movement interval. Full authenticated re-publication and
recovery availability still need consuming integration.

Evidence: `.artifacts/p9-device-lease-01c5d11-kind`; raw archive SHA-256
`5fdfb533260bbc1db91b1952b2786aa6d3fff02627bec51ee1fd340f8a2ecb71`.
Independent gate replay, payload/counter review and slot checks pass. Private
resources and the fixture Namespace are removed, Node UID preserved. All three
reports finish fresh/converged at policy 67 / Service 19. Regular UNF containers
remain Ready with zero restarts; init installers remain completed. Both live
fleets still run `f984db9`.

Before/during/after controller, every agent and installer logs are reviewed. The
final current window contains no WARN/ERROR. Retained current/rotated agent CRI
logs total 333,949 lines / 197,896,778 decoded bytes, including older proof and
activation retries. No live UNF ERROR, panic, OOM or verifier rejection is observed.
INFO amplification and prior reliability findings remain open for stabilization.

Both deployed kernels pass the isolated four-endpoint mechanism. Next is safe
generation publication: packet readers must not combine old cached pointers
with replacement binding tables. Source-side concurrent traffic, authenticated
live attachment/address/route joins, policy-first composition, full Phase 9
lifecycle and stabilization S1–S5 remain open.
