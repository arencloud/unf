# ADR 0369: cl02 Non-Transmitting Device Context Qualification

Date: 2026-09-14

Status: verified for the isolated context acquisition mechanism; Kind pending

Source `fcccf05` passes on cl02 using the anonymously verified immutable image
`quay.io/arencloud/unf-test-tools-dev@sha256:58bd85080f9e7414b9787ed70704f5aae628170a12fdfc410be8bb108c909ffa`.
The diagnostic BPF object remains unchanged from ADRs 0366–0367:
`d74d24720e08886870fa6e64e582068b74534d2f6915d81bd1c5f61e0a7e2558`.

At 01:46:11 UTC the complete fixture passes four context acquisitions without
network seed transmission or a target ingress/clsact filter. All eight target
qdisc snapshots pass. A wrong device fails the actual ownership check; the
absent device in the foreign namespace fails the kernel invocation with
`ENODEV`. Both rejected attempts clear the private candidate/status, and an
explicit valid invocation recovers. No unrelated observer error is counted
as an expected rejection.

The unchanged 62 real IPv4/IPv6 probes also pass: 28 exact payload deliveries,
34 armed-receiver timeout denials and every per-probe counter. Final counters
are 62 seen, 28 redirect requests and 34 classifier rejections. Context-test
execution itself is not delivery evidence or a performance measurement.

Evidence: `.artifacts/p9-device-lease-fcccf05-cl02`; raw archive SHA-256
`67c7a636b35d04693b5d02df00cd63280a2721bb795e8f53492cbee14cad45cc`.
Owned private resources and the fixture Namespace are removed; Node UID is
unchanged. All five agent reports finish fresh/converged at policy 474 /
Service 203. All live UNF containers remain Ready with zero restarts on the
unchanged `f984db9` runtime.

Controller, all agents and installers have before/during/after log review.
The final complete window remains below its cap: 425 bounded flow-history
warnings, five proof-assistance retries, four reciprocal key-attestation
publication rejections and one bounded topology-history warning. No live UNF
ERROR, panic, OOM or verifier rejection is observed. The retries and warning
volume remain stabilization findings; readiness is not a clean-health claim.

Matching retained Kind must pass this identical image next. Concurrent
movement, immutable incarnation publication, authenticated live attachment /
address joins and policy-first production consumption remain open. This
isolated pass enables no live plaintext exception and closes neither full
Phase 9 nor stabilization S1–S5.
