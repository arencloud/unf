# ADR 0370: Matching Kind Non-Transmitting Device Context Qualification

Date: 2026-09-14

Status: verified for the isolated context acquisition mechanism

After ADR 0369's cl02 pass, retained Kind passes source `fcccf05` using the
identical immutable image
`quay.io/arencloud/unf-test-tools-dev@sha256:58bd85080f9e7414b9787ed70704f5aae628170a12fdfc410be8bb108c909ffa`.
The imported manifest and digest reference are checked before execution. The
diagnostic BPF object remains the already-qualified ownership/admin-state object.

At 01:50:47 UTC all four non-transmitting context acquisitions, two strict
wrong-context rejections and 62 real IPv4/IPv6 probes pass. Eight target qdisc
snapshots confirm no ingress/clsact seed attachment. The wrong-device ownership
failure and absent-device `ENODEV` each leave the private candidate/status clear;
explicit valid context recovery succeeds. All 28 exact delivered payloads,
34 armed-receiver timeout denials and per-probe counters pass independently
of the context invocation's result.

Evidence: `.artifacts/p9-device-lease-fcccf05-kind`; raw archive SHA-256
`d25943cc0eaead52a3baaedfded51e8e13ada9a991ba1e06134bbbc4d189dd97`.
Private resources and the fixture Namespace are removed; Node UID is unchanged.
All three reports finish fresh/converged at policy 61 / Service 19. Regular
UNF containers remain Ready with zero restarts; all init installers remain
successfully completed. Both live fleets still run `f984db9`.

Before/final controller, every agent and installer log windows are reviewed;
the final window covers execution and cleanup. Current/rotated agent CRI logs
are also retained and reviewed: 250,042 lines / 148,050,936 decoded bytes,
including older history. Two current proof-assistance warnings and older
proof/activation retries remain recorded. No live UNF ERROR, panic, OOM or
verifier rejection is observed. INFO volume remains a stabilization finding.

Both deployed kernels now pass this isolated context-acquisition prerequisite.
It does not simulate application delivery, enable a live plaintext exception,
or prove concurrent lifetime and immutable incarnation publication. Authenticated
live attachment/address joins, policy-first consuming integration, full Phase 9
lifecycle and stabilization S1–S5 remain open. Concurrent movement qualification
is next, with sequenced traffic and independently checked receiver loss.
