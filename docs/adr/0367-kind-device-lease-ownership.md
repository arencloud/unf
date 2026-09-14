# ADR 0367: Matching Kind Device-Lease Ownership and Admin-State Gate

Date: 2026-09-14

Status: verified for the expanded isolated serial mechanism

Following ADR 0366's cl02 pass, retained Kind passes the identical source
`27efd6e` image:
`quay.io/arencloud/unf-test-tools-dev@sha256:a06fdaf5d71fb811e3a7376dc863c0e2dad068ec28a78ff745601c681b35d6c9`.
The public/imported manifest digest is checked. Diagnostic object SHA-256 remains
`d74d24720e08886870fa6e64e582068b74534d2f6915d81bd1c5f61e0a7e2558`.

At 01:17:30 UTC all 62 IPv4/IPv6 attempts finish with 28 exact deliveries and
34 armed-receiver timeout denials. All per-probe counters match, including
classifier rejection of every denied attempt. The full CNI-derived maximum-
length aliases, all four missing/modified endpoints, digest/role changes,
overlength-prefix rejection and recovery controls pass. Target host/peer
administrative-down checks and all prior move/return, explicit-rebind,
configuration and cloned-index/MAC/alias replacement cases also pass.

Both classifiers load on the retained kernel. Translated/JIT sizes are
9,872/6,171 bytes for redirect and 5,664/3,570 for seed; no performance claim
is inferred. The exact kernel flags/alias layout passes split-module agreement.

Evidence: `.artifacts/p9-device-lease-27efd6e-kind`; raw archive SHA-256
`432164e249f5cd6635466a28bfb6f01535b429adb9bf74ac3c02df76eb824d30`.
Private resources and the Kubernetes Namespace are removed; Node UID is
preserved. Regular UNF containers remain Ready with zero restarts and all
three init installers remain successfully completed. All three reports finish
fresh/converged at policy 58 / Service 19. Live runtime remains `f984db9`.

Before/final controller, every agent and installer logs are reviewed; the final
window covers traffic and cleanup. Retained current/rotated agent CRI logs are
also reviewed (257,287 lines / 152,410,024 decoded bytes, including older history).
Two proof-assistance warnings appear in the current window; older retained logs
contain further proof/activation retries. No live UNF ERROR, panic, OOM or
verifier rejection is observed. High INFO volume remains a stabilization lead.

The expanded isolated mechanism passes both kernels. Synthetic alias matches
are not live placement/attachment authentication. Non-transmitting context
acquisition, concurrent lifetime, immutable publication/retirement, exact address
joins, policy/Service/egress composition and production consumption remain open.
No live plaintext exception or full Phase 9/S1–S5 verification is claimed.
