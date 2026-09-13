# ADR 0332: Matching Kind Interrupted CNI Creation Qualification

Date: 2026-09-13

Status: isolated interrupted-creation slice verified on cl02, then Kind

After ADR 0331 is committed and pushed, retained `unf-s1-571379d` passes the
same four interrupted-creation states, twelve diagnostic-checked negative
cases and complete isolated ownership lifecycle. The worker UID remains
`c5c2bc2c-b272-46b5-943e-c81418307749`. No cluster recreation or live state
reset is performed. Owned test namespaces are positively absent afterward.

The identical image is
`quay.io/arencloud/unf-test-tools-dev@sha256:95a9286327290d5bda418db3c079e69455572e801f3ab93399987e6e57ff87e9`,
source `baaa725c3514a23e6db4203f76642b00de5fe5a5`.
The imported OCI archive manifest matches the published digest.

- Adapter SHA-256: `97feafa727c23130203ddf5e862497a4ca4deeb2f0e9add55dd5b4d2fbd2c756`.
- Result JSON SHA-256: `ea0a45a6305169dd7c2fdb70ac77d4b76ba2f6515aa7f46c6aa579e2812d4f68` (identical to cl02).
- Independent Kind fixture SHA-256: `db98ccc32c50fd748d483a78c07a0961f0b6e585799345e5aa04506a423358cb`.

All current UNF containers are Ready with zero restarts. Controller, agents and
installers are reviewed around validation. Two initial agent log captures hit
the 2-MiB limit and are explicitly incomplete. Expanded 16-MiB/no-tail-limit
readback retains 12,109 lines / 6,672,705 bytes, with no new cap reached.
Actual CRI rotation also shortens current-container history, so a second
retained-file collection reads 126,314 lines / 74,503,522 decoded bytes across
current and rotated agent files. The retained history contains 17 proof-round
assistance warnings (three during this slice), six older activation warnings,
four older plan synchronization warnings, one older egress synchronization
warning and one older flow-export warning. No ERROR/panic/OOM/verifier rejection
or stopped-dataplane match is found. The complete retained files, not truncated
tails, support this bounded review; no complete all-time history is claimed.
Per-packet log amplification and these operational warnings remain S1/S3/S4
findings. Raw archives remain private and ignored.

This closes ADR 0330's isolated interrupted-creation prerequisite only.
Live CNI/runtime fleets remain `67c2772`. Live protocol-compatible rollout,
runtime UID capture, authenticated kernel locality consumption, L4/L5/Q and
stabilization S1–S5 remain open. Neither full Phase 9 platform row is reverified.
Before a new live CNI rollout, installation must establish protocol readiness,
not infer compatibility merely from an existing Unix socket pathname.
