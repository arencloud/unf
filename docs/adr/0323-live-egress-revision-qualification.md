# ADR 0323: Observe the Live Egress Revision

Date: 2026-09-13

Status: local observer regressions and corrected cl02 gate pass; Kind next

After ADR 0322's cl02 pass, retained Kind receives the identical `67c2772`
controller/agent digests through a guarded serial rollout. Node UIDs remain
unchanged; all new UNF Pods are Ready with zero restarts. No cluster, map or
journal is recreated. The scoped gate then stops before encrypted traffic:
its direct ConfigMap `.data["state.json"]` parser encounters an empty payload.

An unused egress control plane legitimately has no durable payload.
`restore_egress_control_plane` explicitly accepts that state. Encryption uses
the *live* control-plane checkpoint revision, normalized by
`current_encryption_plan_source` / `initialized_revision` (`max(1)`), not a
mandatory ConfigMap field. Substituting a guessed revision for missing data
would weaken the exact-cut test.

The gate now reads the existing public `/v1/egress/explain` API for a workload
resolved from current topology. This is a read-only explanation: it emits no
traffic and changes no resource. It remains available after fixture cleanup.
The response must have the expected schema/mode, one authoritative policy
layer matching the fleet policy revision and one numeric, nonnegative,
integer intent revision. Only an explicitly observed zero is normalized to
one, exactly as in the controller. Missing, duplicate, null, string, negative,
fractional, unsafe-integer, stale-policy and wrong-schema/mode evidence is
rejected. Twelve negative mutations and zero/nonzero cases pass locally.

All three API reads retain their raw evidence and bounded timeouts; missing
or torn observations retry only the existing bounded admission loop, never a
workload probe. Every agent's published egress revision must still match the
independently observed controller value. No cluster egress configuration is
changed to accommodate the test.

The failed Kind attempt remains in ignored
`.artifacts/p9-required-reply-67c2772-kind/`; it is not a denied/allowed packet
result. Repeat the corrected observer on cl02 first, then retained Kind.
Required locality/replicas, full lifecycle qualification and S1–S5 remain open.

## cl02 verification

Qualifier `9547c8b` repeats the complete gate on unchanged runtime `67c2772`.
The API independently observes egress revision 38 and the matching policy cut.
All 12 Required requests, 12 Native controls and eight unsolicited reverse
denials pass. The cleanly stopped `br-ex` capture has 176 WireGuard frames,
zero Required plaintext, 72 Native control frames and zero kernel loss. The
owned Namespace is absent and every agent returns to a converged Native cut.
No packet is retried and no runtime image/configuration is changed.

Evidence SHA-256:
`7ab39e4d4c262e0578c0c050de81a57288caa9cbe52e78046538c100afa8f401`.
Capture SHA-256:
`7fa8f2e2c325cd4a96426cb75efdaa46d1dc98a0774c1bc2e6c989a6365a5014`.
Ignored evidence: `.artifacts/p9-required-reply-67c2772-cl02-live-egress/`.
This passes the nonzero-revision platform case first; retained Kind's explicit
initial-revision case is next.
