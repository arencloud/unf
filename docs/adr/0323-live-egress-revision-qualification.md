# ADR 0323: Observe the Live Egress Revision

Date: 2026-09-13

Status: local observer regressions pass; cl02-first rerun required

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
