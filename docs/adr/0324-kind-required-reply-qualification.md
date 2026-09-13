# ADR 0324: Matching Kind Required Reply Qualification

Date: 2026-09-13

Status: scoped Required replies verified on cl02 first, then retained Kind

After ADR 0323's corrected cl02 result is committed and pushed, qualifier
`f4c325ef38d57ca87b95e3ce1d21f803b5b7c12f` passes the identical reply gate on
retained dual-stack `unf-s1-571379d`. Both platforms run immutable runtime
`67c27727d92e86332298724e399b9b6e63f0c6af`, with the same published controller,
agent and test-tools digests. UNF is the primary CNI; kube-proxy is absent.

## Verified scope

All 32 policy outcomes, exact fleet generation and schema-2 initiating-pair
reply provenance are adopted before traffic. Twelve Required requests and
twelve Native controls pass across IPv4/IPv6, TCP/UDP, cross-worker PodIP,
Service and translated ports. Eight independently initiated reverse flows
remain denied. No workload probe is retried.

Kind's live egress explanation explicitly reports initial revision zero;
the observer applies the controller's documented normalization to one and
checks every agent against it. It does not guess from a missing ConfigMap.
The preceding cl02 run independently observes nonzero revision 38.

The `eth0` capture contains 73 WireGuard frames, zero Required plaintext and
90 positive Native plaintext control frames. Explicit capture stop exits zero
and reports zero kernel packet loss. The fixture Namespace is absent, and all
three agents converge to Native generation `1789317436317`, policy 59,
Service 31 and egress 1, with no pending generation or active epochs.

| Evidence | SHA-256 |
|---|---|
| Kind result | `9943071f23d1d0e136d90ec4fb639513dce8ec9cca9a6f63eae1e6db2eb6ba9b` |
| Kind capture | `06060f5e623e7ea4c5672af8eb9aa70d230f44796585c79173f70efd9d03ea95` |
| Prior matching cl02 result | `7ab39e4d4c262e0578c0c050de81a57288caa9cbe52e78046538c100afa8f401` |

Raw evidence remains ignored under
`.artifacts/p9-required-reply-67c2772-kind-live-egress/`. Original Kind Node UIDs,
maps, frontier and journals are retained; guarded serial rollout restores the
normal RollingUpdate strategy. Both fleets' UNF Pods are Ready with zero
restarts. No credentials or private key authority enter Git.

## Log review and limits

All current UNF controller, agent and installer logs are reviewed on both
platforms. Each Kind agent reaches the initial 2-MiB review cap. The audit
therefore reads retained current/rotated CRI logs from the exact three agent
Pod-UID directories: 35,295 lines / 20,788,148 bytes. This is a retained-window
review, not a lossless historical archive. No ERROR, panic, OOM, verifier
rejection or stopped-dataplane entry appears in those records.

Plan/proof/key catch-up and bounded-retention warnings remain visible. On one
Kind worker, telemetry export and egress projection requests fail at
16:34:46 UTC, before this traffic window; the egress request times out. These
warnings are not attributed to a tested packet failure or silently dismissed.
Per-packet INFO volume and controller-request continuity remain S1/S3/S4 work.
cl02's Insights upload and Network Operator configuration issues remain open.

This closes the scoped policy-tracked reply slice, not Phase 9. Required
same-Node/no-underlay and replicated-identity address binding still need
implementation and separate qualification. Full current-runtime lifecycle,
rotation/recovery/composition tests must then pass on cl02 before Kind.
The broader Phase 9 release pins remain pending; S1–S5 and resource-versus-load
claims are not closed by these results.
