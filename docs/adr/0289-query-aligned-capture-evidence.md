# ADR 0289: Query-Aligned Capture Evidence

Date: 2026-09-13

Status: capture evidence repair implemented; full platform lifecycle pending

## Observation

Runtime `cb59e90`, qualifier `2e20161`, passed cl02 host preflight, independent
history verification, Required migration/persistence, Required/selective
dual-stack traffic, eight denied Required outage probes, eight successful
Native outage probes, and owned-link restoration. Capture stopped cleanly at
00:44:53 UTC after starting at 00:43:08 (105 seconds; exit zero).

The gate then correctly refused plaintext-absence evidence because the capture
loss statistics were nonzero or unavailable. The helper did not retain those
raw statistics before failure cleanup removed the Pod. A subsequent exact-path
host-log lookup also found the log already removed. The cause cannot now be
distinguished between capture loss and unavailable statistics. This is not a
passed ciphertext result, full lifecycle, or verified final cleanup.

## Decision

Capture only the union of the existing post-capture query domains: UDP 51820/51821,
Required fixture addresses with TCP 8080, and Native fixture addresses with TCP
8081, in both IP families. This excludes unrelated host traffic without removing
packets relevant to those same assertions. Do not change snap length, enlarge
buffers, weaken zero-loss checks, or claim measured runtime resource savings.
The filter is shared by both platform gates and recorded in final evidence.

Before validating capture statistics, preserve bounded raw tcpdump logs,
explicit process status, and the received pcap in a private task diagnostic
directory. Keep copy-command diagnostics separate from structured JSON:
OpenShift's copy path emits a tar member-name diagnostic that must not corrupt
the JSON result. Failure cleanup may remove fixtures, but must not erase this
already retained evidence. No packet capture or credentials enter Git.

## Verification

Shared regressions verify exact filter construction and actual Ethernet libpcap
compilation, successful closure, retained raw evidence after invalid statistics,
copy-output separation, and refusal of watchdog/crash/loss/missing-stat cases.
Both platform static gates pass. A dedicated filtered cl02 capture-control
smoke test ran from 00:50:05 to 00:50:09 UTC, exited zero, retained its raw
statistics and pcap, and reported zero kernel capture drops. It injected no
fault and is explicitly not a ciphertext or lifecycle qualification.

The full repaired cl02 gate must rerun against the unchanged pinned `cb59e90`
images. Matching-image fresh Kind and Phase 9 closure remain pending; the later
S1–S5 stabilization milestones are not marked complete.

## Subsequent full cl02 run

Runtime `cb59e9080a4cce5544c1ae3c69974233d53d8c52`, qualifier
`f96aec219b09093dc4120de26f7932c130ec1fcb`, passed the existing uninterrupted
cl02 gate in 1,532 seconds, completing at 2026-09-13 01:18:02 UTC.
Archived JSON `.artifacts/phase9-cb59e90-f96aec2-openshift.json` has SHA-256
`7bdcbab95c5224f7658e2f02496a0befaa4c06cd059ef27d7eb33c51ec269aae`.
Its 92,316-byte pcap has SHA-256
`5abaff5c80bd4b7b5ee95f3ecb5e78df8cf2390ed3f231700844dcb42130eefe`.

The 100-second capture retained 352 WireGuard frames, zero Required plaintext,
200 Native plaintext frames and zero kernel drops. The application fault matrix
reported eight Required denials and eight Native successes. Source-agent
replacement, natural rotation, controller replacement, bounded checkpoint and
operations continuity, and final Native journal convergence passed. All eight
persistence checkpoints recorded zero errors and controller restarts, under a
2-GiB limit; the largest stored checkpoint was 877,132 bytes. All sampled codecs
were gzip, so this run does not demonstrate an actual zstd fallback transition.
Operations retained 512 records, explicitly reported historical eviction and
zero upstream loss, and claimed only retained-window completeness.

All five final journals converged to generation 1789262205992 with empty epochs
and no pending generation. Final agent convergence passed. The same six
operators remained unhealthy; no new unhealthy operator appeared. This is not
a wholly healthy-cluster or production-readiness claim.

The final assertion review found two remaining qualifier gaps: an exec failure
could be counted as an HTTP denial, and a failed host query could be mistaken
for cleanup. Cleanup also checked only early table numbers instead of the
rotating range and protocol-owned IPv6 state. Preserve this passing result as
evidence of this exact gate version, but finish that assertion hardening and
requalify before closing Phase 9. Matching-image fresh Kind is still pending.
