# ADR 0288: Fault-Window Capture Closure

Date: 2026-09-13

Status: capture-control repair verified locally and on cl02; full gate pending

## Observation

The `dc738f8` cl02 run's packet capture started at 00:22:08 UTC and expired at
00:23:08 with exit 124 while fault selection was still executing. The previous
qualifier accepted timeout exit 124 and did not require the capture to cover
the complete outage. Kind had the same structural gap with a 45-second timer.
Increasing a fixed duration alone does not establish full-window coverage.

## Decision

Keep a 300-second safety watchdog, but stop capture explicitly only after every
outage probe and exact owned-link restoration. Execute SIGINT against the
capture container's PID 1 (`timeout`), which forwards it to tcpdump for a clean
flush. A capture that has already timed out or crashed cannot accept the exec;
refuse that result. Require exit zero, not watchdog exit 124. Bound stop/status
commands and the termination polling loop.

Read tcpdump's final statistics and require exactly one zero kernel-drop count.
Missing, duplicate or nonzero loss statistics cannot support plaintext-absence
evidence. Both platform artifacts retain the capture start/finish times,
explicit stop request time, watchdog bound, exit code and kernel-drop count.
Packet counts, hash, positive WireGuard/Native evidence and negative Required
plaintext assertions remain unchanged. This does not claim capture completeness
beyond the tested interface/window or account for losses before the capture
hook. Runtime forwarding, keys and generation deadlines are unchanged.

## Verification

`hack/verify-phase9-capture.sh` tests successful explicit closure and refusal of
failed stop, watchdog expiry, crash, missing/duplicate statistics and kernel
drops. Static checks require both gates to stop capture after owned restoration.
Both full platform static gates pass.

A dedicated cl02 host-network capture-control smoke test used the pinned public
test-tools image on worker `bc-24-11-27-b6-49`. The actual shared finish helper
stopped tcpdump from 00:30:58 to 00:31:01 UTC with exit zero and zero kernel
drops. It captured only a narrow loopback filter, injected no networking fault,
and removed its temporary namespace. This verifies capture control, not
ciphertext or fail-closed behavior. Full cl02 lifecycle qualification must
rerun on pinned runtime `cb59e90`, followed by matching-image fresh Kind.
