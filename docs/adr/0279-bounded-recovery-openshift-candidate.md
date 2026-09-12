# ADR 0279: Bounded recovery OpenShift candidate

Date: 2026-09-12

Status: Candidate; cl02 and successor Kind qualification pending

Runtime `d128aabd777c5caa71ea522ed091f0471467a327` combines the proven
replica-aware receipt join with deadline-bound timeout responders (ADR 0276)
and bounded checkpoint fallback (ADR 0277). Its immutable public images are
pinned in the Phase 9 release record and Kustomization. Kind remains pending.

All 723 workspace tests passed with 24 specialized tests excluded by the generic
invocation, and strict all-target/all-feature workspace lint passed. The delayed
peer regression failed before the fix and passed afterward, including altered
nonce/foreign-round refusal and expiry. The isolated marked WireGuard engine
passed 4,096 rounds per family, peer-loss denial, fresh recovery, duplex counters
and ciphertext-only underlay capture. The actual compact-store capture test
restored identical typed authority from gzip and window-bounded zstd.
The assembled release controller links only the ordinary system C/math/GCC
runtime libraries and does not depend on a dynamic libzstd installation.

cl02 must pass preserved-state deployment and the full migration, fixture,
traffic, selective, failure, rotation, replacement, operations and cleanup gate.
ADR 0278 adds explicit persistence-error and resource-limit checks around planned
controller replacement, with final gzip compatibility. Archive each runtime's
evidence separately. No previous Kind or cl02 result qualifies this successor.

The 512-record operations retention boundary and its cumulative loss reporting
remain explicit. Any further conformance work must preserve the architecture's
truthful loss accounting, not clear history to obtain a pass. Neither Phase 9
completion nor heavy-load readiness is claimed by publishing this candidate.

A full-history redacted secret scan covered 598 commits and raised nine
historical findings. Source review identified eight Rust map-key type names
misclassified as API keys and one explicitly invalid Bearer-token fixture that
requires HTTP 401. No actual credential was found in those flagged locations.
No scanner rule or path was suppressed, and recent milestone scans remained
clean. Raw reports and all operational credentials stay in ignored local paths.
