# ADR 0311: Native Connection-Stage Diagnostics

Date: 2026-09-13

Status: local and exact-tools-image regressions pass; cl02 live pending

ADR 0310's single failed connection lacks enough evidence to distinguish a
TCP handshake timeout from a stalled HTTP response. Extend each existing
fresh-connection sample with fixed-enumeration `stage` and `reason` fields.
Use C-locale wget diagnostics to recognize connection establishment, an HTTP
status line, refusal, reset, timeout and the outer watchdog. Unknown output
remains unknown; classifications are diagnostic hints, not packet-level proof.
Do not serialize raw diagnostics, server headers or response bodies.

The original single wget attempt, one-second network timeout, two-second
watchdog, zero-failure gate and exact eight-path observation remain unchanged.
No failure is retried into success. Tests exercise successful and wrong HTTP
statuses, malformed output, watchdog/network failures, handshake and response
timeouts, refusal and reset. Both the full local Native gate regressions and
the exact deployed tools image `e9cce439…2352` pass. No runtime rebuild is
needed; the qualifier runs the checked-in script inside that existing image.

Next cl02 diagnosis should pair these records with bounded, test-address-only
packet observations on the source and destination workers. Retain ADR 0310's
failed window even if a later diagnostic run passes. Neither this instrumentation
nor a repeat pass establishes a root cause or closes Phase 9; Kind stays on
the last qualified runtime until the repaired slice passes cl02.
