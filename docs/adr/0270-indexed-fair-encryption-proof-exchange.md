# ADR 0270: Indexed, fair encryption proof exchange

Date: 2026-09-12

Status: Implemented; full cl02 qualification pending

## Context

ADR 0269's compact runtime stayed within the normal controller memory limit,
but Required activation did not converge. The recovered cl02 plan contained
5,972 selections. The agent scanned all work for each incoming frame, scanned
all responses for completion on every turn, and sent every pending request
inside one retry branch before servicing replies. Assignment matching and
cached-proof retention also repeatedly scanned the assignment vector.

## Decision

Index immutable work by exact round digest once, reject duplicate rounds, and
use indexed response slots plus a decrement-once remaining count. Receive
handling and responder leases retain exact family, peer address/port, nonce and
frame equality checks. Each send branch processes at most one work item before
returning to the fair async selection loop. Retry ticks do not rewind a scan
that is still in progress. Both the four-second exchange cap and authenticated
round expiry remain unchanged.

Assignment matching and cached-proof retention now use round indexes too.
The change removes quadratic searches without introducing hash-collision
authority, larger socket buffers, weaker receipts or additional wire schemas.

## Verification and limits

The 4,096-round index regression verifies exact lookup, unknown-round absence
and duplicate rejection. Strict agent all-target/all-feature Clippy passes.
`UNF_PATH_PROBE_LIVE_ROUNDS=4096 bash hack/verify-encryption-path-executor-live.sh`
passed two production engines over isolated kernel WireGuard, for both IPv4
and IPv6, including peer removal, bounded denial, fresh recovery, positive
duplex counters and ciphertext-only underlay capture. The fixture deletes its
temporary namespaces, interfaces and test key material on exit.

This local privileged test is not Kind qualification and does not substitute
for the full cl02 gate. Complete-cut replay per controller proof submission,
serial proof HTTP publication, and the transient recovery checkpoint size gap
from ADR 0269 remain separate follow-up work. No heavy-load readiness or Phase 9
completion is claimed.
