# ADR 0420: Paired coordinated-admission qualification

Date: 2026-09-21

Status: isolated applied-writer/kernel/socket scope verified

The complete `kernel-admission` gate passes on cl02 first and persistent Kind
second, using identical source `554b664` and immutable diagnostic image:

`quay.io/arencloud/unf-test-tools-dev@sha256:84a1f9cb9ff7078f602c4bbb6c055dc552ec9d06ff3e4d962abaf7f00507746d`

Each run includes all 28 native checks, nineteen original bank decisions,
eight new coordinated-admission decisions and 24 socket observations (eight
allowed, sixteen denied). Startup withdrawal and pending/cancelled writers
deny. Actual private target-route removal followed by rollback cannot rearm
the cancelled writer. Fresh exact route readback and explicit completion allow
publication; the resulting IPv4/IPv6 TCP/UDP payload/reply exchanges pass.
Route completion cannot hide failed identity completion. Actual journal nonce
retirement continues to deny both protocols/families afterward.

Both processes exit zero without restart, all private links/namespaces/pins
are cleaned, and the exact-UID diagnostic Namespace's absence is confirmed.
Production CNI journals are byte-identical to fresh pre-test snapshots, including
all 116 cl02 records and retained Kind records. Production runtime remains
`45d85d5`, Native baseline; no live image, release pin or legacy attachment changes.

Final cl02 current regular/init logs retain 428 warnings: 405 bounded
flow-history retention, sixteen peer-proof retries, four topology-history
retention and three attestation-row rejections. Retained/rotated CRI contains
3,648 warnings in 21 categories. Kind has three current peer-proof warnings and
63 retained warnings in twelve categories. Overlapping inventories are not
additive. No ERROR, observer failure, partial or non-JSON CRI record is found.
Current UNF Pods remain Ready with zero restarts. Warnings remain S1 findings;
this is not uninterrupted rotation or heavy-load qualification.

Evidence prefix: `.artifacts/p9-kernel-admission-554b664-{cl02,kind}`.

| Evidence | SHA-256 |
|---|---|
| cl02 result | `1b6b5527fe872964e30fab99387aad5ef3b73df9ceb8732e5148c62b99d0d039` |
| cl02 complete log | `817424c6b9bc427c9352e0342a92bf3fe2b15bdf008e8418741502398add1cbe` |
| Kind result | `ecd2b464694d94cafc0fbf126824763904075b8d335b40828c3e90fa4e8008dd` |
| Kind complete log | `a4e8e27b814f21743a38467f6408347fa3c1a081af2111ba30e1519df1614533` |

The coordinator still needs actual agent writer hooks and packet composition.
Startup currently mutates remote routes and serves CNI before dataplane map
loading. Production must fence old locality authority before either operation,
and prevent an older CNI server from mutating attachments while a newer locality
program survives. Address that durable startup/rollback boundary before live
integration; do not restore permission from old pins/digests. Pure-local demand,
policy/Service/reverse/source-egress composition, restart continuity and
L3/L4/L5/Q remain open. Phase 9 is not marked verified by this isolated gate.
