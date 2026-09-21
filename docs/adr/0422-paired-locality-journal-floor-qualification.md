# ADR 0422: Paired locality journal reader-floor qualification

Date: 2026-09-21

Status: isolated reader-floor/kernel/socket scope verified

The complete `kernel-journal-floor` suite passes on cl02 first, then persistent
Kind, on identical source `eaef459` and immutable diagnostic image:

`quay.io/arencloud/unf-test-tools-dev@sha256:67266ff494a5848f34bd965c09ce9cb303aa7df5eb60ea8ca288699001946960`

The private journal is upgraded to schema 5 while preserving every attachment
record. Reopening without a fresh hook returns no publication cut and rejects
CNI requests. The actual frozen production `45d85d5` agent rejects it with the
specific 5-versus-4 schema error before opening its private CNI socket or writing
a readiness lease. Its executable SHA-256 is
`46c124dd9090bbca92fe0ab0b521ddc68aefbf778907cff04081ebd9545d046e`.
Journal bytes remain identical across both reader checks. The old agent receives
no controller, BPF object, uplink or inherited credentials; this is not a rollback
of a live Node.

All original 28 native checks, nineteen bank decisions, eight coordinator
decisions and 24 socket cases pass on both kernels. TCP/UDP dual-stack delivery,
pending/cancelled writer fencing, route recovery and actual nonce revocation
remain intact after the durable reader floor. Both complete processes exit zero
without restart. Private links, namespaces and bpffs state are cleaned; exact-UID
Kubernetes Namespace deletion and absence are verified.

No production journal is upgraded: fresh before/after snapshots are byte-identical
on both platforms, including 116 cl02 records and its 107 legacy attachments.
Both live fleets remain `45d85d5`, Native. No runtime/release pin or cluster
networking change occurs.

## Log review and evidence

All current regular/init and retained/rotated logs are reviewed. cl02 current
logs retain 430 warnings: 415 bounded flow-history retention, ten peer-proof
retries, four topology-history retention and one attestation-row rejection.
Retained cl02 CRI has 3,933 warnings in 21 categories. Kind has five current
peer-proof warnings and 65 retained warnings in twelve categories. Overlapping
inventories are not additive. No ERROR, observer failure, partial or non-JSON
CRI record is found. All current UNF Pods are Ready without restarts. Warnings
remain S1 findings; this is not uninterrupted rotation or load qualification.

Evidence prefix: `.artifacts/p9-kernel-journal-floor-eaef459-{cl02,kind}`.

| Evidence | SHA-256 |
|---|---|
| cl02 result | `0015062ab01b9f5d95609a44c0aa4f33754c80982c56bae98186789b44f5a388` |
| cl02 complete log | `2ce7008fc9f4311f20b737841472b7f49931be48ac114a61298fa269a5e08191` |
| Kind result | `bd0aca27872659c84336e693ecf67af5039679eb16508392aceb99e8ea19f307` |
| Kind complete log | `5da6c94c08e750270f35a273c3ae768a6fb5d96892d96b8a56774f9b786e3738` |

This qualifies the durable CNI reader floor, not complete startup ordering or
production packet integration. Next establish actual early runtime-map ownership
and withdrawal before route/CNI startup, then wire the real journal gate,
applied writers, bank producer and policy-first packet continuations. Required
locality/replica, restart continuity and L3/L4/L5/Q remain open.
