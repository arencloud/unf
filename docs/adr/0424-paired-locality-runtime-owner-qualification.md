# ADR 0424: Paired locality runtime-owner qualification

Date: 2026-09-21

Status: isolated runtime-owner scope verified; production integration open

The complete `kernel-runtime-owner` gate passes on cl02 first and then persistent
Kind using source `462102f` and identical immutable diagnostic image:

`quay.io/arencloud/unf-test-tools-dev@sha256:616140d085ae9efdefd4e9ff436df6bd45f30de00febb560c0eb107ca52b8270`

Both kernels pass atomic private bpffs directory publication, exclusive ownership,
exact loaded-map identity, reopen withdrawal of an armed fence/dispatch and all
four continuations, substituted-map rejection, partial-inventory refusal and
foreign-entry preservation. Exact-ID cleanup completes. All 28 native checks,
nineteen original bank decisions, eight coordinator decisions, eight successful
TCP/UDP dual-stack exchanges, sixteen socket denials and the frozen-old-agent
reader-floor rejection also pass. Both complete processes exit zero without a
restart, and exact-UID qualification Namespace removal/absence is confirmed.

The local workspace passes 896 tests (26 ignored), formatting, shell syntax and
strict workspace/all-target Clippy. Staged secret scanning reports no leak.

## State and logs

Both production fleets remain `45d85d5`, Native. All production journal snapshots
are byte-identical before/after; no legacy record is upgraded, recreated or
removed. All current UNF Pods are Ready with zero restarts. No production map,
attachment, image pin or routing change is part of this diagnostic.

Full current regular/init and retained/rotated logs were reviewed. cl02 current
logs retain 418 warnings: 414 bounded flow-history retention, two topology-history
retention and two reciprocal key-attestation-row HTTP 400 rejections. Retained
cl02 CRI contains 4,522 warnings in 21 categories. Kind current logs contain no
warnings/errors; retained CRI contains 65 warnings in twelve categories.
Overlapping inventories are not additive. No ERROR, observer failure, partial
or non-JSON retained record is found. Warnings remain stabilization findings;
this gate does not prove uninterrupted key rotation or heavy-load stability.

Evidence prefix: `.artifacts/p9-kernel-runtime-owner-462102f-{cl02,kind}`.

| Evidence | SHA-256 |
|---|---|
| cl02 result | `d7c1509abecacb82585cbfcd956dc8b8d66f28d1bb3c4ac44650dbeb122f5ea8` |
| cl02 complete log | `77594c40da777c1af7a47e1b83793a97dd99ed7d922b921c96dd4a555756fd26` |
| Kind result | `18e163c69d9a2141d34c690737f91b4de10f3f5ba7220a2e29c7be797d57ac76` |
| Kind complete log | `88b62b27a599dfa119b6245593dfff8cd5d2d1354731d10c16b2a1312343ad9d` |

Next wire actual early agent startup/boot decisions, the real journal gate,
applied writers, bank producer and policy-first packet continuations. These
isolated gates use synthetic trusted policy inputs and native replies; they
do not close production L3, L4/L5 locality/replica coverage or Q full lifecycle.
Phase 9 remains open.
